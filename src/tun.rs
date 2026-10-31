//! TUN inbound ("enhanced mode"): a utun device feeding a userspace TCP/IP stack.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use log::{debug, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::AbstractDevice;

use crate::dns::FakeDns;
use crate::reload::RouterHandle;
use crate::router::Router;
use crate::rule::{ConnInfo, Proto};
use crate::udp::Packet;
use crate::util::{Host, Target};

/// Creates the utun device as a point-to-point link `address -> peer`; returns it and its name.
pub fn create(address: Ipv4Addr, peer: Ipv4Addr, mtu: u16) -> Result<(tun::AsyncDevice, String)> {
    let mut c = tun::Configuration::default();
    c.address(address).destination(peer).netmask((255, 255, 255, 255)).mtu(mtu).up();
    // utun frames every packet with a 4-byte address-family header; with this on, the
    // tun crate strips it on read and adds it on write, so ipstack sees bare IP packets.
    #[cfg(target_os = "macos")]
    c.platform_config(|p| {
        p.packet_information(true);
    });
    let dev = tun::create_as_async(&c).map_err(|e| anyhow!("create TUN device: {e} (needs root: run with sudo)"))?;
    let name = dev.tun_name()?;
    Ok((dev, name))
}

/// Maps a destination seen on the TUN back to what the app asked for.
fn to_target(dst: SocketAddr, fake: &FakeDns) -> Option<Target> {
    match dst.ip() {
        IpAddr::V4(v4) if fake.contains(v4) => match fake.lookup(v4) {
            Some(domain) => Some(Target::new(&domain, dst.port())),
            None => {
                debug!("{dst}: unknown fake IP (stale DNS cache?), dropping");
                None
            }
        },
        ip => Some(Target { host: Host::Ip(ip), port: dst.port() }),
    }
}

async fn handle_tcp(mut tcp: IpStackTcpStream, router: Arc<Router>, fake: Arc<FakeDns>) {
    let Some(target) = to_target(tcp.peer_addr(), &fake) else {
        return;
    };
    let (src, port) = (tcp.local_addr(), tcp.peer_addr().port());
    if let Some(kind) = crate::mitm::intercept_for(&router, &target) {
        let r = match kind {
            crate::mitm::Intercept::Tls => crate::mitm::serve_tls(tcp, router, target.clone(), ConnInfo::new(Proto::Https, Some(src), None, port)).await,
            crate::mitm::Intercept::PlainHttp => {
                crate::mitm::serve_plain(tcp, Vec::new(), router, target.clone(), ConnInfo::new(Proto::Http, Some(src), None, port)).await
            }
        };
        if let Err(e) = r {
            debug!("{target}: {e:#}");
        }
        return;
    }
    let ctx = ConnInfo::new(Proto::Tcp, Some(src), None, port);
    match router.dispatch_with(&target, &ctx).await {
        Ok(Some(mut up)) => {
            if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut up).await {
                debug!("{target}: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => warn!("{target}: {e:#}"),
    }
}

/// ipstack reverses this flow's original tuple, preserving the fake destination as
/// the reply source even when a proxy reports the server's resolved, real address.
/// One write is one datagram; write_all would split an oversized reply into unrelated
/// UDP packets because ipstack truncates each write to the MTU.
async fn write_reply(udp: &mut IpStackUdpStream, packet: &Packet, mtu: u16) -> Result<()> {
    let overhead = if udp.peer_addr().is_ipv4() { 28 } else { 48 };
    if packet.data.len() > usize::from(mtu).saturating_sub(overhead) {
        anyhow::bail!("TUN UDP reply exceeds MTU");
    }
    let n = udp.write(&packet.data).await?;
    if n != packet.data.len() {
        anyhow::bail!("TUN UDP reply exceeds MTU");
    }
    Ok(())
}

async fn handle_udp(mut udp: IpStackUdpStream, router: Arc<Router>, fake: Arc<FakeDns>, mtu: u16) -> Result<()> {
    let dst = udp.peer_addr();
    let mut buf = vec![0u8; 65535];
    if fake.hijacks(dst) {
        loop {
            let n = udp.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            if let Some(resp) = fake.handle(&buf[..n]).await {
                udp.write_all(&resp).await?;
            }
        }
    }

    let Some(target) = to_target(dst, &fake) else {
        return Ok(());
    };
    let proto = if dst.port() == 443 { Proto::Quic } else { Proto::Udp };
    let ctx = ConnInfo::new(proto, Some(udp.local_addr()), None, dst.port());
    let Some(mut pipe) = router.dispatch_udp_with(&target, &ctx).await? else {
        return Ok(());
    };
    debug!("TUN UDP {} -> {target}: flow open", udp.local_addr());
    // ipstack ends the stream after its UDP idle timeout, which closes the pipe. Each
    // ipstack stream is one 5-tuple, so replies from other sources are answered as if
    // from `dst` (the app sees a restricted cone, as before).
    loop {
        tokio::select! {
            r = udp.read(&mut buf) => {
                let n = r?;
                if n == 0 || pipe.tx.send(Packet { addr: target.clone(), data: buf[..n].to_vec() }).await.is_err() { return Ok(()); }
                crate::stats::add_up(n);
            }
            p = pipe.rx.recv() => match p {
                Some(p) => {
                    crate::stats::add_down(p.data.len());
                    write_reply(&mut udp, &p, mtu).await?
                }
                None => return Ok(()),
            },
        }
    }
}

pub async fn serve(dev: tun::AsyncDevice, mtu: u16, handle: Arc<RouterHandle>, fake: Arc<FakeDns>) -> Result<()> {
    let mut cfg = IpStackConfig::default();
    cfg.mtu(mtu).map_err(|e| anyhow!("ipstack mtu: {e:?}"))?;
    cfg.udp_timeout(Duration::from_secs(60));
    let mut stack = IpStack::new(cfg, dev);
    loop {
        match stack.accept().await.map_err(|e| anyhow!("TUN stack: {e:?}"))? {
            IpStackStream::Tcp(tcp) => {
                tokio::spawn(handle_tcp(tcp, handle.current(), fake.clone()));
            }
            IpStackStream::Udp(udp) => {
                let (router, fake) = (handle.current(), fake.clone());
                tokio::spawn(async move {
                    let (src, dst) = (udp.local_addr(), udp.peer_addr());
                    if let Err(e) = handle_udp(udp, router, fake, mtu).await {
                        debug!("TUN UDP {src} -> {dst}: {e:#}");
                    }
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src.ip(), dst.ip()) else { unreachable!() };
        let mut p = vec![0u8; 32];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&32u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src_ip.octets());
        p[16..20].copy_from_slice(&dst_ip.octets());
        let sum: u32 = p[..20].as_chunks::<2>().0.iter().map(|b| u16::from_be_bytes(*b) as u32).sum();
        let checksum = !((sum & 65535) + (sum >> 16)) as u16;
        p[10..12].copy_from_slice(&checksum.to_be_bytes());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[24..26].copy_from_slice(&12u16.to_be_bytes());
        p[28..].copy_from_slice(b"STUN");
        p
    }

    #[tokio::test]
    async fn proxy_reply_uses_original_fake_ip_and_port() {
        let fake = FakeDns::new(Ipv4Addr::new(198, 18, 0, 0), 15, vec![]);
        let src: SocketAddr = "10.0.0.5:43210".parse().unwrap();
        let dst = SocketAddr::new(fake.alloc("stun.l.google.com").into(), 19302);
        assert_eq!(to_target(dst, &fake).unwrap().to_string(), "stun.l.google.com:19302");
        assert!(to_target("198.18.99.99:19302".parse().unwrap(), &fake).is_none());
        assert_eq!(to_target("8.8.8.8:123".parse().unwrap(), &fake).unwrap().to_string(), "8.8.8.8:123");
        let (device, mut wire) = tokio::io::duplex(4096);
        let mut stack = IpStack::new(IpStackConfig::default(), device);
        wire.write_all(&query(src, dst)).await.unwrap();
        let IpStackStream::Udp(mut flow) = stack.accept().await.unwrap() else { panic!("UDP flow") };
        let mut payload = [0u8; 4];
        flow.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"STUN");
        // Real IP returned by VMess/VLESS/Trojan/SS must not replace the fake source.
        write_reply(&mut flow, &Packet { addr: Target::new("74.125.250.129", 19302), data: b"reply".to_vec() }, 1500).await.unwrap();
        let mut response = [0u8; 33];
        tokio::time::timeout(Duration::from_secs(1), wire.read_exact(&mut response)).await.unwrap().unwrap();
        assert_eq!(
            &response[12..16],
            &match dst.ip() {
                IpAddr::V4(ip) => ip.octets(),
                _ => unreachable!(),
            }
        );
        assert_eq!(&response[16..20], &[10, 0, 0, 5]);
        assert_eq!(&response[20..22], &19302u16.to_be_bytes());
        assert_eq!(&response[22..24], &43210u16.to_be_bytes());
        assert_eq!(&response[28..], b"reply");
    }
}
