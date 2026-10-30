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
    let Some(target) = to_target(tcp.peer_addr(), &fake) else { return };
    let ctx = ConnInfo::new(Proto::Tcp, Some(tcp.local_addr()), None, tcp.peer_addr().port());
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

async fn handle_udp(mut udp: IpStackUdpStream, router: Arc<Router>, fake: Arc<FakeDns>) -> Result<()> {
    let dst = udp.peer_addr();
    let mut buf = vec![0u8; 65535];
    if dst.port() == 53 {
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

    let Some(target) = to_target(dst, &fake) else { return Ok(()) };
    let proto = if dst.port() == 443 { Proto::Quic } else { Proto::Udp };
    let ctx = ConnInfo::new(proto, Some(udp.local_addr()), None, dst.port());
    let Some(mut pipe) = router.dispatch_udp_with(&target, &ctx).await? else { return Ok(()) };
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
                    udp.write_all(&p.data).await?
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
                    if let Err(e) = handle_udp(udp, router, fake).await {
                        debug!("TUN UDP {src} -> {dst}: {e:#}");
                    }
                });
            }
            _ => {}
        }
    }
}
