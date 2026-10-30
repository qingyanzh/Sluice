//! UDP plumbing shared by inbounds and outbounds.
//!
//! A UDP association is a [`UdpPipe`]: a pair of channels of addressed packets. The
//! inbound holds one end and the outbound task the other; dropping either end closes it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::util::{resolve, udp_socket, BoxStream, Host, Target};

pub const MAX_PACKET: usize = 65535;

/// One datagram: `addr` is the destination going out and the source coming back.
#[derive(Debug)]
pub struct Packet {
    pub addr: Target,
    pub data: Vec<u8>,
}

/// A UDP association through one outbound. Every outbound except per-target ones (see
/// [`crate::router::Router::open_udp`]) honours each packet's address and reports where
/// replies came from, so one pipe talks to any number of remotes (full-cone).
pub struct UdpPipe {
    pub tx: mpsc::Sender<Packet>,
    pub rx: mpsc::Receiver<Packet>,
}

/// Returns (inbound end, outbound end).
pub fn pipe_pair() -> (UdpPipe, UdpPipe) {
    let (a_tx, b_rx) = mpsc::channel(256);
    let (b_tx, a_rx) = mpsc::channel(256);
    (UdpPipe { tx: a_tx, rx: a_rx }, UdpPipe { tx: b_tx, rx: b_rx })
}

impl From<SocketAddr> for Target {
    fn from(a: SocketAddr) -> Self {
        Target { host: Host::Ip(a.ip().to_canonical()), port: a.port() }
    }
}

/// Parses a SOCKS5-style address (ATYP addr port); returns it and the bytes consumed.
pub fn parse_socks_addr(b: &[u8]) -> Option<(Target, usize)> {
    let (host, end) = match *b.first()? {
        1 => (IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(1..5)?).ok()?)).to_string(), 5),
        4 => (IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(1..17)?).ok()?)).to_string(), 17),
        3 => {
            let len = *b.get(1)? as usize;
            (String::from_utf8(b.get(2..2 + len)?.to_vec()).ok()?, 2 + len)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*b.get(end)?, *b.get(end + 1)?]);
    Some((Target::new(&host, port), end + 2))
}

/// Async counterpart of [`parse_socks_addr`] for stream protocols.
pub async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Target> {
    let atyp = r.read_u8().await?;
    let mut buf = vec![atyp];
    let rest = match atyp {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let len = r.read_u8().await?;
            buf.push(len);
            len as usize + 2
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad address type")),
    };
    let start = buf.len();
    buf.resize(start + rest, 0);
    r.read_exact(&mut buf[start..]).await?;
    parse_socks_addr(&buf).map(|(t, _)| t).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad address"))
}

/// Xray's address encoding (VLESS, VMess, Mux.Cool): `port(2) type addr`, 1=IPv4, 2=domain, 3=IPv6.
pub fn write_port_addr(t: &Target, out: &mut Vec<u8>) -> Result<()> {
    out.extend_from_slice(&t.port.to_be_bytes());
    match &t.host {
        Host::Ip(IpAddr::V4(v4)) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        Host::Domain(d) => {
            if d.len() > 255 {
                bail!("domain too long");
            }
            out.push(2);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            out.push(3);
            out.extend_from_slice(&v6.octets());
        }
    }
    Ok(())
}

/// Parses [`write_port_addr`]'s encoding; returns it and the bytes consumed.
pub fn parse_port_addr(b: &[u8]) -> Option<(Target, usize)> {
    let port = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
    let (host, end) = match *b.get(2)? {
        1 => (Host::Ip(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(3..7)?).ok()?))), 7),
        3 => (Host::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(3..19)?).ok()?))), 19),
        2 => {
            let len = *b.get(3)? as usize;
            (Host::Domain(String::from_utf8(b.get(4..4 + len)?.to_vec()).ok()?), 4 + len)
        }
        _ => return None,
    };
    Some((Target { host, port }, end))
}

/// DIRECT: unconnected sockets on the egress interface (one per address family, opened on
/// first use). Replies are accepted from any source and reported as such (full-cone).
pub fn direct() -> UdpPipe {
    let (app, mut side) = pipe_pair();
    tokio::spawn(async move {
        let mut socks: [Option<Arc<UdpSocket>>; 2] = [None, None];
        let mut resolved: HashMap<String, SocketAddr> = HashMap::new();
        let (back_tx, mut back_rx) = mpsc::channel::<Packet>(256);
        let (mut sent, mut received) = (0u32, 0u32);
        loop {
            tokio::select! {
                p = side.rx.recv() => {
                    let Some(p) = p else { break };
                    let key = p.addr.to_string();
                    let addr = match resolved.get(&key) {
                        Some(a) => *a,
                        None => match resolve(&p.addr.host_str(), p.addr.port).await.map(|a| a.first().copied()) {
                            Ok(Some(a)) => {
                                if resolved.len() > 1024 { resolved.clear(); }
                                *resolved.entry(key).or_insert(a)
                            }
                            r => { debug!("UDP direct {}: resolve: {:?}", p.addr, r.err()); continue }
                        },
                    };
                    let slot = &mut socks[addr.is_ipv6() as usize];
                    if slot.is_none() {
                        let sock = match udp_socket(&addr) {
                            Ok(s) => Arc::new(s),
                            Err(e) => { debug!("UDP direct {addr}: socket: {e}"); continue }
                        };
                        let (sock2, back) = (sock.clone(), back_tx.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; MAX_PACKET];
                            loop {
                                tokio::select! {
                                    _ = back.closed() => break,
                                    r = sock2.recv_from(&mut buf) => match r {
                                        Ok((n, from)) => {
                                            if back.send(Packet { addr: from.into(), data: buf[..n].to_vec() }).await.is_err() { break }
                                        }
                                        Err(e) => { debug!("UDP direct: recv: {e}"); break }
                                    },
                                }
                            }
                        });
                        *slot = Some(sock);
                    }
                    if let Err(e) = slot.as_ref().unwrap().send_to(&p.data, addr).await {
                        debug!("UDP direct {} via {addr}: send: {e}", p.addr);
                    }
                    sent += 1;
                }
                Some(p) = back_rx.recv() => {
                    if received == 0 { debug!("UDP direct: first reply from {}", p.addr); }
                    received += 1;
                    if side.tx.send(p).await.is_err() { break }
                }
            }
        }
        debug!("UDP direct association closed: {sent} sent, {received} received");
    });
    app
}

/// How packets are framed inside a TCP-like stream. Both carry an address per packet.
pub enum Framing {
    /// Trojan: `ATYP addr port len(u16) CRLF payload`.
    Trojan,
    /// Xray XUDP: Mux.Cool frames on session 0 (see [`xudp_frame`]); `Target` stands in
    /// for replies whose frame names no source.
    Xudp(Target),
}

/// Mux.Cool frame `meta_len(2) meta [len(2) data]`, meta = `session(2) status option`
/// plus, for XUDP, `network(2=UDP) port type addr` and on the New frame an 8-byte GlobalID
/// (zero: no session resumption across connections).
pub fn xudp_frame(first: bool, addr: &Target, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + 48);
    out.extend_from_slice(&[0, 0, 0, 0, if first { 1 } else { 2 }, 1, 2]);
    write_port_addr(addr, &mut out)?;
    if first {
        out.extend_from_slice(&[0; 8]);
    }
    let meta = (out.len() - 2) as u16;
    out[..2].copy_from_slice(&meta.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

impl Framing {
    fn encode(&self, first: bool, p: &Packet) -> Result<Vec<u8>> {
        match self {
            Framing::Trojan => {
                let mut out = Vec::with_capacity(p.data.len() + 32);
                p.addr.write_socks_addr(&mut out)?;
                out.extend_from_slice(&(p.data.len() as u16).to_be_bytes());
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&p.data);
                Ok(out)
            }
            Framing::Xudp(_) => xudp_frame(first, &p.addr, &p.data),
        }
    }

    /// Next packet; `None` when the far end closed the session cleanly.
    async fn decode<R: AsyncRead + Unpin>(&self, r: &mut R) -> std::io::Result<Option<Packet>> {
        match self {
            Framing::Trojan => {
                let addr = read_socks_addr(r).await?;
                let len = r.read_u16().await? as usize;
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf).await?;
                let mut data = vec![0u8; len];
                r.read_exact(&mut data).await?;
                Ok(Some(Packet { addr, data }))
            }
            Framing::Xudp(fallback) => loop {
                let mut meta = vec![0u8; r.read_u16().await? as usize];
                r.read_exact(&mut meta).await?;
                if meta.len() < 4 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "xudp: short frame"));
                }
                let (status, option) = (meta[2], meta[3]);
                let data = if option & 1 != 0 {
                    let mut d = vec![0u8; r.read_u16().await? as usize];
                    r.read_exact(&mut d).await?;
                    Some(d)
                } else {
                    None
                };
                match status {
                    3 => return Ok(None),
                    1 | 2 | 4 => {}
                    _ => continue,
                }
                let Some(data) = data else { continue };
                // KeepAlive frames carry data only when they also name an address.
                let addr = match meta.get(4) {
                    Some(2) => parse_port_addr(&meta[5..]).map(|(t, _)| t),
                    _ => None,
                };
                match (status, addr) {
                    (4, None) => continue,
                    (_, addr) => return Ok(Some(Packet { addr: addr.unwrap_or_else(|| fallback.clone()), data })),
                }
            },
        }
    }
}

/// Carries a UDP association over an already-negotiated stream using `framing`. With
/// `first_frame_sent`, the opening frame went out with the protocol header already.
pub fn over_stream(stream: BoxStream, framing: Framing, mut rx: mpsc::Receiver<Packet>, tx: mpsc::Sender<Packet>, first_frame_sent: bool) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let framing = Arc::new(framing);
    let f = framing.clone();
    tokio::spawn(async move {
        let mut first = !first_frame_sent;
        while let Some(p) = rx.recv().await {
            let Ok(frame) = f.encode(first, &p) else { continue };
            first = false;
            if wr.write_all(&frame).await.is_err() {
                return;
            }
        }
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tx.closed() => break,
                r = framing.decode(&mut rd) => match r {
                    Ok(Some(p)) => if tx.send(p).await.is_err() { break },
                    Ok(None) => break,
                    Err(e) => { debug!("UDP over stream: {e}"); break }
                },
            }
        }
    });
}

/// XUDP over a stream that `connect` opens once the first packet is known: Xray only
/// accepts XUDP from a Vision user without a flow when the first Mux frame (session 0,
/// UDP) arrives together with the request header, so `connect` gets that frame to send.
pub fn xudp<F, Fut>(first_target: &Target, connect: F) -> UdpPipe
where
    F: FnOnce(Vec<u8>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<BoxStream>> + Send,
{
    let (app, side) = pipe_pair();
    let fallback = first_target.clone();
    tokio::spawn(async move {
        let UdpPipe { tx, mut rx } = side;
        let Some(p) = rx.recv().await else { return };
        let frame = match xudp_frame(true, &p.addr, &p.data) {
            Ok(f) => f,
            Err(e) => return debug!("xudp: {e}"),
        };
        match connect(frame).await {
            Ok(stream) => over_stream(stream, Framing::Xudp(fallback), rx, tx, true),
            Err(e) => log::warn!("UDP {fallback}: {e:#}"),
        }
    });
    app
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks_addr_and_framing() {
        for t in [Target::new("1.2.3.4", 53), Target::new("::1", 443), Target::new("a.example", 80)] {
            let mut b = Vec::new();
            t.write_socks_addr(&mut b).unwrap();
            let (parsed, n) = parse_socks_addr(&b).unwrap();
            assert_eq!((parsed.to_string(), n), (t.to_string(), b.len()));
            assert_eq!(read_socks_addr(&mut &b[..]).await.unwrap().to_string(), t.to_string());
        }
        let f = Framing::Trojan;
        let pkts = [Packet { addr: Target::new("8.8.8.8", 53), data: b"one".to_vec() }, Packet { addr: Target::new("a.example", 9), data: vec![] }];
        let wire = [f.encode(true, &pkts[0]).unwrap(), f.encode(false, &pkts[1]).unwrap()].concat();
        let mut r = &wire[..];
        for p in &pkts {
            let got = f.decode(&mut r).await.unwrap().unwrap();
            assert_eq!((got.addr.to_string(), got.data), (p.addr.to_string(), p.data.clone()));
        }
    }

    #[tokio::test]
    async fn xudp_frames() {
        let t = Target::new("1.2.3.4", 53);
        let new = xudp_frame(true, &t, b"q").unwrap();
        assert_eq!(new, [&[0, 20, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4][..], &[0; 8], &[0, 1, b'q']].concat());
        let keep = xudp_frame(false, &Target::new("::1", 5353), b"").unwrap();
        assert_eq!(&keep[..10], &[0, 24, 0, 0, 2, 1, 2, 0x14, 0xe9, 3]);
        // Server replies: Keep with a source, Keep without one, a KeepAlive, then End.
        let fallback = Target::new("9.9.9.9", 1);
        let mut wire = xudp_frame(false, &Target::new("5.6.7.8", 123), b"a").unwrap();
        wire.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 1, b'b']);
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 0]);
        wire.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
        let f = Framing::Xudp(fallback);
        let mut r = &wire[..];
        let p = f.decode(&mut r).await.unwrap().unwrap();
        assert_eq!((p.addr.to_string(), p.data), ("5.6.7.8:123".into(), b"a".to_vec()));
        let p = f.decode(&mut r).await.unwrap().unwrap();
        assert_eq!((p.addr.to_string(), p.data), ("9.9.9.9:1".into(), b"b".to_vec()));
        assert!(f.decode(&mut r).await.unwrap().is_none());
    }
}
