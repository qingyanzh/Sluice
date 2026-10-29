//! UDP plumbing shared by inbounds and outbounds.
//!
//! A UDP flow to one target is a [`UdpPipe`]: a pair of packet channels. The inbound
//! holds one end and the outbound task the other; dropping either end closes the flow.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::util::{resolve, udp_socket, BoxStream, Target};

pub const MAX_PACKET: usize = 65535;

pub struct UdpPipe {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

/// Returns (inbound end, outbound end).
pub fn pipe_pair() -> (UdpPipe, UdpPipe) {
    let (a_tx, b_rx) = mpsc::channel(256);
    let (b_tx, a_rx) = mpsc::channel(256);
    (UdpPipe { tx: a_tx, rx: a_rx }, UdpPipe { tx: b_tx, rx: b_rx })
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

/// DIRECT: a connected socket on the egress interface.
pub async fn direct(target: &Target) -> Result<UdpPipe> {
    let addr = *resolve(&target.host_str(), target.port).await?.first().ok_or_else(|| anyhow!("{target}: no address"))?;
    let sock = udp_socket(&addr)?;
    sock.connect(addr).await?;
    let (app, mut side) = pipe_pair();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            tokio::select! {
                p = side.rx.recv() => match p {
                    Some(p) => { let _ = sock.send(&p).await; }
                    None => break,
                },
                r = sock.recv(&mut buf) => match r {
                    Ok(n) => if side.tx.send(buf[..n].to_vec()).await.is_err() { break },
                    Err(e) => { debug!("UDP direct: {e}"); break }
                },
            }
        }
    });
    Ok(app)
}

/// How packets are framed inside a TCP-like stream.
pub enum Framing {
    /// VLESS: `len(u16) payload`.
    LengthPrefixed,
    /// Trojan: `ATYP addr port len(u16) CRLF payload`, every packet carrying its address.
    Trojan(Target),
}

impl Framing {
    fn encode(&self, p: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(p.len() + 32);
        if let Framing::Trojan(t) = self {
            t.write_socks_addr(&mut out)?;
        }
        out.extend_from_slice(&(p.len() as u16).to_be_bytes());
        if matches!(self, Framing::Trojan(_)) {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(p);
        Ok(out)
    }

    async fn decode<R: AsyncRead + Unpin>(&self, r: &mut R) -> std::io::Result<Vec<u8>> {
        if matches!(self, Framing::Trojan(_)) {
            read_socks_addr(r).await?;
        }
        let len = r.read_u16().await? as usize;
        if matches!(self, Framing::Trojan(_)) {
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf).await?;
        }
        let mut p = vec![0u8; len];
        r.read_exact(&mut p).await?;
        Ok(p)
    }
}

/// Carries a UDP flow over an already-negotiated stream using `framing`.
pub fn over_stream(stream: BoxStream, framing: Framing) -> UdpPipe {
    let (app, side) = pipe_pair();
    let UdpPipe { tx, mut rx } = side;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let framing = std::sync::Arc::new(framing);
    let f = framing.clone();
    tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            let Ok(frame) = f.encode(&p) else { continue };
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
                    Ok(p) => if tx.send(p).await.is_err() { break },
                    Err(_) => break,
                },
            }
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
        for f in [Framing::LengthPrefixed, Framing::Trojan(Target::new("8.8.8.8", 53))] {
            let wire = [f.encode(b"one").unwrap(), f.encode(b"").unwrap(), f.encode(b"three").unwrap()].concat();
            let mut r = &wire[..];
            assert_eq!(f.decode(&mut r).await.unwrap(), b"one");
            assert_eq!(f.decode(&mut r).await.unwrap(), b"");
            assert_eq!(f.decode(&mut r).await.unwrap(), b"three");
        }
    }
}
