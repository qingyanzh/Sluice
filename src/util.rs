use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A bidirectional byte stream to the destination, whatever outbound produced it.
pub type BoxStream = Box<dyn AsyncStream>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Self {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        let host = match h.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(h.trim_end_matches('.').to_ascii_lowercase()),
        };
        Target { host, port }
    }

    /// Parses `host`, `host:port`, `[v6]` or `[v6]:port`.
    pub fn parse_authority(s: &str, default_port: u16) -> Result<Self> {
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let end = rest.find(']').ok_or_else(|| anyhow!("bad authority {s:?}"))?;
            let port = match rest[end + 1..].strip_prefix(':') {
                Some(p) => p.parse().with_context(|| format!("bad port in {s:?}"))?,
                None => default_port,
            };
            (&rest[..end], port)
        } else {
            match s.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => {
                    (h, p.parse().with_context(|| format!("bad port in {s:?}"))?)
                }
                _ => (s, default_port),
            }
        };
        if host.is_empty() {
            bail!("empty host in {s:?}");
        }
        Ok(Self::new(host, port))
    }

    pub fn host_str(&self) -> String {
        match &self.host {
            Host::Domain(d) => d.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }

    /// SOCKS5-style address (ATYP + addr + port), shared by Shadowsocks and Trojan.
    pub fn write_socks_addr(&self, out: &mut Vec<u8>) -> Result<()> {
        match &self.host {
            Host::Ip(IpAddr::V4(v4)) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            Host::Ip(IpAddr::V6(v6)) => {
                out.push(4);
                out.extend_from_slice(&v6.octets());
            }
            Host::Domain(d) => {
                if d.len() > 255 {
                    bail!("domain too long");
                }
                out.push(3);
                out.push(d.len() as u8);
                out.extend_from_slice(d.as_bytes());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            _ => write!(f, "{}:{}", self.host_str(), self.port),
        }
    }
}

/// How outbound sockets leave the machine. Set once in TUN mode so our own traffic
/// skips the TUN (bound to the physical interface) and skips the fake-IP system DNS.
pub struct Egress {
    pub if_index: Option<NonZeroU32>,
    pub dns: Vec<SocketAddr>,
}

static EGRESS: OnceLock<Egress> = OnceLock::new();

pub fn set_egress(e: Egress) {
    let _ = EGRESS.set(e);
}

fn bind_egress(sock: SockRef<'_>, v6: bool) -> std::io::Result<()> {
    match EGRESS.get().and_then(|e| e.if_index) {
        Some(idx) if v6 => sock.bind_device_by_index_v6(Some(idx)),
        Some(idx) => sock.bind_device_by_index_v4(Some(idx)),
        None => Ok(()),
    }
}

pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match EGRESS.get() {
        Some(e) if !e.dns.is_empty() => {
            let ips = crate::dns::resolve_a(host, &e.dns).await?;
            Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
        }
        _ => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
    }
}

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve(host, port).await.with_context(|| format!("resolve {host}"))?;
    let mut last = anyhow!("{host}: no addresses");
    for addr in addrs {
        let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        bind_egress(SockRef::from(&sock), addr.is_ipv6())?;
        match tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(addr)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Ok(Err(e)) => last = e.into(),
            Err(_) => last = anyhow!("timed out"),
        }
    }
    Err(last.context(format!("connect to {host}:{port}")))
}

/// A non-blocking std UDP socket bound to the egress interface (for QUIC endpoints).
pub fn udp_socket_std(v6: bool) -> std::io::Result<std::net::UdpSocket> {
    let s = std::net::UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" })?;
    bind_egress(SockRef::from(&s), v6)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

pub fn udp_socket(v6: bool) -> std::io::Result<UdpSocket> {
    UdpSocket::from_std(udp_socket_std(v6)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        let t = Target::parse_authority("Example.COM:8443", 80).unwrap();
        assert_eq!(t.host, Host::Domain("example.com".into()));
        assert_eq!(t.port, 8443);
        let t = Target::parse_authority("[::1]:53", 80).unwrap();
        assert_eq!(t.to_string(), "[::1]:53");
        let t = Target::parse_authority("1.2.3.4", 80).unwrap();
        assert_eq!(t.to_string(), "1.2.3.4:80");
        assert!(Target::parse_authority(":80", 80).is_err());
    }
}
