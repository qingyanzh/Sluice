use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A bidirectional byte stream to the destination, whatever outbound produced it.
pub type BoxStream = Box<dyn AsyncStream>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Keep the OS error as a source while giving the app a stable kind and address.
pub fn listen_error(name: &str, addr: &str, error: std::io::Error) -> anyhow::Error {
    let kind = error.kind();
    anyhow::Error::new(error).context(format!("bind {name} on {addr}: {kind:?}"))
}

/// Set reuse before binding. Do not use SO_REUSEPORT: a live previous core must
/// keep the bind exclusive.
pub async fn listen_tcp(addr: &str, retry_for: Duration) -> std::io::Result<TcpListener> {
    let addrs: Vec<_> = tokio::net::lookup_host(addr).await?.collect();
    let deadline = tokio::time::Instant::now() + retry_for;
    loop {
        let mut last = std::io::Error::new(std::io::ErrorKind::InvalidInput, "no listen addresses");
        for addr in &addrs {
            let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            socket.set_reuseaddr(true)?;
            #[cfg(target_os = "macos")]
            allow_listener_uid_handoff(&socket)?;
            match socket.bind(*addr).and_then(|()| socket.listen(1024)) {
                Ok(listener) => return Ok(listener),
                Err(error) => last = error,
            }
        }
        if last.kind() != std::io::ErrorKind::AddrInUse || tokio::time::Instant::now() >= deadline {
            return Err(last);
        }
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + Duration::from_millis(100))).await;
    }
}

/// Darwin's in_pcbbind checks the old socket's UID even with SO_REUSEADDR, so
/// root-owned API connections in TIME_WAIT prevent the next user core binding.
/// This public option is inherited by accepted sockets. It permits the UID
/// handoff without SO_REUSEPORT (which would also share a live listener).
/// See apple-oss-distributions/xnu: bsd/netinet/in_pcb.c and bsd/kern/uipc_socket2.c.
#[cfg(target_os = "macos")]
fn allow_listener_uid_handoff(socket: &TcpSocket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let enabled: libc::c_int = 1;
    // SAFETY: the live socket and correctly sized integer remain valid for the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSESHAREUID,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

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

/// Pins a socket to the physical interface. Loopback is left alone: it isn't reachable
/// through that interface, and the TUN routes never capture it anyway.
fn bind_egress(sock: SockRef<'_>, dest: &SocketAddr) -> std::io::Result<()> {
    if dest.ip().is_loopback() {
        return Ok(());
    }
    match EGRESS.get().and_then(|e| e.if_index) {
        Some(idx) if dest.is_ipv6() => sock.bind_device_by_index_v6(Some(idx)),
        Some(idx) => sock.bind_device_by_index_v4(Some(idx)),
        None => Ok(()),
    }
}

pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if crate::dns::active() || !egress_dns().is_empty() {
        let ips = crate::dns::resolver().lookup_v4(host).await?;
        return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
    }
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

/// The real (pre-TUN) DNS servers, when enhanced mode has set them.
pub fn egress_dns() -> Vec<SocketAddr> {
    EGRESS.get().map(|e| e.dns.clone()).unwrap_or_default()
}

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve(host, port).await.with_context(|| format!("resolve {host}"))?;
    let mut last = anyhow!("{host}: no addresses");
    for addr in addrs {
        let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        bind_egress(SockRef::from(&sock), &addr)?;
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

/// A non-blocking std UDP socket for talking to `dest`, on the egress interface (for QUIC endpoints).
pub fn udp_socket_std(dest: &SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let s = std::net::UdpSocket::bind(if dest.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
    bind_egress(SockRef::from(&s), dest)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

pub fn udp_socket(dest: &SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::from_std(udp_socket_std(dest)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_reuses_address_after_server_closes_connection() {
        use tokio::io::AsyncReadExt;
        let listener = listen_tcp("127.0.0.1:0", Duration::ZERO).await.unwrap();
        assert!(SockRef::from(&listener).reuse_address().unwrap());
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            // Both the listening and accepted sockets must opt into UID handoff;
            // accepted sockets can outlive the core itself in TIME_WAIT.
            for fd in [listener.as_raw_fd(), server.as_raw_fd()] {
                let mut enabled: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&enabled) as libc::socklen_t;
                let result = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_REUSESHAREUID,
                        std::ptr::from_mut(&mut enabled).cast(),
                        &mut len,
                    )
                };
                assert_eq!(result, 0);
                assert_ne!(enabled, 0, "UID handoff must survive accept");
            }
        }
        // Server initiates close and enters TIME_WAIT after the client closes.
        drop(server);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        drop(client);
        drop(listener);
        let rebound = listen_tcp(&addr.to_string(), Duration::ZERO).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn listener_retries_until_previous_listener_exits() {
        let old = listen_tcp("127.0.0.1:0", Duration::ZERO).await.unwrap();
        let addr = old.local_addr().unwrap().to_string();
        let retry = tokio::spawn(async move { listen_tcp(&addr, Duration::from_secs(2)).await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!retry.is_finished(), "must not share a live listener's port");
        drop(old);
        retry.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn listener_retry_is_bounded_when_port_stays_occupied() {
        let old = listen_tcp("127.0.0.1:0", Duration::ZERO).await.unwrap();
        let addr = old.local_addr().unwrap().to_string();
        let error = tokio::time::timeout(Duration::from_secs(1), listen_tcp(&addr, Duration::from_millis(150)))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn listen_error_names_address_and_preserves_kind() {
        let error = listen_error("HTTP", "127.0.0.1:6252", std::io::Error::from(std::io::ErrorKind::AddrInUse));
        let message = format!("{error:#}");
        assert!(message.contains("bind HTTP on 127.0.0.1:6252: AddrInUse"), "{message}");
        assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::AddrInUse);
    }

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
