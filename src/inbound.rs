//! Local HTTP and SOCKS5 proxy listeners.

use std::sync::Arc;

use anyhow::{bail, Result};
use log::{debug, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::mitm::{intercept_for, Intercept, Prefixed};
use crate::udp::{parse_socks_addr, Packet, UdpPipe, MAX_PACKET};

use crate::reload::RouterHandle;
use crate::router::Router;
use crate::rule::{ConnInfo, Proto};
use crate::util::{BoxStream, Target};

const MAX_HEAD: usize = 64 * 1024;

pub async fn serve<F, Fut>(name: &'static str, addr: String, handle: Arc<RouterHandle>, handler: F) -> Result<()>
where
    F: Fn(TcpStream, Arc<Router>) -> Fut + Copy + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(&addr).await.map_err(|e| crate::util::listen_error(name, &addr, e))?;
    info!("{name} proxy listening on {addr}");
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let router = handle.current();
        tokio::spawn(async move {
            if let Err(e) = handler(sock, router).await {
                debug!("{name} {peer}: {e:#}");
            }
        });
    }
}

async fn relay(mut client: TcpStream, mut upstream: BoxStream) {
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        debug!("relay ended: {e}");
    }
}

/// What a TCP inbound knows about its client.
fn tcp_info(sock: &TcpStream, proto: Proto) -> ConnInfo {
    let in_port = sock.local_addr().ok().map(|a| a.port());
    ConnInfo::new(proto, sock.peer_addr().ok(), in_port, in_port.unwrap_or(0))
}

/// Connects via the router, logging failures; `Ok(None)` is a REJECT.
async fn open(router: &Router, target: &Target, ctx: &ConnInfo) -> Result<Option<BoxStream>> {
    let r = router.dispatch_with(target, ctx).await;
    if let Err(e) = &r {
        warn!("{target}: {e:#}");
    }
    r
}

pub async fn http_conn(mut sock: TcpStream, router: Arc<Router>) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        let mut tmp = [0u8; 4096];
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            bail!("request head too large");
        }
    };
    let head = std::str::from_utf8(&buf[..head_end])?.to_string();
    let body = buf[head_end..].to_vec();
    let mut lines = head.split("\r\n");
    let mut req = lines.next().unwrap_or_default().split_whitespace();
    let (method, uri, version) = match (req.next(), req.next(), req.next()) {
        (Some(m), Some(u), Some(v)) => (m, u, v),
        _ => {
            sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            bail!("malformed request line");
        }
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = Target::parse_authority(uri, 443)?;
        if let Some(Intercept::Tls) = intercept_for(&router, &target) {
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let base = tcp_info(&sock, Proto::Https);
            return crate::mitm::serve_tls(Prefixed::new(body, sock), router, target, base).await;
        }
        let ctx = tcp_info(&sock, Proto::Https).with_url(format!("https://{}/", target.host_str()));
        match open(&router, &target, &ctx).await {
            Ok(Some(mut up)) => {
                sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                if !body.is_empty() {
                    up.write_all(&body).await?;
                }
                relay(sock, up).await;
            }
            Ok(None) => sock.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await?,
            Err(_) => sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await?,
        }
        return Ok(());
    }

    let Some(rest) = uri.strip_prefix("http://") else {
        sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await?;
        bail!("non-proxy request {uri:?}");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let target = Target::parse_authority(authority, 80)?;
    if !router.rewrites().is_empty() {
        let base = tcp_info(&sock, Proto::Http);
        return crate::mitm::serve_plain(sock, buf, router, target, base).await;
    }
    // One request per connection: a keep-alive client may switch hosts mid-connection.
    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive") {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    let ctx = tcp_info(&sock, Proto::Http).with_url(uri.to_string());
    match open(&router, &target, &ctx).await {
        Ok(Some(mut up)) => {
            up.write_all(out.as_bytes()).await?;
            up.write_all(&body).await?;
            relay(sock, up).await;
        }
        Ok(None) => sock.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?,
        Err(_) => sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?,
    }
    Ok(())
}

/// UDP ASSOCIATE: relays `RSV(2) FRAG ATYP addr port data` datagrams until the TCP
/// control connection closes. Each destination is routed on its first packet; all that go
/// through one outbound share its association, and replies carry their real source, so
/// the association is full-cone.
async fn socks5_udp_associate(mut sock: TcpStream, router: Arc<Router>) -> Result<()> {
    let relay = Arc::new(UdpSocket::bind((sock.local_addr()?.ip(), 0)).await?);
    let bound = relay.local_addr()?;
    let in_port = sock.local_addr().ok().map(|a| a.port());
    let mut reply = vec![5, 0, 0];
    Target::new(&bound.ip().to_string(), bound.port()).write_socks_addr(&mut reply)?;
    sock.write_all(&reply).await?;

    let relay_loop = async {
        // Destination -> outbound (None: rejected), and outbound -> its association.
        let mut routes: HashMap<String, Option<String>> = HashMap::new();
        let mut assocs: HashMap<String, mpsc::Sender<Packet>> = HashMap::new();
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, client) = relay.recv_from(&mut buf).await?;
            let pkt = &buf[..n];
            // Fragmented datagrams (FRAG != 0) are not supported, as in most clients.
            if n < 4 || pkt[2] != 0 {
                continue;
            }
            let Some((target, off)) = parse_socks_addr(&pkt[3..]) else { continue };
            let payload = pkt[3 + off..].to_vec();
            crate::stats::add_up(payload.len());
            let key = target.to_string();
            let outbound = match routes.get(&key) {
                Some(o) => o.clone(),
                None => {
                    let proto = if target.port == 443 { Proto::Quic } else { Proto::Udp };
                    let ctx = ConnInfo::new(proto, Some(client), in_port, bound.port());
                    let o = match router.route_udp_with(&target, &ctx).await {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("UDP {target}: {e:#}");
                            continue;
                        }
                    };
                    if routes.len() > 4096 {
                        routes.clear();
                    }
                    routes.insert(key, o.clone());
                    o
                }
            };
            let Some(outbound) = outbound else { continue };
            let packet = Packet { addr: target, data: payload };
            if let Some(tx) = assocs.get(&outbound).filter(|tx| !tx.is_closed()) {
                let _ = tx.send(packet).await;
                continue;
            }
            let UdpPipe { tx, mut rx } = match router.open_udp(&outbound, &packet.addr).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("UDP {} via {outbound}: {e:#}", packet.addr);
                    continue;
                }
            };
            let _ = tx.send(packet).await;
            assocs.insert(outbound, tx);
            let relay = relay.clone();
            tokio::spawn(async move {
                while let Some(p) = rx.recv().await {
                    crate::stats::add_down(p.data.len());
                    let mut out = vec![0u8, 0, 0];
                    if p.addr.write_socks_addr(&mut out).is_err() {
                        continue;
                    }
                    out.extend_from_slice(&p.data);
                    let _ = relay.send_to(&out, client).await;
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let mut probe = [0u8; 1];
    tokio::select! {
        r = relay_loop => r?,
        _ = sock.read(&mut probe) => {}
    }
    Ok(())
}

pub async fn socks5_conn(mut sock: TcpStream, router: Arc<Router>) -> Result<()> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xff]).await?;
        bail!("client requires authentication");
    }
    sock.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => {
            let len = sock.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            sock.read_exact(&mut d).await?;
            String::from_utf8(d)?
        }
        _ => {
            sock.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            bail!("bad address type");
        }
    };
    let port = sock.read_u16().await?;
    if req[1] == 3 {
        return socks5_udp_associate(sock, router).await;
    }
    if req[1] != 1 {
        sock.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("unsupported SOCKS command {} (only CONNECT and UDP ASSOCIATE)", req[1]);
    }
    let target = Target::new(&host, port);
    if let Some(kind) = intercept_for(&router, &target) {
        sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return match kind {
            Intercept::Tls => {
                let base = tcp_info(&sock, Proto::Https);
                crate::mitm::serve_tls(sock, router, target, base).await
            }
            Intercept::PlainHttp => {
                let base = tcp_info(&sock, Proto::Http);
                crate::mitm::serve_plain(sock, Vec::new(), router, target, base).await
            }
        };
    }
    match open(&router, &target, &tcp_info(&sock, Proto::Tcp)).await {
        Ok(Some(up)) => {
            sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            relay(sock, up).await;
        }
        Ok(None) => sock.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
        Err(_) => sock.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
    }
    Ok(())
}
