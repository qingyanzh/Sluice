//! Hysteria2 client (TCP): QUIC + an HTTP/3 `POST /auth`, then one bidirectional QUIC
//! stream per proxied connection. One QUIC connection per server is shared and rebuilt
//! when it dies.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use log::{debug, info};
use quinn::crypto::rustls::QuicClientConfig;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Mutex;

use crate::trojan::quic_tls_config;
use crate::udp::{pipe_pair, Packet, UdpPipe};
use crate::util::{resolve, udp_socket_std, BoxStream, Target};

const TCP_REQUEST: u64 = 0x401;
const AUTH_OK: u16 = 233;

pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for _ in 1..len {
        v = (v << 8) | r.read_u8().await? as u64;
    }
    Ok(v)
}

fn padding_string() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(64..512);
    (0..n).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

fn tcp_request(target: &Target) -> Vec<u8> {
    let addr = target.to_string();
    let mut rng = rand::thread_rng();
    let mut pad = vec![0u8; rng.gen_range(64..512)];
    rng.fill_bytes(&mut pad);
    let mut req = Vec::with_capacity(16 + addr.len() + pad.len());
    put_varint(&mut req, TCP_REQUEST);
    put_varint(&mut req, addr.len() as u64);
    req.extend_from_slice(addr.as_bytes());
    put_varint(&mut req, pad.len() as u64);
    req.extend(pad);
    req
}

/// Parses a QUIC varint from the front of `b`; returns it and its length.
fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | *b.get(i)? as u64;
    }
    Some((v, len))
}

/// UDP datagram: `session(u32) packet(u16) frag_id(u8) frag_count(u8) addr_len(varint) addr payload`.
struct Datagram<'a> {
    session: u32,
    packet: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &'a [u8],
    payload: &'a [u8],
}

fn parse_datagram(b: &[u8]) -> Option<Datagram<'_>> {
    let session = u32::from_be_bytes(b.get(..4)?.try_into().ok()?);
    let packet = u16::from_be_bytes(b.get(4..6)?.try_into().ok()?);
    let (frag_id, frag_count) = (*b.get(6)?, *b.get(7)?);
    let (alen, n) = get_varint(b.get(8..)?)?;
    let start = 8 + n + alen as usize;
    Some(Datagram { session, packet, frag_id, frag_count, addr: b.get(8 + n..start)?, payload: b.get(start..)? })
}

/// Splits one UDP packet into datagrams no larger than `max`.
fn build_datagrams(session: u32, packet: u16, target: &str, payload: &[u8], max: usize) -> Vec<Bytes> {
    let mut head = Vec::with_capacity(16 + target.len());
    head.extend_from_slice(&session.to_be_bytes());
    head.extend_from_slice(&packet.to_be_bytes());
    head.extend_from_slice(&[0, 1]);
    put_varint(&mut head, target.len() as u64);
    head.extend_from_slice(target.as_bytes());
    let room = max.saturating_sub(head.len()).max(1);
    let chunks: Vec<&[u8]> = if payload.is_empty() { vec![payload] } else { payload.chunks(room).collect() };
    let count = chunks.len().min(255) as u8;
    chunks
        .iter()
        .take(255)
        .enumerate()
        .map(|(i, c)| {
            let mut d = head.clone();
            d[6] = i as u8;
            d[7] = count;
            d.extend_from_slice(c);
            Bytes::from(d)
        })
        .collect()
}

/// Routes incoming datagrams of one connection to their UDP sessions.
#[derive(Default)]
struct UdpDemux {
    sessions: std::sync::Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Packet>>>,
    next: AtomicU32,
}

async fn demux_loop(conn: quinn::Connection, demux: Arc<UdpDemux>) {
    // Fragments waiting for the rest of their packet, keyed by (session, packet).
    let mut partial: HashMap<(u32, u16), Vec<Option<Vec<u8>>>> = HashMap::new();
    while let Ok(raw) = conn.read_datagram().await {
        let Some(d) = parse_datagram(&raw) else { continue };
        let whole = if d.frag_count <= 1 {
            d.payload.to_vec()
        } else {
            if partial.len() > 1024 {
                partial.clear();
            }
            let slots = partial.entry((d.session, d.packet)).or_insert_with(|| vec![None; d.frag_count as usize]);
            if let Some(slot) = slots.get_mut(d.frag_id as usize) {
                *slot = Some(d.payload.to_vec());
            }
            if slots.iter().any(Option::is_none) {
                continue;
            }
            partial.remove(&(d.session, d.packet)).unwrap().into_iter().flatten().flatten().collect()
        };
        let Some(addr) = std::str::from_utf8(d.addr).ok().and_then(|a| Target::parse_authority(a, 0).ok()) else { continue };
        let tx = demux.sessions.lock().unwrap().get(&d.session).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(Packet { addr, data: whole });
        }
    }
}

type H3Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// An authenticated connection. The h3 handles are never used again but must stay
/// alive: dropping the last `SendRequest` closes the QUIC connection.
struct Live {
    conn: quinn::Connection,
    udp: Arc<UdpDemux>,
    _endpoint: quinn::Endpoint,
    _h3: (H3Driver, H3Sender),
}

pub struct Hy2Server {
    server: String,
    port: u16,
    password: String,
    sni: String,
    obfs: Option<String>,
    /// Port hopping: (all server ports, hop interval); `None` uses `port` only.
    hop: Option<(Vec<u16>, Duration)>,
    client_config: quinn::ClientConfig,
    live: Mutex<Option<Live>>,
}

impl Hy2Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        obfs: Option<String>,
        ports: Option<String>,
        hop_interval: Option<u64>,
    ) -> Result<Self> {
        let hop = match ports {
            Some(spec) => Some((
                crate::udphop::parse_ports(&spec)?,
                hop_interval.map_or(crate::udphop::DEFAULT_INTERVAL, Duration::from_secs),
            )),
            None => None,
        };
        let tls = quic_tls_config(skip_cert_verify, b"h3")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        client_config.transport_config(Arc::new(transport));
        let sni = sni.unwrap_or_else(|| server.clone());
        Ok(Hy2Server { server, port, password, sni, obfs, hop, client_config, live: Mutex::new(None) })
    }

    async fn dial(&self) -> Result<Live> {
        let addr = *resolve(&self.server, self.port).await?.first().ok_or_else(|| anyhow!("{}: no address", self.server))?;
        let socket = udp_socket_std(&addr)?;
        let endpoint = if self.obfs.is_none() && self.hop.is_none() {
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))?
        } else {
            use quinn::Runtime;
            // Salamander sits above the hop socket, so obfuscation is independent of the port.
            let mut sock: Arc<dyn quinn::AsyncUdpSocket> = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            if let Some((ports, interval)) = &self.hop {
                sock = Arc::new(crate::udphop::UdpHop::new(sock, addr, ports.clone(), *interval));
            }
            if let Some(pw) = &self.obfs {
                sock = Arc::new(crate::salamander::Salamander::new(sock, pw));
            }
            quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, sock, Arc::new(quinn::TokioRuntime))?
        };
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            endpoint.connect_with(self.client_config.clone(), addr, &self.sni)?,
        )
        .await
        .map_err(|_| anyhow!("QUIC handshake with {addr} timed out"))?
        .context("QUIC handshake")?;

        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", padding_string())
            .body(())?;
        let auth = async {
            let mut stream = sender.send_request(req).await?;
            stream.finish().await?;
            Ok::<_, anyhow::Error>(stream.recv_response().await?.status().as_u16())
        };
        let status = tokio::select! {
            r = auth => r?,
            e = driver.wait_idle() => bail!("HTTP/3 connection closed during auth: {e}"),
        };
        if status != AUTH_OK {
            bail!("hysteria2 auth rejected (HTTP {status}): wrong password?");
        }
        info!("hysteria2 connected to {}:{}", self.server, self.port);
        let udp = Arc::new(UdpDemux::default());
        tokio::spawn(demux_loop(conn.clone(), udp.clone()));
        Ok(Live { conn, udp, _endpoint: endpoint, _h3: (driver, sender) })
    }

    /// The shared connection, dialing a new one if there is none or it has closed.
    async fn current(&self) -> Result<(quinn::Connection, Arc<UdpDemux>)> {
        let mut live = self.live.lock().await;
        if let Some(l) = live.as_ref().filter(|l| l.conn.close_reason().is_none()) {
            return Ok((l.conn.clone(), l.udp.clone()));
        }
        if live.is_some() {
            debug!("hysteria2 connection to {} is gone; reconnecting", self.server);
        }
        let l = self.dial().await?;
        let pair = (l.conn.clone(), l.udp.clone());
        *live = Some(l);
        Ok(pair)
    }

    async fn open_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (conn, _) = self.current().await?;
        match conn.open_bi().await {
            Ok(pair) => Ok(pair),
            Err(_) => {
                conn.close(0u32.into(), b"");
                Ok(self.current().await?.0.open_bi().await?)
            }
        }
    }

    /// UDP rides QUIC datagrams, demultiplexed by session id.
    /// Full-cone: every datagram names its destination, and replies their source.
    pub async fn open_udp(&self) -> Result<UdpPipe> {
        let (conn, demux) = self.current().await?;
        if conn.max_datagram_size().is_none() {
            bail!("hysteria2 server does not support UDP (QUIC datagrams disabled)");
        }
        let session = demux.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let (in_tx, mut in_rx) = tokio::sync::mpsc::channel(256);
        demux.sessions.lock().unwrap().insert(session, in_tx);
        let (app, mut side) = pipe_pair();
        tokio::spawn(async move {
            let mut packet: u16 = 0;
            loop {
                tokio::select! {
                    p = side.rx.recv() => match p {
                        Some(p) => {
                            let max = conn.max_datagram_size().unwrap_or(1200);
                            for d in build_datagrams(session, packet, &p.addr.to_string(), &p.data, max) {
                                let _ = conn.send_datagram(d);
                            }
                            packet = packet.wrapping_add(1);
                        }
                        None => break,
                    },
                    p = in_rx.recv() => match p {
                        Some(p) => if side.tx.send(p).await.is_err() { break },
                        None => break,
                    },
                }
            }
            demux.sessions.lock().unwrap().remove(&session);
        });
        Ok(app)
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        let (mut send, mut recv) = self.open_bi().await?;
        send.write_all(&tcp_request(target)).await?;
        let status = recv.read_u8().await?;
        let msg_len = read_varint(&mut recv).await? as usize;
        let mut msg = vec![0u8; msg_len.min(4096)];
        recv.read_exact(&mut msg).await?;
        let pad_len = read_varint(&mut recv).await?;
        tokio::io::copy(&mut (&mut recv).take(pad_len), &mut tokio::io::sink()).await?;
        if status != 0 {
            bail!("hysteria2 server refused {target}: {}", String::from_utf8_lossy(&msg));
        }
        Ok(Box::new(tokio::io::join(recv, send)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn varints() {
        for v in [0u64, 37, 63, 64, 0x401, 16383, 16384, 1 << 29, (1 << 30) + 5, 1 << 40] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(read_varint(&mut &b[..]).await.unwrap(), v);
        }
        let mut b = Vec::new();
        put_varint(&mut b, 0x401);
        assert_eq!(b, [0x44, 0x01]);
    }

    #[test]
    fn datagram_fragments() {
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let ds = build_datagrams(7, 9, "1.1.1.1:53", &payload, 1200);
        assert!(ds.len() == 3 && ds.iter().all(|d| d.len() <= 1200));
        let mut joined = Vec::new();
        for (i, d) in ds.iter().enumerate() {
            let p = parse_datagram(d).unwrap();
            assert_eq!((p.session, p.packet, p.frag_id, p.frag_count), (7, 9, i as u8, 3));
            joined.extend_from_slice(p.payload);
        }
        assert_eq!(joined, payload);
    }

    #[test]
    fn request_layout() {
        let req = tcp_request(&Target::new("example.com", 443));
        assert_eq!(&req[..3], &[0x44, 0x01, 15]);
        assert_eq!(&req[3..18], b"example.com:443");
    }
}
