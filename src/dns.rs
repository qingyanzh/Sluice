//! DNS: fake-IP answers for TUN mode, and a resolver that bypasses the system one.
//!
//! The resolver speaks plain UDP, DNS over HTTPS (h2), DNS over TLS and DNS over QUIC,
//! queries every upstream at once and keeps the fastest answer, caches answers for as
//! long as their TTL allows, and honours the `[Host]` section (static addresses and
//! per-domain upstreams).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use log::debug;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;
use crate::reload::RouterHandle;
use crate::util::{udp_socket, udp_socket_std, BoxStream, Target};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const FAKE_TTL: u32 = 1;
const STATIC_TTL: u32 = 60;
/// How long an answer without records (NXDOMAIN, NODATA) is cached.
const NEGATIVE_TTL: u32 = 30;
const MAX_TTL: u32 = 86400;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CACHE: usize = 4096;

/// Hands out addresses from a reserved range and remembers which domain each one stands for.
pub struct FakeDns {
    net: u32,
    size: u32,
    pool: Mutex<Pool>,
    upstream: Vec<SocketAddr>,
}

struct Pool {
    next: u32,
    by_name: HashMap<String, u32>,
    by_ip: HashMap<u32, String>,
}

/// Offsets 0..3 are the network address, the TUN address and the DNS address.
const FIRST_OFFSET: u32 = 3;

impl FakeDns {
    pub fn new(net: Ipv4Addr, prefix: u8, upstream: Vec<SocketAddr>) -> Self {
        let size = 1u32 << (32 - prefix as u32);
        FakeDns {
            net: u32::from(net) & !(size - 1),
            size,
            pool: Mutex::new(Pool { next: FIRST_OFFSET, by_name: HashMap::new(), by_ip: HashMap::new() }),
            upstream,
        }
    }

    pub fn addr(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.net + offset)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & !(self.size - 1) == self.net
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.pool.lock().unwrap().by_ip.get(&u32::from(ip)).cloned()
    }

    /// Returns the fake address for `name`, recycling the oldest one when the range is full.
    pub fn alloc(&self, name: &str) -> Ipv4Addr {
        let mut p = self.pool.lock().unwrap();
        if let Some(&ip) = p.by_name.get(name) {
            return Ipv4Addr::from(ip);
        }
        let ip = self.net + p.next;
        p.next = if p.next + 1 >= self.size - 1 { FIRST_OFFSET } else { p.next + 1 };
        if let Some(old) = p.by_ip.insert(ip, name.to_string()) {
            p.by_name.remove(&old);
        }
        p.by_name.insert(name.to_string(), ip);
        Ipv4Addr::from(ip)
    }

    /// Whether a UDP packet to `dst` is a DNS query Sluice should answer (`hijack-dns`).
    pub fn hijacks(&self, dst: SocketAddr) -> bool {
        let r = resolver();
        if r.hijack.is_empty() {
            return dst.port() == 53;
        }
        dst.ip() == IpAddr::V4(self.addr(2))
            || r.hijack.iter().any(|(ip, port)| *port == dst.port() && ip.is_none_or(|ip| ip == dst.ip()))
    }

    /// Answers a query received on the TUN. `[Host]` entries come first: static ones are
    /// answered as written, per-domain servers are asked for the real answer. Otherwise A
    /// gets a fake address, AAAA gets nothing (so apps fall back to IPv4), and everything
    /// else goes to the real upstream.
    pub async fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = parse_question(query)?;
        let r = resolver();
        if r.hosts.lookup(&q.name).is_some() {
            return r.query(query).await.ok();
        }
        match q.qtype {
            TYPE_A => {
                let ip = self.alloc(&q.name);
                Some(build_response(query, &q, &[IpAddr::V4(ip)], FAKE_TTL))
            }
            TYPE_AAAA => Some(build_response(query, &q, &[], FAKE_TTL)),
            _ => match r.query(query).await {
                Ok(resp) => Some(resp),
                Err(_) => exchange(query, &self.upstream).await.ok(),
            },
        }
    }
}

// ---------------------------------------------------------------- wire format

struct Question {
    id: u16,
    name: String,
    qtype: u16,
    end: usize,
}

fn be16(p: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(at)?, *p.get(at + 1)?]))
}

fn be32(p: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(p.get(at..at + 4)?.try_into().ok()?))
}

fn parse_question(p: &[u8]) -> Option<Question> {
    if p.len() < 12 || p[2] & 0x80 != 0 || be16(p, 4)? != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *p.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(p.get(pos..pos + len)?).to_ascii_lowercase());
        pos += len;
    }
    let qtype = be16(p, pos)?;
    be16(p, pos + 2)?;
    Some(Question { id: be16(p, 0)?, name: labels.join("."), qtype, end: pos + 4 })
}

/// An answer to `query` with the addresses of the asked-for family among `ips`.
fn build_response(query: &[u8], q: &Question, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let answers: Vec<&IpAddr> = ips
        .iter()
        .filter(|ip| matches!((q.qtype, ip), (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))))
        .collect();
    let rd = query[2] & 0x01;
    let mut out = Vec::with_capacity(q.end + 28 * answers.len());
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x80 | rd, 0x80]);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.end]);
    for ip in answers {
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&[0, 4]);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&[0, 16]);
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// A recursive query for `name`/`qtype` with a random id.
fn build_query(name: &str, qtype: u16) -> Result<(u16, Vec<u8>)> {
    let id: u16 = rand::thread_rng().gen();
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid domain {name:?}");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0]);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    Ok((id, q))
}

fn skip_name(p: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *p.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

/// One resource record: where its TTL sits in the message, plus its type and data.
struct Record<'a> {
    rtype: u16,
    ttl_at: usize,
    data: &'a [u8],
}

/// The answer, authority and additional records of a response.
fn records(p: &[u8]) -> Option<(u16, Vec<Record<'_>>)> {
    let (qd, an, ns, ar) = (be16(p, 4)?, be16(p, 6)?, be16(p, 8)?, be16(p, 10)?);
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(p, pos)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an as usize + ns as usize + ar as usize {
        pos = skip_name(p, pos)?;
        let (rtype, rdlen) = (be16(p, pos)?, be16(p, pos + 8)? as usize);
        out.push(Record { rtype, ttl_at: pos + 4, data: p.get(pos + 10..pos + 10 + rdlen)? });
        pos += 10 + rdlen;
    }
    Some((an, out))
}

fn answer_ips(p: &[u8]) -> Vec<IpAddr> {
    let Some((an, recs)) = records(p) else { return Vec::new() };
    recs.iter()
        .take(an as usize)
        .filter_map(|r| match (r.rtype, r.data.len()) {
            (TYPE_A, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(r.data).ok()?)),
            (TYPE_AAAA, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(r.data).ok()?)),
            _ => None,
        })
        .collect()
}

fn parse_a_records(p: &[u8], id: u16) -> Option<Vec<IpAddr>> {
    if be16(p, 0)? != id || p[2] & 0x80 == 0 {
        return None;
    }
    Some(answer_ips(p).into_iter().filter(IpAddr::is_ipv4).collect())
}

/// How long a response may be cached: its smallest record TTL, or [`NEGATIVE_TTL`]
/// when it has no answers. `None` for errors other than NXDOMAIN and for TTL 0.
fn cache_ttl(p: &[u8]) -> Option<u32> {
    let rcode = *p.get(3)? & 0x0F;
    if rcode != 0 && rcode != 3 {
        return None;
    }
    let (an, recs) = records(p)?;
    let ttls = recs.iter().filter(|r| r.rtype != TYPE_OPT).map(|r| be32(p, r.ttl_at).unwrap_or(0));
    let ttl = if an == 0 { ttls.min().unwrap_or(NEGATIVE_TTL).min(NEGATIVE_TTL) } else { ttls.min()? };
    (ttl > 0).then_some(ttl.min(MAX_TTL))
}

/// Lowers every TTL in a cached response by the seconds it has spent in the cache.
fn age_ttls(p: &mut [u8], elapsed: u32) {
    let Some((_, recs)) = records(p) else { return };
    let spots: Vec<usize> = recs.iter().filter(|r| r.rtype != TYPE_OPT).map(|r| r.ttl_at).collect();
    for at in spots {
        let ttl = be32(p, at).unwrap_or(0).saturating_sub(elapsed).max(1);
        p[at..at + 4].copy_from_slice(&ttl.to_be_bytes());
    }
}

fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        t => format!("TYPE{t}"),
    }
}

// ---------------------------------------------------------------- upstreams

/// One DNS server, as written in `dns-server`, `encrypted-dns-server` or `[Host]`.
#[derive(Debug, Clone, PartialEq)]
pub enum Server {
    Udp(SocketAddr),
    /// DNS over HTTPS (h2): `https://host[:port]/path`.
    Https { host: String, port: u16, path: String },
    /// DNS over TLS: `tls://host[:port]`.
    Tls { host: String, port: u16 },
    /// DNS over QUIC: `quic://host[:port]`.
    Quic { host: String, port: u16 },
    /// The system's own servers (`system`, `syslib`).
    System,
}

fn host_port(s: &str, default: u16) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| anyhow!("bad address {s:?}"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().with_context(|| format!("bad port in {s:?}"))?,
            None => default,
        };
        return Ok((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse().with_context(|| format!("bad port in {s:?}"))?)),
        _ => Ok((s.to_string(), default)),
    }
}

impl Server {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if matches!(s, "system" | "syslib") {
            return Ok(Server::System);
        }
        let encrypted = |rest: &str, default: u16| -> Result<(String, u16)> {
            let (h, p) = host_port(rest.trim_end_matches('/'), default)?;
            if h.is_empty() {
                bail!("missing host in {s:?}");
            }
            Ok((h, p))
        };
        if let Some(rest) = s.strip_prefix("https://") {
            let (auth, path) = rest.find('/').map_or((rest, "/dns-query"), |i| (&rest[..i], &rest[i..]));
            let (host, port) = encrypted(auth, 443)?;
            return Ok(Server::Https { host, port, path: path.to_string() });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port) = encrypted(rest, 853)?;
            return Ok(Server::Tls { host, port });
        }
        if let Some(rest) = s.strip_prefix("quic://") {
            let (host, port) = encrypted(rest, 853)?;
            return Ok(Server::Quic { host, port });
        }
        if s.contains("://") {
            bail!("unsupported DNS server {s:?} (use https://, tls://, quic:// or an IP address)");
        }
        let (h, port) = host_port(s, 53)?;
        let ip: IpAddr = h.parse().with_context(|| format!("DNS server {s:?} must be an IP address"))?;
        Ok(Server::Udp(SocketAddr::new(ip, port)))
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Server::Https { .. } | Server::Tls { .. } | Server::Quic { .. })
    }
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Server::Udp(a) => write!(f, "{a}"),
            Server::Https { host, port, path } => write!(f, "https://{host}:{port}{path}"),
            Server::Tls { host, port } => write!(f, "tls://{host}:{port}"),
            Server::Quic { host, port } => write!(f, "quic://{host}:{port}"),
            Server::System => write!(f, "system"),
        }
    }
}

/// A server plus the connection it keeps open (DoH reuses one h2 connection).
struct Upstream {
    server: Server,
    h2: tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
}

impl Upstream {
    fn new(server: Server) -> Arc<Self> {
        Arc::new(Upstream { server, h2: tokio::sync::Mutex::new(None) })
    }
}

tokio::task_local! {
    /// Set while connecting to an encrypted server: names resolved then (the server's
    /// own, or a proxy's) use plain upstreams only, so DoH can't wait on itself.
    static BOOTSTRAP: ();
}

fn bootstrapping() -> bool {
    BOOTSTRAP.try_with(|_| ()).is_ok()
}

/// Sends a raw query to each upstream in turn (over the physical interface) until one answers.
async fn exchange(query: &[u8], upstream: &[SocketAddr]) -> Result<Vec<u8>> {
    for server in upstream {
        if let Ok(Ok(resp)) = tokio::time::timeout(UPSTREAM_TIMEOUT, udp_exchange(query, server)).await {
            return Ok(resp);
        }
    }
    bail!("no upstream DNS server answered")
}

async fn udp_exchange(query: &[u8], server: &SocketAddr) -> std::io::Result<Vec<u8>> {
    let sock = udp_socket(server)?;
    sock.send_to(query, server).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if from == *server && buf.get(..2) == query.get(..2) {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

/// Answers an A query from the system resolver (for `system` when nothing else is known).
async fn getaddrinfo_exchange(query: &[u8]) -> Result<Vec<u8>> {
    let q = parse_question(query).ok_or_else(|| anyhow!("bad query"))?;
    let ips: Vec<IpAddr> = tokio::net::lookup_host((q.name.as_str(), 0)).await?.map(|a| a.ip()).collect();
    Ok(build_response(query, &q, &ips, STATIC_TTL))
}

/// Opens a TCP stream to an encrypted server: straight out of the physical interface,
/// or through the proxy rules when `encrypted-dns-follow-outbound-mode` is on.
async fn open_stream(host: &str, port: u16, follow: bool) -> Result<BoxStream> {
    BOOTSTRAP
        .scope((), async {
            if follow {
                if let Some(handle) = ROUTER.get() {
                    let router = handle.current();
                    return router
                        .dispatch(&Target::new(host, port))
                        .await?
                        .ok_or_else(|| anyhow!("encrypted DNS {host}:{port} is rejected by the rules"));
                }
            }
            Ok(Box::new(crate::util::connect_tcp(host, port).await?) as BoxStream)
        })
        .await
}

async fn tls_stream(host: &str, port: u16, follow: bool, alpn: &[&[u8]]) -> Result<BoxStream> {
    let (connector, sni) = crate::trojan::tls_client_alpn(host, None, false, alpn)?;
    let tcp = open_stream(host, port, follow).await?;
    Ok(Box::new(connector.connect(sni, tcp).await.with_context(|| format!("TLS with {host}:{port}"))?))
}

/// RFC 8484: POST the message (with id 0) as application/dns-message over h2.
async fn doh_exchange(up: &Upstream, host: &str, port: u16, path: &str, msg: &[u8], follow: bool) -> Result<Vec<u8>> {
    let mut slot = up.h2.lock().await;
    let mut send = match slot.take() {
        Some(s) => match s.ready().await {
            Ok(s) => s,
            Err(_) => doh_connect(host, port, follow).await?,
        },
        None => doh_connect(host, port, follow).await?,
    };
    *slot = Some(send.clone());
    drop(slot);
    let authority = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{path}"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", msg.len())
        .body(())?;
    let (resp, mut body) = send.send_request(req, false)?;
    body.send_data(Bytes::copy_from_slice(msg), true)?;
    let resp = resp.await?;
    if resp.status() != http::StatusCode::OK {
        bail!("DoH {host}: HTTP {}", resp.status());
    }
    let mut stream = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk?;
        stream.flow_control().release_capacity(chunk.len())?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn doh_connect(host: &str, port: u16, follow: bool) -> Result<h2::client::SendRequest<Bytes>> {
    let tls = tls_stream(host, port, follow, &[b"h2"]).await?;
    let (send, conn) = h2::client::handshake(tls).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("DoH connection closed: {e}");
        }
    });
    Ok(send.ready().await?)
}

/// RFC 7858: two-byte length prefix on a TLS stream.
async fn dot_exchange(host: &str, port: u16, msg: &[u8], follow: bool) -> Result<Vec<u8>> {
    let mut s = tls_stream(host, port, follow, &[]).await?;
    framed_exchange(&mut s, msg).await
}

async fn framed_exchange(s: &mut BoxStream, msg: &[u8]) -> Result<Vec<u8>> {
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    s.write_all(&framed).await?;
    s.flush().await?;
    let len = s.read_u16().await? as usize;
    let mut out = vec![0u8; len];
    s.read_exact(&mut out).await?;
    Ok(out)
}

/// RFC 9250: one bidirectional stream per query, length-prefixed, id 0.
async fn doq_exchange(host: &str, port: u16, msg: &[u8]) -> Result<Vec<u8>> {
    let addr = BOOTSTRAP
        .scope((), crate::util::resolve(host, port))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{host}: no address"))?;
    let tls = crate::trojan::quic_tls_config(false, b"doq")?;
    let config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    let endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, udp_socket_std(&addr)?, Arc::new(quinn::TokioRuntime))?;
    let conn = endpoint.connect_with(config, addr, host)?.await.context("QUIC handshake")?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    tx.write_all(&framed).await?;
    tx.finish()?;
    let resp = rx.read_to_end(65537).await?;
    conn.close(0u32.into(), b"");
    if resp.len() < 2 {
        bail!("DoQ {host}: short answer");
    }
    Ok(resp[2..].to_vec())
}

// ---------------------------------------------------------------- [Host]

#[derive(Debug, Clone, PartialEq)]
pub enum HostValue {
    /// Answered locally with these addresses.
    Static(Vec<IpAddr>),
    /// Asked of these servers instead of the default ones.
    Server(Vec<Server>),
}

/// The `[Host]` section: exact names win over wildcard patterns, which apply in order.
#[derive(Debug, Default)]
pub struct Hosts {
    exact: HashMap<String, HostValue>,
    patterns: Vec<(String, HostValue)>,
}

/// Glob match with `*` (any run of characters) and `?` (one character).
fn glob(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&pat[1..], s) || (!s.is_empty() && glob(pat, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&pat[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => glob(&pat[1..], &s[1..]),
        _ => false,
    }
}

impl Hosts {
    pub fn parse(entries: &[(String, String)]) -> Result<Self> {
        let mut hosts = Hosts::default();
        for (name, value) in entries {
            let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
            let value = value.trim();
            let v = if let Some(servers) = value.strip_prefix("server:") {
                HostValue::Server(servers.split(',').map(Server::parse).collect::<Result<_>>()?)
            } else {
                let ips = value
                    .split(',')
                    .map(|ip| ip.trim().parse::<IpAddr>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| anyhow!("[Host] {name}: expected IP addresses or server:<dns>, got {value:?}"))?;
                HostValue::Static(ips)
            };
            if name.contains(['*', '?']) {
                hosts.patterns.push((name, v));
            } else {
                hosts.exact.insert(name, v);
            }
        }
        Ok(hosts)
    }

    pub fn lookup(&self, name: &str) -> Option<&HostValue> {
        let name = name.trim_end_matches('.');
        self.exact.get(name).or_else(|| self.patterns.iter().find(|(p, _)| glob(p.as_bytes(), name.as_bytes())).map(|(_, v)| v))
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.patterns.is_empty()
    }
}

// ---------------------------------------------------------------- cache

struct CacheEntry {
    resp: Vec<u8>,
    stored: Instant,
    ttl: u32,
}

#[derive(Default)]
pub struct Cache {
    map: HashMap<(String, u16), CacheEntry>,
}

/// One cached answer, as listed by the API.
pub struct CachedAnswer {
    pub name: String,
    pub qtype: String,
    pub ttl_left: u32,
    pub ips: Vec<IpAddr>,
}

impl Cache {
    /// A copy of the cached response with `id` and aged TTLs, if it hasn't expired.
    fn get(&mut self, name: &str, qtype: u16, id: u16, now: Instant) -> Option<Vec<u8>> {
        let key = (name.to_string(), qtype);
        let e = self.map.get(&key)?;
        let elapsed = now.saturating_duration_since(e.stored).as_secs() as u32;
        if elapsed >= e.ttl {
            self.map.remove(&key);
            return None;
        }
        let mut resp = e.resp.clone();
        resp[..2].copy_from_slice(&id.to_be_bytes());
        age_ttls(&mut resp, elapsed);
        Some(resp)
    }

    fn put(&mut self, name: &str, qtype: u16, resp: &[u8], now: Instant) {
        let Some(ttl) = cache_ttl(resp) else { return };
        if self.map.len() >= MAX_CACHE {
            self.map.retain(|_, e| now.saturating_duration_since(e.stored).as_secs() < e.ttl as u64);
            if self.map.len() >= MAX_CACHE {
                self.map.clear();
            }
        }
        self.map.insert((name.to_string(), qtype), CacheEntry { resp: resp.to_vec(), stored: now, ttl });
    }

    pub fn flush(&mut self) -> usize {
        let n = self.map.len();
        self.map.clear();
        n
    }

    pub fn list(&self, now: Instant) -> Vec<CachedAnswer> {
        let mut out: Vec<CachedAnswer> = self
            .map
            .iter()
            .filter_map(|((name, qtype), e)| {
                let elapsed = now.saturating_duration_since(e.stored).as_secs() as u32;
                (elapsed < e.ttl).then(|| CachedAnswer {
                    name: name.clone(),
                    qtype: type_name(*qtype),
                    ttl_left: e.ttl - elapsed,
                    ips: answer_ips(&e.resp),
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.name, &a.qtype).cmp(&(&b.name, &b.qtype)));
        out
    }
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    f(CACHE.lock().unwrap().get_or_insert_with(Cache::default))
}

pub fn flush_cache() -> usize {
    with_cache(Cache::flush)
}

pub fn cached_answers() -> Vec<CachedAnswer> {
    with_cache(|c| c.list(Instant::now()))
}

// ---------------------------------------------------------------- resolver

pub struct Resolver {
    /// `dns-server`: plain servers, also used to look up encrypted servers' names.
    plain: Vec<Arc<Upstream>>,
    /// `encrypted-dns-server`: used instead of `plain` when set.
    encrypted: Vec<Arc<Upstream>>,
    hosts: Hosts,
    /// `[Host]` servers, keyed by their text, so their connections are reused.
    per_domain: HashMap<String, Arc<Upstream>>,
    follow_outbound: bool,
    /// `hijack-dns`: (address or any, port).
    hijack: Vec<(Option<IpAddr>, u16)>,
}

fn parse_hijack(s: &str) -> Result<(Option<IpAddr>, u16)> {
    let (h, port) = host_port(s.trim(), 53)?;
    if h == "*" {
        return Ok((None, port));
    }
    Ok((Some(h.parse().with_context(|| format!("bad hijack-dns entry {s:?}"))?), port))
}

impl Resolver {
    pub fn new(cfg: &Config) -> Result<Self> {
        let g = &cfg.general;
        let servers = |list: &[String]| -> Result<Vec<Arc<Upstream>>> {
            list.iter().map(|s| Server::parse(s).map(Upstream::new).with_context(|| format!("bad DNS server {s:?}"))).collect()
        };
        let plain = servers(&g.dns_server)?;
        let encrypted = servers(&g.encrypted_dns_server)?;
        if let Some(u) = encrypted.iter().find(|u| !u.server.is_encrypted()) {
            bail!("encrypted-dns-server {} is not https://, tls:// or quic://", u.server);
        }
        let hosts = Hosts::parse(&cfg.hosts)?;
        let mut per_domain = HashMap::new();
        for v in hosts.exact.values().chain(hosts.patterns.iter().map(|(_, v)| v)) {
            if let HostValue::Server(list) = v {
                for s in list {
                    per_domain.entry(s.to_string()).or_insert_with(|| Upstream::new(s.clone()));
                }
            }
        }
        Ok(Resolver {
            plain,
            encrypted,
            hosts,
            per_domain,
            follow_outbound: g.encrypted_dns_follow_outbound_mode,
            hijack: g.hijack_dns.iter().map(|s| parse_hijack(s)).collect::<Result<_>>()?,
        })
    }

    fn empty() -> Self {
        Resolver {
            plain: Vec::new(),
            encrypted: Vec::new(),
            hosts: Hosts::default(),
            per_domain: HashMap::new(),
            follow_outbound: false,
            hijack: Vec::new(),
        }
    }

    /// Whether anything is configured beyond the system resolver.
    fn is_configured(&self) -> bool {
        !self.plain.is_empty() || !self.encrypted.is_empty() || !self.hosts.is_empty()
    }

    /// The servers for a query about `name`, and whether they came from `[Host]`.
    fn upstreams_for(&self, name: &str) -> Vec<Arc<Upstream>> {
        if let Some(HostValue::Server(list)) = self.hosts.lookup(name) {
            return list.iter().filter_map(|s| self.per_domain.get(&s.to_string()).cloned()).collect();
        }
        if !self.encrypted.is_empty() && !bootstrapping() {
            return self.encrypted.clone();
        }
        if !self.plain.is_empty() {
            return self.plain.clone();
        }
        vec![Upstream::new(Server::System)]
    }

    /// Answers a raw DNS query: `[Host]` static entries, then the cache, then all
    /// upstreams at once (the first good answer wins).
    pub async fn query(&self, query: &[u8]) -> Result<Vec<u8>> {
        let q = parse_question(query).ok_or_else(|| anyhow!("malformed DNS query"))?;
        if let Some(HostValue::Static(ips)) = self.hosts.lookup(&q.name) {
            return Ok(build_response(query, &q, ips, STATIC_TTL));
        }
        if let Some(resp) = with_cache(|c| c.get(&q.name, q.qtype, q.id, Instant::now())) {
            return Ok(resp);
        }
        let ups = self.upstreams_for(&q.name);
        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&[0, 0]);
        let wire: Arc<[u8]> = wire.into();
        let mut set = tokio::task::JoinSet::new();
        for up in ups {
            let (wire, follow) = (wire.clone(), self.follow_outbound);
            let boot = bootstrapping();
            set.spawn(async move {
                let started = Instant::now();
                let run = ask(up.clone(), wire, follow);
                let res = if boot { BOOTSTRAP.scope((), run).await } else { run.await };
                (up.server.to_string(), started.elapsed(), res)
            });
        }
        let mut last = anyhow!("no DNS server configured");
        while let Some(joined) = set.join_next().await {
            let Ok((server, took, res)) = joined else { continue };
            match res {
                Ok(mut resp) if resp.len() >= 12 && resp[2] & 0x80 != 0 => {
                    debug!("DNS {} {} answered by {server} in {}ms", q.name, type_name(q.qtype), took.as_millis());
                    resp[..2].copy_from_slice(&q.id.to_be_bytes());
                    with_cache(|c| c.put(&q.name, q.qtype, &resp, Instant::now()));
                    set.abort_all();
                    return Ok(resp);
                }
                Ok(_) => last = anyhow!("{server}: malformed answer"),
                Err(e) => {
                    debug!("DNS {} via {server}: {e:#}", q.name);
                    last = e.context(server);
                }
            }
        }
        Err(last)
    }

    /// IPv4 addresses for `name`. Boxed: resolving can recurse (an encrypted server's
    /// connection resolves names too), and the future must still be `Send`.
    pub fn lookup_v4<'a>(&'a self, name: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let (id, q) = build_query(name, TYPE_A)?;
            let resp = self.query(&q).await?;
            match parse_a_records(&resp, id) {
                Some(ips) if !ips.is_empty() => Ok(ips),
                _ => bail!("{name}: no A records"),
            }
        })
    }
}

/// Sends one id-0 query to one upstream, within [`UPSTREAM_TIMEOUT`].
async fn ask(up: Arc<Upstream>, wire: Arc<[u8]>, follow: bool) -> Result<Vec<u8>> {
    let run = async {
        match &up.server {
            Server::Udp(addr) => Ok(udp_exchange(&wire, addr).await?),
            Server::System => match crate::util::egress_dns() {
                dns if !dns.is_empty() => exchange(&wire, &dns).await,
                _ => getaddrinfo_exchange(&wire).await,
            },
            Server::Https { host, port, path } => doh_exchange(&up, host, *port, path, &wire, follow).await,
            Server::Tls { host, port } => dot_exchange(host, *port, &wire, follow).await,
            Server::Quic { host, port } => doq_exchange(host, *port, &wire).await,
        }
    };
    // Encrypted servers may need a TLS handshake (and a proxy) first: give them longer.
    let limit = if up.server.is_encrypted() { UPSTREAM_TIMEOUT * 2 } else { UPSTREAM_TIMEOUT };
    tokio::time::timeout(limit, run).await.map_err(|_| anyhow!("timed out"))?
}

static RESOLVER: RwLock<Option<Arc<Resolver>>> = RwLock::new(None);
static ROUTER: OnceLock<Arc<RouterHandle>> = OnceLock::new();

/// Makes `r` the active resolver; the cache is flushed since upstreams may have changed.
pub fn install(r: Resolver) {
    *RESOLVER.write().unwrap() = Some(Arc::new(r));
    flush_cache();
}

/// Gives the resolver the router, for `encrypted-dns-follow-outbound-mode`.
pub fn set_router(handle: Arc<RouterHandle>) {
    let _ = ROUTER.set(handle);
}

pub fn resolver() -> Arc<Resolver> {
    RESOLVER.read().unwrap().clone().unwrap_or_else(|| Arc::new(Resolver::empty()))
}

/// Whether name lookups should go through Sluice's resolver rather than the system's.
pub fn active() -> bool {
    resolver().is_configured()
}

/// Resolves `name` to IPv4 addresses via `upstream`, never via the (hijacked) system resolver.
pub async fn resolve_a(name: &str, upstream: &[SocketAddr]) -> Result<Vec<IpAddr>> {
    let (id, q) = build_query(name, TYPE_A)?;
    let resp = exchange(&q, upstream).await?;
    match parse_a_records(&resp, id) {
        Some(ips) if !ips.is_empty() => Ok(ips),
        _ => bail!("{name}: no A records"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[tokio::test]
    async fn fake_answers() {
        let f = FakeDns::new(Ipv4Addr::new(198, 18, 0, 0), 15, vec![]);
        let resp = f.handle(&query("WWW.Google.com", TYPE_A)).await.unwrap();
        let ips = parse_a_records(&resp, 0x1234).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3))]);
        assert_eq!(f.lookup(Ipv4Addr::new(198, 18, 0, 3)).as_deref(), Some("www.google.com"));
        assert_eq!(f.alloc("www.google.com"), Ipv4Addr::new(198, 18, 0, 3));
        assert!(f.contains(Ipv4Addr::new(198, 19, 255, 1)));
        assert!(!f.contains(Ipv4Addr::new(198, 20, 0, 1)));
        let resp = f.handle(&query("a.com", TYPE_AAAA)).await.unwrap();
        assert_eq!(be16(&resp, 6), Some(0));
    }

    #[test]
    fn pool_wraps_and_evicts() {
        let f = FakeDns::new(Ipv4Addr::new(10, 0, 0, 0), 29, vec![]);
        let first = f.alloc("a0");
        for i in 1..10 {
            f.alloc(&format!("a{i}"));
        }
        assert_eq!(f.lookup(first).as_deref(), Some("a8"));
        assert!(f.alloc("a0") != Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn servers() {
        assert_eq!(Server::parse("8.8.8.8").unwrap(), Server::Udp("8.8.8.8:53".parse().unwrap()));
        assert_eq!(Server::parse("1.1.1.1:5353").unwrap(), Server::Udp("1.1.1.1:5353".parse().unwrap()));
        assert_eq!(Server::parse("[2001:db8::1]").unwrap(), Server::Udp("[2001:db8::1]:53".parse().unwrap()));
        assert_eq!(
            Server::parse("https://1.1.1.1/dns-query").unwrap(),
            Server::Https { host: "1.1.1.1".into(), port: 443, path: "/dns-query".into() }
        );
        assert_eq!(
            Server::parse("https://dns.example:8443").unwrap(),
            Server::Https { host: "dns.example".into(), port: 8443, path: "/dns-query".into() }
        );
        assert_eq!(Server::parse("tls://8.8.8.8").unwrap(), Server::Tls { host: "8.8.8.8".into(), port: 853 });
        assert_eq!(Server::parse("quic://dns.adguard.com:784").unwrap(), Server::Quic { host: "dns.adguard.com".into(), port: 784 });
        assert_eq!(Server::parse("syslib").unwrap(), Server::System);
        assert!(Server::parse("dns.google").is_err());
        assert!(Server::parse("h3://x").is_err());
    }

    #[test]
    fn host_matching() {
        let entries: Vec<(String, String)> = [
            ("example.com", "1.2.3.4"),
            ("*.lan", "server:192.168.1.1"),
            ("*.example.com", "5.6.7.8, ::1"),
            ("corp.internal", "server:syslib"),
            ("Printer.LAN", "10.0.0.9"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let h = Hosts::parse(&entries).unwrap();
        let v4 = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(h.lookup("example.com"), Some(&HostValue::Static(vec![v4("1.2.3.4")])));
        assert_eq!(h.lookup("www.example.com"), Some(&HostValue::Static(vec![v4("5.6.7.8"), v4("::1")])));
        assert_eq!(h.lookup("nas.lan"), Some(&HostValue::Server(vec![Server::Udp("192.168.1.1:53".parse().unwrap())])));
        // Exact names win over patterns, whatever the order.
        assert_eq!(h.lookup("printer.lan"), Some(&HostValue::Static(vec![v4("10.0.0.9")])));
        assert_eq!(h.lookup("corp.internal"), Some(&HostValue::Server(vec![Server::System])));
        assert_eq!(h.lookup("lan"), None);
        assert_eq!(h.lookup("example.org"), None);
        assert!(Hosts::parse(&[("a.com".into(), "b.com".into())]).is_err());
    }

    #[test]
    fn static_answers_by_family() {
        let q4 = query("x.test", TYPE_A);
        let q = parse_question(&q4).unwrap();
        let ips = [v("10.1.2.3"), v("fe80::1")];
        let resp = build_response(&q4, &q, &ips, STATIC_TTL);
        assert_eq!(answer_ips(&resp), vec![v("10.1.2.3")]);
        let q6 = query("x.test", TYPE_AAAA);
        let resp = build_response(&q6, &parse_question(&q6).unwrap(), &ips, STATIC_TTL);
        assert_eq!(answer_ips(&resp), vec![v("fe80::1")]);
    }

    fn v(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cache_respects_ttl() {
        let q = query("cache.test", TYPE_A);
        let parsed = parse_question(&q).unwrap();
        let resp = build_response(&q, &parsed, &[v("1.2.3.4")], 10);
        assert_eq!(cache_ttl(&resp), Some(10));
        let mut c = Cache::default();
        let t0 = Instant::now();
        c.put("cache.test", TYPE_A, &resp, t0);
        let hit = c.get("cache.test", TYPE_A, 0xBEEF, t0 + Duration::from_secs(4)).unwrap();
        assert_eq!(be16(&hit, 0), Some(0xBEEF));
        let (_, recs) = records(&hit).unwrap();
        assert_eq!(be32(&hit, recs[0].ttl_at), Some(6));
        assert_eq!(answer_ips(&hit), vec![v("1.2.3.4")]);
        assert_eq!(c.list(t0 + Duration::from_secs(4))[0].ttl_left, 6);
        assert!(c.get("cache.test", TYPE_A, 1, t0 + Duration::from_secs(10)).is_none());
        assert!(c.list(t0).is_empty());

        // TTL 0 is never cached; empty answers are cached briefly.
        c.put("zero.test", TYPE_A, &build_response(&q, &parsed, &[v("1.2.3.4")], 0), t0);
        assert!(c.get("zero.test", TYPE_A, 1, t0).is_none());
        let empty = build_response(&q, &parsed, &[], 0);
        assert_eq!(cache_ttl(&empty), Some(NEGATIVE_TTL));
        let mut servfail = empty.clone();
        servfail[3] = 0x82;
        assert_eq!(cache_ttl(&servfail), None);
        c.put("cache.test", TYPE_A, &resp, t0);
        assert_eq!(c.flush(), 1);
    }

    #[test]
    fn hijack_entries() {
        assert_eq!(parse_hijack("8.8.8.8:53").unwrap(), (Some(v("8.8.8.8")), 53));
        assert_eq!(parse_hijack("*:53").unwrap(), (None, 53));
        assert_eq!(parse_hijack("1.1.1.1").unwrap(), (Some(v("1.1.1.1")), 53));
        assert!(parse_hijack("dns.google:53").is_err());
    }

    #[tokio::test]
    async fn resolver_static_hosts_win() {
        let mut cfg = Config::default();
        cfg.hosts = vec![("static.test".into(), "10.9.8.7".into())];
        let r = Resolver::new(&cfg).unwrap();
        assert_eq!(r.lookup_v4("Static.Test").await.unwrap(), vec![v("10.9.8.7")]);
        assert!(r.is_configured());
    }
}
