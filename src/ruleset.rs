//! External rule lists: `RULE-SET` (Surge rule lines without policy) and `DOMAIN-SET`
//! (one domain per line, `.example.com` meaning the domain and its subdomains).
//! Lists are loaded from a file or URL, cached on disk and refreshed periodically.

use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use http_body_util::BodyExt;
use hyper::body::Body;

use crate::rule::{Cidr, Matcher};
use crate::trojan::tls_client;
use crate::util::{connect_tcp, BoxStream};

const MAX_BODY: usize = 32 << 20;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetKind {
    Rules,
    Domains,
}

#[derive(Debug, Default)]
pub struct SetData {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keyword: Vec<String>,
    cidr: Vec<Cidr>,
    /// Lines of the other types (ports, processes, logical rules...), checked in order.
    others: Arc<Vec<Matcher>>,
}

impl SetData {
    pub fn parse(text: &str, kind: SetKind) -> (Self, usize) {
        let mut d = SetData::default();
        let mut skipped = 0;
        for raw in text.lines() {
            // Also accepts Clash `payload:` lists: `  - '+.example.com'` / `- DOMAIN,a.com`.
            let line = raw.trim().trim_start_matches("- ").trim().trim_matches(|c| c == '\'' || c == '"');
            if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") || line == "payload:" {
                continue;
            }
            let ok = match kind {
                SetKind::Domains => {
                    match line.strip_prefix("+.").or_else(|| line.strip_prefix('.')) {
                        Some(s) => d.suffix.insert(s.to_ascii_lowercase()),
                        None => d.exact.insert(line.to_ascii_lowercase()),
                    };
                    true
                }
                SetKind::Rules => d.add_rule(line),
            };
            if !ok {
                skipped += 1;
            }
        }
        (d, skipped)
    }

    fn add_rule(&mut self, line: &str) -> bool {
        let parts = crate::rule::split_top(line);
        let (Some(&kind), Some(&raw)) = (parts.first(), parts.get(1)) else { return false };
        let value = raw.to_ascii_lowercase();
        match kind.to_ascii_uppercase().as_str() {
            "DOMAIN" => {
                self.exact.insert(value);
            }
            "DOMAIN-SUFFIX" => {
                self.suffix.insert(value.trim_start_matches('.').to_string());
            }
            "DOMAIN-KEYWORD" => self.keyword.push(value),
            "IP-CIDR" | "IP-CIDR6" => match Cidr::parse(&value) {
                Ok(c) => self.cidr.push(c),
                Err(_) => return false,
            },
            // Lines may carry a policy that the set's rule overrides; only `no-resolve` counts.
            _ => match Matcher::parse(kind, raw, &parts[2..], true) {
                Ok(m) => Arc::make_mut(&mut self.others).push(m),
                Err(_) => return false,
            },
        }
        true
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len() + self.keyword.len() + self.cidr.len() + self.others.len()
    }

    pub fn others(&self) -> Arc<Vec<Matcher>> {
        self.others.clone()
    }

    pub fn has_ip_rules(&self) -> bool {
        !self.cidr.is_empty()
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        if self.exact.contains(domain) || self.keyword.iter().any(|k| domain.contains(k.as_str())) {
            return true;
        }
        let mut rest = domain;
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, tail)) => rest = tail,
                None => return false,
            }
        }
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.cidr.iter().any(|c| c.contains(ip))
    }
}

#[derive(Debug)]
pub struct RuleSet {
    pub source: String,
    pub kind: SetKind,
    pub data: RwLock<SetData>,
}

impl RuleSet {
    pub fn new(source: &str, kind: SetKind) -> Arc<Self> {
        Arc::new(RuleSet { source: source.to_string(), kind, data: RwLock::new(SetData::default()) })
    }

    fn is_remote(&self) -> bool {
        self.source.starts_with("http://") || self.source.starts_with("https://")
    }

    fn install(&self, text: &str, from: &str) -> usize {
        let (data, skipped) = SetData::parse(text, self.kind);
        let n = data.len();
        *self.data.write().unwrap() = data;
        let note = if skipped > 0 { format!(" ({skipped} unsupported lines skipped)") } else { String::new() };
        info!("rule set {}: {n} entries from {from}{note}", self.source);
        n
    }
}

fn cache_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    home.join("Library/Caches/Sluice")
}

/// Response metadata is cached alongside the subscription body. Times are Unix seconds.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct FetchMetadata {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
    pub update_interval_hours: Option<u64>,
    pub last_fetch: Option<u64>,
}

impl FetchMetadata {
    fn from_headers(userinfo: Option<&str>, interval: Option<&str>) -> Self {
        let mut meta = Self::default();
        for field in userinfo.unwrap_or_default().split(';') {
            let Some((key, value)) = field.split_once('=') else { continue };
            let value = value.trim().parse().ok();
            match key.trim().to_ascii_lowercase().as_str() {
                "upload" => meta.upload = value,
                "download" => meta.download = value,
                "total" => meta.total = value,
                "expire" => meta.expire = value,
                _ => {}
            }
        }
        meta.update_interval_hours = interval.and_then(|v| v.trim().parse().ok());
        meta
    }
}

pub struct FetchResult {
    pub text: String,
    pub from: &'static str,
    pub metadata: FetchMetadata,
    /// A failed download may still return a usable stale body.
    pub last_error: Option<String>,
}

pub(crate) fn cache_path(source: &str, user_agent: Option<&str>) -> PathBuf {
    let mut hash = Sha256::new();
    hash.update(source.as_bytes());
    if let Some(ua) = user_agent {
        hash.update([0]);
        hash.update(ua.as_bytes());
    }
    cache_dir().join(format!("{}.txt", &hex::encode(hash.finalize())[..24]))
}

fn age(path: &Path) -> Option<Duration> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

/// Reads a file or HTTP(S) source, with a disk cache and stale fallback on errors.
pub async fn fetch(source: &str, base: &Path, max_age: Duration, user_agent: Option<&str>) -> Result<FetchResult> {
    if !(source.starts_with("http://") || source.starts_with("https://")) {
        let path = if source.starts_with("file://") {
            url::Url::parse(source)?.to_file_path().map_err(|_| anyhow!("invalid local file URL"))?
        } else {
            base.join(source)
        };
        let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        return Ok(FetchResult { text, from: "file", metadata: FetchMetadata::default(), last_error: None });
    }
    fetch_cached(source, max_age, user_agent, &cache_path(source, user_agent)).await
}

async fn fetch_cached(source: &str, max_age: Duration, user_agent: Option<&str>, cache: &Path) -> Result<FetchResult> {
    let sidecar = cache.with_extension("meta.json");
    let cached_metadata = || {
        std::fs::read(&sidecar).ok().and_then(|data| serde_json::from_slice(&data).ok()).unwrap_or_default()
    };
    if age(cache).is_some_and(|a| a < max_age) {
        if let Ok(text) = std::fs::read_to_string(cache) {
            return Ok(FetchResult { text, from: "cache", metadata: cached_metadata(), last_error: None });
        }
    }
    match http_get(source, user_agent).await {
        Ok(result) => {
            let write_cache = || -> Result<()> {
                if let Some(parent) = cache.parent() { std::fs::create_dir_all(parent)?; }
                std::fs::write(cache, &result.text)?;
                std::fs::write(&sidecar, serde_json::to_vec(&result.metadata)?)?;
                Ok(())
            };
            if let Err(e) = write_cache() {
                warn!("{source}: cannot write cache: {e:#}");
            }
            Ok(result)
        }
        Err(e) => match std::fs::read_to_string(cache) {
            Ok(text) => {
                warn!("{source}: download failed ({e:#}); using stale cache");
                Ok(FetchResult { text, from: "stale cache", metadata: cached_metadata(), last_error: Some(format!("{e:#}")) })
            }
            Err(_) => Err(e.context(format!("download {source}"))),
        },
    }
}

pub async fn load(set: &RuleSet, base: &Path, max_age: Duration) -> Result<usize> {
    let result = fetch(&set.source, base, max_age, None).await.with_context(|| format!("rule set {}", set.source))?;
    Ok(set.install(&result.text, result.from))
}

/// Re-downloads remote sets every `interval`.
/// Stops once the sets are dropped (their router was replaced by a reload).
pub fn spawn_refresh(sets: Vec<Arc<RuleSet>>, interval: Duration) {
    let remote: Vec<std::sync::Weak<RuleSet>> = sets.iter().filter(|s| s.is_remote()).map(Arc::downgrade).collect();
    if remote.is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let live: Vec<Arc<RuleSet>> = remote.iter().filter_map(std::sync::Weak::upgrade).collect();
            if live.is_empty() {
                return;
            }
            for s in &live {
                // max_age zero forces a download; the cache is still the fallback.
                if let Err(e) = load(s, Path::new("."), Duration::ZERO).await {
                    warn!("{e:#}");
                }
            }
        }
    });
}

pub const DEFAULT_USER_AGENT: &str = concat!("clash.meta mihomo/1.18.10 Sluice/", env!("CARGO_PKG_VERSION"));

fn decode_body(body: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>> {
    fn bounded(reader: impl Read) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.take(MAX_BODY as u64 + 1).read_to_end(&mut out)?;
        if out.len() > MAX_BODY { bail!("decoded body too large"); }
        Ok(out)
    }
    let mut body = body;
    for encoding in encoding.unwrap_or_default().split(',').rev().map(str::trim) {
        body = match encoding.to_ascii_lowercase().as_str() {
            "" | "identity" => body,
            "gzip" | "x-gzip" => bounded(flate2::read::MultiGzDecoder::new(body.as_slice()))?,
            "deflate" => bounded(flate2::read::ZlibDecoder::new(body.as_slice()))
                .or_else(|_| bounded(flate2::read::DeflateDecoder::new(body.as_slice())))?,
            other => bail!("unsupported Content-Encoding {other:?}"),
        };
    }
    Ok(body)
}

/// HTTP/1.1 GET over the egress path, following at most five redirects.
pub async fn http_get(source: &str, user_agent: Option<&str>) -> Result<FetchResult> {
    let user_agent = user_agent.unwrap_or(DEFAULT_USER_AGENT);
    http::HeaderValue::from_str(user_agent).context("bad user-agent")?;
    let mut url = url::Url::parse(source)?;
    for redirects in 0..=5 {
        if !matches!(url.scheme(), "http" | "https") { bail!("unsupported URL scheme"); }
        let host = url.host_str().ok_or_else(|| anyhow!("URL without host"))?.trim_matches(['[', ']']);
        let port = url.port_or_known_default().ok_or_else(|| anyhow!("URL without port"))?;
        let (status, headers, body) = tokio::time::timeout(Duration::from_secs(30), async {
            let tcp = connect_tcp(host, port).await?;
            let stream: BoxStream = if url.scheme() == "https" {
                let (connector, sni) = tls_client(host, None, false)?;
                Box::new(connector.connect(sni, tcp).await?)
            } else { Box::new(tcp) };
            let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
            let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
            let request = http::Request::builder().uri(path)
                .header(http::header::HOST, authority)
                .header(http::header::USER_AGENT, user_agent)
                .header(http::header::ACCEPT_ENCODING, "gzip")
                .header(http::header::CONNECTION, "close")
                .body(http_body_util::Empty::<bytes::Bytes>::new())?;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .title_case_headers(true).max_buf_size(65536)
                .handshake(hyper_util::rt::TokioIo::new(stream)).await?;
            // Dropping this set closes the connection even if the peer ignores
            // Connection: close, or if the enclosing download times out.
            let mut driver = tokio::task::JoinSet::new();
            driver.spawn(connection);
            let response = sender.send_request(request).await.context("read HTTP response")?;
            let (parts, body) = response.into_parts();
            if body.size_hint().lower() > MAX_BODY as u64 { bail!("HTTP body too large"); }
            // Hyper finishes Content-Length/chunked bodies at their protocol
            // boundary instead of waiting for a possibly delayed TCP/TLS EOF.
            let body = http_body_util::Limited::new(body, MAX_BODY).collect().await
                .map_err(anyhow::Error::from_boxed).context("read HTTP body")?.to_bytes();
            Ok::<_, anyhow::Error>((parts.status.as_u16(), parts.headers, body))
        }).await.map_err(|_| anyhow!("download timed out"))??;
        let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim);
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if redirects == 5 { bail!("too many redirects (limit 5)"); }
            let location = header("location").ok_or_else(|| anyhow!("HTTP {status}: redirect without Location"))?;
            url = url.join(location)?;
            continue;
        }
        let body = decode_body(body.to_vec(), header("content-encoding"))?;
        if !(200..300).contains(&status) {
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body[..body.len().min(200)]));
        }
        let mut metadata = FetchMetadata::from_headers(header("subscription-userinfo"), header("profile-update-interval"));
        metadata.last_fetch = Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs());
        return Ok(FetchResult { text: String::from_utf8_lossy(&body).into_owned(), from: "network", metadata, last_error: None });
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Each fixture runs exclusively on loopback, with no DNS or external requests.
    async fn mock_http(responses: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let byte = socket.read_u8().await.unwrap();
                    request.push(byte);
                    if request.ends_with(b"\r\n\r\n") { break; }
                }
                requests.push(String::from_utf8(request).unwrap());
                socket.write_all(&response).await.unwrap();
                socket.shutdown().await.unwrap();
            }
            requests
        });
        (url, task)
    }

    fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut result = format!("HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n").into_bytes();
        result.extend_from_slice(body);
        result
    }

    #[test]
    fn subscription_userinfo_headers() {
        let meta = FetchMetadata::from_headers(Some(" upload = 12 ; download=34; total = 1000 ; expire=1800000000; unknown=1"), Some(" 24 "));
        assert_eq!((meta.upload, meta.download, meta.total, meta.expire, meta.update_interval_hours), (Some(12), Some(34), Some(1000), Some(1800000000), Some(24)));
        let partial = FetchMetadata::from_headers(Some("download=0; upload=invalid; total=-1; broken"), Some("invalid"));
        assert_eq!(partial, FetchMetadata { download: Some(0), ..Default::default() });
        assert_eq!(FetchMetadata::from_headers(None, None), FetchMetadata::default());
    }

    #[test]
    fn compressed_bodies_decode_offline() {
        let original = "HK = trojan, h, 443, password=p\n禁止访问".as_bytes();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(original).unwrap();
        let gzip = gzip.finish().unwrap();
        assert_eq!(decode_body(gzip, Some("gzip")).unwrap(), original);
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(original).unwrap();
        assert_eq!(decode_body(zlib.finish().unwrap(), Some("deflate")).unwrap(), original);
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(original).unwrap();
        assert_eq!(decode_body(raw.finish().unwrap(), Some("deflate")).unwrap(), original);
        assert!(decode_body(b"truncated".to_vec(), Some("gzip")).is_err());
    }

    #[tokio::test]
    async fn http_redirects_gzip_chunked_and_default_agent() {
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all("HK = trojan, localhost, 443, password=p\n".as_bytes()).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut chunked = Vec::new();
        for chunk in gzip.chunks(7) {
            chunked.extend_from_slice(format!("{:x};extension=yes\r\n", chunk.len()).as_bytes());
            chunked.extend_from_slice(chunk);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\nX-Trailer: yes\r\n\r\n");
        let (destination, final_server) = mock_http(vec![response("200 OK", "Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nSubscription-Userinfo: upload=1; download=2; total=3; expire=4\r\nProfile-Update-Interval: 12\r\n", &chunked)]).await;
        let (origin, redirects) = mock_http(vec![
            response("302 Found", "Location: ../next?token=1\r\n", b""),
            response("307 Temporary Redirect", &format!("Location: {destination}/final\r\n"), b""),
        ]).await;
        let result = http_get(&format!("{origin}/dir/start"), None).await.unwrap();
        assert!(result.text.starts_with("HK = trojan"));
        assert_eq!(result.metadata.total, Some(3));
        assert_eq!(result.metadata.update_interval_hours, Some(12));
        assert!(result.metadata.last_fetch.is_some());
        let requests = redirects.await.unwrap();
        assert!(requests[0].starts_with("GET /dir/start HTTP/1.1"));
        assert!(requests[1].starts_with("GET /next?token=1 HTTP/1.1"));
        for request in requests.into_iter().chain(final_server.await.unwrap()) {
            assert!(request.contains(&format!("User-Agent: {DEFAULT_USER_AGENT}\r\n")));
            assert!(request.contains("Accept-Encoding: gzip\r\n"));
        }
    }

    #[tokio::test]
    async fn http_complete_bodies_do_not_wait_for_connection_close() {
        for chunked in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (release, keep_open) = tokio::sync::oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") { request.push(socket.read_u8().await.unwrap()); }
                let response = if chunked {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=yes\r\nhello\r\n0\r\nX-Trailer: done\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".as_slice()
                };
                for fragment in response.chunks(7) { socket.write_all(fragment).await.unwrap(); }
                let _ = keep_open.await;
            });
            let result = tokio::time::timeout(Duration::from_secs(1), http_get(&url, None)).await;
            let _ = release.send(());
            server.await.unwrap();
            assert_eq!(result.expect("complete HTTP body must not wait for EOF").unwrap().text, "hello");
        }
    }

    #[tokio::test]
    async fn http_rejects_truncated_or_oversized_bodies() {
        for (headers, body) in [
            ("Content-Length: 5\r\n".to_string(), b"hi".as_slice()),
            ("Transfer-Encoding: chunked\r\n".to_string(), b"5\r\nhi".as_slice()),
            (format!("Content-Length: {}\r\n", MAX_BODY + 1), b"".as_slice()),
            ("Transfer-Encoding: chunked\r\n".to_string(), b"ffffffffffffffff\r\n".as_slice()),
        ] {
            let (url, server) = mock_http(vec![response("200 OK", &headers, body)]).await;
            assert!(http_get(&url, None).await.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn http_deflate_custom_agent_and_2xx() {
        for raw in [false, true] {
            let body = if raw {
                let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(b"nodes").unwrap();
                encoder.finish().unwrap()
            } else {
                let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(b"nodes").unwrap();
                encoder.finish().unwrap()
            };
            let (url, server) = mock_http(vec![response("201 Created", &format!("Content-Encoding: deflate\r\nContent-Length: {}\r\n", body.len()), &body)]).await;
            assert_eq!(http_get(&url, Some("Surge/5.0")).await.unwrap().text, "nodes");
            assert!(server.await.unwrap()[0].contains("User-Agent: Surge/5.0\r\n"));
        }
    }

    #[tokio::test]
    async fn http_errors_include_status_and_bounded_lossy_body() {
        let mut body = "禁止访问".as_bytes().to_vec();
        body.push(0xff);
        body.extend_from_slice(&[b'x'; 300]);
        let (url, server) = mock_http(vec![response("403 Forbidden", "", &body)]).await;
        let error = http_get(&url, None).await.err().unwrap().to_string();
        assert!(error.starts_with("HTTP 403: 禁止访问�"));
        assert!(error.len() < 230);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_redirect_limit_allows_five_hops() {
        let redirect = response("302 Found", "Location: /again\r\n", b"");
        let mut responses = vec![redirect.clone(); 5];
        responses.push(response("200 OK", "", b"ok"));
        let (url, server) = mock_http(responses).await;
        assert_eq!(http_get(&url, None).await.unwrap().text, "ok");
        assert_eq!(server.await.unwrap().len(), 6);
        let (url, server) = mock_http(vec![redirect; 6]).await;
        assert!(http_get(&url, None).await.err().unwrap().to_string().contains("too many redirects"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cached_metadata_survives_reload_and_stale_fallback() {
        let (url, server) = mock_http(vec![
            response("200 OK", "Subscription-Userinfo: download=8; total=100\r\nProfile-Update-Interval: 6\r\n", b"nodes"),
            response("403 Forbidden", "", "禁止访问".as_bytes()),
        ]).await;
        let dir = std::env::temp_dir().join(format!("sluice-sub-cache-{}-{}", std::process::id(), url.rsplit(':').next().unwrap()));
        let cache = dir.join("body.txt");
        let first = fetch_cached(&url, Duration::ZERO, None, &cache).await.unwrap();
        let cached = fetch_cached(&url, Duration::from_secs(3600), None, &cache).await.unwrap();
        assert_eq!(cached.from, "cache");
        assert_eq!(cached.metadata, first.metadata);
        let stale = fetch_cached(&url, Duration::ZERO, None, &cache).await.unwrap();
        assert_eq!(stale.from, "stale cache");
        assert_eq!(stale.text, "nodes");
        assert_eq!(stale.metadata, first.metadata);
        assert!(stale.last_error.unwrap().contains("HTTP 403: 禁止访问"));
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert_ne!(cache_path(&url, None), cache_path(&url, Some("custom")));
    }

    #[test]
    fn rule_list() {
        let text = "# comment\nDOMAIN,exact.com\nDOMAIN-SUFFIX,google.com\nDOMAIN-KEYWORD,ads\nIP-CIDR,10.0.0.0/8,no-resolve\nUSER-AGENT,foo*\n";
        let (d, skipped) = SetData::parse(text, SetKind::Rules);
        assert_eq!((d.len(), skipped), (4, 1));
        assert!(d.match_domain("exact.com") && !d.match_domain("a.exact.com"));
        assert!(d.match_domain("google.com") && d.match_domain("mail.google.com") && !d.match_domain("notgoogle.com"));
        assert!(d.match_domain("x.ads.net"));
        assert!(d.match_ip("10.2.3.4".parse().unwrap()) && !d.match_ip("11.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn file_url_rule_set_uses_shared_fetcher() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local-check/rules.list");
        let source = url::Url::from_file_path(path).unwrap();
        let set = RuleSet::new(source.as_str(), SetKind::Rules);
        assert!(load(&set, Path::new("/unused"), Duration::ZERO).await.unwrap() > 0);
        assert!(set.data.read().unwrap().match_domain("set.test"));
        assert!(fetch("file://remote.example/rules.list", Path::new("."), Duration::ZERO, None).await.is_err());
    }

    #[test]
    fn extended_types_in_rule_list() {
        let text = "PROCESS-NAME,curl\nDST-PORT,22\nAND,((DOMAIN,a.com),(PROTOCOL,UDP))\nURL-REGEX,^http://x\nBOGUS,1\n";
        let (d, skipped) = SetData::parse(text, SetKind::Rules);
        assert_eq!((d.len(), skipped), (4, 1));
        assert!(matches!(d.others()[0], Matcher::ProcessName(ref n) if n == "curl"));
        assert!(matches!(d.others()[2], Matcher::And(_)));
    }

    #[test]
    fn domain_list_and_clash_payload() {
        let (d, _) = SetData::parse("apple.com\n.icloud.com\n", SetKind::Domains);
        assert!(d.match_domain("apple.com") && !d.match_domain("www.apple.com"));
        assert!(d.match_domain("icloud.com") && d.match_domain("p1.icloud.com"));
        let (d, _) = SetData::parse("payload:\n  - '+.github.com'\n  - 'raw.example.org'\n", SetKind::Domains);
        assert!(d.match_domain("api.github.com") && d.match_domain("raw.example.org"));
    }

}
