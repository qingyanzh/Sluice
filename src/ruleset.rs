//! External rule lists: `RULE-SET` (Surge rule lines without policy) and `DOMAIN-SET`
//! (one domain per line, `.example.com` meaning the domain and its subdomains).
//! Lists are loaded from a file or URL, cached on disk and refreshed periodically.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use log::{info, warn};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::rule::Cidr;
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
        let mut parts = line.split(',').map(str::trim);
        let (Some(kind), Some(value)) = (parts.next(), parts.next()) else { return false };
        let value = value.to_ascii_lowercase();
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
            _ => return false,
        }
        true
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len() + self.keyword.len() + self.cidr.len()
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

fn cache_path(source: &str) -> PathBuf {
    cache_dir().join(format!("{}.txt", &hex::encode(Sha256::digest(source.as_bytes()))[..24]))
}

fn age(path: &Path) -> Option<Duration> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

/// Reads `source` (a path relative to `base`, or an http(s) URL). URLs come from the disk
/// cache while younger than `max_age`, else from the network, falling back to a stale
/// cache if the download fails. Returns the text and where it came from.
pub async fn fetch(source: &str, base: &Path, max_age: Duration) -> Result<(String, &'static str)> {
    if !(source.starts_with("http://") || source.starts_with("https://")) {
        let path = base.join(source);
        let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        return Ok((text, "file"));
    }
    let cache = cache_path(source);
    if age(&cache).is_some_and(|a| a < max_age) {
        if let Ok(text) = std::fs::read_to_string(&cache) {
            return Ok((text, "cache"));
        }
    }
    match http_get(source).await {
        Ok(text) => {
            if let Err(e) = std::fs::create_dir_all(cache_dir()).and_then(|_| std::fs::write(&cache, &text)) {
                warn!("{source}: cannot write cache: {e}");
            }
            Ok((text, "network"))
        }
        Err(e) => match std::fs::read_to_string(&cache) {
            Ok(text) => {
                warn!("{source}: download failed ({e:#}); using stale cache");
                Ok((text, "stale cache"))
            }
            Err(_) => Err(e.context(format!("download {source}"))),
        },
    }
}

pub async fn load(set: &RuleSet, base: &Path, max_age: Duration) -> Result<usize> {
    let (text, from) = fetch(&set.source, base, max_age).await.with_context(|| format!("rule set {}", set.source))?;
    Ok(set.install(&text, from))
}

/// Re-downloads remote sets every `interval`.
pub fn spawn_refresh(sets: Vec<Arc<RuleSet>>, interval: Duration) {
    let remote: Vec<_> = sets.into_iter().filter(|s| s.is_remote()).collect();
    if remote.is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            for s in &remote {
                // max_age zero forces a download; the cache is still the fallback.
                if let Err(e) = load(s, Path::new("."), Duration::ZERO).await {
                    warn!("{e:#}");
                }
            }
        }
    });
}

struct Url<'a> {
    https: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(url: &str) -> Result<Url<'_>> {
    let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => bail!("unsupported URL {url:?}"),
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse().map_err(|_| anyhow!("bad port in {url}"))?),
        _ => (authority, if https { 443 } else { 80 }),
    };
    Ok(Url { https, host: host.trim_matches(['[', ']']), port, path })
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").ok_or_else(|| anyhow!("bad chunked body"))?;
        let size_str = std::str::from_utf8(&body[..line_end])?.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| anyhow!("bad chunk size {size_str:?}"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            bail!("truncated chunked body");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Minimal HTTP/1.1 GET over the egress path, following up to 5 redirects.
pub async fn http_get(url: &str) -> Result<String> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let u = parse_url(&url)?;
        let tcp = connect_tcp(u.host, u.port).await?;
        let mut s: BoxStream = if u.https {
            let (connector, sni) = tls_client(u.host, None, false)?;
            Box::new(connector.connect(sni, tcp).await?)
        } else {
            Box::new(tcp)
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Sluice/{}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            u.path,
            u.host,
            env!("CARGO_PKG_VERSION")
        );
        s.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), (&mut s).take(MAX_BODY as u64).read_to_end(&mut raw))
            .await
            .map_err(|_| anyhow!("download timed out"))??;
        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("malformed HTTP response"))?;
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        let header = |name: &str| {
            head.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        if (300..400).contains(&status) {
            let loc = header("location").ok_or_else(|| anyhow!("redirect without Location"))?;
            url = if loc.starts_with("http") {
                loc
            } else {
                format!("{}://{}:{}{loc}", if u.https { "https" } else { "http" }, u.host, u.port)
            };
            continue;
        }
        if status != 200 {
            bail!("HTTP {status}");
        }
        let body = &raw[head_end + 4..];
        let body = if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            dechunk(body)?
        } else {
            body.to_vec()
        };
        return Ok(String::from_utf8_lossy(&body).into_owned());
    }
    bail!("too many redirects")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn domain_list_and_clash_payload() {
        let (d, _) = SetData::parse("apple.com\n.icloud.com\n", SetKind::Domains);
        assert!(d.match_domain("apple.com") && !d.match_domain("www.apple.com"));
        assert!(d.match_domain("icloud.com") && d.match_domain("p1.icloud.com"));
        let (d, _) = SetData::parse("payload:\n  - '+.github.com'\n  - 'raw.example.org'\n", SetKind::Domains);
        assert!(d.match_domain("api.github.com") && d.match_domain("raw.example.org"));
    }

    #[test]
    fn urls_and_chunked() {
        let u = parse_url("https://raw.example.com/a/b.txt").unwrap();
        assert_eq!((u.https, u.host, u.port, u.path), (true, "raw.example.com", 443, "/a/b.txt"));
        let u = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!((u.host, u.port, u.path), ("127.0.0.1", 8080, "/"));
        assert_eq!(dechunk(b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n").unwrap(), b"hello world");
    }
}
