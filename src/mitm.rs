//! HTTPS decryption (`[MITM]`) and the HTTP engine that applies [`rewrite`](crate::rewrite)s.
//!
//! A flow to a matching `hostname` is answered with a leaf certificate signed on the fly by
//! the configured CA, then served as HTTP/1.1 or HTTP/2 (per ALPN). Every request is routed
//! on its own, with its full URL for URL-REGEX rules, and sent upstream over a fresh TLS
//! connection that verifies the real server (unless `skip-server-cert-verify`).
//!
//! ```text
//! [MITM]
//! hostname = *.example.com, example.com, -skip.example.com
//! ca-p12 = <base64 PKCS#12, or a path to one>
//! ca-passphrase = secret
//! # or PEM files; with neither, the CA from `sluice mitm gen-ca` is used
//! ca-cert = /path/ca.crt
//! ca-key = /path/ca.key
//! skip-server-cert-verify = false
//! h2 = true
//! ```

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskCx, Poll};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Request, Response, StatusCode, Uri, Version};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::debug;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::rewrite::{Rewrites, UrlOutcome};
use crate::router::Router;
use crate::rule::{ConnInfo, Proto};
use crate::util::{AsyncStream, BoxStream, Host, Target};

type Body = BoxBody<Bytes, hyper::Error>;

/// Largest body buffered for a `[Body Rewrite]`; bigger ones pass through unchanged.
const MAX_REWRITE_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct MitmConfig {
    pub hostnames: Vec<String>,
    pub ca_p12: Option<String>,
    pub ca_passphrase: Option<String>,
    pub ca_cert: Option<String>,
    pub ca_key: Option<String>,
    pub skip_server_cert_verify: bool,
    /// Offer HTTP/2 to decrypted clients.
    pub h2: bool,
}

impl MitmConfig {
    pub fn set(&mut self, k: &str, v: &str) {
        let flag = || matches!(v, "true" | "1");
        match k {
            "hostname" => self.hostnames = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
            "ca-p12" => self.ca_p12 = Some(v.to_string()),
            "ca-passphrase" => self.ca_passphrase = Some(v.to_string()),
            "ca-cert" => self.ca_cert = Some(v.to_string()),
            "ca-key" => self.ca_key = Some(v.to_string()),
            "skip-server-cert-verify" => self.skip_server_cert_verify = flag(),
            "h2" => self.h2 = flag(),
            _ => {}
        }
    }
}

impl MitmConfig {
    pub fn new() -> Self {
        MitmConfig { h2: true, ..Default::default() }
    }
}

/// Where `sluice mitm gen-ca` keeps its CA.
pub fn default_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join("Library/Application Support/Sluice")
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(rest),
        None => PathBuf::from(p),
    }
}

pub struct Ca {
    cert_der: CertificateDer<'static>,
    issuer: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    /// A new self-signed CA: `(cert_pem, key_pem)`.
    pub fn generate() -> Result<(String, String)> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        let tag = hex::encode(rand::random::<[u8; 3]>()).to_uppercase();
        dn.push(DnType::CommonName, format!("Sluice MITM CA {tag}"));
        dn.push(DnType::OrganizationName, "Sluice");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        p.not_after = now + time::Duration::days(3650);
        let cert = p.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    fn from_parts(cert_der: CertificateDer<'static>, key: KeyPair) -> Result<Self> {
        let params = CertificateParams::from_ca_cert_der(&cert_der).context("parse CA certificate")?;
        // Re-signed only to serve as the issuer: subject and key are what leaves refer to.
        let issuer = params.self_signed(&key)?;
        Ok(Ca { cert_der, issuer, key })
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let der = pem_block(cert_pem, "CERTIFICATE")?;
        Self::from_parts(CertificateDer::from(der), KeyPair::from_pem(key_pem).context("parse CA key")?)
    }

    pub fn from_p12(data: &[u8], pass: &str) -> Result<Self> {
        let ks = p12_keystore::KeyStore::from_pkcs12(data, pass).map_err(|e| anyhow!("read PKCS#12: {e}"))?;
        let chain = ks
            .entries()
            .find_map(|(_, e)| match e {
                p12_keystore::KeyStoreEntry::PrivateKeyChain(c) => Some(c.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("PKCS#12 has no private key"))?;
        let cert = chain.chain().first().ok_or_else(|| anyhow!("PKCS#12 has no certificate"))?;
        let key = KeyPair::try_from(chain.key()).context("parse PKCS#12 key")?;
        Self::from_parts(CertificateDer::from(cert.as_der().to_vec()), key)
    }

    pub fn load(cfg: &MitmConfig) -> Result<Self> {
        if let Some(p12) = &cfg.ca_p12 {
            let path = expand(p12);
            let data = if path.is_file() { std::fs::read(&path)? } else { p12.as_bytes().to_vec() };
            let text = String::from_utf8_lossy(&data);
            let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            let der = base64::engine::general_purpose::STANDARD.decode(&compact).unwrap_or(data);
            return Self::from_p12(&der, cfg.ca_passphrase.as_deref().unwrap_or("")).context("ca-p12");
        }
        let dir = default_dir();
        let cert = cfg.ca_cert.as_deref().map(expand).unwrap_or_else(|| dir.join("ca.crt"));
        let key = cfg.ca_key.as_deref().map(expand).unwrap_or_else(|| dir.join("ca.key"));
        let read = |p: &Path| {
            std::fs::read_to_string(p)
                .with_context(|| format!("read MITM CA {} (create one with `sluice mitm gen-ca`, or set ca-p12)", p.display()))
        };
        Self::from_pem(&read(&cert)?, &read(&key)?)
    }

    /// A leaf for `host` signed by this CA, carrying `key`'s public key.
    pub fn leaf(&self, host: &str, key: &KeyPair) -> Result<CertificateDer<'static>> {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into()?),
        }];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        p.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        // Apple rejects TLS leaves valid for more than 398 days.
        p.not_after = now + time::Duration::days(365);
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()[..]));
        Ok(p.signed_by(key, &self.issuer, &self.key)?.der().clone())
    }
}

fn pem_block(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or_else(|| anyhow!("no {label} in PEM"))? + begin.len();
    let stop = pem[start..].find(&end).ok_or_else(|| anyhow!("unterminated {label} PEM"))? + start;
    let b64: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}

/// `sluice mitm gen-ca`: writes `ca.crt` / `ca.key` to [`default_dir`] and prints how to trust it.
pub fn gen_ca(force: bool) -> Result<()> {
    let dir = default_dir();
    let (crt, key) = (dir.join("ca.crt"), dir.join("ca.key"));
    if crt.exists() && !force {
        bail!("{} already exists (pass --force to replace it)", crt.display());
    }
    std::fs::create_dir_all(&dir)?;
    let (cert_pem, key_pem) = Ca::generate()?;
    std::fs::write(&crt, cert_pem)?;
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&key)?;
        f.write_all(key_pem.as_bytes())?;
    }
    println!("wrote {} and {}", crt.display(), key.display());
    println!("Sluice does not install it. To trust it for HTTPS decryption, run:");
    println!("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"{}\"", crt.display());
    println!("then list the hosts to decrypt under [MITM] hostname = ...");
    Ok(())
}

/// One `hostname` entry: a glob (`*` wildcard) with an optional `:port` (default 443).
#[derive(Debug, Clone)]
struct HostPat {
    glob: String,
    port: Option<u16>,
}

impl HostPat {
    fn parse(s: &str) -> Self {
        match s.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => HostPat { glob: h.to_ascii_lowercase(), port: p.parse().ok() },
            _ => HostPat { glob: s.to_ascii_lowercase(), port: None },
        }
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        // Without a port an entry covers 443; an exclusion covers any port.
        self.port.is_none_or(|p| p == port) && glob(&self.glob, host)
    }
}

fn glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == s[si] || p[pi] == b'?') {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

pub struct Mitm {
    include: Vec<HostPat>,
    exclude: Vec<HostPat>,
    ca: Ca,
    leaf_key: KeyPair,
    certs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    pub skip_verify: bool,
    h2: bool,
}

impl Mitm {
    /// `None` when no hostnames are listed.
    pub fn new(cfg: &MitmConfig) -> Result<Option<Self>> {
        if cfg.hostnames.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::with_ca(cfg, Ca::load(cfg)?)?))
    }

    pub fn with_ca(cfg: &MitmConfig, ca: Ca) -> Result<Self> {
        let (exclude, include): (Vec<_>, Vec<_>) = cfg.hostnames.iter().partition(|h| h.starts_with('-'));
        Ok(Mitm {
            include: include.iter().map(|h| HostPat::parse(h)).collect(),
            exclude: exclude.iter().map(|h| HostPat { port: None, ..HostPat::parse(&h[1..]) }).collect(),
            ca,
            leaf_key: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            certs: Mutex::new(HashMap::new()),
            skip_verify: cfg.skip_server_cert_verify,
            h2: cfg.h2,
        })
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let on = |p: &HostPat| p.matches(&host, port) && (p.port.is_some() || port == 443);
        !self.exclude.iter().any(|p| p.matches(&host, port)) && self.include.iter().any(on)
    }

    /// TLS server config presenting a leaf for `host`, cached per host.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(c) = self.certs.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let leaf = self.ca.leaf(host, &self.leaf_key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf, self.ca.cert_der.clone()], key)?;
        cfg.alpn_protocols = if self.h2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
        let cfg = Arc::new(cfg);
        let mut certs = self.certs.lock().unwrap();
        if certs.len() > 1024 {
            certs.clear();
        }
        certs.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// How an inbound should treat a TCP flow to `target`, before plain relaying.
pub enum Intercept {
    Tls,
    PlainHttp,
}

pub fn intercept_for(router: &Router, target: &Target) -> Option<Intercept> {
    if router.mitm().is_some_and(|m| m.matches(&target.host_str(), target.port)) {
        return Some(Intercept::Tls);
    }
    (target.port == 80 && !router.rewrites().is_empty()).then_some(Intercept::PlainHttp)
}

/// Decrypts a client's TLS to `target` and serves its HTTP requests.
pub async fn serve_tls<S: AsyncStream + 'static>(stream: S, router: Arc<Router>, target: Target, base: ConnInfo) -> Result<()> {
    let mitm = router.mitm().cloned().ok_or_else(|| anyhow!("MITM is off"))?;
    let tls = tokio_rustls::TlsAcceptor::from(mitm.server_config(&target.host_str())?).accept(stream).await.context("MITM TLS handshake")?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let session = Arc::new(Session::new(router, base, "https", target));
    serve_http(TokioIo::new(tls), session, h2).await
}

/// Serves plain HTTP from a client (a proxy client, or a TUN flow to port 80); `pre` is what
/// was already read from it.
pub async fn serve_plain<S: AsyncStream + 'static>(stream: S, pre: Vec<u8>, router: Arc<Router>, target: Target, base: ConnInfo) -> Result<()> {
    let session = Arc::new(Session::new(router, base, "http", target));
    serve_http(TokioIo::new(Prefixed::new(pre, stream)), session, false).await
}

async fn serve_http<I>(io: I, session: Arc<Session>, h2: bool) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req| {
        let s = session.clone();
        async move { Ok::<_, Infallible>(s.handle(req).await) }
    });
    if h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await?;
    } else {
        hyper::server::conn::http1::Builder::new().serve_connection(io, svc).with_upgrades().await?;
    }
    Ok(())
}

enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Body>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
}

/// One client connection's state: where its requests default to, and reusable upstreams.
struct Session {
    router: Arc<Router>,
    base: ConnInfo,
    scheme: &'static str,
    default: Target,
    pool: Mutex<HashMap<String, Vec<Sender>>>,
}

fn simple(status: StatusCode, location: Option<&str>) -> Response<Body> {
    let mut r = Response::new(Empty::new().map_err(|n| match n {}).boxed());
    *r.status_mut() = status;
    if let Some(l) = location.and_then(|l| HeaderValue::from_str(l).ok()) {
        r.headers_mut().insert(header::LOCATION, l);
    }
    r
}

fn full(b: Vec<u8>) -> Body {
    Full::new(Bytes::from(b)).map_err(|n| match n {}).boxed()
}

const HOP: [&str; 7] = ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "transfer-encoding", "upgrade"];

fn strip_hop(h: &mut HeaderMap, upgrade: bool) {
    for n in HOP {
        if !(upgrade && matches!(n, "connection" | "upgrade")) {
            h.remove(n);
        }
    }
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
}

/// Buffers a body for rewriting; `Err` gives back what was read if it is too big to rewrite.
async fn collect(body: Body) -> Result<Vec<u8>> {
    let limited = http_body_util::Limited::new(body, MAX_REWRITE_BODY);
    Ok(limited.collect().await.map_err(|e| anyhow!("body: {e}"))?.to_bytes().to_vec())
}

impl Session {
    fn new(router: Arc<Router>, base: ConnInfo, scheme: &'static str, default: Target) -> Self {
        Session { router, base, scheme, default, pool: Mutex::new(HashMap::new()) }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<Body> {
        match self.forward(req).await {
            Ok(r) => r,
            Err(e) => {
                debug!("MITM {}: {e:#}", self.default);
                simple(StatusCode::BAD_GATEWAY, None)
            }
        }
    }

    /// The full URL a request names: absolute-form, `:authority`, `Host`, or the flow's target.
    fn url_of(&self, req: &Request<Incoming>) -> String {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(String::from))
            .unwrap_or_else(|| self.default.to_string());
        let scheme = req.uri().scheme_str().unwrap_or(self.scheme);
        let default_port = if scheme == "https" { ":443" } else { ":80" };
        let authority = authority.strip_suffix(default_port).unwrap_or(&authority);
        let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
        format!("{scheme}://{authority}{path}")
    }

    async fn forward(&self, mut req: Request<Incoming>) -> Result<Response<Body>> {
        let rw: Arc<Rewrites> = self.router.rewrites().clone();
        let mut url = self.url_of(&req);
        match rw.rewrite_url(&url) {
            UrlOutcome::Pass => {}
            UrlOutcome::Redirect(code, to) => {
                debug!("URL rewrite {url} -> {code} {to}");
                return Ok(simple(StatusCode::from_u16(code)?, Some(&to)));
            }
            UrlOutcome::Reject => return Ok(simple(StatusCode::NOT_FOUND, None)),
            UrlOutcome::Rewritten(to) => url = to,
        }
        let uri: Uri = url.parse().with_context(|| format!("bad URL {url:?}"))?;
        let https = uri.scheme_str() == Some("https");
        let host = uri.host().ok_or_else(|| anyhow!("no host in {url}"))?.trim_start_matches('[').trim_end_matches(']').to_string();
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let target = Target::new(&host, port);

        let upgrade = is_upgrade(req.headers());
        let down_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
        let (mut parts, body) = req.into_parts();
        rw.rewrite_headers(false, &url, &mut parts.headers);
        strip_hop(&mut parts.headers, upgrade);
        if rw.has_body(true, &url) {
            // So the response arrives uncompressed and can be rewritten.
            parts.headers.remove(header::ACCEPT_ENCODING);
        }
        let mut body: Body = body.boxed();
        if rw.has_body(false, &url) {
            let raw = collect(body).await?;
            body = full(rw.rewrite_body(false, &url, &raw));
            parts.headers.remove(header::CONTENT_LENGTH);
        }

        let mut ctx = self.base.child(if https { Proto::Https } else { Proto::Http }).with_url(url.clone());
        ctx.mitm = https;
        let d = self.router.decide_logged(&target, &ctx).await?;
        let key = format!("{}|{}|{target}", d.outbound, uri.scheme_str().unwrap_or("http"));
        let mut sender = match (!upgrade).then(|| self.take(&key)).flatten() {
            Some(s) => s,
            None => match self.connect(&d.outbound, &target, https, upgrade).await? {
                Some(s) => s,
                None => return Ok(simple(StatusCode::FORBIDDEN, None)),
            },
        };

        let authority = uri.authority().map(|a| a.as_str().to_string()).unwrap_or_else(|| host.clone());
        let up = match &sender {
            Sender::H1(_) => {
                parts.headers.insert(header::HOST, HeaderValue::from_str(&authority)?);
                parts.version = Version::HTTP_11;
                parts.uri = uri.path_and_query().map_or("/", |p| p.as_str()).parse()?;
                Request::from_parts(parts, body)
            }
            Sender::H2(_) => {
                parts.headers.remove(header::HOST);
                parts.version = Version::HTTP_2;
                parts.uri = uri.clone();
                Request::from_parts(parts, body)
            }
        };
        let mut resp = match &mut sender {
            Sender::H1(s) => s.send_request(up).await?,
            Sender::H2(s) => s.send_request(up).await?,
        };
        if !upgrade {
            self.pool.lock().unwrap().entry(key).or_default().push(sender);
        }

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some(down) = down_upgrade {
                let upstream = hyper::upgrade::on(&mut resp);
                tokio::spawn(async move {
                    if let (Ok(d), Ok(u)) = (down.await, upstream.await) {
                        let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(d), &mut TokioIo::new(u)).await;
                    }
                });
            }
            let (parts, _) = resp.into_parts();
            return Ok(Response::from_parts(parts, Empty::new().map_err(|n| match n {}).boxed()));
        }

        let (mut parts, body) = resp.into_parts();
        rw.rewrite_headers(true, &url, &mut parts.headers);
        strip_hop(&mut parts.headers, false);
        parts.version = Version::HTTP_11;
        let encoded = parts.headers.get(header::CONTENT_ENCODING).is_some_and(|e| e != "identity");
        let mut body: Body = body.boxed();
        if rw.has_body(true, &url) && !encoded {
            let raw = collect(body).await?;
            body = full(rw.rewrite_body(true, &url, &raw));
            parts.headers.remove(header::CONTENT_LENGTH);
        }
        Ok(Response::from_parts(parts, body))
    }

    /// A pooled upstream for `key` that can take a request now.
    fn take(&self, key: &str) -> Option<Sender> {
        let mut pool = self.pool.lock().unwrap();
        let list = pool.get_mut(key)?;
        list.retain(|s| match s {
            Sender::H1(s) => !s.is_closed(),
            Sender::H2(s) => !s.is_closed(),
        });
        let i = list.iter().position(|s| match s {
            Sender::H1(s) => s.is_ready(),
            Sender::H2(s) => s.is_ready(),
        })?;
        Some(list.swap_remove(i))
    }

    async fn connect(&self, outbound: &str, target: &Target, https: bool, upgrade: bool) -> Result<Option<Sender>> {
        let Some(stream) = self.router.connect(outbound, target).await? else { return Ok(None) };
        let (stream, h2): (BoxStream, bool) = if https {
            let skip = self.router.mitm().is_some_and(|m| m.skip_verify);
            // Upgrades (WebSocket) need HTTP/1.1 end to end.
            let alpn: &[&[u8]] = if upgrade { &[b"http/1.1"] } else { &[b"h2", b"http/1.1"] };
            let sni = match &target.host {
                Host::Domain(d) => Some(d.clone()),
                Host::Ip(_) => None,
            };
            let (conn, name) = crate::trojan::tls_client_alpn(&target.host_str(), sni, skip, alpn)?;
            let tls = conn.connect(name, stream).await.with_context(|| format!("TLS to {target}"))?;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            (Box::new(tls), h2)
        } else {
            (stream, false)
        };
        let io = TokioIo::new(stream);
        Ok(Some(if h2 {
            let (s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            tokio::spawn(conn);
            Sender::H2(s)
        } else {
            let (s, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(conn.with_upgrades());
            Sender::H1(s)
        }))
    }
}

/// A stream that first yields bytes already read from it.
pub struct Prefixed<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(pre: Vec<u8>, inner: S) -> Self {
        Prefixed { pre, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let pos = self.pos;
            buf.put_slice(&self.pre[pos..pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(hosts: &str) -> MitmConfig {
        let mut c = MitmConfig::new();
        c.set("hostname", hosts);
        c
    }

    fn test_ca() -> Ca {
        let (c, k) = Ca::generate().unwrap();
        Ca::from_pem(&c, &k).unwrap()
    }

    #[test]
    fn hostname_patterns() {
        let m = Mitm::with_ca(&cfg("*.example.com, example.org, -skip.example.com, alt.test:8443"), test_ca()).unwrap();
        assert!(m.matches("www.example.com", 443));
        assert!(m.matches("WWW.Example.com", 443));
        assert!(!m.matches("example.com", 443));
        assert!(!m.matches("www.example.com", 8443));
        assert!(m.matches("example.org", 443));
        assert!(!m.matches("skip.example.com", 443));
        assert!(m.matches("alt.test", 8443));
        assert!(!m.matches("alt.test", 443));
        assert!(glob("a*b?c", "aXXbYc") && !glob("a*b", "ac") && glob("*", ""));
    }

    #[test]
    fn leaf_chains_to_ca() {
        let m = Mitm::with_ca(&cfg("*"), test_ca()).unwrap();
        let a = m.server_config("a.test").unwrap();
        assert!(Arc::ptr_eq(&a, &m.server_config("a.test").unwrap()));
        assert_eq!(a.alpn_protocols[0], b"h2");
        m.ca.leaf("127.0.0.1", &m.leaf_key).unwrap();
    }

    #[test]
    fn p12_ca() {
        // A PKCS#12 bundle of a freshly generated CA, written by p12-keystore itself.
        let (c, k) = Ca::generate().unwrap();
        let key = KeyPair::from_pem(&k).unwrap();
        let cert = p12_keystore::Certificate::from_der(&pem_block(&c, "CERTIFICATE").unwrap()).unwrap();
        let mut ks = p12_keystore::KeyStore::new();
        ks.add_entry("ca", p12_keystore::KeyStoreEntry::PrivateKeyChain(p12_keystore::PrivateKeyChain::new(key.serialize_der(), [1u8; 20], [cert])));
        let der = ks.writer("pw").write().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let mut mc = cfg("*");
        mc.ca_p12 = Some(b64);
        mc.ca_passphrase = Some("pw".into());
        let ca = Ca::load(&mc).unwrap();
        ca.leaf("x.test", &key).unwrap();
        mc.ca_passphrase = Some("wrong".into());
        assert!(Ca::load(&mc).is_err());
    }

    /// A TLS origin on loopback echoing the `x-sluice` request header in its body.
    async fn origin() -> u16 {
        let ca = test_ca();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = ca.leaf("127.0.0.1", &key).unwrap();
        let mut sc = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
            .unwrap();
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(s).await.unwrap();
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let echo = req.headers().get("x-sluice").map_or("none".to_string(), |v| v.to_str().unwrap().to_string());
                        let mut r = Response::new(Full::new(Bytes::from(format!("Example {echo} {}", req.uri().path()))));
                        r.headers_mut().insert("server", HeaderValue::from_static("origin"));
                        Ok::<_, Infallible>(r)
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn tls_round_trip() {
        let port = origin().await;
        let dir = std::env::temp_dir().join(format!("sluice-mitm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = Ca::generate().unwrap();
        std::fs::write(dir.join("ca.crt"), &c).unwrap();
        std::fs::write(dir.join("ca.key"), &k).unwrap();
        let conf = format!(
            "[MITM]\nhostname = 127.0.0.1:{port}\nca-cert = {d}/ca.crt\nca-key = {d}/ca.key\nskip-server-cert-verify = true\n\
             [URL Rewrite]\n^https://127\\.0\\.0\\.1:{port}/old(.*) https://new.test/$1 302\n\
             [Header Rewrite]\nhttp-request ^https://127\\.0\\.0\\.1 header-add X-Sluice yes\n\
             http-response ^https://127\\.0\\.0\\.1 header-del Server\n\
             [Body Rewrite]\nhttp-response ^https://127\\.0\\.0\\.1 Example Sluice\n\
             [Rule]\nURL-REGEX,^https://127\\.0\\.0\\.1:\\d+/blocked,REJECT\nFINAL,DIRECT\n",
            d = dir.display()
        );
        let router = Arc::new(Router::new(&crate::config::Config::parse(&conf).unwrap()).unwrap());
        let target = Target::new("127.0.0.1", port);
        assert!(matches!(intercept_for(&router, &target), Some(Intercept::Tls)));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(pem_block(&c, "CERTIFICATE").unwrap())).unwrap();
        for h2 in [false, true] {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let ctx = ConnInfo::new(Proto::Https, None, None, port);
            tokio::spawn(serve_tls(server, router.clone(), target.clone(), ctx));
            let mut cc = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            cc.alpn_protocols = vec![if h2 { b"h2".to_vec() } else { b"http/1.1".to_vec() }];
            let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cc)).connect(name, client).await.expect("client trusts the leaf");
            assert_eq!(tls.get_ref().1.alpn_protocol() == Some(b"h2"), h2);
            let io = TokioIo::new(tls);
            let base = format!("https://127.0.0.1:{port}");
            let get = |path: &str| {
                let mut b = Request::get(format!("{base}{path}"));
                if !h2 {
                    b = Request::get(path).header("host", format!("127.0.0.1:{port}"));
                }
                b.body(Empty::<Bytes>::new()).unwrap()
            };
            let (status, headers, body) = if h2 {
                let (mut s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.unwrap();
                tokio::spawn(conn);
                let mut out = Vec::new();
                for p in ["/hello", "/oldx", "/blocked"] {
                    let r = s.send_request(get(p)).await.unwrap();
                    let (parts, b) = r.into_parts();
                    out.push((parts.status, parts.headers, b.collect().await.unwrap().to_bytes()));
                }
                (out.iter().map(|o| o.0).collect::<Vec<_>>(), out.iter().map(|o| o.1.clone()).collect::<Vec<_>>(), out.iter().map(|o| o.2.clone()).collect::<Vec<_>>())
            } else {
                let (mut s, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
                tokio::spawn(conn);
                let mut out = Vec::new();
                for p in ["/hello", "/oldx", "/blocked"] {
                    let r = s.send_request(get(p)).await.unwrap();
                    let (parts, b) = r.into_parts();
                    out.push((parts.status, parts.headers, b.collect().await.unwrap().to_bytes()));
                }
                (out.iter().map(|o| o.0).collect::<Vec<_>>(), out.iter().map(|o| o.1.clone()).collect::<Vec<_>>(), out.iter().map(|o| o.2.clone()).collect::<Vec<_>>())
            };
            assert_eq!(status[0], StatusCode::OK, "h2={h2}");
            assert_eq!(&body[0][..], b"Sluice yes /hello", "h2={h2}");
            assert!(headers[0].get("server").is_none());
            assert_eq!(status[1], StatusCode::FOUND);
            assert_eq!(headers[1]["location"], "https://new.test/x");
            assert_eq!(status[2], StatusCode::FORBIDDEN);
        }
        let recs = crate::conns::recent();
        let hit = recs.iter().rev().find(|r| r.url.as_deref() == Some(&format!("https://127.0.0.1:{port}/hello"))).unwrap();
        assert!(hit.mitm && hit.network == "HTTPS");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
