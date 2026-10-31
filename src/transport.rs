//! Stream transports under VMess/VLESS/Trojan: TCP, optionally TLS/REALITY, optionally
//! WebSocket, HTTPUpgrade, gRPC or XHTTP.

use std::sync::Arc;

use anyhow::{bail, Result};
use base64::Engine;
use log::debug;
use rand::RngCore;
use rustls::pki_types::ServerName;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::trojan::tls_client_config;
use rustls::ClientConfig;
use crate::util::{connect_tcp, BoxStream};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME: usize = 16 * 1024;
const MAX_HANDSHAKE: usize = 16 * 1024;

#[derive(Debug, Clone, Default)]
pub struct WsOpts {
    pub path: String,
    /// `Host` header; defaults to the SNI or server name.
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl WsOpts {
    /// Builds options from Surge-style `ws-path` and `ws-headers=Host:a.com|User-Agent:x`.
    pub fn from_params(path: Option<String>, headers: Option<String>) -> Self {
        let mut opts = WsOpts { path: path.unwrap_or_else(|| "/".to_string()), ..Default::default() };
        for h in headers.iter().flat_map(|h| h.split('|')) {
            let Some((k, v)) = h.split_once(':') else { continue };
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            if k.eq_ignore_ascii_case("host") {
                opts.host = Some(v.to_string());
            } else {
                opts.headers.push((k.to_string(), v.to_string()));
            }
        }
        opts
    }
}

/// What runs on top of TCP/TLS before the proxy protocol.
#[derive(Debug, Clone)]
pub enum Layer {
    Ws(WsOpts),
    /// Xray `httpupgrade`: a WebSocket-style HTTP/1.1 upgrade, then the raw stream (no framing).
    HttpUpgrade(WsOpts),
    /// Xray/V2Ray "gun": the stream rides one gRPC call `/<service>/Tun` over HTTP/2.
    Grpc { service: String },
    /// Xray XHTTP (SplitHTTP): the stream split over plain HTTP/2 requests.
    Xhttp(XhttpOpts),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpMode {
    /// Xray's client default: stream-one over REALITY, packet-up otherwise.
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl XhttpMode {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "" | "auto" => XhttpMode::Auto,
            "packet-up" => XhttpMode::PacketUp,
            "stream-up" => XhttpMode::StreamUp,
            "stream-one" => XhttpMode::StreamOne,
            other => bail!("unknown xhttp mode {other:?}"),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            XhttpMode::Auto => "auto",
            XhttpMode::PacketUp => "packet-up",
            XhttpMode::StreamUp => "stream-up",
            XhttpMode::StreamOne => "stream-one",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpOpts {
    pub path: String,
    /// `:authority`; defaults to the SNI or server name.
    pub host: Option<String>,
    pub mode: XhttpMode,
    /// `x_padding` length range; the server rejects requests outside its own range.
    pub padding: (u32, u32),
}

impl Default for XhttpOpts {
    fn default() -> Self {
        XhttpOpts { path: "/".into(), host: None, mode: XhttpMode::Auto, padding: (100, 1000) }
    }
}

impl XhttpOpts {
    /// Xray's `xPaddingBytes`: `"100-1000"` or a single length.
    pub fn parse_padding(s: &str) -> Result<(u32, u32)> {
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let range = (a.trim().parse()?, b.trim().parse()?);
        if range.0 > range.1 {
            bail!("bad xhttp padding range {s:?}");
        }
        Ok(range)
    }
}

pub struct Transport {
    server: String,
    port: u16,
    tls: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    /// Replaces `tls` when set.
    reality: Option<crate::reality::RealityOpts>,
    layer: Option<Layer>,
    /// Name for the WebSocket `Host` header / gRPC authority when none is configured.
    default_host: String,
    #[cfg(test)]
    test_wire: Option<tokio::sync::mpsc::UnboundedSender<BoxStream>>,
}

impl Transport {
    pub fn new(
        server: String,
        port: u16,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        layer: Option<Layer>,
    ) -> Result<Self> {
        Self::with_reality(server, port, tls, sni, skip_cert_verify, layer, None)
    }

    pub fn with_reality(
        server: String,
        port: u16,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        layer: Option<Layer>,
        reality: Option<crate::reality::RealityOpts>,
    ) -> Result<Self> {
        let default_host = sni.clone().unwrap_or_else(|| server.clone());
        let tls = tls && reality.is_none();
        // gRPC needs HTTP/2, which TLS servers only speak when the client offers ALPN h2.
        let alpn: &[&[u8]] = if matches!(layer, Some(Layer::Grpc { .. } | Layer::Xhttp(_))) { &[b"h2"] } else { &[] };
        let tls = if tls { Some(tls_client_config(&server, sni, skip_cert_verify, alpn)?) } else { None };
        Ok(Transport { server, port, tls, reality, layer, default_host, #[cfg(test)] test_wire: None })
    }

    /// AnyTLS always runs directly over TLS; ALPN is optional.
    pub fn anytls(server: String, port: u16, sni: Option<String>, skip: bool, alpn: &[String], tfo: bool, fingerprint: Option<&str>) -> Result<Self> {
        let protocols: Vec<&[u8]> = alpn.iter().map(|p| p.as_bytes()).collect();
        if protocols.iter().any(|p| p.is_empty() || p.len() > 255) {
            bail!("invalid AnyTLS ALPN protocol length");
        }
        if tfo {
            static NOTICE: std::sync::Once = std::sync::Once::new();
            NOTICE.call_once(|| log::info!("AnyTLS tfo is accepted for compatibility; outbound TCP uses a normal connect"));
        }
        let default_host = sni.clone().unwrap_or_else(|| server.clone());
        let tls = Some(anytls_tls_config(&server, sni, skip, &protocols, fingerprint)?);
        Ok(Transport { server, port, tls, reality: None, layer: None, default_host, #[cfg(test)] test_wire: None })
    }

    /// TLS/protocol tests can run in sandboxes which forbid loopback socket binds.
    #[cfg(test)]
    pub fn with_test_wire(mut self, wire: tokio::sync::mpsc::UnboundedSender<BoxStream>) -> Self {
        self.test_wire = Some(wire);
        self
    }

    pub async fn connect(&self) -> Result<BoxStream> {
        #[cfg(test)]
        let tcp: BoxStream = if let Some(wire) = &self.test_wire {
            let (local, remote) = tokio::io::duplex(256 * 1024);
            wire.send(Box::new(remote)).map_err(|_| anyhow::anyhow!("test listener closed"))?;
            Box::new(local)
        } else { Box::new(connect_tcp(&self.server, self.port).await?) };
        #[cfg(not(test))]
        let tcp: BoxStream = Box::new(connect_tcp(&self.server, self.port).await?);
        let stream: BoxStream = match (&self.reality, &self.tls) {
            (Some(r), _) => crate::reality::connect(tcp, r).await?,
            (None, Some((config, sni))) => Box::new(TlsConnector::from(config.clone()).connect(sni.clone(), tcp).await?),
            (None, None) => tcp,
        };
        match &self.layer {
            Some(Layer::Ws(ws)) => websocket(stream, ws, ws.host.as_deref().unwrap_or(&self.default_host)).await,
            Some(Layer::HttpUpgrade(o)) => http_upgrade(stream, o, o.host.as_deref().unwrap_or(&self.default_host)).await,
            Some(Layer::Grpc { service }) => grpc(stream, service, &self.default_host, self.tls.is_some()).await,
            Some(Layer::Xhttp(x)) => {
                let secure = self.tls.is_some() || self.reality.is_some();
                xhttp(stream, x, x.host.as_deref().unwrap_or(&self.default_host), secure, self.reality.is_some()).await
            }
            None => Ok(stream),
        }
    }
}

/// AnyTLS's explicit insecure mode also accepts unverified handshake signatures.
/// Keep this local: other protocols retain their existing verifier semantics.
#[derive(Debug)]
struct AnyTlsNoVerify;

impl rustls::client::danger::ServerCertVerifier for AnyTlsNoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let mut schemes = rustls::crypto::ring::default_provider()
            .signature_verification_algorithms.supported_schemes();
        // Legacy TLS 1.2 servers may only sign ServerKeyExchange with SHA-1.
        schemes.extend([rustls::SignatureScheme::RSA_PKCS1_SHA1, rustls::SignatureScheme::ECDSA_SHA1_Legacy]);
        schemes
    }
}

fn anytls_tls_config(
    server: &str,
    sni: Option<String>,
    skip: bool,
    alpn: &[&[u8]],
    fingerprint: Option<&str>,
) -> Result<(Arc<ClientConfig>, ServerName<'static>)> {
    let mut provider = rustls::crypto::ring::default_provider();
    if fingerprint.is_some_and(|fp| !fp.is_empty() && fp != "none") {
        // Approximate Chrome's supported cipher/group order, retaining TLS 1.2.
        // This is NOT uTLS: rustls controls extensions, GREASE and key shares. The
        // REALITY ClientHello advertises features (e.g. compressed certificates)
        // its special-purpose handshake cannot safely reuse for ordinary TLS.
        // All requested fingerprints currently select this Chrome-like profile.
        use rustls::crypto::ring::{cipher_suite::*, kx_group};
        provider.cipher_suites = vec![
            TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?;
    let mut config = if skip {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyTlsNoVerify)).with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    // No implicit ALPN: AnyTLS servers need not speak HTTP. Explicit ALPN keeps
    // the user's preference order, including h2 before http/1.1 for Chrome.
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let name = sni.filter(|s| !s.is_empty()).unwrap_or_else(|| server.to_string());
    // ServerName::IpAddress suppresses the SNI extension, including explicit IP SNI.
    let name = name.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(&name);
    let name = ServerName::try_from(name.to_string()).map_err(|_| anyhow::anyhow!("invalid AnyTLS sni {name:?}"))?;
    Ok((Arc::new(config), name))
}

impl Transport {
    /// For XTLS-Vision: the TLS or REALITY handshake done by hand, returning the raw TCP
    /// stream together with the session's record layer.
    pub async fn connect_records(&self) -> Result<(BoxStream, Box<dyn crate::vision::RecordLayer>)> {
        if self.layer.is_some() {
            bail!("{} needs plain TCP under TLS/REALITY (no ws/grpc)", crate::vision::FLOW);
        }
        let mut raw: BoxStream = Box::new(connect_tcp(&self.server, self.port).await?);
        let tls: Box<dyn crate::vision::RecordLayer> = match (&self.reality, &self.tls) {
            (Some(r), _) => Box::new(crate::reality::handshake(&mut raw, r).await?),
            (None, Some((config, sni))) => {
                Box::new(crate::vision::rustls_handshake(&mut raw, config.clone(), sni.clone()).await?)
            }
            (None, None) => bail!("{} needs TLS or REALITY", crate::vision::FLOW),
        };
        Ok((raw, tls))
    }
}

/// gRPC message carrying `data` the way gun does: a protobuf `bytes data = 1` field,
/// behind the 5-byte gRPC length prefix.
pub fn gun_frame(data: &[u8]) -> Vec<u8> {
    let mut proto = vec![0x0A];
    let mut n = data.len();
    while n >= 0x80 {
        proto.push((n as u8) | 0x80);
        n >>= 7;
    }
    proto.push(n as u8);
    proto.extend_from_slice(data);
    let mut out = Vec::with_capacity(5 + proto.len());
    out.push(0);
    out.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    out.extend(proto);
    out
}

/// Pulls complete gun messages out of `buf`, returning their payloads.
pub fn take_gun_messages(buf: &mut Vec<u8>) -> std::io::Result<Vec<Vec<u8>>> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("grpc: {m}"));
    let mut out = Vec::new();
    loop {
        if buf.len() < 5 {
            return Ok(out);
        }
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            return Ok(out);
        }
        let msg: Vec<u8> = buf.drain(..5 + len).skip(5).collect();
        if msg.is_empty() {
            continue;
        }
        if msg[0] != 0x0A {
            return Err(bad("unexpected protobuf field"));
        }
        let (mut size, mut shift, mut i) = (0usize, 0, 1);
        loop {
            let b = *msg.get(i).ok_or_else(|| bad("truncated length"))?;
            size |= ((b & 0x7f) as usize) << shift;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        out.push(msg.get(i..i + size).ok_or_else(|| bad("truncated message"))?.to_vec());
    }
}

/// Opens the gun call and bridges it to a plain byte stream.
async fn grpc(stream: BoxStream, service: &str, authority: &str, tls: bool) -> Result<BoxStream> {
    let (client, conn) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("grpc connection closed: {e}");
        }
    });
    let scheme = if tls { "https" } else { "http" };
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("{scheme}://{authority}/{}/Tun", service.trim_matches('/')))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "grpc-go/1.62.1")
        .body(())?;
    let (response, mut send) = client.ready().await?.send_request(req, false)?;

    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME];
        loop {
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut frame = bytes::Bytes::from(gun_frame(&buf[..n]));
            // Respect HTTP/2 flow control instead of buffering without bound.
            while !frame.is_empty() {
                send.reserve_capacity(frame.len());
                match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(cap)) if cap > 0 => {
                        let chunk = frame.split_to(cap.min(frame.len()));
                        if send.send_data(chunk, false).is_err() {
                            return;
                        }
                    }
                    Some(Ok(_)) => continue,
                    _ => return,
                }
            }
        }
        let _ = send.send_data(bytes::Bytes::new(), true);
    });
    tokio::spawn(async move {
        let result: Result<()> = async {
            let resp = response.await?;
            if resp.status() != 200 {
                bail!("grpc call refused: HTTP {} (check grpc-service-name)", resp.status());
            }
            let mut body = resp.into_body();
            let mut pending = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                let _ = body.flow_control().release_capacity(chunk.len());
                pending.extend_from_slice(&chunk);
                for msg in take_gun_messages(&mut pending)? {
                    iwr.write_all(&msg).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            debug!("grpc stream ended: {e:#}");
        }
        let _ = iwr.shutdown().await;
    });
    Ok(Box::new(app))
}

/// Sends `data` on an HTTP/2 stream, waiting for flow-control credit; false once the stream is gone.
async fn send_h2(send: &mut h2::SendStream<bytes::Bytes>, mut data: bytes::Bytes, end: bool) -> bool {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(cap)) if cap > 0 => {
                let chunk = data.split_to(cap.min(data.len()));
                if send.send_data(chunk, false).is_err() {
                    return false;
                }
            }
            Some(Ok(_)) => continue,
            _ => return false,
        }
    }
    !end || send.send_data(bytes::Bytes::new(), true).is_ok()
}

/// Reads a response body to the end, returning flow-control credit as it goes.
async fn drain_h2(response: h2::client::ResponseFuture) -> Result<http::StatusCode> {
    let resp = response.await?;
    let status = resp.status();
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk?.len());
    }
    Ok(status)
}

fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Path with a leading and trailing `/` (Xray appends session and seq as path segments),
/// plus any query the user configured.
fn xhttp_base(path: &str) -> (String, String) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut p = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    if !p.ends_with('/') {
        p.push('/');
    }
    (p, query.to_string())
}

/// Opens an XHTTP session on one HTTP/2 connection and bridges it to a byte stream.
/// Downlink is one long response (the stream-one POST or a GET on `<path><session>`);
/// uplink is the stream-one/stream-up request body or numbered packet-up POSTs.
async fn xhttp(stream: BoxStream, opts: &XhttpOpts, authority: &str, secure: bool, reality: bool) -> Result<BoxStream> {
    let mode = match opts.mode {
        XhttpMode::Auto if reality => XhttpMode::StreamOne,
        XhttpMode::Auto => XhttpMode::PacketUp,
        m => m,
    };
    let (client, conn) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("xhttp connection closed: {e}");
        }
    });
    let scheme = if secure { "https" } else { "http" };
    let (base, query) = xhttp_base(&opts.path);
    let authority = authority.to_string();
    let padding = opts.padding;
    let request = move |method: &str, path: &str, len: Option<usize>| {
        let n = rand::Rng::gen_range(&mut rand::thread_rng(), padding.0..=padding.1) as usize;
        let sep = if query.is_empty() { "" } else { "&" };
        let mut req = http::Request::builder()
            .method(method)
            .uri(format!("{scheme}://{authority}{path}?{query}{sep}x_padding={}", "X".repeat(n)))
            .header("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36");
        if let Some(len) = len {
            req = req.header("content-length", len);
        }
        req.body(())
    };
    let session = format!("{base}{}", random_uuid());

    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);
    let mut first = client.clone().ready().await?;
    let (down, up) = if mode == XhttpMode::StreamOne {
        let (resp, send) = first.send_request(request("POST", &base, None)?, false)?;
        (resp, Some(send))
    } else {
        let (resp, _) = first.send_request(request("GET", &session, None)?, true)?;
        let up = if mode == XhttpMode::StreamUp {
            let (resp, send) = client.clone().ready().await?.send_request(request("POST", &session, None)?, false)?;
            tokio::spawn(async move {
                match drain_h2(resp).await {
                    Ok(s) if s != 200 => debug!("xhttp stream-up refused: HTTP {s}"),
                    _ => {}
                }
            });
            Some(send)
        } else {
            None
        };
        (resp, up)
    };

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME * 4];
        let mut send = up;
        let mut seq = 0u64;
        loop {
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = bytes::Bytes::copy_from_slice(&buf[..n]);
            if let Some(send) = send.as_mut() {
                if !send_h2(send, data, false).await {
                    return;
                }
                continue;
            }
            // packet-up: one POST per chunk, in order; the server reassembles by seq.
            let result: Result<()> = async {
                let req = request("POST", &format!("{session}/{seq}"), Some(n))?;
                let (resp, mut body) = client.clone().ready().await?.send_request(req, false)?;
                if !send_h2(&mut body, data, true).await {
                    bail!("upload stream reset");
                }
                let status = drain_h2(resp).await?;
                if status != 200 {
                    bail!("HTTP {status}");
                }
                Ok(())
            }
            .await;
            if let Err(e) = result {
                debug!("xhttp packet-up POST {seq} failed: {e:#}");
                return;
            }
            seq += 1;
        }
        if let Some(mut send) = send {
            let _ = send.send_data(bytes::Bytes::new(), true);
        }
    });
    tokio::spawn(async move {
        let result: Result<()> = async {
            let resp = down.await?;
            if resp.status() != 200 {
                bail!("xhttp refused: HTTP {} (check xhttp path, host and mode)", resp.status());
            }
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                let _ = body.flow_control().release_capacity(chunk.len());
                iwr.write_all(&chunk).await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            debug!("xhttp downlink ended: {e:#}");
        }
        let _ = iwr.shutdown().await;
    });
    Ok(Box::new(app))
}

fn accept_key(key: &str) -> String {
    let digest = Sha1::digest(format!("{key}{WS_GUID}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// A masked client frame (FIN set) with the given opcode.
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        n @ 0..=125 => out.push(0x80 | n as u8),
        n @ 126..=0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Reads one frame; returns (opcode, payload), unmasking if the peer masked it.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let b0 = r.read_u8().await?;
    let b1 = r.read_u8().await?;
    let len = match b1 & 0x7f {
        126 => r.read_u16().await? as u64,
        127 => r.read_u64().await?,
        n => n as u64,
    };
    if len > 16 << 20 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "websocket frame too large"));
    }
    let mask = if b1 & 0x80 != 0 {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    if let Some(m) = mask {
        payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= m[i % 4]);
    }
    Ok((b0 & 0x0f, payload))
}

/// Sends an upgrade request (`extra` holds additional header lines) and reads the response
/// head; returns the head and any bytes read past it.
async fn upgrade(stream: &mut BoxStream, ws: &WsOpts, host: &str, extra: &str) -> Result<(String, Vec<u8>)> {
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{extra}", ws.path);
    for (k, v) in &ws.headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        let mut tmp = [0u8; 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("upgrade: server closed during handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HANDSHAKE {
            bail!("upgrade: handshake response too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("101") {
        bail!("upgrade refused: {status} (check the path and Host)");
    }
    Ok((head, buf[head_end..].to_vec()))
}

async fn http_upgrade(mut stream: BoxStream, o: &WsOpts, host: &str) -> Result<BoxStream> {
    let (_, leftover) = upgrade(&mut stream, o, host, "").await?;
    if leftover.is_empty() {
        return Ok(stream);
    }
    // Bytes that arrived with the response head go first.
    let (rd, mut wr) = tokio::io::split(stream);
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ird, &mut wr).await;
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut std::io::Cursor::new(leftover).chain(rd), &mut iwr).await;
        let _ = iwr.shutdown().await;
    });
    Ok(Box::new(app))
}

/// Performs the HTTP upgrade on `stream` and returns a byte stream carried in binary frames.
async fn websocket(mut stream: BoxStream, ws: &WsOpts, host: &str) -> Result<BoxStream> {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let extra = format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n");
    let (head, leftover) = upgrade(&mut stream, ws, host, &extra).await?;
    let expected = accept_key(&key);
    let accepted = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == expected)
    });
    if !accepted {
        bail!("websocket: bad Sec-WebSocket-Accept");
    }
    Ok(frame_stream(stream, leftover))
}

/// Bridges a WebSocket connection to a plain byte stream with two background tasks.
fn frame_stream(stream: BoxStream, leftover: Vec<u8>) -> BoxStream {
    let (rd, wr) = tokio::io::split(stream);
    let wr = Arc::new(Mutex::new(wr));
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);

    let out = wr.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME];
        loop {
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if out.lock().await.write_all(&encode_frame(2, &buf[..n])).await.is_err() {
                return;
            }
        }
        let mut w = out.lock().await;
        let _ = w.write_all(&encode_frame(8, &1000u16.to_be_bytes())).await;
        let _ = w.shutdown().await;
    });

    tokio::spawn(async move {
        let mut rd = std::io::Cursor::new(leftover).chain(rd);
        loop {
            match read_frame(&mut rd).await {
                Ok((0..=2, payload)) => {
                    if iwr.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Ok((9, payload)) => {
                    let _ = wr.lock().await.write_all(&encode_frame(10, &payload)).await;
                }
                Ok((8, _)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = iwr.shutdown().await;
        debug!("websocket closed");
    });
    Box::new(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anytls_client_hello_profile_sni_and_alpn() {
        for (server, sni, expected) in [
            ("proxy.example", None, Some("proxy.example")),
            ("proxy.example", Some(""), Some("proxy.example")),
            ("127.0.0.1", Some("tls.example"), Some("tls.example")),
            ("127.0.0.1", None, None),
            ("proxy.example", Some("::1"), None),
            ("[::1]", None, None),
        ] {
            for alpn in [vec![], vec![&b"h2"[..], &b"http/1.1"[..]]] {
                let (config, name) = anytls_tls_config(server, sni.map(str::to_string), true, &alpn, Some("chrome")).unwrap();
                let mut client = rustls::ClientConnection::new(config, name).unwrap();
                let mut wire = Vec::new();
                client.write_tls(&mut wire).unwrap();
                let mut acceptor = rustls::server::Acceptor::default();
                acceptor.read_tls(&mut &wire[..]).unwrap();
                let accepted = acceptor.accept().unwrap().unwrap();
                let hello = accepted.client_hello();
                assert_eq!(hello.server_name(), expected);
                assert_eq!(hello.alpn().map(|p| p.collect::<Vec<_>>()).unwrap_or_default(), alpn);
                assert_eq!(&hello.cipher_suites()[..3], &[
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                ]);
                assert_eq!(hello.named_groups().unwrap(), &[
                    rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1, rustls::NamedGroup::secp384r1,
                ]);
                assert!(hello.signature_schemes().contains(&rustls::SignatureScheme::RSA_PKCS1_SHA1));
                assert!(hello.signature_schemes().contains(&rustls::SignatureScheme::ECDSA_SHA1_Legacy));
            }
        }
        assert!(anytls_tls_config("proxy.example", Some("bad name".into()), true, &[], None).is_err());
        assert!(Transport::anytls("h".into(), 443, None, true, &["".into()], false, None).is_err());
    }

    // The server deliberately signs with invalid bytes, optionally using a legacy
    // SHA-1 scheme. This reaches both verifier callbacks through real TLS handshakes.
    #[derive(Debug)]
    struct InvalidSignatureKey(Option<rustls::SignatureScheme>);

    impl rustls::sign::SigningKey for InvalidSignatureKey {
        fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
            Some(Box::new(InvalidSignature(self.0.unwrap_or_else(|| *offered.iter().find(|s| matches!(s,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256)).unwrap()))))
        }
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            if self.0 == Some(rustls::SignatureScheme::RSA_PKCS1_SHA1) { rustls::SignatureAlgorithm::RSA }
            else { rustls::SignatureAlgorithm::ECDSA }
        }
    }

    #[derive(Debug)]
    struct InvalidSignature(rustls::SignatureScheme);

    impl rustls::sign::Signer for InvalidSignature {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rustls::Error> { Ok(vec![0; 64]) }
        fn scheme(&self) -> rustls::SignatureScheme { self.0 }
    }

    #[tokio::test]
    async fn anytls_skip_accepts_bad_handshake_signatures_and_tls12_fallback() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                let schemes = if version == &rustls::version::TLS12 {
                    vec![None, Some(rustls::SignatureScheme::RSA_PKCS1_SHA1), Some(rustls::SignatureScheme::ECDSA_SHA1_Legacy)]
                } else { vec![None] };
                for scheme in schemes {
                    let cert = rcgen::generate_simple_self_signed(vec!["wrong-name.example".into()]).unwrap();
                    let certified = rustls::sign::CertifiedKey::new(vec![cert.cert.der().clone()], Arc::new(InvalidSignatureKey(scheme)));
                    let server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_protocol_versions(&[version]).unwrap().with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
                    for skip in [true, false] {
                        let (client, name) = anytls_tls_config("127.0.0.1", None, skip, &[], Some("chrome")).unwrap();
                        let (local, remote) = tokio::io::duplex(65536);
                        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.clone()));
                        let serve = async {
                            let mut tls = acceptor.accept(remote).await?;
                            assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
                            assert!(tls.get_ref().1.server_name().is_none());
                            tls.write_all(b"ok").await?;
                            tls.flush().await
                        };
                        let connect = async {
                            let mut tls = TlsConnector::from(client).connect(name, local).await?;
                            let mut reply = [0; 2];
                            tls.read_exact(&mut reply).await?;
                            assert_eq!(&reply, b"ok");
                            Ok::<_, std::io::Error>(())
                        };
                        let (a, b) = tokio::join!(serve, connect);
                        if skip { a.unwrap(); b.unwrap(); }
                        else { assert!(a.is_err()); assert!(b.is_err()); }
                    }
                }
            }
        }).await.unwrap();
    }

    #[test]
    fn rfc6455_accept_key() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        for len in [0usize, 5, 125, 126, 300, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let wire = encode_frame(2, &payload);
            let (op, got) = read_frame(&mut &wire[..]).await.unwrap();
            assert_eq!((op, got), (2, payload));
        }
    }

    #[test]
    fn gun_frames_roundtrip() {
        for len in [0usize, 1, 127, 128, 300, 70_000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut wire = [gun_frame(&data), gun_frame(b"next")].concat();
            let partial = wire.split_off(wire.len() - 3);
            let msgs = take_gun_messages(&mut wire).unwrap();
            assert_eq!(msgs, vec![data.clone()]);
            wire.extend(partial);
            assert_eq!(take_gun_messages(&mut wire).unwrap(), vec![b"next".to_vec()]);
            assert!(wire.is_empty());
        }
    }

    #[test]
    fn xhttp_helpers() {
        assert_eq!(xhttp_base("xh"), ("/xh/".to_string(), String::new()));
        assert_eq!(xhttp_base("/xh/?ed=1"), ("/xh/".to_string(), "ed=1".to_string()));
        assert_eq!(XhttpOpts::parse_padding("100-1000").unwrap(), (100, 1000));
        assert_eq!(XhttpOpts::parse_padding("64").unwrap(), (64, 64));
        assert!(XhttpOpts::parse_padding("9-1").is_err());
        assert_eq!(XhttpMode::parse("stream-up").unwrap().as_str(), "stream-up");
        let id = random_uuid();
        assert_eq!((id.len(), &id[14..15]), (36, "4"));
    }

    #[test]
    fn surge_headers() {
        let o = WsOpts::from_params(Some("/ray".into()), Some("Host:\"cdn.example.com\"|User-Agent:x".into()));
        assert_eq!(o.path, "/ray");
        assert_eq!(o.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(o.headers, vec![("User-Agent".to_string(), "x".to_string())]);
    }
}
