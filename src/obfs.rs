//! Shadowsocks SIP003 plugins, done in-process: simple-obfs (`obfs-local`, http or tls) and
//! v2ray-plugin (WebSocket, optionally TLS, no mux).
//!
//! simple-obfs `http` sends the first data behind a fake WebSocket upgrade request; `tls` puts it
//! in the session ticket of a fake TLS 1.2 ClientHello and frames the rest as application data.

use anyhow::{bail, Result};
use base64::Engine;
use log::debug;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::BoxStream;

const MAX_RECORD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum SsPlugin {
    /// simple-obfs; `uri` is the HTTP request path.
    Obfs { tls: bool, host: String, uri: String },
    V2ray { tls: bool, host: String, path: String, skip_cert_verify: bool },
}

impl SsPlugin {
    /// A SIP003 plugin name and its `k=v;flag` options, as in SIP002 links (`plugin=name;opts`).
    pub fn parse(name: &str, opts: &str) -> Result<Self> {
        let mut kv = std::collections::HashMap::new();
        for o in opts.split(';').map(str::trim).filter(|o| !o.is_empty()) {
            let (k, v) = o.split_once('=').unwrap_or((o, "true"));
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
        let get = |k: &str| kv.get(k).cloned().filter(|v| !v.is_empty());
        let on = |k: &str| get(k).is_some_and(|v| v == "true" || v == "1");
        Ok(match name.trim() {
            "obfs-local" | "simple-obfs" | "obfs" => SsPlugin::Obfs {
                tls: match get("obfs").or_else(|| get("mode")).as_deref() {
                    Some("http") | None => false,
                    Some("tls") => true,
                    Some(other) => bail!("simple-obfs mode {other:?} not supported"),
                },
                host: get("obfs-host").or_else(|| get("host")).unwrap_or_else(|| "cloudfront.net".into()),
                uri: get("obfs-uri").or_else(|| get("uri")).unwrap_or_else(|| "/".into()),
            },
            "v2ray-plugin" => {
                if let Some(m) = get("mode").filter(|m| m != "websocket") {
                    bail!("v2ray-plugin mode {m:?} not supported");
                }
                SsPlugin::V2ray {
                    tls: on("tls"),
                    host: get("host").unwrap_or_else(|| "cloudfront.com".into()),
                    path: get("path").unwrap_or_else(|| "/".into()),
                    skip_cert_verify: on("skip-cert-verify") || on("allowinsecure"),
                }
            }
            other => bail!("ss plugin {other:?} not supported"),
        })
    }

    /// `plugin=` and `plugin-opts=` values that `parse` reads back.
    pub fn to_sip003(&self) -> (&'static str, String) {
        match self {
            SsPlugin::Obfs { tls, host, uri } => {
                ("obfs-local", format!("obfs={};obfs-host={host};obfs-uri={uri}", if *tls { "tls" } else { "http" }))
            }
            SsPlugin::V2ray { tls, host, path, skip_cert_verify } => {
                let mut o = format!("host={host};path={path}");
                if *tls {
                    o.push_str(";tls");
                }
                if *skip_cert_verify {
                    o.push_str(";skip-cert-verify");
                }
                ("v2ray-plugin", o)
            }
        }
    }
}

fn http_request(host: &str, port: u16, uri: &str, payload: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);
    let host = if port == 80 { host.to_string() } else { format!("{host}:{port}") };
    let mut out = format!(
        "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {}\r\n\r\n",
        rng.gen_range(0..51),
        rng.gen_range(0..2),
        base64::engine::general_purpose::STANDARD.encode(key),
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

const CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0,
    0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09,
    0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

const OTHER_EXTS: [u8; 66] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, // ec_point_formats
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, // supported groups
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04,
    0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, // sig algs
    0x00, 0x16, 0x00, 0x00, // encrypt_then_mac
    0x00, 0x17, 0x00, 0x00, // extended_master_secret
];

/// simple-obfs's ClientHello: the session ticket extension (first, the server reads it at a
/// fixed offset) carries `payload`, then SNI and fixed extensions.
fn client_hello(host: &str, payload: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut exts = vec![0x00, 0x23];
    exts.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    exts.extend_from_slice(payload);
    let h = host.as_bytes();
    exts.extend_from_slice(&[0x00, 0x00]);
    exts.extend_from_slice(&(h.len() as u16 + 5).to_be_bytes());
    exts.extend_from_slice(&(h.len() as u16 + 3).to_be_bytes());
    exts.push(0);
    exts.extend_from_slice(&(h.len() as u16).to_be_bytes());
    exts.extend_from_slice(h);
    exts.extend_from_slice(&OTHER_EXTS);

    let mut body = vec![0x03, 0x03];
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32);
    body.extend_from_slice(&unix.to_be_bytes());
    let mut random = [0u8; 28 + 32];
    rng.fill_bytes(&mut random);
    body.extend_from_slice(&random[..28]);
    body.push(32);
    body.extend_from_slice(&random[28..]);
    body.extend_from_slice(&(CIPHER_SUITES.len() as u16).to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITES);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);

    let mut out = vec![0x16, 0x03, 0x01];
    out.extend_from_slice(&(body.len() as u16 + 4).to_be_bytes());
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend(body);
    out
}

fn app_data(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x17, 0x03, 0x03];
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Server side of `http`: an HTTP response head, then raw data.
async fn read_http<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(rd: &mut R, wr: &mut W) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let end = loop {
        let n = rd.read(&mut tmp).await?;
        if n == 0 {
            bail!("obfs http: server closed before response");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_RECORD {
            bail!("obfs http: response head too large");
        }
    };
    wr.write_all(&buf[end..]).await?;
    tokio::io::copy(rd, wr).await?;
    Ok(())
}

/// Server side of `tls`: ServerHello and ChangeCipherSpec are dropped; the handshake record after
/// them and all application-data records carry data.
async fn read_tls<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(rd: &mut R, wr: &mut W) -> Result<()> {
    let mut seen_ccs = false;
    let mut body = vec![0u8; 1 << 16];
    loop {
        let mut head = [0u8; 5];
        match rd.read_exact(&mut head).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        rd.read_exact(&mut body[..len]).await?;
        match head[0] {
            0x14 => seen_ccs = true,
            0x16 if !seen_ccs => {}
            0x16 | 0x17 => wr.write_all(&body[..len]).await?,
            t => bail!("obfs tls: unexpected record type {t:#x}"),
        }
    }
}

/// Wraps a connection to a simple-obfs server (`port` goes into the HTTP Host header).
pub fn simple_obfs(stream: BoxStream, tls: bool, host: &str, uri: &str, port: u16) -> BoxStream {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);
    let (host, uri) = (host.to_string(), uri.to_string());
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RECORD];
        let mut first = true;
        loop {
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = &buf[..n];
            let out = match (first, tls) {
                (true, true) => client_hello(&host, data),
                (true, false) => http_request(&host, port, &uri, data),
                (false, true) => app_data(data),
                (false, false) => data.to_vec(),
            };
            first = false;
            if wr.write_all(&out).await.is_err() {
                return;
            }
        }
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        let r = if tls { read_tls(&mut rd, &mut iwr).await } else { read_http(&mut rd, &mut iwr).await };
        if let Err(e) = r {
            debug!("simple-obfs: {e:#}");
        }
        let _ = iwr.shutdown().await;
    });
    Box::new(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_opts() {
        let p = SsPlugin::parse("obfs-local", "obfs=tls;obfs-host=www.bing.com").unwrap();
        assert_eq!(p, SsPlugin::Obfs { tls: true, host: "www.bing.com".into(), uri: "/".into() });
        let v = SsPlugin::parse("v2ray-plugin", "tls;host=a.com;path=/ws;mux=0").unwrap();
        assert_eq!(v, SsPlugin::V2ray { tls: true, host: "a.com".into(), path: "/ws".into(), skip_cert_verify: false });
        for p in [p, v] {
            let (n, o) = p.to_sip003();
            assert_eq!(SsPlugin::parse(n, &o).unwrap(), p);
        }
        assert!(SsPlugin::parse("v2ray-plugin", "mode=quic").is_err());
        assert!(SsPlugin::parse("kcptun", "").is_err());
    }

    #[test]
    fn hello_layout() {
        let hello = client_hello("h.example", b"payload");
        assert_eq!(u16::from_be_bytes([hello[3], hello[4]]) as usize, hello.len() - 5);
        // simple-obfs's fixed ClientHello size (138) is where the ticket extension starts.
        assert_eq!(&hello[138..142], &[0x00, 0x23, 0x00, 0x07]);
        assert_eq!(&hello[142..149], b"payload");
        let ext_len = u16::from_be_bytes([hello[136], hello[137]]) as usize;
        assert_eq!(ext_len, hello.len() - 138);
    }

    #[tokio::test]
    async fn tls_response_unwrapped() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x03, 2, 0, 0];
        hello.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        hello.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x02, b'h', b'i']);
        hello.extend(app_data(b" there"));
        let mut out = Vec::new();
        read_tls(&mut &hello[..], &mut out).await.unwrap();
        assert_eq!(out, b"hi there");
        let mut out = Vec::new();
        read_http(&mut &b"HTTP/1.1 101 OK\r\nX: y\r\n\r\nraw"[..], &mut out).await.unwrap();
        assert_eq!(out, b"raw");
    }
}
