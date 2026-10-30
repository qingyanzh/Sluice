//! Stream transports under VMess/VLESS/Trojan: TCP, optionally TLS, optionally WebSocket.

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
    /// Xray/V2Ray "gun": the stream rides one gRPC call `/<service>/Tun` over HTTP/2.
    Grpc { service: String },
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
        let alpn: &[&[u8]] = if matches!(layer, Some(Layer::Grpc { .. })) { &[b"h2"] } else { &[] };
        let tls = if tls { Some(tls_client_config(&server, sni, skip_cert_verify, alpn)?) } else { None };
        Ok(Transport { server, port, tls, reality, layer, default_host })
    }

    pub async fn connect(&self) -> Result<BoxStream> {
        let tcp = connect_tcp(&self.server, self.port).await?;
        let stream: BoxStream = match (&self.reality, &self.tls) {
            (Some(r), _) => crate::reality::connect(Box::new(tcp), r).await?,
            (None, Some((config, sni))) => Box::new(TlsConnector::from(config.clone()).connect(sni.clone(), tcp).await?),
            (None, None) => Box::new(tcp),
        };
        match &self.layer {
            Some(Layer::Ws(ws)) => websocket(stream, ws, ws.host.as_deref().unwrap_or(&self.default_host)).await,
            Some(Layer::Grpc { service }) => grpc(stream, service, &self.default_host, self.tls.is_some()).await,
            None => Ok(stream),
        }
    }
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

/// Performs the HTTP upgrade on `stream` and returns a byte stream carried in binary frames.
async fn websocket(mut stream: BoxStream, ws: &WsOpts, host: &str) -> Result<BoxStream> {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        ws.path
    );
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
            bail!("websocket: server closed during handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HANDSHAKE {
            bail!("websocket: handshake response too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]);
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("101") {
        bail!("websocket upgrade refused: {status} (check ws-path and Host)");
    }
    let expected = accept_key(&key);
    let accepted = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == expected)
    });
    if !accepted {
        bail!("websocket: bad Sec-WebSocket-Accept");
    }
    let leftover = buf[head_end..].to_vec();
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
    fn surge_headers() {
        let o = WsOpts::from_params(Some("/ray".into()), Some("Host:\"cdn.example.com\"|User-Agent:x".into()));
        assert_eq!(o.path, "/ray");
        assert_eq!(o.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(o.headers, vec![("User-Agent".to_string(), "x".to_string())]);
    }
}
