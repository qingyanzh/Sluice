//! VLESS client (protocol version 0) over any stream transport (TCP, TLS, WebSocket).
//!
//! Request:  ver(0) uuid(16) addons_len addons cmd(1=tcp) port(2) atyp addr, then payload.
//! The only addon is the flow (protobuf field 1), set for XTLS-Vision; see [`crate::vision`].
//! Response: ver addons_len addons..., then payload.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::transport::Transport;
use crate::udp::{write_port_addr, UdpPipe};
use crate::util::{BoxStream, Target};

pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(&hex).map_err(|_| anyhow::anyhow!("bad uuid {s:?}"))?;
    match <[u8; 16]>::try_from(bytes) {
        Ok(b) => Ok(b),
        Err(_) => bail!("bad uuid {s:?}: expected 16 bytes"),
    }
}

const CMD_TCP: u8 = 1;

const CMD_MUX: u8 = 3;

/// Addresses use Xray's `port type addr`; Mux (XUDP) requests carry none.
fn request_header(uuid: &[u8; 16], flow: Option<&str>, cmd: u8, target: Option<&Target>) -> Result<Vec<u8>> {
    let mut h = Vec::with_capacity(64);
    h.push(0);
    h.extend_from_slice(uuid);
    match flow {
        Some(f) => h.extend_from_slice(&[f.len() as u8 + 2, 0x0a, f.len() as u8]),
        None => h.push(0),
    }
    h.extend_from_slice(flow.unwrap_or_default().as_bytes());
    h.push(cmd);
    if let Some(t) = target {
        write_port_addr(t, &mut h)?;
    }
    Ok(h)
}

/// Propagates `Pending` out of `poll_read` from inside its loop.
macro_rules! ready {
    ($e:expr) => {
        match $e {
            Poll::Ready(r) => r,
            Poll::Pending => return Poll::Pending,
        }
    };
}

enum Head {
    Version,
    AddonsLen,
    Addons(usize),
    Done,
}

/// Strips the response header off the inner stream before handing data to the reader.
struct VlessStream<S> {
    inner: S,
    head: Head,
}

fn eof(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, format!("vless: {msg}"))
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            let want = match this.head {
                Head::Done => return Pin::new(&mut this.inner).poll_read(cx, buf),
                Head::Version | Head::AddonsLen => 1,
                Head::Addons(left) => left,
            };
            let mut scratch = [0u8; 255];
            let mut rb = ReadBuf::new(&mut scratch[..want]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let got = rb.filled();
            if got.is_empty() {
                return Poll::Ready(Err(eof("closed before response header")));
            }
            this.head = match this.head {
                Head::Version if got[0] != 0 => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "vless: bad response version")))
                }
                Head::Version => Head::AddonsLen,
                Head::AddonsLen if got[0] == 0 => Head::Done,
                Head::AddonsLen => Head::Addons(got[0] as usize),
                Head::Addons(left) if got.len() == left => Head::Done,
                Head::Addons(left) => Head::Addons(left - got.len()),
                Head::Done => unreachable!(),
            };
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct VlessServer {
    uuid: [u8; 16],
    transport: Arc<Transport>,
    vision: bool,
}

impl VlessServer {
    pub fn new(transport: Transport, uuid: &str, flow: Option<&str>) -> Result<Self> {
        let vision = match flow.unwrap_or_default() {
            "" => false,
            crate::vision::FLOW => true,
            other => bail!("unsupported VLESS flow {other:?}"),
        };
        Ok(VlessServer { uuid: parse_uuid(uuid)?, transport: Arc::new(transport), vision })
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        if !self.vision {
            return self.connect_cmd(target, CMD_TCP).await;
        }
        let header = request_header(&self.uuid, Some(crate::vision::FLOW), CMD_TCP, Some(target))?;
        let (raw, tls) = self.transport.connect_records().await?;
        Ok(crate::vision::connect(raw, tls, self.uuid, header))
    }

    /// UDP is XUDP (command Mux, no address in the header), so one connection reaches
    /// any number of remotes. Vision doesn't apply: Xray takes XUDP without a flow even
    /// from Vision users, as long as the first Mux frame comes with the header.
    pub fn open_udp(&self, target: &Target) -> UdpPipe {
        let (uuid, transport) = (self.uuid, self.transport.clone());
        crate::udp::xudp(target, move |first| async move {
            let mut req = request_header(&uuid, None, CMD_MUX, None)?;
            req.extend_from_slice(&first);
            let mut stream = transport.connect().await?;
            stream.write_all(&req).await?;
            stream.flush().await?;
            Ok(Box::new(VlessStream { inner: stream, head: Head::Version }) as BoxStream)
        })
    }

    async fn connect_cmd(&self, target: &Target, cmd: u8) -> Result<BoxStream> {
        let header = request_header(&self.uuid, None, cmd, Some(target))?;
        let mut stream = self.transport.connect().await?;
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(Box::new(VlessStream { inner: stream, head: Head::Version }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn uuid_and_header() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(u[0], 0xb8);
        assert!(parse_uuid("1234").is_err());
        let h = request_header(&u, None, CMD_TCP, Some(&Target::new("a.com", 443))).unwrap();
        assert_eq!(&h[17..], &[0, 1, 1, 187, 2, 5, b'a', b'.', b'c', b'o', b'm']);
        let h = request_header(&u, Some("xtls-rprx-vision"), CMD_TCP, Some(&Target::new("a.com", 443))).unwrap();
        assert_eq!(&h[17..20], &[18, 0x0a, 16]);
        assert_eq!(&h[20..36], b"xtls-rprx-vision");
        assert_eq!(&h[36..], &[1, 1, 187, 2, 5, b'a', b'.', b'c', b'o', b'm']);
        assert_eq!(&request_header(&u, None, CMD_MUX, None).unwrap()[17..], &[0, 3]);
    }

    #[tokio::test]
    async fn strips_response_header() {
        for wire in [&b"\x00\x00hello"[..], &b"\x00\x03abchello"[..]] {
            let mut s = VlessStream { inner: wire, head: Head::Version };
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"hello");
        }
        let mut s = VlessStream { inner: &b"\x01\x00x"[..], head: Head::Version };
        assert!(s.read_to_end(&mut Vec::new()).await.is_err());
    }
}
