//! VLESS client (protocol version 0) over TCP, optionally wrapped in TLS.
//!
//! Request:  ver(0) uuid(16) addons_len(0) cmd(1=tcp) port(2) atyp addr, then payload.
//! Response: ver addons_len addons..., then payload.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsConnector;

use crate::trojan::tls_client;
use crate::udp::{over_stream, Framing, UdpPipe};
use crate::util::{connect_tcp, BoxStream, Host, Target};

pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(&hex).map_err(|_| anyhow::anyhow!("bad uuid {s:?}"))?;
    match <[u8; 16]>::try_from(bytes) {
        Ok(b) => Ok(b),
        Err(_) => bail!("bad uuid {s:?}: expected 16 bytes"),
    }
}

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;

/// VLESS uses its own address types: 1=IPv4, 2=domain, 3=IPv6.
fn request_header(uuid: &[u8; 16], cmd: u8, target: &Target) -> Result<Vec<u8>> {
    let mut h = Vec::with_capacity(64);
    h.push(0);
    h.extend_from_slice(uuid);
    h.push(0);
    h.push(cmd);
    h.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(v4)) => {
            h.push(1);
            h.extend_from_slice(&v4.octets());
        }
        Host::Domain(d) => {
            if d.len() > 255 {
                bail!("domain too long");
            }
            h.push(2);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            h.push(3);
            h.extend_from_slice(&v6.octets());
        }
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
    server: String,
    port: u16,
    uuid: [u8; 16],
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl VlessServer {
    pub fn new(server: String, port: u16, uuid: &str, tls: bool, sni: Option<String>, skip_cert_verify: bool) -> Result<Self> {
        let tls = if tls { Some(tls_client(&server, sni, skip_cert_verify)?) } else { None };
        Ok(VlessServer { server, port, uuid: parse_uuid(uuid)?, tls })
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        self.connect_cmd(target, CMD_TCP).await
    }

    /// UDP: packets are `len(u16) payload` inside the stream.
    pub async fn open_udp(&self, target: &Target) -> Result<UdpPipe> {
        Ok(over_stream(self.connect_cmd(target, CMD_UDP).await?, Framing::LengthPrefixed))
    }

    async fn connect_cmd(&self, target: &Target, cmd: u8) -> Result<BoxStream> {
        let tcp = connect_tcp(&self.server, self.port).await?;
        let header = request_header(&self.uuid, cmd, target)?;
        let mut stream: BoxStream = match &self.tls {
            Some((connector, sni)) => Box::new(connector.connect(sni.clone(), tcp).await?),
            None => Box::new(tcp),
        };
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
        let h = request_header(&u, CMD_TCP, &Target::new("a.com", 443)).unwrap();
        assert_eq!(&h[17..], &[0, 1, 1, 187, 2, 5, b'a', b'.', b'c', b'o', b'm']);
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
