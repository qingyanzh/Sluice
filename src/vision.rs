//! XTLS-Vision (VLESS `flow=xtls-rprx-vision`), mirroring Xray's `proxy/proxy.go`.
//!
//! The first packets in each direction are wrapped in padding blocks
//! `[uuid(16), first block only] command(1) content_len(2) padding_len(2) content padding`
//! so the TLS handshake of the proxied (inner) connection doesn't show its telltale sizes.
//! Both ends watch the inner handshake; once it turns out to be TLS 1.3, the block that
//! carries the first inner application-data record ends with command Direct and from then
//! on that direction skips the outer TLS: the inner records go onto the raw TCP stream as
//! they are, since they are encrypted already.
//!
//! That needs the outer TLS session at record granularity, which [`RecordLayer`] provides
//! for both our REALITY client and rustls.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use log::debug;
use rand::Rng;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::util::BoxStream;

pub const FLOW: &str = "xtls-rprx-vision";

/// Whether `flow` selects Vision. Xray's `-udp443` variant only lifts its client-side block on
/// UDP/443 (QUIC); on the wire it is plain Vision, and our UDP never carries a flow anyway.
pub fn is_vision(flow: &str) -> bool {
    flow == FLOW || flow == "xtls-rprx-vision-udp443"
}

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;
/// Xray's buffer size; a padding block (uuid and header included) never exceeds it.
const BLOCK: usize = 8192;
const MAX_CONTENT: usize = BLOCK - 21;
const MAX_RECORD: usize = 16384 + 2048;

/// One TLS session's record protection, driven a record at a time.
pub trait RecordLayer: Send {
    /// Protects `data` as application-data records.
    fn seal(&mut self, data: &[u8]) -> io::Result<Vec<u8>>;
    /// Opens one complete record (header included) and returns its application data;
    /// `None` once the peer closed the session.
    fn open(&mut self, record: &[u8]) -> io::Result<Option<Vec<u8>>>;
    /// close_notify, protected.
    fn close(&mut self) -> Vec<u8>;
}

impl RecordLayer for ClientConnection {
    fn seal(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.writer().write_all(data)?;
        let mut out = Vec::with_capacity(data.len() + 64);
        while self.wants_write() {
            self.write_tls(&mut out)?;
        }
        Ok(out)
    }

    fn open(&mut self, record: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let mut rd = record;
        while !rd.is_empty() {
            self.read_tls(&mut rd)?;
        }
        let state = self.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut out = vec![0u8; state.plaintext_bytes_to_read()];
        self.reader().read_exact(&mut out)?;
        if state.peer_has_closed() && out.is_empty() {
            return Ok(None);
        }
        Ok(Some(out))
    }

    fn close(&mut self) -> Vec<u8> {
        self.send_close_notify();
        let mut out = Vec::new();
        while self.wants_write() {
            if self.write_tls(&mut out).is_err() {
                break;
            }
        }
        out
    }
}

/// Reads one TLS record (header included).
pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut rec = vec![0u8; 5];
    r.read_exact(&mut rec).await?;
    let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
    if len > MAX_RECORD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "TLS record too large"));
    }
    rec.resize(5 + len, 0);
    r.read_exact(&mut rec[5..]).await?;
    Ok(rec)
}

/// A rustls handshake fed one record at a time, so no bytes past the handshake are
/// buffered inside rustls: the caller keeps exact control of the raw stream.
pub async fn rustls_handshake(stream: &mut BoxStream, config: Arc<ClientConfig>, sni: ServerName<'static>) -> Result<ClientConnection> {
    let mut conn = ClientConnection::new(config, sni)?;
    loop {
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out)?;
        }
        if !out.is_empty() {
            stream.write_all(&out).await?;
            stream.flush().await?;
        }
        if !conn.is_handshaking() {
            return Ok(conn);
        }
        let rec = read_record(stream).await.context("TLS handshake")?;
        let mut rd = &rec[..];
        while !rd.is_empty() {
            conn.read_tls(&mut rd)?;
        }
        if let Err(e) = conn.process_new_packets() {
            // Flush the alert rustls queued before giving up.
            let mut out = Vec::new();
            let _ = conn.write_tls(&mut out);
            let _ = stream.write_all(&out).await;
            bail!("TLS handshake: {e}");
        }
    }
}

// ---------------------------------------------------------------- TLS sniffing

/// What both directions learn about the inner connection (Xray's TrafficState, shared part).
#[derive(Debug)]
struct Sniff {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    remaining_server_hello: i64,
    cipher: u16,
}

impl Default for Sniff {
    fn default() -> Self {
        Sniff { packets_to_filter: 8, is_tls: false, is_tls12_or_above: false, enable_xtls: false, remaining_server_hello: -1, cipher: 0 }
    }
}

impl Sniff {
    /// Xray's XtlsFilterTls for one packet.
    fn filter(&mut self, b: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == [0x16, 0x03, 0x03] && b[5] == 0x02 {
                self.remaining_server_hello = ((b[3] as i64) << 8 | b[4] as i64) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid = b[43] as usize;
                    if let Some(c) = b.get(43 + sid + 1..43 + sid + 3) {
                        self.cipher = u16::from_be_bytes([c[0], c[1]]);
                    }
                }
            } else if b[..2] == [0x16, 0x03] && b[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i64;
            const TLS13: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
            if b[..end].windows(6).any(|w| w == TLS13) {
                // TLS_AES_128_CCM_8_SHA256 (0x1305) is the one suite Xray won't splice.
                self.enable_xtls = (0x1301..=0x1304).contains(&self.cipher);
                self.packets_to_filter = 0;
                debug!("vision: inner TLS 1.3, cipher {:#06x}, direct copy {}", self.cipher, self.enable_xtls);
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

// ---------------------------------------------------------------- padding

fn pad_block(out: &mut Vec<u8>, content: &[u8], command: u8, uuid: &mut Option<[u8; 16]>, long: bool) {
    let mut rng = rand::thread_rng();
    let mut padding = if content.len() < 900 && long { rng.gen_range(0..500) + 900 - content.len() } else { rng.gen_range(0..256) };
    padding = padding.min(BLOCK - 21 - content.len());
    if let Some(u) = uuid.take() {
        out.extend_from_slice(&u);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
}

/// Uplink half of Vision: decides how each outgoing packet is wrapped.
struct Padder {
    uuid: Option<[u8; 16]>,
    padding: bool,
    direct: bool,
}

impl Padder {
    /// Wraps one packet (`None`: an empty keep-padding block). Returns the plaintext for the
    /// outer TLS; afterwards `self.direct` says whether later packets bypass it.
    fn wrap(&mut self, packet: Option<&[u8]>, sniff: &mut Sniff) -> Vec<u8> {
        let Some(b) = packet else {
            let mut out = Vec::new();
            if self.padding {
                pad_block(&mut out, &[], CMD_CONTINUE, &mut self.uuid, true);
            }
            return out;
        };
        sniff.filter(b);
        if !self.padding {
            return b.to_vec();
        }
        let mut out = Vec::with_capacity(b.len() + 600);
        let command = if sniff.is_tls && b.len() >= 6 && b[..3] == [0x17, 0x03, 0x03] {
            self.padding = false;
            self.direct = sniff.enable_xtls;
            if sniff.enable_xtls {
                CMD_DIRECT
            } else {
                CMD_END
            }
        } else if !sniff.is_tls12_or_above && sniff.packets_to_filter <= 1 {
            // Like Xray, finish one packet early for older receivers.
            self.padding = false;
            CMD_END
        } else {
            CMD_CONTINUE
        };
        pad_block(&mut out, b, command, &mut self.uuid, sniff.is_tls);
        out
    }
}

#[derive(Debug, PartialEq)]
enum UnpadState {
    /// Expecting the uuid that opens the first block.
    Start,
    /// Header bytes still to read: (remaining, collected so far).
    Header(usize, [u8; 5]),
    Content { left: usize, padding: usize, command: u8 },
    Padding { left: usize, command: u8 },
    /// Padding is over; everything passes through.
    Done,
}

/// Downlink half of Vision: strips padding blocks off the plaintext stream.
struct Unpadder {
    uuid: [u8; 16],
    state: UnpadState,
    /// Set once a Direct block ended: the rest comes raw.
    direct: bool,
}

impl Unpadder {
    /// Returns the packets (block contents, or passthrough data) found in `data`.
    fn feed(&mut self, mut data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while !data.is_empty() {
            match &mut self.state {
                UnpadState::Start => {
                    if data.len() >= 21 && data[..16] == self.uuid {
                        data = &data[16..];
                        self.state = UnpadState::Header(5, [0; 5]);
                    } else {
                        self.state = UnpadState::Done;
                    }
                }
                UnpadState::Header(left, h) => {
                    h[5 - *left] = data[0];
                    data = &data[1..];
                    *left -= 1;
                    if *left == 0 {
                        let h = *h;
                        self.state = UnpadState::Content {
                            left: u16::from_be_bytes([h[1], h[2]]) as usize,
                            padding: u16::from_be_bytes([h[3], h[4]]) as usize,
                            command: h[0],
                        };
                        self.block_progress();
                    }
                }
                UnpadState::Content { left, .. } => {
                    let n = (*left).min(data.len());
                    out.push(data[..n].to_vec());
                    data = &data[n..];
                    *left -= n;
                    self.block_progress();
                }
                UnpadState::Padding { left, .. } => {
                    let n = (*left).min(data.len());
                    data = &data[n..];
                    *left -= n;
                    self.block_progress();
                }
                UnpadState::Done => {
                    out.push(data.to_vec());
                    data = &[];
                }
            }
        }
        out
    }

    /// Moves past finished content/padding sections.
    fn block_progress(&mut self) {
        loop {
            self.state = match self.state {
                UnpadState::Content { left: 0, padding, command } => UnpadState::Padding { left: padding, command },
                UnpadState::Padding { left: 0, command: CMD_CONTINUE } => UnpadState::Header(5, [0; 5]),
                UnpadState::Padding { left: 0, command } => {
                    self.direct = command == CMD_DIRECT;
                    if command > CMD_DIRECT {
                        debug!("vision: unknown padding command {command}");
                    }
                    UnpadState::Done
                }
                _ => return,
            };
        }
    }

    fn padding_over(&self) -> bool {
        self.state == UnpadState::Done
    }
}

// ---------------------------------------------------------------- the connection

/// Runs VLESS with Vision over `raw` (the TCP stream) protected by `tls`. `header` is the
/// VLESS request header, sent along with the first packet.
pub fn connect(raw: BoxStream, tls: Box<dyn RecordLayer>, uuid: [u8; 16], header: Vec<u8>) -> BoxStream {
    let tls = Arc::new(Mutex::new(tls));
    let sniff = Arc::new(Mutex::new(Sniff::default()));
    let (mut rd, mut wr) = tokio::io::split(raw);
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);

    let (tls_up, sniff_up) = (tls.clone(), sniff.clone());
    tokio::spawn(async move {
        let mut padder = Padder { uuid: Some(uuid), padding: true, direct: false };
        let mut buf = vec![0u8; MAX_CONTENT];
        // Like Xray, give the first packet a moment to join the header.
        let first = match tokio::time::timeout(Duration::from_millis(100), ird.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => Some(n),
            Err(_) => None,
        };
        let mut plain = header;
        plain.extend(padder.wrap(first.map(|n| &buf[..n]), &mut sniff_up.lock().unwrap()));
        let mut direct = false;
        loop {
            if !plain.is_empty() {
                let out = if direct { Ok(plain) } else { tls_up.lock().unwrap().seal(&plain) };
                let Ok(out) = out else { return };
                if wr.write_all(&out).await.is_err() {
                    return;
                }
            }
            if padder.direct && !direct {
                debug!("vision: uplink switched to direct copy");
                direct = true;
            }
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            plain = padder.wrap(Some(&buf[..n]), &mut sniff_up.lock().unwrap());
        }
        if !direct {
            let close = tls_up.lock().unwrap().close();
            let _ = wr.write_all(&close).await;
        }
        let _ = wr.shutdown().await;
    });

    tokio::spawn(async move {
        let mut unpad = Unpadder { uuid, state: UnpadState::Start, direct: false };
        // VLESS response header: version, addons length, addons.
        let mut head = Vec::new();
        let mut head_done = false;
        loop {
            let Ok(rec) = read_record(&mut rd).await else { break };
            let plain = match tls.lock().unwrap().open(&rec) {
                Ok(Some(p)) => p,
                _ => break,
            };
            let mut data = &plain[..];
            while !head_done {
                let need = if head.len() < 2 { 2 } else { 2 + head[1] as usize };
                if head.len() == need {
                    head_done = true;
                } else if data.is_empty() {
                    break;
                } else {
                    let take = (need - head.len()).min(data.len());
                    head.extend_from_slice(&data[..take]);
                    data = &data[take..];
                }
            }
            if !head_done {
                continue;
            }
            if head[0] != 0 {
                debug!("vision: bad VLESS response version");
                break;
            }
            let packets = if unpad.padding_over() && sniff.lock().unwrap().packets_to_filter <= 0 {
                vec![data.to_vec()]
            } else {
                let packets = unpad.feed(data);
                let mut s = sniff.lock().unwrap();
                for p in &packets {
                    s.filter(p);
                }
                packets
            };
            for p in packets.iter().filter(|p| !p.is_empty()) {
                if iwr.write_all(p).await.is_err() {
                    return;
                }
            }
            if unpad.direct {
                debug!("vision: downlink switched to direct copy");
                let _ = tokio::io::copy(&mut rd, &mut iwr).await;
                break;
            }
        }
        let _ = iwr.shutdown().await;
    });
    Box::new(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [7; 16];

    fn server_hello(tls13: bool) -> Vec<u8> {
        let mut body = vec![0x02, 0, 0, 0, 0x03, 0x03];
        body.extend([1u8; 32]);
        body.push(32);
        body.extend([2u8; 32]);
        body.extend([0x13, 0x01, 0x00]);
        let exts: Vec<u8> = if tls13 { vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04] } else { vec![0xff, 0x01, 0x00, 0x01, 0x00] };
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend((body.len() as u16).to_be_bytes());
        rec.extend(body);
        rec
    }

    #[test]
    fn sniffs_tls13_server_hello() {
        let mut s = Sniff::default();
        s.filter(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0, 0]);
        assert!(s.is_tls && !s.enable_xtls);
        s.filter(&server_hello(true));
        assert!(s.enable_xtls && s.packets_to_filter == 0);
        assert_eq!(s.cipher, 0x1301);
        let mut s = Sniff::default();
        s.filter(&server_hello(false));
        assert!(s.is_tls12_or_above && !s.enable_xtls && s.packets_to_filter == 0);
    }

    #[test]
    fn pads_until_application_data_then_direct() {
        let mut sniff = Sniff::default();
        let mut p = Padder { uuid: Some(UUID), padding: true, direct: false };
        let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 1, 2, 3, 4];
        let a = p.wrap(Some(&hello), &mut sniff);
        assert_eq!(&a[..16], &UUID);
        assert_eq!(a[16], CMD_CONTINUE);
        assert!(a.len() >= 900, "long padding while TLS");
        sniff.filter(&server_hello(true)); // arrives on the downlink
        let app_data = [0x17, 0x03, 0x03, 0x00, 0x02, 9, 9];
        let b = p.wrap(Some(&app_data), &mut sniff);
        assert_eq!(b[0], CMD_DIRECT);
        assert!(p.direct && !p.padding);
        assert_eq!(p.wrap(Some(b"raw"), &mut sniff), b"raw");

        // The receiving side recovers exactly the packets and sees Direct.
        let mut u = Unpadder { uuid: UUID, state: UnpadState::Start, direct: false };
        let wire = [a, b].concat();
        // The uuid arrives whole (it opens a record); the rest may come in pieces.
        let mut got = u.feed(&wire[..30]).concat();
        for chunk in wire[30..].chunks(7) {
            got.extend(u.feed(chunk).concat());
        }
        assert_eq!(got, [&hello[..], &app_data[..]].concat());
        assert!(u.direct && u.padding_over());
    }

    #[test]
    fn non_tls_ends_padding() {
        let mut sniff = Sniff::default();
        let mut p = Padder { uuid: Some(UUID), padding: true, direct: false };
        let mut u = Unpadder { uuid: UUID, state: UnpadState::Start, direct: false };
        let mut got = Vec::new();
        for i in 0..10u8 {
            let pkt = vec![b'a' + i; 3];
            got.extend(u.feed(&p.wrap(Some(&pkt), &mut sniff)).concat());
        }
        assert!(!p.padding && !p.direct && !u.direct && u.padding_over());
        assert_eq!(got.len(), 30);
        assert_eq!(&got[27..], b"jjj");
        // Data not starting with the uuid is never treated as padded.
        let mut u = Unpadder { uuid: UUID, state: UnpadState::Start, direct: false };
        assert_eq!(u.feed(b"plain response bytes here").concat(), b"plain response bytes here");
    }
}
