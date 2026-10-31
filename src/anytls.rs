//! AnyTLS v2: authenticated TLS sessions, framed streams and idle-session reuse.
//! Wire format and padding follow anytls-go/docs/protocol.md and Session.writeConn.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::transport::Transport;
use crate::udp::{pipe_pair, UdpPipe};
use crate::util::{BoxStream, Target};

const WASTE: u8 = 0;
const SYN: u8 = 1;
const PSH: u8 = 2;
const FIN: u8 = 3;
const SETTINGS: u8 = 4;
const ALERT: u8 = 5;
const UPDATE_PADDING: u8 = 6;
const SYNACK: u8 = 7;
const HEART_REQUEST: u8 = 8;
const HEART_RESPONSE: u8 = 9;
const SERVER_SETTINGS: u8 = 10;
const HEADER: usize = 7;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IDLE: usize = 4;
const WRITE_CHUNK: usize = 16 * 1024;
const DEFAULT_PADDING: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= u16::MAX as usize);
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u8, u32, Vec<u8>)> {
    let mut h = [0; HEADER];
    r.read_exact(&mut h).await?;
    let sid = u32::from_be_bytes(h[1..5].try_into().unwrap());
    let mut data = vec![0; u16::from_be_bytes([h[5], h[6]]) as usize];
    r.read_exact(&mut data).await?;
    Ok((h[0], sid, data))
}

#[derive(Clone, Debug)]
enum Size {
    Range(u16, u16),
    Check,
}

#[derive(Clone, Debug)]
struct PaddingScheme {
    stop: u32,
    packets: HashMap<u32, Vec<Size>>,
    md5: String,
}

impl PaddingScheme {
    fn parse(raw: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(raw)?;
        let mut stop = None;
        let mut packets = HashMap::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("bad padding scheme line"))?;
            if key == "stop" {
                stop = Some(value.parse()?);
                continue;
            }
            let mut sizes = Vec::new();
            for part in value.split(',') {
                if part == "c" {
                    sizes.push(Size::Check);
                } else {
                    let (a, b) = part
                        .split_once('-')
                        .ok_or_else(|| anyhow!("bad padding range"))?;
                    let (a, b): (u16, u16) = (a.parse()?, b.parse()?);
                    if a == 0 || b == 0 {
                        bail!("zero padding size");
                    }
                    sizes.push(Size::Range(a.min(b), a.max(b)));
                }
            }
            packets.insert(key.parse()?, sizes);
        }
        Ok(Self {
            stop: stop.ok_or_else(|| anyhow!("padding scheme needs stop"))?,
            packets,
            md5: hex::encode(Md5::digest(raw)),
        })
    }

    fn sizes(&self, packet: u32) -> Vec<Option<usize>> {
        self.packets
            .get(&packet)
            .into_iter()
            .flatten()
            .map(|size| match *size {
                Size::Check => None,
                // anytls-go uses an exclusive upper bound except for constant ranges.
                Size::Range(a, b) => Some(if a == b {
                    a
                } else {
                    rand::thread_rng().gen_range(a..b)
                } as usize),
            })
            .collect()
    }

    fn padding0(&self) -> usize {
        self.sizes(0).first().copied().flatten().unwrap_or(0)
    }

    fn authentication(&self, hash: &[u8; 32]) -> Vec<u8> {
        let padding = self.padding0();
        let mut auth = hash.to_vec();
        auth.extend_from_slice(&(padding as u16).to_be_bytes());
        auth.resize(auth.len() + padding, 0);
        auth
    }

    /// Each vector is one TLS plaintext write. Frames may span these writes.
    fn apply(&self, packet: u32, mut payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if packet < self.stop {
            for size in self.sizes(packet) {
                let Some(size) = size else {
                    if payload.is_empty() {
                        break;
                    }
                    continue;
                };
                if payload.len() > size {
                    out.push(payload[..size].to_vec());
                    payload = &payload[size..];
                } else if !payload.is_empty() {
                    let mut tail = payload.to_vec();
                    // Match the reference: a gap <= header size is left unpadded.
                    if size > payload.len() + HEADER {
                        tail.extend(frame(WASTE, 0, &vec![0; size - payload.len() - HEADER]));
                    }
                    out.push(tail);
                    payload = &[];
                } else {
                    // For an entirely padded record the chosen size is the data length.
                    out.push(frame(WASTE, 0, &vec![0; size]));
                }
            }
        }
        if !payload.is_empty() {
            out.push(payload.to_vec());
        }
        out
    }
}

struct Client {
    scheme: RwLock<PaddingScheme>,
    // In creation order; the most recently created idle session is preferred.
    sessions: Mutex<Vec<Arc<Session>>>,
    opening: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub struct AnyTlsServer {
    transport: Arc<Transport>,
    hash: [u8; 32],
    udp: bool,
    client: Arc<Client>,
}

impl AnyTlsServer {
    pub fn new(transport: Transport, password: &str, udp: bool) -> Self {
        Self {
            transport: Arc::new(transport),
            hash: Sha256::digest(password.as_bytes()).into(),
            udp,
            client: Arc::new(Client {
                scheme: RwLock::new(PaddingScheme::parse(DEFAULT_PADDING.as_bytes()).unwrap()),
                sessions: Mutex::new(Vec::new()),
                opening: tokio::sync::Mutex::new(()),
            }),
        }
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        let mut address = Vec::new();
        target.write_socks_addr(&mut address)?;
        // Serialize idle selection and reservation; new TLS sessions dial outside this lock.
        let opening = self.client.opening.lock().await;
        trim_idle(&self.client);
        let idle = self
            .client
            .sessions
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|s| s.is_idle())
            .cloned();
        let (stream, written) = match idle {
            Some(session) => {
                let opened = session.open(&address)?;
                drop(opening);
                opened
            }
            None => {
                // Independent new TLS sessions can dial concurrently. Reserve a stream
                // before publishing the session, so another caller cannot claim it idle.
                drop(opening);
                let scheme = self.client.scheme.read().unwrap().clone();
                let mut wire = tokio::time::timeout(IO_TIMEOUT, self.transport.connect())
                    .await
                    .context("AnyTLS TLS connect timeout")?
                    .context("AnyTLS TLS connect")?;
                // Authentication is packet 0, with its own u16 padding length (not
                // a Waste frame). The reference writes it separately from packet 1.
                let auth = scheme.authentication(&self.hash);
                tokio::time::timeout(IO_TIMEOUT, async {
                    wire.write_all(&auth).await?;
                    wire.flush().await
                })
                .await
                .context("AnyTLS authentication write timeout")?
                .context("AnyTLS authentication write")?;
                let session = Session::start(wire, scheme, Arc::downgrade(&self.client));
                let opened = session.open(&address)?;
                self.client.sessions.lock().unwrap().push(session);
                opened
            }
        };
        written
            .await
            .map_err(|_| anyhow!("AnyTLS session closed"))?
            .context("AnyTLS opening stream write")?;
        Ok(Box::new(stream))
    }

    /// UoT v2 non-connect mode: one stream per UdpPipe, with each packet carrying
    /// its destination or reply source address for full-cone UDP semantics.
    pub async fn open_udp(&self) -> Result<UdpPipe> {
        if !self.udp {
            bail!("AnyTLS UDP is disabled (udp=false)");
        }
        let (app, mut side) = pipe_pair();
        let server = self.clone();
        tokio::spawn(async move {
            let packet = loop {
                let packet = tokio::select! {
                    _ = side.tx.closed() => return,
                    packet = side.rx.recv() => match packet { Some(p) => p, None => return },
                };
                if packet.data.len() > u16::MAX as usize {
                    continue;
                }
                break packet;
            };
            let result = async {
                let mut stream = server
                    .connect(&Target::new("sp.v2.udp-over-tcp.arpa", 0))
                    .await?;
                // The request uses SOCKS address tags; subsequent packets use UoT tags.
                let mut header = vec![0]; // isConnect=false
                packet.addr.write_socks_addr(&mut header)?;
                stream.write_all(&header).await?;
                stream
                    .write_all(&crate::udp::uot_frame(&packet.addr, &packet.data)?)
                    .await?;
                stream.flush().await?;
                crate::udp::over_stream(stream, crate::udp::Framing::Uot, side.rx, side.tx, true);
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(e) = result {
                log::debug!("AnyTLS UDP {}: {e:#}", packet.addr);
            }
        });
        Ok(app)
    }
}

fn trim_idle(client: &Client) {
    let mut sessions = client.sessions.lock().unwrap();
    let mut idle = 0;
    // Reverse retain keeps the newest idle sessions.
    for session in sessions.iter().rev() {
        if session.is_idle() {
            idle += 1;
            if idle > MAX_IDLE {
                session.close("idle pool full");
            }
        }
    }
    sessions.retain(|s| !s.state.lock().unwrap().closed);
}

struct StreamStatus {
    closed: bool,
    error: Option<String>,
}

struct Entry {
    tx: mpsc::Sender<Bytes>,
    status: Arc<Mutex<StreamStatus>>,
    opened: Instant,
    acknowledged: bool,
}

struct State {
    streams: HashMap<u32, Entry>,
    next_id: u32,
    idle_since: Instant,
    closed: bool,
    version: u8,
}

struct Write {
    bytes: Vec<u8>,
    done: Option<oneshot::Sender<io::Result<()>>>,
}

struct Session {
    state: Mutex<State>,
    writes: mpsc::Sender<Write>,
    stop: watch::Sender<bool>,
    client: Weak<Client>,
    settings: Vec<u8>,
}

impl Session {
    fn start(wire: BoxStream, scheme: PaddingScheme, client: Weak<Client>) -> Arc<Self> {
        let (writes, mut rx) = mpsc::channel::<Write>(64);
        let (stop, mut stopped) = watch::channel(false);
        let settings = format!(
            "v=2\nclient=sluice/{}\npadding-md5={}",
            env!("CARGO_PKG_VERSION"),
            scheme.md5
        );
        let session = Arc::new(Self {
            state: Mutex::new(State {
                streams: HashMap::new(),
                next_id: 1,
                idle_since: Instant::now(),
                closed: false,
                version: 1,
            }),
            writes,
            stop,
            client,
            settings: frame(SETTINGS, 0, settings.as_bytes()),
        });
        let (mut rd, mut wr) = tokio::io::split(wire);
        let s = session.clone();
        tokio::spawn(async move {
            let writer = async {
                let mut packet = 1;
                while let Some(write) = rx.recv().await {
                    let result = tokio::time::timeout(IO_TIMEOUT, async {
                        for record in scheme.apply(packet, &write.bytes) {
                            wr.write_all(&record).await?;
                            // Flush each plaintext write so TLS record boundaries match padding.
                            wr.flush().await?;
                        }
                        Ok::<_, io::Error>(())
                    })
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "AnyTLS write timeout",
                        ))
                    });
                    packet = packet.saturating_add(1);
                    let failed = result.is_err();
                    if let Some(done) = write.done {
                        let _ = done.send(
                            result
                                .as_ref()
                                .copied()
                                .map_err(|e| io::Error::new(e.kind(), e.to_string())),
                        );
                    }
                    if failed {
                        return result;
                    }
                }
                Ok::<_, io::Error>(())
            };
            let reader = async {
                loop {
                    let (cmd, sid, data) = read_frame(&mut rd).await?;
                    s.receive(cmd, sid, data).await?;
                }
                #[allow(unreachable_code)]
                Ok::<_, io::Error>(())
            };
            let maintenance = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let state = s.state.lock().unwrap();
                    if state.streams.is_empty() && state.idle_since.elapsed() >= IDLE_TIMEOUT {
                        return "AnyTLS idle session expired";
                    }
                    if state.version >= 2
                        && state
                            .streams
                            .values()
                            .any(|e| !e.acknowledged && e.opened.elapsed() >= IO_TIMEOUT)
                    {
                        return "AnyTLS SYNACK timeout";
                    }
                }
            };
            let reason = tokio::select! {
                r = writer => r.err().map_or_else(|| "AnyTLS writer closed".to_string(), |e| format!("AnyTLS write: {e}")),
                r = reader => r.err().map_or_else(|| "AnyTLS peer closed".to_string(), |e| format!("AnyTLS read: {e}")),
                _ = stopped.changed() => "AnyTLS session closed".to_string(),
                reason = maintenance => reason.to_string(),
            };
            log::debug!("{reason}");
            s.close(&reason);
        });
        session
    }

    fn is_idle(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.closed
            && state.next_id != u32::MAX
            && state.streams.is_empty()
            && state.idle_since.elapsed() < IDLE_TIMEOUT
    }

    fn open(
        self: &Arc<Self>,
        address: &[u8],
    ) -> Result<(AnyTlsStream, oneshot::Receiver<io::Result<()>>)> {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.next_id == u32::MAX {
            bail!("AnyTLS session unavailable");
        }
        let sid = state.next_id;
        state.next_id += 1;
        let (tx, rx) = mpsc::channel(16); // At most 1 MiB of queued data per stream.
        let status = Arc::new(Mutex::new(StreamStatus {
            closed: false,
            error: None,
        }));
        state.streams.insert(
            sid,
            Entry {
                tx,
                status: status.clone(),
                opened: Instant::now(),
                acknowledged: false,
            },
        );
        let mut bytes = if sid == 1 {
            self.settings.clone()
        } else {
            Vec::new()
        };
        bytes.extend(frame(SYN, sid, &[]));
        bytes.extend(frame(PSH, sid, address));
        let (done, written) = oneshot::channel();
        // Queue under the state lock so a concurrent close cannot overtake SYN.
        let queued = self
            .writes
            .try_send(Write {
                bytes,
                done: Some(done),
            })
            .is_ok();
        drop(state);
        if !queued {
            self.close("AnyTLS writer unavailable");
        }
        let stream = AnyTlsStream {
            session: self.clone(),
            sid,
            rx,
            status,
            buffer: Bytes::new(),
            pending: None,
            permit: None,
            shutdown: false,
        };
        if !queued {
            bail!("AnyTLS writer closed");
        }
        Ok((stream, written))
    }

    fn close(&self, error: &str) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        state.closed = true;
        for (_, entry) in state.streams.drain() {
            *entry.status.lock().unwrap() = StreamStatus {
                closed: true,
                error: Some(error.into()),
            };
        }
        self.stop.send_replace(true);
    }

    fn finish(&self, sid: u32, notify: bool, error: Option<String>) {
        let mut state = self.state.lock().unwrap();
        let mut writer_failed = false;
        if let Some(entry) = state.streams.remove(&sid) {
            *entry.status.lock().unwrap() = StreamStatus {
                closed: true,
                error,
            };
            if notify && !state.closed {
                writer_failed = self
                    .writes
                    .try_send(Write {
                        bytes: frame(FIN, sid, &[]),
                        done: None,
                    })
                    .is_err();
            }
            if state.streams.is_empty() {
                state.idle_since = Instant::now();
            }
        }
        drop(state);
        if writer_failed {
            self.close("AnyTLS control queue full");
        }
        if let Some(client) = self.client.upgrade() {
            trim_idle(&client);
        }
    }

    async fn receive(&self, cmd: u8, sid: u32, data: Vec<u8>) -> io::Result<()> {
        match cmd {
            PSH => {
                if data.is_empty() {
                    return Ok(());
                }
                let tx = self
                    .state
                    .lock()
                    .unwrap()
                    .streams
                    .get(&sid)
                    .map(|e| e.tx.clone());
                if let Some(tx) = tx {
                    // AnyTLS has no per-stream flow control. Like anytls-go's pipe writer,
                    // pause session reads rather than dropping data when a consumer is slow.
                    if tx.send(Bytes::from(data)).await.is_err() {
                        self.finish(sid, true, None);
                    }
                }
            }
            FIN => self.finish(sid, false, None),
            SYNACK if self.state.lock().unwrap().version >= 2 => {
                if !data.is_empty() {
                    self.finish(
                        sid,
                        true,
                        Some(format!("AnyTLS remote: {}", String::from_utf8_lossy(&data))),
                    );
                } else if let Some(entry) = self.state.lock().unwrap().streams.get_mut(&sid) {
                    entry.acknowledged = true;
                }
            }
            ALERT => {
                let error = format!("AnyTLS alert: {}", String::from_utf8_lossy(&data));
                log::warn!("{error}");
                self.close(&error);
                return Err(io::Error::other(error));
            }
            UPDATE_PADDING => match PaddingScheme::parse(&data) {
                Ok(scheme) => {
                    if let Some(client) = self.client.upgrade() {
                        let mut current = client.scheme.write().unwrap();
                        if current.md5 != scheme.md5 {
                            log::info!("AnyTLS padding scheme updated: {}", scheme.md5);
                            *current = scheme;
                        }
                    }
                }
                Err(e) => log::warn!("AnyTLS invalid padding update: {e:#}"),
            },
            HEART_REQUEST => {
                self.writes
                    .try_send(Write {
                        bytes: frame(HEART_RESPONSE, sid, &[]),
                        done: None,
                    })
                    .map_err(|_| io::Error::other("AnyTLS writer closed"))?;
            }
            SERVER_SETTINGS => {
                for line in String::from_utf8_lossy(&data).lines() {
                    if let Some(v) = line.strip_prefix("v=").and_then(|v| v.parse().ok()) {
                        self.state.lock().unwrap().version = v;
                    }
                }
            }
            WASTE | HEART_RESPONSE | SYNACK => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected AnyTLS command",
                ))
            }
        }
        Ok(())
    }
}

type PendingWrite = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type PendingPermit = Pin<Box<dyn Future<Output = io::Result<mpsc::OwnedPermit<Write>>> + Send>>;

struct AnyTlsStream {
    session: Arc<Session>,
    sid: u32,
    rx: mpsc::Receiver<Bytes>,
    status: Arc<Mutex<StreamStatus>>,
    buffer: Bytes,
    pending: Option<PendingWrite>,
    permit: Option<PendingPermit>,
    shutdown: bool,
}

impl AnyTlsStream {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = pending.as_mut().poll(cx);
        if result.is_ready() {
            self.pending = None;
        }
        result
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.buffer.is_empty() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(data)) => self.buffer = data,
                Poll::Ready(None) => {
                    let status = self.status.lock().unwrap();
                    return Poll::Ready(match &status.error {
                        Some(e) => Err(io::Error::other(e.clone())),
                        None => Ok(()),
                    });
                }
            }
        }
        let n = self.buffer.len().min(out.remaining());
        out.put_slice(&self.buffer.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.poll_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        {
            let status = self.status.lock().unwrap();
            if status.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    status
                        .error
                        .clone()
                        .unwrap_or_else(|| "AnyTLS stream closed".into()),
                )));
            }
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Reserve capacity before accepting bytes. Pending must never enqueue caller data:
        // AsyncWriteExt::write is cancellation safe and may be retried with a different buffer.
        if self.permit.is_none() {
            let writes = self.session.writes.clone();
            self.permit = Some(Box::pin(async move {
                writes
                    .reserve_owned()
                    .await
                    .map_err(|_| io::Error::other("AnyTLS writer closed"))
            }));
        }
        let permit = match self.permit.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => {
                self.permit = None;
                result?
            }
        };
        let n = data.len().min(WRITE_CHUNK);
        let (done, written) = oneshot::channel();
        permit.send(Write {
            bytes: frame(PSH, self.sid, &data[..n]),
            done: Some(done),
        });
        self.pending = Some(Box::pin(async move {
            written
                .await
                .map_err(|_| io::Error::other("AnyTLS session closed"))?
        }));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => {}
        }
        if !self.shutdown {
            self.shutdown = true;
            self.session.finish(self.sid, true, None);
            self.rx.close();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.finish(self.sid, true, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::Packet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn frames_are_big_endian_and_survive_fragmentation() {
        assert_eq!(
            frame(PSH, 0x12345678, b"abc"),
            [2, 0x12, 0x34, 0x56, 0x78, 0, 3, b'a', b'b', b'c']
        );
        let wire = [
            frame(SYN, 1, &[]),
            frame(PSH, 1, &vec![42; 65535]),
            frame(FIN, 1, &[]),
        ]
        .concat();
        let (mut tx, mut rx) = tokio::io::duplex(31);
        let sender = tokio::spawn(async move {
            for chunk in wire.chunks(3) {
                tx.write_all(chunk).await.unwrap();
            }
        });
        assert_eq!(read_frame(&mut rx).await.unwrap(), (SYN, 1, vec![]));
        assert_eq!(
            read_frame(&mut rx).await.unwrap(),
            (PSH, 1, vec![42; 65535])
        );
        assert_eq!(read_frame(&mut rx).await.unwrap(), (FIN, 1, vec![]));
        sender.await.unwrap();
        assert!(read_frame(&mut &b"\x02\0"[..]).await.is_err());
    }

    #[test]
    fn scheme_md5_and_validation() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING.as_bytes()).unwrap();
        assert_eq!(scheme.md5, "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(scheme.padding0(), 30);
        let hash: [u8; 32] = Sha256::digest(b"secret").into();
        let auth = scheme.authentication(&hash);
        assert_eq!(&auth[..32], &hash);
        assert_eq!(&auth[32..34], &[0, 30]);
        assert_eq!(&auth[34..], &[0; 30]);
        assert_eq!(
            hex::encode(Md5::digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex::encode(Md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        for raw in [
            "",
            "1=20-20",
            "stop=x",
            "stop=2\n1=0-1",
            "stop=2\n1=1-65536",
            "stop=2\n1=wat",
            "stop=2\n1=1",
        ] {
            assert!(PaddingScheme::parse(raw.as_bytes()).is_err(), "{raw}");
        }
        let reverse = PaddingScheme::parse(b"stop=2\n1=30-20").unwrap();
        for _ in 0..100 {
            assert!(matches!(reverse.sizes(1)[0], Some(20..=29)));
        }
        assert_ne!(
            scheme.md5,
            PaddingScheme::parse(format!("{DEFAULT_PADDING}\n").as_bytes())
                .unwrap()
                .md5
        );
    }

    #[tokio::test]
    async fn first_packet_groups_settings_syn_and_address_and_updates_only_future_sessions() {
        let (wire, mut remote) = tokio::io::duplex(4096);
        let original = PaddingScheme::parse(b"stop=2\n0=30-30\n1=300-300").unwrap();
        let client = Arc::new(Client {
            scheme: RwLock::new(original.clone()),
            sessions: Mutex::new(Vec::new()),
            opening: tokio::sync::Mutex::new(()),
        });
        let session = Session::start(Box::new(wire), original.clone(), Arc::downgrade(&client));
        let address = [1, 127, 0, 0, 1, 0, 80];
        let (_stream, written) = session.open(&address).unwrap();
        written.await.unwrap().unwrap();
        let expected = [
            session.settings.clone(),
            frame(SYN, 1, &[]),
            frame(PSH, 1, &address),
        ]
        .concat();
        let mut packet1 = vec![0; 300];
        remote.read_exact(&mut packet1).await.unwrap();
        assert_eq!(packet1, original.apply(1, &expected).concat());
        let mut frames = &packet1[..];
        let (_, _, settings) = read_frame(&mut frames).await.unwrap();
        assert_eq!(
            String::from_utf8(settings).unwrap(),
            format!(
                "v=2\nclient=sluice/{}\npadding-md5={}",
                env!("CARGO_PKG_VERSION"),
                original.md5
            )
        );
        assert_eq!(read_frame(&mut frames).await.unwrap(), (SYN, 1, vec![]));
        assert_eq!(
            read_frame(&mut frames).await.unwrap(),
            (PSH, 1, address.to_vec())
        );
        assert_eq!(read_frame(&mut frames).await.unwrap().0, WASTE);
        session
            .receive(SYNACK, 1, b"ignored for v1".to_vec())
            .await
            .unwrap();
        assert!(session.state.lock().unwrap().streams.contains_key(&1));
        session
            .receive(SERVER_SETTINGS, 0, b"v=2\nextra=ignored".to_vec())
            .await
            .unwrap();
        session.receive(SYNACK, 1, vec![]).await.unwrap();
        assert!(session.state.lock().unwrap().streams[&1].acknowledged);
        let update = b"stop=2\n0=12-12\n1=100-100";
        session
            .receive(UPDATE_PADDING, 0, update.to_vec())
            .await
            .unwrap();
        let md5 = client.scheme.read().unwrap().md5.clone();
        session
            .receive(UPDATE_PADDING, 0, update.to_vec())
            .await
            .unwrap();
        assert_eq!(client.scheme.read().unwrap().md5, md5);
        // This existing writer is on packet 2 of the old scheme: no padding.
        session.receive(HEART_REQUEST, 99, vec![]).await.unwrap();
        assert_eq!(
            read_frame(&mut remote).await.unwrap(),
            (HEART_RESPONSE, 99, vec![])
        );
        assert_eq!(client.scheme.read().unwrap().padding0(), 12);
        session.close("test finished");
    }

    #[tokio::test]
    async fn session_read_errors_reach_streams() {
        let (wire, remote) = tokio::io::duplex(4096);
        let session = Session::start(
            Box::new(wire),
            PaddingScheme::parse(b"stop=0").unwrap(),
            Weak::new(),
        );
        let (mut stream, written) = session.open(&[1, 127, 0, 0, 1, 0, 80]).unwrap();
        written.await.unwrap().unwrap();
        drop(remote);
        let error = stream.read_u8().await.unwrap_err();
        assert!(error.to_string().contains("AnyTLS read:"), "{error}");
    }

    #[tokio::test]
    async fn padding_matches_reference_boundaries() {
        let scheme =
            PaddingScheme::parse(b"stop=8\n1=20-20,c,30-30\n2=9-9,20-20\n3=20-20\n4=2-2,2-2")
                .unwrap();
        let payload = frame(PSH, 1, b"q"); // 8 bytes
        let padded = scheme.apply(1, &payload);
        assert_eq!(padded.iter().map(Vec::len).collect::<Vec<_>>(), [20]);
        let mut wire = &padded[0][..];
        assert_eq!(
            read_frame(&mut wire).await.unwrap(),
            (PSH, 1, b"q".to_vec())
        );
        assert_eq!(read_frame(&mut wire).await.unwrap(), (WASTE, 0, vec![0; 5]));
        let padded = scheme.apply(2, &payload);
        // First record has no room for a Waste header; next record is all Waste.
        assert_eq!(padded, [payload.clone(), frame(WASTE, 0, &[0; 20])]);
        assert_eq!(scheme.apply(3, &[1; 13]), [vec![1; 13]]); // exactly seven spare bytes
        assert_eq!(scheme.apply(4, &payload).concat(), payload); // split header + remainder
        assert_eq!(scheme.apply(5, &payload), std::slice::from_ref(&payload)); // missing packet rule
        assert_eq!(scheme.apply(8, &payload), std::slice::from_ref(&payload)); // stop is exclusive
        assert_eq!(
            scheme
                .apply(1, &[1; 40])
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            [20, 30]
        );
        assert_eq!(
            scheme
                .apply(1, &[1; 70])
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            [20, 30, 20]
        );
    }

    struct Peer {
        server: AnyTlsServer,
        accepted: Arc<AtomicUsize>,
        hearts: Arc<AtomicUsize>,
        listener: tokio::task::JoinHandle<()>,
        tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.listener.abort();
            for task in self.tasks.lock().unwrap().drain(..) {
                task.abort();
            }
            for session in self.server.client.sessions.lock().unwrap().iter() {
                session.close("test finished");
            }
        }
    }

    // A real loopback TLS peer validates authentication and the proxy/UoT wire formats.
    async fn peer() -> Peer {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let mut config = config;
        config.alpn_protocols = vec![b"anytls-test".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => Some(listener),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("sandbox forbids loopback bind; exercising TLS over in-memory transport");
                None
            }
            Err(e) => panic!("loopback bind: {e}"),
        };
        let port = listener
            .as_ref()
            .map_or(443, |l| l.local_addr().unwrap().port());
        let (memory_tx, mut memory_rx) = mpsc::unbounded_channel::<BoxStream>();
        let mut transport = Transport::anytls(
            "127.0.0.1".into(),
            port,
            Some("localhost".into()),
            true,
            &["anytls-test".into()],
            false,
            Some("chrome"),
        )
        .unwrap();
        if listener.is_none() {
            transport = transport.with_test_wire(memory_tx);
        }
        let accepted = Arc::new(AtomicUsize::new(0));
        let hearts = Arc::new(AtomicUsize::new(0));
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let (a, h, t) = (accepted.clone(), hearts.clone(), tasks.clone());
        let listener = tokio::spawn(async move {
            loop {
                let tcp: BoxStream = match &listener {
                    Some(listener) => Box::new(listener.accept().await.unwrap().0),
                    None => match memory_rx.recv().await {
                        Some(wire) => wire,
                        None => break,
                    },
                };
                a.fetch_add(1, Ordering::SeqCst);
                let (acceptor, hearts) = (acceptor.clone(), h.clone());
                let task = tokio::spawn(async move {
                    let mut wire = acceptor.accept(tcp).await.unwrap();
                    assert_eq!(wire.get_ref().1.alpn_protocol(), Some(&b"anytls-test"[..]));
                    let mut hash = [0; 32];
                    wire.read_exact(&mut hash).await.unwrap();
                    assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(b"secret")));
                    let mut padding = vec![0; wire.read_u16().await.unwrap() as usize];
                    wire.read_exact(&mut padding).await.unwrap();
                    // The second session may use the updated scheme.
                    assert!(padding.len() == 30 || padding.len() == 12);
                    run_peer(&mut wire, hearts).await;
                });
                t.lock().unwrap().push(task);
            }
        });
        Peer {
            server: AnyTlsServer::new(transport, "secret", true),
            accepted,
            hearts,
            listener,
            tasks,
        }
    }

    enum PeerStream {
        Tcp,
        UotRequest,
        Uot(Vec<u8>),
    }

    async fn run_peer<S: AsyncRead + AsyncWrite + Unpin>(wire: &mut S, hearts: Arc<AtomicUsize>) {
        let (cmd, sid, settings) = read_frame(wire).await.unwrap();
        assert_eq!((cmd, sid), (SETTINGS, 0));
        let settings = String::from_utf8(settings).unwrap();
        assert!(settings.starts_with("v=2\nclient=sluice/"));
        let default_md5 = PaddingScheme::parse(DEFAULT_PADDING.as_bytes())
            .unwrap()
            .md5;
        let update = b"stop=3\n0=12-12\n1=80-80\n2=40-40,c,80-80";
        let update_md5 = PaddingScheme::parse(update).unwrap().md5;
        assert!(settings.ends_with(&default_md5) || settings.ends_with(&update_md5));
        wire.write_all(&frame(SERVER_SETTINGS, 0, b"v=2"))
            .await
            .unwrap();
        wire.write_all(&frame(UPDATE_PADDING, 0, update))
            .await
            .unwrap();
        wire.write_all(&frame(HEART_REQUEST, 42, &[]))
            .await
            .unwrap();
        wire.flush().await.unwrap();
        let mut streams: HashMap<u32, Option<PeerStream>> = HashMap::new();
        let mut last_id = 0;
        while let Ok((cmd, sid, data)) = read_frame(wire).await {
            match cmd {
                WASTE => {}
                SYN => {
                    assert!(sid > last_id);
                    last_id = sid;
                    streams.insert(sid, None);
                }
                FIN => {
                    streams.remove(&sid);
                } // Do not send a FIN back.
                HEART_RESPONSE => {
                    assert_eq!(sid, 42);
                    hearts.fetch_add(1, Ordering::SeqCst);
                }
                PSH => {
                    let stream = streams.get_mut(&sid).expect("PSH before SYN");
                    if stream.is_none() {
                        let (target, n) = crate::udp::parse_socks_addr(&data).unwrap();
                        assert_eq!(n, data.len());
                        if target.host_str() == "error.test" {
                            wire.write_all(&frame(SYNACK, sid, b"connection refused"))
                                .await
                                .unwrap();
                            continue;
                        }
                        if target.host_str() == "alert.test" {
                            wire.write_all(&frame(ALERT, 0, b"test alert"))
                                .await
                                .unwrap();
                            wire.flush().await.unwrap();
                            return;
                        }
                        wire.write_all(&frame(SYNACK, sid, &[])).await.unwrap();
                        if target.host_str() == "sp.v2.udp-over-tcp.arpa" {
                            assert_eq!(target.port, 0);
                            *stream = Some(PeerStream::UotRequest);
                        } else {
                            *stream = Some(PeerStream::Tcp);
                        }
                    } else {
                        match stream.as_mut().unwrap() {
                            PeerStream::UotRequest => {
                                // The v2 request uses SOCKS tags, unlike packet addresses.
                                assert_eq!(data[0], 0);
                                let (target, n) = crate::udp::parse_socks_addr(&data[1..]).unwrap();
                                assert_eq!(n + 1, data.len());
                                assert!(matches!(
                                    target.host_str().as_str(),
                                    "127.0.0.1" | "::1" | "udp.test"
                                ));
                                *stream = Some(PeerStream::Uot(Vec::new()));
                            }
                            PeerStream::Uot(pending) => {
                                pending.extend_from_slice(&data);
                                while !pending.is_empty() {
                                    let addr_len = match pending[0] {
                                        0 => 7,  // IPv4 + port
                                        1 => 19, // IPv6 + port
                                        2 => match pending.get(1) {
                                            Some(len) => 4 + *len as usize,
                                            None => break,
                                        },
                                        tag => panic!("invalid UoT address tag {tag}"),
                                    };
                                    if pending.len() < addr_len + 2 {
                                        break;
                                    }
                                    let n = u16::from_be_bytes([
                                        pending[addr_len],
                                        pending[addr_len + 1],
                                    ]) as usize;
                                    let end = addr_len + 2 + n;
                                    if pending.len() < end {
                                        break;
                                    }
                                    for chunk in pending[..end].chunks(WRITE_CHUNK) {
                                        wire.write_all(&frame(PSH, sid, chunk)).await.unwrap();
                                    }
                                    if &pending[addr_len + 2..end] == b"full-cone" {
                                        // B replies to A's packet before this pipe ever sends to B.
                                        // UoT IPv4 source 127.0.0.2:5353, then length + payload.
                                        let reply = [
                                            &[0, 127, 0, 0, 2, 0x14, 0xe9, 0, 17][..],
                                            b"B-for-A:full-cone",
                                        ]
                                        .concat();
                                        // Split inside the source address and length as well.
                                        for chunk in reply.chunks(2) {
                                            wire.write_all(&frame(PSH, sid, chunk)).await.unwrap();
                                        }
                                    }
                                    pending.drain(..end);
                                }
                            }
                            PeerStream::Tcp if data == b"server-fin" => {
                                wire.write_all(&frame(PSH, sid, b"before-fin"))
                                    .await
                                    .unwrap();
                                wire.write_all(&frame(FIN, sid, &[])).await.unwrap();
                                streams.remove(&sid);
                            }
                            PeerStream::Tcp => {
                                wire.write_all(&frame(PSH, sid, &data)).await.unwrap();
                            }
                        }
                    }
                }
                _ => panic!("unexpected command {cmd}"),
            }
            if wire.flush().await.is_err() {
                return;
            }
        }
    }

    async fn echo(server: &AnyTlsServer, data: &[u8]) -> BoxStream {
        let mut stream = server
            .connect(&Target::new("echo.test", 443))
            .await
            .unwrap();
        let mut reply = vec![0; data.len()];
        {
            let (mut rd, mut wr) = tokio::io::split(&mut stream);
            tokio::try_join!(wr.write_all(data), rd.read_exact(&mut reply)).unwrap();
        }
        assert_eq!(reply, data);
        stream
    }

    #[tokio::test]
    async fn tls_echo_reuse_padding_update_and_newest_idle() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let peer = peer().await;
            let a = echo(&peer.server, &vec![13; 2_000_000]).await;
            let b = echo(&peer.server, b"second active session").await;
            assert_eq!(peer.accepted.load(Ordering::SeqCst), 2);
            drop(a);
            drop(b);
            let c = echo(&peer.server, b"reused newest").await;
            assert_eq!(peer.accepted.load(Ordering::SeqCst), 2);
            {
                let sessions = peer.server.client.sessions.lock().unwrap();
                assert_eq!(sessions[0].state.lock().unwrap().next_id, 2);
                assert_eq!(sessions[1].state.lock().unwrap().next_id, 3);
            }
            assert_eq!(peer.server.client.scheme.read().unwrap().padding0(), 12);
            // HeartRequest is handled without interfering with the streams.
            while peer.hearts.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
            drop(c);
            // Force expiry without wall-clock sleeps, then verify a fresh TLS session.
            for session in peer.server.client.sessions.lock().unwrap().iter() {
                session.state.lock().unwrap().idle_since = Instant::now() - IDLE_TIMEOUT;
            }
            drop(echo(&peer.server, b"new after expiry").await);
            assert_eq!(peer.accepted.load(Ordering::SeqCst), 3);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn uot_v2_full_cone_reply_from_uncontacted_source() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let peer = peer().await;
            let mut pipe = peer.server.open_udp().await.unwrap();
            pipe.tx
                .send(Packet {
                    addr: Target::new("127.0.0.1", 53),
                    data: b"full-cone".to_vec(),
                })
                .await
                .unwrap();
            let reply = pipe.rx.recv().await.unwrap();
            assert_eq!(reply.addr.to_string(), "127.0.0.1:53");
            assert_eq!(reply.data, b"full-cone");
            let reply = pipe.rx.recv().await.unwrap();
            assert_eq!(reply.addr.to_string(), "127.0.0.2:5353");
            assert_eq!(reply.data, b"B-for-A:full-cone");
            drop(pipe);
            loop {
                if peer
                    .server
                    .client
                    .sessions
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|s| s.is_idle())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn synack_error_alert_and_remote_fin() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let peer = peer().await;
            let mut stream = peer
                .server
                .connect(&Target::new("error.test", 1))
                .await
                .unwrap();
            let error = stream.read_u8().await.unwrap_err();
            assert!(error.to_string().contains("connection refused"));
            assert!(stream.write_all(b"x").await.is_err());
            drop(stream);
            let mut stream = peer
                .server
                .connect(&Target::new("echo.test", 1))
                .await
                .unwrap();
            stream.write_all(b"server-fin").await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"before-fin");
            drop(stream);
            let mut stream = peer
                .server
                .connect(&Target::new("alert.test", 1))
                .await
                .unwrap();
            assert!(stream
                .read_u8()
                .await
                .unwrap_err()
                .to_string()
                .contains("test alert"));
            drop(stream);
            drop(echo(&peer.server, b"recover after alert").await);
            assert_eq!(peer.accepted.load(Ordering::SeqCst), 2);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn uot_v2_multiple_destinations_and_disabled_udp() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let peer = peer().await;
            let mut pipe = peer.server.open_udp().await.unwrap();
            pipe.tx
                .send(Packet {
                    addr: Target::new("127.0.0.1", 53),
                    data: vec![0; 65536],
                })
                .await
                .unwrap();
            for host in ["127.0.0.1", "::1", "udp.test", "127.0.0.1"] {
                let target = Target::new(host, 53);
                for data in [vec![], b"dns query".to_vec(), vec![5; 65535]] {
                    pipe.tx
                        .send(Packet {
                            addr: target.clone(),
                            data: data.clone(),
                        })
                        .await
                        .unwrap();
                    let reply = pipe.rx.recv().await.unwrap();
                    assert_eq!(reply.addr.to_string(), target.to_string());
                    assert_eq!(reply.data, data);
                }
            }
            assert_eq!(peer.accepted.load(Ordering::SeqCst), 1);
            {
                let sessions = peer.server.client.sessions.lock().unwrap();
                assert_eq!(sessions.len(), 1);
                let state = sessions[0].state.lock().unwrap();
                assert_eq!(state.next_id, 2);
                assert_eq!(state.streams.len(), 1);
            }
            let mut disabled = peer.server.clone();
            disabled.udp = false;
            assert!(disabled
                .open_udp()
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("disabled"));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pending_writes_do_not_accept_cancelled_buffers() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (wire, mut remote) = tokio::io::duplex(4096);
            let session = Session::start(
                Box::new(wire),
                PaddingScheme::parse(b"stop=0").unwrap(),
                Weak::new(),
            );
            let (mut stream, _) = session.open(&[1, 127, 0, 0, 1, 0, 80]).unwrap();
            // No task yield: the first frame is accepted, but its write acknowledgement is pending.
            stream.write_all(b"accepted").await.unwrap();
            std::future::poll_fn(|cx| {
                assert!(Pin::new(&mut stream)
                    .poll_write(cx, b"cancelled")
                    .is_pending());
                Poll::Ready(())
            })
            .await;
            stream.write_all(b"replacement").await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(read_frame(&mut remote).await.unwrap().0, SETTINGS);
            assert_eq!(read_frame(&mut remote).await.unwrap().0, SYN);
            assert_eq!(read_frame(&mut remote).await.unwrap().0, PSH); // destination
            assert_eq!(read_frame(&mut remote).await.unwrap().2, b"accepted");
            assert_eq!(read_frame(&mut remote).await.unwrap().2, b"replacement");
            stream.shutdown().await.unwrap();
            assert_eq!(read_frame(&mut remote).await.unwrap(), (FIN, 1, vec![]));
            session.close("test finished");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn multiplex_and_pool_limits_and_failure_cleanup() {
        let (wire, _remote) = tokio::io::duplex(1024);
        let client = Arc::new(Client {
            scheme: RwLock::new(PaddingScheme::parse(b"stop=0").unwrap()),
            sessions: Mutex::new(Vec::new()),
            opening: tokio::sync::Mutex::new(()),
        });
        let session = Session::start(
            Box::new(wire),
            client.scheme.read().unwrap().clone(),
            Arc::downgrade(&client),
        );
        let (mut a, _) = session.open(&[1, 127, 0, 0, 1, 0, 80]).unwrap();
        let (mut b, _) = session.open(&[1, 127, 0, 0, 1, 0, 81]).unwrap();
        session.receive(PSH, 2, b"two".to_vec()).await.unwrap();
        session.receive(PSH, 1, b"one".to_vec()).await.unwrap();
        let mut buf = [0; 3];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"one");
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two");
        // A full receive queue backpressures the session until the application reads.
        for i in 0..16 {
            session.receive(PSH, 1, vec![i]).await.unwrap();
        }
        let mut blocked = Box::pin(session.receive(PSH, 1, vec![16]));
        std::future::poll_fn(|cx| {
            assert!(blocked.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(a.read_u8().await.unwrap(), 0);
        blocked.await.unwrap();
        for i in 1..=16 {
            assert_eq!(a.read_u8().await.unwrap(), i);
        }
        // Dropping one stream leaves the other open, and late frames are discarded.
        drop(a);
        session.receive(PSH, 1, b"late".to_vec()).await.unwrap();
        assert!(!session.state.lock().unwrap().streams.contains_key(&1));
        assert!(session.state.lock().unwrap().streams.contains_key(&2));
        session.close("test disconnect");
        assert!(b
            .read_u8()
            .await
            .unwrap_err()
            .to_string()
            .contains("test disconnect"));
        assert!(session.state.lock().unwrap().streams.is_empty());
        // Invalid updates leave the previous scheme intact.
        session
            .receive(UPDATE_PADDING, 0, b"invalid".to_vec())
            .await
            .unwrap();
        assert_eq!(client.scheme.read().unwrap().stop, 0);
        let mut peers = Vec::new();
        for _ in 0..MAX_IDLE + 2 {
            let (wire, remote) = tokio::io::duplex(1024);
            peers.push(remote);
            let s = Session::start(
                Box::new(wire),
                client.scheme.read().unwrap().clone(),
                Arc::downgrade(&client),
            );
            client.sessions.lock().unwrap().push(s);
        }
        let newest = client.sessions.lock().unwrap().last().unwrap().clone();
        trim_idle(&client);
        assert_eq!(client.sessions.lock().unwrap().len(), MAX_IDLE);
        assert!(Arc::ptr_eq(
            client.sessions.lock().unwrap().last().unwrap(),
            &newest
        ));
        for s in client.sessions.lock().unwrap().iter() {
            s.close("test finished");
        }
    }
}
