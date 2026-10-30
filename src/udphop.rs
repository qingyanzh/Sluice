//! Hysteria2 port hopping (as in apernet/hysteria `extras/transport/udphop`): quinn talks to
//! one fixed "virtual" server address, while this socket wrapper sends every datagram to the
//! currently chosen real port and re-picks a random port every `interval`. Replies from any of
//! the server's ports are reported to quinn as coming from the virtual address, so the QUIC
//! connection never notices the hop.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;
use log::{debug, warn};

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Parses `20000-50000`, `443,8443,20000-30000` (`;` also separates, as in Surge) into a
/// de-duplicated port list.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let port = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| anyhow!("bad port {s:?}"));
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    bail!("bad port range {part:?}");
                }
                ports.extend(a..=b);
            }
            None => ports.push(port(part)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        bail!("empty port list {spec:?}");
    }
    Ok(ports)
}

pub type MakeSocket = Box<dyn Fn() -> io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

struct State {
    /// Bumped on every hop, so pollers know to follow the new socket.
    generation: u64,
    current: Arc<dyn AsyncUdpSocket>,
    /// The socket before the last hop, still read until the next one for in-flight replies.
    prev: Option<Arc<dyn AsyncUdpSocket>>,
    port: u16,
    next_hop: Instant,
    /// The last receiver, woken on a hop so it starts polling the new socket.
    recv_waker: Option<std::task::Waker>,
}

/// Each hop also moves to a fresh local socket, like upstream: a new 5-tuple both ways, so
/// NATs and the server-side redirect (iptables/pf) see a new flow instead of a clashing one.
pub struct UdpHop {
    make: MakeSocket,
    /// The address quinn connects to; every server reply is rewritten to come from it.
    virtual_addr: SocketAddr,
    ports: Vec<u16>,
    interval: Duration,
    segments: (usize, usize),
    state: Mutex<State>,
}

impl UdpHop {
    /// `virtual_addr` carries the server IP; its port is irrelevant on the wire.
    pub fn new(make: MakeSocket, virtual_addr: SocketAddr, ports: Vec<u16>, interval: Duration) -> io::Result<Self> {
        let current = make()?;
        let segments = (current.max_transmit_segments(), current.max_receive_segments());
        let interval = interval.max(MIN_INTERVAL);
        let state = State { generation: 0, current, prev: None, port: pick(&ports, None), next_hop: Instant::now() + interval, recv_waker: None };
        Ok(UdpHop { make, virtual_addr, ports, interval, segments, state: Mutex::new(state) })
    }

    /// The socket and server address to send to now, hopping first if it is time.
    fn sender(&self) -> (Arc<dyn AsyncUdpSocket>, SocketAddr) {
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        if now >= st.next_hop {
            st.next_hop = now + self.interval;
            match (self.make)() {
                Ok(sock) => {
                    let port = pick(&self.ports, Some(st.port));
                    debug!("hysteria2 port hop {} -> {}", st.port, port);
                    st.prev = Some(std::mem::replace(&mut st.current, sock));
                    st.port = port;
                    st.generation += 1;
                    if let Some(w) = st.recv_waker.take() {
                        w.wake();
                    }
                }
                Err(e) => warn!("hysteria2 port hop: new socket failed: {e}"),
            }
        }
        (st.current.clone(), SocketAddr::new(self.virtual_addr.ip(), st.port))
    }

    fn rewrite(&self, meta: &mut [RecvMeta], n: usize) {
        for m in meta.iter_mut().take(n) {
            if m.addr.ip() == self.virtual_addr.ip() && self.ports.binary_search(&m.addr.port()).is_ok() {
                m.addr = self.virtual_addr;
            }
        }
    }
}

/// A random port, different from `avoid` whenever there is a choice.
fn pick(ports: &[u16], avoid: Option<u16>) -> u16 {
    let mut rng = rand::thread_rng();
    loop {
        let p = ports[rng.gen_range(0..ports.len())];
        if ports.len() == 1 || Some(p) != avoid {
            return p;
        }
    }
}

impl fmt::Debug for UdpHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UdpHop")
    }
}

/// Writability of whichever socket is current, re-created after each hop.
struct HopPoller {
    hop: Arc<UdpHop>,
    inner: Option<(u64, Pin<Box<dyn UdpPoller>>)>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopPoller")
    }
}

impl UdpPoller for HopPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let (generation, current) = {
            let st = self.hop.state.lock().unwrap();
            (st.generation, st.current.clone())
        };
        if self.inner.as_ref().is_none_or(|(g, _)| *g != generation) {
            self.inner = Some((generation, current.create_io_poller()));
        }
        self.inner.as_mut().unwrap().1.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller { hop: self, inner: None })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (sock, dest) = self.sender();
        if transmit.destination != self.virtual_addr {
            return sock.try_send(transmit);
        }
        sock.try_send(&Transmit { destination: dest, ..*transmit })
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let (prev, current) = {
            let mut st = self.state.lock().unwrap();
            st.recv_waker = Some(cx.waker().clone());
            (st.prev.clone(), st.current.clone())
        };
        // Errors on the retiring socket don't matter; it is dropped at the next hop anyway.
        if let Some(prev) = prev {
            if let Poll::Ready(Ok(n)) = prev.poll_recv(cx, bufs, meta) {
                self.rewrite(meta, n);
                return Poll::Ready(Ok(n));
            }
        }
        let n = std::task::ready!(current.poll_recv(cx, bufs, meta))?;
        self.rewrite(meta, n);
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.lock().unwrap().current.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.lock().unwrap().current.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.segments.0
    }

    fn max_receive_segments(&self) -> usize {
        self.segments.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        assert_eq!(parse_ports("443").unwrap(), [443]);
        assert_eq!(parse_ports("20000-20003").unwrap(), [20000, 20001, 20002, 20003]);
        assert_eq!(parse_ports("8443, 443;443,10-11").unwrap(), [10, 11, 443, 8443]);
        assert_eq!(parse_ports("20000-50000").unwrap().len(), 30001);
        for bad in ["", "0", "5-3", "x", "1-", "70000"] {
            assert!(parse_ports(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pick_avoids_current() {
        for _ in 0..100 {
            assert_ne!(pick(&[1, 2], Some(1)), 1);
        }
        assert_eq!(pick(&[7], Some(7)), 7);
    }
}
