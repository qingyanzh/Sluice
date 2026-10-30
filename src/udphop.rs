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
use log::debug;

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

struct State {
    current: SocketAddr,
    next_hop: Instant,
}

pub struct UdpHop {
    inner: Arc<dyn AsyncUdpSocket>,
    /// The address quinn connects to; every server reply is rewritten to come from it.
    virtual_addr: SocketAddr,
    ports: Vec<u16>,
    interval: Duration,
    state: Mutex<State>,
}

impl UdpHop {
    /// `virtual_addr` carries the server IP; its port is irrelevant on the wire.
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, virtual_addr: SocketAddr, ports: Vec<u16>, interval: Duration) -> Self {
        let interval = interval.max(MIN_INTERVAL);
        let current = SocketAddr::new(virtual_addr.ip(), pick(&ports, None));
        UdpHop { inner, virtual_addr, ports, interval, state: Mutex::new(State { current, next_hop: Instant::now() + interval }) }
    }

    fn destination(&self) -> SocketAddr {
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        if now >= st.next_hop {
            let port = pick(&self.ports, Some(st.current.port()));
            debug!("hysteria2 port hop {} -> {}", st.current.port(), port);
            st.current.set_port(port);
            st.next_hop = now + self.interval;
        }
        st.current
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

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.destination != self.virtual_addr {
            return self.inner.try_send(transmit);
        }
        self.inner.try_send(&Transmit { destination: self.destination(), ..*transmit })
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for m in meta.iter_mut().take(n) {
            if m.addr.ip() == self.virtual_addr.ip() && self.ports.binary_search(&m.addr.port()).is_ok() {
                m.addr = self.virtual_addr;
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
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
