//! Process-wide traffic counters. They survive config reloads. Totals are also kept per
//! policy and per node, and a 1s sampler keeps the last ten minutes of rates.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::util::BoxStream;

static UP: AtomicU64 = AtomicU64::new(0);
static DOWN: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicI64 = AtomicI64::new(0);

pub fn add_up(n: usize) {
    UP.fetch_add(n as u64, Ordering::Relaxed);
}

pub fn add_down(n: usize) {
    DOWN.fetch_add(n as u64, Ordering::Relaxed);
}

/// (bytes sent upstream, bytes received, connections open now).
pub fn snapshot() -> (u64, u64, i64) {
    (UP.load(Ordering::Relaxed), DOWN.load(Ordering::Relaxed), ACTIVE.load(Ordering::Relaxed).max(0))
}

/// Cumulative bytes for one policy or node.
#[derive(Default)]
pub struct Bucket {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Bucket {
    pub fn add(&self, up: usize, down: usize) {
        self.up.fetch_add(up as u64, Ordering::Relaxed);
        self.down.fetch_add(down as u64, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    Policy,
    Node,
}

type Buckets = BTreeMap<(Kind, String), Arc<Bucket>>;
static BUCKETS: Mutex<Buckets> = Mutex::new(BTreeMap::new());

/// The counter for a policy or node, created on first use.
pub fn bucket(kind: Kind, name: &str) -> Arc<Bucket> {
    BUCKETS.lock().unwrap().entry((kind, name.to_string())).or_default().clone()
}

/// (name, up, down) for every policy or node seen so far.
pub fn totals(kind: Kind) -> Vec<(String, u64, u64)> {
    BUCKETS
        .lock()
        .unwrap()
        .iter()
        .filter(|((k, _), _)| *k == kind)
        .map(|((_, n), b)| (n.clone(), b.up.load(Ordering::Relaxed), b.down.load(Ordering::Relaxed)))
        .collect()
}

/// One second of traffic: bytes per second in total and for each policy that moved data.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub time_ms: u64,
    pub up: u64,
    pub down: u64,
    pub policies: Vec<(String, u64, u64)>,
}

/// The last `cap` samples, oldest first, plus the totals seen at the previous tick.
pub struct Ring {
    cap: usize,
    samples: VecDeque<Sample>,
    last_total: Option<(u64, u64)>,
    last_policy: BTreeMap<String, (u64, u64)>,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Ring { cap, samples: VecDeque::with_capacity(cap), last_total: None, last_policy: BTreeMap::new() }
    }

    /// Records the change since the previous call, over `secs` seconds. The first call
    /// only sets the baseline.
    pub fn tick(&mut self, time_ms: u64, secs: f64, total: (u64, u64), policies: &[(String, u64, u64)]) -> Option<&Sample> {
        let rate = |now: u64, then: u64| (now.saturating_sub(then) as f64 / secs.max(0.001)).round() as u64;
        let prev_total = self.last_total.replace(total);
        let mut per = Vec::new();
        for (name, up, down) in policies {
            let (pu, pd) = self.last_policy.insert(name.clone(), (*up, *down)).unwrap_or((0, 0));
            let (ru, rd) = (rate(*up, pu), rate(*down, pd));
            if prev_total.is_some() && (ru > 0 || rd > 0) {
                per.push((name.clone(), ru, rd));
            }
        }
        let (pu, pd) = prev_total?;
        if self.samples.len() >= self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample { time_ms, up: rate(total.0, pu), down: rate(total.1, pd), policies: per });
        self.samples.back()
    }

    pub fn samples(&self) -> Vec<Sample> {
        self.samples.iter().cloned().collect()
    }
}

/// Ten minutes at one sample per second.
pub const RING_SECS: usize = 600;
static RING: Mutex<Option<Ring>> = Mutex::new(None);

pub fn history() -> Vec<Sample> {
    RING.lock().unwrap().as_ref().map_or_else(Vec::new, Ring::samples)
}

pub fn sample_json(s: &Sample) -> String {
    let per: Vec<String> = s
        .policies
        .iter()
        .map(|(n, u, d)| format!("{{\"policy\":{},\"up\":{u},\"down\":{d}}}", crate::live::json_str(n)))
        .collect();
    format!("{{\"time_ms\":{},\"up\":{},\"down\":{},\"policies\":[{}]}}", s.time_ms, s.up, s.down, per.join(","))
}

/// Starts the 1s sampler (once per process): fills the rate ring, updates each live
/// connection's rate and publishes a `traffic` event.
pub fn spawn_sampler() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.tick().await;
            let mut last = tokio::time::Instant::now();
            loop {
                tick.tick().await;
                let secs = last.elapsed().as_secs_f64();
                last = tokio::time::Instant::now();
                let (up, down, active) = snapshot();
                let sample = {
                    let mut ring = RING.lock().unwrap();
                    let ring = ring.get_or_insert_with(|| Ring::new(RING_SECS));
                    ring.tick(crate::live::now_ms(), secs, (up, down), &totals(Kind::Policy)).cloned()
                };
                for c in crate::live::active() {
                    let (u, d) = (c.up.load(Ordering::Relaxed), c.down.load(Ordering::Relaxed));
                    let (pu, pd) = std::mem::replace(&mut *c.seen.lock().unwrap(), (u, d));
                    c.rate_up.store(((u - pu) as f64 / secs) as u64, Ordering::Relaxed);
                    c.rate_down.store(((d - pd) as f64 / secs) as u64, Ordering::Relaxed);
                }
                if let Some(s) = sample {
                    let mut j = sample_json(&s);
                    j.pop();
                    j.push_str(&format!(",\"total_up\":{up},\"total_down\":{down},\"active\":{active}}}"));
                    crate::live::publish("traffic", &j);
                }
            }
        });
    });
}

/// Counts bytes as they flow, so long-lived connections show up in rates while open.
struct Counted {
    inner: BoxStream,
    live: Option<Arc<crate::live::LiveConn>>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        if let Some(c) = &self.live {
            crate::live::unregister(c.id);
        }
    }
}

impl Counted {
    /// Fails I/O once the API closed this connection; otherwise registers for that wake-up.
    fn check_closed(&self, cx: &Context<'_>) -> io::Result<()> {
        match &self.live {
            Some(c) if c.is_closed() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "closed via control API")),
            Some(c) => {
                c.park(cx.waker());
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl AsyncRead for Counted {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.check_closed(cx)?;
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        add_down(n);
        if let Some(c) = &self.live {
            c.add(0, n);
        }
        r
    }
}

impl AsyncWrite for Counted {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.check_closed(cx)?;
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            add_up(n);
            if let Some(c) = &self.live {
                c.add(n, 0);
            }
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps an upstream stream so its traffic and lifetime are counted.
#[cfg_attr(not(test), allow(dead_code))]
pub fn counted(inner: BoxStream) -> BoxStream {
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    Box::new(Counted { inner, live: None })
}

/// Like [`counted`], and also lists the stream in `/v1/connections/active` until dropped.
pub fn counted_live(inner: BoxStream, meta: crate::live::ConnMeta) -> BoxStream {
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    Box::new(Counted { inner, live: Some(crate::live::register(meta)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Both stream tests read the process-wide counters, so they must not overlap.
    static COUNTERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn counts_both_directions() {
        let _serial = COUNTERS.lock().await;
        let (a, mut b) = tokio::io::duplex(1024);
        let (up0, down0, active0) = snapshot();
        let mut s = counted(Box::new(a));
        assert_eq!(snapshot().2, active0 + 1);
        s.write_all(b"hello").await.unwrap();
        b.write_all(b"worlds!").await.unwrap();
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        let (up, down, _) = snapshot();
        assert!(up - up0 >= 5 && down - down0 >= 7);
        drop(s);
        assert_eq!(snapshot().2, active0);
    }

    #[test]
    fn ring_rates_and_capacity() {
        let mut r = Ring::new(3);
        assert!(r.tick(0, 1.0, (100, 200), &[("P".into(), 10, 0)]).is_none());
        let s = r.tick(1000, 1.0, (150, 400), &[("P".into(), 30, 0), ("Q".into(), 0, 0)]).unwrap().clone();
        assert_eq!((s.up, s.down), (50, 200));
        assert_eq!(s.policies, vec![("P".to_string(), 20, 0)]);
        let s = r.tick(1500, 0.5, (200, 400), &[("P".into(), 30, 0)]).unwrap();
        assert_eq!((s.up, s.down), (100, 0));
        assert!(s.policies.is_empty());
        r.tick(2000, 1.0, (200, 400), &[]);
        r.tick(3000, 1.0, (200, 400), &[]);
        let all = r.samples();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].time_ms, 1500);
        let j: serde_json::Value = serde_json::from_str(&sample_json(&all[0])).unwrap();
        assert_eq!(j["up"], 100);
    }

    #[tokio::test]
    async fn live_stream_is_listed_counted_and_closable() {
        let _serial = COUNTERS.lock().await;
        let (a, mut b) = tokio::io::duplex(1024);
        let meta = crate::live::ConnMeta { network: "tcp", target: "stats-test:1".into(), policy: "StatsP".into(), outbound: "StatsN".into(), ..Default::default() };
        let mut s = counted_live(Box::new(a), meta);
        let c = crate::live::active().into_iter().find(|c| c.meta.target == "stats-test:1").unwrap();
        s.write_all(b"abc").await.unwrap();
        b.write_all(b"xy").await.unwrap();
        let mut buf = [0u8; 2];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!((c.up.load(Ordering::Relaxed), c.down.load(Ordering::Relaxed)), (3, 2));
        assert!(totals(Kind::Node).iter().any(|(n, u, d)| n == "StatsN" && *u == 3 && *d == 2));
        // A read pending when the API closes the connection must fail promptly.
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            s.read(&mut buf).await
        });
        tokio::task::yield_now().await;
        assert!(crate::live::close(c.id));
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), reader).await.unwrap().unwrap();
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert!(!crate::live::active().iter().any(|x| x.id == c.id));
    }
}
