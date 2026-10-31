//! Live TCP connections and the event bus behind the control API's
//! `/v1/connections/active` and `/v1/events`.
//!
//! Each proxied TCP stream is wrapped by [`crate::stats::counted_live`], which registers
//! a [`LiveConn`] here and removes it on drop. Closing one through the API marks it and
//! wakes its pending I/O, which then fails with `ConnectionAborted`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Waker;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use crate::stats::Bucket;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// What is known about a connection when it opens.
#[derive(Clone, Debug, Default)]
pub struct ConnMeta {
    pub network: &'static str,
    pub target: String,
    pub src: Option<String>,
    pub rule: String,
    pub policy: String,
    /// Policy groups followed from the rule's policy down to the node, node last.
    pub chain: Vec<String>,
    pub outbound: String,
    pub process: Option<String>,
    pub traffic: Arc<crate::conns::Traffic>,
}

pub struct LiveConn {
    pub id: u64,
    pub start_ms: u64,
    pub meta: ConnMeta,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    /// Bytes per second over the last sampler tick.
    pub rate_up: AtomicU64,
    pub rate_down: AtomicU64,
    /// Totals at the last tick, for the rates.
    pub(crate) seen: Mutex<(u64, u64)>,
    pub(crate) buckets: [Arc<Bucket>; 2],
    closed: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl LiveConn {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Remembers who to wake if the connection is closed while I/O is pending.
    pub(crate) fn park(&self, w: &Waker) {
        let mut ws = self.wakers.lock().unwrap();
        if !ws.iter().any(|x| x.will_wake(w)) {
            if ws.len() >= 4 {
                ws.remove(0);
            }
            ws.push(w.clone());
        }
    }

    pub(crate) fn add(&self, up: usize, down: usize) {
        if up > 0 {
            self.up.fetch_add(up as u64, Ordering::Relaxed);
            self.buckets.iter().for_each(|b| b.add(up, 0));
        }
        if down > 0 {
            self.down.fetch_add(down as u64, Ordering::Relaxed);
            self.buckets.iter().for_each(|b| b.add(0, down));
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for w in self.wakers.lock().unwrap().drain(..) {
            w.wake();
        }
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE: Mutex<BTreeMap<u64, Arc<LiveConn>>> = Mutex::new(BTreeMap::new());

pub fn register(meta: ConnMeta) -> Arc<LiveConn> {
    let buckets = [crate::stats::bucket(crate::stats::Kind::Policy, &meta.policy), crate::stats::bucket(crate::stats::Kind::Node, &meta.outbound)];
    let c = Arc::new(LiveConn {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        start_ms: now_ms(),
        up: meta.traffic.up.clone(),
        down: meta.traffic.down.clone(),
        meta,
        rate_up: AtomicU64::new(0),
        rate_down: AtomicU64::new(0),
        seen: Mutex::new((0, 0)),
        buckets,
        closed: AtomicBool::new(false),
        wakers: Mutex::new(Vec::new()),
    });
    ACTIVE.lock().unwrap().insert(c.id, c.clone());
    publish("conn_open", &conn_json(&c));
    c
}

pub fn unregister(id: u64) {
    if let Some(c) = ACTIVE.lock().unwrap().remove(&id) {
        publish("conn_close", &conn_json(&c));
    }
}

/// Open connections, oldest first.
pub fn active() -> Vec<Arc<LiveConn>> {
    ACTIVE.lock().unwrap().values().cloned().collect()
}

/// Closes one connection; false if no such id is open.
pub fn close(id: u64) -> bool {
    let c = ACTIVE.lock().unwrap().get(&id).cloned();
    c.inspect(|c| c.close()).is_some()
}

/// Closes every open connection and returns how many there were.
pub fn close_all() -> usize {
    let all = active();
    all.iter().for_each(|c| c.close());
    all.len()
}

pub fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

fn json_opt(s: Option<&str>) -> String {
    s.map_or("null".to_string(), json_str)
}

pub fn conn_json(c: &LiveConn) -> String {
    let m = &c.meta;
    let chain: Vec<String> = m.chain.iter().map(|s| json_str(s)).collect();
    format!(
        "{{\"id\":{},\"start_ms\":{},\"network\":\"{}\",\"target\":{},\"src\":{},\"rule\":{},\"policy\":{},\"chain\":[{}],\"outbound\":{},\"process\":{},\"up\":{},\"down\":{},\"rate_up\":{},\"rate_down\":{}}}",
        c.id,
        c.start_ms,
        m.network,
        json_str(&m.target),
        json_opt(m.src.as_deref()),
        json_str(&m.rule),
        json_str(&m.policy),
        chain.join(","),
        json_str(&m.outbound),
        json_opt(m.process.as_deref()),
        c.up.load(Ordering::Relaxed),
        c.down.load(Ordering::Relaxed),
        c.rate_up.load(Ordering::Relaxed),
        c.rate_down.load(Ordering::Relaxed),
    )
}

/// One event for `/v1/events`: its name and a JSON payload.
#[derive(Clone, Debug)]
pub struct Event {
    pub kind: &'static str,
    pub data: String,
}

fn bus() -> &'static broadcast::Sender<Event> {
    static BUS: OnceLock<broadcast::Sender<Event>> = OnceLock::new();
    BUS.get_or_init(|| broadcast::channel(1024).0)
}

pub fn publish(kind: &'static str, data: &str) {
    // No subscribers is the common case; the send error just means that.
    let _ = bus().send(Event { kind, data: data.to_string() });
}

pub fn subscribe() -> broadcast::Receiver<Event> {
    bus().subscribe()
}

/// Forwards to the real logger and also publishes each record as a `log` event.
pub struct EventLogger<L>(pub L);

impl<L: log::Log> log::Log for EventLogger<L> {
    fn enabled(&self, m: &log::Metadata) -> bool {
        self.0.enabled(m)
    }

    fn log(&self, r: &log::Record) {
        if !self.0.enabled(r.metadata()) {
            return;
        }
        self.0.log(r);
        if bus().receiver_count() > 0 {
            let data = format!(
                "{{\"time_ms\":{},\"level\":\"{}\",\"message\":{}}}",
                now_ms(),
                r.level(),
                json_str(&r.args().to_string())
            );
            publish("log", &data);
        }
    }

    fn flush(&self) {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(target: &str) -> ConnMeta {
        ConnMeta { network: "tcp", target: target.into(), policy: "P".into(), outbound: "N".into(), ..Default::default() }
    }

    #[test]
    fn close_wakes_parked_waker() {
        use std::sync::atomic::AtomicUsize;
        use std::task::Wake;
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let n = Arc::new(Count(AtomicUsize::new(0)));
        let w = Waker::from(n.clone());
        let c = register(meta("wake-test.example:443"));
        c.park(&w);
        assert!(close(c.id));
        assert_eq!(n.0.load(Ordering::SeqCst), 1);
        unregister(c.id);
    }

    #[test]
    fn register_close_unregister() {
        let mut rx = subscribe();
        let c = register(meta("live-test.example:443"));
        assert!(active().iter().any(|x| x.id == c.id));
        assert_eq!(rx.try_recv().unwrap().kind, "conn_open");
        c.add(10, 20);
        let j: serde_json::Value = serde_json::from_str(&conn_json(&c)).unwrap();
        assert_eq!((j["up"].as_u64(), j["down"].as_u64()), (Some(10), Some(20)));
        assert_eq!(j["target"], "live-test.example:443");
        assert!(close(c.id) && c.is_closed());
        assert!(!close(u64::MAX));
        unregister(c.id);
        assert!(!active().iter().any(|x| x.id == c.id));
        loop {
            let e = rx.try_recv().unwrap();
            if e.kind == "conn_close" && e.data.contains("live-test.example") {
                break;
            }
        }
    }
}
