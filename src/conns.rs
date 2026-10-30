//! Recent routing decisions, newest last, for the control API's `/v1/connections`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const KEEP: usize = 500;

#[derive(Clone, Debug)]
pub struct ConnRecord {
    pub id: u64,
    /// Unix time in milliseconds.
    pub time_ms: u64,
    pub network: &'static str,
    pub target: String,
    pub src: Option<String>,
    pub rule: String,
    pub policy: String,
    pub outbound: String,
    /// Owning process, when a PROCESS-NAME rule looked it up.
    pub process: Option<String>,
    /// Request URL when known: plain HTTP, CONNECT (`https://host/`), or a decrypted request.
    pub url: Option<String>,
    /// Whether this was a request decrypted by MITM.
    pub mitm: bool,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static RECENT: Mutex<VecDeque<ConnRecord>> = Mutex::new(VecDeque::new());

pub fn record(mut r: ConnRecord) {
    r.id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    r.time_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let mut q = RECENT.lock().unwrap();
    if q.len() >= KEEP {
        q.pop_front();
    }
    q.push_back(r);
}

pub fn recent() -> Vec<ConnRecord> {
    RECENT.lock().unwrap().iter().cloned().collect()
}
