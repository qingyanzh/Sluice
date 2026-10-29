//! Fake-IP DNS for TUN mode, plus a tiny upstream resolver that bypasses the system one.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Result};
use rand::Rng;

use crate::util::udp_socket;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const FAKE_TTL: u32 = 1;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// Hands out addresses from a reserved range and remembers which domain each one stands for.
pub struct FakeDns {
    net: u32,
    size: u32,
    pool: Mutex<Pool>,
    upstream: Vec<SocketAddr>,
}

struct Pool {
    next: u32,
    by_name: HashMap<String, u32>,
    by_ip: HashMap<u32, String>,
}

/// Offsets 0..3 are the network address, the TUN address and the DNS address.
const FIRST_OFFSET: u32 = 3;

impl FakeDns {
    pub fn new(net: Ipv4Addr, prefix: u8, upstream: Vec<SocketAddr>) -> Self {
        let size = 1u32 << (32 - prefix as u32);
        FakeDns {
            net: u32::from(net) & !(size - 1),
            size,
            pool: Mutex::new(Pool { next: FIRST_OFFSET, by_name: HashMap::new(), by_ip: HashMap::new() }),
            upstream,
        }
    }

    pub fn addr(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.net + offset)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & !(self.size - 1) == self.net
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.pool.lock().unwrap().by_ip.get(&u32::from(ip)).cloned()
    }

    /// Returns the fake address for `name`, recycling the oldest one when the range is full.
    pub fn alloc(&self, name: &str) -> Ipv4Addr {
        let mut p = self.pool.lock().unwrap();
        if let Some(&ip) = p.by_name.get(name) {
            return Ipv4Addr::from(ip);
        }
        let ip = self.net + p.next;
        p.next = if p.next + 1 >= self.size - 1 { FIRST_OFFSET } else { p.next + 1 };
        if let Some(old) = p.by_ip.insert(ip, name.to_string()) {
            p.by_name.remove(&old);
        }
        p.by_name.insert(name.to_string(), ip);
        Ipv4Addr::from(ip)
    }

    /// Answers a query received on the TUN: A gets a fake address, AAAA gets nothing
    /// (so apps fall back to IPv4), everything else goes to the real upstream.
    pub async fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = parse_question(query)?;
        match q.qtype {
            TYPE_A => {
                let ip = self.alloc(&q.name);
                Some(build_response(query, &q, &[ip]))
            }
            TYPE_AAAA => Some(build_response(query, &q, &[])),
            _ => exchange(query, &self.upstream).await.ok(),
        }
    }
}

struct Question {
    id: u16,
    name: String,
    qtype: u16,
    end: usize,
}

fn be16(p: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(at)?, *p.get(at + 1)?]))
}

fn parse_question(p: &[u8]) -> Option<Question> {
    if p.len() < 12 || p[2] & 0x80 != 0 || be16(p, 4)? != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *p.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(p.get(pos..pos + len)?).to_ascii_lowercase());
        pos += len;
    }
    let qtype = be16(p, pos)?;
    be16(p, pos + 2)?;
    Some(Question { id: be16(p, 0)?, name: labels.join("."), qtype, end: pos + 4 })
}

fn build_response(query: &[u8], q: &Question, answers: &[Ipv4Addr]) -> Vec<u8> {
    let rd = query[2] & 0x01;
    let mut out = Vec::with_capacity(q.end + 16 * answers.len());
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x80 | rd, 0x80]);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.end]);
    for ip in answers {
        out.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        out.extend_from_slice(&FAKE_TTL.to_be_bytes());
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&ip.octets());
    }
    out
}

fn skip_name(p: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *p.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

fn parse_a_records(p: &[u8], id: u16) -> Option<Vec<IpAddr>> {
    if be16(p, 0)? != id || p[2] & 0x80 == 0 {
        return None;
    }
    let (qd, an) = (be16(p, 4)?, be16(p, 6)?);
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(p, pos)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        pos = skip_name(p, pos)?;
        let (rtype, rdlen) = (be16(p, pos)?, be16(p, pos + 8)? as usize);
        pos += 10;
        if rtype == TYPE_A && rdlen == 4 {
            let b = p.get(pos..pos + 4)?;
            ips.push(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
        }
        pos += rdlen;
    }
    Some(ips)
}

/// Sends a raw query to each upstream in turn (over the physical interface) until one answers.
async fn exchange(query: &[u8], upstream: &[SocketAddr]) -> Result<Vec<u8>> {
    for server in upstream {
        let attempt = async {
            let sock = udp_socket(server.is_ipv6())?;
            sock.send_to(query, server).await?;
            let mut buf = vec![0u8; 4096];
            let (n, _) = sock.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        };
        if let Ok(Ok(resp)) = tokio::time::timeout(UPSTREAM_TIMEOUT, attempt).await {
            return Ok(resp);
        }
    }
    bail!("no upstream DNS server answered")
}

/// Resolves `name` to IPv4 addresses via `upstream`, never via the (hijacked) system resolver.
pub async fn resolve_a(name: &str, upstream: &[SocketAddr]) -> Result<Vec<IpAddr>> {
    let id: u16 = rand::thread_rng().gen();
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid domain {name:?}");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let resp = exchange(&q, upstream).await?;
    match parse_a_records(&resp, id) {
        Some(ips) if !ips.is_empty() => Ok(ips),
        _ => bail!("{name}: no A records"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[tokio::test]
    async fn fake_answers() {
        let f = FakeDns::new(Ipv4Addr::new(198, 18, 0, 0), 15, vec![]);
        let resp = f.handle(&query("WWW.Google.com", TYPE_A)).await.unwrap();
        let ips = parse_a_records(&resp, 0x1234).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3))]);
        assert_eq!(f.lookup(Ipv4Addr::new(198, 18, 0, 3)).as_deref(), Some("www.google.com"));
        assert_eq!(f.alloc("www.google.com"), Ipv4Addr::new(198, 18, 0, 3));
        assert!(f.contains(Ipv4Addr::new(198, 19, 255, 1)));
        assert!(!f.contains(Ipv4Addr::new(198, 20, 0, 1)));
        let resp = f.handle(&query("a.com", TYPE_AAAA)).await.unwrap();
        assert_eq!(be16(&resp, 6), Some(0));
    }

    #[test]
    fn pool_wraps_and_evicts() {
        let f = FakeDns::new(Ipv4Addr::new(10, 0, 0, 0), 29, vec![]);
        let first = f.alloc("a0");
        for i in 1..10 {
            f.alloc(&format!("a{i}"));
        }
        assert_eq!(f.lookup(first).as_deref(), Some("a8"));
        assert!(f.alloc("a0") != Ipv4Addr::new(10, 0, 0, 7));
    }
}
