//! Minimal control API.
//!
//!   GET  /v1/policies                       groups, current selection and options
//!   POST /v1/policies/<group>?select=<opt>  switch a select group
//!   POST /v1/policies/<group>/test          run an automatic group's health check now
//!   GET  /v1/route?target=<host[:port]>     explain which rule and outbound a target hits
//!   POST /v1/reload                         reload the config file (and subscriptions)
//!   GET  /v1/mode                           outbound mode: rule, direct or global
//!   POST /v1/mode?set=<mode>                switch the outbound mode
//!   GET  /v1/traffic                        total bytes up/down and open connections
//!   GET  /v1/dns                            cached DNS answers with their remaining TTL
//!   POST /v1/dns/flush                      empty the DNS cache
//!   GET  /v1/connections                    recent routing decisions, newest last
//!
//! `/v1/route` also takes `process=`, `src=<ip:port>` and `proto=` to test the
//! PROCESS-NAME, SRC-IP and PROTOCOL rules.

use std::sync::Arc;

use anyhow::Result;
use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::reload::Reloader;
use crate::rule::{ConnInfo, Proto};
use crate::util::Target;

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_opt(s: Option<&str>) -> String {
    s.map_or("null".to_string(), json_str)
}

/// Client facts for `/v1/route`; with no `process=`, PROCESS-NAME rules see no process.
fn route_ctx(query: &str) -> ConnInfo {
    let proto = query_param(query, "proto").and_then(|p| Proto::parse(&p).ok()).unwrap_or_default();
    let src = query_param(query, "src").and_then(|s| s.parse().ok());
    let ctx = ConnInfo::new(proto, src, None, 0);
    match query_param(query, "process") {
        Some(p) => ctx.with_process(&p),
        None => ctx,
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

async fn handle(mut sock: TcpStream, reloader: Arc<Reloader>) -> Result<()> {
    let router = reloader.handle.current();
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut parts = req.lines().next().unwrap_or_default().split_whitespace();
    let (method, uri) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));

    let (status, body) = match (method, path) {
        ("GET", "/v1/policies") => {
            let items: Vec<String> = router
                .groups()
                .iter()
                .map(|g| {
                    let opts: Vec<String> = g
                        .options
                        .iter()
                        .map(|o| {
                            let latency = match o.latency {
                                None => "null".to_string(),
                                Some(None) => "-1".to_string(),
                                Some(Some(ms)) => ms.to_string(),
                            };
                            format!("{{\"name\":{},\"latency_ms\":{latency}}}", json_str(&o.name))
                        })
                        .collect();
                    format!(
                        "{{\"group\":{},\"type\":\"{}\",\"selected\":{},\"options\":[{}]}}",
                        json_str(&g.name),
                        g.kind,
                        json_str(&g.selected),
                        opts.join(",")
                    )
                })
                .collect();
            ("200 OK", format!("[{}]", items.join(",")))
        }
        ("POST", p) if p.starts_with("/v1/policies/") && p.ends_with("/test") => {
            let group = percent_decode(&p["/v1/policies/".len()..p.len() - "/test".len()]);
            router.check_group(&group).await;
            ("200 OK", format!("{{\"tested\":{}}}", json_str(&group)))
        }
        ("POST" | "PUT", p) if p.starts_with("/v1/policies/") => {
            let group = percent_decode(&p["/v1/policies/".len()..]);
            match query_param(query, "select") {
                Some(opt) => match router.select(&group, &opt) {
                    Ok(()) => ("200 OK", format!("{{\"group\":{},\"selected\":{}}}", json_str(&group), json_str(&opt))),
                    Err(e) => ("400 Bad Request", format!("{{\"error\":{}}}", json_str(&e.to_string()))),
                },
                None => ("400 Bad Request", "{\"error\":\"missing ?select=\"}".to_string()),
            }
        }
        ("GET", "/v1/mode") => ("200 OK", format!("{{\"mode\":\"{}\"}}", router.mode().name())),
        ("POST" | "PUT", "/v1/mode") => match query_param(query, "set").as_deref().and_then(crate::router::Mode::parse) {
            Some(m) => {
                router.set_mode(m);
                info!("outbound mode: {}", m.name());
                ("200 OK", format!("{{\"mode\":\"{}\"}}", m.name()))
            }
            None => ("400 Bad Request", "{\"error\":\"set= must be rule, direct or global\"}".to_string()),
        },
        ("GET", "/v1/traffic") => {
            let (up, down, active) = crate::stats::snapshot();
            ("200 OK", format!("{{\"up\":{up},\"down\":{down},\"active\":{active}}}"))
        }
        ("GET", "/v1/dns") => {
            let items: Vec<String> = crate::dns::cached_answers()
                .iter()
                .map(|e| {
                    let ips: Vec<String> = e.ips.iter().map(|ip| json_str(&ip.to_string())).collect();
                    format!(
                        "{{\"name\":{},\"type\":{},\"ttl\":{},\"answers\":[{}]}}",
                        json_str(&e.name),
                        json_str(&e.qtype),
                        e.ttl_left,
                        ips.join(",")
                    )
                })
                .collect();
            ("200 OK", format!("{{\"entries\":[{}]}}", items.join(",")))
        }
        ("POST", "/v1/dns/flush") => ("200 OK", format!("{{\"flushed\":{}}}", crate::dns::flush_cache())),
        ("POST", "/v1/reload") => match reloader.reload("API").await {
            Ok(summary) => ("200 OK", format!("{{\"reloaded\":true,\"summary\":{}}}", json_str(&summary))),
            Err(e) => ("400 Bad Request", format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        ("GET", "/v1/connections") => {
            let items: Vec<String> = crate::conns::recent()
                .iter()
                .map(|c| {
                    format!(
                        "{{\"id\":{},\"time_ms\":{},\"network\":\"{}\",\"target\":{},\"src\":{},\"rule\":{},\"policy\":{},\"outbound\":{},\"process\":{},\"url\":{},\"mitm\":{}}}",
                        c.id,
                        c.time_ms,
                        c.network,
                        json_str(&c.target),
                        json_opt(c.src.as_deref()),
                        json_str(&c.rule),
                        json_str(&c.policy),
                        json_str(&c.outbound),
                        json_opt(c.process.as_deref()),
                        json_opt(c.url.as_deref()),
                        c.mitm
                    )
                })
                .collect();
            ("200 OK", format!("[{}]", items.join(",")))
        }
        ("GET", "/v1/route") => match query_param(query, "target").map(|t| Target::parse_authority(&t, 443)) {
            Some(Ok(t)) => match router.decide_with(&t, &route_ctx(query)).await {
                Ok(d) => (
                    "200 OK",
                    format!(
                        "{{\"target\":{},\"rule\":{},\"policy\":{},\"outbound\":{},\"process\":{}}}",
                        json_str(&t.to_string()),
                        json_str(&d.rule),
                        json_str(&d.policy),
                        json_str(&d.outbound),
                        json_opt(d.process.as_deref())
                    ),
                ),
                Err(e) => ("500 Internal Server Error", format!("{{\"error\":{}}}", json_str(&e.to_string()))),
            },
            _ => ("400 Bad Request", "{\"error\":\"missing or bad ?target=\"}".to_string()),
        },
        _ => ("404 Not Found", "{\"error\":\"not found\"}".to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    Ok(())
}

pub async fn serve(addr: String, reloader: Arc<Reloader>) -> Result<()> {
    let listener = TcpListener::bind(&addr).await.map_err(|e| anyhow::anyhow!("bind api on {addr}: {e}"))?;
    info!("control API listening on http://{addr}");
    loop {
        let (sock, _) = listener.accept().await?;
        let reloader = reloader.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, reloader).await {
                debug!("api: {e:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        assert_eq!(percent_decode("%E9%A6%99%E6%B8%AF+SS"), "香港 SS");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(query_param("x=1&select=JP%20Node", "select").as_deref(), Some("JP Node"));
    }
}
