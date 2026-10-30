//! Minimal control API.
//!
//!   GET  /v1/subscriptions                  subscription usage, expiry and fetch status
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
//!   GET  /v1/connections/active             open TCP connections, oldest first
//!   DELETE /v1/connections/<id>             close one open connection
//!   DELETE /v1/connections                  close every open connection
//!   GET  /v1/stats                          per-policy/per-node totals and the last 10 min of rates
//!   POST /v1/nodes/<name>/test              latency of one node (or group) right now
//!   GET  /v1/events                         Server-Sent Events: traffic, conn_open, conn_close, log
//!   GET  /v1/profile                        active config file and the other .conf files beside it
//!   POST /v1/profile?path=<file>            validate and switch to another config file
//!
//! `/v1/connections/active` items: `id`, `start_ms` (Unix ms), `network`, `target`, `src`,
//! `rule`, `policy`, `chain` (the rule's policy through each group's selection down to the
//! node, node last), `outbound`, `process`, `up`/`down` (bytes so far) and `rate_up`/
//! `rate_down` (bytes/s over the last second). UDP associations are not listed.
//!
//! `/v1/stats` is `{"up","down","active","policies":[{name,up,down}],"nodes":[{name,up,down}],
//! "history":[{time_ms,up,down,policies:[{policy,up,down}]}]}`: totals in bytes since start,
//! history one sample per second (bytes/s, oldest first, at most 600), with only the policies
//! that moved data in that second.
//!
//! `/v1/policies/<group>/test` answers `{"tested","selected","results":[{name,latency_ms}]}`,
//! `latency_ms` null for a failed option. `/v1/nodes/<name>/test` takes `url=` (http://,
//! default the group default test URL) and `timeout=` (ms, default 5000) and answers
//! `{"node","outbound","ok","connect_ms","latency_ms","status","error"}`: `connect_ms` is
//! the time to open a stream through the node (TCP connect plus its handshake), `latency_ms`
//! until the HTTP status line came back.
//!
//! `/v1/events` sends `event: <kind>` / `data: <json>` frames: `traffic` once a second (a
//! history sample plus `total_up`, `total_down`, `active`), `conn_open`/`conn_close` with a
//! connection item as above, and `log` (`time_ms`, `level`, `message`). `?types=traffic,log`
//! limits the kinds; a comment line every 15 s keeps idle streams open.
//!
//! `POST /v1/profile` parses the file and builds its router first; on any error it answers
//! 400 and the current profile stays active. Listen and enhanced-mode settings still need
//! a restart.
//!   POST /v1/diag                           write a redacted diagnostics bundle under ~/Library/Logs/Sluice
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

fn totals_json(kind: crate::stats::Kind) -> String {
    let items: Vec<String> = crate::stats::totals(kind)
        .iter()
        .map(|(n, u, d)| format!("{{\"name\":{},\"up\":{u},\"down\":{d}}}", json_str(n)))
        .collect();
    format!("[{}]", items.join(","))
}

fn latency_json(l: Option<u64>) -> String {
    l.map_or("null".to_string(), |ms| ms.to_string())
}

/// Streams events until the client goes away.
async fn events(mut sock: TcpStream, query: &str) -> Result<()> {
    let types: Option<Vec<String>> = query_param(query, "types").map(|t| t.split(',').map(str::to_string).collect());
    let mut rx = crate::live::subscribe();
    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n: sluice events\n\n").await?;
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            e = rx.recv() => match e {
                Ok(e) if types.as_ref().is_none_or(|t| t.iter().any(|k| k == e.kind)) => {
                    sock.write_all(format!("event: {}\ndata: {}\n\n", e.kind, e.data).as_bytes()).await?;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    sock.write_all(format!(": dropped {n} events\n\n").as_bytes()).await?;
                }
                Err(_) => return Ok(()),
            },
            _ = keepalive.tick() => sock.write_all(b": keepalive\n\n").await?,
        }
    }
}

async fn handle(mut sock: TcpStream, reloader: Arc<Reloader>) -> Result<()> {
    let router = reloader.handle.current();
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut parts = req.lines().next().unwrap_or_default().split_whitespace();
    let (method, uri) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    if (method, path) == ("GET", "/v1/events") {
        return events(sock, query).await;
    }

    let (status, body) = match (method, path) {
        ("GET", "/v1/subscriptions") => {
            ("200 OK", serde_json::to_string(&*reloader.subscriptions.read().unwrap())?)
        }
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
            match router.check_group(&group).await {
                Some(results) => {
                    let items: Vec<String> = results
                        .iter()
                        .map(|(n, l)| format!("{{\"name\":{},\"latency_ms\":{}}}", json_str(n), latency_json(*l)))
                        .collect();
                    let selected = router.groups().into_iter().find(|g| g.name == group).map(|g| g.selected).unwrap_or_default();
                    (
                        "200 OK",
                        format!(
                            "{{\"tested\":{},\"selected\":{},\"results\":[{}]}}",
                            json_str(&group),
                            json_str(&selected),
                            items.join(",")
                        ),
                    )
                }
                None => ("404 Not Found", format!("{{\"error\":{}}}", json_str(&format!("no such group {group:?}")))),
            }
        }
        ("POST", p) if p.starts_with("/v1/nodes/") && p.ends_with("/test") && p.len() > "/v1/nodes//test".len() => {
            let node = percent_decode(&p["/v1/nodes/".len()..p.len() - "/test".len()]);
            let url = query_param(query, "url").unwrap_or_else(|| crate::config::DEFAULT_TEST_URL.to_string());
            let ms = query_param(query, "timeout").and_then(|t| t.parse().ok()).unwrap_or(5000u64).clamp(100, 60_000);
            match router.test_node(&node, &url, std::time::Duration::from_millis(ms)).await {
                Ok(t) => (
                    "200 OK",
                    format!(
                        "{{\"node\":{},\"outbound\":{},\"ok\":true,\"connect_ms\":{},\"latency_ms\":{},\"status\":{},\"error\":null}}",
                        json_str(&node),
                        json_str(&t.outbound),
                        t.connect_ms,
                        t.latency_ms,
                        t.status
                    ),
                ),
                Err(e) if e.to_string().starts_with("no such node") => {
                    ("404 Not Found", format!("{{\"error\":{}}}", json_str(&e.to_string())))
                }
                Err(e) => (
                    "200 OK",
                    format!(
                        "{{\"node\":{},\"outbound\":{},\"ok\":false,\"connect_ms\":null,\"latency_ms\":null,\"status\":null,\"error\":{}}}",
                        json_str(&node),
                        json_opt(router.resolve(&node).ok().as_deref()),
                        json_str(&format!("{e:#}"))
                    ),
                ),
            }
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
        ("GET", "/v1/connections/active") => {
            let items: Vec<String> = crate::live::active().iter().map(|c| crate::live::conn_json(c)).collect();
            ("200 OK", format!("[{}]", items.join(",")))
        }
        ("DELETE", "/v1/connections") => ("200 OK", format!("{{\"closed\":{}}}", crate::live::close_all())),
        ("DELETE", p) if p.starts_with("/v1/connections/") => match p["/v1/connections/".len()..].parse::<u64>() {
            Ok(id) if crate::live::close(id) => ("200 OK", format!("{{\"closed\":1,\"id\":{id}}}")),
            Ok(id) => ("404 Not Found", format!("{{\"error\":\"no open connection {id}\"}}")),
            Err(_) => ("400 Bad Request", "{\"error\":\"bad connection id\"}".to_string()),
        },
        ("GET", "/v1/stats") => {
            let (up, down, active) = crate::stats::snapshot();
            let history: Vec<String> = crate::stats::history().iter().map(crate::stats::sample_json).collect();
            (
                "200 OK",
                format!(
                    "{{\"up\":{up},\"down\":{down},\"active\":{active},\"policies\":{},\"nodes\":{},\"history\":[{}]}}",
                    totals_json(crate::stats::Kind::Policy),
                    totals_json(crate::stats::Kind::Node),
                    history.join(",")
                ),
            )
        }
        ("GET", "/v1/profile") => {
            let path = reloader.path();
            let others: Vec<String> = crate::reload::sibling_profiles(&path).iter().map(|p| json_str(p)).collect();
            ("200 OK", format!("{{\"path\":{},\"profiles\":[{}]}}", json_str(&path), others.join(",")))
        }
        ("POST" | "PUT", "/v1/profile") => match query_param(query, "path") {
            Some(p) => match reloader.switch_profile(&p).await {
                Ok(summary) => (
                    "200 OK",
                    format!("{{\"path\":{},\"reloaded\":true,\"summary\":{}}}", json_str(&reloader.path()), json_str(&summary)),
                ),
                Err(e) => (
                    "400 Bad Request",
                    format!("{{\"error\":{},\"path\":{}}}", json_str(&format!("{e:#}")), json_str(&reloader.path())),
                ),
            },
            None => ("400 Bad Request", "{\"error\":\"missing ?path=\"}".to_string()),
        },
        // The output path is not taken from the request: the core may run as root, and any
        // local process can reach the API, so it must not choose where root writes or deletes.
        ("POST", "/v1/diag") => {
            let out = crate::diag::default_export_path();
            let config = reloader.path().to_string();
            match tokio::task::spawn_blocking(move || crate::diag::export(&out, Some(&config))).await? {
                Ok(p) => ("200 OK", format!("{{\"path\":{}}}", json_str(&p.to_string_lossy()))),
                Err(e) => ("500 Internal Server Error", format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
            }
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
    crate::stats::spawn_sampler();
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

    #[tokio::test]
    async fn subscriptions_endpoint_exposes_metadata_additively() {
        let cfg = crate::config::Config {
            subscriptions: vec![crate::subscription::SubscriptionInfo {
                group: "Airport".into(), url: "http://127.0.0.1/sub".into(),
                metadata: crate::ruleset::FetchMetadata { upload: Some(10), download: Some(20), total: Some(100), expire: Some(1800000000), update_interval_hours: Some(6), last_fetch: Some(1700000000) },
                last_error: Some("HTTP 403: 禁止访问".into()), node_count: 2,
            }], ..crate::config::Config::parse("[Rule]\nFINAL,DIRECT\n").unwrap()
        };
        let reloader = Reloader::start(crate::router::Router::new(&cfg).unwrap(), &cfg, "unused.conf");
        for path in ["/v1/subscriptions", "/v1/policies"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let reloader = reloader.clone();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                handle(socket, reloader).await.unwrap();
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
            let mut raw = String::new();
            client.read_to_string(&mut raw).await.unwrap();
            server.await.unwrap();
            assert!(raw.starts_with("HTTP/1.1 200 OK"));
            let body: serde_json::Value = serde_json::from_str(raw.split_once("\r\n\r\n").unwrap().1).unwrap();
            if path == "/v1/subscriptions" {
                assert_eq!(body, serde_json::json!([{"group":"Airport", "url":"http://127.0.0.1/sub", "upload":10, "download":20, "total":100, "expire":1800000000, "update_interval_hours":6, "last_fetch":1700000000, "last_error":"HTTP 403: 禁止访问", "node_count":2}]));
            } else { assert_eq!(body, serde_json::json!([])); }
        }
    }

    #[test]
    fn decode() {
        assert_eq!(percent_decode("%E9%A6%99%E6%B8%AF+SS"), "香港 SS");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(query_param("x=1&select=JP%20Node", "select").as_deref(), Some("JP Node"));
    }
}
