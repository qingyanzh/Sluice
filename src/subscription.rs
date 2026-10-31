//! Subscriptions: groups with `policy-path=<url|file>` get their nodes from a list of
//! share links (plain or base64) or Surge-style proxy lines.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use log::{info, warn};
use serde::Serialize;

use crate::api::percent_decode;
use crate::config::{parse_proxy, Config, ProxyDef};
use crate::ruleset::fetch;
use crate::transport::{Layer, WsOpts, XhttpMode, XhttpOpts};

/// One entry per (group, source), shared with control API readers by the reloader.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionInfo {
    pub group: String,
    pub url: String,
    #[serde(flatten)]
    pub metadata: crate::ruleset::FetchMetadata,
    pub last_error: Option<String>,
    pub node_count: usize,
    /// Informational entries supplied as pseudo-nodes by the provider.
    pub notices: Vec<String>,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_end_matches('=');
    STANDARD_NO_PAD.decode(s).or_else(|_| URL_SAFE_NO_PAD.decode(s)).ok()
}

fn b64_str(s: &str) -> Option<String> {
    String::from_utf8(b64(s)?).ok()
}

/// Pieces of `scheme://userinfo@host:port?query#name`.
struct Link {
    user: Option<String>,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    name: Option<String>,
}

fn split_link(body: &str) -> Result<Link> {
    let (body, name) = match body.split_once('#') {
        Some((b, n)) => (b, Some(percent_decode(n)).filter(|n| !n.is_empty())),
        None => (body, None),
    };
    let (main, query_str) = body.split_once('?').unwrap_or((body, ""));
    let main = main.trim_end_matches('/');
    let (user, hostport) = match main.rsplit_once('@') {
        Some((u, h)) => (Some(percent_decode(u)), h),
        None => (None, main),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or_else(|| anyhow!("bad host"))?;
        (h.to_string(), p)
    } else {
        let (h, p) = hostport.rsplit_once(':').ok_or_else(|| anyhow!("missing port"))?;
        (h.to_string(), p)
    };
    let port = port.trim_end_matches('/').parse().map_err(|_| anyhow!("bad port {port:?}"))?;
    let query = query_str
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_ascii_lowercase(), percent_decode(v)))
        .collect();
    Ok(Link { user, host, port, query, name })
}

fn truthy(v: Option<&String>) -> bool {
    matches!(v.map(String::as_str), Some("1" | "true"))
}

/// `type=ws` plus `path`/`host` query parameters, shared by vless:// and trojan://.
fn layer_from_query(q: &HashMap<String, String>) -> Result<Option<Layer>> {
    match q.get("type").map(String::as_str) {
        None | Some("tcp") => Ok(None),
        Some("ws") => Ok(Some(Layer::Ws(WsOpts {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: q.get("host").cloned().filter(|h| !h.is_empty()),
            headers: Vec::new(),
        }))),
        Some("httpupgrade") => Ok(Some(Layer::HttpUpgrade(WsOpts {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: q.get("host").cloned().filter(|h| !h.is_empty()),
            headers: Vec::new(),
        }))),
        Some("grpc") => Ok(Some(Layer::Grpc {
            service: q.get("serviceName").or(q.get("servicename")).cloned().unwrap_or_default(),
        })),
        Some("xhttp" | "splithttp") => {
            let mut x = XhttpOpts { host: q.get("host").cloned().filter(|h| !h.is_empty()), ..Default::default() };
            x.path = q.get("path").cloned().unwrap_or(x.path);
            x.mode = XhttpMode::parse(q.get("mode").map_or("", String::as_str))?;
            // `extra` is the JSON of further XHTTP settings; only the padding range matters here.
            let extra: Option<serde_json::Value> = q.get("extra").and_then(|e| serde_json::from_str(e).ok());
            match extra.as_ref().map(|e| &e["xPaddingBytes"]) {
                Some(serde_json::Value::String(p)) => x.padding = XhttpOpts::parse_padding(p)?,
                Some(serde_json::Value::Number(n)) => x.padding = XhttpOpts::parse_padding(&n.to_string())?,
                Some(serde_json::Value::Object(o)) => {
                    let get = |k: &str| o.get(k).and_then(|v| v.as_u64()).map(|v| v as u32);
                    if let (Some(a), Some(b)) = (get("from"), get("to")) {
                        x.padding = (a, b);
                    }
                }
                _ => {}
            }
            Ok(Some(Layer::Xhttp(x)))
        }
        Some(other) => bail!("transport {other:?} not supported yet"),
    }
}

fn parse_ss(body: &str) -> Result<(Option<String>, ProxyDef)> {
    // SIP002: base64(method:password)@host:port; legacy: base64(method:password@host:port).
    let (main, name) = body.split_once('#').map_or((body, None), |(m, n)| (m, Some(percent_decode(n))));
    let main = main.split(['?', '/']).next().unwrap_or(main);
    let expanded = if main.contains('@') { main.to_string() } else { b64_str(main).ok_or_else(|| anyhow!("bad ss link"))? };
    let l = split_link(&expanded)?;
    let user = l.user.ok_or_else(|| anyhow!("ss link without credentials"))?;
    let creds = if user.contains(':') { user } else { b64_str(&user).ok_or_else(|| anyhow!("bad ss credentials"))? };
    let (method, password) = creds.split_once(':').ok_or_else(|| anyhow!("bad ss credentials"))?;
    // SIP002 `?plugin=name;opt=v;flag` (percent-encoded).
    let query = body.split('#').next().and_then(|b| b.split_once('?')).map_or("", |(_, q)| q);
    let plugin = query.split('&').find_map(|kv| kv.strip_prefix("plugin=")).map(percent_decode).filter(|p| !p.is_empty());
    let plugin = match plugin {
        Some(p) => {
            let (name, opts) = p.split_once(';').unwrap_or((&p, ""));
            Some(crate::obfs::SsPlugin::parse(name, opts)?)
        }
        None => None,
    };
    let def = ProxyDef::Shadowsocks { server: l.host, port: l.port, method: method.into(), password: password.into(), plugin };
    Ok((name.filter(|n| !n.is_empty()), def))
}

fn parse_vmess(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let json: serde_json::Value = serde_json::from_str(&b64_str(body).ok_or_else(|| anyhow!("bad vmess base64"))?)?;
    let field = |k: &str| match &json[k] {
        serde_json::Value::String(s) => Some(s.clone()).filter(|s| !s.is_empty()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let layer = match field("net").as_deref() {
        None | Some("tcp") => None,
        Some("ws") => Some(Layer::Ws(WsOpts { path: field("path").unwrap_or_else(|| "/".into()), host: field("host"), headers: Vec::new() })),
        Some("httpupgrade") => {
            Some(Layer::HttpUpgrade(WsOpts { path: field("path").unwrap_or_else(|| "/".into()), host: field("host"), headers: Vec::new() }))
        }
        Some("grpc") => Some(Layer::Grpc { service: field("path").unwrap_or_default() }),
        Some("xhttp" | "splithttp") => {
            let mode = XhttpMode::parse(field("type").as_deref().filter(|t| *t != "none").unwrap_or(""))?;
            Some(Layer::Xhttp(XhttpOpts { path: field("path").unwrap_or_else(|| "/".into()), host: field("host"), mode, ..Default::default() }))
        }
        Some(other) => bail!("transport {other:?} not supported yet"),
    };
    let server = field("add").ok_or_else(|| anyhow!("vmess link without address"))?;
    let def = ProxyDef::Vmess {
        port: field("port").and_then(|p| p.parse().ok()).ok_or_else(|| anyhow!("vmess link without port"))?,
        uuid: field("id").ok_or_else(|| anyhow!("vmess link without id"))?,
        method: field("scy").filter(|s| s != "zero" && s != "none").unwrap_or_else(|| "auto".into()),
        tls: field("tls").as_deref() == Some("tls"),
        sni: field("sni").or_else(|| field("host")),
        // Not in the v2rayN format proper, but common in generated links.
        skip_cert_verify: field("allowInsecure").is_some_and(|v| v == "1" || v == "true")
            || field("verify_cert").is_some_and(|v| v == "false"),
        layer,
        server,
        alter_id: field("aid").and_then(|a| a.parse().ok()).unwrap_or(0),
    };
    Ok((field("ps"), def))
}

fn parse_vless(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let l = split_link(body)?;
    let q = &l.query;
    let flow = q.get("flow").cloned().filter(|f| !f.is_empty());
    if let Some(f) = flow.as_deref().filter(|f| !crate::vision::is_vision(f)) {
        bail!("VLESS flow {f:?} not supported");
    }
    let reality = match q.get("security").map(String::as_str) {
        Some("reality") => {
            let def = crate::config::RealityDef {
                public_key: q.get("pbk").cloned().ok_or_else(|| anyhow!("REALITY link without pbk"))?,
                short_id: q.get("sid").cloned().unwrap_or_default(),
            };
            // Reject bad parameters here, so one bad node can't fail the whole config later.
            let sni = q.get("sni").map(String::as_str).unwrap_or_default();
            crate::reality::RealityOpts::parse(&def.public_key, &def.short_id, sni)?;
            Some(def)
        }
        _ => None,
    };
    let def = ProxyDef::Vless {
        reality,
        flow,
        uuid: l.user.ok_or_else(|| anyhow!("vless link without uuid"))?,
        tls: q.get("security").is_some_and(|s| s == "tls"),
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("allowinsecure")),
        layer: layer_from_query(q)?,
        server: l.host,
        port: l.port,
    };
    Ok((l.name, def))
}

fn parse_trojan(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let l = split_link(body)?;
    let q = &l.query;
    let def = ProxyDef::Trojan {
        password: l.user.ok_or_else(|| anyhow!("trojan link without password"))?,
        sni: q.get("sni").or(q.get("peer")).cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("allowinsecure")),
        layer: layer_from_query(q)?,
        server: l.host,
        port: l.port,
    };
    Ok((l.name, def))
}

fn parse_anytls(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let mut l = split_link(body)?;
    // URI userinfo uses percent escaping, not form encoding: a literal '+' is a password byte.
    if let Some((user, _)) = body.split(['?', '#']).next().unwrap_or_default().rsplit_once('@') {
        l.user = Some(percent_decode(&user.replace('+', "%2B")));
    }
    if l.host.is_empty() { bail!("anytls link without host"); }
    let q = &l.query;
    let def = ProxyDef::AnyTls {
        server: l.host, port: l.port,
        password: l.user.ok_or_else(|| anyhow!("anytls link without password"))?,
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("insecure")) || truthy(q.get("allowinsecure")),
        tfo: truthy(q.get("tfo")),
        alpn: q.get("alpn").map_or_else(Vec::new, |s| s.split([',', '|']).filter(|s| !s.is_empty()).map(str::to_string).collect()),
        udp: !matches!(q.get("udp").map(String::as_str), Some("false" | "0")),
    };
    Ok((l.name, def))
}

fn parse_hy2(body: &str) -> Result<(Option<String>, ProxyDef)> {
    // `host:20000-50000` / `host:443,8443` is a port-hopping spec; the first port stands in
    // as the plain port so split_link can parse the rest.
    let end = body.find(['/', '?', '#']).unwrap_or(body.len());
    let mut ports = None;
    let rewritten;
    let body = match body[..end].rsplit_once(':') {
        Some((head, spec)) if spec.contains(['-', ',']) => {
            let first = crate::udphop::parse_ports(spec)?[0];
            ports = Some(spec.to_string());
            rewritten = format!("{head}:{first}{}", &body[end..]);
            rewritten.as_str()
        }
        _ => body,
    };
    let l = split_link(body)?;
    let q = &l.query;
    let obfs = match q.get("obfs").map(String::as_str) {
        None | Some("") | Some("none") => None,
        Some("salamander") => Some(q.get("obfs-password").cloned().ok_or_else(|| anyhow!("salamander without obfs-password"))?),
        Some(other) => bail!("hysteria2 obfs {other:?} not supported"),
    };
    let ports = ports.or_else(|| q.get("mport").cloned().filter(|p| !p.is_empty()));
    if let Some(p) = &ports {
        crate::udphop::parse_ports(p)?;
    }
    let def = ProxyDef::Hysteria2 {
        password: l.user.ok_or_else(|| anyhow!("hysteria2 link without password"))?,
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("insecure")),
        obfs,
        ports,
        hop_interval: None,
        server: l.host,
        port: l.port,
    };
    Ok((l.name, def))
}

pub fn parse_link(line: &str) -> Result<(Option<String>, ProxyDef)> {
    let (scheme, body) = line.split_once("://").ok_or_else(|| anyhow!("not a link"))?;
    match scheme.to_ascii_lowercase().as_str() {
        "ss" => parse_ss(body),
        "vmess" => parse_vmess(body),
        "vless" => parse_vless(body),
        "trojan" => parse_trojan(body),
        "anytls" => parse_anytls(body),
        "hysteria2" | "hy2" => parse_hy2(body),
        other => bail!("{other}:// not supported"),
    }
}

/// Provider notices sometimes masquerade as working proxies.
pub fn is_metadata(name: &str, server: &str, port: u16) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(
        r"(?i)剩余流量|套餐到期|到期时间|流量重置|官网|重置|流量|有效期|到期|\b(?:traffic|expire|expiry|expiration|reset|website)\b|official\s*(?:site|website)|\d+(?:\.\d+)?\s*[KMGT]B\s*[|/丨]\s*\d+(?:\.\d+)?\s*[KMGT]B"
    ).unwrap());
    let server = server.trim_matches(['[', ']']).trim_end_matches('.');
    port <= 1 || matches!(server, "127.0.0.1" | "0.0.0.0" | "1.1.1.1") || re.is_match(name)
}

fn node_is_metadata(name: &str, def: &ProxyDef) -> bool {
    let line = def.to_line("node");
    let parts: Vec<_> = line.split(',').map(str::trim).collect();
    is_metadata(name, parts[1], parts[2].parse().unwrap_or(0))
}

/// Parses a subscription body; returns named nodes and a list of skip reasons.
pub fn parse(text: &str) -> (Vec<(String, ProxyDef)>, Vec<String>) {
    let (nodes, skipped, _) = parse_with_metadata(text);
    (nodes, skipped)
}

fn parse_with_metadata(text: &str) -> (Vec<(String, ProxyDef)>, Vec<String>, Vec<String>) {
    let decoded;
    let text = text.trim_start_matches('\u{feff}');
    let text = if text.contains("://") || text.contains(',') || crate::clash::looks_like(text) || text.trim_start().starts_with("#!MANAGED-CONFIG") || text.lines().any(|l| l.trim().eq_ignore_ascii_case("[Proxy]")) {
        text
    } else {
        decoded = b64_str(text).unwrap_or_default();
        &decoded
    };
    if crate::clash::looks_like(text) {
        return crate::clash::parse_with_metadata(text).unwrap_or_else(|e| (Vec::new(), vec![format!("{e:#}")], Vec::new()));
    }
    let profile = text.starts_with("#!MANAGED-CONFIG") || text.lines().any(|l| l.trim().eq_ignore_ascii_case("[Proxy]"));
    let mut in_proxy = !profile;
    let (mut nodes, mut skipped, mut notices) = (Vec::new(), Vec::new(), Vec::new());
    for line in text.lines().map(str::trim) {
        if profile && line.starts_with('[') && line.ends_with(']') {
            in_proxy = line.eq_ignore_ascii_case("[Proxy]");
            continue;
        }
        if !in_proxy || line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") { continue; }
        if let Some((_, value)) = line.split_once('=') {
            let kind = value.split(',').next().unwrap_or_default().trim();
            if matches!(kind.to_ascii_lowercase().as_str(), "direct" | "reject" | "reject-tinygif" | "reject-drop") { continue; }
        }
        let parsed = if !profile && line.contains("://") {
            parse_link(line).map(|(name, def)| (name.unwrap_or_else(|| format!("node {}", nodes.len() + 1)), def))
        } else {
            parse_proxy(line)
        };
        match parsed {
            Ok((name, def)) if node_is_metadata(&name, &def) => notices.push(name),
            Ok(n) => nodes.push(n),
            Err(e) => {
                warn!("subscription entry skipped: {e:#}");
                skipped.push(format!("{e:#}"));
            }
        }
    }
    (nodes, skipped, notices)
}

/// Downloads each group's `policy-path`, adds its nodes as proxies and group options.
/// With `strict` off, a subscription that can't be fetched leaves its group empty.
pub async fn expand(cfg: &mut Config, base: &Path, strict: bool) -> Result<()> {
    let mut taken: HashSet<String> = cfg.proxies.iter().map(|(n, _)| n.clone()).collect();
    taken.extend(cfg.groups.iter().map(|g| g.name.clone()));
    taken.extend(["DIRECT".to_string(), "REJECT".to_string()]);
    // Groups sharing a subscription share its proxies: source -> final proxy names.
    let mut imported = HashMap::new();
    cfg.subscriptions.clear();
    for gi in 0..cfg.groups.len() {
        let Some(source) = cfg.groups[gi].policy_path.clone() else { continue };
        let user_agent = cfg.groups[gi].user_agent.clone();
        let key = (source.clone(), user_agent.clone());
        let mut note = String::new();
        if !imported.contains_key(&key) {
            let max_age = Duration::from_secs(cfg.groups[gi].update_interval_secs);
            let (text, metadata, last_error) = match fetch(&source, base, max_age, user_agent.as_deref()).await {
                Ok(result) => (result.text, result.metadata, result.last_error),
                Err(e) if strict => return Err(e.context(format!("subscription for group {:?}", cfg.groups[gi].name))),
                Err(e) => {
                    warn!("subscription for group {:?}: {e:#}", cfg.groups[gi].name);
                    (String::new(), Default::default(), Some(format!("{e:#}")))
                }
            };
            let (nodes, skipped, notices) = parse_with_metadata(&text);
            note = summarize(&skipped);
            let mut names = Vec::new();
            for (name, def) in nodes {
                let mut unique = name.clone();
                let mut i = 2;
                while !taken.insert(unique.clone()) {
                    unique = format!("{name} {i}");
                    i += 1;
                }
                cfg.proxies.push((unique.clone(), def));
                names.push(unique);
            }
            imported.insert(key.clone(), (names, metadata, last_error, notices));
        }
        let filter = cfg.groups[gi].policy_filter.as_deref().map(regex::Regex::new).transpose()?;
        let (names, metadata, last_error, notices) = &imported[&key];
        let picked: Vec<String> = names.iter().filter(|n| filter.as_ref().is_none_or(|re| re.is_match(n))).cloned().collect();
        let g = &mut cfg.groups[gi];
        info!("{}", expansion_summary(&g.name, picked.len(), &source, &note));
        cfg.subscriptions.push(SubscriptionInfo {
            group: g.name.clone(), url: source.clone(), metadata: metadata.clone(), last_error: last_error.clone(), node_count: picked.len(), notices: notices.clone(),
        });
        g.options.extend(picked);
        if g.options.is_empty() {
            warn!("group {} has no usable nodes; it will REJECT", g.name);
            g.options.push("REJECT".into());
        }
    }
    Ok(())
}

fn expansion_summary(group: &str, count: usize, source: &str, note: &str) -> String {
    crate::diag::redact(&format!("group {group}: {count} nodes from {source}{note}"))
}

fn summarize(skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let mut reasons: Vec<(&String, usize)> = Vec::new();
    for r in skipped {
        match reasons.iter_mut().find(|(s, _)| *s == r) {
            Some((_, n)) => *n += 1,
            None => reasons.push((r, 1)),
        }
    }
    let parts: Vec<String> = reasons.iter().map(|(r, n)| format!("{n}× {r}")).collect();
    format!(" ({} skipped: {})", skipped.len(), parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    const NOTICES: &[&str] = &[
        "剩余流量：254.46 GB", "套餐到期：长期有效", "9.2 GB | 150 GB", "Expire Date：2026-12-22",
        "官网", "重置", "Traffic: 254 GB", "Expire: never", "Placeholder", "Zero", "DNS", "Port one", "Port zero",
    ];

    fn pseudo_nodes() -> Vec<(&'static str, &'static str, u16)> {
        NOTICES.iter().enumerate().map(|(i, name)| (*name,
            match i { 8 => "127.0.0.1", 9 => "0.0.0.0", 10 => "1.1.1.1", _ => "node.example.com" },
            match i { 11 => 1, 12 => 0, _ => 443 },
        )).collect()
    }

    #[test]
    fn notices_are_metadata_in_every_subscription_format() {
        let mut surge = String::from("[Proxy]\n");
        let mut yaml = String::from("proxies:\n");
        let mut links = String::new();
        let mut vmess = String::new();
        for (name, server, port) in pseudo_nodes().into_iter().chain([("🇭🇰 Hong Kong丨01", "hk.example.com", 443)]) {
            surge.push_str(&format!("{name} = trojan, {server}, {port}, password=p\n"));
            yaml.push_str(&format!("- {{name: '{name}', type: trojan, server: {server}, port: {port}, password: p}}\n"));
            links.push_str(&format!("trojan://p@{server}:{port}#{name}\n"));
            let json = serde_json::json!({"ps":name, "add":server, "port":port, "id":"test"});
            vmess.push_str(&format!("vmess://{}\n", STANDARD.encode(json.to_string())));
        }
        for body in [surge, yaml, links, vmess] {
            for body in [body.clone(), STANDARD.encode(&body)] {
                let (nodes, skipped, notices) = parse_with_metadata(&body);
                assert!(skipped.is_empty(), "{skipped:?}");
                assert_eq!(nodes.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), ["🇭🇰 Hong Kong丨01"]);
                assert_eq!(notices, NOTICES);
            }
        }
    }

    #[tokio::test]
    async fn notices_never_become_selections_or_health_check_options() {
        let dir = std::env::temp_dir().join(format!("sluice-notices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nodes"), "剩余流量：254.46 GB = trojan, node.example.com, 443, password=p\nHK = trojan, hk.example.com, 443, password=p\n").unwrap();
        let mut cfg = Config::parse("[Proxy Group]\nS = select, policy-path=nodes\nT = url-test, policy-path=nodes\n[Rule]\nFINAL,S\n").unwrap();
        expand(&mut cfg, &dir, true).await.unwrap();
        let router = crate::router::Router::new(&cfg).unwrap();
        for group in router.groups() {
            assert_eq!(group.options.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(), ["HK"]);
            assert_eq!(group.selected, "HK");
        }
        for info in cfg.subscriptions { assert_eq!(info.notices, [NOTICES[0]]); }
        std::fs::write(dir.join("nodes"), "套餐到期：长期有效 = trojan, node.example.com, 443, password=p\n").unwrap();
        let mut cfg = Config::parse("[Proxy Group]\nS = select, policy-path=nodes\n").unwrap();
        expand(&mut cfg, &dir, true).await.unwrap();
        assert!(cfg.proxies.is_empty());
        assert_eq!(cfg.groups[0].options, ["REJECT"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expansion_log_redacts_subscription_secrets() {
        let message = expansion_summary("Subscription", 30,
            "https://user:secret@host/api/v1/client/subscribe?token=private-token&format=clash", "");
        assert!(message.starts_with("group Subscription: 30 nodes from https://"));
        assert!(message.contains("/api/v1/client/subscribe?[REDACTED]"));
        for secret in ["user", "secret", "private-token", "format=clash"] {
            assert!(!message.contains(secret), "{message}");
        }
    }

    #[tokio::test]
    async fn file_url_subscriptions_parse_all_fixture_formats() {
        let dir = std::env::temp_dir().join(format!("sluice-file-sub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("节点 # % ?.txt");
        let source = url::Url::from_file_path(&path).unwrap();
        // The local-check fixtures deliberately use placeholder servers; give this
        // format/import test real-looking endpoints without changing those fixtures.
        let links = include_str!("../tests/fixtures/local-check/links.txt").lines().map(|line| {
            if let Some(body) = line.strip_prefix("vmess://") {
                format!("vmess://{}", STANDARD.encode(b64_str(body).unwrap().replace("127.0.0.1", "node.example.com")))
            } else {
                line.replace("127.0.0.1", "node.example.com")
            }
        }).collect::<Vec<_>>().join("\n");
        for (body, count) in [
            (links.to_string(), 8),
            (STANDARD.encode(&links), 8),
            (include_str!("../tests/fixtures/local-check/clash.yaml").replace("127.0.0.1", "node.example.com"), 2),
            (include_str!("../tests/fixtures/local-check/surge.conf").replace("127.0.0.1", "node.example.com"), 2),
        ] {
            std::fs::write(&path, &body).unwrap();
            let expected: Vec<String> = parse(&body).0.into_iter().map(|(name, _)| name).collect();
            assert_eq!(expected.len(), count);
            let mut cfg = Config::parse(&format!("[Proxy Group]\nLocal = select, policy-path={source}\n")).unwrap();
            expand(&mut cfg, Path::new("/unused"), true).await.unwrap();
            assert_eq!(cfg.proxies.len(), count);
            assert_eq!(cfg.groups[0].options, expected);
            assert_eq!(cfg.subscriptions[0].node_count, count);
            assert!(cfg.subscriptions[0].last_error.is_none());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn surge_managed_profile_extracts_only_proxies() {
        let body = "[General]\nhttp-listen = 8080\n[Proxy]\n# comment\n; comment\n// comment\n\nDIRECT = direct\nREJECT = reject\nBad = future-protocol, h, 443\nHK = trojan, h, 443, password=p\nJP = ss, h, 8388, encrypt-method=aes-128-gcm, password=p\n[Proxy Group]\nAuto = select, HK, JP\n[Rule]\nFINAL,Auto\n";
        for prefix in ["", "#!MANAGED-CONFIG https://example.invalid/sub interval=86400\n"] {
            let text = format!("{prefix}{body}");
            for text in [text.clone(), STANDARD.encode(text)] {
                let (nodes, skipped) = parse(&text);
                assert_eq!(nodes.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["HK", "JP"]);
                assert_eq!(skipped.len(), 1);
                assert!(skipped[0].contains("unsupported proxy type"));
            }
        }
        let (nodes, skipped) = parse("#!MANAGED-CONFIG https://example.invalid\n[Rule]\nFINAL,DIRECT\n");
        assert!(nodes.is_empty() && skipped.is_empty());
    }

    #[tokio::test]
    async fn expansion_tracks_each_group_and_failed_subscription() {
        let dir = std::env::temp_dir().join(format!("sluice-sub-expand-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nodes.txt"), "[Proxy]\nHK = trojan, h, 443, password=p\nJP = trojan, h, 443, password=p\n[Rule]\nFINAL,DIRECT\n").unwrap();
        let mut cfg = Config::parse("[Proxy Group]\nAll = select, policy-path=nodes.txt\nHKOnly = select, policy-path=nodes.txt, policy-regex-filter=HK\nMissing = select, policy-path=missing.txt\n").unwrap();
        expand(&mut cfg, &dir, false).await.unwrap();
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.subscriptions.iter().map(|s| (s.group.as_str(), s.node_count)).collect::<Vec<_>>(), [("All", 2), ("HKOnly", 1), ("Missing", 0)]);
        assert_eq!(cfg.subscriptions[0].url, "nodes.txt");
        assert!(cfg.subscriptions[0].last_error.is_none());
        assert!(cfg.subscriptions[2].last_error.as_ref().unwrap().contains("missing.txt"));
        assert_eq!(cfg.groups[2].options, ["REJECT"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn assert_link_roundtrip(link: &str, expected: ProxyDef) {
        let (name, actual) = parse_link(link).unwrap_or_else(|e| panic!("{link}: {e:#}"));
        assert_eq!(name.as_deref(), Some("Test node"), "{link}");
        // ProxyDef/Layer lack PartialEq; Debug includes all their fields.
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"), "{link}");
        let line = actual.to_line(name.as_deref().unwrap());
        let (back_name, back) = parse_proxy(&line).unwrap();
        assert_eq!(back_name, "Test node");
        assert_eq!(format!("{back:?}"), format!("{expected:?}"), "{line}");
    }

    #[test]
    fn anytls_share_links_roundtrip() {
        assert_link_roundtrip("anytls://p%40ss%3Aword%25@[::1]:443?sni=tls%2Eexample&insecure=1&alpn=h2%2Chttp%2F1.1&udp=0&tfo=1#Test%20node", ProxyDef::AnyTls {
            server: "::1".into(), port: 443, password: "p@ss:word%".into(), sni: Some("tls.example".into()),
            skip_cert_verify: true, tfo: true, alpn: vec!["h2".into(), "http/1.1".into()], udp: false,
        });
        assert_link_roundtrip("anytls://secret@h:8443#Test%20node", ProxyDef::AnyTls {
            server: "h".into(), port: 8443, password: "secret".into(), sni: None,
            skip_cert_verify: false, tfo: false, alpn: vec![], udp: true,
        });
        assert!(parse_link("anytls://h:443").is_err());
        assert!(parse_link("anytls://p@:443").is_err());
        let (_, def) = parse_link("anytls://a+b%2Bc@h:443").unwrap();
        assert!(matches!(def, ProxyDef::AnyTls { password, .. } if password == "a+b+c"));
    }

    #[test]
    fn all_stream_proxy_transports_roundtrip() {
        let mut transports = vec![
            ("".to_string(), "tcp", "", None),
            ("&type=tcp".into(), "tcp", "", None),
            ("&type=ws".into(), "ws", "", Some(Layer::Ws(WsOpts { path: "/".into(), host: None, headers: vec![] }))),
            (
                "&type=ws&path=%2Fsocket&host=cdn.example".into(), "ws", "/socket",
                Some(Layer::Ws(WsOpts { path: "/socket".into(), host: Some("cdn.example".into()), headers: vec![] })),
            ),
            ("&type=grpc".into(), "grpc", "", Some(Layer::Grpc { service: String::new() })),
            ("&type=grpc&serviceName=tunnel".into(), "grpc", "tunnel", Some(Layer::Grpc { service: "tunnel".into() })),
            ("&type=xhttp".into(), "xhttp", "", Some(Layer::Xhttp(XhttpOpts::default()))),
        ];
        for net in ["xhttp", "splithttp"] {
            for mode in [XhttpMode::Auto, XhttpMode::PacketUp, XhttpMode::StreamUp, XhttpMode::StreamOne] {
                transports.push((
                    format!("&type={net}&path=%2Fupload&host=cdn.example&mode={}", mode.as_str()), net, "/upload",
                    Some(Layer::Xhttp(XhttpOpts { path: "/upload".into(), host: Some("cdn.example".into()), mode, ..Default::default() })),
                ));
            }
        }
        for (query, net, path, layer) in transports {
            for tls in [false, true] {
                let security = if tls { "tls" } else { "none" };
                let suffix = format!("?security={security}&sni=tls.example&allowInsecure=1{query}#Test%20node");
                assert_link_roundtrip(
                    &format!("vless://test-uuid@proxy.example:443{suffix}"),
                    ProxyDef::Vless {
                        server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(), tls,
                        sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), reality: None, flow: None,
                    },
                );
                assert_link_roundtrip(
                    &format!("trojan://p%40ss%3Aword@proxy.example:443{suffix}"),
                    ProxyDef::Trojan {
                        server: "proxy.example".into(), port: 443, password: "p@ss:word".into(),
                        sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(),
                    },
                );
                let (host, mode) = match &layer {
                    Some(Layer::Ws(w)) => (w.host.as_deref(), "none"),
                    Some(Layer::Xhttp(x)) => (x.host.as_deref(), x.mode.as_str()),
                    _ => (None, "none"),
                };
                let json = serde_json::json!({
                    "ps": "Test node", "add": "proxy.example", "port": 443, "id": "test-uuid", "aid": 0,
                    "scy": "aes-128-gcm", "tls": if tls { "tls" } else { "" }, "sni": "tls.example",
                    "allowInsecure": "true", "net": net, "path": path, "host": host, "type": mode,
                });
                assert_link_roundtrip(
                    &format!("vmess://{}", STANDARD.encode(json.to_string())),
                    ProxyDef::Vmess {
                        server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(), method: "aes-128-gcm".into(),
                        tls, sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), alter_id: 0,
                    },
                );
            }
        }
    }

    #[test]
    fn shadowsocks_encodings_and_ipv6_roundtrip() {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
        let expected = ProxyDef::Shadowsocks {
            server: "::1".into(), port: 8388, method: "aes-256-gcm".into(), password: "p@ss:word".into(), plugin: None,
        };
        for creds in [STANDARD.encode("aes-256-gcm:p@ss:word"), STANDARD_NO_PAD.encode("aes-256-gcm:p@ss:word"), URL_SAFE_NO_PAD.encode("aes-256-gcm:p@ss:word"), "aes-256-gcm:p%40ss%3Aword".into()] {
            assert_link_roundtrip(&format!("ss://{creds}@[::1]:8388#Test%20node"), expected.clone());
        }
        let legacy = STANDARD.encode("aes-256-gcm:p@ss:word@[::1]:8388");
        assert_link_roundtrip(&format!("SS://{legacy}#Test%20node"), expected);
    }

    #[test]
    fn hysteria2_aliases_and_options_roundtrip() {
        for scheme in ["hy2", "hysteria2"] {
            for (query, obfs, ports) in [
                ("", None, None),
                ("&obfs=none", None, None),
                ("&obfs=salamander&obfs-password=mask&mport=443%2C5000-5002", Some("mask".into()), Some("443,5000-5002".into())),
            ] {
                assert_link_roundtrip(
                    &format!("{scheme}://p%40ss@[::1]:8443/?sni=tls.example&insecure=true{query}#Test%20node"),
                    ProxyDef::Hysteria2 {
                        server: "::1".into(), port: 8443, password: "p@ss".into(), sni: Some("tls.example".into()),
                        skip_cert_verify: true, obfs, ports, hop_interval: None,
                    },
                );
            }
        }
    }

    #[test]
    fn vmess_defaults_numeric_fields_and_security_aliases() {
        for cipher in [None, Some("none"), Some("zero"), Some("auto")] {
            for insecure in [serde_json::json!({"allowInsecure": 1}), serde_json::json!({"verify_cert": "false"})] {
                let mut json = serde_json::json!({"ps": "Test node", "add": "h", "port": "80", "id": "u", "host": "cdn.example"});
                if let Some(cipher) = cipher { json["scy"] = cipher.into(); }
                for (key, value) in insecure.as_object().unwrap() { json[key] = value.clone(); }
                assert_link_roundtrip(
                    &format!("vmess://{}", STANDARD.encode(json.to_string())),
                    ProxyDef::Vmess {
                        server: "h".into(), port: 80, uuid: "u".into(), method: "auto".into(), tls: false,
                        sni: Some("cdn.example".into()), skip_cert_verify: true, layer: None, alter_id: 0,
                    },
                );
            }
        }
    }

    #[test]
    fn xhttp_padding_forms_and_trojan_peer_alias() {
        for (extra, padding) in [
            ("%7B%22xPaddingBytes%22%3A%2210-20%22%7D", (10, 20)),
            ("%7B%22xPaddingBytes%22%3A16%7D", (16, 16)),
            ("%7B%22xPaddingBytes%22%3A%7B%22from%22%3A10%2C%22to%22%3A20%7D%7D", (10, 20)),
        ] {
            assert_link_roundtrip(
                &format!("trojan://p@h:443?peer=tls.example&type=splithttp&extra={extra}#Test%20node"),
                ProxyDef::Trojan {
                    server: "h".into(), port: 443, password: "p".into(), sni: Some("tls.example".into()), skip_cert_verify: false,
                    layer: Some(Layer::Xhttp(XhttpOpts { padding, ..Default::default() })),
                },
            );
        }
    }

    #[test]
    fn subscription_formats_preserve_nodes_and_skip_errors() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let text = "# comment\n\ntrojan://pw@h:443\nunsupported://h:1\nSS = ss, h, 8388, encrypt-method=aes-128-gcm, password=p\nvless://u@h:80#\n";
        let expected = parse(text);
        assert_eq!(expected.0.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["node 1", "SS", "node 3"]);
        assert_eq!(expected.1, ["unsupported:// not supported"]);
        for encoded in [STANDARD.encode(text), URL_SAFE_NO_PAD.encode(text)] {
            let wrapped = format!(" {}\n{} \n", &encoded[..20], &encoded[20..]);
            let actual = parse(&wrapped);
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        }
        let yaml = "proxies:\n  - {name: YAML, type: trojan, server: h, port: 443, password: p}\n";
        assert_eq!(format!("{:?}", parse(yaml)), format!("{:?}", crate::clash::parse(yaml).unwrap()));
        let (nodes, skipped) = parse("proxies: [");
        assert!(nodes.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("Clash YAML"));
        assert!(parse("").0.is_empty());
    }

    #[test]
    fn malformed_links_are_rejected() {
        for (link, reason) in [
            ("not a link", "not a link"),
            ("socks5://h:1", "not supported"),
            ("ss://not-base64", "bad ss link"),
            ("ss://method@h:1", "bad ss credentials"),
            ("ss://aes-128-gcm:p@h:1?plugin=kcptun", "ss plugin \"kcptun\" not supported"),
            ("vless://h:443", "vless link without uuid"),
            ("trojan://h:443", "trojan link without password"),
            ("hy2://h:443", "hysteria2 link without password"),
            ("trojan://p@h", "missing port"),
            ("trojan://p@[::1:443", "bad host"),
            ("trojan://p@h:65536", "bad port"),
            ("vless://u@h:443?type=kcp", "transport"),
            ("trojan://p@h:443?type=xhttp&mode=unknown", "unknown xhttp mode"),
            ("vless://u@h:443?flow=unsupported", "VLESS flow"),
            ("vless://u@h:443?security=reality", "REALITY link without pbk"),
            ("hy2://p@h:443?obfs=salamander", "salamander without obfs-password"),
            ("hy2://p@h:443?obfs=unknown", "hysteria2 obfs"),
            ("hy2://p@h:443?mport=5-3", "bad port range"),
            ("vmess://!", "bad vmess base64"),
        ] {
            let err = parse_link(link).unwrap_err();
            assert!(format!("{err:#}").contains(reason), "{link}: {err:#}");
        }
        for (json, reason) in [
            (r#"{"add":"h","port":443,"aid":1}"#, "vmess link without id"),
            (r#"{"port":443,"id":"u"}"#, "without address"),
            (r#"{"add":"h","id":"u"}"#, "without port"),
            (r#"{"add":"h","port":443}"#, "without id"),
            (r#"{"add":"h","port":443,"id":"u","net":"kcp"}"#, "transport"),
        ] {
            let err = parse_link(&format!("vmess://{}", STANDARD.encode(json))).unwrap_err();
            assert!(format!("{err:#}").contains(reason), "{json}: {err:#}");
        }
    }

    #[test]
    fn base64_alphabets_padding_whitespace_and_invalid_data() {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
        // These bytes exercise both alphabet-specific characters (+/ and -_).
        let bytes = [0xfb, 0xff];
        for encoded in [STANDARD.encode(bytes), STANDARD_NO_PAD.encode(bytes), URL_SAFE.encode(bytes), URL_SAFE_NO_PAD.encode(bytes)] {
            let wrapped = format!(" \t{}\n{}\r\n", &encoded[..1], &encoded[1..]);
            assert_eq!(b64(&wrapped), Some(bytes.to_vec()));
            assert_eq!(b64_str(&wrapped), None, "decoded bytes are not UTF-8");
        }
        assert_eq!(b64_str(&STANDARD.encode("節點")), Some("節點".into()));
        for invalid in ["!", "a", "a=b", "%%%%"] {
            assert_eq!(b64(invalid), None, "{invalid}");
        }
        for text in ["", " \n\t", "not base64!"] {
            let (nodes, skipped) = parse(text);
            assert!(nodes.is_empty() && skipped.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn link_components_decode_ipv6_credentials_names_and_queries() {
        let link = split_link("p%40ss%3Aword@[2001:db8::1]:65535/?SNI=old&SnI=tls.example&path=%2Fa%3Fb%3Dc&ignored#Test%20node").unwrap();
        assert_eq!(link.user.as_deref(), Some("p@ss:word"));
        assert_eq!((link.host.as_str(), link.port), ("2001:db8::1", 65535));
        assert_eq!(link.name.as_deref(), Some("Test node"));
        assert_eq!(link.query.len(), 2);
        assert_eq!(link.query["sni"], "tls.example");
        assert_eq!(link.query["path"], "/a?b=c");
        for suffix in ["", "#"] {
            let link = split_link(&format!("h:1{suffix}")).unwrap();
            assert!(link.user.is_none() && link.name.is_none() && link.query.is_empty());
        }
    }

    #[test]
    fn security_flags_and_empty_optional_values() {
        for (flag, expected) in [("1", true), ("true", true), ("0", false), ("false", false), ("", false)] {
            let (_, def) = parse_link(&format!("VLESS://u@h:443?security=tls&allowInsecure={flag}&sni=&flow=&type=ws&host=")).unwrap();
            assert!(matches!(def, ProxyDef::Vless {
                tls: true, skip_cert_verify, sni: None, flow: None,
                layer: Some(Layer::Ws(WsOpts { host: None, .. })), ..
            } if skip_cert_verify == expected), "{flag}");
            let (_, def) = parse_link(&format!("TROJAN://p@h:443?allowInsecure={flag}")).unwrap();
            assert!(matches!(def, ProxyDef::Trojan { skip_cert_verify, sni: None, layer: None, .. } if skip_cert_verify == expected));
            let (_, def) = parse_link(&format!("HY2://p@h:443?insecure={flag}&sni=&mport=&obfs=")).unwrap();
            assert!(matches!(def, ProxyDef::Hysteria2 {
                skip_cert_verify, sni: None, obfs: None, ports: None, hop_interval: None, ..
            } if skip_cert_verify == expected));
        }
    }

    #[test]
    fn malformed_vmess_fields_and_json_are_rejected() {
        for json in ["not JSON", "null", "[]", "{}",
            r#"{"add":"h","port":-1,"id":"u"}"#,
            r#"{"add":"h","port":65536,"id":"u"}"#,
            r#"{"add":"h","port":"bad","id":"u"}"#,
            r#"{"add":"","port":443,"id":"u"}"#,
            r#"{"add":"h","port":443,"id":""}"#,
            r#"{"add":"h","port":443,"id":"u","net":"xhttp","type":"bad"}"#,
        ] {
            assert!(parse_link(&format!("vmess://{}", STANDARD.encode(json))).is_err(), "{json}");
        }
    }

    #[test]
    fn reality_requires_valid_key_short_id_and_sni() {
        let key = "9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4";
        for (query, reason) in [
            ("pbk=YQ&sni=www.example.com".into(), "must be 32 bytes"),
            (format!("pbk={key}"), "needs sni"),
            (format!("pbk={key}&sni=www.example.com&sid=a"), "even length"),
            (format!("pbk={key}&sni=www.example.com&sid=001122334455667788"), "even length"),
            (format!("pbk={key}&sni=www.example.com&sid=zz"), "bad REALITY short id"),
        ] {
            let err = parse_link(&format!("vless://u@h:443?security=reality&{query}")).unwrap_err();
            assert!(format!("{err:#}").contains(reason), "{query}: {err:#}");
        }
        assert_link_roundtrip(
            &format!("vless://u@h:443?security=reality&pbk={key}&sni=www.example.com#Test%20node"),
            ProxyDef::Vless {
                server: "h".into(), port: 443, uuid: "u".into(), tls: false,
                sni: Some("www.example.com".into()), skip_cert_verify: false, layer: None, flow: None,
                reality: Some(crate::config::RealityDef { public_key: key.into(), short_id: String::new() }),
            },
        );
    }

    #[test]
    fn xhttp_padding_defaults_and_invalid_scalar_ranges() {
        for extra in ["not-json", "{}", r#"{"xPaddingBytes":null}"#] {
            let (_, def) = parse_link(&format!("trojan://p@h:443?type=xhttp&extra={extra}")).unwrap();
            assert!(matches!(def, ProxyDef::Trojan { layer: Some(Layer::Xhttp(x)), .. } if x == XhttpOpts::default()));
        }
        for extra in [r#"{"xPaddingBytes":"20-10"}"#, r#"{"xPaddingBytes":-1}"#, r#"{"xPaddingBytes":4294967296}"#] {
            assert!(parse_link(&format!("vless://u@h:443?type=xhttp&extra={extra}")).is_err(), "{extra}");
        }
    }

    #[test]
    fn invalid_nodes_do_not_hide_neighbors_or_consume_generated_names() {
        let text = "trojan://p@first:443\nss://!\nvless://h:443\nvmess://!\nhy2://p@h:443?mport=0\nBad = trojan, h, 443\ntrojan://p@last:443";
        let (nodes, skipped) = parse(text);
        assert_eq!(nodes.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["node 1", "node 2"]);
        assert_eq!(skipped.len(), 5);
        assert!(matches!(&nodes[0].1, ProxyDef::Trojan { server, .. } if server == "first"));
        assert!(matches!(&nodes[1].1, ProxyDef::Trojan { server, .. } if server == "last"));
    }

    #[test]
    #[ignore = "Known bug: parse_ss truncates legacy standard base64 at '/' before decoding"]
    fn legacy_shadowsocks_base64_can_contain_slashes() {
        let encoded = STANDARD.encode("aes-128-gcm:pa?@h:8388");
        assert!(encoded.contains('/'));
        assert_link_roundtrip(
            &format!("ss://{encoded}#Test%20node"),
            ProxyDef::Shadowsocks { server: "h".into(), port: 8388, method: "aes-128-gcm".into(), password: "pa?".into(), plugin: None },
        );
    }

    #[test]
    #[ignore = "Known bug: XHTTP object padding bypasses range validation and truncates u64 to u32"]
    fn xhttp_object_padding_rejects_reversed_and_overflowing_ranges() {
        let accepted: Vec<_> = [
            r#"{"xPaddingBytes":{"from":20,"to":10}}"#,
            r#"{"xPaddingBytes":{"from":4294967296,"to":4294967297}}"#,
        ].into_iter().filter(|extra| parse_link(&format!("vless://u@h:443?type=xhttp&extra={extra}")).is_ok()).collect();
        assert!(accepted.is_empty(), "invalid padding accepted: {accepted:?}");
    }

    #[test]
    fn to_line_roundtrips() {
        let text = format!(
            "ss://{}@1.2.3.4:8388#A\nvmess://{}\ntrojan://pw@t.example:443?sni=t.example&type=ws&path=%2Fws&host=cdn.example#T\n\
             ss://{ss}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dbing.com#O\n\
             ss://{ss}@1.2.3.4:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dv.example%3Bpath%3D%2Fws#P\n\
             vless://b831381d-6324-4d53-ad4f-8cda48b30811@u.example:80?type=httpupgrade&path=%2Fup&host=h.example#U\n",
            STANDARD.encode("aes-256-gcm:pw"),
            STANDARD.encode(r#"{"ps":"V","add":"v.example","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":64,"net":"ws","path":"/r","tls":"tls"}"#),
            ss = STANDARD.encode("aes-256-gcm:pw"),
        );
        let (nodes, skipped) = parse(&text);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(nodes.len(), 6);
        assert!(matches!(&nodes[1].1, ProxyDef::Vmess { alter_id: 64, .. }));
        assert!(matches!(&nodes[3].1, ProxyDef::Shadowsocks { plugin: Some(crate::obfs::SsPlugin::Obfs { tls: true, .. }), .. }));
        assert!(matches!(&nodes[4].1, ProxyDef::Shadowsocks { plugin: Some(crate::obfs::SsPlugin::V2ray { tls: true, .. }), .. }));
        assert!(matches!(&nodes[5].1, ProxyDef::Vless { layer: Some(Layer::HttpUpgrade(w)), .. } if w.path == "/up"));
        for (name, def) in nodes {
            let line = def.to_line(&name);
            let (back_name, back) = parse_proxy(&line).unwrap();
            assert_eq!((back_name, format!("{back:?}")), (name, format!("{def:?}")), "{line}");
        }
    }

    #[test]
    fn hy2_port_hopping() {
        for (link, spec) in [
            ("hy2://pw@h.example:20000-50000/?sni=h.example#A", "20000-50000"),
            ("hysteria2://pw@[::1]:443,8443,20000-30000?obfs=salamander&obfs-password=o#B", "443,8443,20000-30000"),
            ("hy2://pw@h.example:443/?mport=1000-2000#C", "1000-2000"),
        ] {
            let (nodes, skipped) = parse(link);
            assert!(skipped.is_empty(), "{skipped:?}");
            let def = &nodes[0].1;
            assert!(matches!(def, ProxyDef::Hysteria2 { ports: Some(p), .. } if p == spec), "{def:?}");
            let back = parse_proxy(&def.to_line("X")).unwrap().1;
            assert_eq!(format!("{back:?}"), format!("{def:?}"));
        }
        assert!(matches!(&parse("hy2://pw@h.example:8443#D").0[0].1, ProxyDef::Hysteria2 { ports: None, .. }));
        assert!(!parse("hy2://pw@h.example:5-3#E").1.is_empty());
        let (_, def) = parse_proxy("H = hysteria2, h.example, 443, password=x, port-hopping=\"443;5000-6000\", port-hopping-interval=10").unwrap();
        assert!(matches!(def, ProxyDef::Hysteria2 { ports: Some(p), hop_interval: Some(10), .. } if p == "443,5000-6000"));
    }

    #[test]
    fn links() {
        let ss = format!("ss://{}@1.2.3.4:8388#HK%201", STANDARD.encode("aes-256-gcm:pw"));
        let legacy = format!("ss://{}#Legacy", STANDARD.encode("chacha20-ietf-poly1305:p@ss@5.6.7.8:443"));
        let vmess_json = r#"{"v":"2","ps":"JP","add":"jp.example","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"ws","path":"/ray","host":"cdn.example","tls":"tls"}"#;
        let vmess = format!("vmess://{}", STANDARD.encode(vmess_json));
        let text = format!(
            "{ss}\n{legacy}\n{vmess}\n\
             vless://b831381d-6324-4d53-ad4f-8cda48b30811@v.example:443?security=tls&sni=v.example&type=ws&path=%2Fws#US\n\
             trojan://secret@t.example:443?sni=t.example&allowInsecure=1#TJ\n\
             hy2://hpw@h.example:8443/?sni=h.example&insecure=1#HY\n\
             vless://b831381d-6324-4d53-ad4f-8cda48b30811@r.example:443?security=reality&pbk=x#Reality\n\
             SG = ss, sg.example, 8388, encrypt-method=aes-128-gcm, password=x\n"
        );
        let (nodes, skipped) = parse(&STANDARD.encode(&text));
        let names: Vec<&str> = nodes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["HK 1", "Legacy", "JP", "US", "TJ", "HY", "SG"]);
        assert_eq!(skipped, ["bad REALITY public key"]);
        let good = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@r.example:443?security=reality&pbk=3iNj5NZvYtWSt7Wf18PGYraEqvZ_tiA6Z3hD92XCOnE&sid=0123abcd&sni=www.microsoft.com#R";
        let (reality_nodes, reality_skipped) = parse(good);
        assert!(reality_skipped.is_empty(), "{reality_skipped:?}");
        match &reality_nodes[0].1 {
            ProxyDef::Vless { reality: Some(r), sni: Some(sni), tls: false, .. } => {
                assert_eq!((r.short_id.as_str(), sni.as_str()), ("0123abcd", "www.microsoft.com"));
                let line = reality_nodes[0].1.to_line("R");
                let back = crate::config::parse_proxy(&line).unwrap().1;
                assert_eq!(format!("{back:?}"), format!("{:?}", reality_nodes[0].1), "{line}");
            }
            other => panic!("{other:?}"),
        }
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            let (n, skipped) = parse(&format!("{}&flow={flow}", good.replace("#R", "")));
            assert!(skipped.is_empty(), "{skipped:?}");
            assert!(matches!(&n[0].1, ProxyDef::Vless { flow: Some(f), .. } if f == flow));
            let back = crate::config::parse_proxy(&n[0].1.to_line("V")).unwrap().1;
            assert_eq!(format!("{back:?}"), format!("{:?}", n[0].1));
        }
        let (_, splice) = parse(&format!("{}&flow=xtls-rprx-splice", good.replace("#R", "")));
        assert_eq!(splice, ["VLESS flow \"xtls-rprx-splice\" not supported"]);
        let (_, bad_skipped) = parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@r.example:443?security=reality&pbk=x&sni=a.com#Bad");
        assert_eq!(bad_skipped, ["bad REALITY public key"]);
        assert!(matches!(&nodes[1].1, ProxyDef::Shadowsocks { password, port: 443, .. } if password == "p@ss"));
        match &nodes[2].1 {
            ProxyDef::Vmess { tls: true, layer: Some(Layer::Ws(ws)), sni: Some(sni), .. } => {
                assert_eq!((ws.path.as_str(), ws.host.as_deref(), sni.as_str()), ("/ray", Some("cdn.example"), "cdn.example"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&nodes[3].1, ProxyDef::Vless { tls: true, layer: Some(Layer::Ws(w)), .. } if w.path == "/ws"));
        assert!(matches!(&nodes[4].1, ProxyDef::Trojan { skip_cert_verify: true, .. }));
        assert!(matches!(&nodes[5].1, ProxyDef::Hysteria2 { port: 8443, skip_cert_verify: true, .. }));
    }

    #[test]
    fn xhttp_link() {
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@x.example:443?security=tls&sni=x.example&type=xhttp&path=%2Fxh&host=cdn.example&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%2210-20%22%7D#XH";
        let (nodes, skipped) = parse(link);
        assert!(skipped.is_empty(), "{skipped:?}");
        match &nodes[0].1 {
            ProxyDef::Vless { layer: Some(Layer::Xhttp(x)), .. } => {
                assert_eq!((x.path.as_str(), x.host.as_deref(), x.mode, x.padding), ("/xh", Some("cdn.example"), XhttpMode::StreamUp, (10, 20)))
            }
            other => panic!("{other:?}"),
        }
    }

}
