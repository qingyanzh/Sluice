//! Subscriptions: groups with `policy-path=<url|file>` get their nodes from a list of
//! share links (plain or base64) or Surge-style proxy lines.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use log::{info, warn};

use crate::api::percent_decode;
use crate::config::{parse_proxy, Config, ProxyDef};
use crate::ruleset::fetch;
use crate::transport::WsOpts;

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
struct Link<'a> {
    user: Option<String>,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    name: Option<String>,
    rest: &'a str,
}

fn split_link(body: &str) -> Result<Link<'_>> {
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
    Ok(Link { user, host, port, query, name, rest: main })
}

fn truthy(v: Option<&String>) -> bool {
    matches!(v.map(String::as_str), Some("1" | "true"))
}

/// `type=ws` plus `path`/`host` query parameters, shared by vless:// and trojan://.
fn ws_from_query(q: &HashMap<String, String>) -> Result<Option<WsOpts>> {
    match q.get("type").map(String::as_str) {
        None | Some("tcp") => Ok(None),
        Some("ws") => Ok(Some(WsOpts {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: q.get("host").cloned().filter(|h| !h.is_empty()),
            headers: Vec::new(),
        })),
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
    if body.contains("plugin=") {
        bail!("ss plugins not supported");
    }
    let def = ProxyDef::Shadowsocks { server: l.host, port: l.port, method: method.into(), password: password.into() };
    Ok((name.filter(|n| !n.is_empty()), def))
}

fn parse_vmess(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let json: serde_json::Value = serde_json::from_str(&b64_str(body).ok_or_else(|| anyhow!("bad vmess base64"))?)?;
    let field = |k: &str| match &json[k] {
        serde_json::Value::String(s) => Some(s.clone()).filter(|s| !s.is_empty()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    if field("aid").is_some_and(|a| a != "0") {
        bail!("legacy vmess (alterId > 0) not supported");
    }
    let ws = match field("net").as_deref() {
        None | Some("tcp") => None,
        Some("ws") => Some(WsOpts { path: field("path").unwrap_or_else(|| "/".into()), host: field("host"), headers: Vec::new() }),
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
        ws,
        server,
    };
    Ok((field("ps"), def))
}

fn parse_vless(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let l = split_link(body)?;
    let q = &l.query;
    match q.get("security").map(String::as_str) {
        Some("reality") => bail!("REALITY not supported yet"),
        _ if q.get("flow").is_some_and(|f| !f.is_empty()) => bail!("VLESS flow (XTLS) not supported yet"),
        _ => {}
    }
    let def = ProxyDef::Vless {
        uuid: l.user.ok_or_else(|| anyhow!("vless link without uuid"))?,
        tls: q.get("security").is_some_and(|s| s == "tls"),
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("allowinsecure")),
        ws: ws_from_query(q)?,
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
        ws: ws_from_query(q)?,
        server: l.host,
        port: l.port,
    };
    Ok((l.name, def))
}

fn parse_hy2(body: &str) -> Result<(Option<String>, ProxyDef)> {
    let l = split_link(body)?;
    let q = &l.query;
    if q.get("obfs").is_some_and(|o| !o.is_empty() && o != "none") {
        bail!("hysteria2 obfs not supported yet");
    }
    if l.rest.contains(',') {
        bail!("hysteria2 port hopping not supported yet");
    }
    let def = ProxyDef::Hysteria2 {
        password: l.user.ok_or_else(|| anyhow!("hysteria2 link without password"))?,
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("insecure")),
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
        "hysteria2" | "hy2" => parse_hy2(body),
        other => bail!("{other}:// not supported"),
    }
}

/// Parses a subscription body; returns named nodes and a list of skip reasons.
pub fn parse(text: &str) -> (Vec<(String, ProxyDef)>, Vec<String>) {
    let decoded;
    let text = if text.contains("://") || text.contains(" = ") {
        text
    } else {
        decoded = b64_str(text).unwrap_or_default();
        &decoded
    };
    let (mut nodes, mut skipped) = (Vec::new(), Vec::new());
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let parsed = if line.contains("://") {
            parse_link(line).map(|(name, def)| (name.unwrap_or_else(|| format!("node {}", nodes.len() + 1)), def))
        } else {
            parse_proxy(line)
        };
        match parsed {
            Ok(n) => nodes.push(n),
            Err(e) => skipped.push(format!("{e:#}")),
        }
    }
    (nodes, skipped)
}

/// Downloads each group's `policy-path`, adds its nodes as proxies and group options.
/// With `strict` off, a subscription that can't be fetched leaves its group empty.
pub async fn expand(cfg: &mut Config, base: &Path, strict: bool) -> Result<()> {
    let mut taken: HashSet<String> = cfg.proxies.iter().map(|(n, _)| n.clone()).collect();
    taken.extend(cfg.groups.iter().map(|g| g.name.clone()));
    taken.extend(["DIRECT".to_string(), "REJECT".to_string()]);
    // Groups sharing a subscription share its proxies: source -> final proxy names.
    let mut imported: HashMap<String, Vec<String>> = HashMap::new();
    for gi in 0..cfg.groups.len() {
        let Some(source) = cfg.groups[gi].policy_path.clone() else { continue };
        let mut note = String::new();
        if !imported.contains_key(&source) {
            let max_age = Duration::from_secs(cfg.groups[gi].update_interval_secs);
            let text = match fetch(&source, base, max_age).await {
                Ok((text, _)) => text,
                Err(e) if strict => return Err(e.context(format!("subscription for group {:?}", cfg.groups[gi].name))),
                Err(e) => {
                    warn!("subscription for group {:?}: {e:#}", cfg.groups[gi].name);
                    String::new()
                }
            };
            let (nodes, skipped) = parse(&text);
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
            imported.insert(source.clone(), names);
        }
        let filter = cfg.groups[gi].policy_filter.as_deref().map(regex::Regex::new).transpose()?;
        let picked: Vec<String> =
            imported[&source].iter().filter(|n| filter.as_ref().is_none_or(|re| re.is_match(n))).cloned().collect();
        let g = &mut cfg.groups[gi];
        info!("group {}: {} nodes from {source}{note}", g.name, picked.len());
        g.options.extend(picked);
        if g.options.is_empty() {
            warn!("group {} has no usable nodes; it will REJECT", g.name);
            g.options.push("REJECT".into());
        }
    }
    Ok(())
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

    #[test]
    fn to_line_roundtrips() {
        let text = format!(
            "ss://{}@1.2.3.4:8388#A\nvmess://{}\ntrojan://pw@t.example:443?sni=t.example&type=ws&path=%2Fws&host=cdn.example#T\n",
            STANDARD.encode("aes-256-gcm:pw"),
            STANDARD.encode(r#"{"ps":"V","add":"v.example","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"net":"ws","path":"/r","tls":"tls"}"#)
        );
        for (name, def) in parse(&text).0 {
            let line = def.to_line(&name);
            let (back_name, back) = parse_proxy(&line).unwrap();
            assert_eq!((back_name, format!("{back:?}")), (name, format!("{def:?}")), "{line}");
        }
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
        assert_eq!(skipped, ["REALITY not supported yet"]);
        assert!(matches!(&nodes[1].1, ProxyDef::Shadowsocks { password, port: 443, .. } if password == "p@ss"));
        match &nodes[2].1 {
            ProxyDef::Vmess { tls: true, ws: Some(ws), sni: Some(sni), .. } => {
                assert_eq!((ws.path.as_str(), ws.host.as_deref(), sni.as_str()), ("/ray", Some("cdn.example"), "cdn.example"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&nodes[3].1, ProxyDef::Vless { tls: true, ws: Some(w), .. } if w.path == "/ws"));
        assert!(matches!(&nodes[4].1, ProxyDef::Trojan { skip_cert_verify: true, .. }));
        assert!(matches!(&nodes[5].1, ProxyDef::Hysteria2 { port: 8443, skip_cert_verify: true, .. }));
    }
}
