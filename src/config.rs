use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use crate::rule::Rule;
use crate::transport::WsOpts;

#[derive(Debug, Default)]
pub struct General {
    pub http_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub api_listen: Option<String>,
    pub geoip_db: Option<String>,
    pub loglevel: Option<String>,
    pub enhanced_mode: bool,
    pub tun_mtu: Option<u16>,
    pub fake_ip_range: Option<String>,
    pub dns_server: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ProxyDef {
    Shadowsocks { server: String, port: u16, method: String, password: String },
    Trojan { server: String, port: u16, password: String, sni: Option<String>, skip_cert_verify: bool, ws: Option<WsOpts> },
    Vless {
        server: String,
        port: u16,
        uuid: String,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        ws: Option<WsOpts>,
    },
    Hysteria2 { server: String, port: u16, password: String, sni: Option<String>, skip_cert_verify: bool },
    Vmess {
        server: String,
        port: u16,
        uuid: String,
        method: String,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        ws: Option<WsOpts>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupKind {
    Select,
    /// Picks the lowest latency; only switches when the gain exceeds `tolerance_ms`.
    UrlTest { tolerance_ms: u64 },
    /// Picks the first option that passes the health check.
    Fallback,
    /// Spreads connections randomly over healthy options.
    LoadBalance,
}

#[derive(Debug, Clone)]
pub struct GroupDef {
    pub name: String,
    pub kind: GroupKind,
    pub options: Vec<String>,
    pub url: String,
    pub interval_secs: u64,
}

pub const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Debug, Default)]
pub struct Config {
    pub general: General,
    pub proxies: Vec<(String, ProxyDef)>,
    pub groups: Vec<GroupDef>,
    pub rules: Vec<Rule>,
}

fn split_kv(line: &str) -> Result<(&str, &str)> {
    let (k, v) = line.split_once('=').ok_or_else(|| anyhow!("expected `key = value`"))?;
    Ok((k.trim(), v.trim()))
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)
}

/// Accepts `addr:port` or a bare port (bound to localhost).
fn listen_addr(v: &str) -> String {
    if v.parse::<u16>().is_ok() {
        format!("127.0.0.1:{v}")
    } else {
        v.to_string()
    }
}

fn parse_proxy(line: &str) -> Result<(String, ProxyDef)> {
    let (name, rest) = split_kv(line)?;
    let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        bail!("proxy needs `type, server, port, ...`");
    }
    let server = parts[1].to_string();
    let port: u16 = parts[2].parse().with_context(|| format!("bad port {:?}", parts[2]))?;
    let mut params = HashMap::new();
    for p in &parts[3..] {
        let (k, v) = split_kv(p)?;
        params.insert(k.to_ascii_lowercase(), unquote(v).to_string());
    }
    let mut take = |k: &str| params.remove(k);
    let ws = matches!(take("ws").as_deref(), Some("true" | "1")).then(|| WsOpts::from_params(take("ws-path"), take("ws-headers")));
    let def = match parts[0].to_ascii_lowercase().as_str() {
        "ss" => ProxyDef::Shadowsocks {
            server,
            port,
            method: take("encrypt-method").ok_or_else(|| anyhow!("ss needs encrypt-method"))?,
            password: take("password").ok_or_else(|| anyhow!("ss needs password"))?,
        },
        "trojan" => ProxyDef::Trojan {
            server,
            port,
            password: take("password").ok_or_else(|| anyhow!("trojan needs password"))?,
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            ws: ws.clone(),
        },
        "vless" => ProxyDef::Vless {
            server,
            port,
            uuid: take("uuid").or_else(|| take("username")).ok_or_else(|| anyhow!("vless needs uuid"))?,
            tls: matches!(take("tls").as_deref(), Some("true" | "1")),
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            ws: ws.clone(),
        },
        "vmess" => ProxyDef::Vmess {
            server,
            port,
            uuid: take("username").or_else(|| take("uuid")).ok_or_else(|| anyhow!("vmess needs username (the uuid)"))?,
            method: take("encrypt-method").unwrap_or_else(|| "auto".to_string()),
            tls: matches!(take("tls").as_deref(), Some("true" | "1")),
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            ws: ws.clone(),
        },
        "hysteria2" | "hy2" => ProxyDef::Hysteria2 {
            server,
            port,
            password: take("password").ok_or_else(|| anyhow!("hysteria2 needs password"))?,
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
        },
        other => bail!("unsupported proxy type {other:?} (supported: ss, trojan, vless, vmess, hysteria2)"),
    };
    Ok((name.to_string(), def))
}

fn parse_group(line: &str) -> Result<GroupDef> {
    let (name, rest) = split_kv(line)?;
    let mut parts = rest.split(',').map(str::trim).filter(|p| !p.is_empty());
    let kind = parts.next().ok_or_else(|| anyhow!("empty group"))?.to_ascii_lowercase();
    let (mut options, mut params) = (Vec::new(), HashMap::new());
    for p in parts {
        match p.split_once('=') {
            Some((k, v)) => {
                params.insert(k.trim().to_ascii_lowercase(), unquote(v.trim()).to_string());
            }
            None => options.push(p.to_string()),
        }
    }
    let num = |k: &str, default: u64| -> Result<u64> {
        params.get(k).map_or(Ok(default), |v| v.parse().map_err(|_| anyhow!("bad {k} {v:?}")))
    };
    let kind = match kind.as_str() {
        "select" => GroupKind::Select,
        "url-test" => GroupKind::UrlTest { tolerance_ms: num("tolerance", 100)? },
        "fallback" => GroupKind::Fallback,
        "load-balance" => GroupKind::LoadBalance,
        other => bail!("unsupported group type {other:?} (supported: select, url-test, fallback, load-balance)"),
    };
    if options.is_empty() {
        bail!("group {name:?} has no options");
    }
    Ok(GroupDef {
        name: name.to_string(),
        kind,
        options,
        url: params.get("url").cloned().unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
        interval_secs: num("interval", 600)?.max(10),
    })
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg = Config::default();
        let mut section = String::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with("//") {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_string();
                continue;
            }
            let ctx = || format!("line {}: {}", i + 1, line);
            match section.as_str() {
                "General" => {
                    let (k, v) = split_kv(line).with_context(ctx)?;
                    let g = &mut cfg.general;
                    match k {
                        "http-listen" => g.http_listen = Some(listen_addr(v)),
                        "socks5-listen" => g.socks5_listen = Some(listen_addr(v)),
                        "api-listen" => g.api_listen = Some(listen_addr(v)),
                        "geoip-db" => g.geoip_db = Some(v.to_string()),
                        "loglevel" => g.loglevel = Some(v.to_string()),
                        "enhanced-mode" => g.enhanced_mode = matches!(v, "true" | "1"),
                        "tun-mtu" => g.tun_mtu = Some(v.parse().map_err(|_| anyhow!("bad tun-mtu")).with_context(ctx)?),
                        "fake-ip-range" => g.fake_ip_range = Some(v.to_string()),
                        "dns-server" => {
                            g.dns_server = v.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "system").map(String::from).collect()
                        }
                        _ => {} // unknown keys are tolerated for compatibility
                    }
                }
                "Proxy" => cfg.proxies.push(parse_proxy(line).with_context(ctx)?),
                "Proxy Group" => cfg.groups.push(parse_group(line).with_context(ctx)?),
                "Rule" => cfg.rules.push(Rule::parse(line).with_context(ctx)?),
                _ => {}
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample() {
        let cfg = Config::parse(include_str!("../examples/sluice.conf")).unwrap();
        assert_eq!(cfg.general.http_listen.as_deref(), Some("127.0.0.1:6152"));
        assert_eq!(cfg.proxies.len(), 6);
        assert!(matches!(&cfg.proxies[2].1, ProxyDef::Vmess { tls: true, ws: None, .. }));
        match &cfg.proxies[4].1 {
            ProxyDef::Vmess { ws: Some(ws), .. } => {
                assert_eq!((ws.path.as_str(), ws.host.as_deref()), ("/ray", Some("cdn.example.com")))
            }
            other => panic!("expected VMess over WebSocket, got {other:?}"),
        }
        assert!(matches!(&cfg.proxies[5].1, ProxyDef::Vless { tls: true, .. }));
        assert!(matches!(&cfg.proxies[1].1, ProxyDef::Trojan { skip_cert_verify: false, .. }));
        assert_eq!(cfg.groups[0].options, vec!["Auto", "HK-SS", "JP-Trojan", "US-VLESS", "DIRECT"]);
        assert_eq!(cfg.groups[1].kind, GroupKind::UrlTest { tolerance_ms: 50 });
        assert_eq!(cfg.groups[1].interval_secs, 300);
        assert!(cfg.rules.len() >= 5);
    }

    #[test]
    fn errors_name_the_line() {
        let err = Config::parse("[Proxy]\nA = vless, h, 1\n").unwrap_err();
        assert!(format!("{err:#}").contains("line 2"));
    }
}
