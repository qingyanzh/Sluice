use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use crate::obfs::SsPlugin;
use crate::rule::Rule;
use crate::transport::{Layer, WsOpts, XhttpMode, XhttpOpts};

#[derive(Debug, Default)]
pub struct General {
    pub http_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub api_listen: Option<String>,
    pub geoip_db: Option<String>,
    /// MaxMind ASN database (e.g. GeoLite2-ASN.mmdb) for IP-ASN rules.
    pub asn_db: Option<String>,
    pub loglevel: Option<String>,
    pub enhanced_mode: bool,
    pub tun_mtu: Option<u16>,
    pub fake_ip_range: Option<String>,
    pub dns_server: Vec<String>,
    /// DoH (`https://`), DoT (`tls://`) or DoQ (`quic://`) servers, used instead of `dns_server`.
    pub encrypted_dns_server: Vec<String>,
    /// Send encrypted DNS through the proxy rules instead of straight out.
    pub encrypted_dns_follow_outbound_mode: bool,
    /// `ip:port` or `*:port` destinations whose DNS queries the TUN answers itself.
    pub hijack_dns: Vec<String>,
    pub rule_set_update_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum ProxyDef {
    Shadowsocks { server: String, port: u16, method: String, password: String, plugin: Option<SsPlugin> },
    Trojan { server: String, port: u16, password: String, sni: Option<String>, skip_cert_verify: bool, layer: Option<Layer> },
    Vless {
        server: String,
        port: u16,
        uuid: String,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        layer: Option<Layer>,
        /// REALITY instead of ordinary TLS; `sni` is the site it impersonates.
        reality: Option<RealityDef>,
        /// `xtls-rprx-vision` or none.
        flow: Option<String>,
    },
    /// `obfs`: Salamander obfuscation password. `ports`: port-hopping spec such as
    /// `443;20000-50000` (`port` is then just the first port); `hop_interval` in seconds.
    Hysteria2 {
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        obfs: Option<String>,
        ports: Option<String>,
        hop_interval: Option<u64>,
    },
    Vmess {
        server: String,
        port: u16,
        uuid: String,
        method: String,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        layer: Option<Layer>,
        /// Above 0: legacy (non-AEAD) header.
        alter_id: u16,
    },
}

impl ProxyDef {
    /// Renders the proxy as a `[Proxy]` line that `parse_proxy` reads back.
    pub fn to_line(&self, name: &str) -> String {
        let mut parts: Vec<String> = Vec::new();
        let tls_bits = |parts: &mut Vec<String>, sni: &Option<String>, skip: bool| {
            if let Some(s) = sni {
                parts.push(format!("sni={s}"));
            }
            if skip {
                parts.push("skip-cert-verify=true".into());
            }
        };
        let layer_bits = |parts: &mut Vec<String>, layer: &Option<Layer>| {
            if let Some(Layer::Grpc { service }) = layer {
                parts.push("grpc=true".into());
                parts.push(format!("grpc-service-name={service}"));
            }
            if let Some(Layer::Xhttp(x)) = layer {
                parts.push("xhttp=true".into());
                parts.push(format!("xhttp-path={}", x.path));
                parts.extend(x.host.iter().map(|h| format!("xhttp-host={h}")));
                if x.mode != XhttpMode::Auto {
                    parts.push(format!("xhttp-mode={}", x.mode.as_str()));
                }
                if x.padding != XhttpOpts::default().padding {
                    parts.push(format!("xhttp-padding-bytes={}-{}", x.padding.0, x.padding.1));
                }
            }
            if let Some(Layer::Ws(w) | Layer::HttpUpgrade(w)) = layer {
                parts.push(if matches!(layer, Some(Layer::Ws(_))) { "ws=true" } else { "http-upgrade=true" }.into());
                parts.push(format!("ws-path={}", w.path));
                let mut headers: Vec<String> = w.host.iter().map(|h| format!("Host:{h}")).collect();
                headers.extend(w.headers.iter().map(|(k, v)| format!("{k}:{v}")));
                if !headers.is_empty() {
                    parts.push(format!("ws-headers={}", headers.join("|")));
                }
            }
        };
        match self {
            ProxyDef::Shadowsocks { server, port, method, password, plugin } => {
                parts.extend(["ss".into(), server.clone(), port.to_string()]);
                parts.push(format!("encrypt-method={method}"));
                parts.push(format!("password={password}"));
                match plugin {
                    Some(SsPlugin::Obfs { tls, host, uri }) => {
                        parts.push(format!("obfs={}", if *tls { "tls" } else { "http" }));
                        parts.push(format!("obfs-host={host}"));
                        parts.push(format!("obfs-uri={uri}"));
                    }
                    Some(p) => {
                        let (name, opts) = p.to_sip003();
                        parts.push(format!("plugin={name}"));
                        parts.push(format!("plugin-opts={opts}"));
                    }
                    None => {}
                }
            }
            ProxyDef::Trojan { server, port, password, sni, skip_cert_verify, layer } => {
                parts.extend(["trojan".into(), server.clone(), port.to_string(), format!("password={password}")]);
                tls_bits(&mut parts, sni, *skip_cert_verify);
                layer_bits(&mut parts, layer);
            }
            ProxyDef::Vless { server, port, uuid, tls, sni, skip_cert_verify, layer, reality, flow } => {
                parts.extend(["vless".into(), server.clone(), port.to_string(), format!("uuid={uuid}")]);
                if let Some(f) = flow {
                    parts.push(format!("flow={f}"));
                }
                if *tls {
                    parts.push("tls=true".into());
                }
                tls_bits(&mut parts, sni, *skip_cert_verify);
                layer_bits(&mut parts, layer);
                if let Some(r) = reality {
                    parts.push(format!("reality-public-key={}", r.public_key));
                    if !r.short_id.is_empty() {
                        parts.push(format!("reality-short-id={}", r.short_id));
                    }
                }
            }
            ProxyDef::Hysteria2 { server, port, password, sni, skip_cert_verify, obfs, ports, hop_interval } => {
                parts.extend(["hysteria2".into(), server.clone(), port.to_string(), format!("password={password}")]);
                tls_bits(&mut parts, sni, *skip_cert_verify);
                if let Some(o) = obfs {
                    parts.push("obfs=salamander".into());
                    parts.push(format!("obfs-password={o}"));
                }
                if let Some(p) = ports {
                    parts.push(format!("port-hopping={}", p.replace(',', ";")));
                }
                if let Some(i) = hop_interval {
                    parts.push(format!("port-hopping-interval={i}"));
                }
            }
            ProxyDef::Vmess { server, port, uuid, method, tls, sni, skip_cert_verify, layer, alter_id } => {
                parts.extend(["vmess".into(), server.clone(), port.to_string(), format!("username={uuid}")]);
                parts.push(format!("encrypt-method={method}"));
                if *alter_id > 0 {
                    parts.push(format!("alter-id={alter_id}"));
                }
                if *tls {
                    parts.push("tls=true".into());
                }
                tls_bits(&mut parts, sni, *skip_cert_verify);
                layer_bits(&mut parts, layer);
            }
        }
        format!("{name} = {}", parts.join(", "))
    }
}

/// REALITY parameters as written in configs and links (validated when the router is built).
#[derive(Debug, Clone, PartialEq)]
pub struct RealityDef {
    pub public_key: String,
    pub short_id: String,
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
    /// Subscription URL or file whose nodes are appended to `options`.
    pub policy_path: Option<String>,
    /// Only subscription nodes whose name matches this regex are kept.
    pub policy_filter: Option<String>,
    pub update_interval_secs: u64,
}

pub const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Debug, Default)]
pub struct Config {
    pub general: General,
    pub proxies: Vec<(String, ProxyDef)>,
    pub groups: Vec<GroupDef>,
    pub rules: Vec<Rule>,
    /// `[Host]` lines: name or wildcard pattern, and its value (addresses or `server:...`).
    pub hosts: Vec<(String, String)>,
    pub mitm: crate::mitm::MitmConfig,
    pub rewrites: crate::rewrite::Rewrites,
}

fn split_kv(line: &str) -> Result<(&str, &str)> {
    let (k, v) = line.split_once('=').ok_or_else(|| anyhow!("expected `key = value`"))?;
    Ok((k.trim(), v.trim()))
}

fn list(v: &str) -> Vec<String> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
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

pub fn parse_proxy(line: &str) -> Result<(String, ProxyDef)> {
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
    let layer = if matches!(take("grpc").as_deref(), Some("true" | "1")) {
        Some(Layer::Grpc { service: take("grpc-service-name").ok_or_else(|| anyhow!("grpc=true needs grpc-service-name"))? })
    } else if matches!(take("xhttp").as_deref(), Some("true" | "1")) {
        let mut x = XhttpOpts { path: take("xhttp-path").unwrap_or_else(|| "/".into()), host: take("xhttp-host"), ..Default::default() };
        x.mode = XhttpMode::parse(&take("xhttp-mode").unwrap_or_default())?;
        if let Some(p) = take("xhttp-padding-bytes") {
            x.padding = XhttpOpts::parse_padding(&p)?;
        }
        Some(Layer::Xhttp(x))
    } else if matches!(take("http-upgrade").as_deref(), Some("true" | "1")) {
        Some(Layer::HttpUpgrade(WsOpts::from_params(take("ws-path"), take("ws-headers"))))
    } else {
        matches!(take("ws").as_deref(), Some("true" | "1"))
            .then(|| Layer::Ws(WsOpts::from_params(take("ws-path"), take("ws-headers"))))
    };
    let def = match parts[0].to_ascii_lowercase().as_str() {
        "ss" => ProxyDef::Shadowsocks {
            server,
            port,
            method: take("encrypt-method").ok_or_else(|| anyhow!("ss needs encrypt-method"))?,
            password: take("password").ok_or_else(|| anyhow!("ss needs password"))?,
            // Surge's `obfs=http|tls, obfs-host, obfs-uri`, or SIP003 `plugin` + `plugin-opts`.
            plugin: match (take("obfs"), take("plugin")) {
                (Some(mode), _) => {
                    let opts = [("obfs", Some(mode)), ("obfs-host", take("obfs-host")), ("obfs-uri", take("obfs-uri"))];
                    let opts: Vec<String> = opts.iter().filter_map(|(k, v)| Some(format!("{k}={}", v.as_ref()?))).collect();
                    Some(SsPlugin::parse("obfs-local", &opts.join(";"))?)
                }
                (None, Some(name)) => Some(SsPlugin::parse(&name, &take("plugin-opts").unwrap_or_default())?),
                (None, None) => None,
            },
        },
        "trojan" => ProxyDef::Trojan {
            server,
            port,
            password: take("password").ok_or_else(|| anyhow!("trojan needs password"))?,
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            layer: layer.clone(),
        },
        "vless" => ProxyDef::Vless {
            server,
            port,
            uuid: take("uuid").or_else(|| take("username")).ok_or_else(|| anyhow!("vless needs uuid"))?,
            tls: matches!(take("tls").as_deref(), Some("true" | "1")),
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            layer: layer.clone(),
            reality: take("reality-public-key")
                .map(|public_key| RealityDef { public_key, short_id: take("reality-short-id").unwrap_or_default() }),
            flow: take("flow").filter(|f| !f.is_empty()),
        },
        "vmess" => ProxyDef::Vmess {
            server,
            port,
            uuid: take("username").or_else(|| take("uuid")).ok_or_else(|| anyhow!("vmess needs username (the uuid)"))?,
            method: take("encrypt-method").unwrap_or_else(|| "auto".to_string()),
            alter_id: take("alter-id").map_or(Ok(0), |a| a.parse().map_err(|_| anyhow!("bad alter-id {a:?}")))?,
            tls: matches!(take("tls").as_deref(), Some("true" | "1")),
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            layer: layer.clone(),
        },
        "hysteria2" | "hy2" => ProxyDef::Hysteria2 {
            server,
            port,
            password: take("password").ok_or_else(|| anyhow!("hysteria2 needs password"))?,
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            obfs: match take("obfs").as_deref() {
                None | Some("none") => None,
                Some("salamander") => Some(take("obfs-password").ok_or_else(|| anyhow!("obfs=salamander needs obfs-password"))?),
                Some(other) => bail!("unsupported hysteria2 obfs {other:?} (supported: salamander)"),
            },
            ports: match take("port-hopping").or_else(|| take("ports")) {
                Some(p) => {
                    crate::udphop::parse_ports(&p)?;
                    Some(p.replace(';', ","))
                }
                None => None,
            },
            hop_interval: match take("port-hopping-interval").or_else(|| take("hop-interval")) {
                Some(i) => Some(i.trim_end_matches('s').parse().map_err(|_| anyhow!("bad port-hopping-interval {i:?}"))?),
                None => None,
            },
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
    let policy_path = params.get("policy-path").cloned();
    if options.is_empty() && policy_path.is_none() {
        bail!("group {name:?} has no options");
    }
    if let Some(re) = params.get("policy-regex-filter") {
        regex::Regex::new(re).map_err(|e| anyhow!("bad policy-regex-filter: {e}"))?;
    }
    Ok(GroupDef {
        name: name.to_string(),
        kind,
        options,
        url: params.get("url").cloned().unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
        interval_secs: num("interval", 600)?.max(10),
        policy_path,
        policy_filter: params.get("policy-regex-filter").cloned(),
        update_interval_secs: num("update-interval", 86400)?.max(60),
    })
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg = Config { mitm: crate::mitm::MitmConfig::new(), ..Config::default() };
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
                        "asn-db" => g.asn_db = Some(v.to_string()),
                        "loglevel" => g.loglevel = Some(v.to_string()),
                        "enhanced-mode" => g.enhanced_mode = matches!(v, "true" | "1"),
                        "tun-mtu" => g.tun_mtu = Some(v.parse().map_err(|_| anyhow!("bad tun-mtu")).with_context(ctx)?),
                        "fake-ip-range" => g.fake_ip_range = Some(v.to_string()),
                        "rule-set-update-interval" => {
                            g.rule_set_update_interval = Some(v.parse().map_err(|_| anyhow!("bad rule-set-update-interval")).with_context(ctx)?)
                        }
                        "dns-server" => {
                            g.dns_server = v.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "system").map(String::from).collect()
                        }
                        "encrypted-dns-server" => g.encrypted_dns_server = list(v),
                        "encrypted-dns-follow-outbound-mode" => g.encrypted_dns_follow_outbound_mode = matches!(v, "true" | "1"),
                        "hijack-dns" => g.hijack_dns = list(v),
                        _ => {} // unknown keys are tolerated for compatibility
                    }
                }
                "Proxy" => cfg.proxies.push(parse_proxy(line).with_context(ctx)?),
                "Proxy Group" => cfg.groups.push(parse_group(line).with_context(ctx)?),
                "Host" => {
                    let (k, v) = split_kv(line).with_context(ctx)?;
                    cfg.hosts.push((k.to_string(), v.to_string()));
                }
                "Rule" => cfg.rules.push(Rule::parse(line).with_context(ctx)?),
                "MITM" => {
                    let (k, v) = split_kv(line).with_context(ctx)?;
                    cfg.mitm.set(k, v);
                }
                "URL Rewrite" => cfg.rewrites.url.push(crate::rewrite::UrlRewrite::parse(line).with_context(ctx)?),
                "Header Rewrite" => cfg.rewrites.header.push(crate::rewrite::HeaderRewrite::parse(line).with_context(ctx)?),
                "Body Rewrite" => cfg.rewrites.body.push(crate::rewrite::BodyRewrite::parse(line).with_context(ctx)?),
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
        assert!(matches!(&cfg.proxies[2].1, ProxyDef::Vmess { tls: true, layer: None, .. }));
        match &cfg.proxies[4].1 {
            ProxyDef::Vmess { layer: Some(Layer::Ws(ws)), .. } => {
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
    fn xhttp_roundtrip() {
        let line = "X = vless, v.example, 443, uuid=u, tls=true, xhttp=true, xhttp-path=/xh, xhttp-host=cdn.example, xhttp-mode=stream-up, xhttp-padding-bytes=10-20";
        let (name, def) = parse_proxy(line).unwrap();
        let expected = XhttpOpts { path: "/xh".into(), host: Some("cdn.example".into()), mode: XhttpMode::StreamUp, padding: (10, 20) };
        assert!(matches!(&def, ProxyDef::Vless { layer: Some(Layer::Xhttp(x)), .. } if *x == expected));
        let again = parse_proxy(&def.to_line(&name)).unwrap().1;
        assert!(matches!(&again, ProxyDef::Vless { layer: Some(Layer::Xhttp(x)), .. } if *x == expected));
    }

    #[test]
    fn dns_settings() {
        let cfg = Config::parse(
            "[General]\ndns-server = system, 223.5.5.5\nencrypted-dns-server = https://1.1.1.1/dns-query, tls://8.8.8.8\n\
             encrypted-dns-follow-outbound-mode = true\nhijack-dns = 8.8.8.8:53, *:53\n\
             [Host]\nexample.com = 1.2.3.4\n*.lan = server:192.168.1.1\n",
        )
        .unwrap();
        let g = &cfg.general;
        assert_eq!(g.dns_server, vec!["223.5.5.5"]);
        assert_eq!(g.encrypted_dns_server, vec!["https://1.1.1.1/dns-query", "tls://8.8.8.8"]);
        assert!(g.encrypted_dns_follow_outbound_mode);
        assert_eq!(g.hijack_dns, vec!["8.8.8.8:53", "*:53"]);
        assert_eq!(cfg.hosts[1], ("*.lan".to_string(), "server:192.168.1.1".to_string()));
        crate::dns::Resolver::new(&cfg).unwrap();
    }

    #[test]
    fn errors_name_the_line() {
        let err = Config::parse("[Proxy]\nA = vless, h, 1\n").unwrap_err();
        assert!(format!("{err:#}").contains("line 2"));
    }
}
