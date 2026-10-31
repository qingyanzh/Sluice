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
    /// V2Ray geosite.dat file or HTTP(S) URL. Defaults to MetaCubeX's public database.
    pub geosite_db: Option<String>,
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
    AnyTls {
        server: String, port: u16, password: String, sni: Option<String>,
        skip_cert_verify: bool, tfo: bool, alpn: Vec<String>, udp: bool,
        client_fingerprint: Option<String>,
    },
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
            ProxyDef::AnyTls { server, port, password, sni, skip_cert_verify, tfo, alpn, udp, client_fingerprint } => {
                parts.extend(["anytls".into(), server.clone(), port.to_string(), format!("password={password}")]);
                tls_bits(&mut parts, sni, *skip_cert_verify);
                if let Some(fp) = client_fingerprint { parts.push(format!("client-fingerprint={fp}")); }
                if *tfo { parts.push("tfo=true".into()); }
                if !alpn.is_empty() { parts.push(format!("alpn={}", alpn.join("|"))); }
                parts.push(format!("udp={udp}"));
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
    pub user_agent: Option<String>,
    /// Only subscription nodes whose name matches this regex are kept.
    pub policy_filter: Option<String>,
    pub update_interval_secs: u64,
    /// Named subscription sources whose nodes are flattened into this group.
    pub sources: Vec<String>,
    pub node_filter: Option<String>,
    pub import_groups: bool,
}

#[derive(Debug, Clone)]
pub struct SubscriptionDef {
    pub name: String,
    pub path: String,
    pub user_agent: Option<String>,
    pub filter: Option<String>,
    pub update_interval_secs: u64,
    pub import_groups: bool,
}

pub const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

impl GroupDef {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn to_line(&self) -> String {
        let kind = match self.kind {
            GroupKind::Select => "select",
            GroupKind::UrlTest { .. } => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance => "load-balance",
        };
        let mut parts = vec![kind.to_string()];
        parts.extend(self.options.iter().cloned());
        parts.push(format!("url=\"{}\"", self.url));
        parts.push(format!("interval={}", self.interval_secs));
        if let GroupKind::UrlTest { tolerance_ms } = self.kind {
            parts.push(format!("tolerance={tolerance_ms}"));
        }
        for (key, value) in [("policy-path", &self.policy_path), ("user-agent", &self.user_agent), ("policy-regex-filter", &self.policy_filter)] {
            if let Some(value) = value {
                parts.push(format!("{key}=\"{value}\""));
            }
        }
        parts.push(format!("update-interval={}", self.update_interval_secs));
        if !self.sources.is_empty() { parts.push(format!("use={}", self.sources.join("|"))); }
        if let Some(filter) = &self.node_filter { parts.push(format!("node-filter=\"{filter}\"")); }
        if self.import_groups { parts.push("import-groups=true".into()); }
        format!("{} = {}", self.name, parts.join(", "))
    }
}

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
    pub subscriptions: Vec<crate::subscription::SubscriptionInfo>,
    pub providers: Vec<SubscriptionDef>,
    pub subscription_nodes: Vec<crate::subscription::SubscriptionNode>,
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
        "anytls" => ProxyDef::AnyTls {
            server, port,
            password: take("password").ok_or_else(|| anyhow!("anytls needs password"))?,
            client_fingerprint: take("client-fingerprint").filter(|s| !s.is_empty()),
            sni: take("sni"),
            skip_cert_verify: matches!(take("skip-cert-verify").as_deref(), Some("true" | "1")),
            tfo: matches!(take("tfo").as_deref(), Some("true" | "1")),
            alpn: take("alpn").map_or_else(Vec::new, |s| s.split('|').filter(|s| !s.is_empty()).map(str::to_string).collect()),
            udp: !matches!(take("udp").as_deref(), Some("false" | "0")),
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

pub(crate) fn parse_group(line: &str) -> Result<GroupDef> {
    let (name, rest) = split_kv(line)?;
    let mut quoted = false;
    let mut parts = rest.split(|c| {
        if c == '"' { quoted = !quoted; }
        c == ',' && !quoted
    }).map(str::trim).filter(|p| !p.is_empty());
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
    let sources: Vec<String> = params.get("use").map(|v| v.split('|').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default();
    let node_filter = params.get("node-filter").cloned();
    if let Some(filter) = &node_filter { regex::Regex::new(filter).context("bad node-filter")?; }
    let user_agent = params.get("user-agent").cloned();
    if let Some(value) = &user_agent {
        http::HeaderValue::from_str(value).context("bad user-agent")?;
    }
    if options.is_empty() && policy_path.is_none() && sources.is_empty() {
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
        user_agent,
        policy_filter: params.get("policy-regex-filter").cloned(),
        update_interval_secs: num("update-interval", 86400)?.max(60),
        sources,
        node_filter,
        import_groups: match params.get("import-groups").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            _ => bail!("import-groups must be true or false"),
        },
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
                        "geosite-db" => g.geosite_db = Some(v.to_string()),
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
                "Subscription" => {
                    let (name, params) = split_kv(line).with_context(ctx)?;
                    if name.is_empty() || name.contains(['|', ',', '=', '\r', '\n']) {
                        bail!("{}: invalid subscription name", ctx());
                    }
                    let group = parse_group(&format!("{name} = select, {params}")).with_context(ctx)?;
                    let path = group.policy_path.ok_or_else(|| anyhow!("{}: subscription needs policy-path", ctx()))?;
                    if path.is_empty() || !group.options.is_empty() || !group.sources.is_empty() {
                        bail!("{}: subscription only accepts source parameters", ctx());
                    }
                    cfg.providers.push(SubscriptionDef { name: name.into(), path, user_agent: group.user_agent,
                        filter: group.policy_filter, update_interval_secs: group.update_interval_secs, import_groups: group.import_groups });
                }
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
    fn independent_subscriptions_and_group_sources_parse_and_roundtrip() {
        let cfg = Config::parse("[Subscription]\nA = policy-path=nodes.txt, user-agent=Test, policy-regex-filter=HK, update-interval=100\n[Proxy Group]\nMixed = select, @A/HK, use=A|B, node-filter=\"^(HK|JP)$\"\n").unwrap();
        assert_eq!(cfg.providers[0].name, "A");
        assert_eq!(cfg.providers[0].path, "nodes.txt");
        assert_eq!(cfg.providers[0].update_interval_secs, 100);
        assert_eq!(cfg.groups[0].sources, ["A", "B"]);
        let back = parse_group(&cfg.groups[0].to_line()).unwrap();
        assert_eq!(back.sources, cfg.groups[0].sources);
        assert_eq!(back.node_filter, cfg.groups[0].node_filter);
        for line in ["A = policy-path=", "A = user-agent=Test", "A = policy-path=x, DIRECT", "A|B = policy-path=x"] {
            assert!(Config::parse(&format!("[Subscription]\n{line}\n")).is_err(), "{line}");
        }
        assert!(Config::parse("[Proxy Group]\nG = select, use=A, node-filter=[\n").is_err());
    }

    #[test]
    fn anytls_roundtrip_and_defaults() {
        for options in ["", ", sni=tls.example, skip-cert-verify=true, tfo=true, alpn=h2|http/1.1, udp=false, client-fingerprint=chrome"] {
            let (name, def) = parse_proxy(&format!("Test = anytls, ::1, 443, password=p@ss:word{options}")).unwrap();
            let (_, back) = parse_proxy(&def.to_line(&name)).unwrap();
            assert_proxy_eq(&def, &back);
            assert!(matches!(def, ProxyDef::AnyTls { udp, .. } if udp == options.is_empty()));
        }
        assert!(parse_proxy("Test = anytls, h, 443").unwrap_err().to_string().contains("password"));
    }

    // ProxyDef and Layer do not implement PartialEq; compare every field via Debug.
    fn assert_proxy_eq(actual: &ProxyDef, expected: &ProxyDef) {
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }

    #[test]
    fn every_proxy_and_transport_parses_and_roundtrips() {
        let mut cases = vec![
            (
                "ss, ss.example, 8388, encrypt-method=chacha20-ietf-poly1305, password=secret:with=punctuation".to_string(),
                ProxyDef::Shadowsocks {
                    server: "ss.example".into(), port: 8388,
                    method: "chacha20-ietf-poly1305".into(), password: "secret:with=punctuation".into(), plugin: None,
                },
            ),
            (
                "hy2, ::1, 8443, password=secret, sni=tls.example, skip-cert-verify=1, obfs=salamander, obfs-password=mask, ports=443;5000-5002, hop-interval=15s".to_string(),
                ProxyDef::Hysteria2 {
                    server: "::1".into(), port: 8443, password: "secret".into(),
                    sni: Some("tls.example".into()), skip_cert_verify: true, obfs: Some("mask".into()),
                    ports: Some("443,5000-5002".into()), hop_interval: Some(15),
                },
            ),
            (
                "hysteria2, h.example, 443, password=secret, obfs=none".to_string(),
                ProxyDef::Hysteria2 {
                    server: "h.example".into(), port: 443, password: "secret".into(),
                    sni: None, skip_cert_verify: false, obfs: None, ports: None, hop_interval: None,
                },
            ),
        ];
        let mut transports = vec![
            (String::new(), None),
            (
                ", ws=1, ws-path=/socket, ws-headers=host:cdn.example|User-Agent:sluice|X-Test:a:b".into(),
                Some(Layer::Ws(WsOpts {
                    path: "/socket".into(), host: Some("cdn.example".into()),
                    headers: vec![("User-Agent".into(), "sluice".into()), ("X-Test".into(), "a:b".into())],
                })),
            ),
            (", grpc=true, grpc-service-name=tunnel".into(), Some(Layer::Grpc { service: "tunnel".into() })),
        ];
        for mode in [XhttpMode::Auto, XhttpMode::PacketUp, XhttpMode::StreamUp, XhttpMode::StreamOne] {
            transports.push((
                format!(", xhttp=1, xhttp-path=/upload, xhttp-host=cdn.example, xhttp-mode={}, xhttp-padding-bytes=12-24", mode.as_str()),
                Some(Layer::Xhttp(XhttpOpts { path: "/upload".into(), host: Some("cdn.example".into()), mode, padding: (12, 24) })),
            ));
        }
        for (transport, layer) in transports {
            for tls in [false, true] {
                let opts = format!("sni=tls.example, skip-cert-verify=true, tls={tls}{transport}");
                cases.extend([
                    (
                        format!("trojan, proxy.example, 443, password=secret, {opts}"),
                        ProxyDef::Trojan {
                            server: "proxy.example".into(), port: 443, password: "secret".into(),
                            sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(),
                        },
                    ),
                    (
                        format!("vmess, proxy.example, 443, username=test-uuid, encrypt-method=aes-128-gcm, {opts}"),
                        ProxyDef::Vmess {
                            server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(), method: "aes-128-gcm".into(),
                            tls, sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), alter_id: 0,
                        },
                    ),
                    (
                        format!("vless, proxy.example, 443, uuid=test-uuid, {opts}"),
                        ProxyDef::Vless {
                            server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(),
                            tls, sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), reality: None, flow: None,
                        },
                    ),
                ]);
            }
        }
        // Exercise the section parser as well as individual proxy lines.
        let text = cases.iter().enumerate().map(|(i, (line, _))| format!("Node {i} = {line}\n")).collect::<String>();
        let cfg = Config::parse(&format!("[Proxy]\n{text}")).unwrap();
        assert_eq!(cfg.proxies.len(), cases.len());
        for (i, ((name, actual), (_, expected))) in cfg.proxies.iter().zip(&cases).enumerate() {
            assert_eq!(name, &format!("Node {i}"));
            assert_proxy_eq(actual, expected);
            let rendered = actual.to_line(name);
            let (back_name, back) = parse_proxy(&rendered).unwrap();
            assert_eq!(&back_name, name, "{rendered}");
            assert_proxy_eq(&back, expected);
        }
    }

    #[test]
    fn proxy_defaults_and_aliases() {
        for (line, expected) in [
            ("V = VMESS, h, 1, UUID=u", ProxyDef::Vmess {
                server: "h".into(), port: 1, uuid: "u".into(), method: "auto".into(),
                tls: false, sni: None, skip_cert_verify: false, layer: None, alter_id: 0,
            }),
            ("V = VLESS, h, 1, USERNAME=\"u\"", ProxyDef::Vless {
                server: "h".into(), port: 1, uuid: "u".into(), tls: false, sni: None,
                skip_cert_verify: false, layer: None, reality: None, flow: None,
            }),
            ("T = trojan, h, 1, password=p, ws=true", ProxyDef::Trojan {
                server: "h".into(), port: 1, password: "p".into(), sni: None, skip_cert_verify: false,
                layer: Some(Layer::Ws(WsOpts { path: "/".into(), host: None, headers: vec![] })),
            }),
            ("T = trojan, h, 1, password=p, xhttp=true", ProxyDef::Trojan {
                server: "h".into(), port: 1, password: "p".into(), sni: None, skip_cert_verify: false,
                layer: Some(Layer::Xhttp(XhttpOpts::default())),
            }),
        ] {
            let (name, actual) = parse_proxy(line).unwrap();
            assert_proxy_eq(&actual, &expected);
            assert_proxy_eq(&parse_proxy(&actual.to_line(&name)).unwrap().1, &expected);
        }
    }

    #[test]
    fn reality_and_vision_roundtrip() {
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            for short_id in ["", "abcd"] {
                let expected = ProxyDef::Vless {
                    server: "r.example".into(), port: 443, uuid: "u".into(), tls: false,
                    sni: Some("www.example.com".into()), skip_cert_verify: false, layer: None,
                    reality: Some(RealityDef {
                        public_key: "9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4".into(), short_id: short_id.into(),
                    }),
                    flow: Some(flow.into()),
                };
                let line = expected.to_line("Reality");
                let (name, actual) = parse_proxy(&line).unwrap();
                assert_eq!(name, "Reality");
                assert_proxy_eq(&actual, &expected);
            }
        }
    }

    #[test]
    fn malformed_proxies_are_rejected_with_line_context() {
        for (proxy, reason) in [
            ("ss, h, 1, password=p", "ss needs encrypt-method"),
            ("ss, h, 1, encrypt-method=aes-128-gcm", "ss needs password"),
            ("trojan, h, 1", "trojan needs password"),
            ("vless, h, 1", "vless needs uuid"),
            ("vmess, h, 1", "vmess needs username"),
            ("hysteria2, h, 1", "hysteria2 needs password"),
            ("socks5, h, 1", "unsupported proxy type"),
            ("ss, h", "proxy needs"),
            ("trojan, h, 65536, password=p", "bad port"),
            ("trojan, h, 1, password", "expected `key = value`"),
            ("trojan, h, 1, password=p, grpc=true", "grpc=true needs grpc-service-name"),
            ("trojan, h, 1, password=p, xhttp=true, xhttp-mode=invalid", "unknown xhttp mode"),
            ("trojan, h, 1, password=p, xhttp=true, xhttp-padding-bytes=20-10", "bad xhttp padding range"),
            ("hy2, h, 1, password=p, obfs=unknown", "unsupported hysteria2 obfs"),
            ("hy2, h, 1, password=p, obfs=salamander", "obfs=salamander needs obfs-password"),
            ("hy2, h, 1, password=p, ports=5-3", "bad port range"),
            ("hy2, h, 1, password=p, hop-interval=abc", "bad port-hopping-interval"),
        ] {
            let err = Config::parse(&format!("[Proxy]\nBad = {proxy}\n")).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("line 2"), "{message}");
            assert!(message.contains(reason), "{proxy}: {message}");
        }
    }

    #[test]
    fn stream_flags_defaults_and_disabled_transports() {
        for (value, enabled) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            for (kind, credentials) in [("vmess", "username=u"), ("vless", "uuid=u")] {
                let line = format!("Test = {kind}, h, 443, {credentials}, tls={value}, skip-cert-verify={value}");
                let (_, def) = parse_proxy(&line).unwrap();
                match def {
                    ProxyDef::Vmess { tls, skip_cert_verify, layer: None, .. }
                    | ProxyDef::Vless { tls, skip_cert_verify, layer: None, .. } => {
                        assert_eq!((tls, skip_cert_verify), (enabled, enabled), "{line}");
                    }
                    other => panic!("{line}: {other:?}"),
                }
            }
        }
        for flags in ["ws=false, grpc=false, xhttp=false", "ws=0, grpc=0, xhttp=0"] {
            let (_, def) = parse_proxy(&format!("Test = trojan, h, 443, password=p, {flags}")).unwrap();
            assert!(matches!(def, ProxyDef::Trojan { layer: None, .. }));
        }
        let (_, def) = parse_proxy("Test = trojan, h, 443, password=p, grpc=1, grpc-service-name=\"\"").unwrap();
        assert!(matches!(def, ProxyDef::Trojan { layer: Some(Layer::Grpc { service }), .. } if service.is_empty()));
    }

    #[test]
    fn credential_alias_precedence_and_duplicate_parameters() {
        let (_, def) = parse_proxy("Test = vless, h, 443, username=fallback, uuid=preferred, tls=false, TLS=1").unwrap();
        assert!(matches!(def, ProxyDef::Vless { uuid, tls: true, .. } if uuid == "preferred"));
        let (_, def) = parse_proxy("Test = vmess, h, 443, uuid=fallback, username=preferred").unwrap();
        assert!(matches!(def, ProxyDef::Vmess { uuid, .. } if uuid == "preferred"));
        let (_, def) = parse_proxy("Test = hy2, h, 443, password=p, ports=9000, port-hopping=443;8443, hop-interval=20, port-hopping-interval=5s").unwrap();
        assert!(matches!(def, ProxyDef::Hysteria2 { ports: Some(p), hop_interval: Some(5), .. } if p == "443,8443"));
    }

    #[test]
    fn all_group_kinds_defaults_subscription_options_and_limits() {
        for (kind, expected) in [
            ("SELECT", GroupKind::Select),
            ("url-test", GroupKind::UrlTest { tolerance_ms: 100 }),
            ("fallback", GroupKind::Fallback),
            ("load-balance", GroupKind::LoadBalance),
        ] {
            let cfg = Config::parse(&format!("[Proxy Group]\nTest = {kind}, A, DIRECT, , REJECT\n")).unwrap();
            let g = &cfg.groups[0];
            assert_eq!(g.name, "Test");
            assert_eq!(g.kind, expected);
            assert_eq!(g.options, ["A", "DIRECT", "REJECT"]);
            assert_eq!(g.url, DEFAULT_TEST_URL);
            assert_eq!((g.interval_secs, g.update_interval_secs), (600, 86400));
            assert!(g.policy_path.is_none() && g.policy_filter.is_none());
        }
        let cfg = Config::parse("[Proxy Group]\nAuto = url-test, tolerance=25, url=\"https://test.example/check?a=b\", interval=1, policy-path=\"nodes.txt\", policy-regex-filter=\"^(JP|US)\", update-interval=2\n").unwrap();
        let g = &cfg.groups[0];
        assert_eq!(g.kind, GroupKind::UrlTest { tolerance_ms: 25 });
        assert!(g.options.is_empty());
        assert_eq!(g.url, "https://test.example/check?a=b");
        assert_eq!((g.interval_secs, g.update_interval_secs), (10, 60));
        assert_eq!(g.policy_path.as_deref(), Some("nodes.txt"));
        assert_eq!(g.policy_filter.as_deref(), Some("^(JP|US)"));
    }

    #[test]
    fn malformed_groups_report_line_and_reason() {
        for (body, reason) in [
            ("", "empty group"),
            ("unsupported, DIRECT", "unsupported group type"),
            ("select", "has no options"),
            ("url-test, DIRECT, tolerance=bad", "bad tolerance"),
            ("select, DIRECT, interval=-1", "bad interval"),
            ("select, DIRECT, update-interval=bad", "bad update-interval"),
            ("select, policy-path=nodes.txt, policy-regex-filter=[", "bad policy-regex-filter"),
        ] {
            let err = Config::parse(&format!("# comment\n[Proxy Group]\nBad = {body}\n")).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("line 3"), "{message}");
            assert!(message.contains(reason), "{body}: {message}");
        }
    }

    #[test]
    fn subscription_user_agent_roundtrip() {
        for agent in [None, Some("Surge/5.0"), Some("Custom agent/1.0 (a, b) token=123")] {
            let mut line = "Sub = url-test, DIRECT, policy-path=https://example.invalid/sub, policy-regex-filter=HK|JP, tolerance=50".to_string();
            if let Some(agent) = agent { line.push_str(&format!(", user-agent=\"{agent}\"")); }
            let original = parse_group(&line).unwrap();
            assert_eq!(original.user_agent.as_deref(), agent);
            let back = parse_group(&original.to_line()).unwrap();
            assert_eq!(format!("{original:?}"), format!("{back:?}"));
        }
        assert!(parse_group("Sub = select, policy-path=nodes.txt, user-agent=bad\rvalue").is_err());
    }

    #[test]
    fn general_settings_comments_unknown_sections_and_hosts() {
        let cfg = Config::parse(r#"
# comment
; comment
// comment
ignored before a section
[ General ]
http-listen = 8080
socks5-listen = [::1]:1080
api-listen = 127.0.0.2:9090
geoip-db = geoip.mmdb
asn-db = asn.mmdb
loglevel = debug
enhanced-mode = 1
tun-mtu = 1500
fake-ip-range = 198.18.0.0/15
rule-set-update-interval = 3600
dns-server = system, 1.1.1.1, , 8.8.8.8
encrypted-dns-server = https://dns.example/query, , tls://dns.example
encrypted-dns-follow-outbound-mode = 1
hijack-dns = *:53, , 8.8.8.8:53
future-option = tolerated
[Unknown]
this is ignored
[Host]
example.com = 1.2.3.4, ::1
*.lan = server:192.168.1.1
"#).unwrap();
        let expected = General {
            http_listen: Some("127.0.0.1:8080".into()), socks5_listen: Some("[::1]:1080".into()),
            api_listen: Some("127.0.0.2:9090".into()), geoip_db: Some("geoip.mmdb".into()),
            geosite_db: None, asn_db: Some("asn.mmdb".into()), loglevel: Some("debug".into()), enhanced_mode: true,
            tun_mtu: Some(1500), fake_ip_range: Some("198.18.0.0/15".into()),
            dns_server: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            encrypted_dns_server: vec!["https://dns.example/query".into(), "tls://dns.example".into()],
            encrypted_dns_follow_outbound_mode: true, hijack_dns: vec!["*:53".into(), "8.8.8.8:53".into()],
            rule_set_update_interval: Some(3600),
        };
        assert_eq!(format!("{:?}", cfg.general), format!("{expected:?}"));
        assert_eq!(cfg.hosts, [("example.com".into(), "1.2.3.4, ::1".into()), ("*.lan".into(), "server:192.168.1.1".into())]);
        assert!(cfg.proxies.is_empty() && cfg.groups.is_empty() && cfg.rules.is_empty());
        let empty = Config::parse("").unwrap();
        assert_eq!(format!("{:?}", empty.general), format!("{:?}", General::default()));
    }

    #[test]
    fn malformed_general_and_host_settings_report_line_context() {
        for (section, line, reason) in [
            ("General", "http-listen", "expected `key = value`"),
            ("General", "tun-mtu = bad", "bad tun-mtu"),
            ("General", "tun-mtu = 65536", "bad tun-mtu"),
            ("General", "rule-set-update-interval = -1", "bad rule-set-update-interval"),
            ("Host", "example.com", "expected `key = value`"),
        ] {
            let err = Config::parse(&format!("[{section}]\n{line}\n")).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("line 2"), "{message}");
            assert!(message.contains(reason), "{message}");
        }
    }

    #[test]
    fn parse_sample() {
        let cfg = Config::parse(include_str!("../examples/sluice.conf")).unwrap();
        assert_eq!(cfg.general.http_listen.as_deref(), Some("127.0.0.1:6252"));
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
