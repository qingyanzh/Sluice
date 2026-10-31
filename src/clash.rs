//! Clash / Mihomo YAML subscriptions: the `proxies:` list, mapped onto Sluice's proxy types.

use anyhow::{anyhow, bail, Result};
use serde_yaml::Value;

use crate::config::ProxyDef;
use crate::transport::{Layer, WsOpts, XhttpMode, XhttpOpts};

/// Whether `text` looks like a Clash config (a top-level `proxies:` key).
pub fn looks_like(text: &str) -> bool {
    text.lines().any(|l| l.trim_end() == "proxies:" || l.starts_with("proxies: "))
}

fn s(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(x) => Some(x.clone()).filter(|x| !x.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn flag(v: &Value, key: &str) -> bool {
    matches!(v.get(key), Some(Value::Bool(true))) || s(v, key).is_some_and(|x| x == "true" || x == "1")
}

fn need(v: &Value, key: &str) -> Result<String> {
    s(v, key).ok_or_else(|| anyhow!("missing {key}"))
}

/// `network: ws` (`ws-opts: {path, headers: {Host}}`) or `network: grpc`
/// (`grpc-opts: {grpc-service-name}`) or `network: xhttp` (`xhttp-opts: {path, host, mode}`).
fn transport(v: &Value) -> Result<Option<Layer>> {
    match s(v, "network").as_deref() {
        None | Some("tcp") => Ok(None),
        Some("ws") => {
            let opts = v.get("ws-opts");
            let path = opts.and_then(|o| s(o, "path")).unwrap_or_else(|| "/".into());
            let host = opts.and_then(|o| o.get("headers")).and_then(|h| s(h, "Host").or_else(|| s(h, "host")));
            let opts_ws = WsOpts { path, host, headers: Vec::new() };
            // Mihomo marks Xray's httpupgrade as a ws variant.
            if opts.is_some_and(|o| flag(o, "v2ray-http-upgrade")) {
                return Ok(Some(Layer::HttpUpgrade(opts_ws)));
            }
            Ok(Some(Layer::Ws(opts_ws)))
        }
        Some("grpc") => Ok(Some(Layer::Grpc {
            service: v.get("grpc-opts").and_then(|o| s(o, "grpc-service-name")).unwrap_or_default(),
        })),
        Some("xhttp") => {
            let opts = v.get("xhttp-opts");
            let get = |k: &str| opts.and_then(|o| s(o, k));
            let mut x = XhttpOpts { path: get("path").unwrap_or_else(|| "/".into()), host: get("host"), ..Default::default() };
            x.mode = XhttpMode::parse(&get("mode").unwrap_or_default())?;
            if let Some(p) = get("x-padding-bytes") {
                x.padding = XhttpOpts::parse_padding(&p)?;
            }
            Ok(Some(Layer::Xhttp(x)))
        }
        Some(other) => bail!("transport {other:?} not supported yet"),
    }
}

/// `plugin-opts: {mode: tls, host: x, tls: true}` as SIP003 `mode=tls;host=x;tls`.
fn plugin_opts(v: &Value) -> String {
    let Some(map) = v.get("plugin-opts").and_then(Value::as_mapping) else { return String::new() };
    let opts = map.iter().filter_map(|(k, val)| {
        let k = k.as_str()?;
        match val {
            Value::Bool(true) => Some(k.to_string()),
            // Explicit, so options that default on (v2ray-plugin `mux`) can be turned off.
            Value::Bool(false) => Some(format!("{k}=false")),
            Value::String(x) => Some(format!("{k}={x}")),
            Value::Number(n) => Some(format!("{k}={n}")),
            _ => None,
        }
    });
    opts.collect::<Vec<_>>().join(";")
}

fn proxy(v: &Value) -> Result<(String, ProxyDef)> {
    let name = need(v, "name")?;
    let server = need(v, "server")?;
    let port: u16 = need(v, "port")?.parse().map_err(|_| anyhow!("bad port"))?;
    let sni = s(v, "servername").or_else(|| s(v, "sni"));
    let skip = flag(v, "skip-cert-verify");
    let def = match need(v, "type")?.as_str() {
        "ss" => {
            let plugin = match s(v, "plugin") {
                Some(name) => Some(crate::obfs::SsPlugin::parse(&name, &plugin_opts(v))?),
                None => None,
            };
            ProxyDef::Shadowsocks { server, port, method: need(v, "cipher")?, password: need(v, "password")?, plugin }
        }
        "vmess" => {
            ProxyDef::Vmess {
                server,
                port,
                uuid: need(v, "uuid")?,
                method: s(v, "cipher").filter(|c| c != "none" && c != "zero").unwrap_or_else(|| "auto".into()),
                tls: flag(v, "tls"),
                sni,
                skip_cert_verify: skip,
                layer: transport(v)?,
                alter_id: s(v, "alterId").and_then(|a| a.parse().ok()).unwrap_or(0),
            }
        }
        "vless" => {
            let flow = s(v, "flow").filter(|f| !f.is_empty());
            if let Some(f) = flow.as_deref().filter(|f| !crate::vision::is_vision(f)) {
                bail!("VLESS flow {f:?} not supported");
            }
            let reality = match v.get("reality-opts") {
                Some(o) => {
                    let def = crate::config::RealityDef {
                        public_key: need(o, "public-key")?,
                        short_id: s(o, "short-id").unwrap_or_default(),
                    };
                    crate::reality::RealityOpts::parse(&def.public_key, &def.short_id, sni.as_deref().unwrap_or_default())?;
                    Some(def)
                }
                None => None,
            };
            ProxyDef::Vless {
                server,
                port,
                uuid: need(v, "uuid")?,
                tls: flag(v, "tls"),
                sni,
                skip_cert_verify: skip,
                layer: transport(v)?,
                reality,
                flow,
            }
        }
        "anytls" => {
            let alpn = match v.get("alpn") {
                None => Vec::new(),
                Some(Value::Sequence(items)) => items.iter().map(|v| {
                    v.as_str().map(str::to_string).ok_or_else(|| anyhow!("bad anytls alpn"))
                }).collect::<Result<Vec<_>>>()?,
                Some(Value::String(s)) => s.split([',', '|']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
                _ => bail!("bad anytls alpn"),
            };
            ProxyDef::AnyTls {
                server, port, password: need(v, "password")?, sni, skip_cert_verify: skip,
                tfo: flag(v, "tfo"), alpn,
                client_fingerprint: s(v, "client-fingerprint"),
                udp: v.get("udp").is_none() || flag(v, "udp"),
            }
        }
        "trojan" => ProxyDef::Trojan { server, port, password: need(v, "password")?, sni, skip_cert_verify: skip, layer: transport(v)? },
        "hysteria2" => {
            let obfs = match s(v, "obfs").as_deref() {
                None | Some("none") => None,
                Some("salamander") => Some(need(v, "obfs-password")?),
                Some(other) => bail!("hysteria2 obfs {other:?} not supported"),
            };
            let ports = s(v, "ports");
            if let Some(p) = &ports {
                crate::udphop::parse_ports(p)?;
            }
            let hop_interval = match s(v, "hop-interval") {
                Some(i) => Some(i.parse().map_err(|_| anyhow!("bad hop-interval {i:?}"))?),
                None => None,
            };
            ProxyDef::Hysteria2 { server, port, password: need(v, "password")?, sni, skip_cert_verify: skip, obfs, ports, hop_interval }
        }
        other => bail!("{other} not supported"),
    };
    Ok((name, def))
}

/// Named nodes, in file order.
pub type Nodes = Vec<(String, ProxyDef)>;

/// Parses the `proxies:` list; returns nodes and per-node skip reasons.
#[cfg(test)]
pub fn parse(text: &str) -> Result<(Nodes, Vec<String>)> {
    let (nodes, skipped, _) = parse_with_metadata(text)?;
    Ok((nodes, skipped))
}

pub fn parse_with_metadata(text: &str) -> Result<(Nodes, Vec<String>, Vec<String>)> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| anyhow!("Clash YAML: {e}"))?;
    let list = doc.get("proxies").and_then(Value::as_sequence).ok_or_else(|| anyhow!("Clash YAML has no proxies list"))?;
    let (mut nodes, mut skipped, mut notices) = (Vec::new(), Vec::new(), Vec::new());
    for item in list {
        if let (Some(name), Some(server), Some(port)) = (s(item, "name"), s(item, "server"), s(item, "port").and_then(|p| p.parse().ok())) {
            if crate::subscription::is_metadata(&name, &server, port) {
                notices.push(name);
                continue;
            }
        }
        match proxy(item) {
            Ok(n) => nodes.push(n),
            Err(e) => skipped.push(format!("{e:#}")),
        }
    }
    Ok((nodes, skipped, notices))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_parses_and_roundtrips(yaml: &str, expected: ProxyDef) {
        let (nodes, skipped) = parse(yaml).unwrap();
        assert!(skipped.is_empty(), "{yaml}: {skipped:?}");
        assert_eq!(nodes.len(), 1, "{yaml}");
        let (name, actual) = &nodes[0];
        assert_eq!(name, "Test");
        // ProxyDef/Layer lack PartialEq; Debug includes all their fields.
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"), "{yaml}");
        let line = actual.to_line(name);
        let (back_name, back) = crate::config::parse_proxy(&line).unwrap();
        assert_eq!(&back_name, name);
        assert_eq!(format!("{back:?}"), format!("{expected:?}"), "{line}");
    }

    #[test]
    fn anytls_yaml_roundtrip() {
        for port in ["443", "'443'"] {
            assert_parses_and_roundtrips(&format!("proxies:\n- {{name: Test, type: anytls, server: h, port: {port}, password: secret, sni: tls.example, skip-cert-verify: true, udp: false, tfo: true, alpn: [h2, http/1.1], client-fingerprint: chrome}}"), ProxyDef::AnyTls {
                server: "h".into(), port: 443, password: "secret".into(), sni: Some("tls.example".into()),
                skip_cert_verify: true, tfo: true, udp: false, alpn: vec!["h2".into(), "http/1.1".into()],
                client_fingerprint: Some("chrome".into()),
            });
        }
        assert_parses_and_roundtrips("proxies:\n- {name: Test, type: anytls, server: h, port: 443, password: secret}", ProxyDef::AnyTls {
            server: "h".into(), port: 443, password: "secret".into(), sni: None,
            skip_cert_verify: false, tfo: false, udp: true, alpn: vec![],
            client_fingerprint: None,
        });
    }

    #[test]
    fn every_stream_proxy_and_transport() {
        let mut transports = vec![
            (String::new(), None),
            ("network: tcp".into(), None),
            ("network: ws".into(), Some(Layer::Ws(WsOpts { path: "/".into(), host: None, headers: vec![] }))),
            (
                "network: ws, ws-opts: {path: /socket, headers: {host: cdn.example}}".into(),
                Some(Layer::Ws(WsOpts { path: "/socket".into(), host: Some("cdn.example".into()), headers: vec![] })),
            ),
            ("network: grpc".into(), Some(Layer::Grpc { service: String::new() })),
            ("network: grpc, grpc-opts: {grpc-service-name: tunnel}".into(), Some(Layer::Grpc { service: "tunnel".into() })),
            ("network: xhttp".into(), Some(Layer::Xhttp(XhttpOpts::default()))),
        ];
        for mode in [XhttpMode::Auto, XhttpMode::PacketUp, XhttpMode::StreamUp, XhttpMode::StreamOne] {
            transports.push((
                format!("network: xhttp, xhttp-opts: {{path: /upload, host: cdn.example, mode: {}, x-padding-bytes: 12-24}}", mode.as_str()),
                Some(Layer::Xhttp(XhttpOpts { path: "/upload".into(), host: Some("cdn.example".into()), mode, padding: (12, 24) })),
            ));
        }
        for (transport, layer) in transports {
            for tls in [false, true] {
                let common = format!("name: Test, server: proxy.example, port: '443', tls: {tls}, servername: tls.example, skip-cert-verify: '1'");
                for (kind, credentials, expected) in [
                    ("vmess", "uuid: test-uuid, alterId: '0', cipher: chacha20-poly1305", ProxyDef::Vmess {
                        server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(), method: "chacha20-poly1305".into(),
                        tls, sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), alter_id: 0,
                    }),
                    ("vless", "uuid: test-uuid", ProxyDef::Vless {
                        server: "proxy.example".into(), port: 443, uuid: "test-uuid".into(), tls,
                        sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(), reality: None, flow: None,
                    }),
                    ("trojan", "password: secret", ProxyDef::Trojan {
                        server: "proxy.example".into(), port: 443, password: "secret".into(),
                        sni: Some("tls.example".into()), skip_cert_verify: true, layer: layer.clone(),
                    }),
                ] {
                    let suffix = if transport.is_empty() { String::new() } else { format!(", {transport}") };
                    assert_parses_and_roundtrips(&format!("proxies:\n  - {{{common}, type: {kind}, {credentials}{suffix}}}"), expected);
                }
            }
        }
    }

    #[test]
    fn shadowsocks_and_hysteria2_roundtrip() {
        assert_parses_and_roundtrips(
            "proxies:\n  - {name: Test, type: ss, server: '::1', port: 8388, cipher: aes-256-gcm, password: 'p@ss:word=1'}",
            ProxyDef::Shadowsocks { server: "::1".into(), port: 8388, method: "aes-256-gcm".into(), password: "p@ss:word=1".into(), plugin: None },
        );
        for (opts, obfs, ports, hop_interval) in [
            ("", None, None, None),
            (", obfs: none", None, None, None),
            (", obfs: salamander, obfs-password: mask, ports: '443,5000-5002', hop-interval: '15'", Some("mask".into()), Some("443,5000-5002".into()), Some(15)),
        ] {
            assert_parses_and_roundtrips(
                &format!("proxies:\n  - {{name: Test, type: hysteria2, server: h.example, port: 8443, password: secret, sni: tls.example, skip-cert-verify: true{opts}}}"),
                ProxyDef::Hysteria2 {
                    server: "h.example".into(), port: 8443, password: "secret".into(), sni: Some("tls.example".into()),
                    skip_cert_verify: true, obfs, ports, hop_interval,
                },
            );
        }
    }

    #[test]
    fn vmess_defaults_and_cipher_aliases() {
        for cipher in ["", ", cipher: none", ", cipher: zero", ", cipher: auto"] {
            assert_parses_and_roundtrips(
                &format!("proxies:\n  - {{name: Test, type: vmess, server: h, port: 80, uuid: u{cipher}}}"),
                ProxyDef::Vmess {
                    server: "h".into(), port: 80, uuid: "u".into(), method: "auto".into(),
                    tls: false, sni: None, skip_cert_verify: false, layer: None, alter_id: 0,
                },
            );
        }
    }

    #[test]
    fn reality_and_both_vision_flows() {
        let public_key = "9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4";
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            for short_id in ["", ", short-id: abcd"] {
                assert_parses_and_roundtrips(
                    &format!("proxies:\n  - {{name: Test, type: vless, server: r.example, port: 443, uuid: u, sni: www.example.com, flow: {flow}, reality-opts: {{public-key: {public_key}{short_id}}}}}"),
                    ProxyDef::Vless {
                        server: "r.example".into(), port: 443, uuid: "u".into(), tls: false,
                        sni: Some("www.example.com".into()), skip_cert_verify: false, layer: None,
                        reality: Some(crate::config::RealityDef { public_key: public_key.into(), short_id: if short_id.is_empty() { "" } else { "abcd" }.into() }),
                        flow: Some(flow.into()),
                    },
                );
            }
        }
    }

    #[test]
    fn bad_nodes_are_skipped_without_losing_good_nodes() {
        for (bad, reason) in [
            ("type: ss, cipher: aes-128-gcm", "missing password"),
            ("type: vmess", "missing uuid"),
            ("type: vless", "missing uuid"),
            ("type: trojan", "missing password"),
            ("type: hysteria2", "missing password"),
            ("type: socks5", "not supported"),
            ("type: ss, cipher: aes-128-gcm, password: p, plugin: kcptun", "ss plugin \"kcptun\" not supported"),
            ("type: vmess, alterId: 1", "missing uuid"),
            ("type: trojan, password: p, network: kcp", "transport"),
            ("type: trojan, password: p, network: xhttp, xhttp-opts: {mode: invalid}", "unknown xhttp mode"),
            ("type: trojan, password: p, network: xhttp, xhttp-opts: {x-padding-bytes: 20-10}", "bad xhttp padding range"),
            ("type: vless, uuid: u, flow: unsupported", "VLESS flow"),
            ("type: vless, uuid: u, reality-opts: {public-key: bad}", "bad REALITY public key"),
            ("type: hysteria2, password: p, obfs: salamander", "missing obfs-password"),
            ("type: hysteria2, password: p, obfs: unknown", "hysteria2 obfs"),
            ("type: hysteria2, password: p, ports: 5-3", "bad port range"),
            ("type: hysteria2, password: p, hop-interval: bad", "bad hop-interval"),
        ] {
            let yaml = format!("proxies:\n  - {{name: Bad, server: h, port: 443, {bad}}}\n  - {{name: Good, type: ss, server: h, port: 443, cipher: aes-128-gcm, password: p}}");
            let (nodes, skipped) = parse(&yaml).unwrap();
            assert_eq!(nodes.len(), 1, "{bad}: {nodes:?}");
            assert_eq!(nodes[0].0, "Good");
            assert_eq!(skipped.len(), 1, "{bad}: {skipped:?}");
            assert!(skipped[0].contains(reason), "{bad}: {skipped:?}");
        }
    }

    #[test]
    fn invalid_documents_and_required_fields() {
        for yaml in ["proxies: [", "proxies: {}", "rules: []"] {
            assert!(parse(yaml).is_err(), "{yaml}");
        }
        let (nodes, skipped) = parse("proxies: []").unwrap();
        assert!(nodes.is_empty() && skipped.is_empty());
        for (fields, reason) in [
            ("type: trojan, server: h, port: 443, password: p", "missing name"),
            ("name: Bad, type: trojan, port: 443, password: p", "missing server"),
            ("name: Bad, type: trojan, server: h, password: p", "missing port"),
            ("name: Bad, type: trojan, server: h, port: 65536, password: p", "bad port"),
        ] {
            let (nodes, skipped) = parse(&format!("proxies:\n  - {{{fields}}}")).unwrap();
            assert!(nodes.is_empty());
            assert_eq!(skipped, [reason]);
        }
    }

    #[test]
    fn detects_top_level_proxy_lists() {
        for yaml in ["proxies:\n", "# comment\nproxies: []\n", "proxies:   \n", "---\nproxies: [{name: Test}]\n"] {
            assert!(looks_like(yaml), "{yaml:?}");
        }
        for yaml in ["", "# proxies:\n", "proxy-groups: []\n", "nested:\n  proxies:\n", "proxies-other: []\n"] {
            assert!(!looks_like(yaml), "{yaml:?}");
        }
    }

    #[test]
    fn flags_accept_yaml_booleans_numbers_and_strings() {
        for (value, expected) in [("true", true), ("1", true), ("'true'", true), ("'1'", true), ("false", false), ("0", false), ("'false'", false), ("null", false)] {
            let yaml = format!("proxies:\n  - {{name: Test, type: vmess, server: h, port: 443, uuid: u, tls: {value}, skip-cert-verify: {value}}}");
            assert_parses_and_roundtrips(&yaml, ProxyDef::Vmess {
                server: "h".into(), port: 443, uuid: "u".into(), method: "auto".into(), tls: expected,
                sni: None, skip_cert_verify: expected, layer: None, alter_id: 0,
            });
        }
    }

    #[test]
    fn sni_alias_precedence_and_empty_optional_fields() {
        for (fields, sni) in [
            ("", None),
            (", sni: fallback.example", Some("fallback.example")),
            (", servername: preferred.example, sni: fallback.example", Some("preferred.example")),
            (", servername: '', sni: fallback.example", Some("fallback.example")),
            (", servername: '', sni: null, flow: ''", None),
        ] {
            assert_parses_and_roundtrips(
                &format!("proxies:\n  - {{name: Test, type: vless, server: h, port: 443, uuid: u{fields}}}"),
                ProxyDef::Vless {
                    server: "h".into(), port: 443, uuid: "u".into(), tls: false, sni: sni.map(String::from),
                    skip_cert_verify: false, layer: None, reality: None, flow: None,
                },
            );
        }
    }

    #[test]
    fn websocket_host_header_precedence_and_xhttp_scalar_padding() {
        for (opts, host) in [
            ("path: '', headers: {Host: preferred.example, host: fallback.example}", Some("preferred.example")),
            ("headers: {Host: '', host: fallback.example}", Some("fallback.example")),
            ("headers: {}", None),
        ] {
            assert_parses_and_roundtrips(
                &format!("proxies:\n  - {{name: Test, type: trojan, server: h, port: 443, password: p, network: ws, ws-opts: {{{opts}}}}}"),
                ProxyDef::Trojan {
                    server: "h".into(), port: 443, password: "p".into(), sni: None, skip_cert_verify: false,
                    layer: Some(Layer::Ws(WsOpts { path: "/".into(), host: host.map(String::from), headers: vec![] })),
                },
            );
        }
        for padding in ["16", "'16'", "'16-16'"] {
            assert_parses_and_roundtrips(
                &format!("proxies:\n  - {{name: Test, type: trojan, server: h, port: 443, password: p, network: xhttp, xhttp-opts: {{x-padding-bytes: {padding}}}}}"),
                ProxyDef::Trojan {
                    server: "h".into(), port: 443, password: "p".into(), sni: None, skip_cert_verify: false,
                    layer: Some(Layer::Xhttp(XhttpOpts { padding: (16, 16), ..Default::default() })),
                },
            );
        }
    }

    #[test]
    fn malformed_nodes_and_required_scalar_fields_are_skipped_in_order() {
        let yaml = r#"proxies:
  - null
  - []
  - {name: '', server: h, port: 443, type: trojan, password: p}
  - {name: NoType, server: h, port: 443, password: p}
  - {name: NoCipher, server: h, port: 443, type: ss, password: p}
  - {name: BadPassword, server: h, port: 443, type: trojan, password: []}
  - {name: BadPort, server: h, port: -1, type: trojan, password: p}
  - {name: First, server: h, port: 443, type: trojan, password: p}
  - {name: Second, server: h, port: 65535, type: trojan, password: p}
"#;
        let (nodes, skipped) = parse(yaml).unwrap();
        assert_eq!(nodes.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["First", "Second"]);
        assert_eq!(skipped, ["missing name", "missing name", "missing name", "missing type", "missing cipher", "missing password", "bad port"]);
    }

    #[test]
    fn reality_rejects_invalid_short_ids_and_missing_sni() {
        let key = "9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4";
        for (fields, reason) in [
            ("reality-opts: {}".into(), "missing public-key"),
            ("sni: www.example.com, reality-opts: {public-key: YQ}".into(), "must be 32 bytes"),
            (format!("reality-opts: {{public-key: {key}}}"), "needs sni"),
            (format!("sni: www.example.com, reality-opts: {{public-key: {key}, short-id: a}}"), "even length"),
            (format!("sni: www.example.com, reality-opts: {{public-key: {key}, short-id: zz}}"), "bad REALITY short id"),
        ] {
            let (nodes, skipped) = parse(&format!("proxies:\n  - {{name: Bad, type: vless, server: h, port: 443, uuid: u, {fields}}}")).unwrap();
            assert!(nodes.is_empty(), "{fields}");
            assert_eq!(skipped.len(), 1);
            assert!(skipped[0].contains(reason), "{fields}: {skipped:?}");
        }
    }

    const SAMPLE: &str = r#"
port: 7890
proxies:
  - {name: "HK 01", type: ss, server: hk.example.com, port: 8388, cipher: aes-256-gcm, password: "p@ss", udp: true}
  - name: JP WS
    type: vmess
    server: jp.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    servername: cdn.example.com
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
  - {name: US VLESS, type: vless, server: us.example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: us.example.com}
  - {name: SG Trojan, type: trojan, server: sg.example.com, port: 443, password: pw, sni: sg.example.com, skip-cert-verify: true}
  - {name: KR HY2, type: hysteria2, server: kr.example.com, port: 8443, password: pw, ports: "443,20000-20010", hop-interval: 15}
  - {name: Reality, type: vless, server: r.example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: www.microsoft.com, flow: xtls-rprx-vision, reality-opts: {public-key: 9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4, short-id: ab}}
  - {name: Splice, type: vless, server: s.example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, flow: xtls-rprx-splice}
  - {name: Plugin SS, type: ss, server: p.example.com, port: 443, cipher: aes-128-gcm, password: x, plugin: obfs, plugin-opts: {mode: tls, host: bing.com}}
  - {name: V2 SS, type: ss, server: p.example.com, port: 443, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: a.com, path: /ws, mux: false}}
  - {name: KCP SS, type: ss, server: p.example.com, port: 443, cipher: aes-128-gcm, password: x, plugin: kcptun}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK 01]}
"#;

    #[test]
    fn parses_supported_and_reports_the_rest() {
        assert!(looks_like(SAMPLE));
        let (nodes, skipped) = parse(SAMPLE).unwrap();
        let names: Vec<&str> = nodes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["HK 01", "JP WS", "US VLESS", "SG Trojan", "KR HY2", "Reality", "Plugin SS", "V2 SS"]);
        assert_eq!(skipped, ["VLESS flow \"xtls-rprx-splice\" not supported", "ss plugin \"kcptun\" not supported"]);
        use crate::obfs::SsPlugin;
        assert!(matches!(&nodes[6].1, ProxyDef::Shadowsocks { plugin: Some(SsPlugin::Obfs { tls: true, host, .. }), .. } if host == "bing.com"));
        assert!(matches!(&nodes[7].1, ProxyDef::Shadowsocks { plugin: Some(SsPlugin::V2ray { tls: true, path, mux: false, .. }), .. } if path == "/ws"));
        assert!(matches!(&nodes[5].1, ProxyDef::Vless { flow: Some(f), reality: Some(_), .. } if f == "xtls-rprx-vision"));
        assert!(matches!(&nodes[0].1, ProxyDef::Shadowsocks { password, .. } if password == "p@ss"));
        match &nodes[1].1 {
            ProxyDef::Vmess { tls: true, layer: Some(Layer::Ws(ws)), sni: Some(sni), .. } => {
                assert_eq!((ws.path.as_str(), ws.host.as_deref(), sni.as_str()), ("/ray", Some("cdn.example.com"), "cdn.example.com"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&nodes[3].1, ProxyDef::Trojan { skip_cert_verify: true, .. }));
        assert!(matches!(&nodes[4].1, ProxyDef::Hysteria2 { port: 8443, ports: Some(p), hop_interval: Some(15), .. } if p == "443,20000-20010"));
    }

    #[test]
    fn xhttp() {
        let yaml = "proxies:\n  - {name: XH, type: vless, server: x.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp, xhttp-opts: {path: /xh, host: cdn.example, mode: packet-up}}\n";
        let (nodes, skipped) = parse(yaml).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(matches!(&nodes[0].1, ProxyDef::Vless { layer: Some(Layer::Xhttp(x)), .. }
            if x.path == "/xh" && x.host.as_deref() == Some("cdn.example") && x.mode == XhttpMode::PacketUp));
    }

}
