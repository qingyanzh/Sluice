//! Clash / Mihomo YAML subscriptions: the `proxies:` list, mapped onto Sluice's proxy types.

use anyhow::{anyhow, bail, Result};
use serde_yaml::Value;

use crate::config::ProxyDef;
use crate::transport::{Layer, WsOpts};

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
/// (`grpc-opts: {grpc-service-name}`).
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
            Value::Bool(false) => None,
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
        "trojan" => ProxyDef::Trojan { server, port, password: need(v, "password")?, sni, skip_cert_verify: skip, layer: transport(v)? },
        "hysteria2" => {
            let obfs = match s(v, "obfs").as_deref() {
                None | Some("none") => None,
                Some("salamander") => Some(need(v, "obfs-password")?),
                Some(other) => bail!("hysteria2 obfs {other:?} not supported"),
            };
            if s(v, "ports").is_some() {
                bail!("hysteria2 port hopping not supported yet");
            }
            ProxyDef::Hysteria2 { server, port, password: need(v, "password")?, sni, skip_cert_verify: skip, obfs }
        }
        other => bail!("{other} not supported"),
    };
    Ok((name, def))
}

/// Named nodes, in file order.
pub type Nodes = Vec<(String, ProxyDef)>;

/// Parses the `proxies:` list; returns nodes and per-node skip reasons.
pub fn parse(text: &str) -> Result<(Nodes, Vec<String>)> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| anyhow!("Clash YAML: {e}"))?;
    let list = doc.get("proxies").and_then(Value::as_sequence).ok_or_else(|| anyhow!("Clash YAML has no proxies list"))?;
    let (mut nodes, mut skipped) = (Vec::new(), Vec::new());
    for item in list {
        match proxy(item) {
            Ok(n) => nodes.push(n),
            Err(e) => skipped.push(format!("{e:#}")),
        }
    }
    Ok((nodes, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

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
  - {name: KR HY2, type: hysteria2, server: kr.example.com, port: 8443, password: pw}
  - {name: Reality, type: vless, server: r.example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: www.microsoft.com, flow: xtls-rprx-vision, reality-opts: {public-key: 9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4, short-id: ab}}
  - {name: Splice, type: vless, server: s.example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, flow: xtls-rprx-splice}
  - {name: Plugin SS, type: ss, server: p.example.com, port: 1, cipher: aes-128-gcm, password: x, plugin: obfs, plugin-opts: {mode: tls, host: bing.com}}
  - {name: V2 SS, type: ss, server: p.example.com, port: 1, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: a.com, path: /ws, mux: false}}
  - {name: KCP SS, type: ss, server: p.example.com, port: 1, cipher: aes-128-gcm, password: x, plugin: kcptun}
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
        assert!(matches!(&nodes[7].1, ProxyDef::Shadowsocks { plugin: Some(SsPlugin::V2ray { tls: true, path, .. }), .. } if path == "/ws"));
        assert!(matches!(&nodes[5].1, ProxyDef::Vless { flow: Some(f), reality: Some(_), .. } if f == "xtls-rprx-vision"));
        assert!(matches!(&nodes[0].1, ProxyDef::Shadowsocks { password, .. } if password == "p@ss"));
        match &nodes[1].1 {
            ProxyDef::Vmess { tls: true, layer: Some(Layer::Ws(ws)), sni: Some(sni), .. } => {
                assert_eq!((ws.path.as_str(), ws.host.as_deref(), sni.as_str()), ("/ray", Some("cdn.example.com"), "cdn.example.com"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&nodes[3].1, ProxyDef::Trojan { skip_cert_verify: true, .. }));
        assert!(matches!(&nodes[4].1, ProxyDef::Hysteria2 { port: 8443, .. }));
    }
}
