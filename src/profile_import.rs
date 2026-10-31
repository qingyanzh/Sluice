//! Import supported source topology and rules as an independent local profile.
use std::collections::HashSet;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use crate::config::Config;
use crate::rule::Rule;
use crate::subscription::{group_reference, node_reference};

fn decoded(text: &str) -> String {
    let text = text.trim_start_matches('\u{feff}');
    if text.contains('[') || text.contains("proxies:") || text.contains(',') || text.contains("://") { return text.into(); }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(&compact).or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(compact.trim_end_matches('=')))
        .ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| text.into())
}

fn section(text: &str, wanted: &str) -> Vec<String> {
    let mut current = "";
    text.lines().filter_map(|raw| {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') { current = line; return None; }
        (current == wanted && !line.is_empty() && !line.starts_with(['#', ';']) && !line.starts_with("//")).then(|| line.into())
    }).collect()
}

fn absolute_reference(source: &str, reference: &str) -> Result<String> {
    if url::Url::parse(reference).is_ok() || std::path::Path::new(reference).is_absolute() { return Ok(reference.into()); }
    let origin = url::Url::parse(source).or_else(|_| url::Url::from_file_path(source).map_err(|_| url::ParseError::RelativeUrlWithoutBase))?;
    Ok(origin.join(reference)?.to_string())
}

pub fn convert(body: &str, source: &str, local: &str) -> Result<String> {
    let body = decoded(body);
    if body.lines().any(|line| line.trim() == "[Subscription]") || section(&body, "[General]").iter().any(|l| l.split('=').next().is_some_and(|k| k.trim() == "api-listen")) {
        Config::parse(&body)?;
        return Ok(body);
    }
    if source.contains(['"', '\r', '\n']) { bail!("source address contains unsupported quotes or newlines"); }
    let source_name = "导入来源";
    let (nodes, _, _) = crate::subscription::parse_with_metadata(&body, source);
    let node_names: HashSet<_> = nodes.iter().map(|(name, _)| name.as_str()).collect();
    let mut topology = Config { subscription_nodes: nodes.iter().map(|(name, _)| crate::subscription::SubscriptionNode {
        id: node_reference(source_name, name), name: name.clone(), source: source_name.into(),
        kind: String::new(), server: String::new(), port: 0, aliases: Vec::new(),
    }).collect(), ..Config::default() };
    crate::subscription::import_groups(&mut topology, source_name, &body)?;
    let group_ids: HashSet<_> = topology.groups.iter().map(|g| g.name.clone()).collect();
    if nodes.is_empty() && group_ids.is_empty() { bail!("source has no supported nodes or policy groups"); }
    let yaml: Option<serde_yaml::Value> = if crate::clash::looks_like(&body) { Some(serde_yaml::from_str(&body)?) } else { None };
    let rules: Vec<String> = if let Some(yaml) = &yaml {
        yaml.get("rules").and_then(serde_yaml::Value::as_sequence).map(|items| items.iter().map(|v| {
            v.as_str().map(String::from).ok_or_else(|| anyhow!("each imported rule must be text"))
        }).collect::<Result<Vec<_>>>()).transpose()?.unwrap_or_default()
    } else { section(&body, "[Rule]") };
    let mut converted = Vec::new();
    let mut has_final = false;
    for line in rules {
        let mut fields: Vec<String> = crate::rule::split_top(&line).into_iter().map(String::from).collect();
        if fields.first().is_some_and(|v| v.eq_ignore_ascii_case("MATCH")) { fields[0] = "FINAL".into(); }
        let parsed = Rule::parse(&fields.join(",")).with_context(|| format!("unsupported imported rule: {line}"))?;
        let index = if fields[0].eq_ignore_ascii_case("FINAL") { has_final = true; 1 } else { 2 };
        fields[index] = match parsed.policy.as_str() {
            "DIRECT" | "REJECT" => parsed.policy.clone(),
            name if group_ids.contains(&group_reference(source_name, name)) => group_reference(source_name, name),
            name if node_names.contains(name) => node_reference(source_name, name),
            name => bail!("rule refers to unavailable policy {name:?}"),
        };
        if matches!(fields[0].as_str(), "RULE-SET" | "DOMAIN-SET") {
            if let Some(provider) = yaml.as_ref().and_then(|v| v.get("rule-providers")).and_then(|v| v.get(&fields[1])) {
                let behavior = provider.get("behavior").and_then(serde_yaml::Value::as_str).unwrap_or("classical");
                match behavior { "domain" => fields[0] = "DOMAIN-SET".into(), "classical" => {}, other => bail!("rule-provider behavior {other:?} is unsupported") }
                let reference = provider.get("url").or_else(|| provider.get("path")).and_then(serde_yaml::Value::as_str).ok_or_else(|| anyhow!("rule-provider needs url or path"))?;
                fields[1] = absolute_reference(source, reference)?;
            } else { fields[1] = absolute_reference(source, &fields[1])?; }
        }
        converted.push(fields.join(","));
    }
    let general = section(local, "[General]");
    let general = if general.is_empty() {
        "http-listen = 127.0.0.1:6252\nsocks5-listen = 127.0.0.1:6253\napi-listen = 127.0.0.1:6170".into()
    } else { general.join("\n") };
    let mut output = format!("# Imported profile: local device settings retained; upstream rules copied as a snapshot.\n[General]\n{general}\n\n[Subscription]\n{source_name} = policy-path=\"{source}\", import-groups=true\n");
    if !has_final {
        let member = topology.groups.first().map(|g| g.name.clone());
        let group = member.map_or_else(|| format!("默认出口 = select, use={source_name}"), |m| format!("默认出口 = select, {m}"));
        output.push_str(&format!("\n[Proxy Group]\n{group}\n"));
        converted.push("FINAL,默认出口".into());
    }
    output.push_str(&format!("\n[Rule]\n{}\n", converted.join("\n")));
    Config::parse(&output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: &str = "[General]\napi-listen = 127.0.0.1:6170\nenhanced-mode = false\n[Rule]\nFINAL,DIRECT\n";
    const SOURCE: &str = "proxies:\n  - {name: HK, type: trojan, server: hk.example, port: 443, password: fixture}\nproxy-groups:\n  - {name: Main, type: select, proxies: [HK, DIRECT]}\nrules:\n  - DOMAIN-SUFFIX,office.test,Main\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,Main\n";

    #[test]
    fn imports_source_rules_as_a_separate_profile_and_preserves_options_and_device_settings() {
        let imported = convert(SOURCE, "https://example.test/config", BASE).unwrap();
        let cfg = Config::parse(&imported).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.general.api_listen.as_deref(), Some("127.0.0.1:6170"));
        assert!(!cfg.general.enhanced_mode);
        assert_eq!(cfg.rules[0].policy, "@导入来源/group/Main");
        assert_eq!(cfg.rules[2].policy, "@导入来源/group/Main");
        assert!(imported.contains("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
        assert!(!imported.contains("FINAL,DIRECT"));
        assert!(BASE.contains("FINAL,DIRECT"));
    }

    #[test]
    fn native_profiles_keep_their_own_rules_and_settings() {
        assert_eq!(convert(BASE, "file:///tmp/original.conf", "").unwrap(), BASE);
        let invalid = SOURCE.replace("DOMAIN-SUFFIX,office.test,Main", "UNSUPPORTED,office.test,Main");
        assert!(convert(&invalid, "https://example.test/config", BASE).is_err());
        let missing = SOURCE.replace("MATCH,Main", "MATCH,Unknown");
        assert!(convert(&missing, "https://example.test/config", BASE).is_err());
    }

    #[test]
    fn creates_an_explicit_default_for_a_node_only_subscription() {
        let text = "HK = trojan, hk.example, 443, password=fixture\n";
        let imported = convert(text, "https://example.test/nodes", BASE).unwrap();
        let cfg = Config::parse(&imported).unwrap();
        assert_eq!(cfg.groups[0].sources, ["导入来源"]);
        assert_eq!(cfg.rules.last().unwrap().policy, "默认出口");
    }

    #[test]
    fn maps_domain_rule_providers_and_resolves_relative_sources() {
        let yaml = SOURCE.replace("  - MATCH,Main", "  - RULE-SET,Office,Main\n  - MATCH,Main\nrule-providers:\n  Office: {type: http, behavior: domain, url: ./office.list}");
        let imported = convert(&yaml, "https://example.test/profiles/config", BASE).unwrap();
        assert!(imported.contains("DOMAIN-SET,https://example.test/profiles/office.list,@导入来源/group/Main"));
    }
}
