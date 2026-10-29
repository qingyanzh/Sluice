use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Config, GroupDef, GroupKind, ProxyDef};
use crate::rule::{Matcher, Rule};
use crate::ss::SsServer;
use crate::transport::Transport;
use crate::trojan::TrojanServer;
use crate::hysteria2::Hy2Server;
use crate::vless::VlessServer;
use crate::vmess::VmessServer;
use crate::util::{connect_tcp, BoxStream, Host, Target};

pub enum Outbound {
    Direct,
    Reject,
    Shadowsocks(SsServer),
    Trojan(TrojanServer),
    Vless(VlessServer),
    Vmess(VmessServer),
    Hysteria2(Hy2Server),
}

pub struct Router {
    rules: Vec<Rule>,
    outbounds: HashMap<String, Outbound>,
    groups: Vec<GroupDef>,
    selected: RwLock<HashMap<String, String>>,
    /// Last health-check result per option name: `Some(ms)` healthy, `None` failed.
    latency: RwLock<HashMap<String, Option<u64>>>,
    geoip: Option<maxminddb::Reader<Vec<u8>>>,
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OptionStatus {
    pub name: String,
    /// Not yet tested: `None`; tested: `Some(latency or failure)`.
    pub latency: Option<Option<u64>>,
}

pub struct GroupStatus {
    pub name: String,
    pub kind: &'static str,
    pub selected: String,
    pub options: Vec<OptionStatus>,
}

fn kind_name(k: &GroupKind) -> &'static str {
    match k {
        GroupKind::Select => "select",
        GroupKind::UrlTest { .. } => "url-test",
        GroupKind::Fallback => "fallback",
        GroupKind::LoadBalance => "load-balance",
    }
}

/// Splits an `http://host[:port]/path` test URL.
fn parse_test_url(url: &str) -> Result<(Target, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow!("test url must be http:// ({url})"))?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    Ok((Target::parse_authority(authority, 80)?, path.to_string()))
}

/// Result of matching a target: which rule hit, its policy, and the concrete outbound.
pub struct Decision {
    pub rule: String,
    pub policy: String,
    pub outbound: String,
}

impl Router {
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut outbounds = HashMap::from([("DIRECT".to_string(), Outbound::Direct), ("REJECT".to_string(), Outbound::Reject)]);
        for (name, def) in &cfg.proxies {
            let ob = match def.clone() {
                ProxyDef::Shadowsocks { server, port, method, password } => {
                    Outbound::Shadowsocks(SsServer::new(server, port, &method, &password)?)
                }
                ProxyDef::Trojan { server, port, password, sni, skip_cert_verify, ws } => {
                    Outbound::Trojan(TrojanServer::new(Transport::new(server, port, true, sni, skip_cert_verify, ws)?, &password))
                }
                ProxyDef::Vless { server, port, uuid, tls, sni, skip_cert_verify, ws } => {
                    Outbound::Vless(VlessServer::new(Transport::new(server, port, tls, sni, skip_cert_verify, ws)?, &uuid)?)
                }
                ProxyDef::Hysteria2 { server, port, password, sni, skip_cert_verify } => {
                    Outbound::Hysteria2(Hy2Server::new(server, port, password, sni, skip_cert_verify)?)
                }
                ProxyDef::Vmess { server, port, uuid, method, tls, sni, skip_cert_verify, ws } => {
                    Outbound::Vmess(VmessServer::new(Transport::new(server, port, tls, sni, skip_cert_verify, ws)?, &uuid, &method)?)
                }
            };
            if outbounds.insert(name.clone(), ob).is_some() {
                bail!("duplicate proxy name {name:?}");
            }
        }

        let mut selected = HashMap::new();
        for g in &cfg.groups {
            if outbounds.contains_key(&g.name) || selected.contains_key(&g.name) {
                bail!("group name {:?} is already used", g.name);
            }
            if g.kind != GroupKind::Select {
                parse_test_url(&g.url).with_context(|| format!("group {:?}", g.name))?;
            }
            selected.insert(g.name.clone(), g.options[0].clone());
        }
        let exists = |p: &str| outbounds.contains_key(p) || selected.contains_key(p);
        for g in &cfg.groups {
            if let Some(bad) = g.options.iter().find(|o| !exists(o)) {
                bail!("group {:?} refers to unknown policy {bad:?}", g.name);
            }
        }
        for rule in &cfg.rules {
            if !exists(&rule.policy) {
                bail!("rule `{rule}` refers to unknown policy {:?}", rule.policy);
            }
        }
        if !matches!(cfg.rules.last().map(|r| &r.matcher), Some(Matcher::Final)) {
            bail!("the last rule must be FINAL");
        }

        let geoip = match &cfg.general.geoip_db {
            Some(path) => Some(maxminddb::Reader::open_readfile(path).with_context(|| format!("open geoip-db {path}"))?),
            None => None,
        };
        if geoip.is_none() && cfg.rules.iter().any(|r| matches!(r.matcher, Matcher::GeoIp { .. })) {
            log::warn!("GEOIP rules present but no geoip-db configured; they will never match");
        }

        let router = Router {
            rules: cfg.rules.clone(),
            outbounds,
            groups: cfg.groups.clone(),
            selected: RwLock::new(selected),
            latency: RwLock::new(HashMap::new()),
            geoip,
        };
        // Catches group cycles at load time rather than on first request.
        for g in &router.groups {
            router.resolve(&g.name)?;
        }
        Ok(router)
    }

    fn country(&self, ip: IpAddr) -> Option<String> {
        let country: maxminddb::geoip2::Country = self.geoip.as_ref()?.lookup(ip).ok()?;
        country.country?.iso_code.map(str::to_string)
    }

    async fn ip_of(target: &Target, no_resolve: bool, cache: &mut Option<Option<IpAddr>>) -> Option<IpAddr> {
        match &target.host {
            Host::Ip(ip) => Some(*ip),
            Host::Domain(_) if no_resolve => None,
            Host::Domain(d) => {
                if cache.is_none() {
                    let ip = crate::util::resolve(d, target.port).await.ok().and_then(|a| a.first().map(|a| a.ip()));
                    *cache = Some(ip);
                }
                cache.flatten()
            }
        }
    }

    async fn match_rule(&self, target: &Target) -> &Rule {
        let mut resolved = None;
        for rule in &self.rules {
            let hit = match &rule.matcher {
                Matcher::Final => true,
                Matcher::Domain(_) | Matcher::DomainSuffix(_) | Matcher::DomainKeyword(_) => {
                    matches!(&target.host, Host::Domain(d) if rule.match_domain(d))
                }
                Matcher::IpCidr { cidr, no_resolve, .. } => {
                    Self::ip_of(target, *no_resolve, &mut resolved).await.is_some_and(|ip| cidr.contains(ip))
                }
                Matcher::GeoIp { country, no_resolve } => match Self::ip_of(target, *no_resolve, &mut resolved).await {
                    Some(ip) => self.country(ip).as_deref() == Some(country.as_str()),
                    None => false,
                },
                Matcher::RuleSet { set, no_resolve } => {
                    let (domain_hit, has_ip) = {
                        let data = set.data.read().unwrap();
                        (matches!(&target.host, Host::Domain(d) if data.match_domain(d)), data.has_ip_rules())
                    };
                    domain_hit
                        || (has_ip
                            && Self::ip_of(target, *no_resolve, &mut resolved)
                                .await
                                .is_some_and(|ip| set.data.read().unwrap().match_ip(ip)))
                }
            };
            if hit {
                return rule;
            }
        }
        self.rules.last().expect("FINAL rule validated")
    }

    fn group(&self, name: &str) -> Option<&GroupDef> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Follows group selections down to a concrete outbound name.
    pub fn resolve(&self, policy: &str) -> Result<String> {
        let selected = self.selected.read().unwrap();
        let latency = self.latency.read().unwrap();
        let mut cur = policy.to_string();
        for _ in 0..16 {
            if self.outbounds.contains_key(&cur) {
                return Ok(cur);
            }
            let g = self.group(&cur).ok_or_else(|| anyhow!("unknown policy {cur:?}"))?;
            cur = if g.kind == GroupKind::LoadBalance {
                // Untested options count as healthy; if all failed, try any.
                let healthy: Vec<&String> =
                    g.options.iter().filter(|o| latency.get(*o).is_none_or(|l| l.is_some())).collect();
                let pool: Vec<&String> = if healthy.is_empty() { g.options.iter().collect() } else { healthy };
                pool[rand::thread_rng().gen_range(0..pool.len())].clone()
            } else {
                selected[&cur].clone()
            };
        }
        bail!("policy group loop involving {policy:?}")
    }

    pub async fn decide(&self, target: &Target) -> Result<Decision> {
        let rule = self.match_rule(target).await;
        Ok(Decision { rule: rule.to_string(), policy: rule.policy.clone(), outbound: self.resolve(&rule.policy)? })
    }

    /// Connects to `target` through whatever the rules pick; `None` means rejected.
    pub async fn dispatch(&self, target: &Target) -> Result<Option<BoxStream>> {
        let d = self.decide(target).await?;
        info!("{target} -> {} [{}] via {}", d.policy, d.rule, d.outbound);
        self.open(&d.outbound, target).await
    }

    /// UDP counterpart of [`dispatch`]; `None` means rejected.
    pub async fn dispatch_udp(&self, target: &Target) -> Result<Option<crate::udp::UdpPipe>> {
        let d = self.decide(target).await?;
        info!("UDP {target} -> {} [{}] via {}", d.policy, d.rule, d.outbound);
        let pipe = match &self.outbounds[&d.outbound] {
            Outbound::Reject => return Ok(None),
            Outbound::Direct => crate::udp::direct(target).await?,
            Outbound::Shadowsocks(s) => s.open_udp(target).await?,
            Outbound::Trojan(t) => t.open_udp(target).await?,
            Outbound::Vless(v) => v.open_udp(target).await?,
            Outbound::Vmess(v) => v.open_udp(target).await?,
            Outbound::Hysteria2(h) => h.open_udp(target).await?,
        };
        Ok(Some(pipe))
    }

    async fn open(&self, outbound: &str, target: &Target) -> Result<Option<BoxStream>> {
        let stream: BoxStream = match &self.outbounds[outbound] {
            Outbound::Reject => return Ok(None),
            Outbound::Direct => Box::new(connect_tcp(&target.host_str(), target.port).await?),
            Outbound::Shadowsocks(s) => s.connect(target).await?,
            Outbound::Trojan(t) => t.connect(target).await?,
            Outbound::Vless(v) => v.connect(target).await?,
            Outbound::Vmess(v) => v.connect(target).await?,
            Outbound::Hysteria2(h) => h.connect(target).await?,
        };
        Ok(Some(stream))
    }

    pub fn rule_sets(&self) -> Vec<Arc<crate::ruleset::RuleSet>> {
        self.rules
            .iter()
            .filter_map(|r| match &r.matcher {
                Matcher::RuleSet { set, .. } => Some(set.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn groups(&self) -> Vec<GroupStatus> {
        let selected = self.selected.read().unwrap();
        let latency = self.latency.read().unwrap();
        self.groups
            .iter()
            .map(|g| GroupStatus {
                name: g.name.clone(),
                kind: kind_name(&g.kind),
                // Load-balance picks per connection, so there is no single selection.
                selected: if g.kind == GroupKind::LoadBalance { "*".to_string() } else { selected[&g.name].clone() },
                options: g.options.iter().map(|o| OptionStatus { name: o.clone(), latency: latency.get(o).copied() }).collect(),
            })
            .collect()
    }

    pub fn select(&self, group: &str, option: &str) -> Result<()> {
        let g = self.group(group).ok_or_else(|| anyhow!("no such group {group:?}"))?;
        if g.kind != GroupKind::Select {
            bail!("{group:?} is a {} group and picks its option automatically", kind_name(&g.kind));
        }
        if !g.options.iter().any(|o| o == option) {
            bail!("{option:?} is not an option of group {group:?}");
        }
        let previous = self.selected.write().unwrap().insert(group.to_string(), option.to_string());
        if let Err(e) = self.resolve(group) {
            self.selected.write().unwrap().insert(group.to_string(), previous.unwrap());
            return Err(e);
        }
        info!("group {group} -> {option}");
        Ok(())
    }

    /// Time until the test URL's status line arrives through `option`, or `None` on failure.
    async fn probe(&self, option: &str, url: &str) -> Option<u64> {
        let start = Instant::now();
        let attempt = async {
            let (target, path) = parse_test_url(url)?;
            let outbound = self.resolve(option)?;
            let mut s = self.open(&outbound, &target).await?.ok_or_else(|| anyhow!("rejected"))?;
            let req = format!("HEAD {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target.host_str());
            s.write_all(req.as_bytes()).await?;
            let mut head = [0u8; 9];
            s.read_exact(&mut head).await?;
            if !head.starts_with(b"HTTP/1.") {
                bail!("not an HTTP response");
            }
            Ok(())
        };
        match tokio::time::timeout(PROBE_TIMEOUT, attempt).await {
            Ok(Ok(())) => Some(start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                debug!("health check {option}: {e:#}");
                None
            }
            Err(_) => None,
        }
    }

    /// Probes every option of an automatic group and updates its selection.
    pub async fn check_group(self: &Arc<Self>, name: &str) {
        let Some(g) = self.group(name).cloned() else { return };
        let mut set = tokio::task::JoinSet::new();
        for (i, o) in g.options.iter().enumerate() {
            let (me, o, url) = (self.clone(), o.clone(), g.url.clone());
            set.spawn(async move { (i, me.probe(&o, &url).await) });
        }
        let mut results = vec![None; g.options.len()];
        while let Some(Ok((i, r))) = set.join_next().await {
            results[i] = r;
        }
        {
            let mut latency = self.latency.write().unwrap();
            for (o, r) in g.options.iter().zip(&results) {
                latency.insert(o.clone(), *r);
            }
        }
        let current = self.selected.read().unwrap()[name].clone();
        let pick = match g.kind {
            GroupKind::UrlTest { tolerance_ms } => {
                let best = g.options.iter().zip(&results).filter_map(|(o, r)| r.map(|ms| (o, ms))).min_by_key(|(_, ms)| *ms);
                let cur_ms = g.options.iter().position(|o| *o == current).and_then(|i| results[i]);
                match (best, cur_ms) {
                    (Some((o, ms)), Some(cur)) if ms + tolerance_ms < cur => Some(o.clone()),
                    (Some((o, _)), None) => Some(o.clone()),
                    _ => None,
                }
            }
            GroupKind::Fallback => g.options.iter().zip(&results).find(|(_, r)| r.is_some()).map(|(o, _)| o.clone()),
            _ => None,
        };
        let summary: Vec<String> = g
            .options
            .iter()
            .zip(&results)
            .map(|(o, r)| format!("{o}={}", r.map_or("fail".to_string(), |ms| format!("{ms}ms"))))
            .collect();
        info!("health check {name}: {}", summary.join(", "));
        if let Some(p) = pick.filter(|p| *p != current) {
            info!("group {name}: {current} -> {p}");
            self.selected.write().unwrap().insert(name.to_string(), p);
        }
    }

    /// Runs health checks for every automatic group, forever, each on its own interval.
    pub fn spawn_health_checks(self: &Arc<Self>) {
        for g in self.groups.iter().filter(|g| g.kind != GroupKind::Select) {
            let (me, name, every) = (self.clone(), g.name.clone(), Duration::from_secs(g.interval_secs));
            tokio::spawn(async move {
                loop {
                    me.check_group(&name).await;
                    tokio::time::sleep(every).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(text: &str) -> Router {
        Router::new(&Config::parse(text).unwrap()).unwrap()
    }

    const CONF: &str = "
[Proxy]
A = ss, 127.0.0.1, 1, encrypt-method=aes-128-gcm, password=x
[Proxy Group]
Proxy = select, A, DIRECT
Outer = select, Proxy, REJECT
[Rule]
DOMAIN,exact.com,REJECT
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,tracker,REJECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,Outer,no-resolve
FINAL,DIRECT
";

    async fn decide(r: &Router, host: &str) -> (String, String) {
        let d = r.decide(&Target::parse_authority(host, 443).unwrap()).await.unwrap();
        (d.rule, d.outbound)
    }

    #[tokio::test]
    async fn routing() {
        let r = router(CONF);
        assert_eq!(decide(&r, "exact.com").await, ("DOMAIN,exact.com".into(), "REJECT".into()));
        assert_eq!(decide(&r, "www.google.com").await.1, "A");
        assert_eq!(decide(&r, "x.tracker.io").await.1, "REJECT");
        assert_eq!(decide(&r, "10.1.2.3").await.1, "DIRECT");
        assert_eq!(decide(&r, "172.20.0.1:80").await, ("IP-CIDR,172.16.0.0/12".into(), "A".into()));
        assert_eq!(decide(&r, "other.org").await.0, "FINAL");
    }

    #[tokio::test]
    async fn selection() {
        let r = router(CONF);
        r.select("Proxy", "DIRECT").unwrap();
        assert_eq!(decide(&r, "google.com").await.1, "DIRECT");
        assert!(r.select("Proxy", "REJECT").is_err());
        assert!(r.select("Nope", "A").is_err());
    }

    #[test]
    fn validation() {
        let bad = |t: &str| Router::new(&Config::parse(t).unwrap()).is_err();
        assert!(bad("[Rule]\nDOMAIN,a.com,DIRECT\n"));
        assert!(bad("[Rule]\nDOMAIN,a.com,Missing\nFINAL,DIRECT\n"));
        assert!(bad("[Proxy Group]\nG = select, Ghost\n[Rule]\nFINAL,G\n"));
        assert!(bad("[Proxy Group]\nX = select, Y\nY = select, X\n[Rule]\nFINAL,X\n"));
    }
}
