use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use log::{info, warn};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Config, GroupDef, GroupKind, ProxyDef};
use crate::rule::{ConnInfo, Matcher, Rule};
use crate::ss::SsServer;
use crate::transport::Transport;
use crate::trojan::TrojanServer;
use crate::hysteria2::Hy2Server;
use crate::vless::VlessServer;
use crate::vmess::VmessServer;
use crate::util::{connect_tcp, BoxStream, Host, Target};

// Built once at startup and kept in a map; boxing the big variants would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum Outbound {
    Direct,
    Reject,
    Shadowsocks(SsServer),
    Trojan(TrojanServer),
    AnyTls(crate::anytls::AnyTlsServer),
    Vless(VlessServer),
    Vmess(VmessServer),
    Hysteria2(Hy2Server),
}

pub struct Router {
    rules: Vec<Rule>,
    outbounds: HashMap<String, Outbound>,
    groups: Vec<GroupDef>,
    selected: RwLock<HashMap<String, String>>,
    /// Last health-check result and full error chain per option name.
    latency: RwLock<HashMap<String, HealthCheck>>,
    geoip: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    mode: RwLock<Mode>,
    mitm: Option<Arc<crate::mitm::Mitm>>,
    rewrites: Arc<crate::rewrite::Rewrites>,
}

/// Outbound mode: `Rule` follows the rules, `Direct` sends everything direct,
/// `Global` sends everything to the FINAL rule's policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Rule,
    Direct,
    Global,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Rule => "rule",
            Mode::Direct => "direct",
            Mode::Global => "global",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "rule" => Some(Mode::Rule),
            "direct" => Some(Mode::Direct),
            "global" => Some(Mode::Global),
            _ => None,
        }
    }
}

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

fn short_health_error(error: &str) -> String {
    error.chars().map(|c| if c.is_control() { ' ' } else { c }).take(160).collect()
}

#[derive(Clone, Debug)]
pub struct HealthCheck {
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

impl HealthCheck {
    fn from_result(result: Result<u64>) -> Self {
        match result {
            Ok(ms) => Self { latency_ms: Some(ms), error: None },
            Err(e) => Self { latency_ms: None, error: Some(format!("{e:#}")) },
        }
    }
}

pub struct OptionStatus {
    pub name: String,
    /// Not yet tested: `None`; tested: `Some(latency or failure)`.
    pub latency: Option<Option<u64>>,
    pub error: Option<String>,
}

/// Result of [`Router::test_node`].
pub struct NodeTest {
    /// The concrete outbound the test went through.
    pub outbound: String,
    pub connect_ms: u64,
    pub latency_ms: u64,
    pub status: u16,
}

pub struct GroupStatus {
    pub name: String,
    pub kind: &'static str,
    pub selected: String,
    pub options: Vec<OptionStatus>,
    pub url: String,
    pub interval: u64,
    pub tolerance: Option<u64>,
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
    let (rest, port) = if let Some(rest) = url.strip_prefix("http://") { (rest, 80) }
        else if let Some(rest) = url.strip_prefix("https://") { (rest, 443) }
        else { bail!("test url must be http:// or https:// ({url})"); };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    Ok((Target::parse_authority(authority, port)?, path.to_string()))
}

/// Result of matching a target: which rule hit, its policy, and the concrete outbound.
pub struct Decision {
    pub rule: String,
    pub policy: String,
    pub outbound: String,
    /// The client's process, when the local socket owner can be identified.
    pub process: Option<String>,
    pub(crate) traffic: Arc<crate::conns::Traffic>,
}

impl Router {
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut outbounds = HashMap::from([("DIRECT".to_string(), Outbound::Direct), ("REJECT".to_string(), Outbound::Reject)]);
        for (name, def) in &cfg.proxies {
            let ob = match def.clone() {
                ProxyDef::Shadowsocks { server, port, method, password, plugin } => {
                    Outbound::Shadowsocks(SsServer::new(server, port, &method, &password, plugin)?)
                }
                ProxyDef::AnyTls { server, port, password, sni, skip_cert_verify, tfo, alpn, udp, client_fingerprint } => {
                    let transport = Transport::anytls(server, port, sni, skip_cert_verify, &alpn, tfo, client_fingerprint.as_deref())?;
                    Outbound::AnyTls(crate::anytls::AnyTlsServer::new(transport, &password, udp))
                }
                ProxyDef::Trojan { server, port, password, sni, skip_cert_verify, layer } => {
                    Outbound::Trojan(TrojanServer::new(Transport::new(server, port, true, sni, skip_cert_verify, layer)?, &password))
                }
                ProxyDef::Vless { server, port, uuid, tls, sni, skip_cert_verify, layer, reality, flow } => {
                    let reality = match reality {
                        Some(r) => Some(crate::reality::RealityOpts::parse(
                            &r.public_key,
                            &r.short_id,
                            sni.as_deref().ok_or_else(|| anyhow!("REALITY node {name:?} needs sni"))?,
                        )?),
                        None => None,
                    };
                    Outbound::Vless(VlessServer::new(
                        Transport::with_reality(server, port, tls, sni, skip_cert_verify, layer, reality)?,
                        &uuid,
                        flow.as_deref(),
                    )?)
                }
                ProxyDef::Hysteria2 { server, port, password, sni, skip_cert_verify, obfs, ports, hop_interval } => {
                    Outbound::Hysteria2(Hy2Server::new(server, port, password, sni, skip_cert_verify, obfs, ports, hop_interval)?)
                }
                ProxyDef::Vmess { server, port, uuid, method, tls, sni, skip_cert_verify, layer, alter_id } => {
                    let transport = Transport::new(server, port, tls, sni, skip_cert_verify, layer)?;
                    Outbound::Vmess(VmessServer::new(transport, &uuid, &method, alter_id)?)
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
            let Some(first) = g.options.first() else { bail!("group {:?} has no options", g.name) };
            selected.insert(g.name.clone(), first.clone());
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
            Some(path) if path == "builtin:cn" => Some(maxminddb::Reader::from_source(include_bytes!("../resources/geoip-cn.mmdb").to_vec())?),
            Some(path) => Some(maxminddb::Reader::open_readfile(path).with_context(|| format!("open geoip-db {path}"))?),
            None => None,
        };
        if geoip.is_none() && cfg.rules.iter().any(|r| matches!(r.matcher, Matcher::GeoIp { .. })) {
            log::warn!("GEOIP rules present but no geoip-db configured; they will never match");
        }

        let asn = match &cfg.general.asn_db {
            Some(path) => Some(maxminddb::Reader::open_readfile(path).with_context(|| format!("open asn-db {path}"))?),
            None => None,
        };
        if asn.is_none() && cfg.rules.iter().any(|r| matches!(r.matcher, Matcher::IpAsn { .. })) {
            log::warn!("IP-ASN rules present but no asn-db configured; they will never match");
        }

        let router = Router {
            rules: crate::geosite::configure_rules(&cfg.rules, cfg.general.geosite_db.as_deref()),
            outbounds,
            groups: cfg.groups.clone(),
            selected: RwLock::new(selected),
            latency: RwLock::new(HashMap::new()),
            mode: RwLock::new(Mode::Rule),
            geoip,
            asn,
            mitm: crate::mitm::Mitm::new(&cfg.mitm)?.map(Arc::new),
            rewrites: Arc::new(cfg.rewrites.clone()),
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

    fn asn_of(&self, ip: IpAddr) -> Option<u32> {
        let asn: maxminddb::geoip2::Asn = self.asn.as_ref()?.lookup(ip).ok()?;
        asn.autonomous_system_number
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

    async fn match_rule(&self, target: &Target, ctx: &ConnInfo) -> &Rule {
        let mut resolved = None;
        for rule in &self.rules {
            if self.eval(&rule.matcher, target, ctx, &mut resolved).await {
                return rule;
            }
        }
        self.rules.last().expect("FINAL rule validated")
    }

    /// Whether `m` matches; boxed because logical rules recurse.
    fn eval<'a>(
        &'a self,
        m: &'a Matcher,
        target: &'a Target,
        ctx: &'a ConnInfo,
        resolved: &'a mut Option<Option<IpAddr>>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match m {
                Matcher::Final => true,
                Matcher::Domain(_) | Matcher::DomainSuffix(_) | Matcher::DomainKeyword(_) => {
                    matches!(&target.host, Host::Domain(d) if m.match_domain(d))
                }
                Matcher::IpCidr { cidr, no_resolve, .. } => {
                    Self::ip_of(target, *no_resolve, resolved).await.is_some_and(|ip| cidr.contains(ip))
                }
                Matcher::GeoIp { country, no_resolve } => match Self::ip_of(target, *no_resolve, resolved).await {
                    Some(ip) => self.country(ip).as_deref() == Some(country.as_str()),
                    None => false,
                },
                Matcher::GeoSite { tag, set } => {
                    let data = set.data.read().unwrap();
                    data.geosite_loaded && matches!(&target.host, Host::Domain(d)
                        if data.match_domain(d) != tag.starts_with('!'))
                }
                Matcher::IpAsn { asn, no_resolve } => match Self::ip_of(target, *no_resolve, resolved).await {
                    Some(ip) => self.asn_of(ip) == Some(*asn),
                    None => false,
                },
                Matcher::DstPort { range, .. } => range.contains(target.port),
                Matcher::InPort { range, .. } => ctx.in_port.is_some_and(|p| range.contains(p)),
                Matcher::SrcIp { cidr, .. } => ctx.src.is_some_and(|s| cidr.contains(s.ip())),
                Matcher::Protocol(p) => p.covers(ctx.proto),
                Matcher::UrlRegex(re) => ctx.url.as_deref().is_some_and(|u| re.is_match(u)),
                Matcher::ProcessName(name) => ctx.process().await.is_some_and(|p| p.eq_ignore_ascii_case(name)),
                Matcher::And(v) => {
                    for sub in v {
                        if !self.eval(sub, target, ctx, &mut *resolved).await {
                            return false;
                        }
                    }
                    true
                }
                Matcher::Or(v) => {
                    for sub in v {
                        if self.eval(sub, target, ctx, &mut *resolved).await {
                            return true;
                        }
                    }
                    false
                }
                Matcher::Not(sub) => !self.eval(sub, target, ctx, resolved).await,
                Matcher::RuleSet { set, no_resolve } => {
                    let (domain_hit, has_ip, others) = {
                        let data = set.data.read().unwrap();
                        (matches!(&target.host, Host::Domain(d) if data.match_domain(d)), data.has_ip_rules(), data.others())
                    };
                    if domain_hit
                        || (has_ip
                            && Self::ip_of(target, *no_resolve, &mut *resolved)
                                .await
                                .is_some_and(|ip| set.data.read().unwrap().match_ip(ip)))
                    {
                        return true;
                    }
                    for sub in others.iter() {
                        if self.eval(sub, target, ctx, &mut *resolved).await {
                            return true;
                        }
                    }
                    false
                }
            }
        })
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
                    g.options.iter().filter(|o| latency.get(*o).is_none_or(|l| l.latency_ms.is_some())).collect();
                let pool: Vec<&String> = if healthy.is_empty() { g.options.iter().collect() } else { healthy };
                pool[rand::thread_rng().gen_range(0..pool.len())].clone()
            } else {
                selected[&cur].clone()
            };
        }
        bail!("policy group loop involving {policy:?}")
    }

    pub fn mode(&self) -> Mode {
        *self.mode.read().unwrap()
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.write().unwrap() = mode;
    }

    pub async fn decide(&self, target: &Target) -> Result<Decision> {
        self.decide_with(target, &ConnInfo::default()).await
    }

    /// Like [`decide`](Self::decide), with what is known about the client for
    /// PROCESS-NAME, SRC-IP, IN-PORT, PROTOCOL and URL-REGEX rules.
    pub async fn decide_with(&self, target: &Target, ctx: &ConnInfo) -> Result<Decision> {
        match self.mode() {
            Mode::Direct => {
                return Ok(Decision { rule: "DIRECT-MODE".into(), policy: "DIRECT".into(), outbound: "DIRECT".into(), process: None, traffic: Default::default() })
            }
            Mode::Global => {
                let policy = self
                    .rules
                    .iter()
                    .find(|r| matches!(r.matcher, Matcher::Final))
                    .map_or("DIRECT".to_string(), |r| r.policy.clone());
                return Ok(Decision { rule: "GLOBAL-MODE".into(), outbound: self.resolve(&policy)?, policy, process: None, traffic: Default::default() });
            }
            Mode::Rule => {}
        }
        let rule = self.match_rule(target, ctx).await;
        Ok(Decision {
            rule: rule.to_string(),
            policy: rule.policy.clone(),
            outbound: self.resolve(&rule.policy)?,
            process: ctx.known_process().map(str::to_string),
            traffic: Default::default(),
        })
    }

    pub async fn decide_logged(&self, target: &Target, ctx: &ConnInfo) -> Result<Decision> {
        let mut d = self.decide_with(target, ctx).await?;
        d.process = ctx.process().await.map(str::to_string);
        let proc_note = d.process.as_deref().map_or(String::new(), |p| format!(" ({p})"));
        info!("{} {target}{proc_note} -> {} [{}] via {}", ctx.proto.name(), d.policy, d.rule, d.outbound);
        crate::conns::record(crate::conns::ConnRecord {
            id: 0,
            time_ms: 0,
            network: ctx.proto.name(),
            target: target.to_string(),
            src: ctx.src.map(|s| s.to_string()),
            rule: d.rule.clone(),
            policy: d.policy.clone(),
            outbound: d.outbound.clone(),
            process: d.process.clone(),
            url: ctx.url.clone(),
            mitm: ctx.mitm,
            traffic: d.traffic.clone(),
        });
        Ok(d)
    }

    /// The groups followed from `policy` down to `outbound`, `outbound` last. Load-balance
    /// groups pick per connection, so the walk takes the option that leads to `outbound`.
    pub fn chain(&self, policy: &str, outbound: &str) -> Vec<String> {
        let selected = self.selected.read().unwrap();
        let mut out = vec![policy.to_string()];
        let mut cur = policy.to_string();
        while cur != outbound && out.len() < 16 {
            let Some(g) = self.group(&cur) else { break };
            cur = match selected.get(&cur) {
                Some(s) if g.kind != GroupKind::LoadBalance => s.clone(),
                _ => g.options.iter().find(|o| *o == outbound).unwrap_or(&outbound.to_string()).clone(),
            };
            out.push(cur.clone());
        }
        if out.last().map(String::as_str) != Some(outbound) {
            out.push(outbound.to_string());
        }
        out
    }

    /// Connects to `target` through whatever the rules pick; `None` means rejected.
    pub async fn dispatch_with(&self, target: &Target, ctx: &ConnInfo) -> Result<Option<BoxStream>> {
        let d = self.decide_logged(target, ctx).await?;
        let meta = crate::live::ConnMeta {
            network: ctx.proto.name(),
            target: target.to_string(),
            src: ctx.src.map(|s| s.to_string()),
            chain: self.chain(&d.policy, &d.outbound),
            rule: d.rule,
            policy: d.policy,
            outbound: d.outbound.clone(),
            process: d.process,
            traffic: d.traffic,
        };
        Ok(self.open(&d.outbound, target).await?.map(|s| crate::stats::counted_live(s, meta)))
    }

    /// The outbound for UDP to `target`; `None` means rejected. Every outbound's UDP is
    /// full-cone, so an inbound association needs one [`open_udp`](Self::open_udp) per outbound.
    pub async fn route_udp_with(&self, target: &Target, ctx: &ConnInfo) -> Result<Option<String>> {
        let d = self.decide_logged(target, ctx).await?;
        Ok((!matches!(self.outbounds[&d.outbound], Outbound::Reject)).then_some(d.outbound))
    }

    /// Opens a UDP association through `outbound`; `first` is where its first packet goes.
    pub async fn open_udp(&self, outbound: &str, first: &Target) -> Result<crate::udp::UdpPipe> {
        Ok(match self.outbounds.get(outbound).ok_or_else(|| anyhow!("unknown outbound {outbound:?}"))? {
            Outbound::Reject => bail!("{outbound} rejects UDP"),
            Outbound::Direct => crate::udp::direct(),
            Outbound::Shadowsocks(s) => s.open_udp().await?,
            Outbound::Trojan(t) => t.open_udp(first).await?,
            Outbound::AnyTls(a) => a.open_udp().await?,
            Outbound::Vless(v) => v.open_udp(first),
            Outbound::Vmess(v) => v.open_udp(first),
            Outbound::Hysteria2(h) => h.open_udp().await?,
        })
    }

    /// UDP counterpart of [`dispatch_with`](Self::dispatch_with); `None` means rejected.
    pub async fn dispatch_udp_with(&self, target: &Target, ctx: &ConnInfo) -> Result<Option<crate::udp::UdpPipe>> {
        match self.route_udp_with(target, ctx).await? {
            Some(o) => Ok(Some(self.open_udp(&o, target).await?)),
            None => Ok(None),
        }
    }

    pub fn mitm(&self) -> Option<&Arc<crate::mitm::Mitm>> {
        self.mitm.as_ref()
    }

    pub fn rewrites(&self) -> &Arc<crate::rewrite::Rewrites> {
        &self.rewrites
    }

    /// Opens `target` through an outbound already decided on; `None` means rejected.
    pub async fn connect(&self, outbound: &str, target: &Target) -> Result<Option<BoxStream>> {
        Ok(self.open(outbound, target).await?.map(crate::stats::counted))
    }

    async fn open(&self, outbound: &str, target: &Target) -> Result<Option<BoxStream>> {
        let stream: BoxStream = match &self.outbounds[outbound] {
            Outbound::Reject => return Ok(None),
            Outbound::Direct => Box::new(connect_tcp(&target.host_str(), target.port).await?),
            Outbound::Shadowsocks(s) => s.connect(target).await?,
            Outbound::Trojan(t) => t.connect(target).await?,
            Outbound::AnyTls(a) => a.connect(target).await?,
            Outbound::Vless(v) => v.connect(target).await?,
            Outbound::Vmess(v) => v.connect(target).await?,
            Outbound::Hysteria2(h) => h.connect(target).await?,
        };
        Ok(Some(stream))
    }

    pub fn rule_sets(&self) -> Vec<Arc<crate::ruleset::RuleSet>> {
        fn collect(m: &Matcher, sets: &mut Vec<Arc<crate::ruleset::RuleSet>>) {
            match m {
                Matcher::RuleSet { set, .. } | Matcher::GeoSite { set, .. } => {
                    if !sets.iter().any(|s| Arc::ptr_eq(s, set)) { sets.push(set.clone()); }
                }
                Matcher::And(v) | Matcher::Or(v) => v.iter().for_each(|m| collect(m, sets)),
                Matcher::Not(m) => collect(m, sets),
                _ => {}
            }
        }
        let mut sets = Vec::new();
        for rule in &self.rules { collect(&rule.matcher, &mut sets); }
        sets
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
                options: g.options.iter().map(|o| OptionStatus { name: o.clone(), latency: latency.get(o).map(|r| r.latency_ms), error: latency.get(o).and_then(|r| r.error.clone()) }).collect(),
                url: g.url.clone(), interval: g.interval_secs,
                tolerance: if let GroupKind::UrlTest { tolerance_ms } = g.kind { Some(tolerance_ms) } else { None },
            })
            .collect()
    }

    /// Install saved choices together: applying them one at a time can temporarily
    /// form a cycle with a default choice even when the complete saved graph is valid.
    pub fn restore_selections(&self, saved: &std::collections::BTreeMap<String, String>) {
        let previous = self.selected.read().unwrap().clone();
        {
            let mut selected = self.selected.write().unwrap();
            for group in self.groups.iter().filter(|g| g.kind == GroupKind::Select) {
                if let Some(option) = saved.get(&group.name).filter(|o| group.options.contains(o)) {
                    selected.insert(group.name.clone(), option.clone());
                }
            }
        }
        if self.groups.iter().any(|g| self.resolve(&g.name).is_err()) {
            *self.selected.write().unwrap() = previous;
            log::warn!("saved selections form a cycle; keeping prior choices");
        }
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

    pub fn test_url(&self, name: &str) -> &str {
        self.group(name).or_else(|| self.groups.iter().find(|g| g.kind != GroupKind::Select && g.options.iter().any(|o| o == name)))
            .or_else(|| self.groups.iter().find(|g| g.options.iter().any(|o| o == name)))
            .map(|g| g.url.as_str()).unwrap_or(crate::config::DEFAULT_TEST_URL)
    }

    /// Tests one node or group through its current selection: time to open the stream
    /// through it (TCP connect plus the proxy handshake), and time until the test URL's
    /// HTTP status line arrives. Also stored as the option's health-check result.
    pub async fn test_node(&self, name: &str, url: &str, timeout: Duration) -> Result<NodeTest> {
        if !self.outbounds.contains_key(name) && self.group(name).is_none() {
            bail!("no such node or group {name:?}");
        }
        let start = Instant::now();
        let mut stage = "connecting to node (DNS, TCP and proxy handshake)";
        let attempt = async {
            let (target, path) = parse_test_url(url)?;
            let outbound = self.resolve(name)?;
            let mut s = self.open(&outbound, &target).await?.ok_or_else(|| anyhow!("rejected by {outbound}"))?;
            if url.starts_with("https://") {
                stage = "establishing HTTPS to test target";
                let (connector, name) = crate::trojan::tls_client(&target.host_str(), None, false)?;
                s = Box::new(connector.connect(name, s).await.context("probe HTTPS handshake")?);
            }
            let connect_ms = start.elapsed().as_millis() as u64;
            stage = "writing test request";
            let req = format!("HEAD {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target.host_str());
            s.write_all(req.as_bytes()).await?;
            s.flush().await?;
            stage = "waiting for HTTP response from test target";
            let mut head = [0u8; 12];
            s.read_exact(&mut head).await?;
            if !head.starts_with(b"HTTP/1.") {
                bail!("not an HTTP response");
            }
            let status = std::str::from_utf8(&head[9..12]).ok().and_then(|c| c.parse().ok()).unwrap_or(0);
            Ok(NodeTest { outbound, connect_ms, latency_ms: start.elapsed().as_millis() as u64, status })
        };
        let r = match tokio::time::timeout(timeout, attempt).await {
            Ok(r) => r,
            Err(_) => Err(anyhow!("timed out after {}ms while {stage}", timeout.as_millis())),
        };
        let health = HealthCheck::from_result(r.as_ref().map(|t| t.latency_ms).map_err(|e| anyhow!("{e:#}")));
        if let Some(error) = &health.error { warn!("health check {name}: {error}"); }
        self.latency.write().unwrap().insert(name.to_string(), health);
        r
    }

    /// Time until the test URL's status line arrives, retaining the full failure chain.
    async fn probe(&self, option: &str, url: &str) -> HealthCheck {
        // Groups and individual nodes must measure the same request, timeout and
        // response validation. Keep the established REJECT diagnostic unchanged.
        let result = self.test_node(option, url, PROBE_TIMEOUT).await.map(|t| t.latency_ms)
            .map_err(|e| if e.to_string() == "rejected by REJECT" { anyhow!("rejected") } else { e });
        HealthCheck::from_result(result)
    }

    /// Probes every option of a group, updates an automatic group's selection, and
    /// returns each option's latency and error, or `None` for no such group.
    pub async fn check_group(self: &Arc<Self>, name: &str) -> Option<Vec<(String, HealthCheck)>> {
        let g = self.group(name).cloned()?;
        let mut set = tokio::task::JoinSet::new();
        let mut results = vec![HealthCheck::from_result(Err(anyhow!("health check task did not complete"))); g.options.len()];
        for (i, o) in g.options.iter().enumerate() {
            if set.len() >= 4 {
                match set.join_next().await {
                    Some(Ok((i, result))) => results[i] = result,
                    Some(Err(error)) => warn!("health check {name}: task failed: {error}"),
                    None => {}
                }
            }
            let (me, o, url) = (self.clone(), o.clone(), g.url.clone());
            set.spawn(async move { (i, me.probe(&o, &url).await) });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((i, r)) => results[i] = r,
                Err(e) => warn!("health check {name}: task failed: {e}"),
            }
        }
        for (option, r) in g.options.iter().zip(&results) {
            if let Some(error) = &r.error { warn!("health check {name}: {option}: {error}"); }
        }
        {
            let mut latency = self.latency.write().unwrap();
            for (o, r) in g.options.iter().zip(&results) {
                latency.insert(o.clone(), r.clone());
            }
        }
        let current = self.selected.read().unwrap()[name].clone();
        let pick = match g.kind {
            GroupKind::UrlTest { tolerance_ms } => {
                let best = g.options.iter().zip(&results).filter_map(|(o, r)| r.latency_ms.map(|ms| (o, ms))).min_by_key(|(_, ms)| *ms);
                let cur_ms = g.options.iter().position(|o| *o == current).and_then(|i| results[i].latency_ms);
                match (best, cur_ms) {
                    (Some((o, ms)), Some(cur)) if ms + tolerance_ms < cur => Some(o.clone()),
                    (Some((o, _)), None) => Some(o.clone()),
                    _ => None,
                }
            }
            GroupKind::Fallback => g.options.iter().zip(&results).find(|(_, r)| r.latency_ms.is_some()).map(|(o, _)| o.clone()),
            _ => None,
        };
        let summary: Vec<String> = g
            .options
            .iter()
            .zip(&results)
            .map(|(o, r)| format!("{o}={}", r.latency_ms.map_or_else(|| format!("fail({})", short_health_error(r.error.as_deref().unwrap_or("unknown error"))), |ms| format!("{ms}ms"))))
            .collect();
        info!("health check {name}: {}", summary.join(", "));
        if let Some(p) = pick.filter(|p| *p != current) {
            info!("group {name}: {current} -> {p}");
            self.selected.write().unwrap().insert(name.to_string(), p);
        }
        Some(g.options.into_iter().zip(results).collect())
    }

    /// Groups needed by the active routing mode. Manual groups follow their current
    /// selection; automatic groups need all candidates to make their next choice.
    pub fn required_groups(&self) -> std::collections::HashSet<String> {
        let mut pending: Vec<String> = match self.mode() {
            Mode::Direct => Vec::new(),
            Mode::Global => self.rules.iter().find(|r| matches!(r.matcher, Matcher::Final)).map(|r| vec![r.policy.clone()]).unwrap_or_default(),
            Mode::Rule => self.rules.iter().map(|r| r.policy.clone()).collect(),
        };
        let selected = self.selected.read().unwrap();
        let mut required = std::collections::HashSet::new();
        while let Some(name) = pending.pop() {
            let Some(group) = self.group(&name) else { continue };
            if !required.insert(name.clone()) { continue; }
            if group.kind == GroupKind::Select {
                if let Some(option) = selected.get(&name) { pending.push(option.clone()); }
            } else { pending.extend(group.options.iter().cloned()); }
        }
        required
    }

    /// Only reachable automatic groups probe in the background. A newly selected
    /// group is checked on the next tick instead of waiting a full probe interval.
    pub fn spawn_health_checks(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut checked = HashMap::<String, Instant>::new();
            let mut running = std::collections::HashSet::new();
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                while let Some(result) = tasks.try_join_next() {
                    if let Ok(name) = result { running.remove(&name); }
                }
                let Some(router) = weak.upgrade() else { break };
                let needed = router.required_groups();
                checked.retain(|name, _| needed.contains(name));
                for group in router.groups.iter().filter(|g| g.kind != GroupKind::Select && needed.contains(&g.name)) {
                    if running.contains(&group.name) || checked.get(&group.name).is_some_and(|last| last.elapsed().as_secs() < group.interval_secs) { continue; }
                    let (name, owner) = (group.name.clone(), router.clone());
                    checked.insert(name.clone(), Instant::now()); running.insert(name.clone());
                    tasks.spawn(async move { owner.check_group(&name).await; name });
                }
                drop(router);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    /// Carries group selections and health-check results over from the router being
    /// replaced, wherever the same group and option still exist.
    pub fn inherit_state(&self, old: &Router) {
        self.set_mode(old.mode());
        let old_selected = old.selected.read().unwrap().clone();
        let mut selected = self.selected.write().unwrap();
        for g in self.groups.iter().filter(|g| g.kind != GroupKind::LoadBalance) {
            if let Some(prev) = old_selected.get(&g.name).filter(|p| g.options.contains(p)) {
                selected.insert(g.name.clone(), prev.clone());
            }
        }
        drop(selected);
        if self.groups.iter().any(|g| self.resolve(&g.name).is_err()) {
            // A carried-over choice formed a loop with the new groups; fall back to defaults.
            let mut selected = self.selected.write().unwrap();
            for g in &self.groups {
                selected.insert(g.name.clone(), g.options[0].clone());
            }
        }
        let old_latency = old.latency.read().unwrap();
        let mut latency = self.latency.write().unwrap();
        for g in &self.groups {
            for o in &g.options {
                if let Some(l) = old_latency.get(o) {
                    latency.insert(o.clone(), l.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Proto;

    fn router(text: &str) -> Router {
        Router::new(&Config::parse(text).unwrap()).unwrap()
    }

    #[test]
    fn background_probes_follow_routing_mode_rules_and_manual_selections() {
        let r = router("[Proxy Group]\nRoot = select, DIRECT, Auto\nWork = select, Auto, DIRECT\nAuto = url-test, DIRECT\nUnused = fallback, REJECT\n[Rule]\nDOMAIN,work.test,Work\nFINAL,Root\n");
        assert_eq!(r.required_groups(), ["Root", "Work", "Auto"].into_iter().map(String::from).collect());
        r.select("Work", "DIRECT").unwrap();
        assert!(!r.required_groups().contains("Auto"));
        r.select("Root", "Auto").unwrap();
        assert!(r.required_groups().contains("Auto"));
        assert!(!r.required_groups().contains("Unused"));
        r.set_mode(Mode::Global);
        assert_eq!(r.required_groups(), ["Root", "Auto"].into_iter().map(String::from).collect());
        r.set_mode(Mode::Direct);
        assert!(r.required_groups().is_empty());
    }

    #[tokio::test]
    async fn newly_referenced_automatic_group_is_probed_without_waiting_its_long_interval() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let r = Arc::new(router(&format!("[Proxy Group]\nRoot = select, DIRECT, Auto\nAuto = url-test, DIRECT, interval=600, url=http://{address}/\n[Rule]\nFINAL,Root\n")));
        r.spawn_health_checks();
        assert!(tokio::time::timeout(Duration::from_millis(150), listener.accept()).await.is_err());
        r.select("Root", "Auto").unwrap();
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await.unwrap().unwrap();
        let mut buffer = [0; 1024];
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn group_and_node_probes_use_the_same_target_and_report_the_timeout_phase() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let received = stream.read(&mut request).await.unwrap();
                assert!(received > 0);
                stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0);
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let config = format!("[Proxy Group]\nG = select, DIRECT, url=http://{address}/measured\n[Rule]\nFINAL,G\n");
        let router = Arc::new(router(&config));
        assert_eq!(router.test_url("DIRECT"), format!("http://{address}/measured"));
        let node = router.test_node("DIRECT", router.test_url("DIRECT"), PROBE_TIMEOUT).await.unwrap();
        assert_eq!(node.status, 204);
        let results = router.check_group("G").await.unwrap();
        assert!(results[0].1.latency_ms.is_some());
        assert!(results[0].1.error.is_none());
        let error = router.test_node("DIRECT", router.test_url("DIRECT"), Duration::from_millis(100)).await.err().unwrap().to_string();
        assert!(error.contains("waiting for HTTP response"), "{error}");
        server.abort();
    }

    #[tokio::test]
    async fn health_errors_are_stored_exposed_and_inherited() {
        let conf = "[Proxy Group]\nG = select, REJECT, url=http://test.invalid/\n[Rule]\nFINAL,G\n";
        let r = Arc::new(router(conf));
        let result = r.check_group("G").await.unwrap();
        assert_eq!(result[0].0, "REJECT");
        assert_eq!(result[0].1.latency_ms, None);
        assert_eq!(result[0].1.error.as_deref(), Some("rejected"));
        let group = r.groups().pop().unwrap();
        assert_eq!(group.options[0].latency, Some(None));
        assert_eq!(group.options[0].error.as_deref(), Some("rejected"));
        let new = router(conf);
        new.inherit_state(&r);
        assert_eq!(new.groups()[0].options[0].error.as_deref(), Some("rejected"));
        let error = r.test_node("REJECT", "http://test.invalid/", Duration::from_secs(1)).await.err().unwrap();
        assert!(error.to_string().contains("rejected by REJECT"));
        assert_eq!(r.groups()[0].options[0].error.as_deref(), Some("rejected by REJECT"));
        assert!(r.check_group("missing").await.is_none());
        let chained = HealthCheck::from_result(Err(anyhow!("bad signature").context("TLS handshake")));
        assert_eq!(chained.error.as_deref(), Some("TLS handshake: bad signature"));
        r.latency.write().unwrap().insert("REJECT".into(), HealthCheck::from_result(Ok(12)));
        let status = &r.groups()[0].options[0];
        assert_eq!(status.latency, Some(Some(12)));
        assert!(status.error.is_none());
        assert_eq!(short_health_error("TLS\nerror\r\n雪"), "TLS error  雪");
        assert_eq!(short_health_error(&"雪".repeat(200)).chars().count(), 160);
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

    #[tokio::test]
    async fn modes() {
        let r = router(&CONF.replace("FINAL,DIRECT", "FINAL,Proxy"));
        r.set_mode(Mode::Direct);
        assert_eq!(decide(&r, "exact.com").await.1, "DIRECT");
        r.set_mode(Mode::Global);
        assert_eq!(decide(&r, "10.1.2.3").await, ("GLOBAL-MODE".into(), "A".into()));
        let new = router(CONF);
        new.inherit_state(&r);
        assert_eq!(new.mode(), Mode::Global);
        r.set_mode(Mode::Rule);
        assert_eq!(decide(&r, "exact.com").await.1, "REJECT");
    }

    #[test]
    fn inherit_state_keeps_valid_choices() {
        let old = router(CONF);
        old.select("Proxy", "DIRECT").unwrap();
        let new = router(CONF);
        new.inherit_state(&old);
        assert_eq!(new.groups().iter().find(|g| g.name == "Proxy").unwrap().selected, "DIRECT");
        // An option that no longer exists is not carried over.
        let gone = router(&CONF.replace("Proxy = select, A, DIRECT", "Proxy = select, A"));
        gone.inherit_state(&old);
        assert_eq!(gone.groups().iter().find(|g| g.name == "Proxy").unwrap().selected, "A");
    }

    async fn decide_ctx(r: &Router, host: &str, ctx: ConnInfo) -> String {
        r.decide_with(&Target::parse_authority(host, 443).unwrap(), &ctx).await.unwrap().rule
    }

    #[tokio::test]
    async fn extended_rules() {
        let r = router(
            "
[Rule]
AND,((DOMAIN-SUFFIX,a.com),(DST-PORT,443)),REJECT
OR,((PROCESS-NAME,Curl),(SRC-IP,192.168.9.0/24)),REJECT
NOT,((PROTOCOL,TCP)),DIRECT
IN-PORT,7000-7999,DIRECT
URL-REGEX,^http://ads\\.,REJECT
IP-CIDR6,2001:db8::/32,DIRECT
FINAL,DIRECT
",
        );
        let tcp = || ConnInfo::new(Proto::Https, Some("127.0.0.1:50000".parse().unwrap()), Some(6252), 6252);
        assert_eq!(decide_ctx(&r, "x.a.com", tcp()).await, "AND,((DOMAIN-SUFFIX,a.com),(DST-PORT,443))");
        assert_eq!(decide_ctx(&r, "x.a.com:80", tcp().with_process("other")).await, "FINAL");
        assert_eq!(decide_ctx(&r, "b.com", tcp().with_process("curl")).await, "OR,((PROCESS-NAME,Curl),(SRC-IP,192.168.9.0/24))");
        let lan = ConnInfo::new(Proto::Tcp, Some("192.168.9.4:1234".parse().unwrap()), Some(6252), 6252).with_process("x");
        assert_eq!(decide_ctx(&r, "b.com", lan).await.split(',').next(), Some("OR"));
        let quic = ConnInfo::new(Proto::Quic, None, None, 0).with_process("x");
        assert_eq!(decide_ctx(&r, "b.com", quic).await, "NOT,((PROTOCOL,TCP))");
        let inport = ConnInfo::new(Proto::Tcp, None, Some(7001), 0).with_process("x");
        assert_eq!(decide_ctx(&r, "b.com", inport).await, "IN-PORT,7000-7999");
        let http = || tcp().with_process("x");
        assert_eq!(decide_ctx(&r, "ads.b.com:80", http().with_url("http://ads.b.com/x".into())).await, "URL-REGEX,^http://ads\\.");
        assert_eq!(decide_ctx(&r, "[2001:db8::1]:80", http()).await, "IP-CIDR6,2001:db8::/32");
        let d = r.decide_with(&Target::parse_authority("b.com", 443).unwrap(), &tcp().with_process("curl")).await.unwrap();
        assert_eq!(d.process.as_deref(), Some("curl"));
    }

    #[tokio::test]
    async fn rule_set_with_extended_lines() {
        let r = router("[Rule]\nRULE-SET,inline.list,REJECT\nFINAL,DIRECT\n");
        let set = r.rule_sets().pop().unwrap();
        *set.data.write().unwrap() = crate::ruleset::SetData::parse("PROCESS-NAME,curl\nDST-PORT,22\n", crate::ruleset::SetKind::Rules).0;
        let ctx = || ConnInfo::new(Proto::Tcp, None, None, 0).with_process("curl");
        assert_eq!(decide_ctx(&r, "x.org", ctx()).await, "RULE-SET,inline.list");
        let other = ConnInfo::new(Proto::Tcp, None, None, 0).with_process("wget");
        assert_eq!(decide_ctx(&r, "x.org:22", other).await, "RULE-SET,inline.list");
        let other = ConnInfo::new(Proto::Tcp, None, None, 0).with_process("wget");
        assert_eq!(decide_ctx(&r, "x.org", other).await, "FINAL");
    }

    #[tokio::test]
    async fn native_geosite_routes_domains_and_combinations() {
        let r = router("[General]\ngeosite-db = local.dat\n[Rule]\nAND,((GEOSITE,category-ads-all),(DST-PORT,443)),REJECT\nGEOSITE,category-ads-all,REJECT\nFINAL,DIRECT\n");
        let sets = r.rule_sets();
        assert_eq!(sets.len(), 1, "repeated categories share a loaded database view");
        assert_eq!(sets[0].source, "local.dat");
        *sets[0].data.write().unwrap() = crate::geosite::parse(&crate::geosite::tests::fixture(), "category-ads-all").unwrap();
        for domain in ["x.ads.example", "exact.example", "ad12.example.org", "ad-keyword.test"] {
            let (rule, outbound) = decide(&r, domain).await;
            assert!(rule.starts_with("AND,((GEOSITE,category-ads-all)"));
            assert_eq!(outbound, "REJECT");
        }
        assert_eq!(decide(&r, "x.ads.example:80").await, ("GEOSITE,category-ads-all".into(), "REJECT".into()));
        assert_eq!(decide(&r, "badads.example").await, ("FINAL".into(), "DIRECT".into()));
        assert_eq!(decide(&r, "1.1.1.1").await.1, "DIRECT");
        let inverted = router("[Rule]\nGEOSITE,!category-ads-all,REJECT\nFINAL,DIRECT\n");
        assert_eq!(decide(&inverted, "normal.example").await.1, "DIRECT", "unloaded negated sets never match");
        *inverted.rule_sets()[0].data.write().unwrap() = crate::geosite::parse(&crate::geosite::tests::fixture(), "!category-ads-all").unwrap();
        assert_eq!(decide(&inverted, "normal.example").await.1, "REJECT");
        assert_eq!(decide(&inverted, "ads.example").await.1, "DIRECT");
        assert_eq!(decide(&inverted, "1.1.1.1").await.1, "DIRECT");
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
