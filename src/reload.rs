//! Config loading and hot reload. The active [`Router`] sits behind a [`RouterHandle`];
//! a reload builds a new one off to the side and swaps it in, so new connections use the
//! new config while existing ones finish on the old router.

use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use log::{info, warn};

use crate::config::{Config, General};
use crate::router::Router;
use crate::{ruleset, subscription};

pub struct RouterHandle(RwLock<Arc<Router>>);

impl RouterHandle {
    pub fn current(&self) -> Arc<Router> {
        self.0.read().unwrap().clone()
    }
}

pub fn read_config(path: &str) -> Result<Config> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let cfg = Config::parse(&text)?;
    if let Some(migrated) = migrate_app_config(&text, &cfg) {
        let cfg = Config::parse(&migrated)?;
        std::fs::write(path, migrated).with_context(|| format!("migrate {path}"))?;
        info!("migrated app config {path}: listener ports 6152/6153 -> 6252/6253 and default direct rules");
        return Ok(cfg);
    }
    Ok(cfg)
}

const APP_DIRECT_RULES: &[&str] = &[
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT",
];

/// Only the app's old port pair identifies this migration; custom profiles stay intact.
fn migrate_app_config(text: &str, cfg: &Config) -> Option<String> {
    let old_port = |value: &Option<String>, port: u16| {
        value.as_deref().is_some_and(|v| v.parse::<std::net::SocketAddr>().is_ok_and(|a| a.port() == port))
    };
    if !text.lines().any(|l| l.trim().starts_with("# Sluice config created by the app"))
        || !old_port(&cfg.general.http_listen, 6152) || !old_port(&cfg.general.socks5_listen, 6153) {
        return None;
    }
    let mut section = String::new();
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.to_ascii_lowercase();
        }
        if section == "[general]" {
            if let Some((key, _)) = line.split_once('=') {
                let port = match key.trim().to_ascii_lowercase().as_str() {
                    "http-listen" => Some(6252),
                    "socks5-listen" => Some(6253),
                    _ => None,
                };
                if let Some(port) = port {
                    let current = if port == 6252 { &cfg.general.http_listen } else { &cfg.general.socks5_listen };
                    let mut addr: std::net::SocketAddr = current.as_deref()?.parse().ok()?;
                    addr.set_port(port);
                    out.push_str(&format!("{key}= {addr}\n"));
                    continue;
                }
            }
        }
        if section == "[rule]" && trimmed.split(',').next().is_some_and(|v| v.trim().eq_ignore_ascii_case("FINAL")) {
            for rule in APP_DIRECT_RULES {
                if !cfg.rules.iter().any(|r| format!("{r},{}", r.policy).eq_ignore_ascii_case(rule.trim_end_matches(",no-resolve"))) {
                    out.push_str(rule);
                    out.push('\n');
                }
            }
        }
        out.push_str(line);
        out.push('\n');
        if trimmed.eq_ignore_ascii_case("[General]") && cfg.general.geoip_db.is_none() {
            out.push_str("geoip-db = builtin:cn\n");
        }
    }
    Some(out)
}

fn config_dir(path: &str) -> &Path {
    Path::new(path).parent().unwrap_or(Path::new("."))
}

fn rule_set_interval(cfg: &Config) -> Duration {
    Duration::from_secs(cfg.general.rule_set_update_interval.unwrap_or(86400).max(60))
}

/// Shortest `update-interval` among subscription groups, if there are any.
fn subscription_interval(cfg: &Config) -> Option<Duration> {
    cfg.groups.iter().filter(|g| g.policy_path.is_some()).map(|g| g.update_interval_secs)
        .chain(cfg.providers.iter().map(|p| p.update_interval_secs)).min().map(Duration::from_secs)
}

/// Expands subscriptions, builds the router and fills rule sets. With `strict` off,
/// unreachable subscriptions and rule sets only warn.
pub async fn build(mut cfg: Config, path: &str, strict: bool) -> Result<(Config, Router)> {
    subscription::expand(&mut cfg, config_dir(path), strict).await?;
    let router = Router::new(&cfg)?;
    crate::dns::install(crate::dns::Resolver::new(&cfg)?);
    for set in router.rule_sets() {
        if let Err(e) = ruleset::load(&set, config_dir(path), rule_set_interval(&cfg)).await {
            if strict {
                return Err(e);
            }
            warn!("{e:#}; continuing with it empty");
        }
    }
    Ok((cfg, router))
}

/// A sibling file is shared by user and helper cores, independent of HOME/uid.
fn selection_path(path: &str) -> std::path::PathBuf {
    let mut name = std::path::PathBuf::from(path).into_os_string();
    name.push(".selections.json");
    name.into()
}

fn selections(router: &Router) -> std::collections::BTreeMap<String, String> {
    router.groups().into_iter().filter(|g| g.kind == "select").map(|g| (g.name, g.selected)).collect()
}

pub(crate) fn restore_selections(router: &Router, path: &str) {
    let path = selection_path(path);
    match std::fs::read(&path) {
        Ok(data) => {
            match serde_json::from_slice::<std::collections::BTreeMap<String, String>>(&data) {
                Ok(saved) => router.restore_selections(&saved),
                Err(e) => warn!("invalid selections {}: {e}", path.display()),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("read selections {}: {e}", path.display()),
    }
}

fn save_selections(router: &Router, config: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = selection_path(config);
    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), rand::random::<u64>()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp)?;
        // A root-created file must remain writable by the config's user as well.
        if crate::sysnet::is_root() {
            use std::os::fd::AsRawFd;
            let owner = std::fs::metadata(config)?;
            if unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        file.write_all(&serde_json::to_vec(&selections(router))?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result.with_context(|| format!("persist selections {}", path.display()))
}

/// Settings only read at startup; changing them needs a restart.
#[derive(PartialEq)]
struct Fixed {
    listen: [Option<String>; 3],
    tun: (bool, Option<u16>, Option<String>, Vec<String>),
}

impl Fixed {
    fn of(g: &General) -> Self {
        Fixed {
            listen: [g.http_listen.clone(), g.socks5_listen.clone(), g.api_listen.clone()],
            tun: (g.enhanced_mode, g.tun_mtu, g.fake_ip_range.clone(), g.dns_server.clone()),
        }
    }
}

/// Other config files next to `path` (`.conf`), sorted, for a profile picker.
pub fn sibling_profiles(path: &str) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(config_dir(path)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = dir
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "conf") && p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

pub struct Reloader {
    pub handle: Arc<RouterHandle>,
    pub subscriptions: RwLock<Vec<subscription::SubscriptionInfo>>,
    /// The active config file; `switch_profile` changes it.
    path: Mutex<String>,
    fixed: Fixed,
    ready: std::sync::atomic::AtomicBool,
    lock: tokio::sync::Mutex<()>,
    last: Mutex<Instant>,
    subscription_every: Mutex<Option<Duration>>,
}

/// Starts the router's background work (health checks, rule-set refresh).
fn activate(router: &Arc<Router>, cfg: &Config) {
    router.spawn_health_checks();
    ruleset::spawn_refresh(router.rule_sets(), rule_set_interval(cfg));
}

impl Reloader {
    pub fn start(router: Router, cfg: &Config, path: &str) -> Arc<Self> {
        let router = Arc::new(router);
        restore_selections(&router, path);
        activate(&router, cfg);
        let handle = Arc::new(RouterHandle(RwLock::new(router)));
        crate::dns::set_router(handle.clone());
        Arc::new(Reloader {
            handle,
            subscriptions: RwLock::new(cfg.subscriptions.clone()),
            path: Mutex::new(path.to_string()),
            fixed: Fixed::of(&cfg.general),
            ready: std::sync::atomic::AtomicBool::new(false),
            lock: tokio::sync::Mutex::new(()),
            last: Mutex::new(Instant::now()),
            subscription_every: Mutex::new(subscription_interval(cfg)),
        })
    }

    /// Serialize selection changes with reloads so the acknowledged state is durable.
    pub async fn select(&self, group: &str, option: &str) -> Result<()> {
        let _one_at_a_time = self.lock.lock().await;
        let router = self.handle.current();
        let previous = selections(&router);
        router.select(group, option)?;
        if let Err(e) = save_selections(&router, &self.path()) {
            router.restore_selections(&previous);
            return Err(e);
        }
        Ok(())
    }

    /// Rebuilds from the config file and swaps the new router in; on error the
    /// current one stays. Returns a short summary.
    pub async fn reload(&self, reason: &str) -> Result<String> {
        let _one_at_a_time = self.lock.lock().await;
        let path = self.path();
        self.reload_from(&path, reason).await
    }

    /// Downloads every subscription now, ignoring cache age, and reloads.
    pub async fn update_subscriptions(&self) -> Result<String> {
        let _one_at_a_time = self.lock.lock().await;
        let path = self.path();
        subscription::REFRESH_NOW.store(true, std::sync::atomic::Ordering::Release);
        self.reload_from(&path, "subscription update requested").await
    }

    pub fn mark_ready(&self) { self.ready.store(true, std::sync::atomic::Ordering::Release); }

    pub fn ready(&self) -> bool { self.ready.load(std::sync::atomic::Ordering::Acquire) }

    pub fn enhanced_mode(&self) -> bool {
        self.fixed.tun.0
    }

    /// The config file this reloader reads (it changes with `switch_profile`).
    pub fn path(&self) -> String {
        self.path.lock().unwrap().clone()
    }

    /// Makes `path` the active config file and loads it. The file is parsed and its
    /// router built before anything changes; on any error the current file and config stay.
    pub async fn switch_profile(&self, path: &str) -> Result<String> {
        let _one_at_a_time = self.lock.lock().await;
        let path = std::fs::canonicalize(path).with_context(|| format!("profile {path}"))?.to_string_lossy().into_owned();
        // reload_from expands subscription nodes/groups before validating the router.
        // A preflight Router::new on the raw file rejects valid imported references.
        let summary = self.reload_from(&path, "profile switch").await.with_context(|| format!("profile {path}"))?;
        *self.path.lock().unwrap() = path;
        Ok(summary)
    }

    async fn reload_from(&self, path: &str, reason: &str) -> Result<String> {
        let cfg = read_config(path)?;
        if Fixed::of(&cfg.general) != self.fixed {
            bail!("listen or enhanced-mode settings changed; restart required");
        }
        let (cfg, router) = build(cfg, path, false).await?;
        let router = Arc::new(router);
        self.carry_choices(&router, path);
        save_selections(&router, path)?;
        activate(&router, &cfg);
        *self.handle.0.write().unwrap() = router;
        let mut subscriptions = cfg.subscriptions.clone();
        subscription::mark_changes(&self.subscriptions.read().unwrap(), &mut subscriptions);
        *self.subscriptions.write().unwrap() = subscriptions;
        *self.last.lock().unwrap() = Instant::now();
        *self.subscription_every.lock().unwrap() = subscription_interval(&cfg);
        let summary = format!("{} proxies, {} groups, {} rules", cfg.proxies.len(), cfg.groups.len(), cfg.rules.len());
        info!("config reloaded ({reason}): {summary}");
        Ok(summary)
    }

    /// Reloading the same profile keeps the live choices and health state; switching
    /// to another profile restores that profile's own saved choices instead, even
    /// when group or node names overlap.
    fn carry_choices(&self, router: &Router, path: &str) {
        let canonical = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|_| p.into());
        if canonical(&self.path()) == canonical(path) {
            router.inherit_state(&self.handle.current());
        } else {
            restore_selections(router, path);
        }
    }

    async fn try_reload(&self, reason: &str) {
        if let Err(e) = self.reload(reason).await {
            warn!("reload ({reason}) failed, keeping the current config: {e:#}");
        }
    }

    /// Reloads when the config file changes and when subscriptions are due.
    /// SIGHUP, like SIGTERM/SIGINT, is handled by the lifecycle supervisor.
    pub fn spawn_triggers(self: &Arc<Self>) -> Result<()> {
        let me = self.clone();
        let mtime = |p: &str| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        tokio::spawn(async move {
            let mut watched = me.path();
            let mut seen: Option<SystemTime> = mtime(&watched);
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        if me.path() != watched {
                            // Switched profiles; the switch already loaded the new file.
                            watched = me.path();
                            seen = mtime(&watched);
                            continue;
                        }
                        let now = mtime(&watched);
                        if now != seen {
                            // Let an editor finish writing before reading.
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            seen = mtime(&watched);
                            me.try_reload("config file changed").await;
                        } else {
                            let every = *me.subscription_every.lock().unwrap();
                            let due = every.is_some_and(|e| me.last.lock().unwrap().elapsed() >= e);
                            if due {
                                me.try_reload("subscription update").await;
                            }
                        }
                    }
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        std::fs::canonicalize(p).unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn app_config_migration_is_persisted_and_scoped() {
        let dir = std::env::temp_dir().join(format!("sluice-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let body = "[General]\nhttp-listen = 6152\nsocks5-listen = 127.0.0.1:6153\napi-listen = 127.0.0.1:6170\n[Proxy Group]\nProxy = select, DIRECT\n[Rule]\nDOMAIN-SUFFIX,local,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,Proxy\n";
        let app = format!("# Sluice config created by the app. Edit it, then press Reload.\n{body}");
        let path = write(&dir, "app.conf", &app);
        let cfg = read_config(&path).unwrap();
        assert_eq!(cfg.general.http_listen.as_deref(), Some("127.0.0.1:6252"));
        assert_eq!(cfg.general.socks5_listen.as_deref(), Some("127.0.0.1:6253"));
        assert_eq!(cfg.general.api_listen.as_deref(), Some("127.0.0.1:6170"));
        assert_eq!(cfg.general.geoip_db.as_deref(), Some("builtin:cn"));
        let migrated = std::fs::read_to_string(&path).unwrap();
        for rule in APP_DIRECT_RULES {
            assert_eq!(migrated.matches(rule).count(), 1, "{rule}: {migrated}");
            assert!(migrated.find(rule).unwrap() < migrated.find("FINAL,Proxy").unwrap());
        }
        let router = Router::new(&cfg).unwrap();
        assert!(router.groups().iter().any(|g| g.name == "Proxy"));
        read_config(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), migrated);
        for (i, text) in [body.to_string(), app.replace("6153", "7000"), app.replace("6152", "6252").replace("6153", "6253")].into_iter().enumerate() {
            let path = write(&dir, &format!("custom{i}.conf"), &text);
            read_config(&path).unwrap();
            assert_eq!(std::fs::read_to_string(path).unwrap(), text);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn starter_config_has_working_private_and_cn_rules() {
        let swift = include_str!("../apps/macos/Sources/SluiceApp/Core.swift");
        let text = swift.split("static let starterConfig = \"\"\"").nth(1).unwrap().split("\"\"\"").next().unwrap();
        let cfg = Config::parse(text).unwrap();
        let router = Router::new(&cfg).unwrap();
        for ip in ["10.1.2.3:80", "172.16.1.1:80", "192.168.1.1:80", "127.0.0.1:80", "169.254.1.1:80", "[fc00::1]:80", "[fe80::1]:80", "114.114.114.114:80", "[240e::1]:80"] {
            let d = router.decide(&crate::util::Target::parse_authority(ip, 80).unwrap()).await.unwrap();
            assert_eq!(d.policy, "DIRECT", "{ip}");
            assert_ne!(d.rule, "FINAL", "{ip}");
        }
        let d = router.decide(&crate::util::Target::parse_authority("8.8.8.8:80", 80).unwrap()).await.unwrap();
        assert_eq!(d.rule, "FINAL");
        assert_eq!(d.policy, "Proxy");
        assert!(text.contains("# RULE-SET,"));
    }

    #[test]
    fn restores_saved_selection_graph_atomically() {
        let cfg = Config::parse("[Proxy Group]\nA = select, DIRECT, B\nB = select, A, DIRECT\n[Rule]\nFINAL,A\n").unwrap();
        let router = Router::new(&cfg).unwrap();
        let saved = [("A".into(), "B".into()), ("B".into(), "DIRECT".into())].into_iter().collect();
        router.restore_selections(&saved);
        assert_eq!(selections(&router), saved);
        let cycle = [("A".into(), "B".into()), ("B".into(), "A".into())].into_iter().collect();
        router.restore_selections(&cycle);
        assert_eq!(selections(&router), saved);
    }

    #[tokio::test]
    async fn selections_survive_new_cores_and_ignore_stale_entries() {
        let dir = std::env::temp_dir().join(format!("sluice-selection-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write(&dir, "a.conf", "[Proxy Group]\nProxy = select, DIRECT, REJECT\n[Rule]\nFINAL,Proxy\n");
        let cfg = read_config(&path).unwrap();
        let first = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &path);
        first.select("Proxy", "REJECT").await.unwrap();
        let second = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &path);
        assert_eq!(second.handle.current().groups()[0].selected, "REJECT");
        // A root/user mode switch uses exactly the same sibling state file.
        let mut enabled = read_config(&path).unwrap();
        enabled.general.enhanced_mode = true;
        let third = Reloader::start(Router::new(&enabled).unwrap(), &enabled, &path);
        assert_eq!(third.handle.current().groups()[0].selected, "REJECT");
        std::fs::write(selection_path(&path), br#"{"Proxy":"removed", "OldGroup":"DIRECT"}"#).unwrap();
        let stale = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &path);
        assert_eq!(stale.handle.current().groups()[0].selected, "DIRECT");
        std::fs::write(&path, "[General]\nenhanced-mode = true\n[Rule]\nFINAL,DIRECT\n").unwrap();
        assert!(first.reload("test").await.unwrap_err().to_string().contains("restart required"));
        assert!(!first.enhanced_mode());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn switching_profiles_restores_the_target_choices_without_inheriting_same_named_groups() {
        let dir = std::env::temp_dir().join(format!("sluice-profile-choices-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let text = "[Proxy Group]\nProxy = select, DIRECT, REJECT\n[Rule]\nFINAL,Proxy\n";
        let a = write(&dir, "a.conf", text);
        let b = write(&dir, "b.conf", text);
        let cfg = read_config(&a).unwrap();
        let core = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &a);
        core.select("Proxy", "REJECT").await.unwrap();
        core.switch_profile(&b).await.unwrap();
        assert_eq!(core.handle.current().resolve("Proxy").unwrap(), "DIRECT");
        core.select("Proxy", "DIRECT").await.unwrap();
        core.switch_profile(&a).await.unwrap();
        assert_eq!(core.handle.current().resolve("Proxy").unwrap(), "REJECT");
        core.reload("same profile").await.unwrap();
        assert_eq!(core.handle.current().resolve("Proxy").unwrap(), "REJECT");
        core.switch_profile(&b).await.unwrap();
        assert_eq!(core.handle.current().resolve("Proxy").unwrap(), "DIRECT");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn profile_switch_expands_imported_groups_nodes_and_dynamic_sources_before_validation() {
        let dir = std::env::temp_dir().join(format!("sluice-profile-import-switch-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = write(&dir, "a.conf", "[Rule]\nFINAL,DIRECT\n");
        let source = "[Proxy]\nHK = trojan, hk.example, 443, password=fixture\n[Proxy Group]\n节点选择 = select, 自动选择, DIRECT\n自动选择 = select, HK\n[Rule]\nDOMAIN-KEYWORD,mojie,自动选择\nFINAL,节点选择\n";
        let source_path = write(&dir, "source.txt", source);
        let source_url = url::Url::from_file_path(&source_path).unwrap();
        let imported = crate::profile_import::convert(source, source_url.as_str(), "").unwrap();
        // Match the device settings of the currently running fixture.
        let imported = imported.lines().filter(|line| !line.contains("-listen =")).collect::<Vec<_>>().join("\n");
        let b = write(&dir, "b.conf", &imported);
        let cfg = read_config(&a).unwrap();
        let core = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &a);
        core.switch_profile(&b).await.unwrap();
        assert_eq!(core.path(), b);
        let router = core.handle.current();
        assert_eq!(router.resolve("@导入来源/group/节点选择").unwrap(), "@导入来源/HK");
        let decision = router.decide(&crate::util::Target::parse_authority("mojie.example:443", 443).unwrap()).await.unwrap();
        assert_eq!(decision.policy, "@导入来源/group/自动选择");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), imported);
        for (name, group) in [("dynamic", "Own = select, use=Airport"), ("pinned", "Own = select, @Airport/HK")] {
            let text = format!("[Subscription]\nAirport = policy-path=\"{source_url}\", import-groups=false\n[Proxy Group]\n{group}\n[Rule]\nFINAL,Own\n");
            let path = write(&dir, &format!("{name}.conf"), &text);
            core.switch_profile(&path).await.unwrap();
            assert_eq!(core.handle.current().resolve("Own").unwrap(), "@Airport/HK");
        }
        let invalid = write(&dir, "invalid.conf", &imported.replace("@导入来源/group/自动选择", "@导入来源/group/Missing"));
        let previous_path = core.path();
        let previous = core.handle.current();
        assert!(core.switch_profile(&invalid).await.is_err());
        assert_eq!(core.path(), previous_path);
        assert!(Arc::ptr_eq(&core.handle.current(), &previous));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn profile_switch_validates_and_keeps_old_on_error() {
        let dir = std::env::temp_dir().join(format!("sluice-profile-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = write(&dir, "a.conf", "[Rule]\nFINAL,DIRECT\n");
        let b = write(&dir, "b.conf", "[Proxy Group]\nG = select, DIRECT, REJECT\n[Rule]\nFINAL,G\n");
        let bad = write(&dir, "bad.conf", "[Rule]\nFINAL,NoSuchPolicy\n");
        let garbage = write(&dir, "garbage.conf", "[Proxy]\nA = vless, h, 1\n");
        assert_eq!(sibling_profiles(&a), vec![a.clone(), b.clone(), bad.clone(), garbage.clone()]);

        let cfg = read_config(&a).unwrap();
        let r = Reloader::start(Router::new(&cfg).unwrap(), &cfg, &a);
        for path in [&bad, &garbage, &dir.join("missing.conf").to_string_lossy().into_owned()] {
            let previous = r.handle.current();
            assert!(r.switch_profile(path).await.is_err());
            assert_eq!(r.path(), a);
            assert!(Arc::ptr_eq(&r.handle.current(), &previous));
        }
        r.switch_profile(&b).await.unwrap();
        assert_eq!(r.path(), b);
        assert_eq!(r.handle.current().groups()[0].name, "G");
        // A subscription group with no inline members is validated after expansion.
        write(&dir, "empty.txt", "");
        let sub = write(&dir, "sub.conf", "[Proxy Group]\nS = select, policy-path=empty.txt\n[Rule]\nFINAL,S\n");
        r.switch_profile(&sub).await.unwrap();
        assert_eq!(r.handle.current().resolve("S").unwrap(), "REJECT");
        std::fs::remove_dir_all(&dir).ok();
    }
}
