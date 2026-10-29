mod api;
mod clash;
mod config;
mod dns;
mod hysteria2;
mod inbound;
mod reload;
mod reality;
mod router;
mod rule;
mod ruleset;
mod salamander;
mod ss;
mod stats;
mod subscription;
mod sysnet;
mod transport;
mod trojan;
mod tun;
mod udp;
mod util;
mod vless;
mod vmess;

use std::sync::Arc;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};

use reload::{build, read_config};
use util::Target;

const USAGE: &str = "\
Sluice — rule-based network proxy

usage:
  sluice run   <config.conf>                 start the proxy
  sluice check <config.conf>                 validate the config
  sluice route <config.conf> <host[:port]>   show which rule and outbound a target uses
  sluice convert <share-link>                print a share link as a [Proxy] line";

/// Resolves a name through the egress path (bound interface + upstream DNS).
async fn egress_self_test(upstream: &[SocketAddr]) -> Result<()> {
    let ips = tokio::time::timeout(std::time::Duration::from_secs(5), dns::resolve_a("apple.com", upstream))
        .await
        .map_err(|_| anyhow!("timed out"))??;
    util::connect_tcp(&ips[0].to_string(), 443).await?;
    Ok(())
}

async fn start_tun(
    g: &config::General,
    handle: Arc<reload::RouterHandle>,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<sysnet::SystemGuard> {
    if !sysnet::is_root() {
        bail!("enhanced-mode needs root: run `sudo sluice run <config>`");
    }
    sysnet::restore_stale_backup();

    let range = g.fake_ip_range.as_deref().unwrap_or("198.18.0.0/15");
    let (net, prefix) = range.split_once('/').ok_or_else(|| anyhow!("bad fake-ip-range {range:?}"))?;
    let net: Ipv4Addr = net.parse().context("bad fake-ip-range")?;
    let prefix: u8 = prefix.parse().context("bad fake-ip-range")?;
    if !(8..=24).contains(&prefix) {
        bail!("fake-ip-range prefix must be between /8 and /24");
    }

    let probe = dns::FakeDns::new(net, prefix, Vec::new());
    let mut upstream: Vec<SocketAddr> = g
        .dns_server
        .iter()
        .map(|s| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)).with_context(|| format!("bad dns-server {s:?}")))
        .collect::<Result<_>>()?;
    if upstream.is_empty() {
        upstream = sysnet::system_dns(|ip| matches!(ip, IpAddr::V4(v4) if probe.contains(v4)));
    }
    if upstream.is_empty() {
        upstream = vec!["223.5.5.5:53".parse()?, "8.8.8.8:53".parse()?];
    }

    let vpns = sysnet::connected_vpns();
    if !vpns.is_empty() {
        log::warn!("other VPN services are connected: {vpns:?}; they may block Sluice's outgoing traffic");
    }
    let iface = sysnet::default_interface()?;
    let if_index = sysnet::if_index(&iface).ok_or_else(|| anyhow!("no index for interface {iface}"))?;
    log::info!("egress via {iface}, upstream DNS {upstream:?}");
    util::set_egress(util::Egress { if_index: Some(if_index), dns: upstream.clone() });
    match egress_self_test(&upstream).await {
        Ok(()) => log::info!("egress self-test via {iface} before routes: ok"),
        Err(e) => log::warn!("egress self-test via {iface} before routes FAILED: {e:#}"),
    }

    let fake = Arc::new(dns::FakeDns::new(net, prefix, upstream.clone()));
    let (tun_ip, dns_ip) = (fake.addr(1), fake.addr(2));
    if let Some(other) = sysnet::interface_with_address(&tun_ip.to_string()) {
        bail!(
            "{tun_ip} is already used by {other}, probably another proxy app's TUN (Surge, Clash...). \
             Quit it first, or pick another fake-ip-range"
        );
    }
    let mtu = g.tun_mtu.unwrap_or(1500);
    let (dev, name) = tun::create(tun_ip, dns_ip, mtu)?;
    log::info!("enhanced mode on {name} ({tun_ip}), fake IPs from {range}");
    let guard = sysnet::SystemGuard::apply(&name, range, &dns_ip.to_string(), &iface)?;
    match egress_self_test(&upstream).await {
        Ok(()) => log::info!("egress self-test via {iface} after routes: ok"),
        Err(e) => log::warn!(
            "egress self-test via {iface} after routes FAILED: {e:#}; traffic bound to {iface} is being blocked \
             (another VPN or network extension enforcing its tunnel?)"
        ),
    }
    tasks.spawn(tun::serve(dev, mtu, handle, fake));
    Ok(guard)
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["check", path] => {
            let (cfg, _) = build(read_config(path)?, path, true).await?;
            println!(
                "config OK: {} proxies, {} groups, {} rules",
                cfg.proxies.len(),
                cfg.groups.len(),
                cfg.rules.len()
            );
        }
        ["route", path, target] => {
            let (_, router) = build(read_config(path)?, path, true).await?;
            let t = Target::parse_authority(target, 443)?;
            let d = router.decide(&t).await?;
            println!("{t}\n  rule:     {}\n  policy:   {}\n  outbound: {}", d.rule, d.policy, d.outbound);
        }
        ["convert", link] => {
            let (name, def) = subscription::parse_link(link)?;
            println!("{}", def.to_line(name.as_deref().unwrap_or("Imported")));
        }
        ["run", path] => {
            let cfg = read_config(path)?;
            let level = cfg.general.loglevel.as_deref().unwrap_or("info");
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(format!("sluice={level}")))
                .format_target(false)
                .init();
            sysnet::raise_fd_limit();
            let (cfg, router) = build(cfg, path, false).await?;
            let reloader = reload::Reloader::start(router, &cfg, path);
            reloader.spawn_triggers()?;
            let handle = reloader.handle.clone();
            let g = cfg.general;
            let mut tasks = tokio::task::JoinSet::new();
            if let Some(addr) = g.http_listen.clone() {
                tasks.spawn(inbound::serve("HTTP", addr, handle.clone(), inbound::http_conn));
            }
            if let Some(addr) = g.socks5_listen.clone() {
                tasks.spawn(inbound::serve("SOCKS5", addr, handle.clone(), inbound::socks5_conn));
            }
            if let Some(addr) = g.api_listen.clone() {
                tasks.spawn(api::serve(addr, reloader.clone()));
            }
            // Held until shutdown; dropping it restores routes and DNS.
            let _system = if g.enhanced_mode {
                Some(start_tun(&g, handle.clone(), &mut tasks).await?)
            } else {
                None
            };
            if tasks.is_empty() {
                bail!("nothing to listen on: set http-listen, socks5-listen or enhanced-mode in [General]");
            }
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                Some(res) = tasks.join_next() => res??,
                _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
                _ = term.recv() => log::info!("shutting down"),
            }
        }
        _ => {
            println!("{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}
