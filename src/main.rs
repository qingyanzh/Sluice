mod api;
mod config;
mod dns;
mod hysteria2;
mod inbound;
mod router;
mod rule;
mod ss;
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

use config::Config;
use router::Router;
use util::Target;

const USAGE: &str = "\
Sluice — rule-based network proxy

usage:
  sluice run   <config.conf>                 start the proxy
  sluice check <config.conf>                 validate the config
  sluice route <config.conf> <host[:port]>   show which rule and outbound a target uses";

fn load(path: &str) -> Result<(Config, Router)> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let cfg = Config::parse(&text)?;
    let router = Router::new(&cfg)?;
    Ok((cfg, router))
}

fn start_tun(
    g: &config::General,
    router: Arc<Router>,
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

    let iface = sysnet::default_interface()?;
    let if_index = sysnet::if_index(&iface).ok_or_else(|| anyhow!("no index for interface {iface}"))?;
    log::info!("egress via {iface}, upstream DNS {upstream:?}");
    util::set_egress(util::Egress { if_index: Some(if_index), dns: upstream.clone() });

    let fake = Arc::new(dns::FakeDns::new(net, prefix, upstream));
    let (tun_ip, dns_ip) = (fake.addr(1), fake.addr(2));
    let mtu = g.tun_mtu.unwrap_or(1500);
    let (dev, name) = tun::create(tun_ip, dns_ip, mtu)?;
    log::info!("enhanced mode on {name} ({tun_ip}), fake IPs from {range}");
    let guard = sysnet::SystemGuard::apply(&name, range, &dns_ip.to_string())?;
    tasks.spawn(tun::serve(dev, mtu, router, fake));
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
            let (cfg, _) = load(path)?;
            println!(
                "config OK: {} proxies, {} groups, {} rules",
                cfg.proxies.len(),
                cfg.groups.len(),
                cfg.rules.len()
            );
        }
        ["route", path, target] => {
            let (_, router) = load(path)?;
            let t = Target::parse_authority(target, 443)?;
            let d = router.decide(&t).await?;
            println!("{t}\n  rule:     {}\n  policy:   {}\n  outbound: {}", d.rule, d.policy, d.outbound);
        }
        ["run", path] => {
            let (cfg, router) = load(path)?;
            let level = cfg.general.loglevel.as_deref().unwrap_or("info");
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(format!("sluice={level}")))
                .format_target(false)
                .init();
            let router = Arc::new(router);
            router.spawn_health_checks();
            let g = cfg.general;
            let mut tasks = tokio::task::JoinSet::new();
            if let Some(addr) = g.http_listen.clone() {
                tasks.spawn(inbound::serve("HTTP", addr, router.clone(), inbound::http_conn));
            }
            if let Some(addr) = g.socks5_listen.clone() {
                tasks.spawn(inbound::serve("SOCKS5", addr, router.clone(), inbound::socks5_conn));
            }
            if let Some(addr) = g.api_listen.clone() {
                tasks.spawn(api::serve(addr, router.clone()));
            }
            // Held until shutdown; dropping it restores routes and DNS.
            let _system = if g.enhanced_mode {
                Some(start_tun(&g, router.clone(), &mut tasks)?)
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
