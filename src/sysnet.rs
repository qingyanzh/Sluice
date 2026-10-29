//! macOS system network changes for TUN mode: routes and DNS, undone on drop.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use log::{info, warn};

/// Survives a crash so the next start can put the user's DNS settings back.
const DNS_BACKUP: &str = "/var/tmp/sluice-dns-backup";

fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn default_interface() -> Result<String> {
    let out = sh("route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()))
        .ok_or_else(|| anyhow!("no default route; are you online?"))
}

pub fn if_index(name: &str) -> Option<NonZeroU32> {
    let c = std::ffi::CString::new(name).ok()?;
    NonZeroU32::new(unsafe { libc::if_nametoindex(c.as_ptr()) })
}

/// The DNS servers the system currently uses, skipping any inside `exclude` (our own fake DNS).
pub fn system_dns(exclude: impl Fn(IpAddr) -> bool) -> Vec<SocketAddr> {
    let out = sh("scutil", &["--dns"]).unwrap_or_default();
    let mut servers: Vec<SocketAddr> = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if !line.starts_with("nameserver[") {
            continue;
        }
        if let Some(ip) = line.split(':').nth(1).and_then(|s| s.trim().parse::<IpAddr>().ok()) {
            let addr = SocketAddr::new(ip, 53);
            if !exclude(ip) && !ip.is_loopback() && !servers.contains(&addr) {
                servers.push(addr);
            }
        }
    }
    servers
}

fn network_services() -> Result<Vec<String>> {
    Ok(sh("networksetup", &["-listallnetworkservices"])?
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
        .map(String::from)
        .collect())
}

fn get_dns(service: &str) -> Vec<String> {
    let out = sh("networksetup", &["-getdnsservers", service]).unwrap_or_default();
    out.lines().filter(|l| l.parse::<IpAddr>().is_ok()).map(String::from).collect()
}

fn set_dns(service: &str, servers: &[String]) -> Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    sh("networksetup", &args).map(|_| ())
}

fn restore_dns(backup: &[(String, Vec<String>)]) {
    for (service, servers) in backup {
        if let Err(e) = set_dns(service, servers) {
            warn!("restore DNS for {service}: {e:#}");
        }
    }
    let _ = std::fs::remove_file(DNS_BACKUP);
}

/// Puts DNS back if a previous run died without cleaning up.
pub fn restore_stale_backup() {
    let Ok(text) = std::fs::read_to_string(DNS_BACKUP) else { return };
    let backup: Vec<(String, Vec<String>)> = text
        .lines()
        .filter_map(|l| {
            let mut parts = l.split('\t');
            Some((parts.next()?.to_string(), parts.filter(|s| !s.is_empty()).map(String::from).collect()))
        })
        .collect();
    warn!("restoring DNS settings left over from a previous run");
    restore_dns(&backup);
}

/// Routes and DNS pointing the system at the TUN, reverted when dropped.
pub struct SystemGuard {
    routes: Vec<String>,
    tun: String,
    dns_backup: Vec<(String, Vec<String>)>,
}

impl SystemGuard {
    pub fn apply(tun: &str, fake_cidr: &str, dns_ip: &str) -> Result<Self> {
        let mut guard = SystemGuard { routes: Vec::new(), tun: tun.to_string(), dns_backup: Vec::new() };
        // Two /1 routes beat the default route without replacing it.
        for net in ["0.0.0.0/1", "128.0.0.0/1", fake_cidr] {
            sh("route", &["-n", "add", "-net", net, "-interface", tun])?;
            guard.routes.push(net.to_string());
        }
        let services = network_services()?;
        guard.dns_backup = services.iter().map(|s| (s.clone(), get_dns(s))).collect();
        let text: String = guard.dns_backup.iter().map(|(s, d)| format!("{s}\t{}\n", d.join("\t"))).collect();
        std::fs::write(DNS_BACKUP, text).context("write DNS backup")?;
        for s in &services {
            set_dns(s, &[dns_ip.to_string()])?;
        }
        info!("system routes -> {tun}, DNS -> {dns_ip} on {} network services", services.len());
        Ok(guard)
    }
}

impl Drop for SystemGuard {
    fn drop(&mut self) {
        for net in &self.routes {
            let _ = sh("route", &["-n", "delete", "-net", net, "-interface", &self.tun]);
        }
        restore_dns(&self.dns_backup);
        info!("system routes and DNS restored");
    }
}
