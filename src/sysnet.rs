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

/// Name of the interface already holding `ip`, if any (e.g. another proxy's TUN).
pub fn interface_with_address(ip: &str) -> Option<String> {
    let out = sh("ifconfig", &[]).ok()?;
    let mut iface = None;
    for line in out.lines() {
        if !line.starts_with(['\t', ' ']) {
            iface = line.split(':').next().map(str::to_string);
        } else if line.trim().starts_with(&format!("inet {ip} ")) {
            return iface;
        }
    }
    None
}

/// Names of other VPN / network-extension services macOS reports as connected.
pub fn connected_vpns() -> Vec<String> {
    let out = sh("scutil", &["--nc", "list"]).unwrap_or_default();
    out.lines()
        .filter(|l| l.contains("(Connected)"))
        .map(|l| l.split('"').nth(1).unwrap_or(l.trim()).to_string())
        .collect()
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
    /// Interface we added an interface-scoped default route for, to remove on exit.
    scoped_default: Option<String>,
}

fn default_gateway() -> Option<String> {
    let out = sh("route", &["-n", "get", "default"]).ok()?;
    out.lines().find_map(|l| l.trim().strip_prefix("gateway:").map(|s| s.trim().to_string()))
}

/// Whether `netstat -rn` output has a `default` row with the I (interface-scoped) flag on `iface`.
fn has_scoped_default(table: &str, iface: &str) -> bool {
    table.lines().any(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        cols.len() >= 4 && cols[0] == "default" && cols[2].contains('I') && cols[3] == iface
    })
}

/// Sockets bound to `iface` (IP_BOUND_IF) need a default route scoped to it. macOS only
/// keeps one for non-primary interfaces; for the primary one the scoped lookup falls back
/// to the global table, where our /1 routes via the TUN win and the kernel refuses the
/// mismatch with ENETUNREACH. Adds the scoped default if missing; returns whether it did.
fn ensure_scoped_default(iface: &str) -> Result<bool> {
    // `route get -ifscope` exits 0 even when nothing matches, so read the table instead.
    let table = sh("netstat", &["-rn", "-f", "inet"])?;
    if has_scoped_default(&table, iface) {
        return Ok(false);
    }
    match default_gateway() {
        Some(gw) => sh("route", &["-n", "add", "-ifscope", iface, "-net", "default", &gw])?,
        None => sh("route", &["-n", "add", "-ifscope", iface, "-net", "default", "-interface", iface])?,
    };
    info!("added default route scoped to {iface} for Sluice's own connections");
    Ok(true)
}

impl SystemGuard {
    pub fn apply(tun: &str, fake_cidr: &str, dns_ip: &str, egress: &str) -> Result<Self> {
        let mut guard =
            SystemGuard { routes: Vec::new(), tun: tun.to_string(), dns_backup: Vec::new(), scoped_default: None };
        if ensure_scoped_default(egress)? {
            guard.scoped_default = Some(egress.to_string());
        }
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
        if let Some(iface) = &self.scoped_default {
            let _ = sh("route", &["-n", "delete", "-ifscope", iface, "-net", "default"]);
        }
        restore_dns(&self.dns_backup);
        info!("system routes and DNS restored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_default_detection() {
        let primary = "default            10.152.0.1         UGScg                 en0\n0/1                link#26            UScg                utun6\n";
        let secondary = "default            link#26            UCSg                utun6\ndefault            10.152.0.1         UGScIg                en0\n";
        assert!(!has_scoped_default(primary, "en0"));
        assert!(has_scoped_default(secondary, "en0"));
        assert!(!has_scoped_default(secondary, "en1"));
    }
}
