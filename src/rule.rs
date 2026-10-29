use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

use crate::ruleset::{RuleSet, SetKind};

#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    net: u128,
    prefix: u8,
    v6: bool,
}

fn mask(prefix: u8, max: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (u128::MAX << (128 - prefix as u32)) >> (128 - max as u32)
    }
}

/// Normalizes an address to (bits, width, is_v6); IPv4-mapped IPv6 counts as IPv4.
fn ip_bits(ip: IpAddr) -> (u128, u8, bool) {
    match ip {
        IpAddr::V4(v) => (u32::from(v) as u128, 32, false),
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => (u32::from(v4) as u128, 32, false),
            None => (u128::from(v), 128, true),
        },
    }
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let (addr, prefix) = s.split_once('/').ok_or_else(|| anyhow!("bad CIDR {s:?}"))?;
        let ip: IpAddr = addr.parse().map_err(|_| anyhow!("bad CIDR address {addr:?}"))?;
        let prefix: u8 = prefix.parse().map_err(|_| anyhow!("bad CIDR prefix in {s:?}"))?;
        let (bits, max, v6) = ip_bits(ip);
        if prefix > max {
            bail!("CIDR prefix too long in {s:?}");
        }
        Ok(Cidr { net: bits & mask(prefix, max), prefix, v6 })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (bits, max, v6) = ip_bits(ip);
        v6 == self.v6 && bits & mask(self.prefix, max) == self.net
    }
}

#[derive(Debug, Clone)]
pub enum Matcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr { cidr: Cidr, raw: String, no_resolve: bool },
    GeoIp { country: String, no_resolve: bool },
    /// Contents are filled in by `ruleset::load` after parsing.
    RuleSet { set: Arc<RuleSet>, no_resolve: bool },
    Final,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub matcher: Matcher,
    pub policy: String,
}

impl Rule {
    /// Parses a Surge-style rule line, e.g. `DOMAIN-SUFFIX,google.com,Proxy`.
    pub fn parse(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        let kind = parts[0].to_ascii_uppercase();
        if kind == "FINAL" {
            let policy = parts.get(1).filter(|p| !p.is_empty()).ok_or_else(|| anyhow!("FINAL needs a policy"))?;
            return Ok(Rule { matcher: Matcher::Final, policy: policy.to_string() });
        }
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            bail!("rule needs TYPE,VALUE,POLICY");
        }
        let value = parts[1];
        let no_resolve = parts[3..].iter().any(|p| p.eq_ignore_ascii_case("no-resolve"));
        let matcher = match kind.as_str() {
            "DOMAIN" => Matcher::Domain(value.to_ascii_lowercase()),
            "DOMAIN-SUFFIX" => Matcher::DomainSuffix(value.trim_start_matches('.').to_ascii_lowercase()),
            "DOMAIN-KEYWORD" => Matcher::DomainKeyword(value.to_ascii_lowercase()),
            "IP-CIDR" | "IP-CIDR6" => Matcher::IpCidr { cidr: Cidr::parse(value)?, raw: value.to_string(), no_resolve },
            "GEOIP" => Matcher::GeoIp { country: value.to_ascii_uppercase(), no_resolve },
            "RULE-SET" => Matcher::RuleSet { set: RuleSet::new(value, SetKind::Rules), no_resolve },
            "DOMAIN-SET" => Matcher::RuleSet { set: RuleSet::new(value, SetKind::Domains), no_resolve },
            _ => bail!("unsupported rule type {kind}"),
        };
        Ok(Rule { matcher, policy: parts[2].to_string() })
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        match &self.matcher {
            Matcher::Domain(d) => domain == d,
            Matcher::DomainSuffix(s) => {
                domain == s
                    || (domain.len() > s.len()
                        && domain.ends_with(s.as_str())
                        && domain.as_bytes()[domain.len() - s.len() - 1] == b'.')
            }
            Matcher::DomainKeyword(k) => domain.contains(k.as_str()),
            _ => false,
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.matcher {
            Matcher::Domain(v) => write!(f, "DOMAIN,{v}"),
            Matcher::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
            Matcher::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{v}"),
            Matcher::IpCidr { raw, .. } => write!(f, "IP-CIDR,{raw}"),
            Matcher::GeoIp { country, .. } => write!(f, "GEOIP,{country}"),
            Matcher::RuleSet { set, .. } => {
                let kind = if set.kind == SetKind::Rules { "RULE-SET" } else { "DOMAIN-SET" };
                write!(f, "{kind},{}", set.source)
            }
            Matcher::Final => write!(f, "FINAL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let c = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(c.contains("192.168.3.4".parse().unwrap()));
        assert!(c.contains("::ffff:192.168.3.4".parse().unwrap()));
        assert!(!c.contains("192.169.0.1".parse().unwrap()));
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_err());
    }

    #[test]
    fn domain_rules() {
        let r = Rule::parse("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
        assert!(r.match_domain("google.com"));
        assert!(r.match_domain("www.google.com"));
        assert!(!r.match_domain("notgoogle.com"));
        let r = Rule::parse("domain-keyword,ads,REJECT").unwrap();
        assert!(r.match_domain("x.ads.example"));
        assert!(Rule::parse("DOMAIN,foo").is_err());
        assert!(Rule::parse("USER-AGENT,foo,DIRECT").is_err());
    }
}
