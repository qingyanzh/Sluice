use std::fmt;
use std::net::{IpAddr, SocketAddr};
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

/// A port or port range: `443`, `8000-9000`, `>1024`, `<=1023`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortRange {
    lo: u16,
    hi: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> Result<Self> {
        let num = |v: &str| v.trim().parse::<u16>().map_err(|_| anyhow!("bad port {s:?}"));
        let (lo, hi) = if let Some(v) = s.strip_prefix(">=") {
            (num(v)?, u16::MAX)
        } else if let Some(v) = s.strip_prefix("<=") {
            (0, num(v)?)
        } else if let Some(v) = s.strip_prefix('>') {
            (num(v)?.checked_add(1).ok_or_else(|| anyhow!("bad port {s:?}"))?, u16::MAX)
        } else if let Some(v) = s.strip_prefix('<') {
            (0, num(v)?.checked_sub(1).ok_or_else(|| anyhow!("bad port {s:?}"))?)
        } else if let Some((a, b)) = s.split_once('-') {
            (num(a)?, num(b)?)
        } else {
            let p = num(s)?;
            (p, p)
        };
        if lo > hi {
            bail!("empty port range {s:?}");
        }
        Ok(PortRange { lo, hi })
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.lo..=self.hi).contains(&port)
    }
}

/// What kind of connection is being routed; `PROTOCOL,TCP` also covers HTTP(S), and
/// `PROTOCOL,UDP` covers QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
    Http,
    Https,
    Quic,
}

impl Proto {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "TCP" => Proto::Tcp,
            "UDP" => Proto::Udp,
            "HTTP" => Proto::Http,
            "HTTPS" => Proto::Https,
            "QUIC" => Proto::Quic,
            _ => bail!("unknown protocol {s:?} (TCP, UDP, HTTP, HTTPS or QUIC)"),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Http => "HTTP",
            Proto::Https => "HTTPS",
            Proto::Quic => "QUIC",
        }
    }

    /// Whether a connection of kind `actual` satisfies a `PROTOCOL,<self>` rule.
    pub fn covers(self, actual: Proto) -> bool {
        self == actual
            || (self == Proto::Tcp && matches!(actual, Proto::Http | Proto::Https))
            || (self == Proto::Udp && actual == Proto::Quic)
    }
}

/// Facts about a connection beyond its destination, used by the non-destination rules.
#[derive(Debug, Default)]
pub struct ConnInfo {
    pub proto: Proto,
    /// The client's address: the peer of an inbound connection, or the source of a TUN flow.
    pub src: Option<SocketAddr>,
    /// Local port of the inbound listener the connection arrived on (none for TUN).
    pub in_port: Option<u16>,
    /// The request URL for plain HTTP, or `https://host/` for a CONNECT tunnel.
    pub url: Option<String>,
    /// Remote port of the client's own socket, to find it among the system's sockets:
    /// the listener port for an inbound, the destination port for TUN.
    pub app_remote_port: u16,
    /// A request decrypted by MITM (its `url` is the full https URL).
    pub mitm: bool,
    process: tokio::sync::OnceCell<Option<String>>,
}

impl ConnInfo {
    pub fn new(proto: Proto, src: Option<SocketAddr>, in_port: Option<u16>, app_remote_port: u16) -> Self {
        ConnInfo { proto, src, in_port, app_remote_port, ..Default::default() }
    }

    pub fn with_url(mut self, url: String) -> Self {
        self.url = Some(url);
        self
    }

    /// Same client, for one request inside this connection (keeps a looked-up process).
    pub fn child(&self, proto: Proto) -> ConnInfo {
        ConnInfo {
            proto,
            src: self.src,
            in_port: self.in_port,
            url: None,
            app_remote_port: self.app_remote_port,
            mitm: false,
            process: self.process.clone(),
        }
    }

    /// Presets the owning process (tests and `/v1/route?process=`), skipping the lookup.
    pub fn with_process(self, name: &str) -> Self {
        let _ = self.process.set(Some(name.to_string()));
        self
    }

    /// Name of the process that owns the client socket, looked up once on first use.
    pub async fn process(&self) -> Option<&str> {
        self.process
            .get_or_init(|| async {
                let src = self.src?;
                // IPv4-mapped loopback clients also arrive on dual-stack listeners.
                let ip = match src.ip() {
                    IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
                    ip => ip,
                };
                // Only local clients can be identified.
                if !(ip.is_loopback() || self.in_port.is_none()) {
                    return None;
                }
                let (udp, remote) = (matches!(self.proto, Proto::Udp | Proto::Quic), self.app_remote_port);
                tokio::task::spawn_blocking(move || crate::process::lookup(udp, src, remote)).await.ok().flatten()
            })
            .await
            .as_deref()
    }

    /// The process name if a rule already looked it up.
    pub fn known_process(&self) -> Option<&str> {
        self.process.get().and_then(|p| p.as_deref())
    }
}

#[derive(Debug, Clone)]
pub enum Matcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr { cidr: Cidr, raw: String, no_resolve: bool },
    GeoIp { country: String, no_resolve: bool },
    GeoSite { tag: String, set: Arc<RuleSet> },
    IpAsn { asn: u32, no_resolve: bool },
    /// Contents are filled in by `ruleset::load` after parsing.
    RuleSet { set: Arc<RuleSet>, no_resolve: bool },
    DstPort { range: PortRange, raw: String },
    InPort { range: PortRange, raw: String },
    SrcIp { cidr: Cidr, raw: String },
    Protocol(Proto),
    /// Executable name, compared case-insensitively.
    ProcessName(String),
    UrlRegex(regex::Regex),
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
    Final,
}

/// Splits on commas that are not inside parentheses.
pub fn split_top(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

/// Strips one pair of enclosing parentheses, if `s` is wrapped in a matching pair.
fn unwrap_parens(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0;
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return None,
            ')' => depth -= 1,
            _ => {}
        }
    }
    (depth == 0).then_some(inner)
}

impl Matcher {
    /// Parses `TYPE`, `VALUE` and trailing options such as `no-resolve`. `nested` is set for
    /// sub-rules of AND/OR/NOT and lines of a RULE-SET, where RULE-SET/DOMAIN-SET cannot appear.
    pub fn parse(kind: &str, value: &str, opts: &[&str], nested: bool) -> Result<Self> {
        let kind = kind.to_ascii_uppercase();
        if value.is_empty() {
            bail!("{kind} needs a value");
        }
        let no_resolve = opts.iter().any(|p| p.eq_ignore_ascii_case("no-resolve"));
        Ok(match kind.as_str() {
            "DOMAIN" => Matcher::Domain(value.to_ascii_lowercase()),
            "DOMAIN-SUFFIX" => Matcher::DomainSuffix(value.trim_start_matches('.').to_ascii_lowercase()),
            "DOMAIN-KEYWORD" => Matcher::DomainKeyword(value.to_ascii_lowercase()),
            "IP-CIDR" | "IP-CIDR6" => Matcher::IpCidr { cidr: Cidr::parse(value)?, raw: value.to_string(), no_resolve },
            "GEOIP" => Matcher::GeoIp { country: value.to_ascii_uppercase(), no_resolve },
            "GEOSITE" => {
                let tag = crate::geosite::normalize_tag(value)?;
                Matcher::GeoSite { set: RuleSet::geosite(&tag, crate::geosite::DEFAULT_DATABASE), tag }
            }
            "IP-ASN" => {
                let n = value.trim_start_matches(['A', 'S', 'a', 's']);
                Matcher::IpAsn { asn: n.parse().map_err(|_| anyhow!("bad ASN {value:?}"))?, no_resolve }
            }
            "DST-PORT" | "DEST-PORT" => Matcher::DstPort { range: PortRange::parse(value)?, raw: value.to_string() },
            "IN-PORT" => Matcher::InPort { range: PortRange::parse(value)?, raw: value.to_string() },
            "SRC-IP" => {
                // A bare address means that single host.
                let cidr = if value.contains('/') {
                    Cidr::parse(value)?
                } else {
                    let ip: IpAddr = value.parse().map_err(|_| anyhow!("bad SRC-IP {value:?}"))?;
                    Cidr::parse(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))?
                };
                Matcher::SrcIp { cidr, raw: value.to_string() }
            }
            "PROTOCOL" => Matcher::Protocol(Proto::parse(value)?),
            "PROCESS-NAME" => Matcher::ProcessName(value.to_string()),
            "URL-REGEX" => Matcher::UrlRegex(regex::Regex::new(value).map_err(|e| anyhow!("bad URL-REGEX: {e}"))?),
            "AND" | "OR" | "NOT" => {
                let inner = unwrap_parens(value).ok_or_else(|| anyhow!("{kind} needs ((RULE),(RULE)...)"))?;
                let subs = split_top(inner)
                    .into_iter()
                    .map(|sub| {
                        let body = unwrap_parens(sub).ok_or_else(|| anyhow!("sub-rule {sub:?} must be in parentheses"))?;
                        let p = split_top(body);
                        Matcher::parse(p[0], p.get(1).copied().unwrap_or(""), p.get(2..).unwrap_or(&[]), true)
                    })
                    .collect::<Result<Vec<_>>>()?;
                match kind.as_str() {
                    "AND" if !subs.is_empty() => Matcher::And(subs),
                    "OR" if !subs.is_empty() => Matcher::Or(subs),
                    "NOT" if subs.len() == 1 => Matcher::Not(Box::new(subs.into_iter().next().unwrap())),
                    "NOT" => bail!("NOT takes exactly one sub-rule"),
                    _ => bail!("{kind} needs at least one sub-rule"),
                }
            }
            "RULE-SET" | "DOMAIN-SET" if nested => bail!("{kind} cannot be nested"),
            "RULE-SET" => Matcher::RuleSet { set: RuleSet::new(value, SetKind::Rules), no_resolve },
            "DOMAIN-SET" => Matcher::RuleSet { set: RuleSet::new(value, SetKind::Domains), no_resolve },
            _ => bail!("unsupported rule type {kind}"),
        })
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        match self {
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

    pub fn needs_external_data(&self) -> bool {
        match self {
            Matcher::RuleSet { .. } | Matcher::GeoSite { .. } => true,
            Matcher::And(v) | Matcher::Or(v) => v.iter().any(Matcher::needs_external_data),
            Matcher::Not(m) => m.needs_external_data(),
            _ => false,
        }
    }

}

#[derive(Debug, Clone)]
pub struct Rule {
    pub matcher: Matcher,
    pub policy: String,
}

impl Rule {
    /// Parses a Surge-style rule line, e.g. `DOMAIN-SUFFIX,google.com,Proxy` or
    /// `AND,((DOMAIN,a.com),(DST-PORT,443)),Proxy`.
    pub fn parse(line: &str) -> Result<Self> {
        let parts = split_top(line);
        if parts[0].eq_ignore_ascii_case("FINAL") {
            let policy = parts.get(1).filter(|p| !p.is_empty()).ok_or_else(|| anyhow!("FINAL needs a policy"))?;
            return Ok(Rule { matcher: Matcher::Final, policy: policy.to_string() });
        }
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            bail!("rule needs TYPE,VALUE,POLICY");
        }
        Ok(Rule { matcher: Matcher::parse(parts[0], parts[1], &parts[3..], false)?, policy: parts[2].to_string() })
    }
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |f: &mut fmt::Formatter<'_>, kind: &str, v: &[Matcher]| {
            let subs: Vec<String> = v.iter().map(|m| format!("({m})")).collect();
            write!(f, "{kind},({})", subs.join(","))
        };
        match self {
            Matcher::Domain(v) => write!(f, "DOMAIN,{v}"),
            Matcher::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
            Matcher::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{v}"),
            Matcher::IpCidr { raw, .. } if raw.contains(':') => write!(f, "IP-CIDR6,{raw}"),
            Matcher::IpCidr { raw, .. } => write!(f, "IP-CIDR,{raw}"),
            Matcher::GeoIp { country, .. } => write!(f, "GEOIP,{country}"),
            Matcher::GeoSite { tag, .. } => write!(f, "GEOSITE,{tag}"),
            Matcher::IpAsn { asn, .. } => write!(f, "IP-ASN,{asn}"),
            Matcher::RuleSet { set, .. } => {
                let kind = if set.kind == SetKind::Rules { "RULE-SET" } else { "DOMAIN-SET" };
                write!(f, "{kind},{}", set.source)
            }
            Matcher::DstPort { raw, .. } => write!(f, "DST-PORT,{raw}"),
            Matcher::InPort { raw, .. } => write!(f, "IN-PORT,{raw}"),
            Matcher::SrcIp { raw, .. } => write!(f, "SRC-IP,{raw}"),
            Matcher::Protocol(p) => write!(f, "PROTOCOL,{}", p.name()),
            Matcher::ProcessName(v) => write!(f, "PROCESS-NAME,{v}"),
            Matcher::UrlRegex(r) => write!(f, "URL-REGEX,{}", r.as_str()),
            Matcher::And(v) => list(f, "AND", v),
            Matcher::Or(v) => list(f, "OR", v),
            Matcher::Not(m) => list(f, "NOT", std::slice::from_ref(m)),
            Matcher::Final => write!(f, "FINAL"),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.matcher.fmt(f)
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
        assert!(r.matcher.match_domain("google.com"));
        assert!(r.matcher.match_domain("www.google.com"));
        assert!(!r.matcher.match_domain("notgoogle.com"));
        let r = Rule::parse("domain-keyword,ads,REJECT").unwrap();
        assert!(r.matcher.match_domain("x.ads.example"));
        assert!(Rule::parse("DOMAIN,foo").is_err());
        assert!(Rule::parse("USER-AGENT,foo,DIRECT").is_err());
    }

    #[test]
    fn extended_parsing() {
        let r = Rule::parse("AND,((DOMAIN,a.com),(DST-PORT,443)),Proxy").unwrap();
        assert_eq!(r.policy, "Proxy");
        assert!(matches!(&r.matcher, Matcher::And(v) if v.len() == 2));
        assert_eq!(r.to_string(), "AND,((DOMAIN,a.com),(DST-PORT,443))");
        let r = Rule::parse("OR,((NOT,((PROTOCOL,UDP))),(IP-CIDR,10.0.0.0/8,no-resolve)),REJECT").unwrap();
        match &r.matcher {
            Matcher::Or(v) => {
                assert!(matches!(&v[0], Matcher::Not(m) if matches!(**m, Matcher::Protocol(Proto::Udp))));
                assert!(matches!(&v[1], Matcher::IpCidr { no_resolve: true, .. }));
            }
            m => panic!("{m:?}"),
        }
        assert!(Rule::parse("NOT,((DOMAIN,a.com),(DOMAIN,b.com)),DIRECT").is_err());
        assert!(Rule::parse("AND,(DOMAIN,a.com),DIRECT").is_err());
        assert!(Rule::parse("AND,((RULE-SET,x.list)),DIRECT").is_err());
        assert!(Rule::parse("URL-REGEX,^http://(a|b)\\.com/,REJECT").is_ok());
        assert!(matches!(Rule::parse("IP-ASN,AS13335,DIRECT,no-resolve").unwrap().matcher, Matcher::IpAsn { asn: 13335, no_resolve: true }));
        assert!(matches!(Rule::parse("SRC-IP,192.168.1.5,DIRECT").unwrap().matcher, Matcher::SrcIp { .. }));
        assert!(Rule::parse("PROTOCOL,SCTP,DIRECT").is_err());
        assert_eq!(Rule::parse("IP-CIDR6,2001:db8::/32,DIRECT").unwrap().to_string(), "IP-CIDR6,2001:db8::/32");
        assert!(matches!(Rule::parse("PROCESS-NAME,curl,REJECT").unwrap().matcher, Matcher::ProcessName(_)));
    }

    #[test]
    fn ports_and_protocols() {
        let p = |s| PortRange::parse(s).unwrap();
        assert!(p("443").contains(443) && !p("443").contains(444));
        assert!(p("8000-9000").contains(8080) && !p("8000-9000").contains(9001));
        assert!(p(">1024").contains(1025) && !p(">1024").contains(1024));
        assert!(p("<=1023").contains(80) && !p("<=1023").contains(1024));
        assert!(PortRange::parse("9-1").is_err() && PortRange::parse("x").is_err());
        assert!(Proto::Tcp.covers(Proto::Https) && Proto::Udp.covers(Proto::Quic));
        assert!(!Proto::Http.covers(Proto::Tcp) && !Proto::Tcp.covers(Proto::Udp));
    }
}
