//! Native V2Ray GeoSiteList protobuf decoding. Only the requested category is
//! materialized; no dependency on a running proxy or a text-list conversion.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::rule::{Matcher, Rule};
use crate::ruleset::{RuleSet, SetData};

pub const DEFAULT_DATABASE: &str = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat";

pub fn normalize_tag(value: &str) -> Result<String> {
    let tag = value.to_ascii_lowercase();
    let mut parts = tag.trim_start_matches('!').split('@');
    let valid = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.!".contains(&b));
    let category = parts.next().unwrap_or_default();
    if !valid(category) || category.contains('!') || tag.starts_with("!!") || !parts.all(valid) {
        bail!("bad GEOSITE category {value:?} (expected category or category@attribute)");
    }
    Ok(tag)
}

pub fn configure_rules(rules: &[Rule], source: Option<&str>) -> Vec<Rule> {
    fn configure(m: &mut Matcher, source: &str, shared: &mut HashMap<String, Arc<RuleSet>>) {
        match m {
            Matcher::GeoSite { tag, set } => {
                *set = shared.entry(tag.clone()).or_insert_with(|| RuleSet::geosite(tag, source)).clone();
            }
            Matcher::And(v) | Matcher::Or(v) => v.iter_mut().for_each(|m| configure(m, source, shared)),
            Matcher::Not(m) => configure(m, source, shared),
            _ => {}
        }
    }
    let mut rules = rules.to_vec();
    let mut shared = HashMap::new();
    for rule in &mut rules { configure(&mut rule.matcher, source.unwrap_or(DEFAULT_DATABASE), &mut shared); }
    rules
}

/// Bounded protobuf wire reader for the public routercommon/common.proto schema.
/// Unknown fields are skipped; invalid wire types, lengths and varints fail closed.
struct Proto<'a>(&'a [u8]);

enum Value<'a> { Number(u64), Bytes(&'a [u8]), Fixed }

impl<'a> Proto<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() { bail!("truncated geosite.dat field"); }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 { bail!("geosite.dat varint overflow"); }
            value |= u64::from(byte & 127) << shift;
            if byte < 128 { return Ok(value); }
        }
        bail!("geosite.dat varint overflow")
    }

    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>> {
        if self.0.is_empty() { return Ok(None); }
        let key = self.varint()?;
        let field = key >> 3;
        if field == 0 || field > 0x1fff_ffff { bail!("bad geosite.dat field number"); }
        let value = match key & 7 {
            0 => Value::Number(self.varint()?),
            1 => { self.take(8)?; Value::Fixed }
            2 => {
                let n = usize::try_from(self.varint()?).context("geosite.dat length overflow")?;
                Value::Bytes(self.take(n)?)
            }
            5 => { self.take(4)?; Value::Fixed }
            n => bail!("unsupported geosite.dat wire type {n}"),
        };
        Ok(Some((field, value)))
    }
}

fn text(bytes: &[u8]) -> Result<&str> { std::str::from_utf8(bytes).context("invalid geosite.dat UTF-8") }

fn add_domain(data: &mut SetData, bytes: &[u8], filters: &[&str]) -> Result<()> {
    let mut p = Proto(bytes);
    let (mut kind, mut value, mut attrs) = (0, "", Vec::new());
    while let Some((field, v)) = p.next()? {
        match (field, v) {
            (1, Value::Number(n)) => kind = n,
            (2, Value::Bytes(b)) => value = text(b)?,
            (3, Value::Bytes(b)) => {
                let mut attr = Proto(b);
                while let Some((field, v)) = attr.next()? {
                    if let (1, Value::Bytes(b)) = (field, v) { attrs.push(text(b)?.to_ascii_lowercase()); }
                }
            }
            (1..=3, _) => bail!("bad geosite.dat domain field"),
            _ => {}
        }
    }
    // Attribute matching follows Mihomo: all named attribute keys must exist.
    if !filters.iter().all(|filter| attrs.iter().any(|a| a == filter)) { return Ok(()); }
    if value.is_empty() { bail!("empty geosite.dat domain"); }
    match kind {
        0 => data.keyword.push(value.to_ascii_lowercase()),
        1 => data.regex.push(regex::Regex::new(value).with_context(|| format!("GEOSITE regular expression {value:?}"))?),
        2 => { data.suffix.insert(value.trim_start_matches('.').to_ascii_lowercase()); }
        3 => { data.exact.insert(value.to_ascii_lowercase()); }
        other => bail!("unsupported geosite.dat domain type {other}"),
    }
    Ok(())
}

pub fn parse(bytes: &[u8], tag: &str) -> Result<SetData> {
    let tag = normalize_tag(tag)?;
    let parts: Vec<_> = tag.trim_start_matches('!').split('@').collect();
    let mut list = Proto(bytes);
    let mut data = SetData::default();
    let mut found = false;
    while let Some((field, value)) = list.next()? {
        if field != 1 { continue; }
        let Value::Bytes(site) = value else { bail!("bad geosite.dat entry"); };
        let mut entry = Proto(site);
        let mut name = "";
        while let Some((field, value)) = entry.next()? {
            if field == 1 {
                let Value::Bytes(b) = value else { bail!("bad geosite.dat category name"); };
                name = text(b)?;
            }
        }
        if !name.eq_ignore_ascii_case(parts[0]) { continue; }
        found = true;
        let mut entry = Proto(site);
        while let Some((field, value)) = entry.next()? {
            if field == 2 {
                let Value::Bytes(b) = value else { bail!("bad geosite.dat domain entry"); };
                add_domain(&mut data, b, &parts[1..])?;
            }
        }
    }
    if !found { bail!("category {:?} not found in geosite.dat", parts[0]); }
    if !parts[1..].is_empty() && data.len() == 0 {
        bail!("no GEOSITE domains match attributes {}", parts[1..].join("@"));
    }
    data.geosite_loaded = true;
    Ok(data)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn field(n: u8, b: &[u8]) -> Vec<u8> {
        let mut v = vec![(n << 3) | 2];
        let mut len = b.len();
        while len >= 128 { v.push((len as u8 & 127) | 128); len >>= 7; }
        v.push(len as u8);
        v.extend_from_slice(b);
        v
    }

    pub fn fixture() -> Vec<u8> {
        let mut site = field(1, b"CATEGORY-ADS-ALL");
        for (kind, value, attr) in [
            (0, "ad-keyword", ""), (1, r"^ad\d+\.example\.org$", ""),
            (2, "ads.example", "cn"), (3, "exact.example", "!cn"),
        ] {
            let mut d = vec![8, kind];
            d.extend(field(2, value.as_bytes()));
            if !attr.is_empty() { d.extend(field(3, &field(1, attr.as_bytes()))); }
            site.extend(field(2, &d));
        }
        // Domain fields precede country_code in this second category.
        let mut other = field(2, &field(2, b"unrelated.example"));
        other.extend(field(1, b"OTHER"));
        [field(1, &site), field(1, &other)].concat()
    }

    #[test]
    fn domain_types_and_attributes() {
        let bytes = fixture();
        let data = parse(&bytes, "category-ads-all").unwrap();
        assert_eq!(data.len(), 4);
        for name in ["ads.example", "x.ads.example", "exact.example", "ad123.example.org", "has-ad-keyword.test"] {
            assert!(data.match_domain(name), "{name}");
        }
        for name in ["badads.example", "x.exact.example", "ad.example.org", "unrelated.example"] {
            assert!(!data.match_domain(name), "{name}");
        }
        let filtered = parse(&bytes, "CATEGORY-ADS-ALL@CN").unwrap();
        assert_eq!(filtered.len(), 1);
        assert!(filtered.match_domain("sub.ads.example"));
        assert!(!filtered.match_domain("exact.example"));
        assert!(parse(&bytes, "category-ads-all@!cn").unwrap().match_domain("exact.example"));
        assert!(parse(&bytes, "other").unwrap().match_domain("unrelated.example"));
        assert!(parse(&bytes, "missing").is_err());
        assert!(parse(&bytes, "other@cn").is_err());
    }

    #[test]
    fn invalid_data_does_not_panic_or_succeed() {
        for b in [vec![], vec![0], vec![10, 255], vec![10, 3, 10, 9, 0], vec![255; 12], b"<html>error</html>".to_vec()] {
            assert!(parse(&b, "category-ads-all").is_err());
        }
        for tag in ["", "!", "!!cn", "cn@", "cn/a", "a b", "cn@@ads"] { assert!(normalize_tag(tag).is_err()); }
        assert_eq!(normalize_tag("!CN@ads").unwrap(), "!cn@ads");
        let bad = field(1, &[field(1, b"ADS"), field(2, &[vec![8, 1], field(2, b"[")].concat())].concat());
        assert!(parse(&bad, "ads").is_err());
    }
}
