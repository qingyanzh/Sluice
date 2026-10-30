//! `[URL Rewrite]`, `[Header Rewrite]` and `[Body Rewrite]`: Surge-style HTTP rewriting,
//! applied to plain HTTP and to HTTPS that [`mitm`](crate::mitm) decrypts.
//!
//! ```text
//! [URL Rewrite]
//! ^https?://old\.example\.com/(.*) https://new.example.com/$1 302    # 302 | 307 | reject | header
//! [Header Rewrite]
//! http-request ^https://example\.com/ header-add X-Sluice yes        # header-add | header-del | header-replace
//! http-response ^https://example\.com/ header-del Server
//! [Body Rewrite]
//! http-response ^https://example\.com/ "Example Domain" "Sluice Domain"
//! ```

use anyhow::{anyhow, bail, Result};
use http::{HeaderMap, HeaderName, HeaderValue};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlAction {
    Found,
    TempRedirect,
    Reject,
    /// Rewrite the request URL in place and send it on.
    Header,
}

#[derive(Debug, Clone)]
pub struct UrlRewrite {
    pub re: Regex,
    pub replacement: String,
    pub action: UrlAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderOp {
    Add(String, String),
    Del(String),
    Replace(String, String),
}

#[derive(Debug, Clone)]
pub struct HeaderRewrite {
    pub response: bool,
    pub re: Regex,
    pub op: HeaderOp,
}

#[derive(Debug, Clone)]
pub struct BodyRewrite {
    pub response: bool,
    pub re: Regex,
    pub pairs: Vec<(Regex, String)>,
}

#[derive(Debug, Default, Clone)]
pub struct Rewrites {
    pub url: Vec<UrlRewrite>,
    pub header: Vec<HeaderRewrite>,
    pub body: Vec<BodyRewrite>,
}

/// What a URL rewrite decided for a request.
#[derive(Debug, PartialEq, Eq)]
pub enum UrlOutcome {
    Pass,
    Redirect(u16, String),
    Reject,
    Rewritten(String),
}

/// Splits on whitespace, keeping `"double quoted"` runs (with `\"` escapes) as one token.
pub fn tokens(line: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut tok = String::new();
        if c == '"' {
            chars.next();
            loop {
                match chars.next() {
                    Some('\\') if chars.peek() == Some(&'"') => tok.push(chars.next().unwrap()),
                    Some('"') => break,
                    Some(c) => tok.push(c),
                    None => bail!("unterminated quote"),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                tok.push(c);
                chars.next();
            }
        }
        out.push(tok);
    }
    Ok(out)
}

fn regex(s: &str) -> Result<Regex> {
    Regex::new(s).map_err(|e| anyhow!("bad regex {s:?}: {e}"))
}

/// Strips an optional leading `http-request` / `http-response`; returns whether it was a response.
fn direction(t: &mut Vec<String>) -> bool {
    match t.first().map(String::as_str) {
        Some("http-response") => {
            t.remove(0);
            true
        }
        Some("http-request") => {
            t.remove(0);
            false
        }
        _ => false,
    }
}

impl UrlRewrite {
    pub fn parse(line: &str) -> Result<Self> {
        let t = tokens(line)?;
        let [re, replacement, kind] = t.as_slice() else { bail!("expected `regex replacement 302|307|reject|header`") };
        let action = match kind.to_ascii_lowercase().as_str() {
            "302" => UrlAction::Found,
            "307" => UrlAction::TempRedirect,
            "reject" => UrlAction::Reject,
            "header" => UrlAction::Header,
            k => bail!("unknown URL rewrite type {k:?} (302, 307, reject or header)"),
        };
        Ok(UrlRewrite { re: regex(re)?, replacement: replacement.clone(), action })
    }
}

impl HeaderRewrite {
    pub fn parse(line: &str) -> Result<Self> {
        let mut t = tokens(line)?;
        let response = direction(&mut t);
        if t.len() < 3 {
            bail!("expected `[http-request|http-response] regex header-add|header-del|header-replace name [value]`");
        }
        let (re, op, name) = (regex(&t[0])?, t[1].to_ascii_lowercase(), t[2].clone());
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| anyhow!("bad header name {name:?}"))?;
        let value = t[3..].join(" ");
        let op = match op.as_str() {
            "header-add" => HeaderOp::Add(name, value),
            "header-del" => HeaderOp::Del(name),
            "header-replace" => HeaderOp::Replace(name, value),
            o => bail!("unknown header operation {o:?}"),
        };
        if let HeaderOp::Add(_, v) | HeaderOp::Replace(_, v) = &op {
            HeaderValue::from_str(v).map_err(|_| anyhow!("bad header value {v:?}"))?;
        }
        Ok(HeaderRewrite { response, re, op })
    }
}

impl BodyRewrite {
    pub fn parse(line: &str) -> Result<Self> {
        let mut t = tokens(line)?;
        let response = direction(&mut t);
        if t.len() < 3 || t.len() % 2 == 0 {
            bail!("expected `http-request|http-response url-regex pattern replacement [pattern replacement...]`");
        }
        let pairs = t[1..].chunks(2).map(|p| Ok((regex(&p[0])?, p[1].clone()))).collect::<Result<_>>()?;
        Ok(BodyRewrite { response, re: regex(&t[0])?, pairs })
    }
}

impl Rewrites {
    pub fn is_empty(&self) -> bool {
        self.url.is_empty() && self.header.is_empty() && self.body.is_empty()
    }

    /// The first matching `[URL Rewrite]` decides.
    pub fn rewrite_url(&self, url: &str) -> UrlOutcome {
        let Some(r) = self.url.iter().find(|r| r.re.is_match(url)) else { return UrlOutcome::Pass };
        let to = r.re.replace(url, r.replacement.as_str()).into_owned();
        match r.action {
            UrlAction::Found => UrlOutcome::Redirect(302, to),
            UrlAction::TempRedirect => UrlOutcome::Redirect(307, to),
            UrlAction::Reject => UrlOutcome::Reject,
            UrlAction::Header => UrlOutcome::Rewritten(to),
        }
    }

    /// Applies every matching header rewrite for this direction, in order.
    pub fn rewrite_headers(&self, response: bool, url: &str, headers: &mut HeaderMap) {
        for r in self.header.iter().filter(|r| r.response == response && r.re.is_match(url)) {
            match &r.op {
                HeaderOp::Add(n, v) => {
                    if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(v)) {
                        headers.append(n, v);
                    }
                }
                HeaderOp::Del(n) => {
                    headers.remove(n.as_str());
                }
                HeaderOp::Replace(n, v) => {
                    if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(v)) {
                        if headers.contains_key(&n) {
                            headers.insert(n, v);
                        }
                    }
                }
            }
        }
    }

    pub fn has_body(&self, response: bool, url: &str) -> bool {
        self.body.iter().any(|r| r.response == response && r.re.is_match(url))
    }

    pub fn rewrite_body(&self, response: bool, url: &str, body: &[u8]) -> Vec<u8> {
        let mut text = String::from_utf8_lossy(body).into_owned();
        for r in self.body.iter().filter(|r| r.response == response && r.re.is_match(url)) {
            for (re, rep) in &r.pairs {
                text = re.replace_all(&text, rep.as_str()).into_owned();
            }
        }
        text.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quotes() {
        assert_eq!(tokens(r#"a  "b c" "d\"e" f"#).unwrap(), ["a", "b c", "d\"e", "f"]);
        assert!(tokens("\"open").is_err());
    }

    #[test]
    fn url_rewrites() {
        let rw = Rewrites {
            url: vec![
                UrlRewrite::parse(r"^https?://old\.test/(.*) https://new.test/$1 302").unwrap(),
                UrlRewrite::parse(r"^https://t\.test/ https://t2.test/ 307").unwrap(),
                UrlRewrite::parse(r"^https?://ads\. _ reject").unwrap(),
                UrlRewrite::parse(r"^http://h\.test/(.*) http://h2.test/v2/$1 header").unwrap(),
            ],
            ..Default::default()
        };
        assert_eq!(rw.rewrite_url("https://old.test/a?b=1"), UrlOutcome::Redirect(302, "https://new.test/a?b=1".into()));
        assert_eq!(rw.rewrite_url("https://t.test/x"), UrlOutcome::Redirect(307, "https://t2.test/x".into()));
        assert_eq!(rw.rewrite_url("http://ads.x.com/"), UrlOutcome::Reject);
        assert_eq!(rw.rewrite_url("http://h.test/p"), UrlOutcome::Rewritten("http://h2.test/v2/p".into()));
        assert_eq!(rw.rewrite_url("https://other.test/"), UrlOutcome::Pass);
        assert!(UrlRewrite::parse("^a b 301").is_err());
        assert!(UrlRewrite::parse("^a b").is_err());
    }

    #[test]
    fn header_rewrites() {
        let rw = Rewrites {
            header: vec![
                HeaderRewrite::parse(r"http-request ^https://e\.test/ header-add X-A hello world").unwrap(),
                HeaderRewrite::parse(r"^https://e\.test/ header-del Cookie").unwrap(),
                HeaderRewrite::parse(r"http-request ^https://e\.test/ header-replace User-Agent sluice").unwrap(),
                HeaderRewrite::parse(r"http-request ^https://e\.test/ header-replace X-Absent v").unwrap(),
                HeaderRewrite::parse(r"http-response ^https://e\.test/ header-del Server").unwrap(),
            ],
            ..Default::default()
        };
        let mut h = HeaderMap::new();
        h.insert("cookie", "a=1".parse().unwrap());
        h.insert("user-agent", "curl".parse().unwrap());
        h.insert("server", "nginx".parse().unwrap());
        rw.rewrite_headers(false, "https://e.test/x", &mut h);
        assert_eq!(h["x-a"], "hello world");
        assert!(h.get("cookie").is_none());
        assert_eq!(h["user-agent"], "sluice");
        assert!(h.get("x-absent").is_none());
        assert_eq!(h["server"], "nginx");
        rw.rewrite_headers(true, "https://e.test/x", &mut h);
        assert!(h.get("server").is_none());
        let mut h2 = HeaderMap::new();
        rw.rewrite_headers(false, "https://other.test/", &mut h2);
        assert!(h2.is_empty());
        assert!(HeaderRewrite::parse("^a header-move X").is_err());
        assert!(HeaderRewrite::parse("^a header-add").is_err());
    }

    #[test]
    fn body_rewrites() {
        let rw = Rewrites {
            body: vec![BodyRewrite::parse(r#"http-response ^https://e\.test/ "Example (\w+)" "Sluice $1" foo bar"#).unwrap()],
            ..Default::default()
        };
        assert!(rw.has_body(true, "https://e.test/"));
        assert!(!rw.has_body(false, "https://e.test/"));
        assert_eq!(rw.rewrite_body(true, "https://e.test/", b"<h1>Example Domain foo</h1>"), b"<h1>Sluice Domain bar</h1>");
        assert!(BodyRewrite::parse("http-response ^a only").is_err());
    }
}
