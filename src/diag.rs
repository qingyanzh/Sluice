//! Diagnostics: rotating log files, crash reports and the `sluice diag export` bundle.
//!
//! Everything that leaves the machine through a bundle goes through [`redact`] first:
//! passwords, UUIDs, keys, tokens, share links and subscription URLs are masked.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use regex::{Captures, Regex};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const LOG_NAME: &str = "sluice.log";
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
const LOG_KEEP: usize = 5;
const MASK: &str = "[REDACTED]";

/// `~/Library/Logs/Sluice`, or `$SLUICE_LOG_DIR`. Under sudo it is the invoking user's.
pub fn log_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SLUICE_LOG_DIR") {
        return PathBuf::from(d);
    }
    let home = match std::env::var("SUDO_USER") {
        Ok(u) if crate::sysnet::is_root() && !u.is_empty() => PathBuf::from("/Users").join(u),
        _ => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp")),
    };
    home.join("Library/Logs/Sluice")
}

fn crash_dir() -> PathBuf {
    log_dir().join("crashes")
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A log file that rolls `sluice.log` → `sluice.1.log` … `sluice.<keep>.log` past `max_bytes`,
/// and copies every line to stderr so the app's pipe still sees it.
pub struct RotatingLog {
    dir: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    size: u64,
}

impl RotatingLog {
    pub fn open(dir: &Path, max_bytes: u64, keep: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut log = RotatingLog { dir: dir.to_path_buf(), max_bytes, keep, file: None, size: 0 };
        log.reopen()?;
        Ok(log)
    }

    fn path(&self, n: usize) -> PathBuf {
        if n == 0 {
            self.dir.join(LOG_NAME)
        } else {
            self.dir.join(format!("sluice.{n}.log"))
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        let path = self.path(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        readable_by_all(&path);
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        let _ = fs::remove_file(self.path(self.keep));
        for n in (0..self.keep).rev() {
            let _ = fs::rename(self.path(n), self.path(n + 1));
        }
        self.reopen()
    }

    fn write_file(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        if let Some(f) = self.file.as_mut() {
            f.write_all(buf)?;
            self.size += buf.len() as u64;
        }
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = io::stderr().write_all(buf);
        // A full disk must not take the proxy down: the stderr copy is enough then.
        let _ = self.write_file(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = io::stderr().flush();
        self.file.as_mut().map_or(Ok(()), |f| f.flush())
    }
}

/// Files written as root (enhanced mode) stay readable for the user's app and exports.
fn readable_by_all(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
}

/// env_logger to stderr plus the rotating file; falls back to stderr only.
pub fn init_logging(level: &str) {
    let mut b = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(format!("sluice={level}")));
    b.format_target(false);
    match RotatingLog::open(&log_dir(), LOG_MAX_BYTES, LOG_KEEP) {
        Ok(f) => {
            b.target(env_logger::Target::Pipe(Box::new(f)));
        }
        Err(e) => eprintln!("warning: no log file in {}: {e}", log_dir().display()),
    }
    let logger = b.build();
    log::set_max_level(logger.filter());
    // Wrapped so `/v1/events` subscribers get log lines too.
    let _ = log::set_boxed_logger(Box::new(crate::live::EventLogger(logger)));
}

static CRASH_CONFIG: OnceLock<Mutex<Option<String>>> = OnceLock::new();

/// Remembers which config a crash report should summarize.
pub fn set_crash_config(path: &str) {
    *CRASH_CONFIG.get_or_init(Default::default).lock().unwrap() = Some(path.to_string());
}

/// Chains a hook that writes `crashes/crash-<time>.txt` before the default panic output.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let config = CRASH_CONFIG.get().and_then(|m| m.lock().ok()?.clone());
        let report = crash_report(&info.to_string(), config.as_deref());
        match write_crash(&report) {
            Ok(p) => eprintln!("crash report written to {}", p.display()),
            Err(e) => eprintln!("couldn't write crash report: {e}"),
        }
        default(info);
    }));
}

fn crash_report(panic: &str, config: Option<&str>) -> String {
    let thread = std::thread::current();
    let mut r = format!(
        "Sluice crash report\nversion: {}\ntime: {} (unix)\nos: {}\nthread: {}\n\npanic: {}\n\nbacktrace:\n{}\n",
        version_line(),
        now_secs(),
        std::env::consts::OS,
        thread.name().unwrap_or("<unnamed>"),
        redact(panic),
        std::backtrace::Backtrace::force_capture(),
    );
    r.push_str(&config_summary(config));
    r
}

fn write_crash(report: &str) -> io::Result<PathBuf> {
    let dir = crash_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("crash-{}-{}.txt", now_secs(), std::process::id()));
    fs::write(&path, report)?;
    readable_by_all(&path);
    Ok(path)
}

fn version_line() -> String {
    match option_env!("SLUICE_GIT_REV") {
        Some(rev) => format!("sluice {VERSION} ({rev})"),
        None => format!("sluice {VERSION}"),
    }
}

/// Counts and the redacted text of the config, for crash reports.
fn config_summary(path: Option<&str>) -> String {
    let Some(path) = path else { return "config: none\n".into() };
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return format!("config: {path} (unreadable: {e})\n"),
    };
    let counts = match crate::config::Config::parse(&text) {
        Ok(c) => format!("{} proxies, {} groups, {} rules", c.proxies.len(), c.groups.len(), c.rules.len()),
        Err(e) => format!("parse error: {e:#}"),
    };
    format!("config: {path} ({counts})\n\n--- config (redacted) ---\n{}\n", redact(&text))
}

// MARK: redaction

/// Schemes whose whole body is a credential (share links).
const LINK_SCHEMES: &[&str] =
    &["ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "socks", "socks5", "anytls", "wireguard"];

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b([A-Za-z][A-Za-z0-9+.-]*)://([^\s,"'<>|\\`]*)"#).unwrap())
}

/// `key=value`, `key: value`, `"key":"value"` where the key names a secret.
fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)([A-Za-z0-9_-]*(?:pass|secret|token|uuid|key|psk|auth|user|p12|sign|cookie|credential|short-?id|\bsid\b|pbk)[A-Za-z0-9_-]*)(["']?[ \t]*[:=][ \t]*["']?)((?:Bearer |Basic )?[^\s,"'&}\]\[|;]+)"#,
        )
        .unwrap()
    })
}

fn uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap())
}

/// URL path segments that look like words (`dns-query`, `generate_204`), not tokens.
fn harmless_segment(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(?:[A-Za-z._~-]{0,24}|[A-Za-z._-]{1,20}\d{1,3}|v\d)$").unwrap());
    re.is_match(s)
}

fn redact_url(scheme: &str, rest: &str) -> String {
    let lower = scheme.to_ascii_lowercase();
    if LINK_SCHEMES.contains(&lower.as_str()) {
        return format!("{scheme}://{MASK}");
    }
    if lower == "file" {
        return format!("{scheme}://{rest}");
    }
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = match authority.rsplit_once('@') {
        Some((_, h)) => format!("{MASK}@{h}"),
        None => authority.to_string(),
    };
    let (path, extra) = match tail.find(['?', '#']) {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    let path = if path.split('/').all(harmless_segment) { path.to_string() } else { format!("/{MASK}") };
    let extra = if extra.is_empty() { String::new() } else { format!("{}{MASK}", &extra[..1]) };
    format!("{scheme}://{host}{path}{extra}")
}

/// Masks secrets in config text, logs and command output.
pub fn redact(text: &str) -> String {
    let t = url_re().replace_all(text, |c: &Captures| redact_url(&c[1], &c[2]));
    let t = kv_re().replace_all(&t, |c: &Captures| {
        if c[3].starts_with(MASK) || c[3].eq_ignore_ascii_case("true") || c[3].eq_ignore_ascii_case("false") {
            c[0].to_string()
        } else {
            format!("{}{}{MASK}", &c[1], &c[2])
        }
    });
    uuid_re().replace_all(&t, "[REDACTED-UUID]").into_owned()
}

// MARK: export

/// Runs a local command with a timeout; output (or the failure) as text.
fn capture(program: &str, args: &[&str], timeout: Duration) -> String {
    let child = Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return format!("$ {program} {}\nfailed to run: {e}\n", args.join(" ")),
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                break;
            }
        }
    }
    match child.wait_with_output() {
        Ok(o) => format!(
            "$ {program} {}\nexit: {}\n{}{}",
            args.join(" "),
            o.status,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => format!("$ {program} {}\nfailed: {e}\n", args.join(" ")),
    }
}

fn write_redacted(dst: &Path, text: &str) -> Result<()> {
    fs::write(dst, redact(text)).with_context(|| format!("write {}", dst.display()))
}

/// Copies every regular file in `src` whose name passes `keep`, redacted, into `dst`.
fn copy_dir_redacted(src: &Path, dst: &Path, keep: impl Fn(&str) -> bool) -> Result<usize> {
    let Ok(entries) = fs::read_dir(src) else { return Ok(0) };
    let mut n = 0;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !e.path().is_file() || !keep(&name) || name.ends_with(".zip") || name.ends_with(".pid") {
            continue;
        }
        let Ok(bytes) = fs::read(e.path()) else { continue };
        fs::create_dir_all(dst)?;
        write_redacted(&dst.join(&name), &String::from_utf8_lossy(&bytes))?;
        n += 1;
    }
    Ok(n)
}

/// The default bundle path: `~/Library/Logs/Sluice/sluice-diag-<time>.zip`.
pub fn default_export_path() -> PathBuf {
    log_dir().join(format!("sluice-diag-{}.zip", now_secs()))
}

/// Writes the diagnostics zip to `out` and returns its path. Uses only local commands.
pub fn export(out: &Path, config: Option<&str>) -> Result<PathBuf> {
    if out.extension().and_then(|e| e.to_str()) != Some("zip") {
        bail!("output must end in .zip");
    }
    let name = format!("sluice-diag-{}", now_secs());
    let staging = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let root = staging.join(&name);
    fs::create_dir_all(&root)?;
    let res = fill(&root, config).and_then(|()| zip(&root, out));
    let _ = fs::remove_dir_all(&staging);
    res?;
    Ok(fs::canonicalize(out).unwrap_or_else(|_| out.to_path_buf()))
}

fn fill(root: &Path, config: Option<&str>) -> Result<()> {
    let short = Duration::from_secs(10);
    let mut version = format!("{}\nexe: {}\n\n", version_line(), std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default());
    version.push_str(&capture("sw_vers", &[], short));
    version.push_str(&capture("uname", &["-a"], short));
    write_redacted(&root.join("version.txt"), &version)?;

    copy_dir_redacted(&log_dir(), &root.join("logs"), |_| true)?;
    copy_dir_redacted(&crash_dir(), &root.join("crashes"), |_| true)?;
    // macOS crash reports of the app (SluiceApp) and the core.
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    for dir in [home.join("Library/Logs/DiagnosticReports"), PathBuf::from("/Library/Logs/DiagnosticReports")] {
        copy_dir_redacted(&dir, &root.join("system-crashes"), |n| n.to_ascii_lowercase().contains("sluice"))?;
    }

    match config {
        Some(path) => {
            let text = fs::read_to_string(path).unwrap_or_else(|e| format!("# unreadable {path}: {e}\n"));
            write_redacted(&root.join("config.conf"), &text)?;
            let exe = std::env::current_exe()?;
            let exe = exe.to_string_lossy();
            write_redacted(&root.join("check.txt"), &capture(&exe, &["check", path], Duration::from_secs(30)))?;
        }
        None => fs::write(root.join("config.conf"), "# no config given\n")?,
    }

    let net = root.join("network");
    fs::create_dir_all(&net)?;
    let cmds: &[(&str, &str, &[&str])] = &[
        ("routes.txt", "netstat", &["-rn"]),
        ("dns.txt", "scutil", &["--dns"]),
        ("nwi.txt", "scutil", &["--nwi"]),
        ("proxy.txt", "scutil", &["--proxy"]),
        ("vpn.txt", "scutil", &["--nc", "list"]),
        ("interfaces.txt", "ifconfig", &["-a"]),
    ];
    for (file, prog, args) in cmds {
        write_redacted(&net.join(file), &capture(prog, args, short))?;
    }
    Ok(())
}

fn zip(root: &Path, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(out);
    let st = Command::new("/usr/bin/ditto")
        .args(["-c", "-k", "--keepParent"])
        .arg(root)
        .arg(out)
        .status()
        .context("run ditto")?;
    if !st.success() {
        bail!("ditto failed: {st}");
    }
    readable_by_all(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn assert_clean(out: &str, secrets: &[&str]) {
        for s in secrets {
            assert!(!out.contains(s), "{s:?} leaked in:\n{out}");
        }
    }

    #[test]
    fn proxy_lines_every_type() {
        let cfg = format!(
            "[Proxy]\n\
             SS = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=ss-pass-1\n\
             TJ = trojan, t.example.com, 443, password=tj-pass-2, sni=t.example.com, skip-cert-verify=true\n\
             VM = vmess, v.example.com, 443, username={UUID}, encrypt-method=auto, tls=true, ws=true, ws-path=/ray, ws-headers=Host:v.example.com|Authorization:Bearer tok-3\n\
             VL = vless, l.example.com, 443, uuid={UUID}, sni=www.apple.com, reality-public-key=PubKeyXyz123, reality-short-id=0123abcd, flow=xtls-rprx-vision\n\
             HY = hysteria2, h.example.com, 443, password=hy-pass-4, obfs=salamander, obfs-password=obfs-secret-5, port-hopping=443;20000-50000\n"
        );
        let out = redact(&cfg);
        assert_clean(&out, &["ss-pass-1", "tj-pass-2", UUID, "tok-3", "PubKeyXyz123", "0123abcd", "hy-pass-4", "obfs-secret-5"]);
        // Non-secret structure survives for debugging.
        for keep in ["encrypt-method=aes-256-gcm", "sni=t.example.com", "skip-cert-verify=true", "ws-path=/ray", "flow=xtls-rprx-vision", "port-hopping=443;20000-50000", "1.2.3.4, 8388"] {
            assert!(out.contains(keep), "{keep:?} lost in:\n{out}");
        }
    }

    #[test]
    fn share_links() {
        let links = [
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#HK",
            "ss://aes-256-gcm:plainpw@1.2.3.4:8388",
            "vmess://eyJhZGQiOiJ2LmV4YW1wbGUuY29tIiwiaWQiOiJzZWNyZXQifQ==",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@l.example.com:443?security=reality&pbk=PubKeyXyz123&sid=ab12#JP",
            "trojan://trojanpw@t.example.com:443?sni=t.example.com#US",
            "hysteria2://hypw@h.example.com:443?obfs=salamander&obfs-password=obfspw#SG",
            "hy2://hypw@h.example.com:443/?insecure=1",
            "tuic://tuicuser:tuicpw@x.example.com:443",
        ];
        for l in links {
            let out = redact(&format!("imported {l} ok"));
            assert_clean(&out, &["YWVz", "plainpw", "eyJh", UUID, "PubKeyXyz123", "trojanpw", "hypw", "obfspw", "tuicpw", "@"]);
            assert!(out.ends_with(" ok"), "{out}");
        }
    }

    #[test]
    fn subscription_urls() {
        let cases = [
            ("policy-path=https://sub.example.com/api/v1/client/subscribe?token=abcdef123456", "abcdef123456"),
            ("policy-path=https://sub.example.com/link/AbC9xYz8QwE7?clash=1", "AbC9xYz8QwE7"),
            ("fetching https://user:pw123@sub.example.com/s/xyz", "pw123"),
            ("GET https://sub.example.com/sub/8f3e2a1b9c7d6e5f", "8f3e2a1b9c7d6e5f"),
            ("url=https://example.com/s#frag-token", "frag-token"),
        ];
        for (input, secret) in cases {
            let out = redact(input);
            assert_clean(&out, &[secret]);
            assert!(out.contains("sub.example.com") || out.contains("example.com"), "{out}");
        }
        // Public, token-free URLs stay readable.
        assert_eq!(redact("https://1.1.1.1/dns-query"), "https://1.1.1.1/dns-query");
        assert_eq!(redact("http://www.gstatic.com/generate_204"), "http://www.gstatic.com/generate_204");
        assert_eq!(redact("file:///Users/me/rules.list"), "file:///Users/me/rules.list");
    }

    #[test]
    fn clash_yaml_and_json() {
        let yaml = format!(
            "proxies:\n  - {{name: a, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: yamlpw}}\n  - name: b\n    type: vless\n    uuid: {UUID}\n    reality-opts:\n      public-key: pkvalue\n      short-id: sid9\n    auth-str: authval\n"
        );
        let out = redact(&yaml);
        assert_clean(&out, &["yamlpw", UUID, "pkvalue", "sid9", "authval"]);
        assert!(out.contains("cipher: aes-128-gcm"));
        let json = r#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","password":"jsonpw"}],"privateKey":"privk"}"#;
        assert_clean(&redact(json), &["jsonpw", UUID, "privk"]);
    }

    #[test]
    fn mitm_and_misc_keys() {
        let text = "[MITM]\nca-passphrase = capass\nca-p12 = MIIKbase64blob\n[General]\napi-token=apitok\nX-Secret: hdrsecret\n";
        assert_clean(&redact(text), &["capass", "MIIKbase64blob", "apitok", "hdrsecret"]);
        // Booleans and already-masked values are left alone; idempotent.
        assert_eq!(redact("skip-cert-verify=true"), "skip-cert-verify=true");
        let once = redact("password=x, uuid=y");
        assert_eq!(redact(&once), once);
    }

    #[test]
    fn rotation_caps_size_and_count() {
        let dir = std::env::temp_dir().join(format!("sluice-rot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut log = RotatingLog::open(&dir, 100, 2).unwrap();
        for i in 0..50 {
            log.write_file(format!("line {i:03} padding padding\n").as_bytes()).unwrap();
        }
        let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into()).collect();
        names.sort();
        assert_eq!(names, ["sluice.1.log", "sluice.2.log", "sluice.log"]);
        for n in &names {
            assert!(fs::metadata(dir.join(n)).unwrap().len() <= 100);
        }
        assert!(fs::read_to_string(dir.join("sluice.log")).unwrap().contains("line 049"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn crash_report_redacts_config() {
        let dir = std::env::temp_dir().join(format!("sluice-crash-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("c.conf");
        fs::write(&cfg, "[Proxy]\nA = trojan, h, 443, password=crashpw\n").unwrap();
        let r = crash_report("boom at https://sub.example.com/x?token=t0k", Some(cfg.to_str().unwrap()));
        assert!(r.contains("1 proxies") && r.contains("backtrace:") && r.contains(VERSION));
        assert_clean(&r, &["crashpw", "t0k"]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
