# Offline local checks

Run `scripts/local-check.sh` from any directory. It prints a result for each
named check, writes logs and `summary.tsv` to `target/local-check` (override with
`OUT`), and exits nonzero if any check fails. Use `--help` for check names,
`--only routes,convert` for a subset, or repeat `--skip name` to exclude checks.
Missing tools or cached Swift dependencies are SKIP; real command failures
remain FAIL, including sandbox permission failures. The smoke check reports
SKIP explicitly when the sandbox forbids binding loopback sockets.

Cargo uses offline, locked resolution and private copies of its existing cache.
Swift uses the existing Sparkle checkout and binary artifact with automatic
resolution disabled. Install/cache dependencies separately before running.
Every check has a disposable HOME, including Foundation preferences and build
tool caches. App/DMG builds use the host architecture and ad-hoc signing.

`links.txt` covers every scheme supported by `subscription::parse_link`: SS,
VMess, VLESS (TLS and Reality), Trojan, Hysteria2 (both spellings), and AnyTLS.
The credentials are fake and all endpoints are loopback. SSR, TUIC, WireGuard,
and SOCKS/HTTP share links are currently unsupported. `clash.yaml` and
`surge.conf` exercise file subscription imports through CLI `check` and `route`.

`rules.conf` and `routes.json` assert each rule's name, policy and outbound,
including connection context supplied by the new optional `route` flags
`--process`, `--src`, `--proto`, `--in-port`, and `--url`. A tiny synthetic MMDB
generated in the temporary directory exercises GEOIP and IP-ASN without any
downloaded geodata. It maps IPv4 addresses to reserved country ZZ / ASN 64512.

Example configs are checked from temporary copies, replacing remote rule-list
or subscription sources with these local fixtures; substitutions are logged.
`check` does not activate their enhanced-mode settings, DNS upstreams or health
checks. `GeneratedConfigTests` dumps the app's actual starter config and each
structured group generator's output for CLI validation.

Diagnostics are unzipped and all files scanned for every credential derived
from the config, raw share links, and a fake subscription URL. The URL is in a
config comment so the export's nested `check` never fetches it.

The smoke check uses only DIRECT/REJECT, a select group and FINAL REJECT. It
asserts all control API routes, including PUT aliases and harmless mutations.
`/v1/events` is SSE: its status and JSON data frames are checked separately.
Closing a nonexistent connection deliberately expects 404. Node/group probes
explicitly target the loopback API. Finally it tests both proxy inbounds,
sends SIGTERM, requires exit within five seconds, and rebinds all three ports.
No check changes system proxy settings, runs networksetup, or enables TUN.
