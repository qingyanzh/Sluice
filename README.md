# Sluice

Rule-based network proxy (command-line core and macOS TUN mode).

## Usage

```bash
cargo build --release
./target/release/sluice check examples/sluice.conf
./target/release/sluice route examples/sluice.conf www.google.com
./target/release/sluice run examples/sluice.conf
```

Then point the system or app proxy at `127.0.0.1:6152` (HTTP) or `127.0.0.1:6153` (SOCKS5).

## M1 features

- Inbound: HTTP proxy (CONNECT and plain HTTP), SOCKS5 (CONNECT and UDP ASSOCIATE, no auth)
- Outbound: DIRECT, REJECT, Shadowsocks AEAD (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305), Trojan, VLESS (TCP, optional TLS or REALITY: `reality-public-key=…, reality-short-id=…, sni=<site it impersonates>`), VMess AEAD (alterId 0; auto / aes-128-gcm / chacha20-poly1305; optional TLS), Hysteria2 (one shared QUIC connection per server; optional Salamander obfuscation: `obfs=salamander, obfs-password=…`)
- Transports for VMess / VLESS / Trojan: TCP, TLS, WebSocket (`ws=true, ws-path=/path, ws-headers=Host:cdn.example.com`), WebSocket over TLS, gRPC (`grpc=true, grpc-service-name=…`; Xray "gun")
- UDP over every outbound:
  - DIRECT
  - Shadowsocks (per-packet AEAD)
  - VMess (one packet per chunk)
  - VLESS (length-prefixed)
  - Trojan (UDP ASSOCIATE framing)
  - Hysteria2 (QUIC datagrams, with fragmentation)
- Rules: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR / IP-CIDR6 (`no-resolve`), GEOIP (needs `geoip-db`), FINAL
- More rules: PROCESS-NAME (owning process of the client socket, via libproc; in TUN mode other users' processes need root), DST-PORT (`443`, `8000-9000`, `>1024`), IN-PORT, SRC-IP, PROTOCOL (TCP/UDP/HTTP/HTTPS/QUIC), URL-REGEX (full URL for plain HTTP through the HTTP inbound, `https://host/` for CONNECT), IP-ASN (needs `asn-db`, e.g. GeoLite2-ASN.mmdb), and logical `AND,((DOMAIN,a.com),(DST-PORT,443)),Proxy` / `OR` / `NOT`. All of these also work inside RULE-SET files
- `GET /v1/connections` lists recent routing decisions (with `process` when a PROCESS-NAME rule looked it up); `/v1/route` accepts `process=`, `src=` and `proto=`
- Rule sets: `RULE-SET,<url|file>,Policy` (Surge rule lists) and `DOMAIN-SET,<url|file>,Policy` (domain lists, `.example.com` = with subdomains; Clash `payload:` lists also accepted). Remote lists are cached in `~/Library/Caches/Sluice` and refreshed every `rule-set-update-interval` seconds (default 86400).
- Subscriptions: `Group = select, policy-path=<url|file>, policy-regex-filter=<regex>, update-interval=86400` imports nodes from share links (`ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`, plain or base64), Surge proxy lines, or Clash / Mihomo YAML (`proxies:`). Links needing unsupported features (XTLS-Vision flow, Hysteria2 port hopping) are skipped and reported. Groups sharing a URL share its nodes.
- Policy groups (nestable):
  - `select`: switchable at runtime
  - `url-test`: lowest latency, with `tolerance` to avoid flapping
  - `fallback`: first healthy option in order
  - `load-balance`: random among healthy options per connection
  - Automatic groups probe `url` (default `http://www.gstatic.com/generate_204`) every `interval` seconds through each option
- Control API (`api-listen`):
  - `GET /v1/policies`
  - `POST /v1/policies/<group>?select=<option>`
  - `POST /v1/policies/<group>/test` (run a health check now)
  - `GET /v1/route?target=host:port`
  - `POST /v1/reload`
  - `GET /v1/traffic` (bytes up and down, open connections)

## HTTPS decryption and rewriting

`sluice mitm gen-ca` creates a CA in `~/Library/Application Support/Sluice` (`ca.crt`,
`ca.key`). Sluice never installs it; trust it yourself with the
`sudo security add-trusted-cert ...` command it prints. Then:

```ini
[MITM]
hostname = *.example.com, example.com, -skip.example.com   # host[:port], default port 443
# ca-p12 = <base64 or path>   ca-passphrase = ...   (or ca-cert / ca-key PEM paths)
skip-server-cert-verify = false
h2 = true

[URL Rewrite]
^https?://example\.com/old https://example.com/new 302      # 302 | 307 | reject | header

[Header Rewrite]
http-request ^https://example\.com/ header-add X-Foo bar      # header-add | header-del | header-replace
http-response ^https://example\.com/ header-del Server

[Body Rewrite]
http-response ^https://example\.com/ "Example Domain" "Sluice Domain"
```

Decryption covers the HTTP and SOCKS5 inbounds and enhanced mode. Rewrites also apply to
plain HTTP. Each decrypted request is routed separately, so URL-REGEX rules see the full
`https://` URL. In `/v1/connections` these requests show up with `url` and `"mitm": true`.

## macOS app

`scripts/build-app.sh` builds `dist/Sluice.app`, a SwiftUI app with the core embedded. It runs the
core as a child process and controls it through the control API, so the config needs `api-listen`.

- **Overview**: start, stop and restart Sluice, reload the config, turn the system proxy on or off
  (asks for an administrator password), and see listen addresses.
- **Policies**: switch `select` groups, see latency, and run health checks.
- **Nodes**: add a node from a share link or proxy line, or add a subscription (URL plus an
  optional name filter). New nodes and subscriptions join the group FINAL points at.
- **Connections** and **Logs**: live, with filtering.
- **Route Test**: show which rule and outbound a host would use.
- **Config**: edit the file. Changes are validated with `sluice check` before saving, then applied
  by hot reload.
- **Menu bar**: status, start and stop, group selection, and the system proxy toggle.
- **Enhanced mode**: if the config sets `enhanced-mode = true`, the app starts the core as root
  after a standard administrator prompt and follows its log in `~/Library/Logs/Sluice`.

The default config lives in `~/Library/Application Support/Sluice/sluice.conf`, and is created on
first launch.

`sluice convert <share-link>` prints a share link as a `[Proxy]` line.

## Hot reload

Sluice reloads the config, without dropping connections, in these cases:
- the config file changes (checked every 2 s)
- it receives `SIGHUP`
- `POST /v1/reload` is called
- a subscription's `update-interval` elapses

New connections use the new config, and existing ones finish on the old one. A config with
errors is rejected and the running one is kept. Manual choices in groups, and health-check
results, carry over wherever the group and option still exist. Listen addresses and
enhanced-mode settings only apply after a restart.

## Enhanced mode (M2, macOS)

Set `enhanced-mode = true` and run with `sudo`. Sluice creates a utun device and routes
`0.0.0.0/1` and `128.0.0.0/1` into it. It also points every network service's DNS at a fake-IP
server (`198.18.0.2`), so domain rules still work for apps that ignore proxy settings.

Sluice's own connections are bound to the physical interface (`IP_BOUND_IF`) and use the
real upstream DNS, so they never loop back into the TUN. Routes and DNS are restored on exit.
After a crash, the next start restores DNS from `/var/tmp/sluice-dns-backup`.

If the physical interface is the primary one, Sluice adds a default route scoped to it while
running, because macOS keeps none in that case and the bound sockets would otherwise hit the TUN routes.

To check a running setup, use `scripts/tun-check.sh`, then `scripts/tun-check.sh after` once Sluice
has stopped. `scripts/tun-diag.sh` shows how the kernel routes bound sockets. Verified on macOS:
TCP, UDP, fake-IP DNS, rules, and cleanup.

If the Mac has an IPv6 default route, IPv6 is captured as well (`::/1` and `8000::/1`). Fake-IP DNS still answers AAAA queries empty, so domain names use IPv4, while apps that connect to IPv6 addresses directly go through Sluice instead of around it.

Not yet: XTLS-Vision, Hysteria2 port hopping, more protocols (TUIC, WireGuard), MITM, scripts, GUI, Network Extension packaging.
