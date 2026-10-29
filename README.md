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
- Outbound: DIRECT, REJECT, Shadowsocks AEAD (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305), Trojan, VLESS (TCP, optional TLS), VMess AEAD (alterId 0; auto / aes-128-gcm / chacha20-poly1305; optional TLS), Hysteria2 (TCP; one shared QUIC connection per server)
- Transports for VMess / VLESS / Trojan: TCP, TLS, WebSocket (`ws=true, ws-path=/path, ws-headers=Host:cdn.example.com`), WebSocket over TLS
- UDP over every outbound:
  - DIRECT
  - Shadowsocks (per-packet AEAD)
  - VMess (one packet per chunk)
  - VLESS (length-prefixed)
  - Trojan (UDP ASSOCIATE framing)
  - Hysteria2 (QUIC datagrams, with fragmentation)
- Rules: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR / IP-CIDR6 (`no-resolve`), GEOIP (needs `geoip-db`), FINAL
- Rule sets: `RULE-SET,<url|file>,Policy` (Surge rule lists) and `DOMAIN-SET,<url|file>,Policy` (domain lists, `.example.com` = with subdomains; Clash `payload:` lists also accepted). Remote lists are cached in `~/Library/Caches/Sluice` and refreshed every `rule-set-update-interval` seconds (default 86400).
- Subscriptions: `Group = select, policy-path=<url|file>, policy-regex-filter=<regex>, update-interval=86400` imports nodes from share links (`ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`, plain or base64) or Surge proxy lines. Links needing unsupported features (REALITY, XTLS flow, gRPC, Hysteria2 obfs) are skipped and reported. Groups sharing a URL share its nodes.
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

Limits: IPv4 only.

Not yet: IPv6 capture, Hysteria2 obfs / port hopping, more protocols (TUIC, WireGuard), gRPC/REALITY transports, MITM, scripts, GUI, Network Extension packaging.
