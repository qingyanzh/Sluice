#!/bin/bash
# GitHub Actions macos-15: subscription fetching and imported AnyTLS nodes, entirely
# against loopback fixtures. Needs sing-box and a built ./target/release/sluice.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p ci-logs
work=$(mktemp -d)
cleanup() {
    status=$?
    trap - EXIT
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    if [ "$status" != 0 ]; then
        for log in ci-logs/subscription-*.log; do
            echo "== $log"; tail -60 "$log"
        done
    fi
    exit "$status"
}
trap cleanup EXIT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

api=http://127.0.0.1:16570
source_url=http://127.0.0.1:16580
password=subscription-anytls-ci
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 \
    -subj "/CN=test.local" -addext "subjectAltName=DNS:test.local" 2>ci-logs/subscription-openssl.log
cat > "$work/anytls.json" <<EOF
{"log":{"level":"info"},
 "inbounds":[{"type":"anytls","listen":"127.0.0.1","listen_port":19460,
   "users":[{"password":"$password"}],
   "tls":{"enabled":true,"certificate_path":"$work/cert.pem","key_path":"$work/key.pem"}}],
 "outbounds":[{"type":"direct"}]}
EOF
cat > "$work/sluice.conf" <<EOF
[General]
socks5-listen = 127.0.0.1:16553
api-listen = 127.0.0.1:16570
[Proxy Group]
Clash = select, policy-path=$source_url/clash
Gzip = select, policy-path=$source_url/gzip
Redirect = select, policy-path=$source_url/redirect
Surge = select, policy-path=$source_url/surge
Denied = select, policy-path=$source_url/clash, user-agent=curl/8
P = select, Clash, Gzip, Redirect, Surge
[Rule]
FINAL,P
EOF

wait_http() { # URL, server PID; fail promptly when a server exits.
    for _ in $(seq 40); do
        kill -0 "$2" 2>/dev/null || return 1
        if curl -fsS -m 2 -o /dev/null "$1" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    echo "Timed out waiting for $1" >&2
    return 1
}

sing-box check -c "$work/anytls.json"
sing-box run -c "$work/anytls.json" > ci-logs/subscription-sing-box.log 2>&1 &
sing_box_pid=$!
python3 -u -I scripts/ci/fake_sub_server.py 16580 19460 "$password" > ci-logs/subscription-server.log 2>&1 &
wait_http "$source_url/healthz" "$!"
# Check the AnyTLS listener before Sluice starts so a server startup failure is clear.
python3 -I - <<'PY'
import socket
import time

for attempt in range(40):
    try:
        with socket.create_connection(("127.0.0.1", 19460), timeout=0.5):
            break
    except OSError:
        if attempt == 39:
            raise
        time.sleep(0.5)
PY
kill -0 "$sing_box_pid"
RUST_LOG=sluice=debug ./target/release/sluice run "$work/sluice.conf" > ci-logs/subscription-sluice.log 2>&1 &
wait_http "$api/v1/policies" "$!"

python3 -I - "$api" "$source_url" <<'PY' | tee ci-logs/subscription-checks.log
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse
import urllib.request

api, source_url = sys.argv[1:]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method, path):
    req = urllib.request.Request(api + path, method=method)
    with opener.open(req, timeout=10) as response:
        assert response.status == 200, (path, response.status)
        return json.load(response)


def check(name, ok, detail):
    assert ok, f"FAIL {name}: {detail}"
    print(f"PASS {name}", flush=True)


subscriptions = call("GET", "/v1/subscriptions")
policies = call("GET", "/v1/policies")
for name, data in (("subscriptions", subscriptions), ("policies", policies)):
    Path(f"ci-logs/subscription-{name}.json").write_text(json.dumps(data, indent=2))
subs = {item["group"]: item for item in subscriptions}
groups = {item["group"]: item for item in policies}
check("all subscription groups reported", set(subs) == {"Clash", "Gzip", "Redirect", "Surge", "Denied"}, subscriptions)

expected_metadata = {"upload": 1, "download": 2, "total": 1073741824,
                     "expire": 4102444800, "update_interval_hours": 24}
# The same two YAML node names occur in three independent sources. Expansion
# disambiguates later imports, and every group's exact options must survive.
expected_nodes = {
    "Clash": ["AnyTLS-A", "AnyTLS-B"],
    "Gzip": ["AnyTLS-A 2", "AnyTLS-B 2"],
    "Redirect": ["AnyTLS-A 3", "AnyTLS-B 3"],
    "Surge": ["Surge-AnyTLS"],
}
paths = {"Clash": "/clash", "Gzip": "/gzip", "Redirect": "/redirect", "Surge": "/surge"}
for group, nodes in expected_nodes.items():
    sub = subs[group]
    check(f"{group} source and node_count", sub["url"] == source_url + paths[group]
          and sub["node_count"] == len(nodes), sub)
    check(f"{group} usage/expiry/update interval", all(sub[key] == value for key, value in expected_metadata.items()), sub)
    fetched = sub["last_fetch"]
    check(f"{group} successful fetch", sub["last_error"] is None and isinstance(fetched, int)
          and 0 < fetched <= int(time.time()), sub)
    check(f"{group} imported policies", [option["name"] for option in groups[group]["options"]] == nodes, groups[group])

denied = subs["Denied"]
check("curl/8 override reports HTTP 403", denied["url"] == source_url + "/clash"
      and denied["node_count"] == 0 and "403" in (denied["last_error"] or "")
      and "禁止访问" in denied["last_error"], denied)
check("denied subscription imports no nodes", [option["name"] for option in groups["Denied"]["options"]] == ["REJECT"], groups["Denied"])
check("managed profile imports only [Proxy]", set(groups) == set(subs) | {"P"}, policies)

# Select and use every imported node, including the redirected gzip and Surge
# imports. A closed request remains visible in /v1/connections with its outbound.
for group, nodes in expected_nodes.items():
    call("POST", "/v1/policies/P?" + urllib.parse.urlencode({"select": group}))
    for node in nodes:
        call("POST", f"/v1/policies/{group}?" + urllib.parse.urlencode({"select": node}))
        result = subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
            "--noproxy", "", "--socks5-hostname", "127.0.0.1:16553", source_url + "/origin",
        ], check=True, stdout=subprocess.PIPE)
        check(f"{group}/{node} HTTP via AnyTLS", result.stdout == b"sluice subscription AnyTLS origin\n", result.stdout)
        connections = call("GET", "/v1/connections")
        hits = [conn for conn in connections if conn["target"] == "127.0.0.1:16580"]
        check(f"{group}/{node} routed outbound", bool(hits) and hits[-1]["policy"] == "P"
              and hits[-1]["outbound"] == node, hits[-1:] or connections)

print("All subscription checks passed.", flush=True)
PY
