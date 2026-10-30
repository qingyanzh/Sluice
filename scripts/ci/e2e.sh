#!/bin/bash
# Real-use control API + editor/app hooks. Network activity belongs on the CI VM only.
# Hook contract: <api host:port> <absolute work dir>; the core and traffic stay alive.
set -euo pipefail
cd "$(dirname "$0")/../.."
work="$PWD/ci-logs/e2e"
mkdir -p "$work/screenshots"
if [[ ${GITHUB_ACTIONS:-} != true ]]; then
    echo 'FAIL e2e: network checks may only run on GitHub Actions' >&2
    exit 1
fi
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

pids=()
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ ${#pids[@]} -gt 0 ]]; then
        kill "${pids[@]}" 2>/dev/null || true
        # Bound cleanup even when a server fails to respond to SIGTERM.
        for _ in {1..30}; do
            local alive=0
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then alive=1; fi
            done
            [[ $alive == 0 ]] && break
            sleep 0.1
        done
        kill -KILL "${pids[@]}" 2>/dev/null || true
        for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    fi
    if [[ $status != 0 ]]; then
        echo "FAIL e2e (exit $status); diagnostics retained in $work"
        for log in sluice ss xray hysteria http traffic; do
            if [[ -f "$work/$log.log" ]]; then
                echo "== $log (last 20 lines)"
                tail -20 "$work/$log.log"
            fi
        done
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Track each stage so interruption reaches its cleanup; retain and print its log.
run_logged() {
    local log=$1
    shift
    local index=${#pids[@]}
    "$@" > "$log" 2>&1 &
    local pid=$!
    pids+=("$pid")
    local status=0
    wait "$pid" || status=$?
    unset "pids[$index]"
    cat "$log"
    return "$status"
}

uuid=b831381d-6324-4d53-ad4f-8cda48b30811
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" \
    -days 1 -subj '/CN=test.local' -addext 'subjectAltName=DNS:test.local' > "$work/openssl.log" 2>&1
cat > "$work/xray.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[
 {"listen":"127.0.0.1","port":19001,"protocol":"vmess","settings":{"clients":[{"id":"$uuid"}]}},
 {"listen":"127.0.0.1","port":19002,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"}}
],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
EOF
cat > "$work/hysteria.yaml" <<EOF
listen: 127.0.0.1:19443
tls:
  cert: $work/cert.pem
  key: $work/key.pem
auth:
  type: password
  password: hy
EOF
cat > "$work/main.conf" <<EOF
[General]
socks5-listen = 127.0.0.1:16253
api-listen = 127.0.0.1:16270
[Proxy]
SS-AES256 = ss, 127.0.0.1, 18388, encrypt-method=aes-256-gcm, password=ss
VMess = vmess, 127.0.0.1, 19001, username=$uuid
VLESS = vless, 127.0.0.1, 19002, uuid=$uuid
Hysteria2 = hysteria2, 127.0.0.1, 19443, password=hy, sni=test.local, skip-cert-verify=true
Broken = ss, 127.0.0.1, 18388, encrypt-method=aes-256-gcm, password=deliberately-wrong
[Proxy Group]
P = select, SS-AES256, VMess, VLESS, Hysteria2, DIRECT, Broken
[Rule]
FINAL,P
EOF
sed 's/^FINAL,P$/FINAL,DIRECT/' "$work/main.conf" > "$work/alt.conf"
# Available to both hooks, which can also use /health and /download on this URL.
export E2E_API=127.0.0.1:16270 E2E_SOCKS=127.0.0.1:16253 E2E_HTTP_URL=http://127.0.0.1:18080
cat > "$work/fixtures.txt" <<EOF
API: $E2E_API
SOCKS5: $E2E_SOCKS
HTTP: $E2E_HTTP_URL (/health; /download is 64 MiB, throttled to at most 256 KiB/s)
main.conf: FINAL,P -> SS-AES256; alt.conf: FINAL,DIRECT
Nodes: SS-AES256, VMess, VLESS, Hysteria2, Broken (wrong SS password)
EOF
./target/release/sluice check "$work/main.conf" > "$work/config-check.log" 2>&1
./target/release/sluice check "$work/alt.conf" >> "$work/config-check.log" 2>&1

ssserver -s 127.0.0.1:18388 -m aes-256-gcm -k ss -U > "$work/ss.log" 2>&1 &
pids+=("$!")
xray run -c "$work/xray.json" > "$work/xray.log" 2>&1 &
pids+=("$!")
hysteria server -c "$work/hysteria.yaml" > "$work/hysteria.log" 2>&1 &
pids+=("$!")
python3 -I scripts/ci/e2e_api.py --serve > "$work/http.log" 2>&1 &
pids+=("$!")
RUST_LOG=sluice=info ./target/release/sluice run "$work/main.conf" > "$work/sluice.log" 2>&1 &
core_pid=$!
pids+=("$core_pid")

ready=0
for _ in {1..60}; do
    if curl --disable -fsS --max-time 1 "$E2E_HTTP_URL/health" > /dev/null 2>&1 \
        && curl --disable -fsS --max-time 1 "http://$E2E_API/v1/profile" > "$work/initial-profile.json" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$core_pid" 2>/dev/null || break
    sleep 0.5
done
if [[ $ready != 1 ]]; then echo 'FAIL fixture/core startup'; exit 1; fi
for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then echo "FAIL fixture process $pid exited"; exit 1; fi
done
echo 'PASS fixture/core startup'

fails=0
if ! run_logged "$work/api.log" python3 -I scripts/ci/e2e_api.py "$E2E_API" "$E2E_SOCKS" "$work"; then
    fails=$((fails + 1))
fi

# The generator owns/reaps its curl children, including on signal or hook failure.
python3 -I scripts/ci/e2e_api.py --traffic "$E2E_SOCKS" > "$work/traffic.log" 2>&1 &
traffic_pid=$!
pids+=("$traffic_pid")
sleep 2
for hook in editor screens; do
    if [[ -f "scripts/ci/e2e_$hook.sh" ]]; then
        if ! python3 -I scripts/ci/e2e_api.py --wait-traffic "$E2E_API" 2>&1 | tee "$work/traffic-$hook.log"; then
            echo "FAIL background traffic before $hook hook"
            fails=$((fails + 1))
        fi
        if run_logged "$work/$hook.log" bash "scripts/ci/e2e_$hook.sh" "$E2E_API" "$work"; then
            echo "PASS $hook hook"
        else
            echo "FAIL $hook hook"
            fails=$((fails + 1))
        fi
    else
        echo "SKIP $hook hook (not present on this branch)"
    fi
    for pid in "$core_pid" "$traffic_pid"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "FAIL process $pid exited during $hook hook"
            fails=$((fails + 1))
        fi
    done
done
if [[ $fails != 0 ]]; then echo "FAIL e2e: $fails stage(s) failed"; exit 1; fi
echo 'PASS e2e: all available stages passed'
