#!/bin/bash
# Runs only on disposable macOS CI runners. Mirrors the app: stop, wait, start in
# the new mode. All selection state belongs to the core, shared across uid changes.
cleanup() {
    # Startup can fail before /v1/status; the exec wrapper still records the real PID.
    if [[ -s ${core_pid_file:-} ]]; then read -r pid < "$core_pid_file"; fi
    if (( pid > 0 )); then
        sudo kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 100); do
            sudo kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
    fi
    stop_watchdog
    if (( server > 0 )); then kill "$server" 2>/dev/null || true; fi
    if (( responder > 0 )); then kill "$responder" 2>/dev/null || true; fi
    exec 1>&3 2>&1
    cat "$out"
}
write_config() {
    cat > "$conf" <<EOF
[General]
loglevel = debug
http-listen = 127.0.0.1:$http_port
socks5-listen = 127.0.0.1:$socks_port
api-listen = 127.0.0.1:$api_port
enhanced-mode = $1
[Proxy]
VMess = vmess, 127.0.0.1, 19001, username=$uuid
VLESS = vless, 127.0.0.1, 19002, uuid=$uuid
[Proxy Group]
Proxy = select, DIRECT, VMess, VLESS
[Rule]
FINAL,Proxy
EOF
}
wait_ready() {
    local launcher=$1 log=$2
    for _ in $(seq 600); do
        if [[ -s ${core_pid_file:-} ]]; then read -r pid < "$core_pid_file"; fi
        # sudo may exec the core, making $! root-owned. Unprivileged kill -0
        # returns EPERM for that live process; waiting here then hangs until the
        # watchdog terminates a healthy core. Probe with the same uid as stop.
        if ! sudo kill -0 "$launcher" 2>/dev/null; then
            local status=0
            wait "$launcher" || status=$?
            echo "FAIL core exited before becoming ready (status $status)"
            cat "$log"
            lifecycle_diagnostics
            exit 1
        fi
        if curl -fsS -m 1 "$api/v1/status" > "$work/status.json" 2>/dev/null; then
            local reported
            reported=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$work/status.json")
            if [[ $reported != "$pid" ]]; then
                echo "FAIL API belongs to pid $reported, expected core $pid (launcher $launcher)"
                lifecycle_diagnostics
                exit 1
            fi
            if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["ready"] else 1)' "$work/status.json"; then return; fi
        fi
        sleep 0.1
    done
    echo 'FAIL core did not start'; cat "$log"; lifecycle_diagnostics; exit 1
}
lifecycle_diagnostics() {
    echo "Lifecycle: core pid $pid, launcher pid $launcher"
    ps -p "$pid,$launcher" -o pid,ppid,uid,state,command || true
    # Include non-LISTEN states to distinguish a live owner from TIME_WAIT.
    sudo lsof -nP -iTCP:"$api_port" || true
    netstat -anv -p tcp | grep -E "[.:]$api_port[[:space:]]" || true
}
assert_clean() {
    # Dynamic DNS propagation can lag a completed networksetup call slightly.
    for _ in $(seq 30); do
        netstat -rn > "$work/routes-after.txt"
        scutil --dns > "$work/dns-after.txt"
        if ! grep -Eq '(^198\.18|^(0/1|128\.0/1|::/1|8000::/1).*utun)' "$work/routes-after.txt" &&
           ! grep -q '198.18.0.2' "$work/dns-after.txt"; then
            echo 'PASS routes and DNS restored'; return
        fi
        sleep 0.1
    done
    cat "$work/routes-after.txt" "$work/dns-after.txt"
    echo 'FAIL stale TUN routes or DNS'; exit 1
}
assert_selection() {
    curl -fsS "$api/v1/policies" | python3 -c 'import json,sys; g=next(g for g in json.load(sys.stdin) if g["group"]=="Proxy"); assert g["selected"]==sys.argv[1], g' "$1"
    echo "PASS selection $1 retained"
}
stop_core() {
    local old=$pid
    echo "Stopping core pid $old (launcher $launcher) with ${1:-TERM}"
    sudo kill -"${1:-TERM}" "$old"
    for _ in $(seq 120); do
        # sudo's PID can differ from the core; both must finish before restart.
        if ! sudo kill -0 "$old" 2>/dev/null && ! sudo kill -0 "$launcher" 2>/dev/null; then
            wait "$launcher" || true
            echo "PASS core pid $old and launcher $launcher exited"
            pid=0
            launcher=0
            core_pid_file=
            stop_watchdog
            assert_clean
            return
        fi
        sleep 0.1
    done
    echo 'FAIL core/launcher did not exit within 12 seconds'; lifecycle_diagnostics; exit 1
}
stop_watchdog() {
    if (( watchdog > 0 )); then
        kill "$watchdog" 2>/dev/null || true
        wait "$watchdog" 2>/dev/null || true
        watchdog=0
    fi
}
start_core() {
    local log=ci-logs/tun-lifecycle-$2.log port
    for port in "$api_port" "$http_port" "$socks_port"; do
        if sudo lsof -nP -iTCP:"$port" -sTCP:LISTEN > "$work/listeners.txt"; then
            echo "FAIL lifecycle port $port is already in use"
            cat "$work/listeners.txt"
            exit 1
        fi
    done
    core_pid_file=$work/core-$2.pid
    rm -f "$core_pid_file"
    # Record the exec PID inside sudo, rather than assuming $! is the core.
    if [[ $1 == true ]]; then
        sudo /bin/sh -c 'echo $$ > "$1"; exec "$2" run "$3"' sh "$core_pid_file" "$core" "$conf" > "$log" 2>&1 &
    else
        /bin/sh -c 'echo $$ > "$1"; exec "$2" run "$3"' sh "$core_pid_file" "$core" "$conf" > "$log" 2>&1 &
    fi
    launcher=$!
    pid=$launcher
    # Independent rescue even if a client/test hangs while GitHub is routed via utun.
    (sleep 90; if [[ -s $core_pid_file ]]; then read -r pid < "$core_pid_file"; fi; sudo kill -TERM "$pid" 2>/dev/null || true) & watchdog=$!
    wait_ready "$launcher" "$log"
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["enhanced_mode"] == (sys.argv[2] == "true")' "$work/status.json" "$1"
}
restart_mode() {
    # Write first as the app does. Its reload path now restarts before calling reload.
    write_config "$1"
    stop_core
    start_core "$1" "$2"
}
check_tun_stun() {
    local protocol=$1 phase=$2 host=$3 log=ci-logs/tun-lifecycle-$2.log
    assert_selection "$protocol"
    # This client uses a plain UDP socket to a fake IP, never a SOCKS relay.
    python3 -I scripts/ci/tun_udp_check.py client "$host" 19302
    # Also prove which inbound and outbound handled the reply in this core run.
    # The client can receive the packet before the core finishes writing its log.
    for _ in $(seq 30); do
        if grep -F "UDP $host:19302 (" "$log" | grep -F "via $protocol" > /dev/null &&
           grep -Fq "TUN UDP $host:19302: first reply from" "$log"; then
            echo "PASS $protocol STUN entered utun and returned through TUN ($phase)"
            return
        fi
        sleep 0.1
    done
    echo "FAIL missing $protocol TUN-path evidence ($phase)"
    cat "$log"
    exit 1
}
main() {
    set -euo pipefail
    cd "$(dirname "${BASH_SOURCE[0]}")/../.."
    work=$(mktemp -d)
    mkdir -p ci-logs
    out=ci-logs/tun-lifecycle-output.txt
    exec 3>&1 > "$out" 2>&1
    core=$PWD/target/release/sluice
    pid=0
    launcher=0
    server=0
    responder=0
    watchdog=0
    trap cleanup EXIT
    uuid=b831381d-6324-4d53-ad4f-8cda48b30811
    conf=$work/lifecycle.conf
    # Keep lifecycle listeners separate from tun.sh and the other CI scripts.
    api_port=16470
    http_port=16452
    socks_port=16453
    api=http://127.0.0.1:$api_port
    python3 -I scripts/ci/tun_udp_check.py server 127.0.0.1 19302 > ci-logs/tun-stun-server.log 2>&1 & responder=$!
    # Only the server side uses loopback, so Xray's outbound cannot re-enter TUN. The
    # client still resolves these names to fake IPs and must traverse Sluice's UDP path.
    # Xray now blocks private destinations by default: allow just this UDP responder.
    # Drop unrelated system traffic rather than recursively proxying it back into TUN.
    cat > "$work/xray.json" <<EOF
{"log":{"loglevel":"debug"},
 "dns":{"hosts":{"vmess.sluice.test":"127.0.0.1","vless.sluice.test":"127.0.0.1"},"servers":[]},
 "inbounds":[
 {"listen":"127.0.0.1","port":19001,"protocol":"vmess","settings":{"clients":[{"id":"$uuid"}]}},
 {"listen":"127.0.0.1","port":19002,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"}}],
 "outbounds":[
 {"tag":"drop","protocol":"blackhole"},
 {"tag":"stun","protocol":"freedom",
  "settings":{"finalRules":[{"action":"allow","network":"udp","ip":["127.0.0.1/32"],"port":"19302"}]},
  "streamSettings":{"sockopt":{"domainStrategy":"UseIPv4"}}}],
 "routing":{"rules":[{"type":"field","network":"udp","port":"19302",
  "domain":["full:vmess.sluice.test","full:vless.sluice.test"],"outboundTag":"stun"}]}}
EOF
    xray run -c "$work/xray.json" > ci-logs/tun-xray.log 2>&1 & server=$!
    sleep 1
    kill -0 "$server" "$responder"
    write_config false
    start_core false initial
    curl -fsS -X POST "$api/v1/policies/Proxy?select=VMess"
    # Prove the responder and both proxy protocols work before changing routes/DNS.
    python3 -I scripts/ci/tun_udp_check.py proxy vmess.sluice.test 19302 "$socks_port"
    curl -fsS -X POST "$api/v1/policies/Proxy?select=VLESS"
    python3 -I scripts/ci/tun_udp_check.py proxy vless.sluice.test 19302 "$socks_port"
    curl -fsS -X POST "$api/v1/policies/Proxy?select=VMess"
    restart_mode true enabled
    check_tun_stun VMess enabled vmess.sluice.test
    restart_mode false disabled
    assert_selection VMess
    assert_clean
    restart_mode true reenabled
    assert_selection VMess
    curl -fsS -X POST "$api/v1/policies/Proxy?select=VLESS"
    check_tun_stun VLESS reenabled vless.sluice.test
    # Root termination and network cleanup, with live TUN tasks.
    stop_core TERM
    start_core true sigint
    assert_selection VLESS
    stop_core INT
    start_core true sighup
    stop_core HUP
    echo 'All TUN lifecycle / VMess / VLESS checks passed.'
}

# Source the lifecycle helpers for unprivileged regression tests.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
