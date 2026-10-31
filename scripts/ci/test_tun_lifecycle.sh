#!/bin/bash
# Exercise the real start/stop helpers without sudo, TUN, or network changes.
set -euo pipefail
source "$(dirname "$0")/tun_lifecycle.sh"
work=$(mktemp -d)
trap 'if (( pid > 0 )); then builtin kill -TERM "$pid" 2>/dev/null || true; fi; stop_watchdog; rm -rf "$work"' EXIT
pid=0
launcher=0
watchdog=0
uuid=test
conf=$work/lifecycle.conf
api_port=16470
http_port=16452
socks_port=16453
api=http://unused
core=$work/core
export MOCK_STATUS=$work/mock-status.json
cat > "$core" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import sys
import time

status = Path(os.environ['MOCK_STATUS'])
def stop(signum, frame):
    # Keep holding the resource after accepting the stop signal.
    time.sleep(0.25)
    status.unlink(missing_ok=True)
    sys.exit(0)
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, stop)
mode = 'enhanced-mode = true' in Path(sys.argv[2]).read_text()
if status.exists():
    sys.exit('previous core has not finished shutting down')
status.write_text(json.dumps({'pid': os.getpid(), 'ready': True, 'enhanced_mode': mode}))
while True:
    signal.pause()
PY
chmod +x "$core"
# Keep every fixture/log under the temporary directory.
cd "$work"
mkdir ci-logs
sudo() {
    case $1 in
        kill) shift; builtin kill "$@" ;;
        lsof) return 1 ;;
        *)
            # Model sudo retaining its own launcher PID and reaping the real core.
            "$@" &
            local child=$!
            wait "$child"
            command sleep 0.2
            ;;
    esac
}
kill() {
    # Model EPERM after sudo execs a root-owned core. This is deliberately distinct
    # from the privileged probe above, even though fixtures run as our own uid.
    if [[ $1 == -0 && $2 == "$launcher" && $mock_root == true ]]; then
        return 1
    fi
    builtin kill "$@"
}
curl() { [[ -s $MOCK_STATUS ]] && cat "$MOCK_STATUS"; }
netstat() { echo 'default 192.0.2.1 en0'; }
scutil() { echo 'nameserver[0] : 192.0.2.53'; }
sleep() {
    # Make a readiness regression hit its rescue deadline promptly.
    if [[ $1 == 90 ]]; then command sleep 3; else command sleep "$@"; fi
}

mock_root=false
write_config false
start_core false initial
for spec in 'true enabled' 'false disabled' 'true reenabled'; do
    read -r mode phase <<< "$spec"
    mock_root=$mode
    restart_mode "$mode" "$phase"
    if [[ $mode == true ]]; then
        [[ $pid != "$launcher" ]] || { echo 'FAIL fixture needs distinct sudo/core PIDs'; exit 1; }
        if kill -0 "$launcher" 2>/dev/null; then
            echo 'FAIL fixture did not simulate unprivileged EPERM'; exit 1
        fi
        sudo kill -0 "$launcher"
    fi
done
stop_core TERM
start_core true sigint
stop_core INT
start_core true sighup
stop_core HUP
[[ $pid == 0 && $launcher == 0 && $watchdog == 0 ]]

echo 'PASS distinct sudo/core PIDs, delayed exit, and back-to-back TERM/INT/HUP stops'
# A genuinely dead launcher must still fail fast and retain its exit status/log.
if (
    bash -c 'echo fixture-start-failure; exit 23' > "$work/failed.log" 2>&1 &
    launcher=$!
    wait "$launcher" || true
    wait_ready "$launcher" "$work/failed.log"
) > "$work/failure.txt" 2>&1; then
    echo 'FAIL dead launcher was accepted'; exit 1
fi
grep -Fq 'FAIL core exited before becoming ready (status 23)' "$work/failure.txt"
grep -Fq 'fixture-start-failure' "$work/failure.txt"
echo 'PASS dead launcher reports its exit status and log'

# An API response from a previous core must never replace the tracked exec PID.
command sleep 5 &
launcher=$!
pid=$launcher
echo "{\"pid\": $$, \"ready\": true}" > "$MOCK_STATUS"
if (wait_ready "$launcher" "$work/failed.log") > "$work/stale.txt" 2>&1; then
    echo 'FAIL stale API PID was accepted'; exit 1
fi
grep -Fq 'FAIL API belongs to pid' "$work/stale.txt"
builtin kill -TERM "$launcher"
wait "$launcher" 2>/dev/null || true
pid=0
launcher=0
rm "$MOCK_STATUS"
echo 'PASS stale API PID rejected'

# A hung real core must fail boundedly, without clearing ownership or restarting.
if (
    pid=12345
    launcher=23456
    sudo() { return 0; }
    sleep() { :; }
    stop_core
) > "$work/hung.txt" 2>&1; then
    echo 'FAIL hung core was accepted as stopped'; exit 1
fi
grep -Fq 'FAIL core/launcher did not exit within 12 seconds' "$work/hung.txt"
echo 'PASS hung core stop fails boundedly'

# Verify both protocol checks invoke the raw UDP client and require TUN evidence.
assert_selection() { [[ $1 == "$expected_protocol" ]]; }
python3() {
    [[ $* == "-I scripts/ci/tun_udp_check.py client $expected_host 19302" ]] || exit 1
}
for expected_protocol in VMess VLESS; do
    expected_host=$(echo "$expected_protocol" | tr '[:upper:]' '[:lower:]').sluice.test
    log=ci-logs/tun-lifecycle-fixture.log
    echo "UDP $expected_host:19302 (Python) -> Proxy [FINAL] via $expected_protocol" > "$log"
    if (check_tun_stun "$expected_protocol" fixture "$expected_host") > "$work/missing-tun.txt" 2>&1; then
        echo 'FAIL SOCKS-only evidence was accepted as TUN'; exit 1
    fi
    grep -Fq "FAIL missing $expected_protocol TUN-path evidence" "$work/missing-tun.txt"
    echo "TUN UDP $expected_host:19302: first reply from $expected_host:19302 written to TUN (32 bytes)" >> "$log"
    check_tun_stun "$expected_protocol" fixture "$expected_host"
done
echo 'All unprivileged lifecycle helper checks passed.'
