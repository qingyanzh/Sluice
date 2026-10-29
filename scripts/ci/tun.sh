#!/bin/bash
# Enhanced (TUN) mode end to end on a proxy-free machine with passwordless sudo:
#   1. all traffic DIRECT (examples/tun-test.conf)
#   2. all traffic through a Shadowsocks node, with UDP
# Each run uses scripts/tun-check.sh while Sluice runs and `tun-check.sh after` once it stops.
# Needs: ssserver on PATH and a built ./target/release/sluice.
#
# While the TUN is up the runner's own connection to GitHub is cut (its open TCP session
# gets routed into the TUN mid-stream), so nothing printed then reaches the job log. All
# output therefore goes to a file that is printed once Sluice has stopped, and a watchdog
# stops Sluice after WATCHDOG seconds no matter what, so the network always comes back.
set -u
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
mkdir -p ci-logs
fails=0
WATCHDOG=${WATCHDOG:-150}
out=ci-logs/tun-output.txt
exec 3>&1 > "$out" 2>&1

cat > "$work/tun-proxy.conf" <<'EOF'
[General]
loglevel = info
enhanced-mode = true
api-listen = 127.0.0.1:6170
[Proxy]
SS = ss, 127.0.0.1, 18388, encrypt-method=aes-256-gcm, password=ss
[Rule]
DOMAIN,example.org,REJECT
FINAL,SS
EOF

run_case() {
    local name=$1 conf=$2
    echo "=================== $name"
    sudo ./target/release/sluice run "$conf" > "ci-logs/tun-$name.log" 2>&1 &
    (sleep "$WATCHDOG"; sudo pkill -INT -x sluice && echo "!! watchdog stopped Sluice after ${WATCHDOG}s") &
    local watchdog=$!
    for _ in $(seq 30); do curl -s -m 2 -o /dev/null http://127.0.0.1:6170/v1/policies && break; sleep 0.5; done
    sleep 1
    scripts/tun-check.sh || fails=$((fails + 1))
    sudo pkill -INT -x sluice
    for _ in $(seq 20); do pgrep -x sluice > /dev/null || break; sleep 0.5; done
    kill "$watchdog" 2>/dev/null
    echo "-- after"
    scripts/tun-check.sh after || fails=$((fails + 1))
    echo "-- sluice log"
    grep -vE "^\[.*INFO \] [0-9a-z.:\[\]-]+ -> " "ci-logs/tun-$name.log" | tail -20
    echo "   ($(grep -c ' -> ' "ci-logs/tun-$name.log") connections logged; $(grep -c 'via SS' "ci-logs/tun-$name.log") via SS)"
}

ssserver -s 127.0.0.1:18388 -m aes-256-gcm -k ss -U > ci-logs/tun-ssserver.log 2>&1 &
ss_pid=$!
sleep 1
run_case direct examples/tun-test.conf
run_case proxy "$work/tun-proxy.conf"
kill $ss_pid 2>/dev/null

echo; [ $fails = 0 ] && echo "All TUN checks passed." || echo "$fails TUN check run(s) failed."
exec 1>&3 2>&1
cat "$out"
exit $fails
