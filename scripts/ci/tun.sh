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

# Snapshot the network so a broken cleanup can be diagnosed and repaired.
gw=$(route -n get default | awk '/gateway:/{print $2}')
iface=$(route -n get default | awk '/interface:/{print $2}')
netstat -rn -f inet > "$work/routes-before.txt"
networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' > "$work/services.txt"
while IFS= read -r svc; do
    printf '%s\t%s\n' "$svc" "$(networksetup -getdnsservers "$svc" | tr '\n' ' ')"
done < "$work/services.txt" > "$work/dns-before.txt"
echo "network before: default via $gw on $iface"; cat "$work/dns-before.txt"

online() { curl -s -m 10 -o /dev/null https://github.com; }

# Some cloud networks drop outbound NTP; check it without Sluice first.
if python3 -I -c '
import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"\x1b" + 47 * b"\0", ("time.apple.com", 123)); s.recvfrom(1024)' 2>/dev/null; then
    echo "NTP works without Sluice"
else
    echo "NTP is blocked on this network even without Sluice; skipping the NTP check"
    export SLUICE_CHECK_NTP=0
fi

# If the runner lost the internet after Sluice stopped, show what changed and put it back.
repair_if_offline() {
    online && { echo "-- runner online"; return; }
    echo "!! runner OFFLINE after Sluice stopped; diff of routes (before -> now):"
    netstat -rn -f inet > "$work/routes-after.txt"
    diff "$work/routes-before.txt" "$work/routes-after.txt" | head -40
    echo "!! DNS now:"; scutil --dns | grep nameserver | sort -u
    for net in 0/1 128.0/1 198.18/15; do sudo route -n delete -net "$net" 2>/dev/null; done
    sudo route -n delete -ifscope "$iface" -net default 2>/dev/null
    route -n get default > /dev/null 2>&1 || sudo route -n add default "$gw"
    while IFS=$'\t' read -r svc dns; do
        if [[ "$dns" == *"aren't any"* || -z "$dns" ]]; then sudo networksetup -setdnsservers "$svc" Empty
        else sudo networksetup -setdnsservers "$svc" $dns; fi
    done < "$work/dns-before.txt"
    online && echo "!! repaired: runner online again" || echo "!! still offline after repair"
    fails=$((fails + 1))
}

cat > "$work/tun-proxy.conf" <<'EOF'
[General]
loglevel = debug
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
    repair_if_offline
    echo "-- sluice log"
    grep -vE "^\[.*INFO \] [0-9a-z.:\[\]-]+ -> |DEBUG" "ci-logs/tun-$name.log" | tail -20
    echo "-- UDP debug"
    grep -E "DEBUG.*UDP" "ci-logs/tun-$name.log" | grep -vE "apple-dns|icloud" | tail -12
    echo "   ($(grep -c ' -> ' "ci-logs/tun-$name.log") connections logged; $(grep -c 'via SS' "ci-logs/tun-$name.log") via SS)"
}

# The test server runs on this machine, so its own outgoing traffic must bypass the TUN,
# as a real remote server's would; otherwise it loops back into Sluice. It also needs its
# own DNS: the system resolver now answers with Sluice's fake IPs.
ssserver -s 127.0.0.1:18388 -m aes-256-gcm -k ss -U --outbound-bind-interface "$iface" --dns 8.8.8.8 > ci-logs/tun-ssserver.log 2>&1 &
ss_pid=$!
sleep 1
sed 's/^loglevel = .*/loglevel = debug/' examples/tun-test.conf > "$work/tun-direct.conf"
run_case direct "$work/tun-direct.conf"
run_case proxy "$work/tun-proxy.conf"
kill $ss_pid 2>/dev/null

echo; [ $fails = 0 ] && echo "All TUN checks passed." || echo "$fails TUN check run(s) failed."
exec 1>&3 2>&1
cat "$out"
exit $fails
