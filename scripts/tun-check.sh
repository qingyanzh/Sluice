#!/bin/bash
# Checks enhanced (TUN) mode end to end. Usage:
#   scripts/tun-check.sh          while `sudo sluice run examples/tun-test.conf` is running
#   scripts/tun-check.sh after    once Sluice has been stopped, to confirm cleanup
# Needs no root itself.

unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1${3:+ ($3)}"; fi; }

if [ "$1" = "after" ]; then
    check "Sluice has exited" "! pgrep -x sluice >/dev/null"
    check "TUN address removed" "! ifconfig | grep -q 'inet 198.18.0.1 '"
    check "scoped default route added by Sluice removed" "! netstat -rn -f inet | awk '\$1==\"default\" && \$3 ~ /I/' | grep -q ."
    check "split default routes removed" "! netstat -rn -f inet | grep -E '^(0/1|128.0/1) ' | grep -q utun"
    check "system DNS no longer 198.18.0.2" "! scutil --dns | grep -q 'nameserver\[[0-9]*\] : 198.18.0.2'"
    check "DNS backup file cleaned up" "[ ! -e /var/tmp/sluice-dns-backup ]"
    check "internet still works" "[ \"\$(curl -s -m 10 -o /dev/null -w '%{http_code}' https://example.com/)\" = 200 ]"
    echo; [ $fails = 0 ] && echo "All cleanup checks passed." || echo "$fails check(s) failed."
    exit $fails
fi

check "Sluice is running" "pgrep -x sluice >/dev/null" "start it first with sudo"
utun=$(ifconfig | awk '/^utun/ {iface=$1} /inet 198.18.0.1 / {print iface}' | tr -d ':' | head -1)
check "utun device with 198.18.0.1" "[ -n '$utun' ]" "is Sluice running with enhanced-mode = true?"
check "routes 0/1 and 128/1 via $utun" "[ \$(netstat -rn -f inet | grep -E '^(0/1|128.0/1) ' | grep -c '$utun') = 2 ]"
check "system DNS points at 198.18.0.2" "scutil --dns | grep -q 'nameserver\[[0-9]*\] : 198.18.0.2'"

ip=$(dig +short +time=3 +tries=1 example.com A | head -1)
check "fake-IP answer for example.com" "[[ '$ip' == 198.18.* ]]" "got '$ip'"
aaaa=$(dig +short +time=3 +tries=1 example.com AAAA | head -1)
check "AAAA answered empty (IPv4 only)" "[ -z '$aaaa' ]" "got '$aaaa'"
mx=$(dig +short +time=3 +tries=1 gmail.com MX | head -1)
check "other record types forwarded upstream (MX)" "[ -n '$mx' ]"

code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' https://example.com/)
check "HTTPS by domain through the TUN" "[ '$code' = 200 ]" "HTTP $code"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' https://example.org/)
org_ip=$(dig +short +time=3 +tries=1 example.org A | head -1)
check "REJECT rule blocks example.org (resolved to fake IP $org_ip)" "[[ '$org_ip' == 198.18.* ]] && [ '$code' = 000 ]" "HTTP $code"
# Any HTTP status proves the TCP+TLS path works; override the IP if it's blocked on your network.
ip_target=${SLUICE_CHECK_IP:-1.1.1.1}
code=$(curl -s -m 10 -k -o /dev/null -w '%{http_code}' "https://$ip_target/")
check "HTTPS by IP address ($ip_target) through the TUN" "[ '$code' != 000 ]" "HTTP $code"
size=$(curl -s -m 60 -o /dev/null -w '%{size_download}' 'https://speed.cloudflare.com/__down?bytes=10000000')
check "10 MB download through the TUN" "[ '$size' = 10000000 ]" "got $size bytes"

ntp=$(python3 -I -c '
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"\x1b" + 47 * b"\0", ("time.apple.com", 123))
d, _ = s.recvfrom(1024); print(struct.unpack("!I", d[40:44])[0] - 2208988800)
' 2>/dev/null)
check "UDP (NTP to time.apple.com) through the TUN" "[ -n '$ntp' ]"

route=$(curl -s -m 3 'http://127.0.0.1:6170/v1/route?target=example.org')
check "API sees the REJECT rule" "echo '$route' | grep -q '\"outbound\":\"REJECT\"'" "$route"

echo; [ $fails = 0 ] && echo "All TUN checks passed." || echo "$fails check(s) failed. Please send this output and Sluice's log."
exit $fails
