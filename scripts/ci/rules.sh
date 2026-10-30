#!/bin/bash
# Extended rules end to end on a proxy-free machine: PROCESS-NAME through the HTTP and SOCKS5
# inbounds, routing curl to REJECT and another process (Python) to DIRECT, plus the
# connection log and /v1/route for logical rules.
#   phase 1: PROCESS-NAME,curl,REJECT + FINAL,DIRECT; learns Python's process name.
#   phase 2: PROCESS-NAME,<python>,DIRECT + FINAL,REJECT, after a reload.
# Needs a built ./target/release/sluice.
set -u
cd "$(dirname "$0")/../.."
mkdir -p ci-logs
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null' EXIT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

api=http://127.0.0.1:16270
fail=0
check() { # name, condition result (0 = pass)
    if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

write_conf() {
    cat > "$work/sluice.conf" <<EOF
[General]
http-listen = 127.0.0.1:16252
socks5-listen = 127.0.0.1:16253
api-listen = 127.0.0.1:16270
[Rule]
AND,((DOMAIN,and.test),(DST-PORT,8443)),REJECT
$1
EOF
}

# Prints the HTTP status Python gets for $1 through the HTTP proxy (000 on failure).
py_get() {
    python3 - "$1" <<'EOF'
import sys, urllib.request
p = "http://127.0.0.1:16252"
o = urllib.request.build_opener(urllib.request.ProxyHandler({"http": p, "https": p}))
try:
    print(o.open(sys.argv[1], timeout=15).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print("000")
EOF
}

# Field $2 of the newest /v1/connections record whose target contains $1.
last_conn() {
    curl -s "$api/v1/connections" | python3 -c "
import json, sys
hits = [c for c in json.load(sys.stdin) if '$1' in c['target']]
print(hits[-1]['$2'] if hits else 'none')"
}

write_conf "PROCESS-NAME,curl,REJECT
FINAL,DIRECT"
RUST_LOG=sluice=info ./target/release/sluice run "$work/sluice.conf" > ci-logs/rules-sluice.log 2>&1 &
for _ in $(seq 20); do curl -s -o /dev/null "$api/v1/policies" && break; sleep 0.5; done

echo "== phase 1: curl -> REJECT, everything else DIRECT"
code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:16252 http://example.com/)
check "curl plain HTTP rejected ($code)" "$([ "$code" = 403 ]; echo $?)"
code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:16252 https://example.com/)
check "curl CONNECT rejected ($code)" "$([ "$code" != 200 ]; echo $?)"
code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:16253 https://example.com/)
check "curl SOCKS5 rejected ($code)" "$([ "$code" != 200 ]; echo $?)"
proc=$(last_conn example.com process); rule=$(last_conn example.com rule)
check "connection log names curl ($proc, $rule)" "$([ "$proc" = curl ] && [ "$rule" = PROCESS-NAME,curl ]; echo $?)"

code=$(py_get https://example.com/)
check "python HTTPS direct ($code)" "$([ "$code" = 200 ]; echo $?)"
py=$(last_conn example.com process)
check "connection log names python ($py)" "$([ "$py" != curl ] && [ "$py" != None ] && [ "$py" != none ]; echo $?)"

route=$(curl -s "$api/v1/route?target=and.test:8443")
check "AND rule via /v1/route ($route)" "$(echo "$route" | grep -q '"outbound":"REJECT"'; echo $?)"
route=$(curl -s "$api/v1/route?target=example.com&process=curl")
check "/v1/route process= ($route)" "$(echo "$route" | grep -q '"process":"curl"'; echo $?)"

echo "== phase 2: $py -> DIRECT, everything else REJECT"
write_conf "PROCESS-NAME,$py,DIRECT
FINAL,REJECT"
curl -s -X POST "$api/v1/reload"; echo
code=$(py_get http://example.com/)
check "python plain HTTP direct ($code)" "$([ "$code" = 200 ]; echo $?)"
rule=$(last_conn example.com rule)
check "matched by PROCESS-NAME,$py ($rule)" "$([ "$rule" = "PROCESS-NAME,$py" ]; echo $?)"
code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:16252 http://example.com/)
check "curl falls to FINAL,REJECT ($code)" "$([ "$code" = 403 ]; echo $?)"

kill %1 2>/dev/null; wait 2>/dev/null
echo "== sluice log"; tail -40 ci-logs/rules-sluice.log
exit $fail
