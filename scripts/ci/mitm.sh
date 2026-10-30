#!/bin/bash
# HTTPS decryption and HTTP rewriting end to end against https://example.com, through the
# HTTP and SOCKS5 inbounds. The CA comes from `sluice mitm gen-ca` and is trusted only by
# curl (--cacert), never by the keychain.
# Needs a built ./target/release/sluice.
set -u
cd "$(dirname "$0")/../.."
mkdir -p ci-logs
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null' EXIT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

api=http://127.0.0.1:16370
hp=http://127.0.0.1:16352
fail=0
check() { # name, condition result (0 = pass)
    if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

./target/release/sluice mitm gen-ca | tee ci-logs/mitm-gen-ca.txt
ca="$HOME/Library/Application Support/Sluice/ca.crt"
check "gen-ca wrote the CA and printed the trust command" \
    "$([ -f "$ca" ] && grep -q 'security add-trusted-cert' ci-logs/mitm-gen-ca.txt; echo $?)"
./target/release/sluice mitm gen-ca > /dev/null 2>&1
check "gen-ca refuses to overwrite" "$([ $? != 0 ]; echo $?)"
openssl x509 -in "$ca" -noout -subject

cat > "$work/sluice.conf" <<'CONF'
[General]
http-listen = 127.0.0.1:16352
socks5-listen = 127.0.0.1:16353
api-listen = 127.0.0.1:16370
[MITM]
hostname = example.com, -www.example.com
[URL Rewrite]
^https?://example\.com/old https://example.com/new 302
^https://example\.com/temp https://example.com/t2 307
[Header Rewrite]
http-response ^https?://example\.com/ header-add X-Sluice-Rewrite ok
[Body Rewrite]
http-response ^https://example\.com/ "Example Domain" "Sluice Domain"
[Rule]
URL-REGEX,^https://example\.com/blocked,REJECT
FINAL,DIRECT
CONF
./target/release/sluice check "$work/sluice.conf"
RUST_LOG=sluice=debug ./target/release/sluice run "$work/sluice.conf" > ci-logs/mitm-sluice.log 2>&1 &
for _ in $(seq 20); do curl -s -o /dev/null "$api/v1/policies" && break; sleep 0.5; done

c() { curl -s -m 20 --cacert "$ca" "$@"; }

out=$(c -x $hp -o /dev/null -w '%{http_code} %{redirect_url}' https://example.com/old)
check "URL Rewrite 302 over HTTPS ($out)" "$([ "$out" = "302 https://example.com/new" ]; echo $?)"
out=$(c -x $hp -o /dev/null -w '%{http_code} %{redirect_url}' https://example.com/temp)
check "URL Rewrite 307 ($out)" "$([ "$out" = "307 https://example.com/t2" ]; echo $?)"
out=$(c -x $hp -o /dev/null -w '%{http_code} %{redirect_url}' http://example.com/old)
check "URL Rewrite 302 over plain HTTP ($out)" "$([ "$out" = "302 https://example.com/new" ]; echo $?)"

c -x $hp --http1.1 -D "$work/h1.hdr" -o "$work/h1.body" -w '%{http_code} %{http_version}\n' https://example.com/ | tee "$work/h1.st"
check "Header Rewrite on HTTPS h1 ($(grep -i x-sluice "$work/h1.hdr" | tr -d '\r'))" \
    "$(grep -qi '^x-sluice-rewrite: ok' "$work/h1.hdr"; echo $?)"
check "Body Rewrite on HTTPS" "$(grep -q 'Sluice Domain' "$work/h1.body"; echo $?)"
c -x $hp --http2 -D "$work/h2.hdr" -o /dev/null -w '%{http_code} %{http_version}\n' https://example.com/ | tee "$work/h2.st"
check "decrypted connection speaks h2 ($(cat "$work/h2.st"))" "$(grep -q '^200 2$' "$work/h2.st"; echo $?)"
check "Header Rewrite on HTTPS h2" "$(grep -qi '^x-sluice-rewrite: ok' "$work/h2.hdr"; echo $?)"
c --socks5-hostname 127.0.0.1:16353 -D "$work/s5.hdr" -o /dev/null https://example.com/
check "Header Rewrite via SOCKS5" "$(grep -qi '^x-sluice-rewrite: ok' "$work/s5.hdr"; echo $?)"
c -x $hp -D "$work/plain.hdr" -o /dev/null http://example.com/
check "Header Rewrite on plain HTTP" "$(grep -qi '^x-sluice-rewrite: ok' "$work/plain.hdr"; echo $?)"

code=$(curl -s -m 20 -x $hp -o /dev/null -w '%{http_code}' https://example.com/)
check "without the CA curl refuses the leaf ($code)" "$([ "$code" = 000 ]; echo $?)"
issuer=$(c -x $hp -v -o /dev/null https://www.example.com/ 2>&1 | grep -i 'issuer:' | head -1)
check "excluded host is not decrypted ($issuer)" "$(echo "$issuer" | grep -vq Sluice; echo $?)"

code=$(c -x $hp -o /dev/null -w '%{http_code}' https://example.com/blocked)
check "URL-REGEX matches the full https URL ($code)" "$([ "$code" = 403 ]; echo $?)"
curl -s "$api/v1/connections" > "$work/conns.json"
python3 - "$work/conns.json" <<'PY'
import json, sys
cs = json.load(open(sys.argv[1]))
hits = [c for c in cs if c.get("url") == "https://example.com/blocked"]
print(hits[-1] if hits else "none")
ok = hits and hits[-1]["mitm"] is True and hits[-1]["rule"].startswith("URL-REGEX") and hits[-1]["network"] == "HTTPS"
sys.exit(0 if ok else 1)
PY
check "/v1/connections shows the decrypted URL" "$?"

kill %1 2>/dev/null; wait 2>/dev/null
echo "== sluice log"; tail -60 ci-logs/mitm-sluice.log
exit $fail
