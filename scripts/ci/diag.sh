#!/bin/bash
# Runs `sluice diag export` on the runner (after interop.sh, so real logs exist) and checks the
# bundle has the expected files and none of interop.sh's test secrets. No network involved.
set -eu
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
uuid=$(awk -F= '/^uuid=/{print $2; exit}' scripts/ci/interop.sh)
# interop.sh's [Proxy] lines with its real test credentials, plus a subscription and a share link.
{
    echo "[General]"; echo "socks5-listen = 127.0.0.1:16999"; echo "[Proxy]"
    grep -E '^[A-Za-z0-9-]+ = (ss|vmess|vless|trojan|hysteria2),' scripts/ci/interop.sh | sed "s/\$uuid/$uuid/g; s/\$reality_pub/CiRealityPubKey0123/g"
    echo "[Proxy Group]"; echo "P = select, SS-AES256"
    echo "Sub = select, policy-path=https://sub.example.com/api/v1/client/subscribe?token=ci-sub-token-42"
    echo "[Rule]"; echo "FINAL,P"
} > "$work/ci.conf"
mkdir -p ~/Library/Logs/Sluice
echo "INFO imported trojan://tj@127.0.0.1:19003 vless://$uuid@127.0.0.1:19002 obfs-password=obfs-secret" >> ~/Library/Logs/Sluice/sluice.log

./target/release/sluice diag export "$work/diag.zip" "$work/ci.conf"
mkdir "$work/x" && ditto -x -k "$work/diag.zip" "$work/x"
fails=0
for f in version.txt config.conf check.txt logs/sluice.log network/routes.txt network/dns.txt network/nwi.txt network/interfaces.txt; do
    if compgen -G "$work/x/sluice-diag-*/$f" > /dev/null; then echo "has $f PASS"; else echo "missing $f FAIL"; fails=$((fails + 1)); fi
done
secrets=("$uuid" "password=ss" "password=tj" "password=hy" "password: hy" "obfs-secret" "CiRealityPubKey0123" "0123abcd" "ci-sub-token-42" "tj@")
for s in "${secrets[@]}"; do
    if grep -rqF -- "$s" "$work/x"; then
        echo "leaked $s FAIL"; grep -rnF -- "$s" "$work/x" | head -5; fails=$((fails + 1))
    else
        echo "no $s PASS"
    fi
done
mkdir -p ci-logs && cp "$work/diag.zip" ci-logs/
[ $fails = 0 ] && echo "Diagnostics bundle OK." || echo "$fails diagnostics check(s) failed."
exit $fails
