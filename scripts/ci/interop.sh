#!/bin/bash
# Interop test against real servers on a proxy-free machine: Shadowsocks (ssserver), VMess /
# VLESS / Trojan incl. WebSocket, gRPC, XHTTP (Xray) and Hysteria2 (official server). For each node it checks
# HTTPS, a 10 MB download, UDP DNS (public targets) and full-cone UDP (two local ports on one
# association) through Sluice's SOCKS5 inbound.
# Shadowsocks plugins (obfs-server, v2ray-plugin) and legacy VMess (v2fly's v2ray, alterId > 0) too.
# Needs: ssserver, obfs-server, v2ray-plugin, v2ray, xray, hysteria on PATH and a built ./target/release/sluice.
set -u
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null' EXIT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

uuid=b831381d-6324-4d53-ad4f-8cda48b30811
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 \
    -subj "/CN=test.local" -addext "subjectAltName=DNS:test.local" 2>/dev/null
tls="\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$work/cert.pem\",\"keyFile\":\"$work/key.pem\"}]}"
keys=$(xray x25519)
reality_priv=$(echo "$keys" | awk -F': ' '/^Private ?[Kk]ey/{print $2}')
reality_pub=$(echo "$keys" | awk -F': ' '/Public ?[Kk]ey/{print $2}')
wrong_pub=$(xray x25519 | awk -F': ' '/Public ?[Kk]ey/{print $2}')
reality="\"security\":\"reality\",\"realitySettings\":{\"dest\":\"www.apple.com:443\",\"serverNames\":[\"www.apple.com\"],\"privateKey\":\"$reality_priv\",\"shortIds\":[\"0123abcd\"]}"
ws='"network":"ws","wsSettings":{"path":"/ray"}'
grpc='"network":"grpc","grpcSettings":{"serviceName":"gun"}'
xhttp='"network":"xhttp","xhttpSettings":{"path":"/xh"}'
# Xray 26.10+ blocks private destinations by default; the full-cone check uses loopback.
cat > "$work/xray.json" <<EOF
{"log":{"loglevel":"warning"},
"inbounds":[
 {"listen":"127.0.0.1","port":19001,"protocol":"vmess","settings":{"clients":[{"id":"$uuid"}]}},
 {"listen":"127.0.0.1","port":19002,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"}},
 {"listen":"127.0.0.1","port":19003,"protocol":"trojan","settings":{"clients":[{"password":"tj"}]},"streamSettings":{$tls}},
 {"listen":"127.0.0.1","port":19004,"protocol":"vmess","settings":{"clients":[{"id":"$uuid"}]},"streamSettings":{$ws,$tls}},
 {"listen":"127.0.0.1","port":19005,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{$ws}},
 {"listen":"127.0.0.1","port":19006,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{$grpc,$tls}},
 {"listen":"127.0.0.1","port":19007,"protocol":"vmess","settings":{"clients":[{"id":"$uuid"}]},"streamSettings":{$grpc}},
 {"listen":"127.0.0.1","port":19008,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{"network":"tcp",$reality}},
 {"listen":"127.0.0.1","port":19009,"protocol":"vless","settings":{"clients":[{"id":"$uuid","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp",$reality}},
 {"listen":"127.0.0.1","port":19010,"protocol":"vless","settings":{"clients":[{"id":"$uuid","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp",$tls}},
 {"listen":"127.0.0.1","port":19011,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{$xhttp,$tls}},
 {"listen":"127.0.0.1","port":19012,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{$xhttp,$reality}},
 {"listen":"127.0.0.1","port":19014,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"path":"/up"}}}],
"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
EOF
# Xray dropped legacy VMess; v2fly still has it behind V2RAY_VMESS_AEAD_FORCED=false.
cat > "$work/v2ray.json" <<EOF
{"log":{"loglevel":"warning"},
"inbounds":[{"listen":"127.0.0.1","port":19013,"protocol":"vmess","settings":{"clients":[{"id":"$uuid","alterId":4}]}}],
"outbounds":[{"protocol":"freedom"}]}
EOF
cat > "$work/hy.yaml" <<EOF
listen: 127.0.0.1:19443
tls:
  cert: $work/cert.pem
  key: $work/key.pem
auth:
  type: password
  password: hy
EOF
cat > "$work/hy-obfs.yaml" <<EOF
listen: 127.0.0.1:19444
tls:
  cert: $work/cert.pem
  key: $work/key.pem
auth:
  type: password
  password: hy
obfs:
  type: salamander
  salamander:
    password: obfs-secret
EOF
cat > "$work/sluice.conf" <<EOF
[General]
socks5-listen = 127.0.0.1:16153
api-listen = 127.0.0.1:16170
[Proxy]
SS-AES256 = ss, 127.0.0.1, 18388, encrypt-method=aes-256-gcm, password=ss
SS-CHACHA = ss, 127.0.0.1, 18389, encrypt-method=chacha20-ietf-poly1305, password=ss
VMess = vmess, 127.0.0.1, 19001, username=$uuid
VLESS = vless, 127.0.0.1, 19002, uuid=$uuid
Trojan-TLS = trojan, 127.0.0.1, 19003, password=tj, sni=test.local, skip-cert-verify=true
VMess-WS-TLS = vmess, 127.0.0.1, 19004, username=$uuid, tls=true, sni=test.local, skip-cert-verify=true, ws=true, ws-path=/ray
VLESS-WS = vless, 127.0.0.1, 19005, uuid=$uuid, ws=true, ws-path=/ray
Hysteria2 = hysteria2, 127.0.0.1, 19443, password=hy, sni=test.local, skip-cert-verify=true
VLESS-gRPC-TLS = vless, 127.0.0.1, 19006, uuid=$uuid, tls=true, sni=test.local, skip-cert-verify=true, grpc=true, grpc-service-name=gun
VMess-gRPC = vmess, 127.0.0.1, 19007, username=$uuid, grpc=true, grpc-service-name=gun
VLESS-REALITY = vless, 127.0.0.1, 19008, uuid=$uuid, sni=www.apple.com, reality-public-key=$reality_pub, reality-short-id=0123abcd
VLESS-REALITY-Vision = vless, 127.0.0.1, 19009, uuid=$uuid, sni=www.apple.com, reality-public-key=$reality_pub, reality-short-id=0123abcd, flow=xtls-rprx-vision
VLESS-TLS-Vision = vless, 127.0.0.1, 19010, uuid=$uuid, tls=true, sni=test.local, skip-cert-verify=true, flow=xtls-rprx-vision
VLESS-XHTTP-TLS = vless, 127.0.0.1, 19011, uuid=$uuid, tls=true, sni=test.local, skip-cert-verify=true, xhttp=true, xhttp-path=/xh
VLESS-XHTTP-StreamUp = vless, 127.0.0.1, 19011, uuid=$uuid, tls=true, sni=test.local, skip-cert-verify=true, xhttp=true, xhttp-path=/xh, xhttp-mode=stream-up
VLESS-XHTTP-REALITY = vless, 127.0.0.1, 19012, uuid=$uuid, sni=www.apple.com, reality-public-key=$reality_pub, reality-short-id=0123abcd, xhttp=true, xhttp-path=/xh
REALITY-WrongKey = vless, 127.0.0.1, 19008, uuid=$uuid, sni=www.apple.com, reality-public-key=$wrong_pub, reality-short-id=0123abcd
Hy2-Obfs = hysteria2, 127.0.0.1, 19444, password=hy, sni=test.local, skip-cert-verify=true, obfs=salamander, obfs-password=obfs-secret
Hy2-Hopping = hysteria2, 127.0.0.1, 19450, password=hy, sni=test.local, skip-cert-verify=true, obfs=salamander, obfs-password=obfs-secret, port-hopping=19450-19459, port-hopping-interval=1
SS-Obfs-HTTP = ss, 127.0.0.1, 18390, encrypt-method=aes-256-gcm, password=ss, obfs=http, obfs-host=www.bing.com
SS-Obfs-TLS = ss, 127.0.0.1, 18391, encrypt-method=aes-256-gcm, password=ss, obfs=tls, obfs-host=www.bing.com
SS-V2rayPlugin = ss, 127.0.0.1, 18392, encrypt-method=aes-256-gcm, password=ss, plugin=v2ray-plugin, plugin-opts=host=cdn.example;path=/v2
VMess-Legacy = vmess, 127.0.0.1, 19013, username=$uuid, alter-id=4
VLESS-HTTPUpgrade = vless, 127.0.0.1, 19014, uuid=$uuid, http-upgrade=true, ws-path=/up
[Proxy Group]
P = select, DIRECT, SS-AES256, SS-CHACHA, VMess, VLESS, Trojan-TLS, VMess-WS-TLS, VLESS-WS, VLESS-gRPC-TLS, VMess-gRPC, VLESS-REALITY, VLESS-REALITY-Vision, VLESS-TLS-Vision, VLESS-XHTTP-TLS, VLESS-XHTTP-StreamUp, VLESS-XHTTP-REALITY, REALITY-WrongKey, Hysteria2, Hy2-Obfs, Hy2-Hopping, SS-Obfs-HTTP, SS-Obfs-TLS, SS-V2rayPlugin, VMess-Legacy, VLESS-HTTPUpgrade
[Rule]
FINAL,P
EOF

ssserver -s 127.0.0.1:18388 -m aes-256-gcm -k ss -U > "$work/ss1.log" 2>&1 &
ssserver -s 127.0.0.1:18389 -m chacha20-ietf-poly1305 -k ss -U > "$work/ss2.log" 2>&1 &
# Plugin nodes: the plugin server takes TCP, a UDP-only ssserver the same port (as ss-server does).
obfs-server -s 127.0.0.1 -p 18390 --obfs http -r 127.0.0.1:18388 > "$work/obfs-http.log" 2>&1 &
obfs-server -s 127.0.0.1 -p 18391 --obfs tls -r 127.0.0.1:18388 > "$work/obfs-tls.log" 2>&1 &
SS_REMOTE_HOST=127.0.0.1 SS_REMOTE_PORT=18392 SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=18388 SS_PLUGIN_OPTIONS="server;path=/v2" \
    v2ray-plugin > "$work/v2ray-plugin.log" 2>&1 &
for p in 18390 18391 18392; do ssserver -s 127.0.0.1:$p -m aes-256-gcm -k ss -u > "$work/ss-udp-$p.log" 2>&1 & done
V2RAY_VMESS_AEAD_FORCED=false v2ray run -c "$work/v2ray.json" > "$work/v2ray.log" 2>&1 &
xray run -c "$work/xray.json" > "$work/xray.log" 2>&1 &
hysteria server -c "$work/hy.yaml" > "$work/hy.log" 2>&1 &
hysteria server -c "$work/hy-obfs.yaml" > "$work/hy-obfs.log" 2>&1 &
# Port hopping, as a real server deploys it: pf redirects the whole range to one listener.
echo "rdr pass on lo0 inet proto udp from any to 127.0.0.1 port 19450:19459 -> 127.0.0.1 port 19444" | sudo pfctl -Ef - 2>&1 | grep -v ALTQ || true
cat > "$work/xray-client.json" <<EOF
{"log":{"loglevel":"warning"},
"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"udp":true}}],
"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":19008,"users":[{"id":"$uuid","encryption":"none"}]}]},
 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.apple.com","fingerprint":"chrome","publicKey":"$reality_pub","shortId":"0123abcd"}}}]}
EOF
xray run -c "$work/xray-client.json" > "$work/xray-client.log" 2>&1 &
sleep 2
RUST_LOG=sluice=info,sluice::vision=debug,sluice::transport=debug,sluice::udphop=debug ./target/release/sluice run "$work/sluice.conf" > "$work/sluice.log" 2>&1 &
for _ in $(seq 20); do curl -s -o /dev/null http://127.0.0.1:16170/v1/policies && break; sleep 0.5; done

# Xray's own REALITY client and Sluice against the same server: Sluice must do as well
# (if both fail, the target site is at fault, not the client).
curl -s -X POST "http://127.0.0.1:16170/v1/policies/P?select=VLESS-REALITY" > /dev/null
reality_ok() { # socks port -> successes out of 20
    local ok=0
    for _ in $(seq 20); do
        [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:$1 https://example.com/)" = 200 ] && ok=$((ok + 1))
    done
    echo $ok
}
xray_ok=$(reality_ok 10808)
sluice_ok=$(reality_ok 16153)
control_fail=0
[ "$sluice_ok" -lt "$xray_ok" ] && control_fail=1
echo "REALITY control: xray $xray_ok/20, sluice $sluice_ok/20 $([ $control_fail = 0 ] && echo PASS || echo FAIL)"

fails=$control_fail
printf '%-20s %-6s %-12s %s / %s\n' NODE HTTPS DOWNLOAD UDP CONE
for node in DIRECT SS-AES256 SS-CHACHA VMess VLESS Trojan-TLS VMess-WS-TLS VLESS-WS VLESS-gRPC-TLS VMess-gRPC VLESS-REALITY VLESS-REALITY-Vision VLESS-TLS-Vision VLESS-XHTTP-TLS VLESS-XHTTP-StreamUp VLESS-XHTTP-REALITY Hysteria2 Hy2-Obfs Hy2-Hopping SS-Obfs-HTTP SS-Obfs-TLS SS-V2rayPlugin VMess-Legacy VLESS-HTTPUpgrade; do
    log_start=$(wc -l < "$work/sluice.log")
    curl -s -X POST "http://127.0.0.1:16170/v1/policies/P?select=$node" > /dev/null
    https=$(curl -s -m 15 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:16153 https://example.com/)
    size=$(curl -s -m 60 -o /dev/null -w '%{size_download}' --socks5-hostname 127.0.0.1:16153 \
        'https://speed.cloudflare.com/__down?bytes=10000000')
    udp=$(python3 -I scripts/ci/udp_dns_check.py 16153 8.8.8.8,1.1.1.1 2>&1 | tail -1)
    cone=$(python3 -I scripts/ci/udp_fullcone_check.py 16153 2>&1 | tail -1)
    # v2fly's Mux has no XUDP, so its UDP sessions are not full-cone: nothing Sluice can fix.
    [ "$node" = VMess-Legacy ] && cone="full-cone ok (n/a: v2fly server, $cone)"
    ok=yes
    [ "$https" = 200 ] || ok=no
    [ "$size" = 10000000 ] || ok=no
    [[ "$udp" == "replies 23/23"* ]] || ok=no
    [[ "$cone" == "full-cone ok"* ]] || ok=no
    if [ "$node" = Hy2-Hopping ]; then
        # The connection must live through real hops (interval 1s): keep it busy for ~5s.
        for _ in $(seq 5); do
            sleep 1
            [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:16153 https://example.com/)" = 200 ] || ok=no
        done
        hops=$(tail -n +$((log_start + 1)) "$work/sluice.log" | grep -c "hysteria2 port hop")
        conns=$(tail -n +$((log_start + 1)) "$work/sluice.log" | grep -c "hysteria2 connected")
        [ "$hops" -ge 2 ] && [ "$conns" = 1 ] || ok=no
        echo "Hy2-Hopping: $hops hops on $conns QUIC connection(s)"
    fi
    [ $ok = yes ] || fails=$((fails + 1))
    printf '%-20s %-6s %-12s %s / %s %s\n' "$node" "$https" "$size" "$udp" "$cone" "$([ $ok = yes ] && echo PASS || echo FAIL)"
done

# A wrong REALITY key must not connect: the client has to refuse the real site's certificate.
curl -s -X POST "http://127.0.0.1:16170/v1/policies/P?select=REALITY-WrongKey" > /dev/null
log_lines=$(wc -l < "$work/sluice.log")
wrong=$(curl -s -m 15 -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:16153 https://example.com/)
if [ "$wrong" = 000 ] && tail -n +$((log_lines + 1)) "$work/sluice.log" | grep -q "REALITY verification failed"; then
    echo "REALITY-WrongKey  refused (REALITY verification failed) PASS"
else
    echo "REALITY-WrongKey  HTTP $wrong, expected refusal FAIL"; fails=$((fails + 1))
fi

# Vision must have spliced the inner TLS 1.3 both ways, not just padded it.
for dir in uplink downlink; do
    if grep -q "vision: $dir switched to direct copy" "$work/sluice.log"; then
        echo "Vision $dir direct copy seen PASS"
    else
        echo "Vision $dir direct copy never happened FAIL"; fails=$((fails + 1))
    fi
done

if [ $fails != 0 ]; then
    echo; echo "== sluice log (warnings)"; grep -E "WARN|ERROR" "$work/sluice.log" | tail -30
    echo; echo "== xray log"; tail -30 "$work/xray.log"
    for l in v2ray obfs-http obfs-tls v2ray-plugin; do echo; echo "== $l log"; tail -15 "$work/$l.log"; done
fi
mkdir -p ci-logs && cp "$work"/*.log ci-logs/ 2>/dev/null
echo; [ $fails = 0 ] && echo "All interop checks passed." || echo "$fails node(s) failed."
exit $fails
