#!/bin/bash
# Diagnoses why sockets bound to the physical interface fail while Sluice's TUN routes are up.
# Run (no sudo needed) while `sudo sluice run examples/tun-test.conf` is running.

# The physical interface: a default route with a real gateway that isn't a tunnel. Override with $1.
iface=${1:-$(netstat -rn -f inet | awk '$1 == "default" && $3 ~ /G/ && $4 !~ /^utun/ {print $4; exit}')}
iface=${iface:-en0}
echo "== physical interface: $iface"
echo "== IPv4 routes"
netstat -rn -f inet | head -25
for dst in 1.1.1.1 172.28.103.10; do
    echo "== route -n get $dst (unscoped)"
    route -n get "$dst" | grep -E "gateway|interface|flags"
    echo "== route -n get -ifscope $iface $dst (what a socket bound to $iface gets)"
    route -n get -ifscope "$iface" "$dst" 2>&1 | grep -E "gateway|interface|flags|not in table|unreachable"
done
echo "== socket bound to $iface (IP_BOUND_IF)"
python3 -I - "$iface" <<'EOF'
import socket, sys
idx = socket.if_nametoindex(sys.argv[1])
for dst in [("1.1.1.1", 443), ("172.28.103.10", 443)]:
    s = socket.socket(); s.settimeout(4)
    s.setsockopt(socket.IPPROTO_IP, 25, idx)
    try:
        s.connect(dst); print(dst, "OK")
    except Exception as e:
        print(dst, "ERROR:", e)
EOF
