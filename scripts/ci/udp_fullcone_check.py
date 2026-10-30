"""Full-cone check through SOCKS5 UDP ASSOCIATE: one association, two remote ports.

Usage: udp_fullcone_check.py <socks-port>. Runs two UDP servers A and B on this machine. A packet to A
is answered by A and also by B (a source the client never sent to); a packet to B is
answered by B. A full-cone proxy delivers all three replies on the one association, each
with its real source address in the SOCKS header. Exits non-zero otherwise.
"""
import socket
import struct
import sys
import threading

proxy_port = int(sys.argv[1])
# The machine's own non-loopback address: newer Xray servers drop UDP to loopback.
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.connect(("8.8.8.8", 53))
host = probe.getsockname()[0]
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.bind((host, 0))
b.bind((host, 0))
pa, pb = a.getsockname()[1], b.getsockname()[1]


def serve_a():
    while True:
        data, peer = a.recvfrom(65535)
        a.sendto(b"A:" + data, peer)
        b.sendto(b"B-for-A:" + data, peer)


def serve_b():
    while True:
        data, peer = b.recvfrom(65535)
        b.sendto(b"B:" + data, peer)


threading.Thread(target=serve_a, daemon=True).start()
threading.Thread(target=serve_b, daemon=True).start()

ctl = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
ctl.sendall(b"\x05\x01\x00")
assert ctl.recv(2) == b"\x05\x00"
ctl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep = ctl.recv(10)
assert rep[1] == 0, f"associate failed: {rep!r}"
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(3)


def send(port, data):
    u.sendto(b"\0\0\0\x01" + socket.inet_aton(host) + struct.pack(">H", port) + data, relay)


def collect(want):
    """Returns the {(source port, payload)} received until `want` is covered or a timeout."""
    got = set()
    try:
        while not want <= got:
            data, _ = u.recvfrom(65535)
            if data[3] == 1:
                got.add((struct.unpack(">H", data[8:10])[0], data[10:]))
    except socket.timeout:
        pass
    return got


missing = set()
for attempt in range(3):
    tag = str(attempt).encode()
    send(pa, b"one" + tag)
    want = {(pa, b"A:one" + tag), (pb, b"B-for-A:one" + tag)}
    got = collect(want)
    send(pb, b"two" + tag)
    want2 = {(pb, b"B:two" + tag)}
    got |= collect(want2)
    missing = (want | want2) - got
    if not missing:
        break
names = {pa: "A", pb: "B"}
if missing:
    print("full-cone FAIL, missing " + ", ".join(f"{p.decode()} from {names.get(s, s)}" for s, p in sorted(missing)))
    sys.exit(1)
print("full-cone ok (replies from A, unsolicited B, then B)")
