"""SOCKS5 UDP ASSOCIATE client: sends DNS queries to <server>:53 through the proxy and counts valid replies.

Usage: udp_dns_check.py <socks-port> <dns-server-ip>; exits non-zero unless every query is answered.
"""
import random
import socket
import struct
import sys

proxy_port, server = int(sys.argv[1]), sys.argv[2]


def query(name, qtype, edns=False):
    qid = random.randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack(">HH", qtype, 1)
    if edns:
        q += b"\0" + struct.pack(">HHIH", 41, 4096, 0, 0)
    return qid, q


ctl = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
ctl.sendall(b"\x05\x01\x00")
assert ctl.recv(2) == b"\x05\x00"
ctl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep = ctl.recv(10)
assert rep[1] == 0, f"associate failed: {rep!r}"
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(4)
head = b"\0\0\0\x01" + socket.inet_aton(server) + struct.pack(">H", 53)

ok, sizes = 0, []
cases = [("example.com", 1, False)] * 20 + [("google.com", 16, True)] * 3
for name, qtype, edns in cases:
    qid, q = query(name, qtype, edns)
    u.sendto(head + q, relay)
    try:
        while True:
            data, _ = u.recvfrom(65535)
            body = data[10:]
            if struct.unpack(">H", body[:2])[0] == qid and body[2] & 0x80:
                ok += 1
                sizes.append(len(body))
                break
    except socket.timeout:
        pass
print(f"replies {ok}/{len(cases)}, largest {max(sizes) if sizes else 0} bytes")
sys.exit(0 if ok == len(cases) else 1)
