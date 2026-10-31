"""Deterministic STUN binding check; client must reach the responder through a fake IP.

server <physical-ip> <port>: responder on the runner's non-loopback address.
client <domain> <port>: resolve using TUN DNS and require the original fake source tuple.
"""
import ipaddress
import os
import socket
import struct
import sys

COOKIE = 0x2112A442
mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if mode == "server":
    s.bind((host, port))
    print("STUN responder ready", flush=True)
    while True:
        data, peer = s.recvfrom(65535)
        if len(data) != 20 or data[:8] != struct.pack("!HHI", 1, 0, COOKIE):
            continue
        attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, peer[1] ^ (COOKIE >> 16))
        attr += struct.pack("!I", int(ipaddress.IPv4Address(peer[0])) ^ COOKIE)
        s.sendto(struct.pack("!HHI", 0x101, len(attr), COOKIE) + data[8:20] + attr, peer)
else:
    # Unique name per protocol/run avoids macOS's DNS cache across core restarts.
    fake = socket.gethostbyname(host)
    assert ipaddress.ip_address(fake) in ipaddress.ip_network("198.18.0.0/15"), fake
    s.settimeout(3)
    for attempt in range(3):
        txid = os.urandom(12)
        s.sendto(struct.pack("!HHI", 1, 0, COOKIE) + txid, (fake, port))
        try:
            data, source = s.recvfrom(65535)
        except socket.timeout:
            if attempt == 2:
                raise
            continue
        assert source == (fake, port), (source, fake, port)
        assert data[:8] == struct.pack("!HHI", 0x101, 12, COOKIE), data
        assert data[8:20] == txid, data
        assert data[20:24] == struct.pack("!HH", 0x20, 8), data
        print(f"PASS STUN {host} via TUN, reply from {source}")
        break
