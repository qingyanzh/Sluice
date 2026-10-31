"""Deterministic STUN binding check; client must reach the responder through a fake IP.

server <ip> <port>: responder reachable from the proxy server.
client <domain> <port>: resolve using TUN DNS and require the original fake source tuple.
proxy <domain> <port> <socks-port>: check server reachability before enabling TUN.
"""
import ipaddress
import io
import os
import socket
import struct
import sys

COOKIE = 0x2112A442


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        assert chunk, "SOCKS server closed during handshake"
        data += chunk
    return data


def read_address(read):
    atyp = read(1)[0]
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, read(4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(16))
    else:
        assert atyp == 3, atyp
        host = read(read(1)[0]).decode()
    return host, struct.unpack("!H", read(2))[0]


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
        print(f"STUN binding reply sent to {peer}", flush=True)
else:
    assert mode in ("client", "proxy"), mode
    prefix = b""
    if mode == "proxy":
        ctl = socket.create_connection(("127.0.0.1", int(sys.argv[4])), timeout=3)
        ctl.sendall(b"\x05\x01\x00")
        assert read_exact(ctl, 2) == b"\x05\x00"
        ctl.sendall(b"\x05\x03\x00\x01" + b"\0" * 6)
        assert read_exact(ctl, 3) == b"\x05\x00\x00", "SOCKS UDP association failed"
        dest = read_address(lambda n: read_exact(ctl, n))
        domain = host.encode()
        prefix = b"\0\0\0\x03" + bytes([len(domain)]) + domain + struct.pack("!H", port)
    else:
        # Unique name per protocol/run avoids macOS's DNS cache across core restarts.
        fake = socket.gethostbyname(host)
        assert ipaddress.ip_address(fake) in ipaddress.ip_network("198.18.0.0/15"), fake
        dest = (fake, port)
    s.settimeout(3)
    for attempt in range(3):
        txid = os.urandom(12)
        s.sendto(prefix + struct.pack("!HHI", 1, 0, COOKIE) + txid, dest)
        try:
            data, source = s.recvfrom(65535)
        except socket.timeout:
            if attempt == 2:
                raise
            continue
        if mode == "proxy":
            packet = io.BytesIO(data)
            assert packet.read(3) == b"\0\0\0", "bad SOCKS UDP reply"
            source = read_address(packet.read)
            assert source in ((host, port), ("127.0.0.1", port)), source
            data = packet.read()
        else:
            assert source == (fake, port), (source, fake, port)
        assert data[:8] == struct.pack("!HHI", 0x101, 12, COOKIE), data
        assert data[8:20] == txid, data
        assert data[20:24] == struct.pack("!HH", 0x20, 8), data
        print(f"PASS STUN {host} via {'TUN' if mode == 'client' else 'SOCKS'}, reply from {source}")
        break
