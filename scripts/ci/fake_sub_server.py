"""Local, stdlib-only subscription fixtures and HTTP origin for subscription.sh.

Usage: fake_sub_server.py <HTTP port> <AnyTLS port> <AnyTLS password>.
Subscription endpoints deliberately advertise text/html and require a Clash-like UA.
"""
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
from urllib.parse import urlsplit


ORIGIN_BODY = b"sluice subscription AnyTLS origin\n"


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.reply(200, b"ready\n")
            return
        if path == "/origin":
            self.reply(200, ORIGIN_BODY, {"Content-Type": "text/plain"})
            return

        agent = self.headers.get("User-Agent", "").lower()
        if not any(token in agent for token in ("clash", "mihomo", "meta")):
            self.reply(403, "禁止访问".encode("utf-8"),
                       {"Content-Type": "text/html; charset=utf-8"})
            return
        if path == "/redirect":
            self.reply(302, headers={"Location": "/gzip"})
            return
        if path not in ("/", "/clash", "/gzip", "/surge"):
            self.reply(404, b"not found\n")
            return

        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "subscription-userinfo": "upload=1; download=2; total=1073741824; expire=4102444800",
            "profile-update-interval": "24",
        }
        body = self.server.surge if path == "/surge" else self.server.clash
        if path == "/gzip":
            body = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
        self.reply(200, body, headers)


def main():
    port, anytls_port, password = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    # JSON-quoted strings are valid YAML scalars; no third-party YAML library needed.
    nodes = []
    for name in ("AnyTLS-A", "AnyTLS-B"):
        nodes.append(f"""  - name: {name}
    type: anytls
    server: 127.0.0.1
    port: "{anytls_port}"
    password: {json.dumps(password)}
    sni: test.local
    skip-cert-verify: true
    client-fingerprint: chrome
    udp: true
""")
    surge = f"""#!MANAGED-CONFIG http://127.0.0.1:{port}/surge interval=86400
[General]
loglevel = notify
[Proxy]
Surge-AnyTLS = anytls, 127.0.0.1, {anytls_port}, password={password}, sni=test.local, skip-cert-verify=true, udp=true
[Proxy Group]
Profile-Only = select, Surge-AnyTLS
[Rule]
FINAL,Profile-Only
"""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.clash = ("proxies:\n" + "".join(nodes)).encode("utf-8")
    server.surge = surge.encode("utf-8")
    print(f"subscription fixtures and origin on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
