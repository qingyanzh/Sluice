"""Local interop origin: exact-size payloads and a barrier proving eight live streams."""
import http.server
import threading

barrier = threading.Barrier(8, timeout=30)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/parallel":
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                self.send_error(503, "eight concurrent streams never arrived")
                return
            data = b"eight concurrent streams ok\n"
        elif self.path == "/download":
            data = b"A" * 10_000_000
        else:
            data = b"AnyTLS interop ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


http.server.ThreadingHTTPServer(("127.0.0.1", 19463), Handler).serve_forever()
