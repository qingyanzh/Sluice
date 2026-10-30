"""Real-use API assertions and local traffic fixtures; Python stdlib only.

CI only: python3 -I scripts/ci/e2e_api.py <api host:port> <socks host:port> <work>
Fixture modes: --serve (HTTP on 127.0.0.1:18080), --traffic <socks host:port>,
--wait-traffic <api host:port> (prove three downloads are transferring).
No public network destinations, curl configuration, or environment proxies are used.
"""

import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
import urllib.parse


HTTP_URL = "http://127.0.0.1:18080"
FILE_SIZE = 64 * 1024 * 1024
MAX_RATE = 256 * 1024
CURL_ENV = {k: v for k, v in os.environ.items() if k.lower() not in
            {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def eventually(fn, timeout=8):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(0.2)
    raise AssertionError(f"condition did not become true in {timeout}s (last={last!r})")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait()


def curl_download(socks, label, source_port=None):
    args = ["curl", "--disable", "--fail", "--silent", "--show-error",
            "--connect-timeout", "5", "--max-time", "120", "--noproxy", "",
            "--socks5-hostname", socks, "--output", os.devnull,
            "--write-out", "%{size_download}\n"]
    if source_port is not None:
        args += ["--local-port", str(source_port)]
    return args + [f"{HTTP_URL}/download?{urllib.parse.urlencode({'client': label})}"]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        # Give localhost probes a measurable latency, even on a fast runner.
        time.sleep(0.03)
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        download = urllib.parse.urlsplit(self.path).path == "/download"
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream" if download else "text/plain")
        self.send_header("Content-Length", str(FILE_SIZE if download else 3))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            if not download:
                self.wfile.write(b"ok\n")
                return
            # A per-request ramp makes successive rate samples observably increase.
            # Cap at 256 KiB/s: a full response takes at least 256 seconds, whereas
            # DELETE must stop curl within 5 seconds, long before its own timeout.
            block = (b"sluice-e2e-data!\n" * 256)[:4096]
            started = deadline = time.monotonic()
            remaining = FILE_SIZE
            while remaining:
                rate = min(MAX_RATE, 16 * 1024 * (1 + int(time.monotonic() - started)))
                chunk = block[:min(len(block), remaining)]
                self.wfile.write(chunk)
                self.wfile.flush()
                remaining -= len(chunk)
                deadline += len(chunk) / rate
                time.sleep(max(0, deadline - time.monotonic()))
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected when the API or the harness closes a download.


class Download:
    def __init__(self, socks, work, label, source_port):
        self.label, self.source_port = label, source_port
        self.started = time.monotonic()
        self.stdout = (work / f"curl-{label}.size").open("wb")
        self.stderr = (work / f"curl-{label}.log").open("wb")
        self.process = subprocess.Popen(curl_download(socks, label, source_port),
                                        stdout=self.stdout, stderr=self.stderr, env=CURL_ENV)
        self.size_path = work / f"curl-{label}.size"

    def close(self):
        stop(self.process)
        self.stdout.close()
        self.stderr.close()


class Checks:
    def __init__(self, api, socks, work):
        self.api, self.socks, self.work = api, socks, work
        self.fails = 0
        self.downloads = []
        self.samples = []
        self.closed_id = None
        self.transcript = (work / "api-exchanges.jsonl").open("w")

    def call(self, method, path, **query):
        if query:
            path += "?" + urllib.parse.urlencode(query)
        conn = http.client.HTTPConnection(self.api, timeout=12)
        try:
            conn.request(method, path, body=b"" if method == "POST" else None)
            response = conn.getresponse()
            data = json.loads(response.read())
            self.transcript.write(json.dumps({"time": time.time(), "method": method,
                                             "path": path, "status": response.status, "body": data}) + "\n")
            self.transcript.flush()
            require(response.status == 200, f"{method} {path}: HTTP {response.status}: {data}")
            return data
        finally:
            conn.close()

    def run(self, name, fn):
        try:
            detail = fn()
            print(f"PASS {name}: {detail or 'ok'}", flush=True)
        except Exception as exc:
            self.fails += 1
            print(f"FAIL {name}: {exc}", flush=True)
            traceback.print_exc()

    def download(self, label):
        # The SOCKS client's source port uniquely identifies this curl in active/SSE.
        dl = Download(self.socks, self.work, label, 16301 + len(self.downloads))
        self.downloads.append(dl)
        return dl

    def connection(self, dl):
        hits = [c for c in self.call("GET", "/v1/connections/active")
                if c.get("src") == f"127.0.0.1:{dl.source_port}"
                and c.get("target") == "127.0.0.1:18080"]
        return hits[0] if len(hits) == 1 else None

    def active_and_rates(self):
        self.call("POST", "/v1/policies/P", select="SS-AES256")
        for i in range(3):
            self.download(f"active-{i}")
        time.sleep(3.2)
        first = [eventually(lambda dl=dl: self.connection(dl)) for dl in self.downloads]
        time.sleep(3.2)
        second = [self.connection(dl) for dl in self.downloads]
        self.samples = [first, second]
        (self.work / "active-samples.json").write_text(json.dumps(self.samples, indent=2) + "\n")
        for dl, a, b in zip(self.downloads, first, second):
            require(dl.process.poll() is None and b is not None, f"{dl.label} ended before sampling")
            require(a["id"] == b["id"] and b["network"] == "TCP" and b["start_ms"] > 0,
                    f"unexpected live identity: {a} -> {b}")
            require(a["chain"] == b["chain"] == ["P", "SS-AES256"]
                    and b["policy"] == "P" and b["outbound"] == "SS-AES256"
                    and b["rule"] == "FINAL", f"incorrect policy path: {b}")
            # A GET uploads its request once; only download bytes/rates keep growing.
            require(b["up"] >= a["up"] > 0 and b["down"] > a["down"] > 0
                    and b["rate_down"] > a["rate_down"] > 0,
                    f"counters/rates did not grow: {a} -> {b}")
        return str([{k: c[k] for k in ("id", "chain", "down", "rate_down")} for c in second])

    def close_download(self):
        require(bool(self.downloads), "no download was started")
        victim = self.downloads[0]
        c = eventually(lambda: self.connection(victim))
        require(victim.process.poll() is None and c["down"] > 0, "victim is not downloading")
        started = time.monotonic()
        result = self.call("DELETE", f"/v1/connections/{c['id']}")
        require(result.get("closed") == 1 and result.get("id") == c["id"], str(result))
        # Do not terminate curl ourselves until cleanup: a stuck download must fail.
        code = victim.process.wait(timeout=5)
        elapsed = time.monotonic() - started
        size = int(float(victim.size_path.read_text().strip() or "0"))
        require(code != 0 and 0 < size < FILE_SIZE and elapsed < 5
                and time.monotonic() - victim.started < FILE_SIZE / MAX_RATE / 2,
                f"curl exit={code}, bytes={size}/{FILE_SIZE}, close took {elapsed:.2f}s")
        eventually(lambda: all(x["id"] != c["id"] for x in self.call("GET", "/v1/connections/active")))
        self.closed_id = c["id"]
        for other in self.downloads[1:]:
            require(other.process.poll() is None and self.connection(other) is not None,
                    "DELETE also stopped an unrelated download")
        return f"id={c['id']}, curl exit={code}, {size}/{FILE_SIZE} bytes, stopped in {elapsed:.2f}s"

    def node_test(self, node):
        result = self.call("POST", f"/v1/nodes/{urllib.parse.quote(node, safe='')}/test",
                           url=HTTP_URL + "/health", timeout=5000)
        require(result.get("node") == node and result.get("outbound") == node, str(result))
        if node == "Broken":
            require(result.get("ok") is False and bool(result.get("error"))
                    and result.get("latency_ms") is None, str(result))
        else:
            latency, connect = result.get("latency_ms"), result.get("connect_ms")
            require(result.get("ok") is True and result.get("status") == 200
                    and isinstance(latency, int) and isinstance(connect, int)
                    and 0 <= connect <= latency and latency > 0 and result.get("error") is None,
                    str(result))
        return json.dumps(result)

    def history(self):
        a = self.call("GET", "/v1/stats")
        time.sleep(2.2)
        b = self.call("GET", "/v1/stats")
        ah, bh = a["history"], b["history"]
        require(len(bh) > len(ah) and bool(ah) and bh[-1]["time_ms"] > ah[-1]["time_ms"],
                f"history did not grow: {len(ah)} -> {len(bh)}")
        added = [s for s in bh if s["time_ms"] > ah[-1]["time_ms"]]
        require(b["down"] > a["down"] > 0 and any(s["down"] > 0 for s in added)
                and all(x["time_ms"] < y["time_ms"] for x, y in zip(bh, bh[1:])),
                f"missing traffic or invalid timestamps: {added}")
        for key, name in (("policies", "P"), ("nodes", "SS-AES256")):
            before = next(n for n in a[key] if n["name"] == name)
            after = next(n for n in b[key] if n["name"] == name)
            require(after["down"] > before["down"] > 0, f"{key} totals did not grow")
        require(any(p["policy"] == "P" and p["down"] > 0 for s in added for p in s["policies"]),
                "new samples do not attribute bytes to P")
        return f"samples {len(ah)} -> {len(bh)}, bytes down {a['down']} -> {b['down']}"

    def profile(self):
        main, alt = self.work / "main.conf", self.work / "alt.conf"
        current = self.call("GET", "/v1/profile")
        require(Path(current["path"]).resolve() == main, str(current))
        require({main, alt} <= {Path(p).resolve() for p in current["profiles"]}, str(current))
        try:
            switched = self.call("POST", "/v1/profile", path=str(alt))
            require(switched.get("reloaded") is True
                    and Path(self.call("GET", "/v1/profile")["path"]).resolve() == alt, str(switched))
            dl = self.download("alt-profile")
            c = eventually(lambda: self.connection(dl))
            require(c["chain"] == ["DIRECT"] and c["outbound"] == c["policy"] == "DIRECT"
                    and c["rule"] == "FINAL", f"alt profile did not route a real connection: {c}")
            eventually(lambda: (self.connection(dl) or {}).get("down", 0) > 0)
        finally:
            restored = self.call("POST", "/v1/profile", path=str(main))
            require(restored.get("reloaded") is True
                    and Path(self.call("GET", "/v1/profile")["path"]).resolve() == main, str(restored))
        dl = self.download("restored-profile")
        c = eventually(lambda: self.connection(dl))
        require(c["chain"] == ["P", "SS-AES256"], f"restored profile chain: {c}")
        eventually(lambda: (self.connection(dl) or {}).get("down", 0) > 0)
        return "main [P, SS-AES256] -> alt [DIRECT] -> main [P, SS-AES256], real downloads"

    def events(self):
        raw = (self.work / "events.sse").read_text()
        kinds = {}
        # Ignore only an unfinished final frame while curl is still streaming.
        for frame in raw.split("\n\n")[:-1]:
            lines = frame.splitlines()
            kind = next((s[7:] for s in lines if s.startswith("event: ")), None)
            if kind:
                data = "\n".join(s[6:] for s in lines if s.startswith("data: "))
                kinds.setdefault(kind, []).append(json.loads(data))
        require({"traffic", "conn_open", "conn_close", "log"} <= kinds.keys(),
                f"missing SSE kinds: {list(kinds)}")
        traffic = [e for e in kinds["traffic"] if e.get("down", 0) > 0]
        require(len(traffic) >= 2 and traffic[-1]["total_down"] > traffic[0]["total_down"]
                and any(e["active"] >= 3 for e in traffic), "SSE traffic did not track downloads")
        require(self.closed_id is not None, "DELETE did not identify a closed download")
        opened = next((e for e in kinds["conn_open"] if e["id"] == self.closed_id), None)
        closed = next((e for e in kinds["conn_close"] if e["id"] == self.closed_id), None)
        require(opened and closed and opened["chain"] == closed["chain"] == ["P", "SS-AES256"]
                and closed["down"] > 0, "SSE open/close did not match the deleted download")
        require(any(e.get("time_ms", 0) > 0 and e.get("level") == "INFO"
                    and "127.0.0.1:18080" in e.get("message", "") for e in kinds["log"]),
                "no routing log event for the local traffic")
        return str({k: len(v) for k, v in kinds.items()})


def traffic(socks):
    """Keep three curl loops alive while the independent editor/app hooks run."""
    running = True

    def end(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, end)
    signal.signal(signal.SIGINT, end)
    children = []
    try:
        while running:
            children = [p for p in children if p.poll() is None]  # poll also reaps
            while len(children) < 3:
                children.append(subprocess.Popen(curl_download(socks, "hook-traffic"), env=CURL_ENV))
            time.sleep(0.2)
    finally:
        # Signal all children before waiting on any one of them.
        for p in children:
            if p.poll() is None:
                p.terminate()
        for p in children:
            stop(p)


def wait_for_traffic(api):
    def sample():
        conn = http.client.HTTPConnection(api, timeout=2)
        try:
            conn.request("GET", "/v1/connections/active")
            response = conn.getresponse()
            data = json.loads(response.read())
            require(response.status == 200, str(data))
            moving = [c for c in data if c.get("target") == "127.0.0.1:18080"
                      and c.get("down", 0) > 0 and c.get("rate_down", 0) > 0]
            return moving if len(moving) >= 3 else None
        finally:
            conn.close()

    moving = eventually(sample)
    print(f"PASS hook traffic: {len(moving)} active downloads with positive bytes/rates", flush=True)


def main(api, socks, directory):
    def interrupted(signum, _frame):
        # Execute the finally block so an interrupted run reaps its curl children.
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    work = Path(directory).resolve()
    work.mkdir(parents=True, exist_ok=True)
    checks = Checks(api, socks, work)
    stream = None
    with (work / "events.sse").open("wb") as out, (work / "events-curl.log").open("wb") as err:
        try:
            stream = subprocess.Popen(["curl", "--disable", "--fail", "--silent", "--show-error",
                                       "--no-buffer", "--noproxy", "*", "--max-time", "100",
                                       f"http://{api}/v1/events"], stdout=out, stderr=err, env=CURL_ENV)
            checks.run("SSE subscription", lambda: eventually(
                lambda: ": sluice events" in (work / "events.sse").read_text(), timeout=5))
            checks.run("active downloads: policy chain, bytes and increasing rates", checks.active_and_rates)
            checks.run("DELETE live connection stops only its curl", checks.close_download)
            for node in ("SS-AES256", "VMess", "VLESS", "Hysteria2", "Broken"):
                checks.run(f"node latency {node}", lambda node=node: checks.node_test(node))
            checks.run("stats history and attributed totals grow", checks.history)
            checks.run("profile switch and restore change new connection chains", checks.profile)
            checks.run("SSE traffic, conn_open, conn_close and log payloads", checks.events)
        finally:
            for dl in checks.downloads:
                dl.close()
            if stream is not None:
                stop(stream)
            checks.transcript.close()
    print(f"{'FAIL' if checks.fails else 'PASS'} API checks: {checks.fails} failed", flush=True)
    return bool(checks.fails)


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("FAIL e2e: network checks may only run on GitHub Actions")
    if sys.argv[1:] == ["--serve"]:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
        server.daemon_threads = True
        server.serve_forever()
    elif len(sys.argv) == 3 and sys.argv[1] == "--traffic":
        traffic(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--wait-traffic":
        wait_for_traffic(sys.argv[2])
    elif len(sys.argv) == 4:
        sys.exit(main(*sys.argv[1:]))
    else:
        sys.exit(__doc__)
