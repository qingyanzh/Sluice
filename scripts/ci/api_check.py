"""Checks the control API while traffic flows: live connections, stats, node tests,
closing connections, the event stream and profile switching.
Usage: api_check.py <api host:port> <socks port> <work dir>. Prints one line per check."""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

api, socks, work = sys.argv[1], sys.argv[2], sys.argv[3]
fails = 0


def call(method, path):
    req = urllib.request.Request(f"http://{api}{path}", method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, ok, detail=""):
    global fails
    print(f"api {name:<28} {'PASS' if ok else 'FAIL'} {detail}"[:400])
    fails += 0 if ok else 1


events = subprocess.Popen(["curl", "-sN", "-m", "8", f"http://{api}/v1/events"], stdout=subprocess.PIPE)
call("POST", "/v1/policies/P?select=SS-AES256")
dl = subprocess.Popen(["curl", "-s", "-m", "60", "--limit-rate", "1M", "-o", "/dev/null", "-w", "%{size_download}",
                       "--socks5-hostname", f"127.0.0.1:{socks}", "https://speed.cloudflare.com/__down?bytes=50000000"],
                      stdout=subprocess.PIPE)
time.sleep(4)

_, active = call("GET", "/v1/connections/active")
mine = [c for c in active if c["target"].startswith("speed.cloudflare.com")]
c = mine[0] if mine else {}
check("connections/active", bool(mine) and c["chain"] == ["P", "SS-AES256"] and c["down"] > 0
      and c["rate_down"] > 0 and c["policy"] == "P" and c["start_ms"] > 0, json.dumps(c))

_, stats = call("GET", "/v1/stats")
node = {n["name"]: n for n in stats["nodes"]}.get("SS-AES256", {})
hist = stats["history"]
check("stats", node.get("down", 0) > 0 and len(hist) >= 2 and any(s["down"] > 0 for s in hist)
      and any(p["policy"] == "P" for s in hist for p in s["policies"]),
      f"node={node} samples={len(hist)} last={hist[-1:]}")

st, t = call("POST", "/v1/nodes/SS-AES256/test?url=http://example.com/&timeout=8000")
check("nodes/<name>/test", st == 200 and t["ok"] and 0 <= t["connect_ms"] <= t["latency_ms"] and t["status"] == 200, json.dumps(t))
st, t = call("POST", "/v1/nodes/REALITY-WrongKey/test?url=http://example.com/&timeout=8000")
check("nodes test (failing node)", st == 200 and not t["ok"] and t["error"], json.dumps(t))
st, _ = call("POST", "/v1/nodes/NoSuchNode/test")
check("nodes test (unknown)", st == 404)

_, pol = call("GET", "/v1/policies")
n_opts = len(next(p for p in pol if p["group"] == "P")["options"])
st, g = call("POST", "/v1/policies/P/test")
res = {r["name"]: r["latency_ms"] for r in g.get("results", [])}
check("policies/<group>/test", st == 200 and len(res) == n_opts and isinstance(res.get("SS-AES256"), int)
      and res.get("REALITY-WrongKey") is None, json.dumps(g)[:300])

if mine:
    st, r = call("DELETE", f"/v1/connections/{c['id']}")
    out, _ = dl.communicate(timeout=20)
    size = int(out or b"0")
    _, active = call("GET", "/v1/connections/active")
    check("DELETE connections/<id>", st == 200 and size < 50000000 and all(x["id"] != c["id"] for x in active),
          f"downloaded {size}")
else:
    dl.kill()
    check("DELETE connections/<id>", False, "no connection to close")
st, _ = call("DELETE", "/v1/connections/999999999")
check("DELETE unknown id", st == 404)
st, r = call("DELETE", "/v1/connections")
check("DELETE connections", st == 200 and "closed" in r)

raw = events.communicate()[0].decode()
kinds = {}
for frame in raw.split("\n\n"):
    lines = dict(l.split(": ", 1) for l in frame.splitlines() if ": " in l and not l.startswith(":"))
    if "event" in lines:
        json.loads(lines["data"])
        kinds.setdefault(lines["event"], []).append(json.loads(lines["data"]))
check("events", {"traffic", "conn_open", "conn_close", "log"} <= kinds.keys()
      and any(e["down"] > 0 for e in kinds["traffic"]), str({k: len(v) for k, v in kinds.items()}))

_, prof = call("GET", "/v1/profile")
orig = prof["path"]
check("GET profile", orig.endswith("sluice.conf") and orig in prof["profiles"], json.dumps(prof))
with open(orig) as f:
    text = f.read()
with open(os.path.join(work, "other.conf"), "w") as f:
    f.write(text.replace("[Proxy Group]\n", "[Proxy Group]\nSwitched = select, DIRECT\n"))
with open(os.path.join(work, "broken.conf"), "w") as f:
    f.write(text.replace("FINAL,P", "FINAL,Missing"))
st, r = call("POST", f"/v1/profile?path={work}/broken.conf")
_, pol = call("GET", "/v1/policies")
check("POST profile (invalid)", st == 400 and r["path"] == orig and all(p["group"] != "Switched" for p in pol), json.dumps(r))
st, r = call("POST", f"/v1/profile?path={work}/other.conf")
_, pol = call("GET", "/v1/policies")
check("POST profile (valid)", st == 200 and r["path"].endswith("other.conf") and any(p["group"] == "Switched" for p in pol), json.dumps(r))
st, r = call("POST", f"/v1/profile?path={orig}")
check("POST profile (back)", st == 200 and os.path.realpath(call("GET", "/v1/profile")[1]["path"]) == os.path.realpath(orig))

print(f"api checks: {fails} failed")
sys.exit(1 if fails else 0)
