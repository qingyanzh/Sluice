#!/bin/bash
# Called by e2e.sh while its core and background SOCKS traffic are still running.
# Deliberately CI-only: never attach to the developer's proxy or change system settings.
# See E2ELaunch.swift for the inert-in-normal-use launch controls. Requires a logged-in
# WindowServer session with screen capture available; no Accessibility permission.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ ${GITHUB_ACTIONS:-} != true ]]; then
  echo 'e2e_screens.sh only runs on GitHub Actions' >&2
  exit 1
fi
if [[ $# != 2 ]]; then
  echo "usage: $0 API_HOST:PORT WORK_DIR" >&2
  exit 1
fi
api=$1
mkdir -p "$2/screenshots" "$2/app"
work=$(cd "$2" && pwd)
shots="$work/screenshots"
app=dist/Sluice.app
binary=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")
executable="$PWD/$app/Contents/MacOS/$binary"
[[ -x $executable ]] || { echo "missing app binary: $executable" >&2; exit 1; }
app_pid=''
stop_app() {
  if [[ -n $app_pid ]]; then
    kill -TERM "$app_pid" 2>/dev/null || true
    for ((attempt=0; attempt<30; attempt++)); do
      kill -0 "$app_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
    app_pid=''
  fi
}
trap stop_app EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Select the contract's main fixture via the API: the editor hook may have left the
# core on alt.conf. Read real node names instead of assuming fixture-specific names.
# Save raw API evidence alongside screenshots; no synthetic UI fixtures are generated.
python3 - "$api" "$work" <<'PY'
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

address, work = sys.argv[1], Path(sys.argv[2])
parsed = urllib.parse.urlsplit('http://' + address)
if (parsed.hostname not in ('127.0.0.1', 'localhost', '::1') or not parsed.port
        or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password):
    raise SystemExit('E2E requires a loopback API host:port')
client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
base = 'http://' + address

def request(path, post=False):
    req = urllib.request.Request(base + path, method='POST' if post else 'GET')
    with client.open(req, timeout=20) as response:
        return json.load(response)

request('/v1/profile?' + urllib.parse.urlencode({'path': str(work / 'main.conf')}), post=True)
profile = request('/v1/profile')
(work / 'app/profile-api.json').write_text(json.dumps(profile, indent=2))
# API returns {path, profiles}; show the same file that the running core uses.
config = Path(profile['path']).resolve()
if not config.is_file():
    raise SystemExit(f'Active core profile is unavailable: {config}')
(work / 'app/active-config-path').write_text(str(config))
text = config.read_text()
section, nodes, test_url = '', [], os.environ.get('SLUICE_E2E_TEST_URL')
for raw in text.splitlines():
    line = raw.strip()
    if line.startswith('[') and line.endswith(']'):
        section = line[1:-1]
    elif line and not line.startswith(('#', ';', '//')):
        if section == 'Proxy' and '=' in line:
            nodes.append(line.split('=', 1)[0].strip())
        if section == 'Proxy Group' and not test_url:
            for part in line.split(',')[1:]:
                key, _, value = part.strip().partition('=')
                if key in ('url', 'test-url') and value.startswith('http://127.0.0.1:'):
                    test_url = value
if not nodes:
    raise SystemExit('No real proxy nodes available for latency screenshots')
# The API itself is a local HTTP target shared by every fixture node. Its response
# to HEAD is 404, which still measures a complete proxy handshake + HTTP round trip.
# A fixture's local group URL or explicit override takes precedence.
if not test_url:
    test_url = base + '/v1/traffic'

def test(node):
    query = {'timeout': '5000'}
    if test_url:
        query['url'] = test_url
    return request('/v1/nodes/' + urllib.parse.quote(node, safe='') + '/test?'
                   + urllib.parse.urlencode(query), post=True)

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(test, nodes))
(work / 'app/node-tests.json').write_text(json.dumps(results, indent=2))
if not any(result.get('ok') and result.get('latency_ms') is not None for result in results):
    raise SystemExit('No successful node latency test; see app/node-tests.json')
# Populate the core's resolver cache through a real DIRECT request even when
# fixture downloads use numeric loopback addresses. This hook only runs in CI.
if not request('/v1/dns').get('entries'):
    dns_probe = request('/v1/nodes/DIRECT/test?' + urllib.parse.urlencode({
        'url': 'http://example.com/', 'timeout': '5000',
    }), post=True)
    (work / 'app/dns-probe.json').write_text(json.dumps(dns_probe, indent=2))
for endpoint in ('policies', 'connections', 'connections/active', 'traffic', 'stats', 'dns'):
    result = request('/v1/' + endpoint)
    (work / ('app/' + endpoint.replace('/', '-') + '.json')).write_text(json.dumps(result, indent=2))
    if endpoint == 'dns' and not result.get('entries'):
        print('DNS cache remains empty (system resolver fixtures do not cache); capturing its real state.', file=sys.stderr)
PY
config=$(cat "$work/app/active-config-path")

# Compile once. CGWindowList does not require Accessibility permission. Restrict by
# PID and the app's readiness window ID so menu extras/other apps cannot be selected.
cat > "$work/app/window-id.swift" <<'SWIFT'
import CoreGraphics
import Foundation
let pid = Int(CommandLine.arguments[1])!
let expected = Int(CommandLine.arguments[2])!
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
let matches = windows.filter {
    ($0[kCGWindowOwnerPID as String] as? Int) == pid &&
    ($0[kCGWindowLayer as String] as? Int) == 0 &&
    ($0[kCGWindowNumber as String] as? Int) == expected
}
if let window = matches.first, let id = window[kCGWindowNumber as String] as? Int { print(id) }
SWIFT
swiftc "$work/app/window-id.swift" -o "$work/app/window-id"

# The menu-bar extra uses a native NSMenu, not a popover with a public programmatic
# presentation binding. Opening it would require the unavailable Accessibility clicks.
printf '%s\n' 'Native menu-bar menu omitted: no public presentation API; Accessibility clicks unavailable.' > "$work/app/menu-bar.txt"
panes=(activity requests-recent requests-active policies nodes rules dns stats profiles editor-rules editor-policies settings settings-maintenance logs)
failures=0
index=0
for pane in "${panes[@]}"; do
  index=$((index + 1))
  name=$(printf '%02d-%s' "$index" "$pane")
  ready="$work/app/$name-ready.json"
  png="$shots/$name.png"
  rm -f "$ready" "$png"
  echo "screenshot: $pane"
  SLUICE_E2E=1 SLUICE_E2E_NODE_TESTS="$work/app/node-tests.json" \
    "$executable" -SluiceE2EAPI "$api" -SluiceE2EConfig "$config" \
    -SluiceE2EPane "$pane" -SluiceE2EReady "$ready" \
    > "$work/app/$name.log" 2>&1 &
  app_pid=$!
  for ((attempt=0; attempt<100; attempt++)); do
    [[ -s $ready ]] && break
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.5
  done
  if [[ ! -s $ready ]] || ! kill -0 "$app_pid" 2>/dev/null; then
    echo "FAIL: $pane did not report populated UI readiness" >&2
    failures=$((failures + 1))
    # Keep a diagnostic capture even if the app failed to load.
    screencapture -x "$shots/$name-failed.png" 2>> "$work/app/$name.log" || true
    stop_app
    continue
  fi
  expected_window=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["window"])' "$ready")
  window_id=$("$work/app/window-id" "$app_pid" "$expected_window")
  if [[ -z $window_id ]] || ! screencapture -x -l "$window_id" "$png" 2>> "$work/app/$name.log"; then
    echo "$pane: window capture unavailable; falling back to full screen" >> "$work/app/$name.log"
    screencapture -x "$png" 2>> "$work/app/$name.log" || true
  fi
  # Decode the actual PNG as well as checking size: blank/truncated artifacts fail.
  if ! python3 - "$png" <<'PY'
from pathlib import Path
import struct
import subprocess
import sys
path = Path(sys.argv[1])
if not path.is_file() or path.stat().st_size < 10000:
    raise SystemExit(f'Missing or tiny screenshot: {path}')
header = path.read_bytes()[:24]
if header[:8] != b'\x89PNG\r\n\x1a\n' or len(header) != 24:
    raise SystemExit(f'Invalid PNG: {path}')
width, height = struct.unpack('>II', header[16:24])
if width < 800 or height < 600:
    raise SystemExit(f'Tiny screenshot dimensions: {width}x{height}')
subprocess.run(['sips', '-g', 'pixelWidth', '-g', 'pixelHeight', str(path)], check=True,
               stdout=subprocess.DEVNULL)
PY
  then
    failures=$((failures + 1))
  fi
  stop_app
  # The app must never stop the core it attached to.
  if ! curl --noproxy '*' -fsS --max-time 5 "http://$api/v1/traffic" > "$work/app/$name-after-quit.json"; then
    echo "FAIL: core unavailable after $pane" >&2
    failures=$((failures + 1))
  fi
done
if [[ $failures != 0 ]]; then
  echo "$failures screenshot checks failed; see $work/app" >&2
  exit 1
fi
echo "captured ${#panes[@]} populated app views in $shots"
