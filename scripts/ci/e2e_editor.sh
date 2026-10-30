#!/bin/bash
# Structured editor save/reload round-trip. Called with the core and traffic still running.
# Network operations are deliberately restricted to GitHub Actions.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 <api-addr> <workdir>" >&2
    exit 2
fi
if [[ ${GITHUB_ACTIONS:-} != true ]]; then
    echo "e2e_editor.sh only runs on GitHub Actions; use swift test for offline editor checks." >&2
    exit 2
fi
cd "$(dirname "$0")/../.."
mkdir -p "$2/editor"
python3 - "$1" "$2" <<'PY' 2>&1 | tee "$2/editor/editor.log"
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.request

addr, work = sys.argv[1], Path(sys.argv[2]).resolve()
logs = work / "editor"
base = f"http://{addr}"
# Ignore the runner's proxy environment even for loopback requests.
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(endpoint, method="GET", artifact=None):
    request = urllib.request.Request(base + endpoint, method=method)
    with http.open(request, timeout=30) as response:
        data = response.read()
    if artifact:
        (logs / artifact).write_bytes(data)
    return json.loads(data)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic_write(path, data, mode):
    fd, name = tempfile.mkstemp(prefix=".e2e-editor-save-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def reload(artifact):
    result = api("/v1/reload", "POST", artifact)
    require(result.get("reloaded") is True, f"Reload failed: {result}")


def interrupted(signum, frame):
    raise SystemExit(f"Interrupted by signal {signum}; restoring the original profile")


signal.signal(signal.SIGTERM, interrupted)
profile = api("/v1/profile", artifact="profile-before.json")
# The API supplies the exact file POST /v1/reload reads, including after an API profile switch.
active = Path(profile["path"]).resolve()
require(active.is_relative_to(work), f"Active profile must be under the e2e workdir: {active}")
original = active.read_bytes()
permissions = active.stat().st_mode & 0o777
(logs / "original.conf").write_bytes(original)
before_groups = api("/v1/policies", artifact="policies-before.json")
require(all(g["group"] != "E2E-Group" for g in before_groups), "Editor group already exists")
mode = api("/v1/mode", artifact="mode-before.json")["mode"]
fd, name = tempfile.mkstemp(prefix=".e2e-editor-", suffix=".conf", dir=active.parent)
os.close(fd)
candidate = Path(name)
modified = False
try:
    shutil.copyfile(active, candidate)
    env = dict(os.environ, SLUICE_E2E_CONFIG=str(candidate))
    command = ["swift", "test", "--package-path", "apps/macos", "--filter",
               "StructuredEditorRoundTripTests/testEditCIProfile"]
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=300)
    (logs / "swift-test.log").write_text(result.stdout)
    print(result.stdout, flush=True)
    require(result.returncode == 0, f"Structured editor test exited {result.returncode}")
    require("SLUICE_E2E_EDIT_SAVED" in result.stdout, "The filtered editor test did not run")
    shutil.copyfile(candidate, logs / "edited.conf")
    # A sibling candidate keeps relative rule-set/subscription paths meaningful during check.
    result = subprocess.run(["target/release/sluice", "check", str(candidate)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    (logs / "check.log").write_text(result.stdout)
    print(result.stdout, flush=True)
    require(result.returncode == 0, f"sluice check exited {result.returncode}")
    require(active.read_bytes() == original, "Active profile changed while the editor was saving")
    require(api("/v1/profile")["path"] == profile["path"], "Active profile switched during editing")
    modified = True  # Restore even if replacement or reload raises.
    atomic_write(active, candidate.read_bytes(), permissions)
    reload("reload-edited.json")
    if mode != "rule":
        api("/v1/mode?set=rule", "POST")
    groups = api("/v1/policies", artifact="policies-edited.json")
    group = next((g for g in groups if g["group"] == "E2E-Group"), None)
    require(group is not None, "Saved editor group is not live")
    require(group["type"] == "select" and group["selected"] == "DIRECT"
            and [o["name"] for o in group["options"]] == ["DIRECT"], f"Wrong editor group: {group}")
    route = api("/v1/route?target=e2e-editor.test:443", artifact="route-edited.json")
    require(route["rule"] == "DOMAIN,e2e-editor.test" and route["policy"] == "DIRECT"
            and route["outbound"] == "DIRECT", f"Saved editor rule is not live: {route}")
    print("PASS: structured rule and group saved, validated, reloaded and observed through the API", flush=True)
finally:
    try:
        if modified:
            atomic_write(active, original, permissions)
            reload("reload-restored.json")
            groups = api("/v1/policies", artifact="policies-restored.json")
            require({g["group"] for g in groups} == {g["group"] for g in before_groups},
                    "Policy groups were not restored")
            route = api("/v1/route?target=e2e-editor.test:443", artifact="route-restored.json")
            require(route["rule"] != "DOMAIN,e2e-editor.test", "Editor rule survived restoration")
            require(active.read_bytes() == original, "Original profile bytes were not restored")
            require(api("/v1/profile")["path"] == profile["path"], "Active profile path changed")
            print("PASS: original profile restored and reloaded", flush=True)
    finally:
        try:
            if modified and mode != "rule":
                result = api(f"/v1/mode?set={mode}", "POST", "mode-restored.json")
                require(result["mode"] == mode, "Outbound mode was not restored")
        finally:
            candidate.unlink(missing_ok=True)
PY
