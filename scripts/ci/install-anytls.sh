#!/bin/bash
# CI only: install the latest reference release without assuming its versioned asset name.
set -euo pipefail
bin_dir=${1:?usage: install-anytls.sh BIN_DIR}
mkdir -p "$bin_dir"
archive_dir=$(mktemp -d)
trap 'rm -rf "$archive_dir"' EXIT
asset=$(gh release view --repo anytls/anytls-go --json assets --jq '.assets[].name' | python3 -c '
import sys
names = [n.strip() for n in sys.stdin]
assets = [n for n in names if "darwin" in n.lower() and "arm64" in n.lower()
          and not any(s in n.lower() for s in ("checksum", "sha256", ".sig"))]
servers = [n for n in assets if "server" in n.lower()]
if servers:
    assets = servers
if len(assets) != 1:
    raise SystemExit(f"expected one darwin arm64 release asset, got {assets!r}; all assets: {names!r}")
print(assets[0])
')
gh release view --repo anytls/anytls-go --json tagName --jq '.tagName'
gh release download --repo anytls/anytls-go --pattern "$asset" --dir "$archive_dir"
mkdir "$archive_dir/unpacked"
case "$asset" in
    *.zip) unzip -q "$archive_dir/$asset" -d "$archive_dir/unpacked" ;;
    *.tar.gz|*.tgz|*.tar.xz|*.tar) tar -xf "$archive_dir/$asset" -C "$archive_dir/unpacked" ;;
    *) cp "$archive_dir/$asset" "$archive_dir/unpacked/anytls-server" ;;
esac
server=$(find "$archive_dir/unpacked" -type f -name anytls-server -print -quit)
if [[ -z "$server" ]]; then
    echo "::error::No anytls-server in release asset $asset"
    find "$archive_dir/unpacked" -type f
    exit 1
fi
cp "$server" "$bin_dir/anytls-server"
chmod +x "$bin_dir/anytls-server"
# This also detects a runner/asset architecture mismatch before interop starts.
"$bin_dir/anytls-server" -h
