#!/bin/bash
# Builds dist/Sluice-<version>.dmg: Sluice.app next to an Applications link, for drag-to-install.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/build-app.sh

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
dmg="dist/Sluice-$version.dmg"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp -R dist/Sluice.app "$stage/"
ln -s /Applications "$stage/Applications"

rm -f "$dmg"
hdiutil create -volname "Sluice $version" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
echo "built $dmg"
