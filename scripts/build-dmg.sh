#!/bin/bash
# Builds dist/Sluice-<version>.dmg: Sluice.app next to an Applications link, for drag-to-install.
# Takes the same environment as build-app.sh; SKIP_APP_BUILD=1 packages an existing dist/Sluice.app.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ ${SKIP_APP_BUILD:-0} == 1 ]] || scripts/build-app.sh

version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" dist/Sluice.app/Contents/Info.plist)
dmg="dist/Sluice-$version.dmg"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

ditto dist/Sluice.app "$stage/Sluice.app"
ln -s /Applications "$stage/Applications"

rm -f "$dmg"
hdiutil create -volname "Sluice $version" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
[[ ${SIGN_IDENTITY:--} != - ]] && codesign --force --timestamp --sign "$SIGN_IDENTITY" "$dmg"
echo "built $dmg"
