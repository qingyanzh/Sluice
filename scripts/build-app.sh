#!/bin/bash
# Builds dist/Sluice.app: the SwiftUI app with the Rust core embedded in Contents/Resources
# and Sparkle.framework in Contents/Frameworks.
#
# Environment (all optional):
#   VERSION=1.2.3          CFBundleShortVersionString (default: Cargo.toml version; a leading "v" is dropped)
#   BUILD_NUMBER=42        CFBundleVersion (default: VERSION); Sparkle compares this
#   UNIVERSAL=1            build arm64 + x86_64 instead of the host architecture
#   SIGN_IDENTITY="Developer ID Application: …"   sign with hardened runtime (default: ad-hoc "-")
#   SPARKLE_ED_PUBLIC_KEY  SUPublicEDKey for verifying updates
#   SPARKLE_FEED_URL       SUFeedURL (default: the latest GitHub release's appcast.xml)
set -euo pipefail
cd "$(dirname "$0")/.."

version=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
version=${version#v}
build=${BUILD_NUMBER:-$version}
identity=${SIGN_IDENTITY:--}
feed=${SPARKLE_FEED_URL:-https://github.com/qingyanzh/Sluice/releases/latest/download/appcast.xml}

if [[ ${UNIVERSAL:-0} == 1 ]]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
  cargo build --release --target aarch64-apple-darwin
  cargo build --release --target x86_64-apple-darwin
  mkdir -p target/universal
  lipo -create -output target/universal/sluice \
    target/aarch64-apple-darwin/release/sluice target/x86_64-apple-darwin/release/sluice
  core=target/universal/sluice
  swift_args=(-c release --arch arm64 --arch x86_64)
else
  cargo build --release
  core=target/release/sluice
  swift_args=(-c release)
fi
(cd apps/macos && swift build "${swift_args[@]}")
bin=$(cd apps/macos && swift build "${swift_args[@]}" --show-bin-path)
bin=apps/macos/${bin#"$PWD/apps/macos/"}

app=dist/Sluice.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Frameworks" "$app/Contents/Library/LaunchDaemons"
cp "$bin/SluiceApp" "$app/Contents/MacOS/Sluice"
# Privileged helper for enhanced mode, registered by the app with SMAppService (docs/helper.md).
cp "$bin/SluiceHelper" "$app/Contents/MacOS/SluiceHelper"
cp apps/macos/Helper/dev.sluice.Sluice.helper.plist "$app/Contents/Library/LaunchDaemons/"
# Cached SwiftPM artifacts can have framework symlinks flattened into copies.
# Copy the canonical version and rebuild the links before signing.
framework="$app/Contents/Frameworks/Sparkle.framework"
ditto "$bin/Sparkle.framework/Versions/B" "$framework/Versions/B"
ln -s B "$framework/Versions/Current"
for entry in Autoupdate Sparkle Headers Modules PrivateHeaders Resources Updater.app XPCServices; do
  ln -s "Versions/Current/$entry" "$framework/$entry"
done
cp "$core" "$app/Contents/Resources/sluice"
cp apps/macos/Icon/Sluice.icns "$app/Contents/Resources/Sluice.icns"
cp apps/macos/Icon/SluiceMenuBarIcon.png "$app/Contents/Resources/SluiceMenuBarIcon.png"
public_key=""
[[ -n ${SPARKLE_ED_PUBLIC_KEY:-} ]] && public_key="<key>SUPublicEDKey</key><string>$SPARKLE_ED_PUBLIC_KEY</string>"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Sluice</string>
  <key>CFBundleDisplayName</key><string>Sluice</string>
  <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
  <key>CFBundleLocalizations</key><array><string>zh-Hans</string></array>
  <key>CFBundleIdentifier</key><string>dev.sluice.Sluice</string>
  <key>CFBundleExecutable</key><string>Sluice</string>
  <key>CFBundleIconFile</key><string>Sluice</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$build</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>SUFeedURL</key><string>$feed</string>
  <key>SUEnableAutomaticChecks</key><true/>
  <key>SUScheduledCheckInterval</key><integer>86400</integer>
  $public_key
</dict>
</plist>
PLIST

# Sign inside-out. Hardened runtime only matters (and only works for notarization) with a real identity.
opts=(--force --timestamp --options runtime --sign "$identity")
[[ $identity == - ]] && opts=(--force --sign -)
sparkle="$app/Contents/Frameworks/Sparkle.framework/Versions/B"
codesign "${opts[@]}" "$sparkle/XPCServices/Installer.xpc"
codesign "${opts[@]}" --preserve-metadata=entitlements "$sparkle/XPCServices/Downloader.xpc"
codesign "${opts[@]}" "$sparkle/Autoupdate"
codesign "${opts[@]}" "$sparkle/Updater.app"
codesign "${opts[@]}" "$app/Contents/Frameworks/Sparkle.framework"
codesign "${opts[@]}" --identifier dev.sluice.core --entitlements apps/macos/Entitlements/core.entitlements "$app/Contents/Resources/sluice"
scripts/record-core-cdhash.sh "$app/Contents/MacOS/SluiceHelper" "$app/Contents/Resources/sluice"
codesign "${opts[@]}" --identifier dev.sluice.Sluice.helper "$app/Contents/MacOS/SluiceHelper"
codesign "${opts[@]}" --entitlements apps/macos/Entitlements/Sluice.entitlements "$app"
codesign --verify --deep --strict "$app"
echo "built $app ($version, build $build, signed by ${identity/#-/ad-hoc})"
