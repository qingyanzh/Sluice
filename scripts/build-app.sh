#!/bin/bash
# Builds dist/Sluice.app: the SwiftUI app with the Rust core embedded in Contents/Resources.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release
(cd apps/macos && swift build -c release)

app=dist/Sluice.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Library/LaunchDaemons"
bin=$(cd apps/macos && swift build -c release --show-bin-path)
cp "$bin/SluiceApp" "$app/Contents/MacOS/Sluice"
# Privileged helper for enhanced mode, registered by the app with SMAppService (docs/helper.md).
cp "$bin/SluiceHelper" "$app/Contents/MacOS/SluiceHelper"
cp apps/macos/Helper/dev.sluice.Sluice.helper.plist "$app/Contents/Library/LaunchDaemons/"
cp target/release/sluice "$app/Contents/Resources/sluice"
cp apps/macos/Icon/Sluice.icns "$app/Contents/Resources/Sluice.icns"
cp apps/macos/Icon/SluiceMenuBarIcon.png "$app/Contents/Resources/SluiceMenuBarIcon.png"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Sluice</string>
  <key>CFBundleDisplayName</key><string>Sluice</string>
  <key>CFBundleIdentifier</key><string>dev.sluice.Sluice</string>
  <key>CFBundleExecutable</key><string>Sluice</string>
  <key>CFBundleIconFile</key><string>Sluice</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
codesign --force --sign - "$app/Contents/Resources/sluice"
codesign --force --sign - --identifier dev.sluice.Sluice.helper "$app/Contents/MacOS/SluiceHelper"
codesign --force --sign - "$app"
echo "built $app"
