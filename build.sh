#!/bin/bash
# Builds dist/Warden.app (menu-bar app + bundled `warden` CLI), ad-hoc signed, plus dist/warden and a zip.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${VERSION:-1.0.0}"
swift build -c release 2>&1 | grep -E "error:|Build complete" | tail -3
BIN=.build/release
APP=dist/Warden.app
rm -rf dist && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
cp "$BIN/WardenBar" "$APP/Contents/MacOS/WardenBar"
cp "$BIN/warden" "$APP/Contents/Resources/bin/warden"
cp "$BIN/warden" dist/warden
ICONSET="$(mktemp -d)/Warden.iconset"
"$BIN/WardenBar" --make-icon "$ICONSET"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>app.warden.mac</string>
  <key>CFBundleName</key><string>Warden</string>
  <key>CFBundleDisplayName</key><string>Warden</string>
  <key>CFBundleExecutable</key><string>WardenBar</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>LSMultipleInstancesProhibited</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticTermination</key><false/>
  <key>NSSupportsSuddenTermination</key><false/>
</dict></plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --deep --sign - "$APP" 2>&1 | tail -1
codesign --verify --deep --strict "$APP" && echo "signature OK (ad-hoc)"
(cd dist && ditto -c -k --keepParent Warden.app Warden.zip && ditto -c -k --keepParent Warden.app "Warden-$VERSION.zip")
echo "built: $APP ($(du -sh "$APP" | cut -f1)), dist/warden, dist/Warden-$VERSION.zip"
