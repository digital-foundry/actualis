#!/bin/bash
# Build the menu bar app into a .app bundle. No Xcode project, no dependencies.
set -euo pipefail
cd "$(dirname "$0")"

APP="agentfleet.app"
NAME="agentfleet"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# No -parse-as-library: the file is main.swift, so top-level code is the entry
# point. And no `|| true` — a build script that reports success on a failed
# compile is worse than no build script.
swiftc -O main.swift -o "$APP/Contents/MacOS/$NAME" \
  -framework AppKit -framework Foundation

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$NAME</string>
    <key>CFBundleDisplayName</key><string>agentfleet</string>
    <key>CFBundleExecutable</key><string>$NAME</string>
    <key>CFBundleIdentifier</key><string>tech.digitalfoundry.agentfleet.tray</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <!-- Menu bar only: no Dock icon, no app switcher entry. -->
    <key>LSUIElement</key><true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright (C) 2026 Digital Foundry Solutions, LLC. AGPL-3.0-or-later.</string>
</dict>
</plist>
PLIST

# Ad-hoc signature: enough to run locally. Distribution needs a Developer ID
# and notarisation, which is a cost to weigh only if this is ever shipped.
codesign --force --deep --sign - "$APP" 2>/dev/null || true
echo "built $(pwd)/$APP"
du -sh "$APP" | cut -f1 | sed 's/^/size: /'
