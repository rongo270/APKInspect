#!/usr/bin/env bash
# APKInspect launcher for macOS and Linux.
#   - macOS: double-click this file in Finder (Terminal opens and runs it).
#            On the first run it builds APKInspect.app (a real icon you can keep
#            in your Dock); after that you can launch from the app instead.
#   - Linux / Terminal: run  ./APKInspect.command
# It finds Python 3, offers to install it if missing, then starts the local GUI.

cd "$(dirname "$0")" || exit 1

echo "============================================"
echo "  APKInspect - Android APK/AAB security GUI"
echo "============================================"

# --- find a Python 3.8+ interpreter (skips macOS's legacy python 2) ---
find_python() {
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 \
       && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

# --- macOS only: build a double-clickable APKInspect.app with the real icon ---
make_mac_app() {
  local app="$PWD/APKInspect.app"
  [ -e "$app" ] && return 0
  if [ ! -f "$PWD/assets/icon.icns" ]; then
    echo "  (skipping app icon: assets/icon.icns is missing - run 'python3 tools/make_icon.py')"
    return 0
  fi
  echo "First-time setup: creating APKInspect.app (with icon)..."
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" || return 0
  cp "$PWD/assets/icon.icns" "$app/Contents/Resources/icon.icns"
  printf 'APPL????' > "$app/Contents/PkgInfo"
  cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>APKInspect</string>
  <key>CFBundleDisplayName</key><string>APKInspect</string>
  <key>CFBundleIdentifier</key><string>com.apkinspect.gui</string>
  <key>CFBundleVersion</key><string>1.0.0</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleSignature</key><string>????</string>
  <key>CFBundleExecutable</key><string>APKInspect</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>LSMinimumSystemVersion</key><string>10.12</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
  cat > "$app/Contents/MacOS/APKInspect" <<'RUN'
#!/bin/bash
# Runs the APKInspect GUI from the repo folder that holds this .app.
cd "$(cd "$(dirname "$0")/../../.." && pwd)" || exit 1
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 \
     && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  osascript -e 'display dialog "APKInspect needs Python 3.8 or newer. Opening the download page now." buttons {"OK"} default button 1 with title "APKInspect"' >/dev/null 2>&1
  open "https://www.python.org/downloads/"
  exit 1
fi
exec "$PY" -m apkinspect.web
RUN
  chmod +x "$app/Contents/MacOS/APKInspect"
  touch "$app"   # nudge Finder to refresh the icon
  echo "  Done - APKInspect.app is in this folder (drag it to your Dock if you like)."
}

PY="$(find_python)"

# --- offer to install Python if it is missing ---
if [ -z "$PY" ] && command -v brew >/dev/null 2>&1; then
  echo "Python 3 was not found. Installing it via Homebrew..."
  brew install python && PY="$(find_python)"
fi

if [ -z "$PY" ]; then
  echo
  echo "Python 3.8+ is needed and was not found."
  echo "Install it from https://www.python.org/downloads/ then run this again."
  command -v open     >/dev/null 2>&1 && open     "https://www.python.org/downloads/"
  command -v xdg-open >/dev/null 2>&1 && xdg-open "https://www.python.org/downloads/"
  echo
  read -r -n 1 -s -p "Press any key to close..." _ 2>/dev/null || read -r _
  exit 1
fi

[ "$(uname)" = "Darwin" ] && make_mac_app

echo "Using $("$PY" --version 2>&1)"
echo "Starting the local app and opening your browser... (press Ctrl+C to stop)"
echo
exec "$PY" -m apkinspect.web
