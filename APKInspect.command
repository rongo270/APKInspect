#!/usr/bin/env bash
# APKInspect launcher for macOS and Linux.
#   - macOS: double-click this file in Finder (Terminal opens and runs it).
#   - Linux / Terminal: run  ./APKInspect.command
# It finds Python 3, offers to install it if missing, then starts the local GUI.

cd "$(dirname "$0")" || exit 1

echo "============================================"
echo "  APKInspect - Android APK/AAB security GUI"
echo "============================================"

# --- find a Python 3.8+ interpreter (skips macOS's legacy python 2) ---
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 \
     && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    PY="$c"; break
  fi
done

# --- offer to install Python if it is missing ---
if [ -z "$PY" ] && command -v brew >/dev/null 2>&1; then
  echo "Python 3 was not found. Installing it via Homebrew..."
  brew install python && PY=python3
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

echo "Using $("$PY" --version 2>&1)"
echo "Starting the local app and opening your browser... (press Ctrl+C to stop)"
echo
exec "$PY" -m apkinspect.web
