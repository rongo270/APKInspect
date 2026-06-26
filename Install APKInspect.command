#!/usr/bin/env bash
# APKInspect installer for macOS and Linux.
#   Installs APKInspect into Python so you can run, from any terminal:
#     apkinspect       (command-line scanner)
#     apkinspect-gui   (the graphical app)
#   macOS: double-click this file in Finder (first time: right-click -> Open).
#   Linux / Terminal: run  ./Install\ APKInspect.command
# It finds Python 3.8+, offers to install it if missing, then runs pip install.

cd "$(dirname "$0")" || exit 1

echo "=================================================="
echo "  Install APKInspect"
echo "=================================================="
echo
echo "This installs APKInspect into Python so you can run"
echo "  apkinspect       (command-line scanner)"
echo "  apkinspect-gui   (the graphical app)"
echo "from any terminal window."
echo
echo "You need Python 3.8 or newer first. If you do not have"
echo "it, the one-click APKInspect.command installs it for you."
echo

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

PY="$(find_python)"

# --- offer to install Python via Homebrew if it is missing (macOS) ---
if [ -z "$PY" ] && command -v brew >/dev/null 2>&1; then
  echo "Python 3 was not found. Installing it via Homebrew..."
  brew install python && PY="$(find_python)"
fi

if [ -z "$PY" ]; then
  echo
  echo "Python 3.8+ is needed and was not found."
  echo "Install it from https://www.python.org/downloads/ then run this again,"
  echo "or just double-click APKInspect.command, which installs Python for you."
  command -v open     >/dev/null 2>&1 && open     "https://www.python.org/downloads/"
  command -v xdg-open >/dev/null 2>&1 && xdg-open "https://www.python.org/downloads/"
  echo
  read -r -n 1 -s -p "Press any key to close..." _ 2>/dev/null || read -r _
  exit 1
fi

echo "Using $("$PY" --version 2>&1)"
echo
echo "Installing APKInspect (this can take a moment)..."
"$PY" -m pip install --upgrade pip >/dev/null 2>&1
if ! "$PY" -m pip install .; then
  echo
  echo "Install failed. You can still run APKInspect without installing"
  echo "by double-clicking APKInspect.command in this folder."
  echo
  read -r -n 1 -s -p "Press any key to close..." _ 2>/dev/null || read -r _
  exit 1
fi

echo
echo "============================================"
echo "  Done. APKInspect is installed."
echo
echo "  Command line:  apkinspect path/to/app.apk"
echo "  Graphical app: apkinspect-gui"
echo "============================================"
echo
read -r -n 1 -s -p "Press any key to close..." _ 2>/dev/null || read -r _
