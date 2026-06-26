#!/usr/bin/env pythonw
"""APKInspect - double-click launcher for Windows (no console window).

Requires Python 3.8+ from https://www.python.org/downloads/
(during install, tick "Add python.exe to PATH").

Double-clicking this file just starts the local web app and opens your
browser. Everything runs on your own computer (127.0.0.1) - nothing is
uploaded. See INSTALL.txt for full instructions.
"""
import os
import sys
import runpy

# Run the bundled package even if launched from another folder.
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

# pythonw.exe has no console, so sys.stdout / sys.stderr are None. Give the
# server a harmless place to write its log lines so request handling can't
# crash on a missing console.
if sys.stdout is None or sys.stderr is None:
    _log_dir = os.environ.get("TEMP") or os.environ.get("TMP") or BASE
    _log = open(os.path.join(_log_dir, "apkinspect.log"),
                "a", buffering=1, encoding="utf-8", errors="replace")
    if sys.stdout is None:
        sys.stdout = _log
    if sys.stderr is None:
        sys.stderr = _log

runpy.run_module("apkinspect.web", run_name="__main__")
