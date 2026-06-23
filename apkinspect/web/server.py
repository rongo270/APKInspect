"""A tiny local web server (standard library only) that powers the GUI:

* serves the static single-page app,
* ``GET  /api/catalog`` -> the threat encyclopedia,
* ``POST /api/scan``    -> scans an uploaded APK/AAB and returns the result JSON.

Binds to localhost only; uploads are streamed to a temp file, scanned, removed.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .. import __version__
from ..catalog import as_payload
from ..scanner import scan_file

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "assets")

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".json": "application/json; charset=utf-8",
}
_MAX_UPLOAD = 700 * 1024 * 1024  # 700 MiB


class Handler(BaseHTTPRequestHandler):
    server_version = f"APKInspect/{__version__}"

    # quieter, single-line logging
    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    # ---- helpers ----
    def _send(self, status, body, ctype="application/octet-stream", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json; charset=utf-8")

    def _serve_file(self, path):
        if not os.path.isfile(path):
            self._send(404, "not found", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(path)[1].lower()
        with open(path, "rb") as fh:
            self._send(200, fh.read(), _CONTENT_TYPES.get(ext, "application/octet-stream"))

    def _static(self, name):
        # prevent path traversal: only files directly inside STATIC_DIR
        safe = os.path.basename(name)
        self._serve_file(os.path.join(STATIC_DIR, safe))

    # ---- routing ----
    def do_GET(self):
        route = urlparse(self.path).path
        if route in ("/", "/index.html"):
            self._serve_file(os.path.join(STATIC_DIR, "index.html"))
        elif route == "/icon.svg":
            self._serve_file(os.path.join(STATIC_DIR, "icon.svg"))
        elif route == "/favicon.ico":
            ico = os.path.join(ASSETS_DIR, "icon.ico")
            self._serve_file(ico if os.path.isfile(ico) else os.path.join(STATIC_DIR, "icon.svg"))
        elif route.startswith("/static/"):
            self._static(route[len("/static/"):])
        elif route == "/api/catalog":
            self._json(200, as_payload())
        elif route == "/api/demo":
            self._demo()
        elif route == "/api/health":
            self._json(200, {"status": "ok", "version": __version__})
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def _demo(self):
        candidates = [
            os.environ.get("APKINSPECT_DEMO"),
            os.path.join(os.getcwd(), "samples", "vulnerable.apk"),
            os.path.join(os.path.dirname(ASSETS_DIR), "samples", "vulnerable.apk"),
        ]
        path = next((c for c in candidates if c and os.path.isfile(c)), None)
        if not path:
            self._json(404, {"error": "no bundled sample found — run tools/make_samples.py first"})
            return
        payload = scan_file(path).to_dict()
        payload["path"] = "vulnerable-sample.apk"
        self._json(200, payload)

    do_HEAD = do_GET

    def do_POST(self):
        route = urlparse(self.path).path
        if route != "/api/scan":
            self._json(404, {"error": "unknown endpoint"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"error": "empty upload"})
            return
        if length > _MAX_UPLOAD:
            self._json(413, {"error": "file too large"})
            return

        filename = self.headers.get("X-Filename", "upload.apk")
        ext = os.path.splitext(filename)[1].lower() or ".apk"
        fd, tmp = tempfile.mkstemp(suffix=ext, prefix="apkinspect_")
        try:
            with os.fdopen(fd, "wb") as fh:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    remaining -= len(chunk)
            result = scan_file(tmp)
            payload = result.to_dict()
            payload["path"] = filename  # report the real name, not the temp path
            self._json(200, payload)
        except Exception as exc:  # never leak a stack trace to the browser
            self._json(500, {"error": str(exc)})
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"APKInspect GUI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        httpd.server_close()
