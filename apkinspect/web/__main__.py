"""``python -m apkinspect.web`` -> launch the GUI and open it in the browser."""
from __future__ import annotations

import argparse

from .server import run


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="apkinspect.web", description="Launch the APKInspect web GUI.")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    p.add_argument("--no-browser", action="store_true", help="do not auto-open the browser")
    args = p.parse_args(argv)
    run(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
