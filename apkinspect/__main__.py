"""Command-line entry point: ``python -m apkinspect app.apk [app.aab ...]``."""
from __future__ import annotations

import argparse
import json
import sys

from . import baseline
from .model import SEVERITY_RANK
from .report import render_sarif, render_text
from .scanner import scan_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apkinspect",
        description="Static security scanner for Android APK/AAB files. "
                    "Flags dangerous permissions, exported components, hard-coded "
                    "secrets/API keys, exposed Firebase URLs and more, then scores "
                    "the app 0 (fully exposed) - 100 (safe).",
    )
    p.add_argument("paths", nargs="+", help="APK or AAB file(s) to scan")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON instead of a text report")
    fmt.add_argument("--sarif", action="store_true",
                     help="emit SARIF 2.1.0 (GitHub code scanning / SAST tooling)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--quiet", action="store_true", help="summary only (omit per-finding detail)")
    p.add_argument("--no-secrets", action="store_true", help="skip the secret/API-key sweep")
    p.add_argument("--min-score", type=int, metavar="N",
                   help="exit non-zero if any file scores below N (CI gate)")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="exit non-zero if any finding is at or above this severity")
    p.add_argument("--baseline", metavar="FILE",
                   help="suppress findings whose fingerprints are listed in FILE (CI baseline)")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="scan, then write all current findings to FILE as a baseline and exit")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    return p


def _gate_failed(result, min_score, fail_on) -> bool:
    if min_score is not None and result.score < min_score:
        return True
    if fail_on is not None:
        threshold = SEVERITY_RANK[fail_on]
        if any(f.rank <= threshold for f in result.findings):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    out_enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    ascii_only = False if args.output else not out_enc.startswith("utf")
    color = (not args.output) and sys.stdout.isatty() and not args.no_color
    # Safety net so a legacy code page can never crash the report.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    # When writing a baseline we capture the *unsuppressed* findings.
    suppress = None
    if args.baseline and not args.write_baseline:
        try:
            suppress = baseline.load(args.baseline)
        except OSError as exc:
            sys.stderr.write(f"could not read baseline {args.baseline}: {exc}\n")
            return 2

    results = []
    exit_code = 0
    rendered: list[str] = []

    for path in args.paths:
        try:
            result = scan_file(path, scan_secrets=not args.no_secrets, suppress=suppress)
        except Exception as exc:  # never crash the CLI on a bad file
            sys.stderr.write(f"error scanning {path}: {exc}\n")
            exit_code = 2
            continue
        results.append(result)
        if not args.write_baseline and _gate_failed(result, args.min_score, args.fail_on):
            exit_code = max(exit_code, 1)
        if not (args.json or args.sarif):
            rendered.append(render_text(result, color=color, quiet=args.quiet,
                                        ascii_only=ascii_only))

    if args.write_baseline:
        n = baseline.write(args.write_baseline, results)
        sys.stderr.write(f"baseline written to {args.write_baseline} ({n} finding(s))\n")
        return exit_code

    if args.sarif:
        text = render_sarif(results)
    elif args.json:
        payload = [r.to_dict() for r in results]
        text = json.dumps(payload if len(payload) != 1 else payload[0], indent=2)
    else:
        text = "\n".join(rendered)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        sys.stderr.write(f"report written to {args.output}\n")
    else:
        print(text)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
