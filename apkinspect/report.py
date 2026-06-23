"""Render a :class:`ScanResult` as a colourised terminal report or JSON."""
from __future__ import annotations

import json

from .model import SEVERITIES, ScanResult

_COLORS = {
    "CRITICAL": "\033[1;37;41m",  # white on red
    "HIGH": "\033[1;31m",          # bold red
    "MEDIUM": "\033[33m",          # yellow
    "LOW": "\033[36m",             # cyan
    "INFO": "\033[2m",             # dim
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_GLYPHS = {
    True: {"h": "─", "full": "█", "empty": "░", "ell": "…"},
    False: {"h": "-", "full": "#", "empty": ".", "ell": "..."},
}


def _grade_color(grade: str) -> str:
    return {
        "A": "\033[1;32m", "B": "\033[32m", "C": "\033[33m",
        "D": "\033[31m", "F": "\033[1;37;41m",
    }.get(grade, "")


class _Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled or not code:
            return text
        return f"{code}{text}{_RESET}"


def _score_bar(score: int, full: str, empty: str, width: int = 24) -> str:
    filled = round(score / 100 * width)
    return full * filled + empty * (width - filled)


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{n} B"


def render_text(result: ScanResult, color: bool = True, quiet: bool = False,
                ascii_only: bool = False) -> str:
    paint = _Painter(color)
    g = _GLYPHS[not ascii_only]
    out: list[str] = []
    line = g["h"] * 64

    out.append(paint(line, _DIM))
    out.append(paint("  APKInspect security report", _BOLD))
    out.append(paint(line, _DIM))
    out.append(f"  File       : {result.path}")
    out.append(f"  Type       : {result.file_type.upper()}   "
               f"Size: {_human_size(result.file_size)}   "
               f"Entries: {result.meta.get('entry_count', '?')}")
    if result.package:
        ver = ""
        if result.version_name or result.version_code:
            ver = f"  v{result.version_name} ({result.version_code})"
        out.append(f"  Package    : {result.package}{ver}")
    out.append(f"  SDK        : minSdk={result.min_sdk}  targetSdk={result.target_sdk}   "
               f"dex={result.meta.get('dex_count', '?')}  "
               f"native_libs={result.meta.get('has_native_libs', '?')}")

    # ---- score ----
    gc = _grade_color(result.grade)
    bar = _score_bar(result.score, g["full"], g["empty"])
    out.append("")
    out.append(f"  SAFETY SCORE  {paint(f'{result.score:>3}/100', gc)}  "
               f"[{paint(bar, gc)}]  "
               f"{paint('grade ' + result.grade, gc)}  "
               f"{paint('(' + result.risk_label + ')', _DIM)}")

    counts = result.counts()
    summary = "  ".join(
        paint(f"{s.title()}: {counts[s]}", _COLORS[s]) for s in SEVERITIES if counts[s]
    )
    out.append(f"  Findings      {summary or paint('none', _COLORS['INFO'])}")
    out.append("")

    if not quiet:
        current = None
        for f in result.sorted_findings():
            if f.severity != current:
                current = f.severity
                header = f"  {g['h'] * 2} {f.severity} " + g["h"] * (58 - len(f.severity))
                out.append(paint(header, _COLORS[f.severity]))
            tag = paint(f"[{f.severity}]", _COLORS[f.severity])
            out.append(f"  {tag} {paint(f.title, _BOLD)}  {paint('(' + f.id + ')', _DIM)}")
            if f.location:
                out.append(f"        location : {f.location}")
            if f.detail:
                out.append(f"        detail   : {f.detail}")
            if f.evidence:
                out.append(f"        evidence : {paint(f.evidence, _COLORS['HIGH'])}")
            if f.recommendation:
                out.append(f"        fix      : {paint(f.recommendation, _DIM)}")
            out.append("")

    if result.errors:
        out.append(paint("  Notes / errors:", _DIM))
        for e in result.errors:
            out.append(paint(f"    - {e}", _DIM))
        out.append("")

    if result.meta.get("manifest_note"):
        out.append(paint(f"  * {result.meta['manifest_note']}", _DIM))

    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
