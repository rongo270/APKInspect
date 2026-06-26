"""Render a :class:`ScanResult` as a colourised terminal report, JSON or SARIF."""
from __future__ import annotations

import json
from typing import Iterable, List

from . import __version__, catalog
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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 (for GitHub code scanning / Azure DevOps and other SAST tooling)
# ---------------------------------------------------------------------------
_SARIF_LEVEL = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFO": "none",
}
# GitHub maps this CVSS-like number to its Critical/High/Medium/Low buckets.
_SARIF_SECURITY_SEVERITY = {
    "CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0",
}


def _sarif_uri(path: str) -> str:
    return path.replace("\\", "/")


def render_sarif(results: Iterable[ScanResult]) -> str:
    """Render one or more scan results as a SARIF 2.1.0 log (single run)."""
    rules: dict = {}
    sarif_results: List[dict] = []

    for result in results:
        uri = _sarif_uri(result.path)
        for f in result.sorted_findings():
            entry = catalog.for_finding_id(f.id)
            if f.id not in rules:
                full = f.detail
                if entry:
                    full = f"{entry['what']} {entry['risk']}"
                help_text = f.recommendation or (entry["block"] if entry else "")
                rules[f.id] = {
                    "id": f.id,
                    "name": (entry["title"] if entry else f.title),
                    "shortDescription": {"text": (entry["title"] if entry else f.title)},
                    "fullDescription": {"text": full},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                    "help": {"text": help_text},
                    "properties": {
                        "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
                        "tags": ["security", "android", f.category],
                    },
                }
            message = f.detail or f.title
            if f.evidence:
                message = f"{message} (evidence: {f.evidence})"
            sarif_results.append({
                "ruleId": f.id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": uri}},
                    "logicalLocations": [
                        {"fullyQualifiedName": f.location or result.package or "application"}
                    ],
                }],
                "properties": {"severity": f.severity, "category": f.category,
                               "score": result.score},
            })

    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "APKInspect",
                "version": __version__,
                "informationUri": "https://github.com/rongo270/APKInspect",
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(log, indent=2)
