"""Baseline suppression.

A baseline records the *fingerprints* of findings you have reviewed and accepted,
so a CI gate only fires on **new** issues.  It is a small JSON file:

    {
      "version": 1,
      "tool": "apkinspect",
      "fingerprints": {
        "<sha1>": {"id": "...", "location": "...", "title": "..."}
      }
    }

A fingerprint is a stable hash of the finding's ``id``, ``location``, ``title``
and (redacted) ``evidence`` — enough to tell two findings apart (e.g. different
dangerous permissions) while surviving re-scans of the same build.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, Set

from .model import Finding


def fingerprint(finding: Finding) -> str:
    raw = "\x1f".join((finding.id, finding.location, finding.title, finding.evidence))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def load(path: str) -> Set[str]:
    """Read a baseline file and return the set of suppressed fingerprints."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    fps = doc.get("fingerprints", {})
    return set(fps.keys() if isinstance(fps, dict) else fps)


def build(results: Iterable) -> dict:
    entries = {}
    for result in results:
        for f in result.findings:
            entries[fingerprint(f)] = {
                "id": f.id,
                "location": f.location,
                "title": f.title,
            }
    return {"version": 1, "tool": "apkinspect", "fingerprints": entries}


def write(path: str, results: Iterable) -> int:
    """Write a baseline capturing every finding in ``results``; return the count."""
    doc = build(results)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return len(doc["fingerprints"])
