"""Turn a list of findings into a 0-100 safety score.

Model: every issue chips away at a perfect score of 100.  We use a *bounded
multiplicative* model so the score saturates toward 0 (never below) and a long
tail of minor issues can't underflow:

    score = 100 * product over findings of (1 - impact)

``impact`` depends on severity and decays for repeated findings within the same
category, so e.g. 20 dangerous permissions don't zero an otherwise sound app.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .model import Finding

# Fraction of the *remaining* score each severity removes (first occurrence).
IMPACT = {
    "CRITICAL": 0.45,
    "HIGH": 0.22,
    "MEDIUM": 0.09,
    "LOW": 0.025,
    "INFO": 0.0,
}

# Each additional finding in the same category counts for less.
DECAY = 0.55

GRADES = [
    (90, "A", "minimal risk"),
    (75, "B", "low risk"),
    (60, "C", "moderate risk"),
    (40, "D", "high risk"),
    (0, "F", "critical risk"),
]


def grade_for(score: int) -> tuple[str, str]:
    for threshold, grade, label in GRADES:
        if score >= threshold:
            return grade, label
    return "F", "critical risk"


def compute_score(findings: Iterable[Finding]) -> tuple[int, str, str]:
    """Return ``(score, grade, risk_label)``."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.category].append(f)

    remaining = 1.0
    for items in groups.values():
        items.sort(key=lambda f: -IMPACT[f.severity])
        for i, f in enumerate(items):
            impact = IMPACT[f.severity] * (DECAY ** i)
            remaining *= (1.0 - impact)

    score = max(0, min(100, round(100 * remaining)))
    grade, label = grade_for(score)
    return score, grade, label
