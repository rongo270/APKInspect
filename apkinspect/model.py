"""Shared data model: severities and findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Ordered most -> least severe.
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Per-finding score weight (points of risk).  Scoring applies diminishing
# returns when the same check fires many times (see scoring.py).
SEVERITY_WEIGHT = {
    "CRITICAL": 28,
    "HIGH": 16,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    id: str           # stable identifier for the check, e.g. "MANIFEST_DEBUGGABLE"
    title: str
    severity: str     # one of SEVERITIES
    category: str     # "secret" | "component" | "permission" | "network" | "manifest" | "config"
    location: str = ""   # file / component the finding relates to
    detail: str = ""     # human-readable explanation and evidence
    recommendation: str = ""
    evidence: str = ""    # redacted snippet, when relevant

    def __post_init__(self):
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"invalid severity: {self.severity}")

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "location": self.location,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        return d


@dataclass
class ScanResult:
    path: str = ""
    file_type: str = ""        # "apk" | "aab"
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: Any = None
    target_sdk: Any = None
    file_size: int = 0
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    risk_label: str = "minimal risk"
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.category, f.id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "file_type": self.file_type,
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "file_size": self.file_size,
            "score": self.score,
            "grade": self.grade,
            "risk_label": self.risk_label,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
            "meta": self.meta,
        }
