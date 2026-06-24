"""Detect hard-coded secrets, API keys, tokens and exposed backend URLs in the
decoded bytes of an APK/AAB (DEX, resources, assets, native libs, manifest).

Scanning is done on a ``latin-1`` view of the raw bytes so that byte offsets map
1:1 and every ASCII match is found regardless of the surrounding binary data.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .model import Finding

# Obvious placeholders / non-secrets we never want to report.
_PLACEHOLDER = re.compile(
    r"^(your[_-]?|my[_-]?|the[_-]?|some[_-]?|example|sample|placeholder|dummy|test|fake|changeme|"
    r"xxx+|0000+|1234|abcd|none|null|true|false|undefined|insert[_-]?|replace[_-]?)",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """Mask the middle of a secret so a report can be shared safely."""
    v = value.strip()
    first_line = v.splitlines()[0] if v else v
    if "PRIVATE KEY" in first_line:
        return first_line.strip() + " ...(redacted)"
    if len(v) <= keep * 2:
        return "*" * len(v)
    return f"{v[:keep]}...{v[-keep:]} (len {len(v)})"


@dataclass
class SecretPattern:
    id: str
    title: str
    severity: str
    regex: re.Pattern
    group: int = 0
    category: str = "secret"
    recommendation: str = ""
    validator: Optional[Callable[[str], bool]] = None
    redact_value: bool = True   # URLs/identifiers are shown in full


def _looks_secret(value: str, min_len: int = 12, min_entropy: float = 2.6) -> bool:
    v = value.strip().strip("\"'")
    if len(v) < min_len:
        return False
    if _PLACEHOLDER.match(v):
        return False
    if len(set(v)) <= 2:  # e.g. "aaaaaaaaaaaa"
        return False
    return _shannon_entropy(v) >= min_entropy


# ---------------------------------------------------------------------------
# Pattern catalogue.  Severity reflects the blast-radius of the credential if
# it is indeed live and unrestricted.
# ---------------------------------------------------------------------------
PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "PRIVATE_KEY", "Private key material", "CRITICAL",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        recommendation="Never ship private keys in an app. Rotate the key immediately and move signing/decryption server-side.",
    ),
    SecretPattern(
        "GCP_SERVICE_ACCOUNT", "Google service-account JSON", "CRITICAL",
        re.compile(r'"type"\s*:\s*"service_account"'),
        recommendation="Service-account credentials grant backend access. Remove from the bundle and rotate the key.",
    ),
    SecretPattern(
        "AWS_ACCESS_KEY_ID", "AWS access key id", "CRITICAL",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b"), group=1,
        recommendation="Rotate the key in IAM. Use temporary STS credentials or a backend proxy instead of embedding long-lived keys.",
    ),
    SecretPattern(
        "AWS_SECRET_KEY", "AWS secret access key", "CRITICAL",
        re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,8}?[=:'\"\s]([A-Za-z0-9/+]{40})"), group=1,
        recommendation="Rotate the secret key immediately; it should never reach a client.",
    ),
    SecretPattern(
        "STRIPE_LIVE", "Stripe live secret key", "CRITICAL",
        re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b"), group=1,
        recommendation="Roll the key in the Stripe dashboard. Only publishable (pk_) keys belong in a client.",
    ),
    SecretPattern(
        "SENDGRID", "SendGrid API key", "CRITICAL",
        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), group=1,
        recommendation="Revoke and recreate the key; send mail from a backend.",
    ),
    SecretPattern(
        "GITHUB_TOKEN", "GitHub token", "CRITICAL",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b"), group=1,
        recommendation="Revoke the token on GitHub immediately.",
    ),
    SecretPattern(
        "SLACK_TOKEN", "Slack token", "HIGH",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), group=1,
        recommendation="Revoke the token in the Slack admin console.",
    ),
    SecretPattern(
        "SLACK_WEBHOOK", "Slack incoming webhook", "HIGH",
        re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"), group=1,
        recommendation="Anyone with this URL can post to the channel. Rotate it.",
    ),
    SecretPattern(
        "TWILIO_KEY", "Twilio API/Account SID key", "HIGH",
        re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), group=1,
        recommendation="Rotate the Twilio key; calls/SMS are billable.",
    ),
    SecretPattern(
        "MAILGUN", "Mailgun API key", "HIGH",
        re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"), group=1,
        recommendation="Rotate the Mailgun key.",
    ),
    SecretPattern(
        "ANTHROPIC_KEY", "Anthropic API key", "HIGH",
        re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), group=1,
        recommendation="Revoke the key in the Anthropic console and call the API from a backend, not the client.",
    ),
    SecretPattern(
        "OPENAI_KEY", "OpenAI API key", "HIGH",
        re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{32,})\b"), group=1,
        recommendation="Revoke the key in the OpenAI dashboard; never ship LLM provider keys in a client.",
    ),
    SecretPattern(
        "AZURE_STORAGE_KEY", "Azure Storage account key", "HIGH",
        re.compile(r"AccountKey=([A-Za-z0-9+/]{86}==)"), group=1,
        recommendation="Rotate the storage account key in Azure and prefer SAS tokens or managed identity.",
    ),
    SecretPattern(
        "SQUARE_TOKEN", "Square access token", "HIGH",
        re.compile(r"\b((?:sq0atp|sq0csp|EAAA)[A-Za-z0-9_\-]{22,})\b"), group=1,
        recommendation="Revoke the token in the Square developer dashboard.",
    ),
    SecretPattern(
        "NPM_TOKEN", "npm access token", "HIGH",
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), group=1,
        recommendation="Revoke the token ('npm token revoke') and keep it out of client artifacts.",
    ),
    SecretPattern(
        "DB_CONNECTION_STRING", "Database connection string with credentials", "HIGH",
        re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/\"']+)"),
        group=1,
        recommendation="Move the database behind a backend API; never embed DB credentials in a client.",
    ),
    SecretPattern(
        "GOOGLE_OAUTH", "Google OAuth client id", "LOW",
        re.compile(r"\b([0-9]+-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com)\b"), group=1,
        redact_value=False,
        recommendation="Client ids are public but confirm the matching client secret is not also bundled.",
    ),
    SecretPattern(
        "GOOGLE_API_KEY", "Google API key", "HIGH",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), group=1,
        recommendation="Restrict the key (application + API restrictions) in Google Cloud Console; an unrestricted key can be abused for billable calls.",
    ),
    SecretPattern(
        "FCM_SERVER_KEY", "Firebase Cloud Messaging legacy server key", "HIGH",
        re.compile(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{120,})\b"), group=1,
        recommendation="A leaked FCM server key lets anyone push notifications to all users. Rotate it and migrate to the HTTP v1 API.",
    ),
    SecretPattern(
        "FIREBASE_DB_URL", "Firebase Realtime Database URL", "HIGH",
        re.compile(r"(https://[a-z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app))"), group=1,
        category="network", redact_value=False,
        recommendation="Verify Firebase security rules are not world-readable/writable. Open rules expose the entire database; test '<url>/.json'.",
    ),
    SecretPattern(
        "FIREBASE_STORAGE", "Firebase Storage / GCS bucket", "MEDIUM",
        re.compile(r"\b([a-z0-9.\-]+\.(?:appspot\.com|firebasestorage\.app))\b"), group=1,
        category="network", redact_value=False,
        recommendation="Confirm Storage rules require authentication; open buckets leak user uploads.",
    ),
    SecretPattern(
        "JWT", "JSON Web Token", "LOW",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"), group=1,
        recommendation="If this is a long-lived/credentialed token, move it server-side and rotate.",
    ),
]

# Generic "<keyword> = <value>" credential heuristic (entropy-gated).
_GENERIC = re.compile(
    r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|password|passwd|pwd|"
    r"auth[_-]?token|access[_-]?token|private[_-]?key|encryption[_-]?key|"
    r"consumer[_-]?secret)\b\s*[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9_\-+/.=]{12,})"
)


def scan_text(text: str, source: str) -> list[Finding]:
    """Scan one decoded entry, returning de-duplicated findings."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            value = m.group(pat.group) if pat.group else m.group(0)
            if pat.validator and not pat.validator(value):
                continue
            key = (pat.id, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=f"SECRET_{pat.id}",
                    title=pat.title,
                    severity=pat.severity,
                    category=pat.category,
                    location=source,
                    detail=f"{pat.title} found in {source}.",
                    recommendation=pat.recommendation,
                    evidence=redact(value) if pat.redact_value else value,
                )
            )

    for m in _GENERIC.finditer(text):
        keyword = m.group(1)
        value = m.group(2)
        if not _looks_secret(value):
            continue
        key = ("GENERIC", value)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                id="SECRET_HARDCODED_CREDENTIAL",
                title=f"Hard-coded credential ('{keyword.lower()}')",
                severity="MEDIUM",
                category="secret",
                location=source,
                detail=f"A high-entropy value is assigned to '{keyword}' in {source}.",
                recommendation="Move secrets out of the binary (server-side or secure remote config); embedded strings are trivially extracted.",
                evidence=redact(value),
            )
        )

    return findings
