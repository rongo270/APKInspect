"""Network Security Config (NSC) analysis.

Android apps can relax TLS/cleartext policy in a ``res/xml`` network-security
config referenced from the manifest.  The manifest check only sees *that* a
config is referenced, not what it permits - so we locate the compiled NSC
(binary XML) inside the archive and flag the dangerous settings directly:

* ``cleartextTrafficPermitted="true"`` - allows unencrypted HTTP, and
* ``<trust-anchors><certificates src="user"/>`` - trusts user-installed CAs,
  which lets anyone intercept TLS with a user-added certificate.

``debug-overrides`` blocks are ignored: they only apply to debuggable builds and
are the *recommended* place to relax trust for local debugging.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from . import axml
from .axml import Element
from .manifest import as_bool
from .model import Finding

_AXML_MAGIC = b"\x03\x00\x08\x00"   # RES_XML_TYPE, header size 8
_NSC_ROOT = "network-security-config"


def _find_nsc(zf) -> Tuple[Optional[str], Optional[Element]]:
    """Return ``(entry_name, root)`` for the compiled NSC, or ``(None, None)``."""
    for name in zf.namelist():
        if not name.lower().endswith(".xml") or not name.startswith("res/"):
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        if data[:4] != _AXML_MAGIC:
            continue
        try:
            root = axml.parse(data)
        except Exception:
            continue
        if root.tag == _NSC_ROOT:
            return name, root
    return None, None


def _trusts_user_ca(config: Element) -> bool:
    for anchors in config.children:
        if anchors.tag != "trust-anchors":
            continue
        for cert in anchors.children:
            if cert.tag == "certificates" and str(cert.get("src", "")).lower() == "user":
                return True
    return False


def analyze(zf) -> List[Finding]:
    name, root = _find_nsc(zf)
    if root is None:
        return []

    configs = [c for c in root.children if c.tag in ("base-config", "domain-config")]
    cleartext = any(as_bool(c.get("cleartextTrafficPermitted")) is True for c in configs)
    user_ca = any(_trusts_user_ca(c) for c in configs)

    findings: List[Finding] = []
    if cleartext:
        findings.append(Finding(
            "NETWORK_NSC_CLEARTEXT", "Network security config permits cleartext traffic", "MEDIUM",
            "network", location=name,
            detail="A base-config/domain-config sets cleartextTrafficPermitted=\"true\", allowing "
                   "unencrypted HTTP even on Android 9+ where it is disabled by default.",
            recommendation="Set cleartextTrafficPermitted=\"false\" and use HTTPS; scope any unavoidable "
                           "exception to a single domain.",
        ))
    if user_ca:
        findings.append(Finding(
            "NETWORK_NSC_USER_CA", "Network security config trusts user-installed CAs", "MEDIUM",
            "network", location=name,
            detail="trust-anchors include <certificates src=\"user\"/>, so the app trusts CA "
                   "certificates the device user installs - enabling TLS interception (MITM) with a "
                   "user-added certificate.",
            recommendation="Trust only the system store (src=\"system\") in production; relax trust "
                           "inside a <debug-overrides> block for local debugging instead.",
        ))
    return findings
