"""Top-level scanning: open an APK/AAB, parse its manifest, sweep its entries
for secrets, and score the result."""
from __future__ import annotations

import os
import zipfile
from typing import Optional

from . import aab, axml, secrets
from .manifest import analyze
from .model import Finding, ScanResult
from .scoring import compute_score

# Entries with these extensions are skipped during the secret sweep (binary
# media/fonts produce only noise).
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".mp3", ".mp4",
    ".wav", ".ogg", ".m4a", ".aac", ".flac", ".ttf", ".otf", ".woff", ".woff2",
    ".jar", ".zip",
}

# Per-entry size cap for the secret sweep (avoid pathological/zip-bomb entries).
_MAX_ENTRY_BYTES = 40 * 1024 * 1024
_MANIFEST_APK = "AndroidManifest.xml"
_MANIFEST_AAB = "base/manifest/AndroidManifest.xml"


def _detect_type(names: set[str]) -> str:
    if "BundleConfig.pb" in names or _MANIFEST_AAB in names:
        return "aab"
    return "apk"


def _read_manifest(zf: zipfile.ZipFile, file_type: str) -> tuple[Optional[axml.Element], list[str]]:
    errors: list[str] = []
    entry = _MANIFEST_AAB if file_type == "aab" else _MANIFEST_APK
    try:
        raw = zf.read(entry)
    except KeyError:
        # Fall back: locate any manifest in the archive.
        candidates = [n for n in zf.namelist() if n.endswith("AndroidManifest.xml")]
        if not candidates:
            return None, [f"manifest not found ({entry})"]
        entry = candidates[0]
        raw = zf.read(entry)
    try:
        if file_type == "aab":
            return aab.parse(raw), errors
        return axml.parse(raw), errors
    except Exception as exc:  # parsing should never crash the whole scan
        errors.append(f"failed to parse {entry}: {exc}")
        return None, errors


def _manifest_text(root: axml.Element) -> str:
    """Flatten manifest string values so embedded keys (meta-data) get scanned."""
    parts: list[str] = []
    for el in root.iter():
        for a in el.attributes:
            if isinstance(a.value, str) and a.value:
                parts.append(f"{a.name}={a.value}")
    return "\n".join(parts)


def _sweep_secrets(zf: zipfile.ZipFile, errors: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in _SKIP_EXT:
            continue
        if info.file_size > _MAX_ENTRY_BYTES:
            errors.append(f"skipped {name} (too large: {info.file_size} bytes)")
            continue
        try:
            data = zf.read(name)
        except Exception as exc:
            errors.append(f"could not read {name}: {exc}")
            continue
        text = data.decode("latin-1")
        for f in secrets.scan_text(text, name):
            key = (f.id, f.evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
    return findings


def scan_file(path: str, scan_secrets: bool = True) -> ScanResult:
    result = ScanResult(path=path)
    if not os.path.exists(path):
        result.errors.append("file not found")
        result.score, result.grade, result.risk_label = 0, "F", "unscannable"
        return result
    result.file_size = os.path.getsize(path)

    if not zipfile.is_zipfile(path):
        result.errors.append("not a valid zip/APK/AAB archive")
        result.score, result.grade, result.risk_label = 0, "F", "unscannable"
        return result

    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        result.file_type = _detect_type(names)

        root, errs = _read_manifest(zf, result.file_type)
        result.errors.extend(errs)

        if root is not None:
            meta, mfindings = analyze(root, is_aab=(result.file_type == "aab"))
            result.package = str(meta.get("package") or "")
            result.version_name = str(meta.get("version_name") or "")
            result.version_code = str(meta.get("version_code") or "")
            result.min_sdk = meta.get("min_sdk")
            result.target_sdk = meta.get("target_sdk")
            result.meta["permission_count"] = len(meta.get("permissions", []))
            for f in mfindings:
                result.add(f)
            # scan manifest-embedded strings (e.g. Maps/Firebase API keys in meta-data)
            for f in secrets.scan_text(_manifest_text(root), "AndroidManifest.xml"):
                result.add(f)
            if result.file_type == "aab":
                result.meta["manifest_note"] = "AAB manifest decoded from protobuf (best-effort)."

        if scan_secrets:
            seen = {(f.id, f.evidence) for f in result.findings}
            for f in _sweep_secrets(zf, result.errors):
                if (f.id, f.evidence) in seen:
                    continue
                seen.add((f.id, f.evidence))
                result.add(f)

        result.meta["entry_count"] = len(names)
        result.meta["dex_count"] = sum(1 for n in names if n.endswith(".dex"))
        result.meta["has_native_libs"] = any(n.endswith(".so") for n in names)

    result.score, result.grade, result.risk_label = compute_score(result.findings)
    return result
