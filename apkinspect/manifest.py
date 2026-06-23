"""Security analysis of a decoded ``AndroidManifest.xml`` element tree."""
from __future__ import annotations

from typing import Any, Optional

from .axml import Element
from .model import Finding
from .permissions import lookup as lookup_permission

BROWSABLE = "android.intent.category.BROWSABLE"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


# --- value coercion ---------------------------------------------------------
def as_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1"):
            return True
        if s in ("false", "0", ""):
            return False
    return None


def as_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            return None
    return None


def protection_name(v: Any) -> Optional[str]:
    """Normalise a protectionLevel value to normal/dangerous/signature."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.lower()
        if "signature" in s:
            return "signature"
        if "dangerous" in s:
            return "dangerous"
        if "normal" in s:
            return "normal"
        return None
    if isinstance(v, int):
        return {0: "normal", 1: "dangerous", 2: "signature", 3: "signature"}.get(v & 0xF)
    return None


# --- metadata ---------------------------------------------------------------
def extract_metadata(root: Element) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "package": root.get("package", "", android=False) or "",
        "version_code": root.get("versionCode", "") ,
        "version_name": root.get("versionName", ""),
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
    }
    uses_sdk = next(iter(root.findall("uses-sdk")), None)
    if uses_sdk is not None:
        meta["min_sdk"] = as_int(uses_sdk.get("minSdkVersion"))
        meta["target_sdk"] = as_int(uses_sdk.get("targetSdkVersion"))
    for up in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
        name = up.get("name")
        if isinstance(name, str) and name:
            meta["permissions"].append(name)
    return meta


def _declared_permission_levels(root: Element) -> dict[str, str]:
    levels: dict[str, str] = {}
    for p in root.findall("permission"):
        name = p.get("name")
        lvl = protection_name(p.get("protectionLevel"))
        if isinstance(name, str) and name and lvl:
            levels[name] = lvl
    return levels


def _is_exported(elem: Element, tag: str, target_sdk: Optional[int]) -> tuple[bool, bool]:
    """Return (exported, explicit) for a component element."""
    a = elem.attr("exported")
    if a is not None:
        b = as_bool(a.value)
        if b is not None:
            return b, True
    has_filter = any(c.tag == "intent-filter" for c in elem.children)
    if tag == "provider":
        # Providers default to exported only on very old target SDKs (<17).
        if target_sdk is not None and target_sdk < 17:
            return True, False
        return False, False
    # activity/service/receiver default to exported iff they declare a filter.
    return has_filter, False


def _is_launcher(elem: Element) -> bool:
    """A standard home-screen entry point (MAIN/LAUNCHER) is meant to be public."""
    for flt in elem.children:
        if flt.tag != "intent-filter":
            continue
        actions = {c.get("name") for c in flt.children if c.tag == "action"}
        cats = {c.get("name") for c in flt.children if c.tag == "category"}
        if "android.intent.action.MAIN" in actions and (
            "android.intent.category.LAUNCHER" in cats
            or "android.intent.category.LEANBACK_LAUNCHER" in cats
        ):
            return True
    return False


def _http_browsable_schemes(elem: Element) -> set[str]:
    """Cleartext-capable web schemes reachable via a BROWSABLE deep link."""
    schemes: set[str] = set()
    for flt in elem.children:
        if flt.tag != "intent-filter":
            continue
        cats = {c.get("name") for c in flt.children if c.tag == "category"}
        if BROWSABLE not in cats:
            continue
        for data in (c for c in flt.children if c.tag == "data"):
            sch = data.get("scheme")
            if isinstance(sch, str) and sch.lower() == "http":
                schemes.add("http")
    return schemes


def _component_permissions(elem: Element, tag: str) -> list[str]:
    perms = []
    for attr in ("permission", "readPermission", "writePermission"):
        v = elem.get(attr)
        if isinstance(v, str) and v:
            perms.append(v)
    return perms


def analyze(root: Element, is_aab: bool = False) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    meta = extract_metadata(root)
    target_sdk = meta["target_sdk"]
    min_sdk = meta["min_sdk"]
    declared_levels = _declared_permission_levels(root)

    app = next(iter(root.findall("application")), None)

    # ---- application-level flags ----
    if app is not None:
        if as_bool(app.get("debuggable")) is True:
            findings.append(Finding(
                "MANIFEST_DEBUGGABLE", "Application is debuggable", "HIGH", "config",
                location="application",
                detail="android:debuggable=\"true\" lets anyone attach a debugger and run code in the app's context on any device.",
                recommendation="Set android:debuggable=\"false\" (or remove it) for release builds.",
            ))
        backup = as_bool(app.get("allowBackup"))
        if backup is True:
            findings.append(Finding(
                "MANIFEST_ALLOWBACKUP", "Backups are allowed", "MEDIUM", "config",
                location="application",
                detail="android:allowBackup=\"true\" allows app data to be extracted via 'adb backup' / cloud backup.",
                recommendation="Set android:allowBackup=\"false\" or define fullBackupContent/dataExtractionRules to exclude sensitive data.",
            ))
        elif backup is None:
            findings.append(Finding(
                "MANIFEST_ALLOWBACKUP_DEFAULT", "Backups not explicitly disabled", "LOW", "config",
                location="application",
                detail="android:allowBackup is unset, which defaults to true on most versions.",
                recommendation="Explicitly set android:allowBackup=\"false\" unless backups are required.",
            ))
        if as_bool(app.get("usesCleartextTraffic")) is True:
            findings.append(Finding(
                "MANIFEST_CLEARTEXT", "Cleartext (HTTP) traffic permitted", "MEDIUM", "network",
                location="application",
                detail="android:usesCleartextTraffic=\"true\" permits unencrypted HTTP, exposing traffic to interception/tampering.",
                recommendation="Remove the flag and use HTTPS; restrict any required cleartext via a network security config.",
            ))
        elif (app.get("networkSecurityConfig") is None and target_sdk is not None and target_sdk < 28):
            findings.append(Finding(
                "MANIFEST_CLEARTEXT_DEFAULT", "Cleartext traffic allowed by default", "LOW", "network",
                location="application",
                detail=f"targetSdkVersion {target_sdk} (<28) allows cleartext HTTP by default and no networkSecurityConfig is set.",
                recommendation="Raise targetSdkVersion and/or add a network security config that disables cleartext.",
            ))
        if as_bool(app.get("testOnly")) is True:
            findings.append(Finding(
                "MANIFEST_TESTONLY", "Application marked test-only", "LOW", "config",
                location="application",
                detail="android:testOnly=\"true\" indicates a non-release build not intended for distribution.",
                recommendation="Remove android:testOnly for production builds.",
            ))

    # ---- exported components ----
    components = app.children if app is not None else []
    for comp in components:
        tag = comp.tag
        if tag not in COMPONENT_TAGS:
            continue
        name = comp.get("name") or "(unnamed)"
        exported, explicit = _is_exported(comp, tag, target_sdk)
        http_schemes = _http_browsable_schemes(comp) if tag in ("activity", "activity-alias") else set()

        # Cleartext deep link is reachable regardless of the exported attribute.
        if http_schemes:
            findings.append(Finding(
                "COMPONENT_HTTP_DEEPLINK", "Activity handles cleartext http:// web links", "HIGH",
                "component", location=f"{tag} {name}",
                detail="A BROWSABLE intent-filter accepts the 'http' scheme, so any web page/app can launch this activity over unencrypted HTTP (deep-link hijacking / MITM).",
                recommendation="Use https only, verify App Links with android:autoVerify, and validate all incoming intent data.",
            ))

        if not exported:
            continue

        perms = _component_permissions(comp, tag)
        levels = [declared_levels.get(p) for p in perms]
        signature_protected = any(lv == "signature" for lv in levels)
        if perms and signature_protected:
            continue  # adequately protected

        base_sev = "HIGH" if tag == "provider" else "MEDIUM"
        if http_schemes and base_sev == "MEDIUM":
            base_sev = "HIGH"

        if not perms and tag in ("activity", "activity-alias") and _is_launcher(comp):
            # The launcher entry point is intended to be publicly reachable.
            continue

        if not perms:
            findings.append(Finding(
                "COMPONENT_EXPORTED", f"Exported {tag} without permission", base_sev,
                "component", location=f"{tag} {name}",
                detail=(
                    f"This {tag} is exported"
                    + ("" if explicit else " (implicitly, via an intent-filter / default)")
                    + " and is reachable by any other app without a permission check."
                    + (" Exported content providers can leak or accept data directly." if tag == "provider" else "")
                ),
                recommendation=(
                    "Set android:exported=\"false\" if it need not be public, otherwise guard it with a "
                    "signature-level android:permission and validate all incoming intents."
                ),
            ))
        else:
            weak = [p for p, lv in zip(perms, levels) if lv in ("normal", "dangerous")]
            if weak:
                findings.append(Finding(
                    "COMPONENT_EXPORTED_WEAKPERM", f"Exported {tag} guarded by weak permission",
                    "LOW", "component", location=f"{tag} {name}",
                    detail=f"Protected by '{', '.join(weak)}' which is normal/dangerous level — any app can request it.",
                    recommendation="Use a signature-level permission to restrict access to your own apps.",
                ))
            else:
                findings.append(Finding(
                    "COMPONENT_EXPORTED_PERM", f"Exported {tag} (permission-guarded)", "LOW",
                    "component", location=f"{tag} {name}",
                    detail=f"Exported but protected by permission(s): {', '.join(perms)}. Verify their protectionLevel.",
                    recommendation="Confirm the guarding permission is signature-level; otherwise restrict it.",
                ))

        if tag == "provider" and as_bool(comp.get("grantUriPermissions")) is True and not perms:
            findings.append(Finding(
                "COMPONENT_PROVIDER_GRANTURI", "Exported provider grants URI permissions", "MEDIUM",
                "component", location=f"{tag} {name}",
                detail="grantUriPermissions=\"true\" on an unprotected exported provider can let other apps reach arbitrary files/rows.",
                recommendation="Scope grant-uri-permission <path> entries narrowly and require a permission.",
            ))

    # ---- dangerous permissions ----
    for perm in meta["permissions"]:
        info = lookup_permission(perm)
        if info is None:
            continue
        sev, desc = info
        findings.append(Finding(
            "PERMISSION_DANGEROUS", f"Requests permission: {perm.rsplit('.', 1)[-1]}", sev,
            "permission", location="manifest",
            detail=f"{desc}.",
            recommendation="Confirm this permission is actually required; request the minimum scope at runtime.",
        ))

    # ---- old min SDK ----
    if isinstance(min_sdk, int) and min_sdk < 24:
        findings.append(Finding(
            "MANIFEST_OLD_MINSDK", f"Low minSdkVersion ({min_sdk})", "LOW", "config",
            location="uses-sdk",
            detail=f"minSdkVersion {min_sdk} supports old Android releases that lack modern platform mitigations (e.g. scoped storage, stricter TLS).",
            recommendation="Raise minSdkVersion where feasible.",
        ))

    return meta, findings
