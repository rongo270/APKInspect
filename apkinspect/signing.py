"""APK signing analysis.

Inspects the v1 (JAR) signature certificate and detects the presence of the
APK Signature Scheme v2/v3 block.  A tiny stdlib DER reader extracts the signer
certificate's subject CN, signature algorithm and RSA key size from the PKCS#7
block in ``META-INF``, so we can flag:

* signing with the well-known Android **debug** certificate,
* **weak** certificate signature algorithms (MD5/SHA-1),
* **short** signing keys (< 2048-bit RSA),
* **v1-only** signing (no v2/v3 block — malleable, e.g. Janus/CVE-2017-13156).

AABs are (re-)signed by Google Play at distribution time, so signing analysis is
only meaningful for APKs.  A completely unsigned archive (a pre-signing build
artifact) yields no findings — there is nothing deployed to assess.
"""
from __future__ import annotations

from typing import List, Optional

from .model import Finding

# ---- APK Signing Block ----------------------------------------------------
_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_SCHEME_IDS = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v3.1",
}

# ---- certificate signatureAlgorithm OIDs -> (display name, is_weak) --------
_SIG_ALGOS = {
    "1.2.840.113549.1.1.4": ("MD5withRSA", True),
    "1.2.840.113549.1.1.5": ("SHA1withRSA", True),
    "1.2.840.113549.1.1.11": ("SHA256withRSA", False),
    "1.2.840.113549.1.1.12": ("SHA384withRSA", False),
    "1.2.840.113549.1.1.13": ("SHA512withRSA", False),
    "1.2.840.10040.4.3": ("SHA1withDSA", True),
    "1.2.840.10045.4.1": ("SHA1withECDSA", True),
    "1.2.840.10045.4.3.2": ("SHA256withECDSA", False),
    "1.2.840.10045.4.3.3": ("SHA384withECDSA", False),
    "1.2.840.10045.4.3.4": ("SHA512withECDSA", False),
    "1.3.14.3.2.29": ("SHA1withRSA", True),
}
_CN_OID = "2.5.4.3"
_DEBUG_SUBJECT = b"Android Debug"


# ===========================================================================
# Minimal DER reader (enough of X.509 / PKCS#7 to read the fields we need)
# ===========================================================================
def _read_tlv(data: bytes, p: int):
    """Return ``(tag, value_bytes, full_bytes, end)`` for the TLV at ``p``."""
    start = p
    tag = data[p]
    p += 1
    length = data[p]
    p += 1
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or p + nbytes > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[p:p + nbytes], "big")
        p += nbytes
    end = p + length
    if end > len(data):
        raise ValueError("DER value overruns buffer")
    return tag, data[p:end], data[start:end], end


def _items(value: bytes):
    out = []
    p = 0
    while p < len(value):
        tag, v, full, p = _read_tlv(value, p)
        out.append((tag, v, full))
    return out


def _oid(value: bytes) -> str:
    if not value:
        return ""
    parts = [str(value[0] // 40), str(value[0] % 40)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def _first_oid(seq_value: bytes) -> str:
    for tag, v, _ in _items(seq_value):
        if tag == 0x06:
            return _oid(v)
    return ""


class Certificate:
    """The handful of certificate facts the scanner reasons about."""

    def __init__(self, sig_algo_oid: str, subject_cn: str, key_bits: Optional[int]):
        self.sig_algo_oid = sig_algo_oid
        self.subject_cn = subject_cn
        self.key_bits = key_bits

    @property
    def sig_algo(self) -> str:
        return _SIG_ALGOS.get(self.sig_algo_oid, (self.sig_algo_oid, False))[0]

    @property
    def weak_sig_algo(self) -> bool:
        return _SIG_ALGOS.get(self.sig_algo_oid, ("", False))[1]

    @property
    def is_debug(self) -> bool:
        return (self.subject_cn or "").strip().lower() == "android debug"


def parse_certificate(der: bytes) -> Certificate:
    """Parse an X.509 certificate DER into a :class:`Certificate`."""
    _, cert_val, _, _ = _read_tlv(der, 0)            # Certificate ::= SEQUENCE
    items = _items(cert_val)                          # [tbs, signatureAlgorithm, sig]
    tbs_val = items[0][1]
    sig_oid = _first_oid(items[1][1])
    tbs = _items(tbs_val)
    # Optional [0] EXPLICIT version shifts every subsequent field by one.
    idx = 1 if tbs and tbs[0][0] == 0xA0 else 0
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    subject_val = tbs[idx + 4][1]
    spki_val = tbs[idx + 5][1]
    return Certificate(sig_oid, _subject_cn(subject_val), _rsa_key_bits(spki_val))


def _subject_cn(name_val: bytes) -> str:
    # Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
    for set_tag, set_val, _ in _items(name_val):
        if set_tag != 0x31:
            continue
        for _, atv_val, _ in _items(set_val):
            atv = _items(atv_val)
            if len(atv) >= 2 and atv[0][0] == 0x06 and _oid(atv[0][1]) == _CN_OID:
                return atv[1][1].decode("utf-8", "replace")
    return ""


def _rsa_key_bits(spki_val: bytes) -> Optional[int]:
    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    items = _items(spki_val)
    if len(items) < 2:
        return None
    bitstring = items[1][1]
    if len(bitstring) < 2:
        return None
    try:
        tag, val, _, _ = _read_tlv(bitstring[1:], 0)  # skip the unused-bits byte
        if tag != 0x30:
            return None                                # not RSA (e.g. an EC point)
        modulus = _items(val)[0][1]
        return int.from_bytes(modulus, "big").bit_length()
    except Exception:
        return None


def certs_from_pkcs7(der: bytes) -> List[bytes]:
    """Extract X.509 certificate DERs from a PKCS#7 ``SignedData`` block."""
    _, ci_val, _, _ = _read_tlv(der, 0)              # ContentInfo ::= SEQUENCE
    content = next((v for tag, v, _ in _items(ci_val) if tag == 0xA0), None)
    if content is None:
        return []
    _, sd_val, _, _ = _read_tlv(content, 0)          # SignedData ::= SEQUENCE
    certs_field = next((v for tag, v, _ in _items(sd_val) if tag == 0xA0), None)
    if certs_field is None:
        return []
    out = []
    p = 0
    while p < len(certs_field):
        tag, _, full, p = _read_tlv(certs_field, p)
        if tag == 0x30:
            out.append(full)
    return out


# ===========================================================================
# APK Signing Block (v2/v3) location
# ===========================================================================
def _signing_block_schemes(path: str, file_size: int) -> Optional[List[str]]:
    """Return the scheme labels present in the APK Signing Block, or ``None``
    if there is no such block (i.e. no v2/v3 signature)."""
    try:
        with open(path, "rb") as f:
            n = min(file_size, 0x10000 + 22)         # EOCD + max comment
            f.seek(file_size - n)
            tail = f.read(n)
            i = tail.rfind(b"PK\x05\x06")            # End Of Central Directory
            if i < 0 or i + 20 > len(tail):
                return None
            cd_offset = int.from_bytes(tail[i + 16:i + 20], "little")
            if cd_offset == 0xFFFFFFFF or cd_offset < 24 or cd_offset > file_size:
                return None
            f.seek(cd_offset - 24)
            footer = f.read(24)
            if footer[8:24] != _SIG_BLOCK_MAGIC:
                return None
            block_size = int.from_bytes(footer[0:8], "little")
            start = cd_offset - block_size - 8
            if start < 0:
                return None
            f.seek(start)
            block = f.read(cd_offset - start)
    except OSError:
        return None
    return _scheme_ids(block)


def _scheme_ids(block: bytes) -> List[str]:
    ids: List[str] = []
    p = 8                                            # skip the leading uint64 size
    end = len(block) - 24                            # stop before trailing size + magic
    try:
        while p + 12 <= end:
            length = int.from_bytes(block[p:p + 8], "little")
            block_id = int.from_bytes(block[p + 8:p + 12], "little")
            ids.append(_SCHEME_IDS.get(block_id, f"0x{block_id:08x}"))
            if length <= 0:
                break
            p += 8 + length
    except Exception:
        pass
    return ids or ["present"]


# ===========================================================================
# Analysis
# ===========================================================================
def _v1_cert_entries(zf) -> List[str]:
    out = []
    for name in zf.namelist():
        up = name.upper()
        if up.startswith("META-INF/") and up.rsplit(".", 1)[-1] in ("RSA", "DSA", "EC"):
            out.append(name)
    return out


def _debug_subject_present(path: str, file_size: int, zf, v1_files: List[str]) -> bool:
    for name in v1_files:
        try:
            if _DEBUG_SUBJECT in zf.read(name):
                return True
        except Exception:
            pass
    try:
        with open(path, "rb") as f:
            n = min(file_size, 2 * 1024 * 1024)
            f.seek(file_size - n)
            if _DEBUG_SUBJECT in f.read(n):
                return True
    except OSError:
        pass
    return False


def analyze(path: str, zf, file_type: str, file_size: int) -> List[Finding]:
    if file_type != "apk":
        return []

    v1_files = _v1_cert_entries(zf)
    schemes = _signing_block_schemes(path, file_size)
    has_v1 = bool(v1_files)
    has_v2plus = schemes is not None

    if not has_v1 and not has_v2plus:
        return []   # unsigned build artifact — nothing deployed to assess

    findings: List[Finding] = []

    cert: Optional[Certificate] = None
    if has_v1:
        for name in v1_files:
            try:
                certs = certs_from_pkcs7(zf.read(name))
            except Exception:
                continue
            if certs:
                try:
                    cert = parse_certificate(certs[0])
                except Exception:
                    cert = None
                break

    is_debug = cert.is_debug if cert is not None else False
    if not is_debug and cert is None:
        # Couldn't parse the cert (or only v2/v3 is present): fall back to a
        # byte search for the well-known debug subject DN.
        is_debug = _debug_subject_present(path, file_size, zf, v1_files)

    if is_debug:
        findings.append(Finding(
            "SIGNING_DEBUG_CERT", "Signed with the Android debug certificate", "HIGH",
            "signing", location="signature",
            detail="The app is signed with the public Android debug key (CN=Android Debug). "
                   "Anyone can re-sign a modified build with the same well-known key, so update "
                   "integrity and signature-permission protections are void.",
            recommendation="Sign release builds with a private release keystore, never the debug key.",
        ))

    if cert is not None:
        if cert.weak_sig_algo:
            findings.append(Finding(
                "SIGNING_WEAK_ALGORITHM", f"Weak certificate signature algorithm ({cert.sig_algo})",
                "MEDIUM", "signing", location="signature",
                detail=f"The signing certificate uses {cert.sig_algo}; MD5/SHA-1 signatures are "
                       "collision-prone and deprecated.",
                recommendation="Re-issue the signing certificate with SHA-256 or stronger.",
                evidence=cert.sig_algo,
            ))
        if cert.key_bits is not None and cert.key_bits < 2048:
            findings.append(Finding(
                "SIGNING_SHORT_KEY", f"Short signing key ({cert.key_bits}-bit RSA)", "MEDIUM",
                "signing", location="signature",
                detail=f"The signing key is only {cert.key_bits} bits; RSA keys under 2048 bits are "
                       "considered weak.",
                recommendation="Use an RSA key of at least 2048 bits (or an EC P-256 key).",
                evidence=f"{cert.key_bits}-bit",
            ))

    if has_v1 and not has_v2plus:
        findings.append(Finding(
            "SIGNING_V1_ONLY", "Only the legacy v1 (JAR) signature scheme is present", "MEDIUM",
            "signing", location="signature",
            detail="No APK Signature Scheme v2/v3 block was found. v1-only signing is malleable "
                   "(e.g. the Janus vulnerability, CVE-2017-13156) and offers weaker integrity than "
                   "whole-file v2+ signing.",
            recommendation="Enable APK Signature Scheme v2+ (the default in modern Android build tools).",
        ))

    return findings
