"""Test fixtures: a from-scratch Android Binary XML *encoder* and a minimal
protobuf encoder, used to synthesise APK/AAB archives with known-bad content so
every check can be exercised offline (no Android SDK required).

The AXML encoder mirrors the AOSP on-disk layout, so round-tripping it through
``apkinspect.axml`` validates the parser, and feeding the resulting archive to
the scanner validates the whole pipeline.
"""
from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any, Union

from apkinspect.axml import ANDROID_NS

# ===========================================================================
# A tiny manifest tree model
# ===========================================================================
@dataclass
class Attr:
    name: str
    value: Any           # str -> string, bool -> boolean, int -> int_dec
    ns: Union[str, None] = ANDROID_NS


@dataclass
class El:
    tag: str
    attrs: list[Attr] = field(default_factory=list)
    children: list["El"] = field(default_factory=list)


def A(name: str, value: Any, ns: Union[str, None] = ANDROID_NS) -> Attr:
    return Attr(name, value, ns)


def E(tag: str, attrs=(), children=()) -> El:
    return El(tag, list(attrs), list(children))


# ===========================================================================
# AXML encoder (APK manifest)
# ===========================================================================
_UTF8_FLAG = 0x100


def _enc_len8(n: int) -> bytes:
    if n > 0x7F:
        return bytes([0x80 | ((n >> 8) & 0x7F), n & 0xFF])
    return bytes([n])


def _utf8_string(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _enc_len8(len(s)) + _enc_len8(len(raw)) + raw + b"\x00"


class _Pool:
    def __init__(self):
        self.items: list[str] = []
        self.index: dict[str, int] = {}

    def intern(self, s: Union[str, None]) -> int:
        if s is None:
            return -1
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]

    def encode(self) -> bytes:
        data = b""
        offsets: list[int] = []
        for s in self.items:
            offsets.append(len(data))
            data += _utf8_string(s)
        while len(data) % 4:
            data += b"\x00"
        strings_start = 28 + 4 * len(self.items)
        body = struct.pack("<IIIII", len(self.items), 0, _UTF8_FLAG, strings_start, 0)
        body += b"".join(struct.pack("<I", o) for o in offsets)
        body += data
        size = 8 + len(body)
        return struct.pack("<HHI", 0x0001, 28, size) + body


def _chunk(ctype: int, header_size: int, body: bytes) -> bytes:
    size = 8 + len(body)
    return struct.pack("<HHI", ctype, header_size, size) + body


def _ns_chunk(ctype: int, prefix: int, uri: int) -> bytes:
    body = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<ii", prefix, uri)
    return _chunk(ctype, 16, body)


def _start_element(pool: _Pool, elem: El) -> bytes:
    name_idx = pool.intern(elem.tag)
    ext = struct.pack("<ii", -1, name_idx)
    ext += struct.pack("<HHHHHH", 20, 20, len(elem.attrs), 0, 0, 0)
    attr_bytes = b""
    for a in elem.attrs:
        a_ns = pool.intern(a.ns)
        a_name = pool.intern(a.name)
        if isinstance(a.value, bool):
            dtype, data, raw = 0x12, (0xFFFFFFFF if a.value else 0), -1
        elif isinstance(a.value, int):
            dtype, data, raw = 0x10, a.value & 0xFFFFFFFF, -1
        else:
            idx = pool.intern(str(a.value))
            dtype, data, raw = 0x03, idx, idx
        attr_bytes += struct.pack("<iii", a_ns, a_name, raw)
        attr_bytes += struct.pack("<HBBI", 8, 0, dtype, data)
    body = struct.pack("<II", 1, 0xFFFFFFFF) + ext + attr_bytes
    return _chunk(0x0102, 16, body)


def _end_element(pool: _Pool, elem: El) -> bytes:
    body = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<ii", -1, pool.intern(elem.tag))
    return _chunk(0x0103, 16, body)


def _intern_all(elem: El, pool: _Pool) -> None:
    pool.intern(elem.tag)
    for a in elem.attrs:
        pool.intern(a.ns)
        pool.intern(a.name)
        if not isinstance(a.value, (bool, int)):
            pool.intern(str(a.value))
    for c in elem.children:
        _intern_all(c, pool)


def encode_axml(root: El) -> bytes:
    pool = _Pool()
    uri_idx = pool.intern(ANDROID_NS)
    prefix_idx = pool.intern("android")
    _intern_all(root, pool)

    chunks = [_ns_chunk(0x0100, prefix_idx, uri_idx)]

    def emit(elem: El):
        chunks.append(_start_element(pool, elem))
        for c in elem.children:
            emit(c)
        chunks.append(_end_element(pool, elem))

    emit(root)
    chunks.append(_ns_chunk(0x0101, prefix_idx, uri_idx))

    body = pool.encode() + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ===========================================================================
# Minimal protobuf encoder (AAB manifest)
# ===========================================================================
def _pb_varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def _pb_tag(field: int, wire: int) -> bytes:
    return _pb_varint((field << 3) | wire)


def _pb_len(field: int, payload: bytes) -> bytes:
    return _pb_tag(field, 2) + _pb_varint(len(payload)) + payload


def _pb_vint(field: int, value: int) -> bytes:
    return _pb_tag(field, 0) + _pb_varint(value)


def _pb_str(field: int, value: str) -> bytes:
    return _pb_len(field, value.encode("utf-8"))


def _pb_attr(name: str, ns: str = "", value: str = None, boolean: bool = None,
             resource_id: int = 0) -> bytes:
    out = b""
    if ns:
        out += _pb_str(1, ns)
    out += _pb_str(2, name)
    if value is not None:
        out += _pb_str(3, value)
    if boolean is not None:
        prim = _pb_vint(8, 1 if boolean else 0)        # Primitive.boolean_value
        item = _pb_len(7, prim)                          # Item.prim
        out += _pb_len(6, item)                          # XmlAttribute.compiled_item
    if resource_id:
        out += _pb_vint(5, resource_id)
    return out


def _pb_element(name: str, attrs: list[bytes], children: list[bytes], ns: str = "") -> bytes:
    out = b""
    if ns:
        out += _pb_str(2, ns)
    out += _pb_str(3, name)
    for a in attrs:
        out += _pb_len(4, a)
    for c in children:
        out += _pb_len(5, c)  # child XmlNode
    return out


def _pb_node(element: bytes) -> bytes:
    return _pb_len(1, element)


# ===========================================================================
# Planted secrets (deterministic, clearly fake)
# ===========================================================================
GOOGLE_API_KEY = "AIza" + "SyD9eXampLeK3yAbcdEfGhIjKlMnOpQrStU"   # AIza + 35
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FIREBASE_DB = "https://apkinspect-demo.firebaseio.com"
SLACK_TOKEN = "xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX"
GENERIC_SECRET = "p4ssw0rd_Hx9KqZ2mLn"
MAPS_API_KEY = "AIza" + "SyMapsK3yAbcdEfGhIjKlMnOpQrStUvWxY1"     # AIza + 35
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIBAQ==\n"
    "-----END RSA PRIVATE KEY-----"
)

assert len(GOOGLE_API_KEY) == 39, len(GOOGLE_API_KEY)
assert len(MAPS_API_KEY) == 39, len(MAPS_API_KEY)


def planted_dex() -> bytes:
    """A fake classes.dex carrying planted secrets as null-separated strings."""
    blob = b"dex\n035\x00" + b"\x00" * 24
    for s in (GOOGLE_API_KEY, AWS_KEY, FIREBASE_DB, SLACK_TOKEN, PRIVATE_KEY):
        blob += s.encode("utf-8") + b"\x00"
    blob += b'\x00api_key="' + GENERIC_SECRET.encode() + b'"\x00'
    return blob


def clean_dex() -> bytes:
    return b"dex\n035\x00" + b"\x00" * 64 + b"com/example/app/MainActivity\x00"


# ===========================================================================
# Manifest trees
# ===========================================================================
def vulnerable_manifest() -> El:
    return E("manifest", [A("package", "com.apkinspect.vulnerable", ns=None)], [
        E("uses-sdk", [A("minSdkVersion", 19), A("targetSdkVersion", 26)]),
        E("uses-permission", [A("name", "android.permission.READ_SMS")]),
        E("uses-permission", [A("name", "android.permission.SYSTEM_ALERT_WINDOW")]),
        E("uses-permission", [A("name", "android.permission.ACCESS_FINE_LOCATION")]),
        E("uses-permission", [A("name", "android.permission.REQUEST_INSTALL_PACKAGES")]),
        E("application", [
            A("debuggable", True),
            A("allowBackup", True),
            A("usesCleartextTraffic", True),
        ], [
            E("meta-data", [
                A("name", "com.google.android.geo.API_KEY"),
                A("value", MAPS_API_KEY),
            ]),
            E("activity", [A("name", ".PublicActivity"), A("exported", True)], [
                E("intent-filter", [], [
                    E("action", [A("name", "android.intent.action.VIEW")]),
                    E("category", [A("name", "android.intent.category.BROWSABLE")]),
                    E("category", [A("name", "android.intent.category.DEFAULT")]),
                    E("data", [A("scheme", "http"), A("host", "example.com")]),
                ]),
            ]),
            E("activity", [A("name", ".ImplicitActivity")], [
                E("intent-filter", [], [
                    E("action", [A("name", "com.apkinspect.CUSTOM")]),
                ]),
            ]),
            E("provider", [
                A("name", ".LeakyProvider"),
                A("authorities", "com.apkinspect.vulnerable.provider"),
                A("exported", True),
                A("grantUriPermissions", True),
            ]),
            E("receiver", [A("name", ".BootReceiver"), A("exported", True)], [
                E("intent-filter", [], [
                    E("action", [A("name", "android.intent.action.BOOT_COMPLETED")]),
                ]),
            ]),
        ]),
    ])


def clean_manifest() -> El:
    return E("manifest", [A("package", "com.apkinspect.clean", ns=None)], [
        E("uses-sdk", [A("minSdkVersion", 26), A("targetSdkVersion", 34)]),
        E("uses-permission", [A("name", "android.permission.INTERNET")]),
        E("application", [
            A("debuggable", False),
            A("allowBackup", False),
            A("networkSecurityConfig", "@0x7f0f0001"),
        ], [
            E("activity", [A("name", ".MainActivity"), A("exported", True)], [
                E("intent-filter", [], [
                    E("action", [A("name", "android.intent.action.MAIN")]),
                    E("category", [A("name", "android.intent.category.LAUNCHER")]),
                ]),
            ]),
            E("activity", [A("name", ".SecondActivity"), A("exported", False)]),
            E("provider", [
                A("name", "androidx.startup.InitializationProvider"),
                A("authorities", "com.apkinspect.clean.androidx-startup"),
                A("exported", False),
            ]),
        ]),
    ])


# ===========================================================================
# Archive assembly
# ===========================================================================
def build_apk_bytes(manifest_tree: El, dex: bytes, extra: dict[str, bytes] = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", encode_axml(manifest_tree))
        zf.writestr("classes.dex", dex)
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 16)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def build_aab_manifest() -> bytes:
    """A protobuf manifest with: debuggable (compiled boolean), READ_SMS perm,
    and an exported activity (string value)."""
    perm = _pb_element("uses-permission", [
        _pb_attr("name", ns=ANDROID_NS, value="android.permission.READ_SMS"),
    ], [])
    activity = _pb_element("activity", [
        _pb_attr("name", ns=ANDROID_NS, value="com.apkinspect.aab.Exported"),
        _pb_attr("exported", ns=ANDROID_NS, value="true"),
    ], [])
    application = _pb_element("application", [
        _pb_attr("debuggable", ns=ANDROID_NS, boolean=True),
    ], [_pb_node(activity)])
    manifest = _pb_element("manifest", [
        _pb_attr("package", value="com.apkinspect.aab"),
    ], [_pb_node(perm), _pb_node(application)])
    return _pb_node(manifest)


def build_aab_bytes(dex: bytes, extra: dict[str, bytes] = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("BundleConfig.pb", b"")
        zf.writestr("base/manifest/AndroidManifest.xml", build_aab_manifest())
        zf.writestr("base/dex/classes.dex", dex)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def vulnerable_assets() -> dict[str, bytes]:
    return {
        "assets/config.json": (
            b'{\n  "firebase": "' + FIREBASE_DB.encode() + b'",\n'
            b'  "api_key": "' + GENERIC_SECRET.encode() + b'"\n}'
        ),
    }
