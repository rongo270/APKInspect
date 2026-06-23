"""Parser for Android Binary XML (AXML) - the compiled ``AndroidManifest.xml``
shipped inside an APK.

The format is a sequence of chunks; we decode the string pool and the XML node
chunks into a small DOM (:class:`Element`) that the manifest analyser walks.

Reference: AOSP ``frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

# ---- chunk types -----------------------------------------------------------
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# ---- string pool flags -----------------------------------------------------
SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

# ---- Res_value typed data types -------------------------------------------
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# A subset of the public ``android:`` attribute resource IDs.  Some compiled
# manifests leave the attribute *name* string empty and only carry the resource
# id, so we map ids back to names for the attributes the scanner cares about.
RES_ID_NAMES = {
    0x01010003: "name",
    0x01010006: "permission",
    0x01010009: "protectionLevel",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010022: "host",
    0x01010027: "scheme",
    0x010102D3: "process",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x010103E7: "authorities",
    0x01010519: "grantUriPermissions",
    0x01010527: "networkSecurityConfig",
    0x01010565: "usesCleartextTraffic",
    0x01010572: "value",
    0x010104EF: "fullBackupContent",
    0x01010604: "testOnly",
}


class AXMLError(ValueError):
    """Raised when the binary XML cannot be decoded."""


@dataclass
class Attribute:
    ns: Optional[str]
    name: str
    value: Any
    type: int
    resource_id: int = 0

    @property
    def is_android(self) -> bool:
        return self.ns == ANDROID_NS


@dataclass
class Element:
    tag: str
    ns: Optional[str] = None
    attributes: list[Attribute] = field(default_factory=list)
    children: list["Element"] = field(default_factory=list)

    def attr(self, name: str, android: bool = True) -> Optional[Attribute]:
        """Return the first matching attribute (preferring the android ns)."""
        match = None
        for a in self.attributes:
            if a.name != name:
                continue
            if android and a.is_android:
                return a
            if match is None:
                match = a
        return match

    def get(self, name: str, default: Any = None, android: bool = True) -> Any:
        a = self.attr(name, android=android)
        return default if a is None else a.value

    def iter(self, tag: Optional[str] = None):
        """Depth-first iteration over this element and its descendants."""
        if tag is None or self.tag == tag:
            yield self
        for child in self.children:
            yield from child.iter(tag)

    def findall(self, tag: str) -> list["Element"]:
        return list(self.iter(tag))


class _Reader:
    __slots__ = ("data", "off")

    def __init__(self, data: bytes, off: int = 0):
        self.data = data
        self.off = off

    def u8(self) -> int:
        v = self.data[self.off]
        self.off += 1
        return v

    def u16(self, at: Optional[int] = None) -> int:
        o = self.off if at is None else at
        v = struct.unpack_from("<H", self.data, o)[0]
        if at is None:
            self.off += 2
        return v

    def u32(self, at: Optional[int] = None) -> int:
        o = self.off if at is None else at
        v = struct.unpack_from("<I", self.data, o)[0]
        if at is None:
            self.off += 4
        return v


def _decode_string_pool(data: bytes, base: int) -> list[str]:
    # ResStringPool_header
    chunk_size = struct.unpack_from("<I", data, base + 4)[0]
    string_count = struct.unpack_from("<I", data, base + 8)[0]
    flags = struct.unpack_from("<I", data, base + 16)[0]
    strings_start = struct.unpack_from("<I", data, base + 20)[0]
    is_utf8 = bool(flags & UTF8_FLAG)

    offsets = []
    pos = base + 28  # header is 28 bytes
    for _ in range(string_count):
        offsets.append(struct.unpack_from("<I", data, pos)[0])
        pos += 4

    strings: list[str] = []
    data_base = base + strings_start
    end = base + chunk_size
    for off in offsets:
        p = data_base + off
        if p >= end or p >= len(data):
            strings.append("")
            continue
        try:
            if is_utf8:
                # two length prefixes: number of UTF-16 units, then byte length
                _, p = _decode_len8(data, p)
                nbytes, p = _decode_len8(data, p)
                strings.append(data[p:p + nbytes].decode("utf-8", "replace"))
            else:
                nchars, p = _decode_len16(data, p)
                raw = data[p:p + nchars * 2]
                strings.append(raw.decode("utf-16-le", "replace"))
        except Exception:
            strings.append("")
    return strings


def _decode_len8(data: bytes, p: int) -> tuple[int, int]:
    n = data[p]
    p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | data[p]
        p += 1
    return n, p


def _decode_len16(data: bytes, p: int) -> tuple[int, int]:
    n = struct.unpack_from("<H", data, p)[0]
    p += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
        p += 2
    return n, p


def _resolve_value(type_: int, data_val: int, raw_ref: int, strings: list[str]) -> Any:
    def s(idx: int) -> str:
        return strings[idx] if 0 <= idx < len(strings) else ""

    if type_ == TYPE_STRING:
        if 0 <= raw_ref < len(strings):
            return s(raw_ref)
        return s(data_val)
    if type_ == TYPE_INT_BOOLEAN:
        return data_val != 0
    if type_ in (TYPE_INT_DEC, TYPE_INT_HEX):
        return data_val
    if type_ == TYPE_REFERENCE:
        return f"@0x{data_val:08x}"
    if type_ == TYPE_ATTRIBUTE:
        return f"?0x{data_val:08x}"
    if type_ == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data_val))[0]
    if type_ == TYPE_NULL:
        return None
    return data_val


def parse(data: bytes) -> Element:
    """Decode AXML bytes into an :class:`Element` tree (the root element)."""
    if len(data) < 8:
        raise AXMLError("file too small")
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic not in (RES_XML_TYPE, RES_NULL_TYPE):
        raise AXMLError(f"not a binary XML file (magic=0x{magic:04x})")

    strings: list[str] = []
    res_ids: list[int] = []
    root: Optional[Element] = None
    stack: list[Element] = []
    ns_map: dict[str, str] = {}

    pos = 8  # skip the RES_XML chunk header
    n = len(data)
    while pos + 8 <= n:
        ctype = struct.unpack_from("<H", data, pos)[0]
        header_size = struct.unpack_from("<H", data, pos + 2)[0]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if size < 8:
            break  # malformed; stop rather than loop forever

        if ctype == RES_STRING_POOL_TYPE:
            strings = _decode_string_pool(data, pos)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            count = (size - header_size) // 4
            res_ids = [struct.unpack_from("<I", data, pos + header_size + i * 4)[0] for i in range(count)]
        elif ctype == RES_XML_START_NAMESPACE_TYPE:
            prefix = struct.unpack_from("<I", data, pos + header_size)[0]
            uri = struct.unpack_from("<I", data, pos + header_size + 4)[0]
            if 0 <= uri < len(strings):
                ns_map[strings[uri]] = strings[prefix] if 0 <= prefix < len(strings) else ""
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            elem = _parse_start_element(data, pos, header_size, strings, res_ids)
            if root is None:
                root = elem
            if stack:
                stack[-1].children.append(elem)
            stack.append(elem)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()

        pos += size

    if root is None:
        raise AXMLError("no XML elements found")
    return root


def _name_of(idx: int, res_id: int, strings: list[str]) -> str:
    if 0 <= idx < len(strings) and strings[idx]:
        return strings[idx]
    return RES_ID_NAMES.get(res_id, "")


def _parse_start_element(
    data: bytes, base: int, header_size: int, strings: list[str], res_ids: list[int]
) -> Element:
    ext = base + header_size  # ResXMLTree_attrExt
    ns_idx = struct.unpack_from("<i", data, ext)[0]
    name_idx = struct.unpack_from("<i", data, ext + 4)[0]
    attr_start = struct.unpack_from("<H", data, ext + 8)[0]
    attr_size = struct.unpack_from("<H", data, ext + 10)[0]
    attr_count = struct.unpack_from("<H", data, ext + 12)[0]

    tag = strings[name_idx] if 0 <= name_idx < len(strings) else ""
    ns_uri = strings[ns_idx] if 0 <= ns_idx < len(strings) else None
    elem = Element(tag=tag, ns=ns_uri)

    attrs_base = ext + attr_start
    if attr_size == 0:
        attr_size = 20
    for i in range(attr_count):
        a = attrs_base + i * attr_size
        a_ns = struct.unpack_from("<i", data, a)[0]
        a_name = struct.unpack_from("<i", data, a + 4)[0]
        a_raw = struct.unpack_from("<i", data, a + 8)[0]
        # Res_value: size(u16) res0(u8) dataType(u8) data(u32)
        a_type = data[a + 15]
        a_data = struct.unpack_from("<I", data, a + 16)[0]

        res_id = res_ids[a_name] if 0 <= a_name < len(res_ids) else 0
        name = _name_of(a_name, res_id, strings)
        value = _resolve_value(a_type, a_data, a_raw, strings)
        ns = strings[a_ns] if 0 <= a_ns < len(strings) else None
        elem.attributes.append(
            Attribute(ns=ns, name=name, value=value, type=a_type, resource_id=res_id)
        )
    return elem
