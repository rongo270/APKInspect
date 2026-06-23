"""Best-effort parser for the protobuf-encoded ``AndroidManifest.xml`` that
ships inside an Android App Bundle (``.aab``).

Unlike an APK (binary AXML), an AAB stores the manifest as an ``aapt.pb.XmlNode``
protobuf.  We don't have the generated bindings, so we decode the wire format
generically and reconstruct the element tree, reusing the :class:`~apkinspect.axml.Element`
model so the same manifest analyser works for both inputs.

Field numbers (from aapt2 ``Resources.proto``):

* ``XmlNode``      : element=1, text=2
* ``XmlElement``   : namespace_decl=1, namespace_uri=2, name=3, attribute=4, child=5
* ``XmlAttribute`` : namespace_uri=1, name=2, value=3, source=4, resource_id=5, compiled_item=6
* ``Item``         : prim=7 (among others)
* ``Primitive``    : int_decimal=6, int_hex=7, boolean=8
"""
from __future__ import annotations

from typing import Any

from .axml import ANDROID_NS, Attribute, Element

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LEN = 2
WIRE_32BIT = 5


class AABError(ValueError):
    pass


def _read_varint(data: bytes, p: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if p >= len(data):
            raise AABError("truncated varint")
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, p
        shift += 7


def parse_fields(data: bytes) -> dict[int, list[tuple[int, Any]]]:
    """Decode a protobuf message into ``{field_number: [(wire_type, value), ...]}``.

    Length-delimited values are returned as raw ``bytes``; varints/fixed as ints.
    """
    out: dict[int, list[tuple[int, Any]]] = {}
    p = 0
    n = len(data)
    while p < n:
        key, p = _read_varint(data, p)
        field_no = key >> 3
        wire = key & 0x07
        if wire == WIRE_VARINT:
            val, p = _read_varint(data, p)
        elif wire == WIRE_64BIT:
            val = int.from_bytes(data[p:p + 8], "little")
            p += 8
        elif wire == WIRE_LEN:
            length, p = _read_varint(data, p)
            val = data[p:p + length]
            p += length
        elif wire == WIRE_32BIT:
            val = int.from_bytes(data[p:p + 4], "little")
            p += 4
        else:
            raise AABError(f"unsupported wire type {wire}")
        out.setdefault(field_no, []).append((wire, val))
    return out


def _first(fields: dict[int, list[tuple[int, Any]]], no: int, wire: int | None = None) -> Any:
    for w, v in fields.get(no, []):
        if wire is None or w == wire:
            return v
    return None


def _as_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def _decode_compiled_item(raw: bytes) -> Any:
    """Pull a concrete value out of an ``Item`` (compiled_item) protobuf."""
    try:
        item = parse_fields(raw)
        prim_raw = _first(item, 7, WIRE_LEN)  # Item.prim
        if isinstance(prim_raw, bytes):
            prim = parse_fields(prim_raw)
            if 8 in prim:  # boolean_value
                return bool(prim[8][0][1])
            if 6 in prim:  # int_decimal_value
                return prim[6][0][1]
            if 7 in prim:  # int_hexadecimal_value
                return prim[7][0][1]
        ref_raw = _first(item, 1, WIRE_LEN)  # Item.ref -> reference
        if isinstance(ref_raw, bytes):
            ref = parse_fields(ref_raw)
            if 2 in ref:  # Reference.id
                return f"@0x{ref[2][0][1]:08x}"
    except AABError:
        pass
    return None


def _decode_attribute(raw: bytes) -> Attribute:
    f = parse_fields(raw)
    ns = _as_str(_first(f, 1, WIRE_LEN)) or None
    name = _as_str(_first(f, 2, WIRE_LEN))
    res_id = _first(f, 5, WIRE_VARINT) or 0

    value: Any = None
    str_val = _first(f, 3, WIRE_LEN)
    if str_val is not None and str_val != b"":
        value = _as_str(str_val)
    else:
        compiled = _first(f, 6, WIRE_LEN)
        if isinstance(compiled, bytes):
            value = _decode_compiled_item(compiled)
        if value is None and str_val == b"":
            value = ""
    return Attribute(ns=ns, name=name, value=value, type=-1, resource_id=res_id)


def _decode_element(raw: bytes) -> Element:
    f = parse_fields(raw)
    ns = _as_str(_first(f, 2, WIRE_LEN)) or None
    name = _as_str(_first(f, 3, WIRE_LEN))
    elem = Element(tag=name, ns=ns)
    for w, attr_raw in f.get(4, []):
        if w == WIRE_LEN and isinstance(attr_raw, bytes):
            elem.attributes.append(_decode_attribute(attr_raw))
    for w, child_raw in f.get(5, []):
        if w == WIRE_LEN and isinstance(child_raw, bytes):
            child = _decode_node(child_raw)
            if child is not None:
                elem.children.append(child)
    return elem


def _decode_node(raw: bytes) -> Element | None:
    f = parse_fields(raw)
    elem_raw = _first(f, 1, WIRE_LEN)  # XmlNode.element
    if isinstance(elem_raw, bytes):
        return _decode_element(elem_raw)
    return None


def parse(data: bytes) -> Element:
    """Decode a protobuf ``XmlNode`` manifest into an :class:`Element` tree."""
    root = _decode_node(data)
    if root is None:
        raise AABError("no root element in protobuf manifest")
    return root
