"""Generate the APKInspect app icon (PNG + Windows ICO) with no image libraries -
just zlib from the standard library. A magnifying glass over a shield = "inspect
+ security", on an indigo->violet gradient badge.

    python tools/make_icon.py

Writes assets/icon.png (256x256) and assets/icon.ico (multi-size).
"""
from __future__ import annotations

import math
import os
import struct
import zlib

SS = 4              # supersampling factor for anti-aliasing
BASE = 256
R = BASE * SS

# palette
GRAD_TOP = (91, 108, 240)     # #5B6CF0
GRAD_BOT = (155, 93, 229)     # #9B5DE5
SHIELD = (58, 45, 143)        # deep indigo
WHITE = (255, 255, 255)


class Canvas:
    def __init__(self, w: int, h: int):
        self.w, self.h = w, h
        self.buf = bytearray(w * h * 4)

    def set(self, x: int, y: int, rgb, a: int = 255):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 4
            self.buf[i] = rgb[0]
            self.buf[i + 1] = rgb[1]
            self.buf[i + 2] = rgb[2]
            self.buf[i + 3] = a


def _round_inside(x, y, x0, y0, x1, y1, rad) -> bool:
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    # corner circles
    for cx, cy in ((x0 + rad, y0 + rad), (x1 - rad, y0 + rad),
                   (x0 + rad, y1 - rad), (x1 - rad, y1 - rad)):
        inx = (cx == x0 + rad and x < x0 + rad) or (cx == x1 - rad and x > x1 - rad)
        iny = (cy == y0 + rad and y < y0 + rad) or (cy == y1 - rad and y > y1 - rad)
        if inx and iny:
            if (x - cx) ** 2 + (y - cy) ** 2 > rad * rad:
                return False
    return True


def _point_in_poly(x, y, poly) -> bool:
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y):
            xc = (xj - xi) * (y - yi) / (yj - yi) + xi
            if x < xc:
                inside = not inside
        j = i
    return inside


def _seg_dist(px, py, ax, ay, bx, by) -> float:
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def render() -> Canvas:
    c = Canvas(R, R)
    margin = 0.055 * R
    rad = 0.235 * R
    x0, y0, x1, y1 = margin, margin, R - margin, R - margin

    # background gradient inside the rounded badge
    for y in range(int(y0), int(y1) + 1):
        t = (y - y0) / (y1 - y0)
        rgb = (round(GRAD_TOP[0] + (GRAD_BOT[0] - GRAD_TOP[0]) * t),
               round(GRAD_TOP[1] + (GRAD_BOT[1] - GRAD_TOP[1]) * t),
               round(GRAD_TOP[2] + (GRAD_BOT[2] - GRAD_TOP[2]) * t))
        for x in range(int(x0), int(x1) + 1):
            if _round_inside(x, y, x0, y0, x1, y1, rad):
                c.set(x, y, rgb)

    # magnifying glass geometry
    cx, cy = 0.45 * R, 0.43 * R
    ro = 0.205 * R          # lens (white disc) radius
    a45 = math.cos(math.pi / 4)
    hx0, hy0 = cx + (ro - 0.02 * R) * a45, cy + (ro - 0.02 * R) * a45
    hx1, hy1 = 0.74 * R, 0.72 * R
    hr = 0.058 * R          # handle radius

    # white handle (drawn first so the lens overlaps it cleanly)
    for y in range(int(cy), int(hy1 + hr) + 1):
        for x in range(int(cx), int(hx1 + hr) + 1):
            if _seg_dist(x, y, hx0, hy0, hx1, hy1) <= hr:
                c.set(x, y, WHITE)

    # white lens disc
    r2 = ro * ro
    for y in range(int(cy - ro), int(cy + ro) + 1):
        for x in range(int(cx - ro), int(cx + ro) + 1):
            if (x - cx) ** 2 + (y - cy) ** 2 <= r2:
                c.set(x, y, WHITE)

    # indigo shield inside the lens
    hw = 0.125 * R
    poly = [
        (cx - hw, cy - 0.115 * R),
        (cx + hw, cy - 0.115 * R),
        (cx + hw, cy + 0.02 * R),
        (cx, cy + 0.17 * R),
        (cx - hw, cy + 0.02 * R),
    ]
    minx = int(min(p[0] for p in poly))
    maxx = int(max(p[0] for p in poly))
    miny = int(min(p[1] for p in poly))
    maxy = int(max(p[1] for p in poly))
    for y in range(miny, maxy + 1):
        for x in range(minx, maxx + 1):
            if _point_in_poly(x, y, poly):
                c.set(x, y, SHIELD)
    return c


def downscale(src: Canvas, dst_size: int) -> bytes:
    """Box-downscale with premultiplied alpha -> clean anti-aliased edges."""
    factor = src.w // dst_size
    out = bytearray(dst_size * dst_size * 4)
    for oy in range(dst_size):
        for ox in range(dst_size):
            ar = ag = ab = aa = 0
            for dy in range(factor):
                for dx in range(factor):
                    i = ((oy * factor + dy) * src.w + (ox * factor + dx)) * 4
                    a = src.buf[i + 3]
                    ar += src.buf[i] * a
                    ag += src.buf[i + 1] * a
                    ab += src.buf[i + 2] * a
                    aa += a
            o = (oy * dst_size + ox) * 4
            if aa:
                out[o] = ar // aa
                out[o + 1] = ag // aa
                out[o + 2] = ab // aa
            out[o + 3] = aa // (factor * factor)
    return bytes(out)


def png_bytes(w: int, h: int, rgba: bytes) -> bytes:
    def chunk(typ: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += rgba[y * w * 4:(y + 1) * w * 4]
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def ico_bytes(images: list[tuple[int, bytes]]) -> bytes:
    n = len(images)
    out = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    body = b""
    for size, png in images:
        dim = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
        body += png
    return out + body


def icns_bytes(entries: list[tuple[bytes, bytes]]) -> bytes:
    """Wrap PNGs in a macOS ICNS container.

    ``entries`` is a list of ``(4-byte OSType, png_bytes)``. Each block is
    ``OSType + uint32(len + 8) + png``; the file is ``b"icns" + uint32(total) + blocks``.
    """
    body = b"".join(ostype + struct.pack(">I", len(png) + 8) + png
                    for ostype, png in entries)
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(root, "assets")
    os.makedirs(assets, exist_ok=True)

    master = render()
    png256 = png_bytes(BASE, BASE, downscale(master, BASE))
    with open(os.path.join(assets, "icon.png"), "wb") as fh:
        fh.write(png256)

    images = []
    for size in (16, 32, 48, 64, 128, 256):
        rgba = downscale(master, size)
        images.append((size, png_bytes(size, size, rgba)))
    with open(os.path.join(assets, "icon.ico"), "wb") as fh:
        fh.write(ico_bytes(images))

    # macOS .icns — PNG-backed OSTypes covering Finder/Dock at every size + retina
    png = {s: png_bytes(s, s, downscale(master, s)) for s in (16, 32, 64, 128, 256, 512, 1024)}
    icns = icns_bytes([
        (b"icp4", png[16]),    # 16x16
        (b"icp5", png[32]),    # 32x32
        (b"ic11", png[32]),    # 16x16@2x
        (b"ic12", png[64]),    # 32x32@2x
        (b"ic07", png[128]),   # 128x128
        (b"ic13", png[256]),   # 128x128@2x
        (b"ic08", png[256]),   # 256x256
        (b"ic14", png[512]),   # 256x256@2x
        (b"ic09", png[512]),   # 512x512
        (b"ic10", png[1024]),  # 512x512@2x
    ])
    with open(os.path.join(assets, "icon.icns"), "wb") as fh:
        fh.write(icns)

    print(f"wrote {assets}\\icon.png ({len(png256)} bytes), icon.ico, icon.icns ({len(icns)} bytes)")


if __name__ == "__main__":
    main()
