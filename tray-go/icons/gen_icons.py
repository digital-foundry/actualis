#!/usr/bin/env python3
"""Generate the tray icon set from the ACTUALIS macOS icon sheet.

Every constant below is measured off branding/trayiconMac.png rather than
chosen by eye. The 32px cells of the SIZES table are the authoritative
templates; the 98px STATE ICONS OVERVIEW tiles are used where the 32px
cells are too coarse to measure (stroke weight, mainly). Measurements are
recorded next to each constant so they can be re-derived.

The sheet's usage notes say "do not alter proportions or stroke weights",
so these ratios are the spec. Change them only by re-measuring the sheet.

Two colourways are emitted per state because macOS template images are
alpha-only -- they cannot carry the amber, and the sheet requires amber in
both the light and dark menu bar. See appearance_darwin.go.

    python3 gen_icons.py
"""

import math
import pathlib
import struct
import zlib

# --- palette, from PALETTE (APPROVED) on the sheet -----------------------
CARBON = (0x0B, 0x0C, 0x0E)
BONE   = (0xF2, 0xEF, 0xE9)
AMBER  = (0xC4, 0x7A, 0x3A)

# --- geometry, as ratios ------------------------------------------------
# A-mark, from the 32px IDLE cell: bbox 22w x 23h in a 32px canvas.
CAP        = 0.72          # cap height / canvas          23/32
# Stroke from the 98px PRIMARY tile (6px stroke, 47px cap); the 32px cell
# is too coarse to measure a 2px stroke against antialiasing.
STROKE     = 0.12          # stroke / cap                  6/47
# Amber crossbar: a short centred dash low in the counter, NOT a bar
# spanning the legs. 32px cell 7/22; 98px tile 13/45.
DASH_W     = 0.31          # dash length / cap
DASH_Y     = 0.81          # dash centre below apex / cap  32px 0.826, 98px 0.793

# MONITORING: two amber dots, upper right, unequal. From the 32px cell --
# big d=4 at (36.5,7.5), small d=3 at (31.0,8.0), A centre (23,20.5) cap 24.
MON_BIG_R  = 0.083         # r / cap                       2/24
MON_BIG_X  = 0.563         # centre offset / cap          13.5/24
MON_BIG_Y  = -0.542        #                              -13/24
MON_SML_R  = 0.063         #                             1.5/24
MON_SML_X  = 0.333         #                               8/24
MON_SML_Y  = -0.521        #                            -12.5/24

# EXPOSED/WARNING, from the 32px cell: amber ring outer d=35, stroke 2,
# inner A cap 20. The ring is the outermost element so it, not the A, is
# what the canvas has to contain.
RING_OUTER = 0.93          # ring outer diameter / canvas
RING_W     = 0.057         # ring stroke / ring outer      2/35
RING_CAP   = 0.571         # inner A cap / ring outer      20/35

# UPDATE AVAILABLE: solid amber badge. 32px cell d=12 at (34.5,11).
UPD_R      = 0.26          # r / cap                       6/23
UPD_X      = 0.50          #                            11.5/23
UPD_Y      = -0.478        #                             -11/23

# SYNCING: 8-segment spinner, no A-mark.
SYNC_R     = 0.34          # segment ring radius / canvas
SYNC_SEGS  = 8

S  = 44                    # canvas, 22pt @2x
SS = 4                     # supersampling


# ------------------------------------------------------------------ raster
def render(shapes):
    """shapes: list of (hit_fn, rgb, alpha), painted back to front."""
    buf = [[(0.0, 0.0, 0.0, 0.0)] * S for _ in range(S)]
    buf = [[(0.0, 0.0, 0.0, 0.0) for _ in range(S)] for _ in range(S)]
    for fn, rgb, alpha in shapes:
        for py in range(S):
            for px in range(S):
                hits = sum(1 for sy in range(SS) for sx in range(SS)
                           if fn(px + (sx + .5) / SS, py + (sy + .5) / SS))
                if not hits:
                    continue
                a = (hits / (SS * SS)) * alpha
                r0, g0, b0, a0 = buf[py][px]
                na = a + a0 * (1 - a)
                buf[py][px] = ((rgb[0] * a + r0 * a0 * (1 - a)) / na,
                               (rgb[1] * a + g0 * a0 * (1 - a)) / na,
                               (rgb[2] * a + b0 * a0 * (1 - a)) / na, na)
    raw = bytearray()
    for y in range(S):
        raw += b"\x00"
        for x in range(S):
            r, g, b, a = buf[y][x]
            raw += bytes((int(r + .5), int(g + .5), int(b + .5), int(a * 255 + .5)))

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", S, S, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def seg(x1, y1, x2, y2, w):
    """Round-capped line, so the A's apex joins cleanly."""
    hw = w / 2.0
    dx, dy = x2 - x1, y2 - y1
    L2 = dx * dx + dy * dy

    def f(x, y):
        t = 0.0 if L2 == 0 else max(0.0, min(1.0, ((x - x1) * dx + (y - y1) * dy) / L2))
        return math.hypot(x - (x1 + t * dx), y - (y1 + t * dy)) <= hw
    return f


def ring(cx, cy, r, w):
    hw = w / 2.0
    return lambda x, y: abs(math.hypot(x - cx, y - cy) - r) <= hw


def disc(cx, cy, r):
    return lambda x, y: math.hypot(x - cx, y - cy) <= r


def arc(cx, cy, r, a0, a1, w):
    """Angles in degrees, counter-clockwise from east."""
    hw = w / 2.0
    lo, hi = math.radians(a0), math.radians(a1)

    def f(x, y):
        d = math.hypot(x - cx, y - cy)
        if abs(d - r) > hw:
            return False
        th = math.atan2(cy - y, x - cx) % (2 * math.pi)
        span = (hi - lo) % (2 * math.pi)
        return ((th - lo) % (2 * math.pi)) <= span
    return f


# ------------------------------------------------------------------ glyphs
def a_mark(cap, cx, cy, ink, alpha=1.0):
    """The A: square bbox, apex a clean join, short centred amber dash."""
    stroke = STROKE * cap
    top, bot = cy - cap / 2, cy + cap / 2
    # Inset the endpoints by half a stroke so the painted bbox is cap x cap.
    h = stroke / 2
    apex = (cx, top + h)
    left = (cx - cap / 2 + h, bot - h)
    right = (cx + cap / 2 - h, bot - h)
    legs = [(seg(*apex, *left, stroke), ink, alpha),
            (seg(*apex, *right, stroke), ink, alpha)]
    dw = DASH_W * cap
    dy = top + DASH_Y * cap
    dash = [(seg(cx - dw / 2 + h, dy, cx + dw / 2 - h, dy, stroke), AMBER, alpha)]
    return legs + dash


def shapes_for(state, ink):
    c = S / 2.0
    cap = CAP * S

    if state == "syncing":
        r = SYNC_R * S
        w = STROKE * cap
        out = []
        for i in range(SYNC_SEGS):
            a0 = i * (360 / SYNC_SEGS) + 6
            a1 = a0 + (360 / SYNC_SEGS) - 12
            # Amber head fading into ink tail, per the sheet's spinner.
            if i < 3:
                col, alpha = AMBER, 1.0 - i * 0.22
            else:
                col, alpha = ink, 0.55 - (i - 3) * 0.07
            out.append((arc(c, c, r, a0, a1, w), col, max(alpha, 0.18)))
        return out

    if state == "exposed":
        outer = RING_OUTER * S
        rw = RING_W * outer
        rcap = RING_CAP * outer
        return (a_mark(rcap, c, c, ink)
                + [(ring(c, c, (outer - rw) / 2.0, rw), AMBER, 1.0)])

    out = a_mark(cap, c, c, ink)

    if state == "monitoring":
        out += [(disc(c + MON_SML_X * cap, c + MON_SML_Y * cap, MON_SML_R * cap), AMBER, 1.0),
                (disc(c + MON_BIG_X * cap, c + MON_BIG_Y * cap, MON_BIG_R * cap), AMBER, 1.0)]
    elif state == "update":
        r = UPD_R * cap
        # Clamp into the canvas; at 44px the sheet's offset would overflow.
        bx = min(c + UPD_X * cap, S - r - 0.5)
        by = max(c + UPD_Y * cap, r + 0.5)
        out += [(disc(bx, by, r), AMBER, 1.0)]
    elif state == "muted":
        out += [(seg(6.5, S - 6.5, S - 6.5, 6.5, STROKE * cap), ink, 1.0)]
    return out


STATES = ["idle", "active", "monitoring", "exposed", "syncing", "update", "muted"]


def main():
    out = pathlib.Path(__file__).resolve().parent
    for f in out.glob("*.png"):
        f.unlink()
    for st in STATES:
        # -dark  = for a dark menu bar  (bone ink)
        # -light = for a light menu bar (carbon ink)
        (out / f"{st}-dark.png").write_bytes(render(shapes_for(st, BONE)))
        (out / f"{st}-light.png").write_bytes(render(shapes_for(st, CARBON)))
    # The sheet has no error glyph; MUTED (A with a slash) carries the
    # unreadable-data state rather than inventing a state off-spec.
    for suffix in ("dark", "light"):
        (out / f"error-{suffix}.png").write_bytes((out / f"muted-{suffix}.png").read_bytes())
    print(f"wrote {len(list(out.glob('*.png')))} icons to {out}")


if __name__ == "__main__":
    main()
