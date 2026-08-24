# 0001 — Tray icon deviates from the brand sheet on weight and scale

**Status:** accepted, 2026-08-23
**Applies to:** `tray-go/icons/gen_icons.py`, all tray platforms

## Context

`branding/trayiconMac.png` specifies the tray icon geometry and its usage
notes say **"Do not alter proportions or stroke weights."** The icon set was
rebuilt to follow it exactly — every ratio measured off the sheet rather than
eyeballed, with the source measurement recorded beside each constant.

Rendered faithfully, the mark sits visibly lighter than everything else in the
menu bar. This was measured, not asserted. A real screen capture of the menu
bar was segmented against a per-row background model and compared against 12
neighbouring tray icons:

| | ACTUALIS | neighbours (median) |
|---|---|---|
| footprint height | 30px | 30px |
| ink coverage | 0.31 | 0.53 all / 0.44 excluding solid-filled marks |
| mean horizontal run | 3.18px | 6.69 all / 5.29 excluding solid-filled marks |

Height already matched. The gap is entirely weight: neighbouring icons are
either solid glyphs or considerably heavier strokes, and against them a
faithful A-mark reads as a faint outline rather than a peer.

There is a second, structural reason the sheet cannot be followed literally
here. The sheet's own SIZES table draws the EXPOSED ring at 35px inside a
nominal 32px cell — the ring overflows the box. macOS scales a status image to
the menu bar height, so on a fixed-height bar the ring and the A cannot both be
at the sheet's sizes. Something has to give.

## Decision

Deviate from the sheet on **stroke weight** and **overall scale**, and on
nothing else.

```
CAP_BOOST    = 1.30    #  0.72 -> 0.936 of canvas height
STROKE_BOOST = 1.70    #  0.12 -> 0.204 of cap
```

`STROKE_BOOST` is applied to the exposed ring as well, so it does not stay
hairline beside a bolder A.

Everything else stays exactly as measured off the sheet: the square A bbox, the
crossbar's length and its position 0.81 down the cap, the two unequal amber
monitoring dots and their x offsets, the ring stroke as a ratio of ring
diameter, the inner-A-to-ring ratio, and ACTIVE being identical to IDLE.

Two consequential fit adjustments follow from the boost rather than being
choices of their own:

- The canvas is **50x44**, not square. A status image may be wider than it is
  tall, and at the boosted cap the monitoring dots need the room.
- The monitoring dots are clamped so their tops align with the A's apex. The
  sheet places them slightly above it, which at the boosted cap is off-canvas.

Result, measured the same way as the table above: every state renders at 30px
with coverage 0.42–0.46, against a neighbour band of 0.44–0.53.

## Consequences

- The tray icon is **not** pixel-faithful to `trayiconMac.png`. Anyone
  comparing the two will find a difference, and this record is why.
- The deviation is two named constants. Setting both to `1.0` restores the
  sheet exactly, which is the point of expressing it this way.
- The sheet is unchanged and remains the source for every other ratio. If it is
  revised, re-measure and the boosts still apply on top.
- This does not license further drift. Any new deviation needs its own record.

## Alternatives rejected

- **Follow the sheet exactly.** Rejected: the icon does not hold its own in the
  menu bar, which is the one place it exists.
- **Revise the brand sheet instead.** Reasonable, and still open — but the
  sheet is shared artwork covering more than the tray, and changing it is not
  this repo's call. Recorded here so it can be raised.
- **Boost weight without scale.** Rejected: a heavier stroke on a small mark
  reads as a blob rather than as presence.

## Open item

The palettes disagree between sheets. `trayiconMac.png` gives slate `#2A3138`,
smoke `#6B7278`, amber `#C47A3A`; the brand guide and `trayiconWindows.png`
give `#1F2430`, `#3A414E`, `#E08A24`. The amber differs visibly. The macOS tray
follows the macOS sheet (`#C47A3A`). Whoever owns the sheets should reconcile
them.
