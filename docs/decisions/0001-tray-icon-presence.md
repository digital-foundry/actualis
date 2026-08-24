# 0001 — Tray icon deviates from the brand sheet on weight and scale

**Status:** accepted, 2026-08-23
**Applies to:** `tray-go/icons/gen_icons.py`, all tray platforms

## Context

The ACTUALIS macOS icon sheet specifies the tray icon geometry and its usage
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
STROKE_BOOST = 1.35    #  0.12 -> 0.162 of cap
```

`STROKE_BOOST` applies to three things, and it has to apply to all three or the
mark comes apart:

- the A's legs;
- the **exposed ring**, otherwise it stays hairline beside a bolder A;
- the **crossbar's length as well as its thickness**. The sheet's dash is
  2.6:1. Boosting only the thickness takes it to 1.9:1, and inside the exposed
  ring -- where the A is reduced to 0.571 of the ring -- it stops reading as a
  dash and becomes a dot.

`STROKE_BOOST` is capped at 1.35 by **legibility, not by the coverage target**.
1.70 hits the neighbour coverage band exactly and is wrong: at that weight the
exposed A's counter closes and the mark reads as a filled triangle. Candidates
were rendered at true menu bar scale and compared before choosing. The final
figure sits a little under the neighbour band -- coverage 0.38-0.39 against
0.44-0.53 -- and that gap is the price of keeping the counter open.

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

Result: every state renders at 30px, matching the neighbour median exactly,
with the four states that carry the A-mark at coverage 0.38–0.39 against a
neighbour band of 0.44–0.53. Up from 0.31.

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
- **Boost weight until coverage matches the neighbour band** (STROKE_BOOST
  1.70). Rejected on inspection at true menu bar scale: it hits the number and
  destroys the glyph. Coverage is a useful proxy for "does this hold its own",
  not a target to optimise into.

## Resolved: the palette contradiction

The sheets disagreed on three of five swatches. The macOS icon sheet printed
slate `#2A3138`, smoke `#6B7278` and amber `#C47A3A`; the brand guide and the
Windows sheet print `#1F2430`, `#3A414E` and `#E08A24`. Carbon and bone matched
in both.

Amber is the one that mattered: it is the brand's only accent, and `#C47A3A` is
visibly browner and duller than `#E08A24`. The macOS tray shipped one and the
website the other, so the two were the same brand in different colours.

Settled on the **brand guide**. It is the primary source that the platform
sheets derive from, the Windows sheet already agrees with it, and the website
uses it. The pattern of the disagreement supports that reading rather than
contradicting it: all three divergent swatches are browner and lighter on the
macOS sheet while carbon and bone are identical, which is what a colour-profile
mismatch in rendering looks like, not what three deliberate design changes look
like.

The tray icons are regenerated at `#E08A24`. If the sheet's amber turns out to
be intentional after all, this is one constant in `gen_icons.py`.
