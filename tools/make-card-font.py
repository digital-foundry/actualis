#!/usr/bin/env python3
"""Print the CARD_FONT table that actualis.py embeds, from Spleen's 8x16 BDF.

Spleen 2.2.0, BSD-2-Clause, (c) Frederic Cambus: https://github.com/fcambus/spleen

    curl -LO https://github.com/fcambus/spleen/releases/download/2.2.0/spleen-2.2.0.tar.gz
    shasum -a 256 spleen-2.2.0.tar.gz
    # ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
    tar xzf spleen-2.2.0.tar.gz
    python3 tools/make-card-font.py spleen-2.2.0/spleen-8x16.bdf

Paste the output over the CARD_FONT block in actualis.py. Only the glyphs a
card can draw are kept: printable ASCII plus the few symbols below. Keys are
written as escapes so the source gains no non-ASCII glyph that needs a
terminal fallback.
"""
import sys

EXTRA = "·▁▂▃▄▅▆▇█░─—"
WANT = [chr(c) for c in range(32, 127)] + list(EXTRA)


def main(path: str) -> None:
    glyphs, enc, rows, in_bitmap = {}, -1, [], False
    with open(path, encoding="ascii") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("ENCODING "):
                enc, rows = int(line.split()[1]), []
            elif line.startswith("BBX ") and line.split()[1:] != ["8", "16", "0", "-4"]:
                sys.exit(f"glyph {enc}: unexpected {line}; this script assumes full 8x16 cells")
            elif line == "BITMAP":
                in_bitmap = True
            elif line == "ENDCHAR":
                in_bitmap = False
                if enc >= 0 and chr(enc) in WANT:
                    glyphs[chr(enc)] = "".join(r.lower() for r in rows)
            elif in_bitmap:
                rows.append(line)
    missing = [c for c in WANT if c not in glyphs]
    if missing:
        sys.exit(f"missing glyphs: {missing!r}")
    print("CARD_FONT: dict[str, str] = {")
    for ch in WANT:
        print(f"    {ascii(ch)}: {glyphs[ch]!r},")
    print("}")


if __name__ == "__main__":
    main(sys.argv[1])
