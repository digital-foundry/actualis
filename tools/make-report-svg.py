#!/usr/bin/env python3
"""Render a coloured `actualis` report to SVG, for the README and the site.

Run against a SYNTHETIC fleet only, never a real one — see
tools/make-demo-fleet.py, which invents every project name, branch, command and
credential shape so the image cannot leak anything.

SVG rather than PNG: sharp at any zoom, a few KB, and the text stays selectable
and greppable in the page.

    python3 tools/make-demo-fleet.py /tmp/actualis-demo-fleet
    python3 tools/capture-report.py  /tmp/actualis-demo-fleet /tmp/ansi.txt
    python3 tools/make-report-svg.py /tmp/ansi.txt docs/img/actualis-report.svg
"""
import re, sys, html, pathlib

PAL = {"fg": "#F2EFE9", "bg": "#0B0C0E", "dim": "#6C7480", "bold": "#FFFFFF",
       "31": "#E86A5A", "32": "#6FBF9A", "33": "#E08A24", "36": "#7FA8BF"}
# Sections that carry the argument: what it cost, where it went, what leaked.
# The long tails (per-ticket, per-command, the 15 most recent flags) say nothing
# the summary lines do not and tripled the height.
RANGES = [(8, 16), (24, 29), (30, 36), (37, 45), (66, 70), (84, 91)]
CW, LH, PAD = 8.05, 19.0, 26


def main(capture: str, dest: str) -> None:
    src = re.sub(r"^.*\r", "", pathlib.Path(capture).read_text(errors="replace"), flags=re.M)
    rows, state = [], {"c": None, "b": False, "d": False}
    for raw in src.split("\n"):
        cur, i = [], 0
        for m in re.finditer(r"\x1b\[([0-9;]*)m", raw):
            if m.start() > i:
                cur.append((raw[i:m.start()], dict(state)))
            for code in (m.group(1) or "0").split(";"):
                if code in ("", "0"): state.update(c=None, b=False, d=False)
                elif code == "1": state["b"] = True
                elif code == "2": state["d"] = True
                elif code in PAL: state["c"] = code
            i = m.end()
        if i < len(raw):
            cur.append((raw[i:], dict(state)))
        rows.append(cur)

    keep = []
    for a, b in RANGES:
        for r in rows[a:b]:
            # The demo's source path is a scratch directory. Cropped rather than
            # replaced: substituting a plausible ~/.claude/projects would be
            # inventing output, which is what this tool exists to oppose.
            if "actualis-demo-fleet" in "".join(t for t, _ in r):
                continue
            keep.append(r)
        keep.append([])
    while keep and not any(t.strip() for t, _ in keep[-1]):
        keep.pop()

    width = max(sum(len(t) for t, _ in ln) for ln in keep)
    W, H = int(width * CW + PAD * 2), int(len(keep) * LH + PAD * 2 + 34)

    def colour(st):
        return (PAL[st["c"]] if st["c"] else PAL["dim"] if st["d"]
                else PAL["bold"] if st["b"] else PAL["fg"])

    body = []
    for r, ln in enumerate(keep):
        x, y = PAD, PAD + 34 + r * LH
        for text, st in ln:
            if text.strip():
                # xml:space belongs on the element. Inheriting it from a parent
                # group is honoured inconsistently, and losing it collapses
                # every aligned column in the report.
                a = f'x="{x:.1f}" y="{y:.1f}" fill="{colour(st)}" xml:space="preserve"'
                if st["b"]:
                    a += ' font-weight="600"'
                body.append(f"<text {a}>{html.escape(text)}</text>")
            x += len(text) * CW

    font = "ui-monospace,SFMono-Regular,Menlo,'IBM Plex Mono',monospace"
    pathlib.Path(dest).write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="{font}" font-size="13">\n'
        f"<title>actualis report — illustrative output from a synthetic fleet</title>\n"
        f'<rect width="{W}" height="{H}" rx="8" fill="{PAL["bg"]}"/>\n'
        f'<circle cx="24" cy="22" r="5.5" fill="#3A414E"/>'
        f'<circle cx="42" cy="22" r="5.5" fill="#3A414E"/>'
        f'<circle cx="60" cy="22" r="5.5" fill="#3A414E"/>\n'
        f'<text x="80" y="26" fill="{PAL["dim"]}" font-size="11" xml:space="preserve">'
        f"actualis — illustrative output, synthetic data</text>\n"
        + "\n".join(body) + "\n</svg>\n")
    print(f"  {dest}  {len(keep)} lines  {W}x{H}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
