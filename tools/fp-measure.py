#!/usr/bin/env python3
"""Measure what the 0.8.0 shell-audit changes add, on this machine's transcripts.

It reads the agent transcripts actualis would read (read-only, through
actualis.py) and prints counts and rates only: never a command, a path or a
host, so the output can be pasted into a pull request.

  python3 tools/fp-measure.py
  python3 tools/fp-measure.py --days 90
  python3 tools/fp-measure.py --sample 30 --out ~/fp-sample.txt

--sample N --out FILE writes up to N randomly chosen new hits of each kind,
redacted, to FILE: created with mode 0600, never overwritten, never stdout.
Mark each line tp (worth a look) or fp (a false positive) and report only the
counts.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import random
import re
import statistics
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import actualis as A  # noqa: E402

# The unreadable shapes 0.8.0 added; every other shape was in 0.7.0.
NEW_SHAPES = ("runs a variable after assignments", "interpreter reaching the network",
              "inline script running decoded code", "decodes data into a shell")
B64_RULE = "base64 -d | sh rule"
KINDS = NEW_SHAPES + (B64_RULE, A.RETRY_CATEGORY, A.OUTSIDE_ROOT_CATEGORY)


class _Collecting(A.Fleet):
    """A Fleet that also keeps each shell command it audits, in memory only."""

    def __init__(self) -> None:
        super().__init__()
        self.commands: list[str] = []

    def add_tool(self, project, name, tool_input, ts, mode=None, **kw):
        before = self.bash_total
        super().add_tool(project, name, tool_input, ts, mode, **kw)
        if self.bash_total > before:
            self.commands.append(tool_input["command"])


def scan(days: "int | None", guardrails: bool) -> "tuple[_Collecting, float]":
    """Every agent's transcripts, as the report reads them; and the seconds taken."""
    f = _Collecting()
    f._guardrails = guardrails
    since = A.window_start(days, datetime.now(timezone.utc)) if days else None
    t = time.perf_counter()
    f.scan(A.transcript_roots(), since, None, progress=False)
    f.scan_codex(A.codex_roots(), since, None)
    f.scan_copilot(A.copilot_roots(), since, None)
    f.scan_gemini(A.gemini_roots(), since, None)
    f.scan_qwen(A.qwen_roots(), since, None)
    return f, time.perf_counter() - t


def measure(f: _Collecting) -> dict:
    """Per command: the audit's time, the new patterns' time, and which new
    shape or rule matched; per flag, the two new categories."""
    b64 = re.compile(A._B64_TO_SHELL, re.IGNORECASE)
    # Each with its literal prefilter, as unreadable_shapes and audit_command run them.
    new_rx = [(rx, lits) for (name, rx), lits in zip(A.UNREADABLE_SHAPES, A.SHAPE_PREFILTERS)
              if name in NEW_SHAPES] + [(b64, ("base64",))]
    hits: dict[str, list[str]] = {k: [] for k in KINDS}
    old_unread = new_unread = 0
    per_cmd: list[float] = []
    new_time = 0.0
    for cmd in f.commands:
        t = time.perf_counter()
        A.command_rule_matches(cmd)
        shapes = A.unreadable_shapes(cmd)
        per_cmd.append(time.perf_counter() - t)
        text = cmd[:A.MAX_SCAN_TOTAL]
        t = time.perf_counter()
        low = A._fold_lower(text)
        for rx, lits in new_rx:
            if lits is None or any(x in low for x in lits):
                rx.search(text)
        new_time += time.perf_counter() - t
        old_unread += any(s not in NEW_SHAPES for s in shapes)
        new_unread += bool(shapes)
        for s in shapes:
            if s in NEW_SHAPES:
                hits[s].append(cmd)
        if b64.search(text):
            hits[B64_RULE].append(cmd)
    for fl in f.flags:
        for cat in (A.RETRY_CATEGORY, A.OUTSIDE_ROOT_CATEGORY):
            if cat in fl["categories"]:
                hits[cat].append(fl["evidence"])
    return {"hits": hits, "old_unread": old_unread, "new_unread": new_unread,
            "per_cmd": per_cmd, "new_time": new_time}


def _pct(a: float, b: float) -> str:
    return f"{100.0 * a / b:.2f}%" if b else "n/a"


def report(m: dict, n: int, t_on: float, t_off: float) -> None:
    """Counts and rates only: nothing here can carry a command, path or host."""
    per = sorted(m["per_cmd"])
    total = sum(per)
    print(f"commands audited           {n:,}")
    print(f"unreadable, 0.7.0 shapes   {m['old_unread']:,} ({_pct(m['old_unread'], n)})")
    print(f"unreadable, 0.8.0 shapes   {m['new_unread']:,} ({_pct(m['new_unread'], n)})")
    print(f"unreadable added           {m['new_unread'] - m['old_unread']:,} "
          f"({_pct(m['new_unread'] - m['old_unread'], n)} of commands)")
    print("new hits by kind")
    for k in KINDS:
        print(f"  {k:<38} {len(m['hits'][k]):,}")
    if per:
        print(f"audit per command          median {statistics.median(per) * 1e6:.0f} us, "
              f"p95 {per[int(0.95 * (len(per) - 1))] * 1e6:.0f} us")
    print(f"new patterns               {_pct(m['new_time'], total)} of audit time (limit 10%)")
    print(f"scan, guardrails off / on  {t_off:.2f} s / {t_on:.2f} s "
          f"({_pct(t_on - t_off, t_off)} added)")


def write_sample(path: pathlib.Path, n: int, hits: dict, seed: int = 20261108) -> int:
    """Up to n random hits per kind, redacted, one per line: kind, a blank
    column for tp/fp, the text. O_EXCL: an existing file is never touched."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    rng = random.Random(seed)
    lines = 0
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# actualis fp-measure sample. Fill the second column: tp or fp.\n")
        for kind in KINDS:
            rows = hits[kind]
            for row in rng.sample(rows, min(n, len(rows))):
                fh.write(f"{kind}\t\t{A.redact(A.clean(row)).replace(chr(10), ' ')[:240]}\n")
                lines += 1
    return lines


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description="Count what the 0.8.0 audit changes add, counts only.")
    ap.add_argument("--days", type=int, metavar="N", help="only sessions from the last N days")
    ap.add_argument("--sample", type=int, default=0, metavar="N",
                    help="also write up to N redacted hits per kind to --out")
    ap.add_argument("--out", metavar="FILE", help="the sample file: new, mode 0600, never stdout")
    args = ap.parse_args(argv)
    out = None
    if args.out and not args.sample:
        print("fp-measure: --out needs --sample N", file=sys.stderr)
        return 2
    if args.sample:
        if not args.out or args.out == "-":
            print("fp-measure: --sample needs --out FILE; the sample never goes to stdout",
                  file=sys.stderr)
            return 2
        out = pathlib.Path(args.out).expanduser()
        if out.exists():
            print("fp-measure: --out names a file that already exists; it is never overwritten",
                  file=sys.stderr)
            return 2
    # A first scan warms the disk cache and is not timed; then each mode runs
    # twice, alternating, and the faster run counts, so neither mode pays for
    # a cold cache.
    scan(args.days, False)
    on, t_on = scan(args.days, True)
    _off, t_off = scan(args.days, False)
    t_on = min(t_on, scan(args.days, True)[1])
    t_off = min(t_off, scan(args.days, False)[1])
    m = measure(on)
    report(m, len(on.commands), t_on, t_off)
    if out is not None:
        try:
            lines = write_sample(out, args.sample, m["hits"])
        except FileExistsError:
            print("fp-measure: --out names a file that already exists; it is never overwritten",
                  file=sys.stderr)
            return 2
        print(f"sample written             {lines:,} line(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
