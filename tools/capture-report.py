#!/usr/bin/env python3
"""Capture `actualis` output WITH its ANSI colour, by running it under a pty.

The tool emits colour only when stdout is a terminal, which a plain pipe is
not — so a naive subprocess capture loses every highlight, which is most of
what makes the report readable.

    python3 tools/capture-report.py /tmp/actualis-demo-fleet /tmp/ansi.txt
"""
import os, pty, sys, pathlib

def main(root: str, dest: str) -> None:
    buf = bytearray()
    def read(fd):
        data = os.read(fd, 65536)
        buf.extend(data)
        return data
    pty.spawn([sys.executable, "actualis.py", "--root", root, "--days", "90"], read)
    pathlib.Path(dest).write_bytes(bytes(buf))
    seqs = bytes(buf).count(b"\x1b[")
    print(f"  captured {len(buf)} bytes, {seqs} ANSI sequences")
    if seqs < 50:
        sys.exit("  no colour captured — check TTY detection")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
