#!/usr/bin/env python3
"""Render every card from the invented demo fleet.

    python3 tools/make-card-images.py docs/img

The goldens in tests/goldens come from cards() here too, so the images in the
README and the cards the tests pin are the same cards.
"""
import contextlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def demo_fleet():
    af = _load("actualis", ROOT / "actualis.py")
    demo = _load("make_demo_fleet", ROOT / "tools" / "make-demo-fleet.py")
    with tempfile.TemporaryDirectory() as td:
        claude, copilot = Path(td) / "claude", Path(td) / "copilot"
        with contextlib.redirect_stdout(io.StringIO()):
            demo.main(str(claude), str(copilot))
        fleet = af.Fleet()
        fleet.scan([claude], None, None, progress=False)
        fleet.scan_copilot([copilot / "session-state"], None, None)
    return af, fleet


def cards():
    """(style, mode) -> draw ops, for all six cards."""
    af, fleet = demo_fleet()
    out = {}
    for mode in af.CARD_MODES:
        m = af.card_model(fleet, mode)
        out[("hero", mode)] = af.layout_hero(m)
        out[("terminal", mode)] = af.layout_terminal(m)
    return af, out


def main(dest: str) -> None:
    af, all_ops = cards()
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    for (style, mode), ops in all_ops.items():
        with (d / f"card-{style}-{mode}.svg").open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(af.svg_text(ops))
        (d / f"card-{style}-{mode}.png").write_bytes(af.png_bytes(ops))
    print(f"  {len(all_ops) * 2} files in {d}")


if __name__ == "__main__":
    main(sys.argv[1])
