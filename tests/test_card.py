import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest
import zlib
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    _spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(_spec)
    sys.modules["actualis"] = af
    _spec.loader.exec_module(af)


def _claude_dir(td, records):
    p = Path(td) / "proj"
    p.mkdir()
    (p / "s.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n",
                               encoding="utf-8")
    return Path(td)


class TestPerCommandSupervision(unittest.TestCase):
    """The card says "% of shell commands". --share counted turns. A command is
    supervised or not by the mode in force when it ran."""

    TS = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)

    def test_one_definition_of_ungated(self):
        for k in ("auto", "bypassPermissions", "codex:never", "copilot:auto"):
            with self.subTest(k=k):
                self.assertTrue(af.is_ungated_mode(k))
        for k in ("default", "plan", "acceptEdits", "codex:on-request",
                  "copilot:prompted", "sandbox:workspace-write"):
            with self.subTest(k=k):
                self.assertFalse(af.is_ungated_mode(k))

    def test_a_command_inherits_the_mode_recorded_before_it(self):
        recs = [
            {"timestamp": "2026-09-01T12:00:00Z", "type": "user", "permissionMode": "default",
             "message": {"role": "user", "content": "x"}},
            {"timestamp": "2026-09-01T12:00:01Z", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}}]}},
            {"timestamp": "2026-09-01T12:00:02Z", "type": "user",
             "permissionMode": "bypassPermissions",
             "message": {"role": "user", "content": "y"}},
            {"timestamp": "2026-09-01T12:00:03Z", "message": {"content": [
                {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "ls"}}]}},
        ]
        f = af.Fleet()
        with tempfile.TemporaryDirectory() as td:
            f.scan([_claude_dir(td, recs)], None, None, progress=False)
        self.assertEqual(f.bash_by_day["2026-09-01"], 2)
        self.assertEqual(f.bash_moded_by_day["2026-09-01"], 2)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)

    def test_a_mode_set_before_the_window_still_applies(self):
        recs = [
            {"timestamp": "2026-08-01T00:00:00Z", "type": "user", "permissionMode": "auto",
             "message": {"role": "user", "content": "x"}},
            {"timestamp": "2026-09-01T12:00:00Z", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}}]}},
        ]
        f = af.Fleet()
        since = datetime(2026, 8, 15, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            f.scan([_claude_dir(td, recs)], since, None, progress=False)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)
        self.assertNotIn("auto", f.permission_modes, "the out-of-window turn is not counted")

    def test_a_command_with_no_recorded_mode_is_in_neither_bucket(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, self.TS)
        self.assertEqual(f.bash_by_day["2026-09-01"], 1)
        self.assertEqual(f.bash_moded_by_day["2026-09-01"], 0)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 0)

    def test_codex_commands_carry_the_turn_policy(self):
        lines = [
            {"timestamp": "2026-09-01T12:00:00Z", "type": "turn_context",
             "payload": {"cwd": "/x/proj", "model": "gpt-5.2-codex",
                         "approval_policy": "never"}},
            {"timestamp": "2026-09-01T12:00:01Z", "type": "response_item",
             "payload": {"type": "function_call", "name": "shell_command",
                         "arguments": json.dumps({"command": "ls"})}},
        ]
        f = af.Fleet()
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "rollout-1.jsonl").write_text(
                "\n".join(json.dumps(r) for r in lines) + "\n", encoding="utf-8")
            f.scan_codex([Path(td)], None, None)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)

    def test_share_uses_the_same_definition(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, self.TS)
        f.permission_modes.update({"codex:never": 1, "default": 1})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        self.assertIn("50% of turns ran unsupervised", buf.getvalue())

    def test_mcp_fleet_summary_agrees_with_share(self):
        f = af.Fleet()
        f.permission_modes.update({"codex:never": 1, "default": 1})

        class Stub:
            def fleet(self, days, project):
                return f

        out = af._mcp_call("fleet_summary", {}, Stub())
        self.assertEqual(out["unsupervised_pct"], 50.0)

    def test_agents_seen(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1}, self.TS)
        f.add_codex_session("p", "gpt-5.2-codex", {"output_tokens": 1}, self.TS)
        self.assertEqual(f.agents_seen, {"claude-code", "codex"})


class TestCommandCategory(unittest.TestCase):
    """Four words is the only shape of a command a card shows. A program name
    can identify (`./acme-deploy`); a fixed vocabulary cannot."""

    CASES = {
        "git status": "git", "cd app && git push": "git",
        "pytest -q": "test", "python -m pytest tests": "test",
        "python3 -m unittest discover": "test", "npm test -- --run": "test",
        "npm run test:unit": "test", "go test ./...": "test", "cargo test": "test",
        "make test": "test",
        "npm i left-pad": "install", "pip install requests": "install",
        "uv pip install x": "install", "uv add httpx": "install",
        "brew install gh": "install", "sudo apt-get install jq": "install",
        "npm run build": "other", "ls -la": "other", "pip list": "other",
        "./acme-deploy --prod": "other", "": "other",
    }

    def test_categories(self):
        for cmd, want in self.CASES.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(af.command_category(cmd), want)

    def test_counted_at_ingest(self):
        f = af.Fleet()
        for cmd in ("git status", "pytest", "ls"):
            f.add_tool("p", "Bash", {"command": cmd}, None)
        self.assertEqual(f.bash_categories, {"git": 1, "test": 1, "other": 1})


D1 = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)


def _day(n):
    return D1.replace(day=n)


def _busy_fleet():
    """Five days of Claude activity: 4 commands a day, 3 of them in auto."""
    f = af.Fleet()
    for d in range(1, 6):
        f.add_usage("p", "claude-opus-5", {"output_tokens": 100_000,
                                           "cache_read_input_tokens": 1_000_000}, _day(d))
        for i in range(4):
            f.add_tool("p", "Bash", {"command": ["git status", "pytest", "npm i x", "ls"][i]},
                       _day(d), "auto" if i < 3 else "default")
    return f


class TestCardModel(unittest.TestCase):

    def test_supervision(self):
        m = af.card_model(_busy_fleet(), "supervision")
        self.assertEqual(m["hero"], "75%")
        self.assertEqual(m["days"], 5)
        self.assertEqual(m["label"], "ACTUALIS · LAST 5 DAYS")
        self.assertEqual([s[1] for s in m["stats"]], ["commands", "refused", "agents"])
        self.assertEqual(m["stats"][0][0], "20")
        self.assertEqual([b[0] for b in m["bars"]], ["auto", "you", "refused"])
        self.assertEqual(m["series"], [75.0] * 5)
        self.assertTrue(m["trend"])
        self.assertTrue(m["share"].startswith("75% of my coding agents' shell commands"))
        self.assertTrue(m["share"].endswith("uv tool install actualis"))

    def test_volume(self):
        m = af.card_model(_busy_fleet(), "volume")
        self.assertEqual(m["hero"], "20")
        self.assertEqual(dict((b[0], b[1]) for b in m["bars"]),
                         {"git": 5, "test": 5, "install": 5, "other": 5})
        self.assertEqual(m["stats"][0][1], "of tool calls")

    def test_cost(self):
        f = _busy_fleet()
        m = af.card_model(f, "cost")
        self.assertEqual(m["hero"], f"${f.total_cost:,.0f}")
        self.assertEqual(m["caption"], "at API list price, last 5 days")
        self.assertEqual([b[0] for b in m["bars"]], ["claude-opus-5"])
        self.assertEqual(len(m["stats"]), 3, "no premium row without Copilot")

    def test_no_shell_commands_refuses_supervision_and_volume(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1}, D1)
        for mode in ("supervision", "volume"):
            with self.subTest(mode=mode):
                with self.assertRaises(af.CardError) as cm:
                    af.card_model(f, mode)
                self.assertEqual(str(cm.exception),
                                 "no shell commands in window — try --days or --card cost")
        af.card_model(f, "cost")   # still drawable

    def test_no_priced_usage_is_a_dash_never_zero(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, D1, "auto")
        m = af.card_model(f, "cost")
        self.assertEqual(m["hero"], "—")
        self.assertEqual(m["caption"], "no priced usage in window")
        for value, _label in m["stats"]:
            self.assertNotIn("$", value)

    def test_premium_row_only_with_copilot(self):
        f = _busy_fleet()
        f.premium_requests_by_agent["copilot"] += 3.96
        m = af.card_model(f, "cost")
        self.assertEqual(m["stats"][3], ("3.96", "premium requests"))
        self.assertNotIn("$", m["stats"][3][0])

    def test_fewer_than_three_active_days_has_no_trend(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, _day(1), "auto")
        f.add_tool("p", "Bash", {"command": "ls"}, _day(2), "auto")
        self.assertFalse(af.card_model(f, "volume")["trend"])

    def test_unknown_mode_everywhere_is_a_dash(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, D1)
        m = af.card_model(f, "supervision")
        self.assertEqual(m["hero"], "—")

    def test_model_names_are_catalog_names_or_custom(self):
        self.assertEqual(af.card_model_name("claude-opus-5"), "claude-opus-5")
        for private in ("ft:leaktest-model", "ft:gpt-5.2-acme-internal", "gpt-5-mini"):
            with self.subTest(private=private):
                self.assertEqual(af.card_model_name(private), "custom")

    def test_custom_models_are_merged(self):
        f = af.Fleet()
        f.add_usage("p", "ft:one", {"output_tokens": 1_000_000}, D1)
        f.add_usage("p", "ft:two", {"output_tokens": 1_000_000}, D1)
        bars = af.card_model(f, "cost")["bars"]
        self.assertEqual([b[0] for b in bars], ["custom"])

    def test_window_with_days_ends_today(self):
        w = af.card_window(af.Fleet(), 3, date(2026, 9, 10))
        self.assertEqual(w, ["2026-09-08", "2026-09-09", "2026-09-10"])


W, H = 1200, 630


def _paint(rects_by_colour, bg="0d1117"):
    """An independent painter, for checking the writers against each other."""
    buf = bytearray(bytes.fromhex(bg) * (W * H))
    for colour, rects in rects_by_colour:
        px = bytes.fromhex(colour.lstrip("#"))
        for x, y, w, h in rects:
            x0, y0, x1, y1 = max(x, 0), max(y, 0), min(x + w, W), min(y + h, H)
            for yy in range(y0, y1):
                o = (yy * W + x0) * 3
                buf[o:o + (x1 - x0) * 3] = px * max(x1 - x0, 0)
    return buf


def _png_pixels(data):
    """Check every chunk's CRC and the IHDR, and return the unfiltered pixels."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, ihdr = 8, b"", None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        tag, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        assert crc == zlib.crc32(tag + body) & 0xFFFFFFFF, f"bad CRC on {tag!r}"
        if tag == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif tag == b"IDAT":
            idat += body
        pos += 12 + length
    assert ihdr == (W, H, 8, 2, 0, 0, 0), ihdr
    raw, stride, out = zlib.decompress(idat), W * 3, bytearray()
    for y in range(H):
        row = raw[y * (stride + 1):(y + 1) * (stride + 1)]
        assert row[0] == 0, "filter type 0 on every scanline"
        out += row[1:]
    return out


def _ops():
    return [af.Rect(0, 0, 10, 10, "#f0883e"),
            af.Text(20, 20, 2, "#e6edf3", "A%·█"),
            af.Polyline(((100, 100), (200, 150), (300, 120)), "#f0883e", 4),
            af.Rect(1190, 620, 50, 50, "#8b949e")]        # clipped at the corner


class TestCardWriters(unittest.TestCase):

    def test_font_covers_every_glyph_a_card_draws(self):
        for ch in [chr(c) for c in range(32, 127)] + list("·▁▂▃▄▅▆▇█░─—"):
            with self.subTest(ch=ch):
                self.assertRegex(af.CARD_FONT[ch], r"^[0-9a-f]{32}$")
        self.assertEqual(af.CARD_FONT["A"][4:6], "7c", "Spleen 'A', row 2")

    def test_unknown_glyph_falls_back(self):
        q = af.op_rects(af.Text(0, 0, 1, "#ffffff", "?"))
        self.assertEqual(af.op_rects(af.Text(0, 0, 1, "#ffffff", "漢")), q)

    def test_text_scales_by_integer_cells(self):
        one = af.op_rects(af.Text(0, 0, 1, "#ffffff", "A"))
        three = af.op_rects(af.Text(0, 0, 3, "#ffffff", "A"))
        self.assertEqual(three, [(x * 3, y * 3, w * 3, h * 3) for x, y, w, h in one])

    def test_png_is_valid_and_matches_the_rasterizer(self):
        ops = _ops()
        self.assertEqual(_png_pixels(af.png_bytes(ops)), af.rasterize(ops))

    def test_svg_and_png_agree_pixel_for_pixel(self):
        ops = _ops()
        svg = af.svg_text(ops)
        self.assertNotIn("<text", svg)
        painted = []
        for colour, d in re.findall(r'<path fill="(#[0-9a-f]{6})" d="([^"]*)"/>', svg):
            rects = [tuple(int(v) for v in r) for r in
                     re.findall(r"M(-?\d+) (-?\d+)h(\d+)v(\d+)h-\d+z", d)]
            painted.append((colour, rects))
        self.assertEqual(_paint(painted), af.rasterize(ops))

    def test_polyline_is_contiguous(self):
        rects = af.op_rects(af.Polyline(((0, 0), (40, 7)), "#ffffff", 1))
        xs = sorted({x + dx for x, y, w, h in rects for dx in range(w)})
        self.assertEqual(xs, list(range(41)))


def _extent(op):
    """Bounding box of an op's pixels, or None when it draws nothing."""
    rects = af.op_rects(op)
    if not rects:
        return None
    return (min(r[0] for r in rects), min(r[1] for r in rects),
            max(r[0] + r[2] for r in rects), max(r[1] + r[3] for r in rects))


def _extreme_model():
    return {"mode": "cost", "days": 365, "label": "ACTUALIS · LAST 365 DAYS",
            "header": "COST", "hero": "$12,345,678", "hero_label": "at list price",
            "caption": "at API list price, last 365 days",
            "stats": [("$123,456", "per active day"), ("$9,999,999", "cache saved"),
                      ("3", "agents"), ("12,345.67", "premium requests")],
            "bars": [("claude-sonnet-4-5", 9e6, "$9,000,000"), ("custom", 1.0, "$1"),
                     ("gpt-5.2", 0.0, "$0")],
            "series": [float(i % 17) for i in range(365)], "series_max": 16.0,
            "trend": True, "share": "x"}


class TestCardLayouts(unittest.TestCase):

    def _all(self):
        models = [af.card_model(_busy_fleet(), mode) for mode in af.CARD_MODES]
        models.append(_extreme_model())
        for m in models:
            for name, layout in (("hero", af.layout_hero), ("terminal", af.layout_terminal)):
                yield name, m, layout(m)

    def test_every_op_is_inside_the_canvas(self):
        for name, m, ops in self._all():
            for op in ops:
                box = _extent(op)
                if box is None:
                    continue
                with self.subTest(style=name, mode=m["mode"], op=op):
                    x0, y0, x1, y1 = box
                    self.assertGreaterEqual(min(x0, y0), 0)
                    self.assertLessEqual(x1, 1200)
                    self.assertLessEqual(y1, 630)

    def test_extreme_values_stay_inside_their_columns(self):
        ops = af.layout_hero(_extreme_model())
        left = [op for op in ops if isinstance(op, af.Text) and op.x < af.HERO_RULE_X]
        for op in left:
            with self.subTest(op=op):
                self.assertLessEqual(op.x + len(op.text) * 8 * op.scale, af.HERO_RULE_X - 16)
        hero = next(op for op in ops if isinstance(op, af.Text) and op.text == "$12,345,678")
        self.assertLess(hero.scale, 10)

    def test_long_windows_are_bucketed(self):
        ops = af.layout_terminal(_extreme_model())
        spark = [op for op in ops if isinstance(op, af.Text)
                 and op.x == af.TERM_X + 5 * af.CELL_W and op.y > af.TERM_Y + 4 * af.CELL_H]
        self.assertEqual(len(spark), 1)
        self.assertLessEqual(len(spark[0].text), 40)
        last_bar = max(op.y for op in ops if isinstance(op, af.Text)
                       and op.x >= af.TERM_X + 12 * af.CELL_W and set(op.text) <= {"█", "░"})
        self.assertGreaterEqual(spark[0].y, last_bar + 2 * af.CELL_H)
        footer = next(op for op in ops if isinstance(op, af.Text) and op.text == af.CARD_INSTALL)
        self.assertGreaterEqual(footer.y, spark[0].y + af.CELL_H)
        line = next(op for op in af.layout_hero(_extreme_model()) if isinstance(op, af.Polyline))
        for x, y in line.points:
            self.assertTrue(64 <= x <= 832 and 416 <= y <= 536, (x, y))

    def test_no_trend_says_so(self):
        m = dict(_extreme_model(), trend=False)
        for layout in (af.layout_hero, af.layout_terminal):
            with self.subTest(layout=layout.__name__):
                texts = [op.text for op in layout(m) if isinstance(op, af.Text)]
                self.assertIn("not enough days for a trend", texts)

    def test_terminal_bars_are_28_cells(self):
        ops = af.layout_terminal(af.card_model(_busy_fleet(), "volume"))
        bar_rows = {}
        for op in ops:
            # The sparkline starts at column 5, so x excludes it.
            if (isinstance(op, af.Text) and set(op.text) <= {"█", "░"}
                    and op.x >= af.TERM_X + 12 * af.CELL_W):
                bar_rows[op.y] = bar_rows.get(op.y, 0) + len(op.text)
        self.assertEqual(sorted(bar_rows.values()), [28, 28, 28, 28])

    def test_footer_on_both(self):
        for name, m, ops in self._all():
            with self.subTest(style=name):
                self.assertIn("uv tool install actualis",
                              [op.text for op in ops if isinstance(op, af.Text)])


GOLDENS = ROOT / "tests" / "goldens"
UPDATE = os.environ.get("ACTUALIS_UPDATE_GOLDENS") == "1"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402


def _tool(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCardFiles(unittest.TestCase):

    def test_first_card_has_no_suffix(self):
        with tempfile.TemporaryDirectory() as td:
            svg, png = af.card_paths(Path(td))
        self.assertEqual((svg.name, png.name), ("actualis-card.svg", "actualis-card.png"))

    def test_one_existing_file_bumps_both(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "actualis-card.png").write_bytes(b"mine")
            svg, png = af.card_paths(Path(td))
            self.assertEqual((svg.name, png.name),
                             ("actualis-card-2.svg", "actualis-card-2.png"))
            self.assertEqual((Path(td) / "actualis-card.png").read_bytes(), b"mine")

    def test_write_card_never_overwrites(self):
        m = af.card_model(_busy_fleet(), "volume")
        with tempfile.TemporaryDirectory() as td:
            a = af.write_card(m, "hero", Path(td))
            b = af.write_card(m, "hero", Path(td))
            self.assertNotEqual(a, b)
            self.assertEqual(len(list(Path(td).iterdir())), 4)

    def test_failed_png_leaves_no_half_card(self):
        m = af.card_model(_busy_fleet(), "volume")
        real = af.png_bytes

        def boom(ops):
            raise RuntimeError("png")
        af.png_bytes = boom
        try:
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(RuntimeError):
                    af.write_card(m, "hero", Path(td))
                self.assertEqual(list(Path(td).iterdir()), [])
        finally:
            af.png_bytes = real


class TestCardCli(unittest.TestCase):

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = af.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_card_writes_two_files_and_a_caption(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            fx.write_sessions(home / ".copilot" / "session-state")
            rc, stdout, _ = self._run(["--card", "--out", out])
            names = sorted(p.name for p in Path(out).iterdir())
        self.assertEqual(rc, af.EXIT_OK)
        self.assertEqual(names, ["actualis-card.png", "actualis-card.svg"])
        self.assertIn("uv tool install actualis", stdout)
        self.assertIn("actualis-card.svg", stdout)

    def test_terminal_style_and_mode(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            fx.write_sessions(home / ".copilot" / "session-state")
            rc, _, _ = self._run(["--card", "cost", "--style", "terminal", "--out", out])
        self.assertEqual(rc, af.EXIT_OK)

    def test_out_must_be_a_directory(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as td:
            fx.write_sessions(home / ".copilot" / "session-state")
            target = Path(td) / "file.txt"
            target.write_text("x")
            rc, _, err = self._run(["--card", "--out", str(target)])
            self.assertEqual(sorted(p.name for p in Path(td).iterdir()), ["file.txt"])
        self.assertEqual(rc, af.EXIT_CANNOT_RUN)
        self.assertIn("is not a directory", err)

    def test_no_commands_exits_nonzero_and_writes_nothing(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            p = home / ".claude" / "projects" / "proj"
            p.mkdir(parents=True)
            (p / "s.jsonl").write_text(json.dumps(
                {"timestamp": "2026-09-01T00:00:00Z",
                 "message": {"id": "m1", "model": "claude-opus-5",
                             "usage": {"output_tokens": 10}}}) + "\n")
            rc, _, err = self._run(["--card", "--out", out])
            self.assertEqual(list(Path(out).iterdir()), [])
        self.assertEqual(rc, af.EXIT_CANNOT_RUN)
        self.assertIn("no shell commands in window — try --days or --card cost", err)

    def test_card_and_json_conflict(self):
        with self.assertRaises(SystemExit):
            self._run(["--card", "--json"])

    def test_style_without_card_is_an_error(self):
        with self.assertRaises(SystemExit):
            self._run(["--style", "terminal"])

    def test_card_with_another_mode_is_an_error(self):
        for argv, flag in ((["--card", "--fail-on", "high"], "--fail-on"),
                           (["--card", "--share"], "--share")):
            with self.subTest(flag=flag):
                err = io.StringIO()
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
                    af.main(argv)
                self.assertIn("cannot be combined with " + flag, err.getvalue())

    def test_card_with_an_early_exit_flag_is_an_error(self):
        for argv, flag in ((["--card", "--self-check"], "--self-check"),
                           (["--card", "--explain"], "--explain"),
                           (["--card", "--agents"], "--agents"),
                           (["--card", "--suppressions"], "--suppressions"),
                           (["--card", "--suppress", "abcd1234"], "--suppress"),
                           (["--card", "--completions", "bash"], "--completions"),
                           (["--card", "--service", "systemd"], "--service")):
            with self.subTest(flag=flag):
                err = io.StringIO()
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(err), \
                        contextlib.redirect_stdout(io.StringIO()):
                    af.main(argv)
                self.assertIn("cannot be combined with " + flag, err.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_unwritable_out_exits_cleanly(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as d:
            fx.write_sessions(home / ".copilot" / "session-state")
            os.chmod(d, 0o500)
            try:
                rc, _, err = self._run(["--card", "--out", d])
            finally:
                os.chmod(d, 0o700)
        self.assertEqual(rc, af.EXIT_CANNOT_RUN)
        self.assertIn("cannot write the card", err)

    def test_self_check_names_the_card_write_path(self):
        with fx.isolated_home():
            _, stdout, _ = self._run(["--self-check"])
        self.assertIn("actualis-card", stdout)
        self.assertIn("--card", stdout)


class TestCardGoldens(unittest.TestCase):
    """Cost goldens change when the price table does. Regenerate deliberately:
    ACTUALIS_UPDATE_GOLDENS=1 python3 -m unittest discover -s tests -p test_card.py"""

    @classmethod
    def setUpClass(cls):
        cls.mod, cls.cards = _tool("make_card_images", "make-card-images.py").cards()

    def test_svg_goldens(self):
        self.assertEqual(len(self.cards), 6)
        for (style, mode), ops in self.cards.items():
            with self.subTest(style=style, mode=mode):
                got = self.mod.svg_text(ops)
                path = GOLDENS / f"card-{style}-{mode}.svg"
                if UPDATE:
                    GOLDENS.mkdir(exist_ok=True)
                    with path.open("w", encoding="utf-8", newline="\n") as fh:
                        fh.write(got)
                self.assertEqual(path.read_text(encoding="utf-8").replace("\r\n", "\n"), got)

    def test_png_pixels_golden(self):
        digest = hashlib.sha256(bytes(self.mod.rasterize(self.cards[("hero", "supervision")]))).hexdigest()
        path = GOLDENS / "card-hero-supervision.pixels.sha256"
        if UPDATE:
            GOLDENS.mkdir(exist_ok=True)
            with path.open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(digest + "\n")
        self.assertEqual(path.read_text(encoding="utf-8").strip(), digest)


class TestCardLeaksNothing(unittest.TestCase):
    """The card is made to be posted. The only thing that matters about it is
    that nothing identifying can reach it -- in the model, the SVG, the PNG or
    the caption line printed beside them."""

    NEEDLES = ["ACME-CLASSIFIED-MERGER", "feat/9999-project-tigerclaw", "9999",
               "/Users/someone/private/repo", "internal-db.corp.example.com",
               "hunter2pass", "sk_live_leakcanary1234567", "ft:leaktest-model",
               "acme-deploy"]

    def _fleet(self):
        f = af.Fleet()
        ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for d in range(1, 6):
            t = ts.replace(day=d)
            f.add_usage("ACME-CLASSIFIED-MERGER", "ft:leaktest-model",
                        {"output_tokens": 1_000_000}, t, "feat/9999-project-tigerclaw")
            f.add_tool("ACME-CLASSIFIED-MERGER", "Bash",
                       {"command": "psql postgresql://u:hunter2pass@internal-db.corp.example.com/x "
                                   "&& export K=sk_live_leakcanary1234567 "
                                   "&& cat /Users/someone/private/repo/.env"}, t, "auto")
            f.add_tool("ACME-CLASSIFIED-MERGER", "Bash", {"command": "./acme-deploy --prod"},
                       t, "default")
        return f

    def _surfaces(self, f):
        for mode in af.CARD_MODES:
            m = af.card_model(f, mode)
            yield mode, "model", json.dumps(m, ensure_ascii=False)
            yield mode, "share", m["share"]
            for style, layout in (("hero", af.layout_hero), ("terminal", af.layout_terminal)):
                ops = layout(m)
                yield mode, f"{style}.ops", repr(ops)
                yield mode, f"{style}.svg", af.svg_text(ops)
                yield mode, f"{style}.png-raw", af.png_bytes(ops).decode("latin-1")
                yield mode, f"{style}.png", bytes(_png_pixels(af.png_bytes(ops))).decode("latin-1")

    def test_no_identifying_string_reaches_any_surface(self):
        canary = af.Fleet()
        canary.add_tool("p", "Bash", {"command": "export K=sk_live_leakcanary1234567"},
                        datetime(2026, 8, 1, tzinfo=timezone.utc), "auto")
        self.assertTrue(canary.secrets, "the sk_live canary itself must be recognised as a secret")
        f = self._fleet()
        fps = list(f.secrets)
        self.assertTrue(fps, "the canary must have been detected for this test to mean anything")
        for mode, surface, text in self._surfaces(f):
            for needle in self.NEEDLES + fps:
                with self.subTest(mode=mode, surface=surface, needle=needle):
                    self.assertNotIn(needle, text)

    def test_network_data_never_reaches_the_card(self):
        f = self._fleet()
        ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
        f.add_tool("leaky-project", "Bash", {"command": "curl https://leaky-host.example/secret-path"},
                   ts, "auto")
        f.add_tool("leaky-project", "WebFetch", {"url": "https://other-leak.example/x"}, ts, "auto",
                   why="Fetching the leaky-why-sentence now.", prompt="leaky-prompt-words please",
                   where={"root": "/leaky-root", "file": "leaky-file.jsonl", "line": 7})
        for mode, surface, text in self._surfaces(f):
            for needle in ("leaky-host", "secret-path", "other-leak", "leaky-project",
                       "leaky-why", "leaky-prompt", "leaky-root", "leaky-file"):
                with self.subTest(mode=mode, surface=surface, needle=needle):
                    self.assertNotIn(needle, text)

    def test_private_model_is_shown_as_custom(self):
        m = af.card_model(self._fleet(), "cost")
        self.assertEqual([b[0] for b in m["bars"]], ["custom"])

    def test_end_to_end_through_main(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            p = home / ".claude" / "projects" / "-Users-someone-private-ACME-CLASSIFIED-MERGER"
            p.mkdir(parents=True)
            cmds = ["psql postgresql://u:hunter2pass@internal-db.corp.example.com/x",
                    "cat /Users/someone/private/repo/.env",
                    "export K=sk_live_leakcanary1234567",
                    "./acme-deploy --prod",
                    "export K=sk_live_leakcanary1234567 && ./acme-deploy --prod"]
            fps = sorted({fp for c in cmds for _p, _k, fp in af.classify_secrets(c)})
            self.assertTrue(fps, "the seeded commands must contain a detectable secret")
            needles = self.NEEDLES + fps
            recs = [{"timestamp": f"2026-09-0{d}T10:00:00Z", "permissionMode": "auto",
                     "gitBranch": "feat/9999-project-tigerclaw",
                     "message": {"id": f"m{d}", "model": "ft:leaktest-model",
                                 "usage": {"output_tokens": 1_000_000},
                                 "content": [{"type": "tool_use", "id": f"t{d}", "name": "Bash",
                                              "input": {"command": cmds[d - 1]}}]}}
                    for d in range(1, 6)]
            (p / "s.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
            for mode in af.CARD_MODES:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(af.main(["--card", mode, "--out", out]), af.EXIT_OK)
                self.assertIn("uv tool install actualis", buf.getvalue())
                for needle in needles:
                    with self.subTest(mode=mode, needle=needle):
                        self.assertNotIn(needle, buf.getvalue().replace(out, ""))
            files = list(Path(out).iterdir())
            self.assertEqual(len(files), 6)
            for written in files:
                body = written.read_bytes().decode("latin-1")
                for needle in needles:
                    with self.subTest(file=written.name, needle=needle):
                        self.assertNotIn(needle, body)

    def test_share_leak_test_still_holds_with_copilot_in_the_fleet(self):
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            f = af.Fleet()
            f.scan_copilot([state], None, None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        for needle in ("orbital-ledger", "ORB-412", fx.CANARY, fx.A, "quarry-cli"):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
