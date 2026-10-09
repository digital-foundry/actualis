"""network_reconciles: totals that must add up."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
sys.modules["actualis"] = af
spec.loader.exec_module(af)
af.SRC_TEXT = (ROOT / "actualis.py").read_text(encoding="utf-8")
af.SRC_PATH = ROOT / "actualis.py"

TS1 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
TS2 = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def rec(tid, command, mode="bypassPermissions", ts="2026-10-01T10:00:00Z"):
    return {"timestamp": ts, "type": "assistant", "uuid": "a" + tid, "sessionId": "s1",
            "permissionMode": mode,
            "message": {"id": "m" + tid, "role": "assistant", "content": [
                {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": command}}]}}




class TestReconcile(unittest.TestCase):
    def fleets(self):
        yield af.Fleet()
        f = af.Fleet()
        for k, mode in enumerate(("auto", "default", "copilot:prompted", "auto")):
            f.add_tool("p", "Bash", {"command": f"curl https://h{k}.io/x"}, TS1, mode)
        f.add_tool("p", "WebSearch", {"query": "q"}, TS1, "auto")
        f.add_tool("p", "Bash", {"command": "npm i left-pad && git clone https://github.com/o/r"}, TS1, "auto")
        yield f
        g = af.Fleet()
        for k in range(af.NETWORK_ITEMS_CAP + 5):
            g.add_tool("p", "Bash", {"command": f"curl https://h{k % 7}.io/{k}"}, TS1, "auto")
        yield g

    def test_ok_across_fleets_including_the_cap(self):
        for f in self.fleets():
            n = af.network_json(f)
            self.assertEqual(af.network_reconciles(n), [])
        self.assertTrue(n["items_truncated"])

    def test_problems_are_named(self):
        f = next(iter(list(self.fleets())[1:2]))
        good = af.network_json(f)
        for mutate, word in (
                (lambda n: n["totals"].__setitem__("items", n["totals"]["items"] + 1), "items"),
                (lambda n: n["by_kind"].__setitem__("fetch", 99), "by_kind"),
                (lambda n: n["totals"].__setitem__("failed", 99), "failed"),
                (lambda n: n["hosts"][0].__setitem__("count", 99), "hosts"),
                (lambda n: n["items"][0].__setitem__("approval", "maybe"), "approval"),
                (lambda n: n["items"][0].__setitem__("kind", "zap"), "kind"),
                (lambda n: n.__setitem__("items_truncated", True), "truncated")):
            n = json.loads(json.dumps(good))
            mutate(n)
            problems = af.network_reconciles(n)
            self.assertTrue(problems and any(word in p for p in problems), (word, problems))

    def test_render_shows_red_line_and_never_crashes(self):
        f = list(self.fleets())[1]
        real = af.network_json

        def bad(fleet, raw=False):
            n = real(fleet, raw)
            n["totals"]["items"] += 1
            return n
        buf = io.StringIO()
        with mock.patch.object(af, "network_json", bad), redirect_stdout(buf):
            af.render_network(f, af.C(False), top=12)
        self.assertIn("totals do not reconcile", buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            af.render_network(f, af.C(False), top=12)
        self.assertNotIn("reconcile", buf.getvalue())

    def test_self_check_has_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "t"
            (root / "-Users-x-p").mkdir(parents=True)
            (root / "-Users-x-p" / "s.jsonl").write_text(json.dumps(rec("t1", "curl https://a.io/x")) + "\n")
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {"HOME": tmp}), redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = af.self_check(af.C(False), None, str(root))
        self.assertIn("[pass]  network totals reconcile", buf.getvalue())
        self.assertEqual(code, 0)
