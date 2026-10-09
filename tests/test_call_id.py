"""call_id on network items, and the verify recipe."""
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




def two_files(root, calls_a, calls_b):
    d = Path(root) / "-Users-x-proj"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.jsonl").write_text("\n".join(json.dumps(r) for r in calls_a) + "\n")
    f = af.Fleet()
    f.suppressions = {}
    f.scan([Path(root)], None, None, progress=False)
    return f


class TestCallId(unittest.TestCase):
    def test_call_id_on_items_and_in_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = two_files(tmp, [rec("toolu_abc", "curl https://a.io/x")], [])
        [it] = af.network_json(f)["items"]
        self.assertEqual(it["call_id"], "toolu_abc")
        self.assertEqual(af.JSON_SCHEMA["network.items[].call_id"], "str|null")
        g = af.Fleet()
        g.add_tool("p", "Bash", {"command": "curl https://a.io"}, TS1, "auto")
        self.assertIsNone(af.network_json(g)["items"][0]["call_id"])

    def test_copilot_call_id(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://a.io"}, TS1, "copilot:auto",
                   session="s", call_id="tc_9", agent="copilot")
        self.assertEqual(af.network_json(f)["items"][0]["call_id"], "tc_9")

    def test_verify_recipe_documented(self):
        e = af.EXPLAIN["network"]
        t = "\n".join(e["formula"] + e["assumes"])
        self.assertIn(".items[0] | .session, .call_id", t)
        self.assertIn("grep -l '<call_id>' ~/.claude/projects/*/*.jsonl", t)
        for line in e["formula"] + e["assumes"]:
            self.assertLessEqual(len(line), 78, line)
        self.assertIn(".items[0] | .session, .call_id", (ROOT / "docs" / "json.md").read_text(encoding="utf-8"))
        self.assertIn("call_id", (ROOT / "docs" / "json.md").read_text(encoding="utf-8"))
