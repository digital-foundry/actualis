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


if __name__ == "__main__":
    unittest.main()
