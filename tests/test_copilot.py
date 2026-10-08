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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402


def _fleet(state, since=None, project=None):
    f = af.Fleet()
    f.scan_copilot([state], since, project)
    return f


class TestCopilotCost(unittest.TestCase):
    """Copilot's inputTokens already include cache reads and writes, for every
    provider. Treating them as Anthropic-style additions double-bills."""

    def test_input_includes_cache_so_fresh_is_the_remainder(self):
        r = af.rate_for("claude-haiku-4-5")
        u = fx.USAGE_A["claude-haiku-4.5"]
        expected = (0.1 * r.input + 0.6 * r.input * af.CACHE_READ_MULT
                    + 0.3 * r.input * af.CACHE_WRITE_ASSUMED_MULT + 0.1 * r.output)
        self.assertAlmostEqual(af.copilot_session_cost(u, "claude-haiku-4-5"), expected, places=9)

    def test_reasoning_is_a_subset_not_an_addition(self):
        u = dict(fx.USAGE_A["gpt-5-mini"])
        a = af.copilot_session_cost(u, "gpt-5.2")
        u["reasoningTokens"] = 9_999_999
        self.assertEqual(a, af.copilot_session_cost(u, "gpt-5.2"))

    def test_dotted_claude_ids_get_the_published_rate(self):
        self.assertEqual(af.copilot_model("claude-haiku-4.5"), "claude-haiku-4-5")
        self.assertEqual(af.rate_for(af.copilot_model("claude-haiku-4.5")).tier, af.VENDOR)
        self.assertEqual(af.copilot_model("gpt-5.2"), "gpt-5.2")


class TestCopilotReader(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.state = fx.write_sessions(Path(self._td.name) / "session-state")

    def tearDown(self):
        self._td.cleanup()

    def test_cost_is_counted_once_per_model_per_session(self):
        f = _fleet(self.state)
        want = sum(af.copilot_session_cost(u, af.copilot_model(m))
                   for usage in (fx.USAGE_A, fx.USAGE_D) for m, u in usage.items())
        self.assertAlmostEqual(f.cost_by_agent["copilot"], want, places=9)
        self.assertEqual(f.units_by_agent["copilot"], 2)          # A and D
        self.assertEqual(f.msgs_by_model["claude-haiku-4-5"], 1)

    def test_a_session_with_no_shutdown_is_unpriced_not_zero(self):
        f = _fleet(self.state, project="atlas")
        self.assertEqual(f.copilot_unpriced, 1)
        self.assertNotIn("copilot", f.cost_by_agent)
        self.assertEqual(f.bash_total, 1, "its commands still count")

    def test_supervision(self):
        f = _fleet(self.state, project="orbital")
        self.assertEqual(f.permission_modes["copilot:auto"], 2)
        self.assertEqual(f.permission_modes["copilot:prompted"], 1)
        self.assertEqual(f.unsupervised_by_day["2026-09-02"], 2)
        self.assertEqual(f.bash_moded_by_day["2026-09-02"], 3)

    def test_the_refusal_is_recorded_and_joined(self):
        f = _fleet(self.state, project="mesa")
        self.assertEqual(f.denials["copilot:denied-by-user"], 1)
        self.assertEqual(f.refusals, 1)
        self.assertEqual(f.refusals_joined, 1)
        self.assertEqual(f.refusal_program["copilot:denied-by-user"]["rm"], 1)

    def test_approved_is_not_a_refusal(self):
        self.assertEqual(_fleet(self.state, project="orbital").refusals, 0)

    def test_credential_is_grouped_and_never_output(self):
        f = _fleet(self.state, project="quarry")
        self.assertEqual(len(f.secrets), 1)
        self.assertNotIn(fx.CANARY, json.dumps(af.to_json(f)))

    def test_project_branch_and_ticket_come_from_session_context(self):
        f = _fleet(self.state, project="orbital")
        self.assertIn("ORB-412", f.cost_by_ticket)
        self.assertTrue(any("orbital-ledger" in p for p in f.cost_by_project))

    def test_premium_requests_are_fractional_and_never_dollars(self):
        f = _fleet(self.state)
        self.assertAlmostEqual(f.premium_requests_by_agent["copilot"], 1.33, places=9)

    def test_subagent_is_counted(self):
        self.assertEqual(_fleet(self.state, project="orbital").sub_calls, 1)

    def test_window_excludes_an_older_shutdown(self):
        f = _fleet(self.state, since=datetime(2026, 9, 5, tzinfo=timezone.utc))
        self.assertEqual(f.units_by_agent["copilot"], 1)          # D only

    def test_malformed_sessions_are_skipped_not_fatal(self):
        (self.state / "no-events-here").mkdir()
        bad = self.state / "bbbbbbbb-0000-4000-8000-000000000009"
        bad.mkdir()
        (bad / "events.jsonl").write_text(
            '{"type":"session.start","data":"not an object"}\n'
            '{"type":"tool.execution_start","data":{"toolName":"bash",'
            '"arguments":{"command":"echo hi"}},"timestamp":"2026-09-06T10:00:00Z"}\n'
            '{"type":"tool.execution_start","data":{"toolName":"ba',   # truncated
            encoding="utf-8")
        f = _fleet(self.state, project="copilot")
        self.assertEqual(f.permission_modes["copilot:auto"], 1, "no toolCallId -> auto")


class TestCopilotWiring(unittest.TestCase):

    def test_roots_honour_copilot_home(self):
        with fx.isolated_home() as home:
            self.assertEqual(af.copilot_roots(), [])
            (home / ".copilot" / "session-state").mkdir(parents=True)
            self.assertEqual(af.copilot_roots(), [home / ".copilot" / "session-state"])
            other = home / "elsewhere"
            (other / "session-state").mkdir(parents=True)
            os.environ["COPILOT_HOME"] = str(other)
            self.assertEqual(af.copilot_roots(), [other / "session-state"])

    def test_agent_copilot_reads_only_copilot(self):
        with fx.isolated_home() as home:
            fx.write_sessions(home / ".copilot" / "session-state")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = af.main(["--agent", "copilot", "--json"])
        self.assertEqual(rc, af.EXIT_OK)
        want = sum(af.copilot_session_cost(u, af.copilot_model(m))
                   for usage in (fx.USAGE_A, fx.USAGE_D) for m, u in usage.items())
        self.assertAlmostEqual(json.loads(buf.getvalue())["cost_usd"], want, places=2)

    def test_no_transcripts_message_names_copilot(self):
        with fx.isolated_home():
            msg = af.no_transcripts_message()
        self.assertIn("Copilot CLI", msg)
        self.assertIn("COPILOT_HOME", msg)

    def test_agents_row_is_present(self):
        self.assertIn("copilot", [cmd for _, cmd in af.AGENT_COMMANDS])

    def test_watch_reads_copilot_commands(self):
        rec = {"type": "tool.execution_start",
               "data": {"toolName": "bash", "arguments": {"command": "ls"}}}
        self.assertEqual(af._commands_in(rec), ["ls"])
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            files = af._jsonl_files([], [], [state])
        self.assertEqual(len(files), 4)

    def test_self_check_reads_copilot_and_leaves_it_unchanged(self):
        with fx.isolated_home() as home:
            state = fx.write_sessions(home / ".copilot" / "session-state")
            before = {p: af._digest_file(p) for p in state.rglob("events.jsonl")}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = af.self_check(af.C(False), None, None)
            after = {p: af._digest_file(p) for p in state.rglob("events.jsonl")}
        self.assertEqual(rc, af.EXIT_OK)
        self.assertIn(str(state), buf.getvalue())
        self.assertEqual(before, after)

    def test_mcp_fleet_summary_sees_copilot(self):
        with fx.isolated_home() as home:
            fx.write_sessions(home / ".copilot" / "session-state")
            out = af._mcp_call("fleet_summary", {}, af._MCPCache())
        self.assertGreater(out["cost_usd_list_price"], 0)
        self.assertIn("copilot", out["by_agent"])


class TestCopilotReplay(unittest.TestCase):

    def test_replay_finds_the_in_session_commands(self):
        with fx.isolated_home() as home:
            state = fx.write_sessions(home / ".copilot" / "session-state")
            fleet = _fleet(state, project="quarry")
            fp = next(iter(fleet.secrets))
            inc = af.replay(fp, af.replay_events(None, None))
        self.assertTrue(inc)
        self.assertEqual(inc["exposure"]["vendors"], ["copilot"])
        self.assertEqual(inc["exposure"]["sessions"], [fx.D])
        self.assertIn("fix/QRY-9", inc["exposure"]["branches"])
        self.assertGreaterEqual(inc["blast_radius"]["same_session"]["commands"], 1)

    def test_replay_with_root(self):
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            events = af.replay_events(None, str(state))
        self.assertEqual({e.vendor for e in events}, {"copilot"})


class TestCopilotMalformedContext(unittest.TestCase):

    def test_non_string_context_values_cannot_abort_a_run(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "session-state"
            d = state / "cccccccc-0000-4000-8000-000000000001"
            d.mkdir(parents=True)
            with (d / "events.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps({"type": "session.start", "timestamp": "2026-09-06T10:00:00Z",
                                     "data": {"context": {"gitRoot": {"x": 1}, "cwd": 7,
                                                          "branch": ["a"]}}}) + "\n")
                fh.write(json.dumps({"type": "tool.execution_start",
                                     "timestamp": "2026-09-06T10:00:01Z",
                                     "data": {"toolName": "bash",
                                              "arguments": {"command": "echo hi"}}}) + "\n")
            f = _fleet(state)
            self.assertEqual(f.permission_modes["copilot:auto"], 1)
            events = af.replay_events(None, str(state))
        self.assertEqual([e.cmd for e in events], ["echo hi"])


class TestCopilotCapabilities(unittest.TestCase):

    def test_copilot_column(self):
        gaps = dict(af.vendor_gaps("copilot"))
        self.assertNotIn("Git branch", gaps, "Copilot records the branch; Codex does not")
        self.assertIn("Sandbox policy", gaps)
        self.assertIn("Git branch", dict(af.vendor_gaps("codex")))

    def test_it_reaches_json(self):
        caps = af.to_json(af.Fleet())["vendors"]["capabilities"]
        self.assertTrue(all("copilot" in row for row in caps))

    def test_explain_copilot_states_the_unverified_mapping(self):
        e = af.EXPLAIN["copilot"]
        text = " ".join(e["formula"] + e["assumes"])
        self.assertIn("approved-for-location", text)
        self.assertIn("not been observed", text)
        self.assertIn("unpriced", text)

    def test_explain_copilot_states_the_cache_ttl_assumption(self):
        self.assertIn("1h", " ".join(af.EXPLAIN["copilot"]["assumes"]))

    def test_unpriced_sessions_are_shown_and_in_json(self):
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            f = _fleet(state, project="atlas")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render(f, af.C(False), bash_only=False, top=10)
        self.assertIn("1 Copilot session unpriced (no shutdown record)", buf.getvalue())
        self.assertEqual(af.to_json(f)["copilot_unpriced_sessions"], 1)
        f.copilot_unpriced = 2
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render(f, af.C(False), bash_only=False, top=10)
        self.assertIn("2 Copilot sessions unpriced (no shutdown record)", buf.getvalue())

    def test_refusals_section_warns_about_copilot_kinds(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1},
                    datetime(2026, 9, 1, tzinfo=timezone.utc))
        f.denials["copilot:denied-by-user"] += 1
        f._record_refusal("copilot:denied-by-user", "p", None, ("Bash", "rm -rf x"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render(f, af.C(False), bash_only=False, top=5)
        self.assertIn("--explain copilot", buf.getvalue())
