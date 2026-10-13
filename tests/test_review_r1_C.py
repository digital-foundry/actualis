"""Review round 1, slice C: scanners (Claude/Codex/Copilot), coach, --diff.

Every transcript here is synthetic and written to a temp directory; HOME,
CODEX_HOME and COPILOT_HOME point at an empty temp directory throughout.
"""
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
spec.loader.exec_module(af)

TS = "2026-10-10T00:00:00Z"
_HOME = tempfile.mkdtemp()


def setUpModule():
    p = mock.patch.dict(os.environ, {"HOME": _HOME, "CODEX_HOME": _HOME + "/cx",
                                     "COPILOT_HOME": _HOME + "/cp"})
    p.start()
    unittest.addModuleCleanup(p.stop)


def _write(dirpath: Path, name: str, lines) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / name).write_text("\n".join(json.dumps(l) for l in lines) + "\n")


def codex(lines, since=None, files=1):
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(files):
            _write(Path(tmp), f"rollout-{i}.jsonl", lines)
        f = af.Fleet()
        f.scan_codex([Path(tmp)], since, None)
        return f


def copilot(lines, since=None):
    with tempfile.TemporaryDirectory() as tmp:
        _write(Path(tmp) / "s1", "events.jsonl", lines)
        f = af.Fleet()
        f.scan_copilot([Path(tmp)], since, None)
        return f


def claude(lines, since=None):
    with tempfile.TemporaryDirectory() as tmp:
        _write(Path(tmp) / "-p", "a.jsonl", lines)
        f = af.Fleet()
        f.scan([Path(tmp)], since, None, False)
        return f


def token_count(ts, **tot):
    return {"type": "event_msg", "timestamp": ts,
            "payload": {"type": "token_count", "info": {"total_token_usage": tot}}}


def shell(ts, arguments, call_id=None):
    p = {"type": "function_call", "name": "shell_command", "arguments": arguments}
    if call_id is not None:
        p["call_id"] = call_id
    return {"type": "response_item", "timestamp": ts, "payload": p}


class TestC1CodexWrongTypes(unittest.TestCase):
    def test_wrong_typed_fields_do_not_crash(self):
        cases = {
            "info list": [{"type": "event_msg", "timestamp": TS,
                           "payload": {"type": "token_count", "info": [1]}}],
            "info str": [{"type": "event_msg", "timestamp": TS,
                          "payload": {"type": "token_count", "info": "x"}}],
            "total_tokens str": [token_count(TS, total_tokens="5")],
            "input_tokens str": [token_count(TS, total_tokens=5, input_tokens="5")],
            "cwd int": [{"type": "session_meta", "payload": {"cwd": 5}}],
            "cwd list": [{"type": "turn_context", "payload": {"cwd": ["a"]}}],
            "args dict": [shell(TS, {"command": "ls"})],
            "args json list": [shell(TS, "[1]")],
            "command list": [shell(TS, json.dumps({"command": ["bash", "-lc", "ls"]}))],
            "workdir int": [shell(TS, json.dumps({"command": "ls", "workdir": 5}))],
            "session dict": [{"type": "session_meta", "payload": {"id": {"a": 1}}},
                             shell(TS, json.dumps({"command": "curl https://x.com/a"}))],
            "call_id list": [shell(TS, json.dumps({"command": "ls"}), call_id=["c"])],
        }
        for name, lines in cases.items():
            with self.subTest(name):
                codex(lines)

    def test_a_list_command_is_not_audited(self):
        f = codex([shell(TS, json.dumps({"command": ["bash", "-lc", "rm -rf /"]}))])
        self.assertEqual(f.bash_total, 0)

    def test_a_wrong_typed_cwd_names_no_project(self):
        f = codex([{"type": "session_meta", "payload": {"cwd": 5}},
                   shell(TS, json.dumps({"command": "ls", "workdir": ["x"]}))])
        self.assertEqual(dict(f.bash_by_project), {"unknown": 1})

    def test_a_string_total_is_absent_not_a_crash(self):
        f = codex([token_count(TS, total_tokens="9", input_tokens="5", output_tokens=7)])
        self.assertEqual(f.tokens["input"], 0)
        self.assertEqual(f.tokens["output"], 7)


class TestC2CopilotWrongTypes(unittest.TestCase):
    def test_string_token_counts(self):
        f = copilot([{"type": "session.shutdown", "timestamp": TS,
                      "data": {"modelMetrics": {"gpt-5": {"usage": {
                          "inputTokens": "5", "cacheReadTokens": "1",
                          "cacheWriteTokens": [1], "outputTokens": "3"}}}}}])
        self.assertEqual(f.total_cost, 0)
        self.assertEqual(f.tokens["input"], 0)

    def test_string_duration(self):
        f = copilot([{"type": "subagent.completed", "timestamp": TS,
                      "data": {"durationMs": "5"}}])
        self.assertEqual(f.sub_ms, 0)
        self.assertEqual(f.sub_calls, 1)


class TestC3ClaudeWrongTypes(unittest.TestCase):
    def _sub(self, **result):
        return [{"type": "user", "timestamp": TS, "toolUseResult": result,
                 "message": {"usage": {}}}]

    def test_subagent_results(self):
        cases = {
            "toolStats list": self._sub(toolStats=[1]),
            "toolStats str count": self._sub(toolStats={"bashCount": "3", "linesAdded": "x"}),
            "totalDurationMs str": self._sub(toolStats={}, totalDurationMs="3"),
            "status list": self._sub(toolStats={}, status=[1]),
            "usage str": self._sub(toolStats={}, usage={"input_tokens": "3"}),
            "cache_creation list": self._sub(toolStats={}, usage={"cache_creation": [1]}),
            "resolvedModel list": self._sub(toolStats={}, resolvedModel=["x"]),
        }
        for name, lines in cases.items():
            with self.subTest(name):
                f = claude(lines)
                self.assertGreaterEqual(f.sub_cost_floor, 0)

    def test_subagent_wrong_types_count_as_absent(self):
        f = claude(self._sub(toolStats={"bashCount": "3", "readCount": 2},
                             totalDurationMs="9", status=[1]))
        self.assertEqual(f.sub_tools["bashCount"], 0)
        self.assertEqual(f.sub_tools["readCount"], 2)
        self.assertEqual(f.sub_ms, 0)

    def test_list_command(self):
        f = claude([{"type": "assistant", "timestamp": TS, "message": {"content": [
            {"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": ["ls"]}}]}}])
        self.assertEqual(f.bash_total, 0)
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": ["ls"]}, None)
        self.assertEqual(f.bash_total, 0)

    def test_list_tool_use_id_on_a_refusal(self):
        claude([{"type": "assistant", "timestamp": TS, "message": {"content": [
                    {"type": "tool_use", "id": "t", "name": "Bash",
                     "input": {"command": "ls"}}]}},
                {"type": "user", "toolDenialKind": "x", "timestamp": TS,
                 "message": {"content": [{"type": "tool_result", "tool_use_id": ["t"]}],
                             "usage": {}}}])


class TestC4Timestamps(unittest.TestCase):
    def test_parse_ts_is_aware_utc(self):
        naive = af.parse_ts("2026-10-10T00:00:00")
        self.assertEqual(naive, datetime(2026, 10, 10, tzinfo=timezone.utc))
        off = af.parse_ts("2026-10-10T23:30:00-05:00")
        self.assertEqual(off.utcoffset().total_seconds(), 0)
        self.assertEqual(off, datetime(2026, 10, 11, 4, 30, tzinfo=timezone.utc))
        self.assertEqual(af.parse_ts(TS).tzinfo, timezone.utc)

    def test_parse_ts_overflow_is_absent(self):
        self.assertIsNone(af.parse_ts("9999-12-31T23:00:00-05:00"))
        self.assertIsNone(af.parse_ts("0001-01-01T00:30:00+05:00"))

    def test_naive_timestamps_with_days(self):
        since = af.window_start(30, datetime(2026, 10, 12, tzinfo=timezone.utc))
        naive = "2026-10-10T00:00:00"
        f = codex([token_count(naive, total_tokens=5, input_tokens=5),
                   shell(naive, json.dumps({"command": "ls"}))], since)
        self.assertEqual(f.bash_total, 1)
        f = copilot([{"type": "tool.execution_start", "timestamp": naive,
                      "data": {"toolName": "bash", "arguments": {"command": "ls"}}}], since)
        self.assertEqual(f.bash_total, 1)
        f = claude([{"type": "assistant", "timestamp": naive,
                     "message": {"id": "m", "model": "claude-opus-4-1",
                                 "usage": {"input_tokens": 5}}}], since)
        self.assertEqual(f.messages, 1)

    def test_mixed_naive_and_aware_without_days(self):
        f = claude([{"type": "assistant", "timestamp": "2026-10-10T00:00:00",
                     "message": {"id": "m", "usage": {"input_tokens": 5}}},
                    {"type": "assistant", "timestamp": "2026-10-09T00:00:00Z",
                     "message": {"id": "m2", "usage": {"input_tokens": 5}}}])
        self.assertEqual(f.messages, 2)
        self.assertEqual(f.first_ts, datetime(2026, 10, 9, tzinfo=timezone.utc))

    def test_an_offset_record_lands_on_its_utc_date(self):
        ts = "2026-10-10T23:30:00-05:00"
        f = claude([{"type": "assistant", "timestamp": ts,
                     "message": {"id": "m", "model": "claude-opus-4-1",
                                 "usage": {"input_tokens": 1000},
                                 "content": [{"type": "tool_use", "id": "t", "name": "Bash",
                                              "input": {"command": "ls"}}]}}])
        self.assertEqual(list(f.cost_by_day), ["2026-10-11"])
        self.assertEqual(list(f.bash_by_day), ["2026-10-11"])


class TestC5CodexDaysPerCommand(unittest.TestCase):
    OLD, NEW = "2026-08-01T00:00:00Z", "2026-10-12T00:00:00Z"

    def setUp(self):
        self.since = af.window_start(7, datetime(2026, 10, 13, tzinfo=timezone.utc))

    def test_an_old_command_in_a_recent_session_is_outside_the_window(self):
        f = codex([shell(self.OLD, json.dumps({"command": "rm -rf /tmp/x"}), "c1"),
                   token_count(self.NEW, total_tokens=1000, input_tokens=1000)], self.since)
        self.assertEqual(f.bash_total, 0)
        self.assertEqual(dict(f.bash_by_day), {})
        self.assertEqual(f.flags, [])
        self.assertGreater(f.total_cost, 0, "the session is still in the window")

    def test_an_old_command_with_no_token_count(self):
        f = codex([shell(self.OLD, json.dumps({"command": "rm -rf /tmp/x"}), "c1")],
                  self.since)
        self.assertEqual(f.bash_total, 0)
        self.assertEqual(f.flags, [])

    def test_a_new_command_is_kept(self):
        f = codex([shell(self.NEW, json.dumps({"command": "rm -rf /tmp/x"}), "c1")],
                  self.since)
        self.assertEqual(f.bash_total, 1)


class TestC6CodexDedup(unittest.TestCase):
    LINES = [{"type": "session_meta", "payload": {"id": "S1", "cwd": "/w/p"}},
             shell("2026-10-12T00:00:00Z", json.dumps({"command": "rm -rf /tmp/x"}), "c1"),
             token_count("2026-10-12T00:00:00Z", total_tokens=1_000_000,
                         input_tokens=1_000_000, output_tokens=0)]

    def test_two_copies_of_one_session_count_once(self):
        one = codex(self.LINES)
        two = codex(self.LINES, files=2)
        self.assertEqual(two.bash_total, 1)
        self.assertEqual(len(two.flags), len(one.flags))
        self.assertEqual(two.units_by_agent["codex"], 1)
        self.assertAlmostEqual(two.total_cost, one.total_cost)
        self.assertEqual(two.duplicate_tool_calls_skipped, 1)

    def test_a_resumed_copy_keeps_the_larger_total(self):
        more = [dict(self.LINES[0]), self.LINES[1],
                token_count("2026-10-12T01:00:00Z", total_tokens=3_000_000,
                            input_tokens=3_000_000, output_tokens=0)]
        with tempfile.TemporaryDirectory() as tmp:
            _write(Path(tmp), "rollout-a.jsonl", self.LINES)
            _write(Path(tmp), "rollout-b.jsonl", more)
            f = af.Fleet()
            f.scan_codex([Path(tmp)], None, None)
        self.assertEqual(f.units_by_agent["codex"], 1)
        self.assertEqual(f.tokens["input"], 3_000_000)

    def test_distinct_sessions_still_add_up(self):
        other = [{"type": "session_meta", "payload": {"id": "S2", "cwd": "/w/p"}}] + self.LINES[1:]
        with tempfile.TemporaryDirectory() as tmp:
            _write(Path(tmp), "rollout-a.jsonl", self.LINES)
            _write(Path(tmp), "rollout-b.jsonl", other)
            f = af.Fleet()
            f.scan_codex([Path(tmp)], None, None)
        self.assertEqual(f.units_by_agent["codex"], 2)


class TestC7SandboxNotATurn(unittest.TestCase):
    def test_a_never_codex_fleet_is_fully_ungated(self):
        lines = [{"type": "session_meta", "payload": {"id": "S", "cwd": "/w/p"}}]
        for _ in range(600):
            lines.append({"type": "turn_context", "timestamp": TS, "payload": {
                "cwd": "/w/p", "model": "gpt-5", "approval_policy": "never",
                "sandbox_policy": {"type": "danger-full-access"}}})
        f = codex(lines)
        af003 = [x for x in af.coach(f) if x.id == "AF003"]
        self.assertEqual(len(af003), 1)
        self.assertIn("100% of 600", af003[0].evidence)
        status, text = af._aisvs_9_2_1(f)
        self.assertEqual(status, af.FAILING)
        self.assertIn("100.0% of 600", text)
        self.assertEqual(af.recorded_turns(f.permission_modes), 600)


def _report(**over):
    base = {"schema_version": af.JSON_SCHEMA_VERSION,
            "window": {"from": "2026-01-01T00:00:00+00:00", "to": "2026-01-08T00:00:00+00:00"},
            "secrets": [], "coach": [], "bash": {"flags": []},
            "cost_usd": 10.0, "messages": 100, "report_sha256": "a" * 64}
    base.update(over)
    return base


def _af002(project, evidence=None, with_field=True):
    row = {"id": "AF002", "severity": "high",
           "title": "Cache efficiency below your own median",
           "evidence": evidence or f"{project} reads 10% of tokens from cache; your median "
                                   f"project is 80%."}
    if with_field:
        row["project"] = project
    return row


class TestC8DiffPerProject(unittest.TestCase):
    def test_a_second_project_regressing_appears(self):
        d = af.diff_reports(_report(coach=[_af002("projA")]),
                            _report(coach=[_af002("projA"), _af002("projB")]))
        fam = d["families"]["findings"]
        self.assertEqual([r["project"] for r in fam["appeared"]], ["projB"])

    def test_one_fixed_another_broken(self):
        d = af.diff_reports(_report(coach=[_af002("projA")]),
                            _report(coach=[_af002("projB")]))
        fam = d["families"]["findings"]
        self.assertEqual(len(fam["appeared"]), 1)
        self.assertEqual(len(fam["resolved"]), 1)

    def test_a_baseline_without_the_project_field_still_matches(self):
        d = af.diff_reports(_report(coach=[_af002("projA", with_field=False)]),
                            _report(coach=[_af002("projA"), _af002("projB")]))
        fam = d["families"]["findings"]
        self.assertEqual(len(fam["appeared"]), 1)
        self.assertEqual(fam["resolved"], [])

    def test_coach_json_carries_the_project(self):
        f = af.Fleet()
        payload = af.to_json(f)
        for row in payload["coach"]:
            self.assertIsInstance(row["project"], str)
        self.assertIn("coach[].project", af.JSON_SCHEMA)


class TestC9HostileBaseline(unittest.TestCase):
    def _render(self, old, new=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_diff(af.diff_reports(old, new or {}), af.C(False))
        return buf.getvalue()

    def test_wrong_types_do_not_crash_render(self):
        for bad in ({"secrets": [{"id": "x", "priority": ["high"]}]},
                    {"secrets": [{"id": "x", "priority": "high", "types": [1]}]},
                    {"secrets": [{"id": "x", "priority": "high", "types": "AWS"}]},
                    {"window": [1]},
                    {"coach": [{"id": "AF001", "severity": {"a": 1}, "title": ["t"]}]},
                    {"bash": {"flags": [{"id": "f", "severity": 3, "program": ["x"],
                                         "categories": "a"}]}}):
            with self.subTest(bad=bad):
                self._render(bad)

    def test_baseline_strings_are_cleaned(self):
        out = self._render({"bash": {"flags": [{"id": "f", "severity": "high",
                                                "program": "\x1b]0;pwned\x07evil",
                                                "categories": ["\x1b[31ma"]}]},
                            "secrets": [{"id": "s", "priority": "high",
                                         "types": ["\x1b[2Jt"], "projects": ["\x9bp"]}],
                            "coach": [{"id": "AF001", "severity": "high",
                                       "title": "\x1b]8;;http://x\x07t"}],
                            "window": {"from": "\x1b[2J", "to": "x"}})
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("\x9b", out)
        self.assertIn("evil", out)

    def test_load_report_refuses_a_malformed_baseline(self):
        for bad in ({"window": [1]}, {"secrets": {"a": 1}}, {"secrets": [1]},
                    {"secrets": [{"id": "x", "priority": ["high"]}]},
                    {"secrets": [{"id": "x", "types": [1]}]},
                    {"coach": [{"id": "AF001", "severity": []}]},
                    {"bash": []}, {"bash": {"flags": [{"id": "f", "categories": "a"}]}},
                    {"cost_usd": "1"}, {"scope": []}):
            with self.subTest(bad=bad):
                path = self._file(_report(**bad))
                with self.assertRaises(ValueError) as cm:
                    af.load_report(path)
                self.assertIn("baseline", str(cm.exception))

    def test_a_well_formed_baseline_loads(self):
        af.load_report(self._file(_report(coach=[_af002("p")])))
        af.load_report(self._file(af.to_json(af.Fleet())))

    def _file(self, payload):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(payload, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return Path(fh.name)

    def test_cli_malformed_baseline_is_a_usage_error(self):
        path = self._file(_report(window=[1]))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            af.main(["--diff", str(path)])
        self.assertEqual(cm.exception.code, af.EXIT_USAGE)
        self.assertIn("--diff", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_cli_unparseable_baseline_is_a_usage_error(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        fh.write("{not json")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            af.main(["--diff", fh.name])
        self.assertEqual(cm.exception.code, af.EXIT_USAGE)


class TestC10DiffScope(unittest.TestCase):
    def test_json_records_the_scope(self):
        f = af.Fleet()
        f.scope = {"days": 7, "project": "api", "agent": "codex"}
        p = af.to_json(f)
        self.assertEqual(p["scope"], {"days": 7, "project": "api", "agent": "codex"})
        default = af.to_json(af.Fleet())["scope"]
        self.assertEqual(default, {"days": None, "project": "", "agent": "all"})
        for k in ("scope.days", "scope.project", "scope.agent"):
            self.assertIn(k, af.JSON_SCHEMA)

    def _render(self, old, new):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_diff(af.diff_reports(old, new), af.C(False))
        return buf.getvalue()

    def test_a_scope_mismatch_is_called_out(self):
        old = _report(scope={"days": None, "project": "api", "agent": "all"},
                      scanned={"roots": ["/r"]})
        new = _report(scope={"days": 7, "project": "", "agent": "all"},
                      scanned={"roots": ["/r"]}, report_sha256="b" * 64)
        out = self._render(old, new)
        self.assertIn("different scope", out)
        self.assertIn("--project", out)
        self.assertIn("--days", out)
        self.assertNotIn("--agent", out)

    def test_different_roots_are_called_out(self):
        old = _report(scope={"days": None, "project": "", "agent": "all"},
                      scanned={"roots": ["/a"]})
        new = _report(scope={"days": None, "project": "", "agent": "all"},
                      scanned={"roots": ["/b"]}, report_sha256="b" * 64)
        self.assertIn("roots", self._render(old, new))

    def test_same_scope_says_nothing(self):
        sc = {"days": 7, "project": "", "agent": "all"}
        old = _report(scope=sc, scanned={"roots": ["/a"]})
        new = _report(scope=dict(sc), scanned={"roots": ["/a"]}, report_sha256="b" * 64)
        self.assertNotIn("different scope", self._render(old, new))

    def test_hostile_scope_values_are_cleaned(self):
        old = _report(scope={"days": None, "project": "\x1b]0;x\x07", "agent": "all"})
        new = _report(scope={"days": None, "project": "", "agent": "all"},
                      report_sha256="b" * 64)
        self.assertNotIn("\x1b", self._render(old, new))


class TestC11NegativeAndInfiniteCounts(unittest.TestCase):
    def test_codex_negative(self):
        f = codex([token_count(TS, total_tokens=5, input_tokens=-5_000_000_000,
                               output_tokens=-10**9)])
        self.assertGreaterEqual(f.total_cost, 0)
        self.assertGreaterEqual(f.tokens["output"], 0)
        self.assertGreaterEqual(f.tokens["input"], 0)

    def test_codex_infinite(self):
        f = codex([token_count(TS, total_tokens=5, input_tokens=1e400, output_tokens=5)])
        self.assertTrue(f.total_cost == f.total_cost and f.total_cost != float("inf"))

    def test_copilot_negative_and_infinite(self):
        for usage in ({"inputTokens": 0, "outputTokens": -10**9},
                      {"inputTokens": 1e400}, {"cacheReadTokens": -10**9, "inputTokens": 5}):
            with self.subTest(usage=usage):
                f = copilot([{"type": "session.shutdown", "timestamp": TS,
                              "data": {"modelMetrics": {"gpt-5": {"usage": usage}}}}])
                self.assertGreaterEqual(f.total_cost, 0)
                self.assertNotEqual(f.total_cost, float("inf"))
                for v in f.tokens.values():
                    self.assertGreaterEqual(v, 0)


if __name__ == "__main__":
    unittest.main()
