"""Review r1, slice F: the CLI's gate, mode combinations, service units and
self-check. Synthetic data only, under a temp HOME."""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

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

CANARY_FP = "5e346453"     # session D's Stripe canary, as the report prints it


class _Env(unittest.TestCase):
    """A temp HOME, the four synthetic Copilot sessions, and a main() runner."""

    def setUp(self):
        self._home = fx.isolated_home()
        self.home = self._home.__enter__()
        self.addCleanup(self._home.__exit__, None, None, None)
        self.state = fx.write_sessions(self.home / "state")
        self._cwd = os.getcwd()
        os.chdir(self.home)              # project-local suppressions land here
        self.addCleanup(os.chdir, self._cwd)
        os.environ["XDG_CONFIG_HOME"] = str(self.home / "cfg")

    def run_main(self, *argv, scan=True):
        base = ["--root", str(self.state), "--agent", "copilot"] if scan else []
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = af.main(base + list(argv))
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def assertUsage(self, *argv, scan=True):
        code, _, err = self.run_main(*argv, scan=scan)
        self.assertEqual(code, 2, (argv, err))
        return err


# --- F1 / R5: a closed stdout must not turn a failing gate into exit 0 ------

class _PipeOut(io.StringIO):
    def write(self, s):
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")


class TestF1GateSurvivesBrokenPipe(_Env):

    def _gated(self, *argv):
        err = io.StringIO()
        with mock.patch.object(sys, "stdout", _PipeOut()), \
                mock.patch.object(af, "_silence_stdout", lambda: None), \
                contextlib.redirect_stderr(err):
            code = af._cli(["--root", str(self.state), "--agent", "copilot", *argv])
        return code, err.getvalue()

    def test_json_gate_still_fails_when_stdout_is_closed(self):
        code, err = self._gated("--json", "--fail-on", "critical")
        self.assertEqual(code, af.EXIT_FINDINGS)
        self.assertIn("FAIL at --fail-on critical", err)

    def test_text_gate_still_fails_when_stdout_is_closed(self):
        code, _ = self._gated("--fail-on", "critical")
        self.assertEqual(code, af.EXIT_FINDINGS)

    def _subprocess(self, *argv):
        r, w = os.pipe()
        os.close(r)                         # the reader is already gone
        try:
            p = subprocess.run(
                [sys.executable, "-I", str(ROOT / "actualis.py"), "--root", str(self.state),
                 "--agent", "copilot", *argv],
                stdout=w, stderr=subprocess.PIPE, env=os.environ.copy(), timeout=120)
        finally:
            os.close(w)
        return p.returncode, p.stderr.decode("utf-8", "replace")

    def test_real_closed_pipe_exits_with_the_gate_code(self):
        for argv in (("--json", "--fail-on", "critical"), ("--fail-on", "critical")):
            with self.subTest(argv=argv):
                code, err = self._subprocess(*argv)
                self.assertEqual(code, 3, err)
                self.assertNotIn("Traceback", err)

    def test_closed_pipe_without_a_gate_is_still_quiet(self):
        code, err = self._subprocess("--json")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)


# --- F2 / R4: --fail-on is refused by modes that cannot evaluate it ---------

class TestF2FailOnRefused(_Env):
    MODES = (("--diff", "x.json"), ("--why", "AF004"), ("--replay", CANARY_FP),
             ("--watch",), ("--mcp",), ("--explain",), ("--agents",),
             ("--suppress", CANARY_FP), ("--suppressions",), ("--self-check",),
             ("--service", "systemd"), ("--completions", "bash"))

    def test_every_early_returning_mode_refuses_fail_on(self):
        for mode in self.MODES:
            with self.subTest(mode=mode):
                err = self.assertUsage(*mode, "--fail-on", "critical")
                self.assertIn("--fail-on", err)
                self.assertIn(mode[0], err)

    def test_refusing_suppress_writes_nothing(self):
        self.assertUsage("--suppress", CANARY_FP, "--fail-on", "critical")
        self.assertEqual(af.load_suppressions(), {})

    def test_the_plain_gate_still_works(self):
        code, _, _ = self.run_main("--fail-on", "critical")
        self.assertEqual(code, 3)


# --- F3 / R6: AF013 does not count toward --fail-on -------------------------

class TestF3ClockFindingNotGated(unittest.TestCase):

    def test_stale_rate_table_does_not_trip_the_gate(self):
        old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%d")
        with mock.patch.object(af, "PRICING_VERIFIED", old):
            fleet = af.Fleet()
            self.assertIn("AF013", [f.id for f in af.coach(fleet)])
            for level in af.FAIL_ON_LEVELS:
                with self.subTest(level=level):
                    self.assertFalse([r for r in af.failing_findings(fleet, level)
                                      if r.startswith("AF013")])


# --- F4 / R7: str fields are "" when unknown, never null ---------------------

class TestF4NoNullForStrFields(unittest.TestCase):

    def test_timestampless_record_emits_empty_strings(self):
        rec = {"type": "assistant", "sessionId": "s1", "gitBranch": "feat/412-x", "uuid": "u1",
               "message": {"id": "m1", "role": "assistant", "model": "claude-sonnet-4-5",
                           "usage": {"input_tokens": 10, "output_tokens": 5},
                           "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                                        "input": {"command": "export STRIPE_KEY=" + fx.CANARY}}]}}
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj-a"
            proj.mkdir()
            (proj / "s1.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
            fleet = af.Fleet()
            fleet.scan([Path(td)], None, None, progress=False)
            data = af.to_json(fleet)
        self.assertTrue(data["by_ticket"] and data["secrets"])
        for row in data["by_ticket"] + data["secrets"]:
            self.assertEqual(row["first_seen"], "")
            self.assertEqual(row["last_seen"], "")


# --- F5 / F6: service units ---------------------------------------------------

class TestF5ServiceUnitQuoting(unittest.TestCase):

    def _unit(self, argv, kind="systemd"):
        with mock.patch.object(af, "_actualis_command", return_value=list(argv)):
            return af.service_unit(kind)

    def test_systemd_execstart_is_quoted_and_escaped(self):
        unit = self._unit(['/home/Jane Doe/50%/.venv/bin/python', '/home/Jane Doe/$src/a"b\\c.py'])
        lines = [ln for ln in unit.splitlines() if ln.startswith("ExecStart")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(
            lines[0],
            'ExecStart="/home/Jane Doe/50%%/.venv/bin/python" '
            '"/home/Jane Doe/$$src/a\\"b\\\\c.py" --watch --interval 4')

    def test_a_newline_in_a_path_is_refused(self):
        with self.assertRaises(ValueError):
            self._unit(['/usr/bin/python3', '/x/a.py\nExecStartPre=/bin/touch /tmp/pwn'])

    def test_a_control_character_is_refused_in_launchd_too(self):
        with self.assertRaises(ValueError):
            self._unit(['/usr/bin/python3', '/x/a\x01.py'], kind="launchd")

    def test_newsyslog_refuses_whitespace_in_the_log_path_or_user(self):
        with mock.patch.object(af, "SERVICE_LOG", "/tmp/my logs/actualis.log"):
            with self.assertRaises(ValueError):
                af.service_unit("newsyslog")
        with mock.patch.dict(os.environ, {"USER": "jane doe"}):
            with self.assertRaises(ValueError):
                af.service_unit("newsyslog")
        with mock.patch.dict(os.environ, {"USER": "jane"}):
            self.assertIn("jane:staff", af.service_unit("newsyslog"))

    def test_main_reports_a_refused_unit_without_a_traceback(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(af, "_actualis_command", return_value=["/a\nb"]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = af.main(["--service", "systemd"])
        self.assertEqual(code, af.EXIT_CANNOT_RUN)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("actualis:", err.getvalue())


class TestF6SourceCheckoutService(unittest.TestCase):

    def test_a_checkout_names_its_own_interpreter_not_path(self):
        old = sys.argv[:]
        try:
            sys.argv = [str(Path(af.__file__)), "--service", "systemd"]
            with mock.patch("shutil.which", return_value="/opt/other/bin/actualis"):
                self.assertEqual(af._actualis_command(),
                                 [sys.executable, str(Path(af.__file__).resolve())])
        finally:
            sys.argv = old


# --- F7 / R4: --json refused with modes it would override or that ignore it -

class TestF7JsonConflicts(_Env):

    def test_json_is_refused_with_text_only_modes(self):
        for mode in (("--share",), ("--coach",), ("--aisvs",), ("--bash",), ("--why", "AF004"),
                     ("--explain",), ("--suppressions",), ("--self-check",),
                     ("--service", "systemd"), ("--completions", "bash"),
                     ("--suppress", CANARY_FP)):
            with self.subTest(mode=mode):
                err = self.assertUsage("--json", *mode)
                self.assertIn("--json", err)
                self.assertIn(mode[0], err)

    def test_share_coach_aisvs_bash_are_mutually_exclusive(self):
        modes = ("--share", "--coach", "--aisvs", "--bash")
        for i, a in enumerate(modes):
            for b in modes[i + 1:]:
                with self.subTest(pair=(a, b)):
                    err = self.assertUsage(a, b)
                    self.assertIn(a, err)
                    self.assertIn(b, err)

    def test_json_still_works_where_it_has_a_shape(self):
        code, out, _ = self.run_main("--json")
        self.assertEqual(code, 0)
        json.loads(out)
        code, out, _ = self.run_main("--replay", CANARY_FP, "--json")
        self.assertEqual(code, 0)
        json.loads(out)


# --- F8: --network and --ioc refused where they would be dropped ------------

class TestF8NetworkIocConflicts(_Env):
    EARLY = (("--why", "AF004"), ("--agents",), ("--explain",), ("--suppress", CANARY_FP),
             ("--suppressions",), ("--self-check",), ("--service", "systemd"),
             ("--completions", "bash"))

    def test_network_is_refused_with_modes_that_drop_it(self):
        for mode in self.EARLY:
            with self.subTest(mode=mode):
                err = self.assertUsage("--network", *mode)
                self.assertIn("--network", err)
                self.assertIn(mode[0], err)

    def test_ioc_is_refused_with_modes_that_never_read_it(self):
        bogus = str(self.home / "nonexistent.ioc")
        for mode in (("--replay", CANARY_FP),) + tuple(m for m in self.EARLY if m[0] != "--why"):
            with self.subTest(mode=mode):
                err = self.assertUsage("--ioc", bogus, *mode)
                self.assertIn("--ioc", err)
                self.assertIn(mode[0], err)


# --- F9: --ci-log with flags it would ignore ----------------------------------

class TestF9CiLogConflicts(_Env):

    def test_ci_log_refuses_root_agent_project_and_replay(self):
        log = self.home / "log.json"
        log.write_text("[]", encoding="utf-8")
        for extra in (("--root", str(self.home)), ("--agent", "codex"),
                      ("--project", "x"), ("--replay", CANARY_FP)):
            with self.subTest(extra=extra):
                err = self.assertUsage("--ci-log", str(log), *extra, scan=False)
                self.assertIn("--ci-log", err)
                self.assertIn(extra[0], err)


# --- F10: the FAIL summary counts suppressed flags too ------------------------

class TestF10SuppressedCount(_Env):

    def test_suppressed_flag_is_counted_in_the_fail_summary(self):
        code, out, _ = self.run_main("--json")
        flags = [f for f in json.loads(out)["bash"]["flags"] if f["severity"] == "high"]
        self.assertTrue(flags)
        for f in flags:
            self.run_main("--suppress", f["id"], "--reason", "test", scan=False)
        code, _, err = self.run_main("--fail-on", "any")
        self.assertEqual(code, 3, err)
        self.assertNotIn("  0 suppressed", err)
        self.assertIn(f"{len(flags)} suppressed", err)


# --- F11: --json --no-redact warns on stderr ---------------------------------

class TestF11JsonNoRedactWarns(_Env):

    def test_json_and_network_json_warn(self):
        for extra in ((), ("--network",)):
            with self.subTest(extra=extra):
                code, out, err = self.run_main("--json", "--no-redact", *extra)
                self.assertEqual(code, 0)
                json.loads(out)                      # stdout stays pure JSON
                self.assertIn("--no-redact", err)


# --- F12: --interval and --days validated ------------------------------------

class TestF12NumericValidation(_Env):

    def test_bad_interval_is_a_usage_error(self):
        for v in ("nan", "inf", "-inf", "0", "-1"):
            with self.subTest(v=v):
                self.assertUsage("--service", "systemd", "--interval", v, scan=False)

    def test_bad_days_is_a_usage_error(self):
        for v in ("0", "-3"):
            with self.subTest(v=v):
                self.assertUsage("--days", v)

    def test_good_values_pass(self):
        code, out, _ = self.run_main("--service", "systemd", "--interval", "2.5", scan=False)
        self.assertEqual(code, 0)
        self.assertIn("--interval 2.5", out)


# --- F13: AISVS 9.3.1 counts actionable commands, not category matches ------

class TestF13Aisvs931(unittest.TestCase):

    def _fleet(self, suppressed):
        fleet = af.Fleet()
        fleet.bash_total = 1
        fleet.flags = [{"id": "abcd1234", "severity": "high", "suppressed": suppressed,
                        "categories": ["destructive", "egress", "credentials"]}]
        fleet.flag_counts.update({"high:destructive": 1, "high:egress": 1,
                                  "high:credentials": 1})
        return fleet

    def test_one_command_is_one_command(self):
        status, detail = af._aisvs_9_3_1(self._fleet(False))
        self.assertEqual(status, af.FAILING)
        self.assertIn("1 command", detail)
        self.assertNotIn("3 commands", detail)

    def test_suppressed_flags_do_not_fail_the_control(self):
        status, _ = af._aisvs_9_3_1(self._fleet(True))
        self.assertEqual(status, af.CONSISTENT)


# --- F14: self-check exit code and write paths --------------------------------

class TestF14SelfCheck(unittest.TestCase):

    def test_a_failed_self_check_has_its_own_exit_code(self):
        self.assertNotIn(af.EXIT_SELF_CHECK_FAILED,
                         (af.EXIT_OK, af.EXIT_CANNOT_RUN, af.EXIT_USAGE, af.EXIT_FINDINGS))
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(af, "imports_in", return_value=["socket"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(af.self_check(af.C(False), 7, td), af.EXIT_SELF_CHECK_FAILED)

    def test_write_paths_name_the_html_report(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(out):
            self.assertEqual(af.self_check(af.C(False), 7, td), af.EXIT_OK)
        self.assertIn("--network --html: actualis-network[-N].html",
                      " ".join(out.getvalue().split()))

    def test_readme_documents_the_code(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"| `{af.EXIT_SELF_CHECK_FAILED}` |", readme)


# --- F15: usage errors exit 2 ------------------------------------------------

class TestF15UsageErrors(_Env):

    def test_malformed_suppress_id_is_a_usage_error(self):
        self.assertUsage("--suppress", "zz", scan=False)

    def test_unknown_why_id_is_a_usage_error(self):
        self.assertUsage("--why", "AF999")

    def test_known_but_not_firing_id_is_not_a_usage_error(self):
        code, out, _ = self.run_main("--why", "af012")
        self.assertIn(code, (0, 1))
        self.assertIn("AF012", out)

    def test_the_id_list_matches_the_coach_source(self):
        import re
        src = (ROOT / "actualis.py").read_text(encoding="utf-8")
        body = src[src.index("def coach("):]
        body = body[:body.index("\ndef ", 1)]
        self.assertEqual(set(re.findall(r'"(AF\d{3})"', body)), set(af.COACH_FINDING_IDS))


# --- F16: replay reads what the report read, once ----------------------------

class TestF16ReplayMatchesReport(unittest.TestCase):

    @staticmethod
    def _rec(uuid, mid, ts, tid, cmd):
        return {"type": "assistant", "sessionId": "s1", "uuid": uuid, "timestamp": ts,
                "cwd": "/x/proj-a", "gitBranch": "main",
                "message": {"id": mid, "role": "assistant", "model": "claude-sonnet-4-5",
                            "usage": {"input_tokens": 10, "output_tokens": 5},
                            "content": [{"type": "tool_use", "id": tid, "name": "Bash",
                                         "input": {"command": cmd}}]}}

    def test_a_resumed_copy_is_not_a_second_sighting(self):
        recs = [self._rec("u1", "m1", "2026-10-01T10:00:00Z", "t1",
                          "export STRIPE_KEY=" + fx.CANARY),
                self._rec("u2", "m2", "2026-10-01T10:01:00Z", "t2", "make deploy")]
        body = "".join(json.dumps(r) + "\n" for r in recs)
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj-a"
            (proj / "s1" / "subagents").mkdir(parents=True)
            for name in ("s1.jsonl", "s2.jsonl"):           # s2 is a resumed copy
                (proj / name).write_text(body, encoding="utf-8")
            # A file the report never reads must not be replayed either.
            (proj / "s1" / "subagents" / "a.jsonl").write_text(
                json.dumps(self._rec("u9", "m9", "2026-10-01T10:02:00Z", "t9",
                                     "export STRIPE_KEY=" + fx.CANARY)) + "\n",
                encoding="utf-8")
            fleet = af.Fleet()
            fleet.scan([Path(td)], None, None, progress=False)
            fp, entry = next(iter(fleet.secrets.items()))
            inc = af.replay(fp, af._claude_events([Path(td)], None))
        self.assertEqual(entry["uses"], 1)
        self.assertEqual(inc["window"]["sightings"], 1)


if __name__ == "__main__":
    unittest.main()
