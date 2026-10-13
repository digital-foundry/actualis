"""Review r3, slice R3E, fixer TEST: test-suite and docs hygiene (R3E2-R3E5, R3E8, R3E9).

- R3E2/R3E3: the timing helpers survive a busy machine and still catch a quadratic.
- R3E4: "no findings" tests do not depend on the wall clock (AF013 fires once
  the rate table is PRICING_STALE_DAYS old).
- R3E5: the whole suite runs in a temp HOME, agent homes, XDG_CONFIG_HOME and
  cwd, and an audit hook refuses and records any read under the real home.
- R3E8: the docs say which paths the secret scanners skip.
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402
import _timing  # noqa: E402
import test_actualis as ta  # noqa: E402

af = ta.af
TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent


def _under(path, base) -> bool:
    p = os.path.normcase(os.path.realpath(str(path)))
    b = os.path.normcase(os.path.realpath(str(base)))
    return p == b or p.startswith(b + os.sep)


class TestHermeticSuite(unittest.TestCase):
    """R3E5: no test reads the developer's transcripts, suppressions or config."""

    def test_the_process_runs_in_temp_dirs(self):
        self.assertTrue(getattr(sys, "_actualis_tests_isolated", False))
        self.assertNotEqual(os.path.normcase(fx.TEMP_HOME), os.path.normcase(fx.REAL_HOME))
        self.assertEqual(os.environ["HOME"], fx.TEMP_HOME)
        self.assertTrue(_under(Path.home(), fx.TEMP_HOME))
        self.assertNotIn("CLAUDE_CONFIG_DIR", os.environ)
        for var in ("XDG_CONFIG_HOME", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME",
                    "QWEN_HOME", "QWEN_RUNTIME_DIR"):
            self.assertTrue(_under(os.environ[var], fx.TEMP_HOME), var)
        # The cwd is the suite's own temp dir (a test may chdir into its own
        # temp dir and back): never the repo, whose .actualis-suppressions
        # every Fleet() would otherwise read.
        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(fx.TEMP_CWD))
        self.assertFalse(_under(os.getcwd(), ROOT))

    def test_suppressions_and_default_roots_are_inside_the_temp_home(self):
        user, project = af.suppression_paths()
        self.assertTrue(_under(user, fx.TEMP_HOME), user)
        self.assertTrue(_under(project, fx.TEMP_CWD), project)
        # Every agent's default transcript location, as if each existed.
        with mock.patch.object(af.Path, "is_dir", lambda self: True):
            roots = (af.transcript_roots() + af.codex_roots() + af.copilot_roots()
                     + af.gemini_roots() + af.qwen_roots())
        self.assertGreaterEqual(len(roots), 5)
        for d in roots:
            self.assertTrue(_under(d, fx.TEMP_HOME), d)

    def test_every_test_module_imports_the_isolation(self):
        """Statically: each module imports _fixtures, directly or through a
        test module that does, so it is isolated even when run on its own."""
        sources = {p.stem: p.read_text(encoding="utf-8") for p in TESTS.glob("test_*.py")}

        def isolated(name, seen=()):
            src = sources[name]
            if re.search(r"^import _fixtures\b", src, re.M):
                return True
            for dep in re.findall(r"^from (test_\w+) import", src, re.M):
                if dep in sources and dep not in seen and isolated(dep, seen + (name,)):
                    return True
            return False
        missing = sorted(n for n in sources if not isolated(n))
        self.assertEqual(missing, [], "add `import _fixtures` at the top of these modules")

    def test_no_module_relies_on_add_module_cleanup(self):
        """Python 3.9.6 (Apple's /usr/bin/python3) runs addModuleCleanup
        callbacks only when the module also defines tearDownModule; an env
        patch undone that way leaks into every later module there."""
        offenders = sorted(p.name for p in TESTS.glob("test_*.py")
                           if "addModuleCleanup(" in p.read_text(encoding="utf-8")
                           and p.name != Path(__file__).name)
        self.assertEqual(offenders, [], "undo module-level patches in tearDownModule")

    def test_a_read_under_the_real_home_is_refused_and_recorded(self):
        probe = os.path.join(fx.REAL_HOME, ".actualis-isolation-probe-does-not-exist")
        before = list(fx.LEAKS)
        try:
            with self.assertRaises(PermissionError):
                open(probe, encoding="utf-8")
            with self.assertRaises(PermissionError):
                os.listdir(os.path.join(fx.REAL_HOME, ".claude-isolation-probe"))
            self.assertEqual(len(fx.LEAKS), len(before) + 2)
        finally:
            fx.LEAKS[:] = before          # the probe is not a leak; keep the run green

    def test_the_repo_and_temp_dirs_stay_readable(self):
        before = list(fx.LEAKS)
        (ROOT / "actualis.py").open(encoding="utf-8").close()
        with tempfile.TemporaryDirectory() as td:
            Path(td, "x").write_text("x")
            os.listdir(td)
        self.assertEqual(fx.LEAKS, before)

    def test_a_scan_with_no_root_reads_nothing_real(self):
        """The paths that used to reach the real home: every Fleet() (two
        suppression files) and --self-check without --root (~/.claude/projects)."""
        before = list(fx.LEAKS)
        f = af.Fleet()
        self.assertEqual(f.suppressions, {})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            af.self_check(af.C(False), days=1)
        self.assertEqual(fx.LEAKS, before)

    def test_no_test_so_far_touched_the_real_home(self):
        # The atexit report fails the whole run on a leak; this names it early
        # for the modules that ran before this one.
        self.assertEqual(fx.LEAKS, [])


class _FrozenClock:
    """actualis's datetime, with now() fixed `days` after PRICING_VERIFIED."""

    def __init__(self, days):
        base = af.datetime.strptime(af.PRICING_VERIFIED, "%Y-%m-%d").replace(tzinfo=af.timezone.utc)
        moment = base + timedelta(days=days, hours=12)
        real = af.datetime

        class Frozen(real):
            @classmethod
            def now(cls, tz=None):
                return moment if tz else moment.replace(tzinfo=None)
        self.patch = mock.patch.object(af, "datetime", Frozen)

    def __enter__(self):
        return self.patch.__enter__()

    def __exit__(self, *exc):
        return self.patch.__exit__(*exc)


class TestNoDateBomb(unittest.TestCase):
    """R3E4: once the rate table is 90 days old, AF013 joins every coach() run.
    Tests that expect no findings must not start failing on that date."""

    CASES = [("TestCoach", "test_silent_on_an_unremarkable_fleet"),
             ("TestCorrectnessFindings", "test_af013_fires_only_when_the_table_is_stale"),
             ("TestUnreadableCommands", "test_it_is_counted_and_never_flagged")]

    def test_the_clock_really_is_moved(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1000}, None)
        with _FrozenClock(400):
            self.assertEqual(af.pricing_age_days(), 400)
            self.assertIn("AF013", [x.id for x in af.coach(f)])

    def test_no_findings_cases_pass_400_days_after_verification(self):
        for days in (0, 400):
            for cls, name in self.CASES:
                with self.subTest(days=days, test=name), _FrozenClock(days):
                    result = unittest.TestResult()
                    getattr(ta, cls)(name).run(result)
                    self.assertEqual(result.failures + result.errors, [], (days, name))
                    self.assertEqual(result.testsRun, 1)


class TestTimingHelpers(unittest.TestCase):
    """R3E2/R3E3: robust under load, and still a real check."""

    @staticmethod
    def _work(text):
        n = 0
        for _ in text:
            n += 1
        return n

    def test_a_linear_function_passes(self):
        _timing.assert_linear(self, self._work, [("", "x", 20000, "")], ceiling=1.0)

    def test_a_quadratic_function_fails(self):
        def quadratic(text):
            n = len(text) // 40
            return sum(1 for _ in range(n) for _ in range(n))
        with mock.patch.object(_timing, "MIN_SAMPLE", 0.005), \
                self.assertRaises(AssertionError) as cm:
            _timing.assert_linear(self, quadratic, [("", "x", 4000, "")], ceiling=10.0, epsilon=0.0)
        self.assertIn("4n is not ~4x n", str(cm.exception))

    def test_short_calls_are_sampled_long_enough(self):
        calls = []

        def fn(text):
            calls.append(len(text))
        _timing.assert_linear(self, fn, [("", "x", 10, "")], ceiling=1.0)
        # one warm-up call, then repeated samples: far more than the six calls
        # of a plain best-of-three, so each sample outlasts a scheduler quantum
        self.assertGreater(len(calls), 100)

    def test_ceilings_keep_five_times_headroom(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CI", None)
            self.assertGreaterEqual(_timing.budget(1.0), 5.0)
            os.environ["CI"] = "1"
            self.assertGreaterEqual(_timing.budget(1.0), 2 * 5.0)

    def test_no_test_hard_codes_a_wall_clock_ceiling(self):
        """Timing ceilings go through _timing (clock() and budget()), so one
        place decides how a busy or slow machine is allowed for."""
        offenders = []
        for p in TESTS.glob("test_*.py"):
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if "perf_counter" + "()" in line:
                    offenders.append(f"{p.name}:{n}")
        self.assertEqual(offenders, [])


class TestScannerExclusionsAreDocumented(unittest.TestCase):
    """R3E8: whatever the secret scanners skip, SECURITY.md and CONTRIBUTING.md say so."""

    def test_agentfleet_history_is_documented(self):
        gitleaks = (ROOT / "tools" / "security" / "gitleaks.toml").read_text(encoding="utf-8")
        truffle = (ROOT / "tools" / "security" / "trufflehog-exclude.txt").read_text(encoding="utf-8")
        if "agentfleet" not in gitleaks + truffle:
            self.skipTest("agentfleet.py is no longer excluded")
        for doc in ("SECURITY.md", "CONTRIBUTING.md"):
            text = (ROOT / doc).read_text(encoding="utf-8")
            self.assertIn("agentfleet.py", text, doc)
            self.assertNotRegex(text, r"skip only the invented fixtures", doc)


if __name__ == "__main__":
    unittest.main()
