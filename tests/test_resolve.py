"""Resolving findings (#97): false positive, rotated, accepted, expected,
with a reason and an optional expiry.

Every fixture is synthetic and built here: an invented token, an invented
address on an invented domain, and ids computed from them at runtime.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
sys.modules["actualis"] = af
spec.loader.exec_module(af)
af.SRC_TEXT = (ROOT / "actualis.py").read_text(encoding="utf-8")
af.SRC_PATH = ROOT / "actualis.py"

TOKEN_CMD = "export API_TOKEN=notarealtokenjustafixture97"
EMAIL = "robin.fixture@mailbox-demo.net"  # pii-ok: invented address the detector under test must find
BEFORE = datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
ROTATED_AT = "2026-08-01T12:00:00Z"
AFTER = datetime(2026, 8, 2, 9, 0, tzinfo=timezone.utc)
FUTURE = (date.today() + timedelta(days=30)).isoformat()
PAST = (date.today() - timedelta(days=3)).isoformat()


class ResolveCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self._tmp.name})
        self._env.start()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)          # no project file from elsewhere

    def tearDown(self):
        os.chdir(self._cwd)
        self._env.stop()
        self._tmp.cleanup()

    def user_file(self) -> Path:
        return af.suppression_paths()[0]

    def write(self, *lines: str) -> None:
        path = self.user_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def fleet_with_token(*times):
        f = af.Fleet()
        for ts in times:
            f.add_tool("proj", "Bash", {"command": TOKEN_CMD}, ts)
        return f

    def token_id(self) -> str:
        return next(iter(self.fleet_with_token(BEFORE).secrets))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = af.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


class TestOldFilesReadUnchanged(ResolveCase):

    def test_a_pre_resolve_file_loads_as_before(self):
        self.write("# actualis suppressions", "",
                   "a1b2c3d4  test fixture in CI config  (added 2026-01-02)",
                   "E5F6A7B8\tspaced reason",
                   "0badc0de")
        self.assertEqual(af.load_suppressions(),
                         {"a1b2c3d4": "test fixture in CI config",
                          "e5f6a7b8": "spaced reason", "0badc0de": "(no reason given)"})
        res = af.load_resolutions()
        self.assertEqual({e["disposition"] for e in res.values()}, {"false-positive"})
        self.assertEqual(res["a1b2c3d4"]["added"], "2026-01-02")

    def test_suppress_still_writes_the_old_line(self):
        path = af.add_suppression("a41f9c02", "vendor example key")
        last = path.read_text(encoding="utf-8").splitlines()[-1]
        self.assertRegex(last, r"^a41f9c02  vendor example key  \(added \d{4}-\d{2}-\d{2}\)$")

    def test_resolve_as_false_positive_is_the_same_line(self):
        path = af.add_resolution("a41f9c02", "false-positive", "vendor example key")
        self.assertNotIn("[", path.read_text(encoding="utf-8").splitlines()[-1])


class TestTheFile(ResolveCase):

    def test_each_disposition_round_trips(self):
        af.add_resolution("11111111", "rotated", "replaced in the vault")
        af.add_resolution("22222222", "accepted", "sandbox key", until=FUTURE)
        af.add_resolution("33333333", "expected", "own address")
        af.add_resolution("44444444", "false-positive", "a hash, not a key")
        body = self.user_file().read_text(encoding="utf-8")
        self.assertRegex(body, r"11111111  \[rotated\]  replaced in the vault  "
                               r"\(added \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\)")
        self.assertIn(f"22222222  [accepted until {FUTURE}]  sandbox key", body)
        res = af.load_resolutions()
        self.assertEqual({fp: e["disposition"] for fp, e in res.items()},
                         {"11111111": "rotated", "22222222": "accepted",
                          "33333333": "expected", "44444444": "false-positive"})
        self.assertEqual(res["22222222"]["until"].isoformat(), FUTURE)
        self.assertEqual(res["11111111"]["reason"], "replaced in the vault")
        self.assertIsNotNone(res["11111111"]["at"])

    def test_the_last_line_for_an_id_wins(self):
        af.add_suppression("55555555", "first thought")
        af.add_resolution("55555555", "rotated", "on reflection, real; replaced")
        self.assertEqual(af.load_resolutions()["55555555"]["disposition"], "rotated")

    def test_an_expired_resolution_no_longer_holds(self):
        self.write(f"66666666  [accepted until {PAST}]  short-lived  (added 2026-01-01T00:00:00Z)",
                   f"77777777  [expected until {FUTURE}]  still fine  (added 2026-01-01T00:00:00Z)")
        live = af.load_suppressions()
        self.assertNotIn("66666666", live)
        self.assertIn("77777777", live)
        self.assertIn("66666666", af.load_resolutions())     # kept for --suppressions

    def test_an_until_that_is_not_a_date_is_rejected_not_loaded(self):
        self.write("88888888  [accepted until someday]  vague  (added 2026-01-01T00:00:00Z)")
        rejected = []
        self.assertNotIn("88888888", af.load_resolutions(rejected))
        self.assertEqual(len(rejected), 1)

    def test_refusals(self):
        cases = [
            (("99999999", "rotated", "x", FUTURE), "rotated"),
            (("99999999", "accepted", "x", PAST), "already passed"),
            (("99999999", "accepted", "x", "31/12/2026"), "YYYY-MM-DD"),
            (("99999999", "ignored", "x", None), "--as takes"),
            (("99999999", "rotated", "ok\n620e24b6 x", None), "one line"),
            (("not-an-id", "rotated", "x", None), "not an id"),
        ]
        for args, msg in cases:
            with self.subTest(args=args), self.assertRaises(ValueError) as cm:
                af.add_resolution(*args)
            self.assertIn(msg, str(cm.exception))
        with self.assertRaises(af.AuditConfigId):
            af.add_resolution(af.AUDIT_CONFIG_ID, "accepted", "x")
        self.assertFalse(self.user_file().exists())

    def test_only_the_id_is_written(self):
        fp = self.token_id()
        path = af.add_resolution(fp, "rotated", "replaced")
        body = path.read_text(encoding="utf-8")
        self.assertNotIn("notarealtokenjustafixture97", body)
        self.assertIn(fp, body)


class TestRotated(ResolveCase):

    def resolve_rotated(self, fp):
        self.write(f"{fp}  [rotated]  replaced in the vault  (added {ROTATED_AT})")

    def test_sightings_before_the_rotation_leave_the_list(self):
        fp = self.token_id()
        self.resolve_rotated(fp)
        f = self.fleet_with_token(BEFORE)
        self.assertEqual(f.actionable_secrets, {})
        row = af.to_json(f)["secrets"][0]
        self.assertEqual((row["suppressed"], row["disposition"], row["seen_after_rotation"]),
                         (True, "rotated", False))

    def test_a_sighting_after_the_rotation_is_a_new_finding(self):
        fp = self.token_id()
        self.resolve_rotated(fp)
        f = self.fleet_with_token(BEFORE, AFTER)
        self.assertIn(fp, f.actionable_secrets)
        row = af.to_json(f)["secrets"][0]
        self.assertEqual((row["suppressed"], row["disposition"], row["seen_after_rotation"]),
                         (False, None, True))
        self.assertIn("seen again after rotation", row["suppressed_reason"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            af.render(f, af.C(False), bash_only=True, top=12)
        self.assertIn("seen again after rotation", out.getvalue())

    def test_a_date_only_rotation_covers_that_whole_day(self):
        fp = self.token_id()
        self.write(f"{fp}  [rotated]  by hand  (added 2026-08-01)")
        self.assertEqual(self.fleet_with_token(BEFORE).actionable_secrets, {})
        self.assertIn(fp, self.fleet_with_token(AFTER).actionable_secrets)


class TestAcceptedAndExpected(ResolveCase):

    def test_accepted_until_a_future_date_holds_and_is_reported(self):
        fp = self.token_id()
        af.add_resolution(fp, "accepted", "sandbox only", until=FUTURE)
        f = self.fleet_with_token(BEFORE)
        self.assertEqual(f.actionable_secrets, {})
        payload = af.to_json(f)
        self.assertEqual(payload["secrets"][0]["disposition"], "accepted")
        self.assertEqual(payload["suppressed_secrets"], 1)      # still counted
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            af.render(f, af.C(False), bash_only=True, top=12)
        self.assertIn("1 resolved (1 accepted)", out.getvalue())

    def test_an_expired_acceptance_is_actionable_again(self):
        fp = self.token_id()
        self.write(f"{fp}  [accepted until {PAST}]  was fine  (added 2026-01-01T00:00:00Z)")
        f = self.fleet_with_token(BEFORE)
        self.assertIn(fp, f.actionable_secrets)
        self.assertIsNone(af.to_json(f)["secrets"][0]["disposition"])

    def test_expected_personal_data_on_screen_stays_counted(self):
        f = af.Fleet()
        f.add_tool_result("proj", "mcp__playwright__browser_snapshot",
                          f"Signed in as {EMAIL}", BEFORE, session="s1", call_id="c1")
        fp = af.screen_json(f)["findings"][0]["id"]
        af.add_resolution(fp, "expected", "my own address on my own account page")
        f = af.Fleet()
        f.add_tool_result("proj", "mcp__playwright__browser_snapshot",
                          f"Signed in as {EMAIL}", BEFORE, session="s1", call_id="c1")
        screen = af.screen_json(f)
        self.assertEqual(screen["personal_data"], 1)
        self.assertEqual(screen["resolved"], 1)
        self.assertEqual(screen["findings"][0]["disposition"], "expected")
        self.assertEqual(af.resolved_note(Counter(expected=1)), ", 1 resolved (1 expected)")


class TestCli(ResolveCase):

    def test_resolve_writes_and_says_what_happens_next(self):
        code, out, _ = self.run_cli("--resolve", "1a2b3c4d", "--as", "rotated",
                                    "--reason", "replaced in the vault")
        self.assertEqual(code, 0)
        self.assertIn("resolved 1a2b3c4d as rotated", out)
        self.assertIn("comes back as a new finding", out)
        self.assertEqual(af.load_resolutions()["1a2b3c4d"]["disposition"], "rotated")

    def test_resolve_with_until(self):
        code, out, _ = self.run_cli("--resolve", "1a2b3c4d", "--as", "expected",
                                    "--reason", "own address", "--until", FUTURE)
        self.assertEqual(code, 0)
        self.assertIn(f"through {FUTURE}", out)

    def test_misuse_is_refused_before_anything_is_written(self):
        for argv, msg in [
            (("--resolve", "1a2b3c4d"), "--resolve needs --as"),
            (("--as", "rotated"), "--as applies only to --resolve"),
            (("--until", FUTURE), "--until applies only"),
            (("--suppress", "1a2b3c4d", "--until", FUTURE), "--until applies only"),
            (("--resolve", "1a2b3c4d", "--as", "rotated", "--json"), "--json cannot"),
            (("--resolve", "1a2b3c4d", "--as", "rotated", "--fail-on", "high"), "--fail-on cannot"),
            (("--resolve", "1a2b3c4d", "--as", "rotated", "--suppressions"), "cannot be combined"),
            (("--resolve", "1a2b3c4d", "--as", "rotated", "--until", FUTURE), "rotated"),
            (("--resolve", "1a2b3c4d", "--as", "nonsense"), "invalid choice"),
            (("--resolve", af.AUDIT_CONFIG_ID, "--as", "accepted"), "audit-config"),
        ]:
            with self.subTest(argv=argv):
                code, _, err = self.run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertIn(msg, err)
        self.assertFalse(self.user_file().exists())

    def test_suppressions_lists_by_disposition(self):
        self.write("a1b2c3d4  legacy reason  (added 2026-01-02)",
                   "b2c3d4e5  [rotated]  replaced  (added 2026-08-01T12:00:00Z)",
                   f"c3d4e5f6  [accepted until {PAST}]  was fine  (added 2026-01-01T00:00:00Z)")
        code, out, _ = self.run_cli("--suppressions")
        self.assertEqual(code, 0)
        self.assertLess(out.index("false positive (1)"), out.index("rotated (1)"))
        self.assertLess(out.index("rotated (1)"), out.index("accepted (1)"))
        self.assertIn("added 2026-08-01 12:00:00 UTC", out)
        self.assertIn(f"until {PAST}, expired", out)


class TestTripwire(unittest.TestCase):
    """An agent that resolves its own findings is the edit audit-config reports."""

    def test_resolve_is_a_write_of_the_suppressions_file(self):
        for cmd in ("actualis --resolve 1a2b3c4d --as rotated --reason x",
                    "python3 actualis.py --resolve=1a2b3c4d --as expected",
                    "uvx actualis --resolve 1a2b3c4d --as accepted --until 2030-01-01",
                    "env A=1 actualis --suppress 1a2b3c4d"):
            with self.subTest(cmd=cmd):
                self.assertTrue(af.writes_audit_config(cmd))

    def test_other_actualis_runs_are_not(self):
        for cmd in ("actualis --json --days 7", "actualis --explain suppressions"):
            with self.subTest(cmd=cmd):
                self.assertFalse(af.writes_audit_config(cmd))


class TestJsonSchema(ResolveCase):

    def test_new_keys_are_declared_and_the_version_is_unchanged(self):
        self.assertEqual(af.JSON_SCHEMA_VERSION, 1)
        for key, typ in (("secrets[].disposition", "str|null"),
                         ("secrets[].seen_after_rotation", "bool"),
                         ("bash.flags[].disposition", "str|null"),
                         ("screen.findings[].disposition", "str|null"),
                         ("screen.resolved", "int")):
            self.assertEqual(af.JSON_SCHEMA.get(key), typ)

    def test_a_resolved_flag_carries_its_disposition(self):
        f = af.Fleet()
        f.add_tool("proj", "Bash", {"command": "rm -rf build"}, BEFORE)
        flags = af.to_json(f)["bash"]["flags"]
        if not flags:
            self.skipTest("rm -rf build is not flagged in this build")
        af.add_resolution(flags[0]["id"], "expected", "build output")
        f = af.Fleet()
        f.add_tool("proj", "Bash", {"command": "rm -rf build"}, BEFORE)
        row = next(r for r in af.to_json(f)["bash"]["flags"] if r["id"] == flags[0]["id"])
        self.assertEqual((row["suppressed"], row["disposition"]), (True, "expected"))


if __name__ == "__main__":
    unittest.main()
