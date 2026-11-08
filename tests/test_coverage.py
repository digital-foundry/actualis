"""Coverage ledger, finding assessments, assumptions, rejected leads and
transcript retention (0.7.0).

Synthetic data only. Every transcript and every settings.json here is written
by the test under a temporary HOME; nothing reads a real agent directory.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    _spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(_spec)
    sys.modules["actualis"] = af
    _spec.loader.exec_module(af)

TS = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
DEFAULT = {"assessment": "confirmed", "basis": "observed", "missing": None}


def recent(hours=1):
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def assistant(mid, ts, command=None, model="claude-sonnet-5"):
    """One Claude Code assistant record with usage, and a Bash call when
    `command` is given."""
    msg = {"id": mid, "model": model, "role": "assistant",
           "usage": {"input_tokens": 10, "output_tokens": 5,
                     "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}
    if command is not None:
        msg["content"] = [{"type": "tool_use", "id": "call-" + mid, "name": "Bash",
                           "input": {"command": command}}]
    return json.dumps({"timestamp": ts.isoformat(), "type": "assistant", "uuid": "u-" + mid,
                       "sessionId": "s1", "gitBranch": "main", "message": msg})


def write_session(project_dir, name="s.jsonl", lines=(), mtime=None):
    project_dir.mkdir(parents=True, exist_ok=True)
    path = project_dir / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if mtime is not None:
        os.utime(path, (mtime.timestamp(), mtime.timestamp()))
    return path


def run_main(*argv):
    """main() as _cli() runs it: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    af._PENDING_GATE[:] = []
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = af.main(list(argv))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def walk(node, path=""):
    """(path, type) for every leaf, as TestJSONSchemaFreeze._walk."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        out.append((path, "array"))
        for item in node:
            out += walk(item, path + "[]")
    elif isinstance(node, bool):
        out.append((path, "bool"))
    elif node is None:
        out.append((path, "null"))
    else:
        out.append((path, type(node).__name__))
    return out


def declared(path):
    """The JSON_SCHEMA type for a concrete path, `*` standing in for a data
    key, as TestJSONSchemaFreeze._declared."""
    if path in af.JSON_SCHEMA:
        return af.JSON_SCHEMA[path]
    parts = path.split(".")
    for mask in range(1, 1 << len(parts)):
        cand = ".".join(("*[]" if p.endswith("[]") else "*") if mask >> i & 1 else p
                        for i, p in enumerate(parts))
        if cand in af.JSON_SCHEMA:
            return af.JSON_SCHEMA[cand]
    return None


def schema_drift(payload):
    """Every leaf of payload that JSON_SCHEMA does not declare, or declares
    with another type."""
    bad = []
    for path, actual in walk(payload):
        want = declared(path)
        if want is None:
            bad.append(f"{path}: undeclared")
            continue
        allowed = set(want.split("|"))
        if actual not in allowed and not (actual == "int" and "float" in allowed):
            bad.append(f"{path}: declared {want}, got {actual}")
    return bad


class HomeCase(unittest.TestCase):
    """A fresh temp HOME per test, the cwd inside it, and today's prices
    (AF013 is about the date, not about these fixtures)."""

    def setUp(self):
        self._home = fx.isolated_home()
        self.home = self._home.__enter__()
        self._cwd = os.getcwd()
        os.chdir(self.home)
        self._prices = fx.fresh_prices(af)
        self._prices.start()
        self.projects = self.home / ".claude" / "projects"

    def tearDown(self):
        self._prices.stop()
        os.chdir(self._cwd)
        self._home.__exit__(None, None, None)

    def claude(self, *lines, project="-home-dev-orbital", name="s.jsonl", mtime=None):
        return write_session(self.projects / project, name, lines, mtime)

    def settings(self, text):
        path = self.home / ".claude" / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path


def assessed_fleet():
    """A fleet with a flag from every producer (shell rule, oversized,
    audit-config, strict network, IOC match and unresolved, reputation listed,
    candidate and stale), a critical credential (AF004) and invisible
    subagent shell work (AF011)."""
    f = af.Fleet()
    f.suppressions = {}
    for cmd in ("rm -rf /tmp/build",
                "export STRIPE_SECRET_KEY=sk_live_" + "a" * 30,
                "echo " + "x" * (af.MAX_SCAN_TOTAL + 10),
                "echo x >> .actualis-suppressions",
                "curl -sO https://a.example/x",
                "curl -sO https://b.example/y",
                "npm i evil@1.0.0",
                "npm i pending"):
        f.add_tool("proj", "Bash", {"command": cmd}, TS, "auto")
    f.add_subagent({"toolStats": {"bashCount": 50}, "resolvedModel": "claude-haiku-4-5",
                    "totalDurationMs": 1000, "totalLines": 10, "status": "ok"}, TS)
    af.apply_network_policy(f, af.parse_trust([]), strict=True)
    ioc = af.IocSet()
    ioc.sources.append(af._ioc_source(Path("iocs.txt")))
    ioc.mtimes.append(0.0)
    af.parse_ioc_lines(af._ioc_lines(b"npm:evil@=1.0.0\nnpm:pending@=2.0.0\n"), ioc, 0, "iocs.txt")
    af.apply_ioc(f, ioc)
    a, b = af.sb_hash("a.example/"), af.sb_hash("b.example/")
    old = TS - timedelta(days=30)
    rep = af.ReputationData()
    rep.status = "ok"
    rep.lists = {name: b"" for name in af.REPUTATION_LISTS}
    rep.lists["mw-4b"] = b"".join(sorted([a[:4], b[:4]]))
    rep.state = {name: {"fetched_at": old, "next_update_at": old, "prefix_count": 0, "version": None}
                 for name in af.REPUTATION_LISTS}
    rep.oldest = old
    rep.confirmations = {a[:4]: {"full_hashes": [{"hash": a, "threat_types": ["MALWARE"], "canary": False}],
                                 "confirmed_at": TS, "cache_until": TS + timedelta(days=1)}}
    af.apply_reputation(f, rep, TS + timedelta(minutes=1))
    return f


def finding_rows(payload):
    return (payload["bash"]["flags"] + payload["coach"] + payload["secrets"]
            + payload["network"]["ioc"]["matches"] + payload["network"]["reputation"]["candidates"])


class TestAssessments(unittest.TestCase):
    """Task 1: one classifier table, applied to every finding at output time."""

    def test_the_table_keeps_its_invariant(self):
        for key, (assessment, basis, missing) in af._ASSESSMENT.items():
            with self.subTest(key=key):
                self.assertIn(assessment, af.ASSESSMENTS)
                self.assertIn(basis, af.BASES)
                if assessment == "needs-validation":
                    self.assertTrue(missing)
                else:
                    self.assertIsNone(missing)

    def test_every_emitted_category_and_finding_id_has_an_entry(self):
        f = assessed_fleet()
        emitted = {c for fl in f.flags for c in fl["categories"]}
        self.assertTrue({"destructive", "oversized-command", "audit-config", "network-unasked",
                         "network-ioc", "network-ioc-unresolved", "reputation-listed",
                         "reputation-candidate", "reputation-stale"} <= emitted, emitted)
        every = (emitted | {c for _s, c, _r in af.COMPILED_RULES} | set(af.REPUTATION_FLAG_CATEGORIES)
                 | {"network-config", "secret"} | set(af.COACH_FINDING_IDS))
        self.assertEqual(sorted(every - set(af._ASSESSMENT)), [])

    def test_every_finding_row_carries_the_three_fields(self):
        payload = af.to_json(assessed_fleet())
        rows = finding_rows(payload)
        self.assertGreater(len(rows), 10)
        for r in rows:
            with self.subTest(row=r.get("id") or r.get("verdict") or r.get("prefix_b64")):
                self.assertIn(r["assessment"], af.ASSESSMENTS)
                self.assertIn(r["basis"], af.BASES)
                if r["assessment"] == "needs-validation":
                    self.assertTrue(r["missing"])
                else:
                    self.assertIsNone(r["missing"])

    def test_each_producer_gets_its_row_of_the_table(self):
        payload = af.to_json(assessed_fleet())
        by_cat = {fl["categories"][0]: fl for fl in payload["bash"]["flags"]}
        self.assertEqual(by_cat["destructive"]["assessment"], "confirmed")
        self.assertEqual(by_cat["oversized-command"]["missing"],
                         "command longer than what is read; the rest was not checked")
        self.assertEqual(by_cat["network-ioc"]["assessment"], "confirmed")
        self.assertEqual((by_cat["network-ioc-unresolved"]["assessment"],
                          by_cat["network-ioc-unresolved"]["missing"]),
                         ("needs-validation", "version not resolved"))
        self.assertEqual(by_cat["reputation-listed"]["assessment"], "confirmed")
        self.assertEqual(by_cat["reputation-candidate"]["missing"],
                         "local hash-prefix match; run actualis-reputation confirm")
        self.assertEqual(by_cat["reputation-stale"]["missing"], "lists are 30 days old")
        coach = {c["id"]: c for c in payload["coach"]}
        self.assertEqual(coach["AF011"]["missing"], "agent writes no shell records")
        self.assertEqual(coach["AF004"]["assessment"], "confirmed")
        self.assertEqual(payload["secrets"][0]["assessment"], "confirmed")
        matches = {m["verdict"]: m for m in payload["network"]["ioc"]["matches"]}
        self.assertEqual(matches["match"]["missing"], None)
        self.assertEqual(matches["unresolved"]["missing"], "version not resolved")
        [cand] = payload["network"]["reputation"]["candidates"]
        self.assertEqual(cand["assessment"], "needs-validation")

    def test_af002_is_inferred(self):
        self.assertEqual(af.assessment_of("AF002"),
                         {"assessment": "confirmed", "basis": "inferred", "missing": None})

    def test_a_name_read_from_a_url_is_inferred(self):
        self.assertEqual(af._ioc_assessment("unresolved", "name-from-url"),
                         {"assessment": "needs-validation", "basis": "inferred",
                          "missing": "name from URL"})
        self.assertEqual(af._ioc_assessment("match", "host"), DEFAULT)

    def test_an_unknown_shape_gets_the_default_triple(self):
        for row in (None, 42, "AF999", [], {}, {"categories": "destructive"},
                    {"categories": ["never-seen"]}, {"verdict": None}, {"id": "AF999"},
                    {"categories": [["nested"]]}, object()):
            with self.subTest(row=row):
                self.assertEqual(af.classify(row), DEFAULT)

    def test_a_producer_set_value_wins_over_the_table(self):
        row = {"categories": ["oversized-command"], "assessment": "confirmed",
               "basis": "inferred", "missing": None}
        self.assertEqual(af.classify(row), {"assessment": "confirmed", "basis": "inferred",
                                            "missing": None})

    def test_a_flag_is_as_uncertain_as_its_least_certain_category(self):
        row = {"categories": ["destructive", "oversized-command"]}
        self.assertEqual(af.classify(row)["assessment"], "needs-validation")

    def test_severity_is_unchanged(self):
        f = assessed_fleet()
        before = [(fl["id"], fl["severity"]) for fl in f.flags]
        payload = af.to_json(f)
        self.assertEqual([(fl["id"], fl["severity"]) for fl in payload["bash"]["flags"]], before)

    def test_mcp_coach_findings_carry_the_fields(self):
        cache = mock.Mock(fleet=lambda *a: assessed_fleet())
        rows = af._mcp_call("coach_findings", {}, cache)["findings"]
        af011 = next(r for r in rows if r["id"] == "AF011")
        self.assertEqual((af011["assessment"], af011["missing"]),
                         ("needs-validation", "agent writes no shell records"))

    def test_the_new_paths_are_declared_with_their_types(self):
        self.assertEqual(schema_drift(af.to_json(assessed_fleet())), [])

    def test_the_fields_are_documented(self):
        doc = (ROOT / "docs" / "json.md").read_text(encoding="utf-8")
        for word in ("## Assessments", "`assessment`", "`basis`", "`missing`",
                     "`needs-validation`", "`inferred`"):
            self.assertIn(word, doc)


class TestCoverageCounters(HomeCase):
    """Task 2: files read, unreadable and skipped, per agent, and lines decoded."""

    def test_claude_files_read_unreadable_and_skipped(self):
        proj = self.projects / "-home-dev-orbital"
        good = write_session(proj, "a.jsonl", [assistant("m1", recent()),
                                               '{"type": "summary"}', '{"usage": 1,'])
        old = recent(24 * 30)
        write_session(proj, "old.jsonl", [assistant("m0", old)], mtime=old)
        (proj / "broken.jsonl").mkdir()                  # stat works, open does not
        f = af.Fleet()
        f.scan([self.projects], af.window_start(7), None, progress=False)
        row = f.agent_roots["claude-code"]
        self.assertEqual((row["files_read"], row["files_unreadable"], row["files_skipped_mtime"]),
                         (1, 1, 1))
        self.assertEqual((f.files_unreadable, f.files_skipped_mtime), (1, 1))
        self.assertEqual(f.lines_read, 2)                # the summary line is never decoded
        self.assertEqual(f.unparsable_lines, 1)
        self.assertEqual(row["oldest_mtime"], good.stat().st_mtime)
        self.assertEqual(sorted(len(v) for v in row["mtimes"].values()), [2])
        self.assertEqual(f.files_scanned, 2)              # unchanged: past the prefilter, opened or not

    def test_every_agent_counts_a_file_it_cannot_open(self):
        codex = self.home / "codex"
        (codex / "2026" / "rollout-1.jsonl").mkdir(parents=True)
        copilot = self.home / "copilot"
        (copilot / "sid" / "events.jsonl").mkdir(parents=True)
        log = self.home / "ci-log.json"
        log.mkdir()
        f = af.Fleet()
        f.scan_codex([codex], None, None)
        f.scan_copilot([copilot], None, None)
        f.scan_execution_log(log, "ci", None)
        self.assertEqual({a: r["files_unreadable"] for a, r in f.agent_roots.items()},
                         {"codex": 1, "copilot": 1, "claude-code": 1})
        self.assertEqual(f.files_unreadable, 3)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs POSIX permissions, as non-root")
    def test_a_file_without_read_permission_is_counted_not_dropped(self):
        qwen = self.home / "qwen" / "projects"
        gemini = self.home / "gemini" / "tmp"
        paths = [write_session(qwen / "-home-dev-orbital" / "chats", "s.jsonl", ['{"type": "user"}']),
                 write_session(gemini / "orbital" / "chats", "session-1.jsonl", ['{"sessionId": "x"}'])]
        for p in paths:
            p.chmod(0)
        try:
            f = af.Fleet()
            f.scan_qwen([qwen], None, None)
            f.scan_gemini([gemini], None, None)
        finally:
            for p in paths:
                p.chmod(0o600)
        self.assertEqual(f.agent_roots["qwen"]["files_unreadable"], 1)
        self.assertEqual(f.agent_roots["gemini"]["files_unreadable"], 1)
        self.assertEqual(f.agent_roots["qwen"]["files_read"], 0)

    def test_a_root_with_no_files_is_still_a_root(self):
        empty = self.home / "sessions"
        empty.mkdir()
        f = af.Fleet()
        f.scan_codex([empty], None, None)
        self.assertEqual(f.agent_roots["codex"]["files_read"], 0)
        self.assertTrue(f.agent_roots["codex"]["exists"])
        f.scan_copilot([], None, None)
        self.assertNotIn("copilot", f.agent_roots)

    def test_a_ci_log_is_one_file_read(self):
        log = self.home / "claude-execution-output.json"
        log.write_text("[" + assistant("m1", recent()) + "]", encoding="utf-8")
        f = af.Fleet()
        f.scan_execution_log(log, "ci", None)
        self.assertEqual(f.agent_roots["claude-code"]["files_read"], 1)


class TestRetention(HomeCase):
    """Task 3: cleanupPeriodDays from Claude Code's settings.json, one key."""

    def claude_retention(self):
        r = af.read_retention()["claude-code"]
        return r["retention_days"], r["retention_source"]

    def test_the_documented_cases(self):
        cases = (('{"cleanupPeriodDays": 14}', (14, "settings")),
                 ('{"theme": "dark"}', (30, "default")),
                 (None, (None, "unknown")),
                 ("{not json", (None, "unknown")),
                 ('{"cleanupPeriodDays": "14"}', (None, "unknown")),
                 ('{"cleanupPeriodDays": 0}', (0, "settings")))
        for text, want in cases:
            with self.subTest(text=text):
                path = self.home / ".claude" / "settings.json"
                if path.exists():
                    path.unlink()
                if text is not None:
                    self.settings(text)
                self.assertEqual(self.claude_retention(), want)

    def test_the_other_agents(self):
        r = af.read_retention()
        self.assertEqual(r["codex"], {"retention_days": None, "retention_source": "none"})
        for agent in ("copilot", "gemini", "qwen"):
            self.assertEqual(r[agent], {"retention_days": None, "retention_source": "unknown"})

    def test_odd_values_and_odd_files_are_unknown_never_an_error(self):
        for text in ("true", "[30]", '{"cleanupPeriodDays": true}', '{"cleanupPeriodDays": 14.0}',
                     '{"cleanupPeriodDays": -1}', '{"cleanupPeriodDays": null}', "",
                     b'\xff\xfe{"cleanupPeriodDays": 14}',
                     '{"cleanupPeriodDays": 14, "pad": "' + "x" * af.SETTINGS_MAX + '"}'):
            with self.subTest(text=text[:40]):
                self.settings(text)
                self.assertEqual(self.claude_retention(), (None, "unknown"))
        self.settings('{"cleanupPeriodDays": ' + "9" * 40 + "}")
        self.assertEqual(self.claude_retention(), (af.MAX_DAYS, "settings"))

    def test_a_directory_is_unknown(self):
        (self.home / ".claude" / "settings.json").mkdir(parents=True)
        self.assertEqual(self.claude_retention(), (None, "unknown"))

    @unittest.skipIf(os.name == "nt", "POSIX FIFOs and device files")
    def test_a_fifo_or_a_device_never_blocks(self):
        path = self.home / ".claude" / "settings.json"
        path.parent.mkdir(parents=True)
        os.mkfifo(path)
        self.assertEqual(self.claude_retention(), (None, "unknown"))
        path.unlink()
        os.symlink("/dev/zero", path)
        self.assertEqual(self.claude_retention(), (None, "unknown"))

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_a_symlink_to_a_regular_file_is_read(self):
        real = self.home / "dotfiles" / "claude-settings.json"
        real.parent.mkdir()
        real.write_text('{"cleanupPeriodDays": 60}', encoding="utf-8")
        (self.home / ".claude").mkdir()
        os.symlink(real, self.home / ".claude" / "settings.json")
        self.assertEqual(self.claude_retention(), (60, "settings"))

    def test_claude_config_dir_names_the_file(self):
        a, b = self.home / "cfg-a", self.home / "cfg-b"
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": f"{a}{os.pathsep}{b}"}):
            self.assertEqual(af.claude_settings_path(), a / "settings.json")
        self.assertEqual(af.claude_settings_path(), self.home / ".claude" / "settings.json")

    def test_it_is_read_once_per_run(self):
        self.claude(assistant("m1", recent(), command="git status"))
        for argv in (("--json",), ()):
            with self.subTest(argv=argv), \
                    mock.patch.object(af, "_claude_retention", wraps=af._claude_retention) as spy:
                code, _, err = run_main(*argv)
                self.assertEqual(code, af.EXIT_OK, err)
                self.assertEqual(spy.call_count, 1)

    def test_nothing_is_read_without_a_claude_root(self):
        f = af.Fleet()
        with mock.patch.object(af, "_claude_retention") as spy:
            af.coach(f)
            af.to_json(f)
        spy.assert_not_called()

    def test_self_check_lists_the_file(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.self_check(af.C(False), days=1)
        # The report wraps at 80 columns; a long temp path (Windows) moves the
        # break, so compare with the line breaks folded to spaces.
        out = " ".join(buf.getvalue().split())
        self.assertIn(str(af.claude_settings_path()), out)
        self.assertIn("one key", out)


class TestAF014(HomeCase):
    """Task 3: transcripts about to expire."""

    def fleet(self, settings='{"cleanupPeriodDays": 30}', age_days=25):
        if settings is not None:
            self.settings(settings)
        old = recent(24 * age_days)
        self.claude(assistant("m1", old), mtime=old)
        f = af.Fleet()
        f.scan(af.transcript_roots(), None, None, progress=False)
        return f

    def af014(self, f):
        return [x for x in af.coach(f) if x.id == "AF014"]

    def test_a_file_25_days_old_with_30_kept_fires(self):
        f = self.fleet()
        [hit] = self.af014(f)
        first = af._utc_date(next(self.projects.rglob("s.jsonl")).stat().st_mtime)
        self.assertEqual(hit.severity, "info")
        self.assertEqual(hit.title, "Transcripts are about to expire")
        self.assertEqual(hit.evidence, f"1 transcript file, the oldest from {first}, is deleted within 7 days "
                                       "(Claude Code keeps 30 days).")
        self.assertIn("cleanupPeriodDays", hit.action)
        self.assertIn("actualis --watch", hit.action)

    def test_the_default_period_counts_too(self):
        self.assertTrue(self.af014(self.fleet(settings='{"theme": "dark"}')))

    def test_no_settings_file_is_unknown_and_never_fires(self):
        self.assertEqual(self.af014(self.fleet(settings=None)), [])

    def test_a_recent_file_does_not_fire(self):
        self.assertEqual(self.af014(self.fleet(age_days=1)), [])

    def test_an_overdue_file_still_fires(self):
        self.assertTrue(self.af014(self.fleet(age_days=40)))

    def test_keeping_nothing_fires_for_a_fresh_file(self):
        self.assertTrue(self.af014(self.fleet(settings='{"cleanupPeriodDays": 0}', age_days=0)))

    def test_unknown_retention_never_fires(self):
        self.assertEqual(self.af014(self.fleet(settings="{not json")), [])

    def test_a_copy_read_with_root_never_fires(self):
        self.settings('{"cleanupPeriodDays": 30}')
        old = recent(24 * 25)
        archive = self.home / "archive"
        write_session(archive / "-home-dev-orbital", "s.jsonl", [assistant("m1", old)], mtime=old)
        f = af.Fleet()
        f.scan([archive], None, None, progress=False)
        self.assertEqual(af.transcripts_expiring(f), [])
        self.assertEqual(self.af014(f), [])

    def test_clock_edges_never_raise(self):
        self.settings('{"cleanupPeriodDays": 30}')
        self.projects.mkdir(parents=True)
        f = af.Fleet()
        f.roots.append(self.projects)
        now = datetime.now(timezone.utc).timestamp()
        f._file_read("claude-code", self.projects, now + 86400 * 400)   # dated in the future
        f._file_read("claude-code", self.projects, 1e20)                # out of range for a date
        self.assertEqual(af.transcripts_expiring(f), [])
        [(row, _first)] = af._coverage_agents(f)
        self.assertEqual(row["oldest"], af._utc_date(now + 86400 * 400))
        self.assertIsNone(af._utc_date(1e20))

    def test_af014_is_outside_the_digest_and_the_gate(self):
        f = self.fleet()
        payload = af.to_json(f)
        self.assertIn("AF014", [c["id"] for c in payload["coach"]])
        body = dict(payload)
        body["coach"] = [c for c in payload["coach"] if c["id"] != "AF014"]
        self.assertEqual(af.report_digest(body), payload["report_sha256"])
        self.assertEqual([r for r in af.failing_findings(f, "any") if r.startswith("AF014")], [])
        self.assertEqual(af.REPORT_DIGEST_CLOCK_FINDINGS, frozenset({"AF013", "AF014"}))

    def test_the_id_is_registered_and_documented(self):
        self.assertEqual(af.COACH_FINDING_IDS[-1], "AF014")
        self.assertEqual(af.assessment_of("AF014"),
                         {"assessment": "confirmed", "basis": "inferred", "missing": None})
        doc = (ROOT / "docs" / "findings.md").read_text(encoding="utf-8")
        self.assertIn("## AF014", doc)
        self.assertIn("[AF014](#af014)", doc)


class TestCoverageLedger(HomeCase):
    """Task 4: coverage(fleet), in --json."""

    def scanned(self):
        f = af.Fleet()
        f.scan(af.transcript_roots(), None, None, progress=False)
        return f

    def test_a_clean_run_is_complete(self):
        path = self.claude(assistant("m1", recent(), command="git status"))
        self.settings("{}")
        cov = af.coverage(self.scanned())
        self.assertEqual((cov["ok"], cov["gaps"]), (True, []))
        self.assertEqual(cov["agents"], [{
            "agent": "claude-code", "root_exists": True, "files_read": 1, "files_unreadable": 0,
            "dirs_unreadable": 0, "files_skipped_mtime": 0, "oldest": af._utc_date(path.stat().st_mtime),
            "retention_days": 30, "retention_source": "default", "expiring_7d": 0}])
        self.assertEqual([c["check"] for c in cov["checks"]], ["credentials", "shell", "records"])
        creds = cov["checks"][0]
        self.assertEqual((creds["examined"], creds["not_examined"], creds["why_not"]), (1, 0, {}))

    def test_an_empty_fleet_never_raises(self):
        cov = af.coverage(af.Fleet())
        self.assertEqual((cov["ok"], cov["agents"], cov["gaps"]), (True, [], []))
        f = af.Fleet()
        f._root_seen("codex")
        self.assertEqual(af.coverage(f)["gaps"], ["codex: no transcript file read"])

    def test_an_agent_named_without_a_root_is_listed(self):
        f = af.Fleet()
        f.scope["agent"] = "codex"
        [row] = af.coverage(f)["agents"]
        self.assertEqual((row["agent"], row["root_exists"], row["retention_source"]),
                         ("codex", False, "none"))
        self.assertEqual(af.coverage(f)["gaps"], [])

    def test_unreadable_and_oversized_commands_are_not_examined(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "$CMD"}, TS)
        f.add_tool("p", "Bash", {"command": "echo " + "x" * (af.MAX_SCAN_TOTAL + 10)}, TS)
        f.add_tool("p", "Bash", {"command": "git status"}, TS)
        creds = af.coverage(f)["checks"][0]
        self.assertEqual(creds, {"check": "credentials", "examined": 1, "not_examined": 2,
                                 "why_not": {"unreadable-command": 1, "oversized": 1}})

    def test_a_root_copy_has_unknown_retention(self):
        self.settings('{"cleanupPeriodDays": 30}')
        archive = self.home / "archive"
        write_session(archive / "-home-dev-orbital", "s.jsonl", [assistant("m1", recent())])
        code, out, err = run_main("--root", str(archive), "--json")
        self.assertEqual(code, af.EXIT_OK, err)
        [row] = json.loads(out)["coverage"]["agents"]
        self.assertEqual((row["retention_days"], row["retention_source"]), (None, "unknown"))

    def test_expiring_7d_is_outside_the_digest(self):
        f = af.Fleet()
        f._file_read("claude-code", "r", TS.timestamp())
        payload = af.to_json(f)
        payload["coverage"]["agents"][0]["expiring_7d"] += 5
        self.assertEqual(af.report_digest(payload), payload["report_sha256"])
        payload["coverage"]["agents"][0]["files_read"] += 1
        self.assertNotEqual(af.report_digest(payload), payload["report_sha256"])

    def test_every_coverage_path_is_declared(self):
        self.claude(assistant("m1", recent(), command="npm install"),
                    assistant("m2", recent(), command="curl -sO https://files.example/x"))
        (self.projects / "-home-dev-orbital" / "broken.jsonl").mkdir()
        ioc = self.home / "bad.ioc"
        ioc.write_text("npm:left-pad\n", encoding="utf-8")
        code, out, err = run_main("--json", "--ioc", str(ioc))
        self.assertEqual(code, af.EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(schema_drift(payload), [])
        self.assertEqual([c["check"] for c in payload["coverage"]["checks"]],
                         ["credentials", "shell", "records", "network", "ioc"])

    def test_the_keys_are_documented(self):
        doc = (ROOT / "docs" / "json.md").read_text(encoding="utf-8")
        for word in ("## coverage", "`coverage`", "`retention_source`", "`expiring_7d`",
                     "`files_skipped_mtime`", "exit 5", ".coverage.agents[].expiring_7d"):
            self.assertIn(word, doc)


class TestFailOnCoverage(HomeCase):
    """Task 4: each gap, exit 5 with --fail-on-coverage, 0 without, and 3 first."""

    def assertGap(self, argv, needle):
        code, out, err = run_main(*argv, "--json")
        self.assertEqual(code, af.EXIT_OK, err)
        cov = json.loads(out)["coverage"]
        self.assertFalse(cov["ok"])
        self.assertTrue(any(needle in g for g in cov["gaps"]), cov["gaps"])
        code, out2, err = run_main(*argv, "--json", "--fail-on-coverage")
        self.assertEqual(code, af.EXIT_COVERAGE, err)
        self.assertIn("actualis: FAIL at --fail-on-coverage", err)
        self.assertIn(needle, err)
        self.assertEqual(json.loads(out2)["coverage"], cov)      # the payload is unchanged

    def test_gap_1_a_root_with_nothing_read(self):
        self.claude(assistant("m1", recent()))
        (self.home / ".codex" / "sessions").mkdir(parents=True)
        self.assertGap([], "codex: no transcript file read")

    def test_gap_1_names_what_the_window_left_out(self):
        self.claude(assistant("m1", recent()))
        old = recent(24 * 30)
        write_session(self.home / ".codex" / "sessions" / "2026", "rollout-1.jsonl", ["{}"], mtime=old)
        self.assertGap(["--days", "7"], "codex: no transcript file read (1 older than --days 7 skipped)")

    def test_gap_2_an_unreadable_file(self):
        self.claude(assistant("m1", recent()))
        (self.projects / "-home-dev-orbital" / "broken.jsonl").mkdir()
        self.assertGap([], "1 transcript file could not be read (claude-code)")

    def test_gap_3_unparsable_lines_over_one_percent(self):
        self.claude(assistant("m1", recent()), '{"usage": 1,')
        self.assertGap([], "1 of 2 record lines could not be parsed (over 1%)")

    def test_gap_4_days_past_retention(self):
        self.settings('{"cleanupPeriodDays": 14}')
        self.claude(assistant("m1", recent()))
        self.assertGap(["--days", "30"], "asked for 30 days; Claude Code keeps 14")

    def test_gap_4_keeping_nothing_is_a_gap_for_any_days(self):
        self.settings('{"cleanupPeriodDays": 0}')
        self.claude(assistant("m1", recent()))
        # --days 2, not 1: recent() is an hour ago, which is yesterday in UTC
        # during the first hour after midnight, and --days counts UTC days.
        self.assertGap(["--days", "2"], "asked for 2 days; Claude Code keeps 0")

    def test_gap_4_needs_days_within_retention_to_pass(self):
        self.settings('{"cleanupPeriodDays": 14}')
        self.claude(assistant("m1", recent()))
        code, _, err = run_main("--json", "--days", "14", "--fail-on-coverage")
        self.assertEqual(code, af.EXIT_OK, err)

    def test_gap_5_downloads_the_ioc_list_cannot_check(self):
        ioc = self.home / "bad.ioc"
        ioc.write_text("npm:left-pad\n", encoding="utf-8")
        self.claude(assistant("m1", recent(), command="npm install"))
        self.assertGap(["--ioc", str(ioc)], "1 download could not be checked against the IOC list")

    def test_gap_6_stale_reputation_lists(self):
        import _reputation as R
        R.write_cache(self.home / ".cache" / "actualis" / "reputation",
                      fetched_at=datetime.now(timezone.utc) - timedelta(days=9))
        self.claude(assistant("m1", recent(), command="curl -sO https://files.example/x"))
        self.assertGap(["--reputation"], "reputation lists are 9 days old")

    def test_no_gap_passes(self):
        self.claude(assistant("m1", recent(), command="git status"))
        code, _, err = run_main("--json", "--fail-on-coverage")
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertIn("actualis: PASS at --fail-on-coverage", err)

    def test_a_finding_and_a_gap_together_exit_3(self):
        self.claude(assistant("m1", recent(), command="rm -rf /tmp/build"))
        (self.home / ".codex" / "sessions").mkdir(parents=True)
        code, _, err = run_main("--json", "--fail-on", "any", "--fail-on-coverage")
        self.assertEqual(code, af.EXIT_FINDINGS, err)
        self.assertIn("actualis: FAIL at --fail-on any", err)
        self.assertIn("actualis: FAIL at --fail-on-coverage", err)

    def test_cannot_run_still_wins(self):
        self.projects.mkdir(parents=True)
        code, _, _ = run_main("--fail-on-coverage")
        self.assertEqual(code, af.EXIT_CANNOT_RUN)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs POSIX permissions, as non-root")
    def test_an_unlistable_root_is_a_gap_not_a_crash(self):
        fx.write_sessions(self.home / ".copilot" / "session-state")
        self.projects.mkdir(parents=True)
        self.projects.chmod(0)
        try:
            code, out, err = run_main("--json")
            alone, _, _ = run_main("--agent", "claude", "--fail-on-coverage")
        finally:
            self.projects.chmod(0o700)
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertIn("cannot read", err)
        self.assertIn("claude-code: no transcript file read", json.loads(out)["coverage"]["gaps"])
        self.assertEqual(alone, af.EXIT_CANNOT_RUN)

    def test_a_mode_without_the_gate_refuses_it(self):
        for argv in (("--explain",), ("--agents",), ("--card",), ("--suppressions",)):
            with self.subTest(argv=argv):
                code, _, err = run_main(*argv, "--fail-on-coverage")
                self.assertEqual(code, af.EXIT_USAGE)
                self.assertIn("--fail-on-coverage", err)

    def test_the_exit_codes_are_distinct_and_fixed(self):
        self.assertEqual(af.EXIT_COVERAGE, 5)
        self.assertEqual(len({af.EXIT_OK, af.EXIT_CANNOT_RUN, af.EXIT_USAGE, af.EXIT_FINDINGS,
                              af.EXIT_SELF_CHECK_FAILED, af.EXIT_COVERAGE}), 6)


class TestFailOnUnchanged(HomeCase):
    """Task 4: --fail-on gives the same exit codes as before on the fixture corpus."""

    def test_existing_exit_codes_are_unchanged(self):
        state = fx.write_sessions(self.home / "state")
        scan = ("--root", str(state), "--agent", "copilot", "--json")
        for level in af.FAIL_ON_LEVELS:
            with self.subTest(level=level):
                code, _, err = run_main(*scan, "--fail-on", level)
                self.assertEqual(code, af.EXIT_FINDINGS, err)        # session D's live key
                code, _, err = run_main(*scan, "--fail-on", level, "--fail-on-coverage")
                self.assertEqual(code, af.EXIT_FINDINGS, err)
        code, _, err = run_main(*scan)
        self.assertEqual(code, af.EXIT_OK, err)
        self.claude(assistant("m1", recent(), command="git status"))
        code, _, err = run_main("--json", "--fail-on", "any")
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertNotIn("--fail-on-coverage", err)


class TestAssumptions(unittest.TestCase):
    """Task 5: assumptions(fleet), one entry per marker, with its volume."""

    def test_each_marker_gives_one_entry_with_its_volume(self):
        f = af.Fleet()
        f.add_usage("proj", "claude-sonnet-5", {"input_tokens": 10, "output_tokens": 5,
                                                "cache_creation_input_tokens": 1000}, TS)
        f.add_usage("proj", "claude-sonnet-4-9", {"input_tokens": 1_000_000, "output_tokens": 0}, TS)
        f.add_tool("proj", "Bash", {"command": "npm i y@1.0.0"}, TS, "auto")
        by_kind = {a["kind"]: a for a in af.assumptions(f)}
        self.assertEqual(by_kind["cache-ttl-assumed-1h"],
                         {"path": "tokens.cache_w_assumed", "kind": "cache-ttl-assumed-1h",
                          "basis": "record omits the 1h/5m split; priced at the 1h rate",
                          "volume": {"tokens": 1000}})
        self.assertEqual(by_kind["price-tier-family"]["path"], "pricing.cost_by_tier.family")
        self.assertGreater(by_kind["price-tier-family"]["volume"]["usd"], 0)
        self.assertEqual(by_kind["host-inferred"]["volume"], {"items": 1})
        self.assertNotIn("price-tier-vendor", by_kind)

    def test_the_rest(self):
        f = af.Fleet()
        f.add_usage("proj", "claude-sonnet-5", {"output_tokens": 10}, TS)
        f.add_usage("proj", "claude-sonnet-5", {"output_tokens": 10}, TS + timedelta(days=2))
        f.add_model_usage("gemini", "proj", "gemini-3.5-flash", 500, 20, 0, 0, 0, TS)
        f.sub_cost_floor = 1.25
        by_kind = {a["kind"]: a for a in af.assumptions(f)}
        self.assertEqual(by_kind["rate-active-days"]["volume"], {"days": 2})
        self.assertGreater(by_kind["model-unpriced"]["volume"]["tokens"], 0)
        self.assertEqual(by_kind["subagent-cost-floor"]["volume"], {"usd": 1.25})

    def test_nothing_assumed_is_an_empty_list(self):
        self.assertEqual(af.assumptions(af.Fleet()), [])
        self.assertEqual(af.to_json(af.Fleet())["assumptions"], [])


class TestRejected(unittest.TestCase):
    """Task 5: rejected[], leads evaluated and cleared."""

    def ioc_fleet(self, ioc_text, *cmds, refuse=()):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "osv-malicious.txt"
            path.write_text(ioc_text, encoding="utf-8")
            f = af.Fleet()
            f.suppressions = {}
            for k, cmd in enumerate(cmds):
                f.add_tool("proj", "Bash", {"command": cmd}, TS, "auto", session="s1", call_id=f"t{k}")
            for k in refuse:
                f._network_outcome(f"claude:t{k}", refused=True)
            af.apply_network_policy(f, af.parse_trust([]), strict=False)
            with contextlib.redirect_stderr(io.StringIO()):
                af.apply_ioc(f, af.load_ioc([str(path)]))
            return f

    def test_a_version_outside_the_range_is_rejected_not_matched(self):
        payload = af.to_json(self.ioc_fleet("npm:left-pad@<1.4.0\n", "npm i left-pad@1.4.2"))
        self.assertEqual(payload["network"]["ioc"]["matches"], [])
        self.assertEqual(payload["rejected"], [{
            "kind": "ioc", "id": "npm:left-pad", "what": "left-pad 1.4.2",
            "why_cleared": "1.4.2 is outside <1.4.0", "source": "osv-malicious.txt:1"}])
        self.assertEqual(payload["rejected_total"], 1)

    def test_a_refused_install_is_not_a_lead(self):
        f = self.ioc_fleet("npm:left-pad@<1.4.0\n", "npm i left-pad@1.4.2", refuse=(0,))
        self.assertEqual(af.to_json(f)["rejected_total"], 0)

    def test_a_match_is_never_rejected(self):
        f = self.ioc_fleet("npm:left-pad@<1.4.0\n", "npm i left-pad@1.3.0")
        payload = af.to_json(f)
        self.assertEqual(len(payload["network"]["ioc"]["matches"]), 1)
        self.assertEqual(payload["rejected"], [])

    def test_a_placeholder_credential_is_rejected_without_its_value(self):
        f = af.Fleet()
        f.add_tool("proj", "Bash", {"command": "export STRIPE_SECRET_KEY=your_stripe_key_here"}, TS)
        payload = af.to_json(f)
        self.assertEqual(payload["secrets"], [])
        self.assertEqual(payload["rejected"], [{
            "kind": "secret", "id": "secret:STRIPE_SECRET_KEY", "what": "STRIPE_SECRET_KEY in proj",
            "why_cleared": "failed the STRIPE_SECRET_KEY shape check", "source": ""}])
        self.assertNotIn("your_stripe_key_here", json.dumps(payload["rejected"]))

    def test_a_confirmed_not_listed_candidate_is_rejected(self):
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("proj", "Bash", {"command": "curl -sO https://a.example/x"}, TS, "auto")
        af.apply_network_policy(f, af.parse_trust([]), strict=False)
        a = af.sb_hash("a.example/")
        rep = af.ReputationData()
        rep.status = "ok"
        rep.lists = {name: b"" for name in af.REPUTATION_LISTS}
        rep.lists["mw-4b"] = a[:4]
        rep.state = {name: {"fetched_at": TS, "next_update_at": TS, "prefix_count": 0, "version": None}
                     for name in af.REPUTATION_LISTS}
        rep.oldest = TS
        rep.confirmations = {a[:4]: {"full_hashes": [], "confirmed_at": TS,
                                     "cache_until": TS + timedelta(days=1)}}
        af.apply_reputation(f, rep, TS + timedelta(minutes=1))
        self.assertEqual(af.to_json(f)["rejected"], [{
            "kind": "reputation", "id": "gsb:a.example", "what": "a.example",
            "why_cleared": "confirmed not listed at 2026-10-01 12:00 UTC",
            "source": "gsb/confirmations.json"}])

    def test_capped_newest_first_with_the_total(self):
        f = af.Fleet()
        for n in range(250):
            f._reject("ioc", f"npm:p{n:03d}", f"p{n:03d} 1.0.0", "1.0.0 is outside <0.1.0",
                      "x.txt:1", TS + timedelta(minutes=n))
        payload = af.to_json(f)
        self.assertEqual(len(payload["rejected"]), af.REJECTED_CAP)
        self.assertEqual(payload["rejected_total"], 250)
        self.assertEqual(payload["rejected"][0]["id"], "npm:p249")

    def test_one_row_per_lead_the_newest_kept(self):
        f = af.Fleet()
        f._reject("ioc", "npm:x", "x 2.0.0", "2.0.0 is outside <1.0.0", "a.txt:1", TS)
        f._reject("ioc", "npm:x", "x 2.0.0", "2.0.0 is outside <1.0.0", "a.txt:9",
                  TS + timedelta(days=1))
        f._reject("ioc", "npm:x", "x 2.0.0", "2.0.0 is outside <1.0.0", "a.txt:5", None)
        [row] = af.to_json(f)["rejected"]
        self.assertEqual(row["source"], "a.txt:9")

    def test_the_new_paths_are_declared_and_documented(self):
        f = self.ioc_fleet("npm:left-pad@<1.4.0\n", "npm i left-pad@1.4.2")
        f.add_usage("proj", "claude-sonnet-5", {"input_tokens": 10, "output_tokens": 5,
                                                "cache_creation_input_tokens": 1000}, TS)
        self.assertEqual(schema_drift(af.to_json(f)), [])
        doc = (ROOT / "docs" / "json.md").read_text(encoding="utf-8")
        for word in ("## assumptions", "## rejected", "`rejected_total`", "`why_cleared`",
                     "`cache-ttl-assumed-1h`", "`rate-active-days`"):
            self.assertIn(word, doc)


def rendered(fn, *args, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kw)
    return buf.getvalue()


class TestCoverageText(HomeCase):
    """Task 6: the Coverage line, assumptions in the caveats, missing facts, --verbose."""

    def report(self, f, **kw):
        return rendered(af.render, f, af.C(False), bash_only=False, top=5, **kw)

    def test_a_complete_run_says_so(self):
        self.settings("{}")
        path = self.claude(assistant("m1", recent(), command="git status"))
        f = af.Fleet()
        f.scan(af.transcript_roots(), None, None, progress=False)
        self.assertIn(f"Coverage   complete · claude-code from {af._utc_date(path.stat().st_mtime)} "
                      "(keeps 30d)", self.report(f))

    def test_gaps_are_listed_and_unparsable_lines_shown(self):
        f = af.Fleet()
        f.add_usage("proj", "claude-sonnet-5", {"output_tokens": 10}, TS)
        f._file_read("claude-code", "r", TS.timestamp())
        f._file_unreadable("claude-code")
        f.unparsable_lines, f.lines_read = 3, 1000
        out = self.report(f)
        self.assertIn("Coverage   1 gap\n", out)
        self.assertIn("! 1 transcript file could not be read (claude-code)", out)
        self.assertIn("3 unparsable line(s) skipped, of 1,000 decoded", out)

    def test_the_bash_view_shows_coverage_too(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "git status"}, TS)
        out = rendered(af.render, f, af.C(False), bash_only=True, top=5)
        self.assertIn("Coverage   complete", out)

    def test_assumptions_print_once(self):
        f = af.Fleet()
        f.add_usage("proj", "claude-sonnet-5", {"input_tokens": 10, "output_tokens": 5,
                                                "cache_creation_input_tokens": 1000}, TS)
        out = self.report(f)
        self.assertIn("derived or assumed, not read", out)
        self.assertEqual(out.count("cache-ttl-assumed-1h"), 1)
        self.assertIn("1,000 tokens", out)

    def test_needs_validation_findings_print_what_is_missing(self):
        f = assessed_fleet()
        self.assertIn("needs validation: agent writes no shell records",
                      rendered(af.render_coach, af.coach(f), af.C(False)))
        self.assertIn("needs validation: local hash-prefix match; run actualis-reputation confirm",
                      rendered(af.render_reputation, f, af.C(False)))

    def test_verbose_lists_what_was_checked_and_cleared(self):
        ioc = self.home / "osv.txt"
        ioc.write_text("npm:left-pad@<1.4.0\n", encoding="utf-8")
        self.claude(assistant("m1", recent(), command="npm i left-pad@1.4.2"))
        code, out, err = run_main("--ioc", str(ioc), "--verbose")
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertIn("Checked and cleared", out)
        self.assertIn("left-pad 1.4.2", out)
        self.assertIn("1.4.2 is outside <1.4.0  osv.txt:1", out)
        code, out, err = run_main("--ioc", str(ioc))
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertNotIn("Checked and cleared", out)

    def test_verbose_shows_at_most_twenty_then_a_count(self):
        f = af.Fleet()
        f.add_usage("proj", "claude-sonnet-5", {"output_tokens": 10}, TS)
        for n in range(25):
            f._reject("ioc", f"npm:p{n:02d}", f"p{n:02d} 1.0.0", "1.0.0 is outside <0.1.0",
                      "x.txt:1", TS + timedelta(minutes=n))
        out = self.report(f, verbose=True)
        self.assertEqual(out.count("is outside <0.1.0"), af.REJECTED_SHOWN)
        self.assertIn("… and 5 more (actualis --json | jq .rejected)", out)

    def test_verbose_is_refused_where_nothing_prints_it(self):
        for argv in (("--json",), ("--coach",), ("--share",), ("--network",), ("--explain",)):
            with self.subTest(argv=argv):
                code, _, err = run_main(*argv, "--verbose")
                self.assertEqual(code, af.EXIT_USAGE)
                self.assertIn("--verbose", err)

    def test_explain_coverage(self):
        code, out, _ = run_main("--explain", "coverage")
        self.assertEqual(code, af.EXIT_OK)
        for needle in ("--fail-on-coverage", "exit 5", "cleanupPeriodDays", "jq '.coverage'"):
            self.assertIn(needle, out)


class TestDiffAssessmentsAndCoverage(unittest.TestCase):
    """Task 6: --diff reports assessment changes and coverage gaps."""

    def report(self, **over):
        base = {"schema_version": af.JSON_SCHEMA_VERSION, "version": af.__version__,
                "window": {"from": "2026-01-01T00:00:00+00:00", "to": "2026-01-08T00:00:00+00:00"},
                "secrets": [], "coach": [], "bash": {"flags": []},
                "cost_usd": 10.0, "messages": 100, "report_sha256": "a" * 64}
        base.update(over)
        return base

    FLAG = {"id": "cccccccc", "severity": "med", "program": "npm:pending@?",
            "categories": ["network-ioc-unresolved"], "assessment": "needs-validation"}

    def test_an_assessment_change_is_reported(self):
        old = self.report(bash={"flags": [self.FLAG]})
        new = self.report(bash={"flags": [dict(self.FLAG, assessment="confirmed")]},
                          report_sha256="b" * 64)
        d = af.diff_reports(old, new)
        [(before, after)] = d["families"]["flags"]["assessed"]
        self.assertEqual((before["assessment"], after["assessment"]), ("needs-validation", "confirmed"))
        out = rendered(af.render_diff, d, af.C(False))
        self.assertIn("needs-validation → confirmed", out)

    def test_a_baseline_without_assessments_reports_none(self):
        bare = {k: v for k, v in self.FLAG.items() if k != "assessment"}
        d = af.diff_reports(self.report(bash={"flags": [bare]}), self.report(bash={"flags": [self.FLAG]}))
        self.assertEqual(d["families"]["flags"]["assessed"], [])

    def test_coverage_gaps_that_appeared_and_cleared(self):
        old = self.report(coverage={"ok": False, "gaps": ["reputation lists are 9 days old"]})
        new = self.report(coverage={"ok": False, "gaps": ["1 transcript file could not be read (codex)"]},
                          report_sha256="b" * 64)
        d = af.diff_reports(old, new)
        self.assertEqual(d["coverage"], (["1 transcript file could not be read (codex)"],
                                         ["reputation lists are 9 days old"]))
        out = rendered(af.render_diff, d, af.C(False))
        self.assertIn("coverage gaps", out)
        self.assertIn("+ 1 transcript file could not be read (codex)", out)
        self.assertIn("- reputation lists are 9 days old", out)

    def test_a_baseline_from_before_coverage_reports_no_gap_change(self):
        d = af.diff_reports(self.report(), self.report(coverage={"ok": False, "gaps": ["x"]}))
        self.assertIsNone(d["coverage"])

    def test_a_malformed_coverage_baseline_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "old.json"
            path.write_text(json.dumps(self.report(coverage={"gaps": "not a list"})), encoding="utf-8")
            with self.assertRaises(ValueError) as cm:
                af.load_report(path)
        self.assertIn("coverage.gaps", str(cm.exception))


class TestCoverageDocs(unittest.TestCase):
    """Task 7: the README, docs/findings.md and the CHANGELOG say all of it."""

    def test_the_readme(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for needle in ("## Coverage: what the report could see", "`--fail-on-coverage`",
                       "| `5` | `--fail-on-coverage`", "cleanupPeriodDays", "`--verbose`",
                       "actualis --days 7 --fail-on high --fail-on-coverage"):
            self.assertIn(needle, readme)

    def test_findings_md_has_the_assessment_table(self):
        doc = (ROOT / "docs" / "findings.md").read_text(encoding="utf-8")
        self.assertIn("## Assessments", doc)
        for key, (assessment, basis, missing) in af._ASSESSMENT.items():
            if missing and key not in ("network-ioc-unresolved", "reputation-stale"):
                with self.subTest(key=key):
                    self.assertIn(missing, doc)

    def test_the_changelog(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## 0.7.0 (", 1)[1].split("\n## ", 1)[0]
        for needle in ("--fail-on-coverage", "AF014", "`assessment`", "`rejected`",
                       "cleanupPeriodDays", "--explain coverage"):
            self.assertIn(needle, unreleased)


class TestFinalReviewFixes(HomeCase):
    """Final review: --project is scope, not a gap; a project directory that
    cannot be listed is a gap, not silence."""

    def test_an_agent_without_the_project_is_not_a_gap(self):
        f = af.Fleet()
        f._root_seen("claude-code")
        self.assertEqual(af.coverage(f)["gaps"], ["claude-code: no transcript file read"])
        f.scope["project"] = "atlas"
        self.assertEqual(af.coverage(f)["gaps"], [])

    def test_project_scope_still_reports_what_could_not_be_read(self):
        f = af.Fleet()
        f.scope["project"] = "atlas"
        f._file_unreadable("claude-code")
        self.assertEqual(af.coverage(f)["gaps"], ["1 transcript file could not be read (claude-code)"])

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "permission bits do not stop Windows or root")
    def test_a_project_directory_that_cannot_be_listed_is_a_gap(self):
        good = self.claude(assistant("m1", recent()), project="-home-dev-orbital")
        claude_bad = self.projects / "-home-dev-atlas"
        write_session(claude_bad, "s.jsonl", [assistant("m2", recent())])
        gemini = self.home / "gemini" / "tmp"
        write_session(gemini / "orbital" / "chats", "session-1.jsonl", ['{"sessionId": "x"}'])
        qwen = self.home / "qwen" / "projects"
        write_session(qwen / "-home-dev-orbital" / "chats", "s.jsonl", ['{"type": "user"}'])
        copilot = self.home / "copilot"
        write_session(copilot / "sid", "events.jsonl", ['{"type": "session.start"}'])
        codex = self.home / "codex"
        write_session(codex / "2026" / "11", "rollout-1.jsonl", ['{"type": "session_meta"}'])
        locked = [claude_bad, gemini / "orbital", qwen / "-home-dev-orbital", copilot / "sid", codex / "2026"]
        for d in locked:
            d.chmod(0)
        try:
            f = af.Fleet()
            f.scan([self.projects], None, None, False)
            f.scan_gemini([gemini], None, None)
            f.scan_qwen([qwen], None, None)
            f.scan_copilot([copilot], None, None)
            f.scan_codex([codex], None, None)
        finally:
            for d in locked:
                d.chmod(0o700)
        for agent in ("claude-code", "gemini", "qwen", "copilot", "codex"):
            with self.subTest(agent=agent):
                self.assertEqual(f.agent_roots[agent]["dirs_unreadable"], 1)
        self.assertEqual(f.agent_roots["claude-code"]["files_read"], 1, good)
        gaps = af.coverage(f)["gaps"]
        self.assertIn("1 project directory could not be listed (claude-code)", gaps)
        self.assertIn("1 project directory could not be listed (codex)", gaps)
        rows = {r["agent"]: r for r in af.coverage(f)["agents"]}
        self.assertEqual(rows["claude-code"]["dirs_unreadable"], 1)
        self.assertEqual(af.JSON_SCHEMA["coverage.agents[].dirs_unreadable"], "int")

class TestCoverageFollowUps(unittest.TestCase):
    """#87: messages that said the wrong thing, and a producer triple taken on trust."""

    def tree(self, tmp, age_days=0):
        root = Path(tmp) / "projects" / "proj"
        root.mkdir(parents=True)
        f = root / "s.jsonl"
        f.write_text('{"type":"user"}\n')
        t = time.time() - age_days * 86400
        os.utime(f, (t, t))
        fleet = af.Fleet()
        fleet.roots.append(Path(tmp) / "projects")
        return fleet

    def test_a_run_where_nothing_could_be_read_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            fleet = self.tree(tmp)
            fleet._file_unreadable("claude-code")
            args = argparse.Namespace(root=None, days=None, project=None, agent="all")
            msg = af.dead_end_message(fleet, args)
            self.assertIn("could not be read", msg)
            self.assertNotIn("none matched", msg)

    def test_the_days_hint_never_suggests_the_window_already_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            fleet = self.tree(tmp, age_days=0)
            args = argparse.Namespace(root=None, days=1, project=None, agent="all")
            msg = af.dead_end_message(fleet, args)
            self.assertNotIn("Try --days 1.", msg)
            self.assertIn("records", msg)

    def test_the_days_hint_still_suggests_a_wider_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            fleet = self.tree(tmp, age_days=10)
            args = argparse.Namespace(root=None, days=1, project=None, agent="all")
            # The suggestion is a whole number of days from the file's mtime;
            # filesystems round mtimes differently (Windows), so pin only its floor.
            m = re.search(r"Try --days (\d+)\.", af.dead_end_message(fleet, args))
            self.assertIsNotNone(m)
            self.assertGreater(int(m.group(1)), 1)

    def test_af014_without_a_date_says_nothing_about_one(self):
        f = af.Fleet()
        orig = af.transcripts_expiring
        af.transcripts_expiring = lambda _f: [("claude-code", 2, "", 30)]
        try:
            [hit] = [x for x in af.coach(f) if x.id == "AF014"]
        finally:
            af.transcripts_expiring = orig
        self.assertNotIn("?", hit.evidence)
        self.assertTrue(hit.evidence.startswith("2 transcript files are deleted within 7 days"))

    def test_an_out_of_range_mtime_gives_no_date(self):
        self.assertEqual(af._utc_date(1e300) or "", "")

    def test_a_producer_triple_with_a_bad_missing_is_not_taken(self):
        for bad in (5, ["x"], {"a": 1}):
            got = af.classify({"assessment": "needs-validation", "basis": "observed", "missing": bad})
            self.assertTrue(got["missing"] is None or isinstance(got["missing"], str), got)

    def test_a_producer_triple_with_text_or_none_is_kept(self):
        for ok in ("could not check", None):
            row = {"assessment": "needs-validation", "basis": "inferred", "missing": ok}
            self.assertEqual(af.classify(row), row)


if __name__ == "__main__":
    unittest.main()
