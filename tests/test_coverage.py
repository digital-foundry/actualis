"""Coverage ledger, finding assessments, assumptions, rejected leads and
transcript retention (0.7.0).

Synthetic data only. Every transcript and every settings.json here is written
by the test under a temporary HOME; nothing reads a real agent directory.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
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


if __name__ == "__main__":
    unittest.main()
