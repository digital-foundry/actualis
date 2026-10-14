"""Review round 2, slice E: tray numbers from --json, --share suppression,
make security (trufflehog offline, docs), Go-test wrapper, fuzzer coverage.

Every transcript here is synthetic, under a temp HOME/CODEX_HOME/COPILOT_HOME.

    python3 -m unittest tests.test_review_r2_E -v
"""

import contextlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

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


def _text(rel):
    path = ROOT / rel
    if not path.exists():
        raise unittest.SkipTest(f"{rel} is not in this tree (an sdist?)")
    return path.read_text(encoding="utf-8")


def _load(name, rel):
    path = ROOT / rel
    if not path.exists():
        raise unittest.SkipTest(f"{rel} is not in this tree (an sdist?)")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _share(fleet):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        af.render_share(fleet, af.C(False))
    return buf.getvalue()


# ------------------------------------------------------------ P2E1 / P2E4

class TestJsonCarriesTrayNumbers(unittest.TestCase):

    def test_unsupervised_pct_leaves_out_codex_sandbox_keys(self):           # P2E1
        f = af.Fleet()
        f.permission_modes = Counter({"codex:never": 4, "sandbox:workspace-write": 4})
        out = af.to_json(f)
        self.assertEqual(out["unsupervised_pct"], 100.0)
        self.assertIn("100% of turns ran unsupervised", _share(f))

    def test_unsupervised_pct_is_null_without_modes(self):
        self.assertIsNone(af.to_json(af.Fleet())["unsupervised_pct"])

    def test_unsupervised_pct_matches_share_rounding(self):
        f = af.Fleet()
        f.permission_modes = Counter({"auto": 1, "default": 2})
        pct = af.to_json(f)["unsupervised_pct"]
        self.assertIn(f"{pct:.0f}% of turns ran unsupervised", _share(f))

    def test_flagged_counts_commands_not_categories_and_skips_suppressed(self):  # P2E4
        f = af.Fleet()
        f.bash_total = 3
        f.flags = [
            {"severity": "high", "categories": ["remote-exec", "destructive"],
             "suppressed": True, "evidence": "x"},
            {"severity": "high", "categories": ["remote-exec", "destructive"], "evidence": "y"},
            {"severity": "med", "categories": ["network"], "evidence": "z"},
        ]
        f.flag_counts = Counter({"high:remote-exec": 2, "high:destructive": 2, "med:network": 1})
        out = af.to_json(f)
        self.assertEqual(out["bash"]["flagged"], {"high": 1, "medium": 1})

    def test_schema_and_docs_declare_the_new_fields(self):
        for k, t in (("unsupervised_pct", "float|null"), ("bash.flagged.high", "int"),
                     ("bash.flagged.medium", "int")):
            self.assertEqual(af.JSON_SCHEMA[k], t)
        doc = _text("docs/json.md")
        self.assertIn("`unsupervised_pct`", doc)
        self.assertIn("`flagged.high`", doc)

    def test_codex_fleet_end_to_end(self):
        recs = [{"timestamp": "2026-10-01T10:00:00Z", "type": "session_meta",
                 "payload": {"id": "cx-1", "cwd": "/home/dev/p"}}]
        for i in range(4):
            recs.append({"timestamp": f"2026-10-01T10:0{i}:00Z", "type": "turn_context",
                         "payload": {"cwd": "/home/dev/p", "approval_policy": "never",
                                     "model": "gpt-5-codex",
                                     "sandbox_policy": {"type": "workspace-write"}}})
            recs.append({"timestamp": f"2026-10-01T10:0{i}:01Z", "type": "response_item",
                         "payload": {"type": "function_call", "name": "shell_command",
                                     "call_id": f"c{i}",
                                     "arguments": json.dumps({"command": "ls"})}})
        with tempfile.TemporaryDirectory() as td:
            home, codex = Path(td) / "home", Path(td) / "codex"
            d = codex / "sessions" / "2026" / "10" / "01"
            d.mkdir(parents=True)
            home.mkdir()
            (d / "rollout-2026-10-01T10-00-00-cx-1.jsonl").write_text(
                "\n".join(json.dumps(r) for r in recs) + "\n")
            # USERPROFILE: Windows' Python finds the home there, not in HOME.
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home),
                   "USERPROFILE": str(home),
                   "CODEX_HOME": str(codex), "COPILOT_HOME": str(Path(td) / "copilot")}
            if os.name == "nt" and os.environ.get("SYSTEMROOT"):
                env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
            run = lambda *a: subprocess.run([sys.executable, str(ROOT / "actualis.py"),
                                             "--days", "3650", *a], capture_output=True,
                                            text=True, env=env, cwd=td, timeout=120)
            js = json.loads(run("--json").stdout)
            share = run("--share").stdout
        self.assertEqual(js["permission_modes"].get("sandbox:workspace-write"), 4)
        self.assertEqual(js["unsupervised_pct"], 100.0)
        self.assertIn("100% of turns ran unsupervised", share)


# ------------------------------------------------------------------ P2E5

class TestShareLeavesOutSuppressedCredentials(unittest.TestCase):

    def test_suppressed_credential_is_not_worth_rotating(self):
        f = af.Fleet()
        f.secrets = {
            "aaaa1111": {"priority": "critical", "kinds": {"github"}, "uses": 1,
                         "first": "", "last": "", "projects": set(), "suppressed": True,
                         "suppressed_reason": "fixture"},
            "bbbb2222": {"priority": "high", "kinds": {"slack"}, "uses": 1,
                         "first": "", "last": "", "projects": set()},
        }
        out = _share(f)
        self.assertIn("2 distinct credentials", out)
        self.assertIn("0 critical, 1 worth rotating, 1 suppressed", out)
        self.assertNotIn("aaaa1111", out)


# ------------------------------------------------------------------ P2E3

class TestTrufflehogOffline(unittest.TestCase):

    def test_not_only_verified_and_uses_the_fixture_allowlist(self):
        sh = _text("tools/security/run.sh")
        self.assertNotIn("--only-verified", sh)
        self.assertIn("--exclude-paths /src/tools/security/trufflehog-exclude.txt", sh)
        self.assertNotIn("verified secrets:", sh)
        excl = [l for l in _text("tools/security/trufflehog-exclude.txt").splitlines() if l]
        toml = _text(".gitleaks.toml")
        allow = re.findall(r"'''(.*?)'''", toml)
        self.assertEqual(sorted(excl), sorted(allow))
        for path, excluded in (("tests/test_x.py", True), ("tools/make-demo-fleet.py", True),
                               ("docs/superpowers/plans/a.md", True), ("actualis.py", False),
                               ("docs/json.md", False)):
            self.assertEqual(any(re.search(p, path) for p in excl), excluded, path)

    @unittest.skipIf(sys.platform == "win32" or not shutil.which("sh"), "needs sh")
    def test_reports_candidates_honestly(self):
        sh = _text("tools/security/run.sh")
        start = sh.index("rc=0\ntrufflehog")
        end = sh.index("rc=0\ngitleaks")
        for lines, want in (("", "trufflehog: no candidates outside fixtures"),
                            ('{"a":1}\n{"b":2}\n',
                             "trufflehog: 2 unverified candidates outside fixtures")):
            with tempfile.TemporaryDirectory() as td:
                bindir = Path(td) / "bin"
                bindir.mkdir()
                (Path(td) / "res").write_text(lines)
                (bindir / "trufflehog").write_text(f"#!/bin/sh\ncat '{td}/res'\nexit 0\n")
                (bindir / "trufflehog").chmod(0o755)
                script = f'set -eu\nOUT="{td}"\n' + sh[start:end]
                p = subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                                   env={"PATH": f"{bindir}:/usr/bin:/bin"})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(want, p.stdout)


# ------------------------------------------------------------------ P2E6

class TestGoWrapper(unittest.TestCase):

    def test_never_rewrites_go_mod_and_skips_without_modules(self):
        src = _text("tests/test_review_r1_EG.py")
        self.assertNotIn("-mod=mod", src)
        self.assertIn('GOFLAGS="-mod=readonly"', src)
        for marker in ("module lookup disabled", "requires go >=", "setup failed"):
            self.assertIn(marker, src)


# ------------------------------------------------------------------ P2E7

class TestMakeSecurityDocumented(unittest.TestCase):

    def test_docs(self):
        contrib = _text("CONTRIBUTING.md")
        for s in ("make security", "--network none", "security-out/", "read-only",
                  "unverified", "tests/", "FAILED"):
            self.assertIn(s, contrib)
        sec = _text("SECURITY.md")
        self.assertIn("make security", sec)
        self.assertIn("security-out/", sec)
        self.assertIn("make security", _text("README.md"))


# ------------------------------------------------------------- P2E8 / P2E9

class TestFuzzerCoverage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fz = _load("fuzz_transcripts_r2", "tools/security/fuzz_transcripts.py")

    def test_object_and_array_arguments_reach_the_parser(self):               # P2E8
        kinds = Counter()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.jsonl"
            for i in range(400):
                rec = {"timestamp": "2026-10-01T10:00:01Z", "type": "response_item",
                       "payload": {"arguments": json.dumps({"command": "ls", "workdir": "/w"}),
                                   "output": json.dumps({"output": "ok"})}}
                path.write_text(json.dumps(rec) + "\n")
                self.fz.mutate_structural(random.Random(i), path)
                for line in path.read_text().splitlines():
                    got = json.loads(line)
                    p = got.get("payload") if isinstance(got, dict) else None
                    if isinstance(p, dict):
                        for key in ("arguments", "output"):
                            kinds[type(p.get(key)).__name__] += 1
        self.assertGreater(kinds["dict"], 0, kinds)
        self.assertGreater(kinds["str"], 0, kinds)

    def test_file_list_is_sorted(self):                                       # P2E9
        src = _text("tools/security/fuzz_transcripts.py")
        self.assertRegex(src, r"files = sorted\(p for p in work\.rglob")


if __name__ == "__main__":
    unittest.main()
