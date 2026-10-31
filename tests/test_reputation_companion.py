"""actualis-reputation, the only networked part of actualis. Every request in
these tests goes to a fake provider server on 127.0.0.1 (tests/_reputation.py),
injected through main(http_factory=...); _fixtures blocks any other socket.
Keys here are invented, never real."""
from __future__ import annotations

import io
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
sys.path.insert(0, str(ROOT))
import actualis_reputation as ar  # noqa: E402

FAKE_KEY = "AIzaFAKE-test-key-0000000000000000000"


class TTY(io.StringIO):
    def isatty(self):
        return True


class CompanionCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=_fixtures.TEMP_HOME)
        self.tmp = Path(self._tmp.name)
        self.rep = self.tmp / "rep"
        self._env = mock_env = {"ACTUALIS_REPUTATION_DIR": str(self.rep)}
        self._old = {k: os.environ.get(k) for k in (*mock_env, "ACTUALIS_GSB_KEY", "ACTUALIS_VT_KEY")}
        os.environ.update(mock_env)
        os.environ.pop("ACTUALIS_GSB_KEY", None)
        os.environ.pop("ACTUALIS_VT_KEY", None)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def cli(self, *argv, stdin=None, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = ar.main(list(argv), stdin=stdin or io.StringIO(), stdout=out, stderr=err, **kw)
        return code, out.getvalue(), err.getvalue()


class TestCore(CompanionCase):
    def test_imports_are_stdlib_and_actualis(self):
        src = (ROOT / "actualis_reputation.py").read_text(encoding="utf-8")
        self.assertEqual(sorted(set(af.imports_in(src))),
                         ["__future__", "actualis", "argparse", "base64", "datetime", "hashlib", "json",
                          "math", "os", "pathlib", "secrets", "shlex", "ssl", "subprocess", "sys", "time",
                          "urllib"])

    def test_key_like_argument_is_not_echoed_or_run(self):
        code, out, err = self.cli("update", "--key", FAKE_KEY)
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, out + err)
        code, out, err = self.cli("update", FAKE_KEY)
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, out + err)

    def test_no_key_is_a_usage_error(self):
        code, _, err = self.cli("update", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("ACTUALIS_GSB_KEY", err)

    def test_key_command_runs_without_a_shell(self):
        scrub = ar.Scrubber()
        cmd = f'{sys.executable} -c "print(\'{FAKE_KEY}\')"'
        self.assertEqual(ar.read_key("gsb", cmd, scrub), FAKE_KEY)
        self.assertEqual(scrub(f"x{FAKE_KEY}y"), "x***y")
        with self.assertRaises(ar.UsageError) as cm:
            ar.read_key("gsb", f'{sys.executable} -c "import sys; print(\'{FAKE_KEY}\'); sys.exit(3)"', ar.Scrubber())
        self.assertNotIn(FAKE_KEY, str(cm.exception))
        with self.assertRaises(ar.UsageError):
            ar.read_key("gsb", "echo a; echo b", ar.Scrubber())     # "a;" is an argument to echo, one line out
        # `echo a; echo b` without a shell prints "a; echo b": a key with spaces is refused.

    def test_no_terminal_no_yes_sends_nothing(self):
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        server = R.FakeProvider()
        try:
            code, _, err = self.cli("update", http_factory=server.factory)
        finally:
            server.close()
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(server.requests, [])
        self.assertNotIn(FAKE_KEY, err)

    def test_terminal_no_answer_sends_nothing(self):
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        server = R.FakeProvider()
        try:
            code, _, err = self.cli("update", stdin=TTY("n\n"), http_factory=server.factory)
        finally:
            server.close()
        self.assertEqual(code, 0)
        self.assertEqual(server.requests, [])
        self.assertIn("nothing sent", err)

    def test_atomic_write_modes_and_symlink_refusal(self):
        target = self.rep / "gsb" / "state.json"
        ar.write_atomic(target, b"{}")
        self.assertEqual(target.read_bytes(), b"{}")
        if os.name != "nt":
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.rep / "gsb").stat().st_mode & 0o777, 0o700)
            link = self.rep / "gsb" / "confirmations.json"
            link.symlink_to(self.tmp / "elsewhere")
            with self.assertRaises(ar.NetError):
                ar.write_atomic(link, b"x")
            self.assertFalse((self.tmp / "elsewhere").exists())
        self.assertEqual([p.name for p in (self.rep / "gsb").iterdir() if p.name.startswith(".tmp")], [])

    def test_status_never_networks(self):
        R.write_cache(self.rep, {"mw-4b": [R.prefix("evil.example/")]},
                      log=[{"at": "2026-10-30T14:02:00+00:00", "provider": "gsb"}])
        code, out, _ = self.cli("status")
        self.assertEqual(code, 0)
        self.assertIn("mw-4b", out)
        self.assertIn("2026-10-30", out)

    def test_forget_requires_consent_and_deletes_only_cache_files(self):
        R.write_cache(self.rep)
        (self.rep / "keep-me.txt").write_text("not ours")
        code, _, _ = self.cli("forget")
        self.assertEqual(code, 2)
        self.assertTrue((self.rep / "gsb" / "state.json").exists())
        code, _, _ = self.cli("forget", "--yes")
        self.assertEqual(code, 0)
        self.assertFalse((self.rep / "gsb").exists())
        self.assertTrue((self.rep / "keep-me.txt").exists())

    def test_session_closing_line_receipt_and_log(self):
        receipt = self.tmp / "receipt.json"
        err = io.StringIO()
        scrub = ar.Scrubber()
        scrub.add(FAKE_KEY)
        with ar.NetSession("confirm", "gsb", scrub, receipt=str(receipt), out=err) as s:
            s.record({"method": "GET", "host": "safebrowsing.googleapis.com", "path": "/v5/hashes:search",
                      "sent": {"prefixes": 3, "decoys": 27}, "status": 200, "bytes": 10,
                      "note": f"key={FAKE_KEY}"})
            self.assertTrue((self.rep / "in-flight.json").exists())
        self.assertFalse((self.rep / "in-flight.json").exists())
        self.assertIn("network used: 1 request to safebrowsing.googleapis.com", err.getvalue())
        body = receipt.read_text()
        self.assertNotIn(FAKE_KEY, body)
        log = (self.rep / "network-log.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(log[-1])["provider"], "gsb")
        self.assertNotIn(FAKE_KEY, "".join(log))

    def test_session_prints_closing_line_on_ctrl_c(self):
        err = io.StringIO()
        with self.assertRaises(KeyboardInterrupt):
            with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=err):
                raise KeyboardInterrupt
        self.assertIn("network used: nothing sent", err.getvalue())
        self.assertFalse((self.rep / "network-log.jsonl").exists())

    def test_console_script_entry_point_runs(self):
        r = subprocess.run([sys.executable, str(ROOT / "actualis_reputation.py"), "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn(af.__version__, r.stdout)
