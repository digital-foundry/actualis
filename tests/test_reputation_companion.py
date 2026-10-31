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
import ssl
import tempfile
import unittest
from unittest import mock
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


class TestFixRound1(CompanionCase):
    def test_no_explicit_argument_value_is_echoed(self):
        for argv in (("update", f"--yes={FAKE_KEY}"), ("update", f"--dry-run={FAKE_KEY}"),
                     ("forget", f"--yes={FAKE_KEY}"), (f"--version={FAKE_KEY}",),
                     (FAKE_KEY,), ("update", "--receipt"), ("status", FAKE_KEY),
                     ("virustotal", "x", f"--vt-threshold={FAKE_KEY}")):
            code, out, err = self.cli(*argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn(FAKE_KEY, out + err, argv)

    def test_abbreviated_options_are_refused(self):
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr", io.StringIO()):
                ar.build_parser().parse_args(["update", "--key-c", "x"])
        code, out, err = self.cli("update", f"--key={FAKE_KEY}")
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, out + err)

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_forget_does_not_delete_through_symlinked_subdir(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        for n in ("state.json", "x.prefixes", ".tmp-1", "results.json"):
            (victim / n).write_text("keep")
        self.rep.mkdir()
        (self.rep / "gsb").symlink_to(victim)
        (self.rep / "vt").symlink_to(victim)
        code, _, err = self.cli("forget", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in victim.iterdir()),
                         [".tmp-1", "results.json", "state.json", "x.prefixes"])
        self.assertIn("symlink", err)
        self.assertTrue((self.rep / "gsb").is_symlink())

    def test_read_report_never_names_the_path(self):
        key_path = FAKE_KEY
        bad = self.tmp / "bad.json"
        bad.write_text("not json")
        for path in (key_path, str(bad)):
            with self.assertRaises(ar.UsageError) as cm:
                ar.read_report(path, io.StringIO())
            self.assertNotIn(path, str(cm.exception))
        with self.assertRaises(ar.UsageError) as cm:
            ar.read_report("-", io.StringIO("[1]"))
        self.assertIn("report file", str(cm.exception))

    def test_key_command_not_run_when_consent_is_impossible(self):
        with mock.patch.object(ar.subprocess, "run") as run:
            code, _, err = self.cli("update", "--key-command", "x")
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        run.assert_not_called()

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_ensure_dir_creates_nothing_through_a_symlinked_root(self):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.rep.symlink_to(elsewhere)
        with self.assertRaises(ar.NetError):
            ar.ensure_dir(self.rep / "gsb")
        self.assertEqual(list(elsewhere.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_receipt_is_not_written_through_a_symlink(self):
        target = self.tmp / "target.txt"
        target.write_text("keep")
        link = self.tmp / "receipt.json"
        link.symlink_to(target)
        err = io.StringIO()
        with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=str(link), out=err):
            pass
        self.assertEqual(target.read_text(), "keep")
        self.assertIn("cannot write the receipt", err.getvalue())

    def test_receipt_mode_is_0600(self):
        if os.name == "nt":
            self.skipTest("posix modes")
        r = self.tmp / "r.json"
        with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=str(r), out=io.StringIO()):
            pass
        self.assertEqual(r.stat().st_mode & 0o777, 0o600)

    def test_receipt_that_already_exists_ends_0600(self):
        if os.name == "nt":
            self.skipTest("posix modes")
        r = self.tmp / "r.json"
        r.write_text("old")
        os.chmod(r, 0o644)
        with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=str(r), out=io.StringIO()):
            pass
        self.assertEqual(r.stat().st_mode & 0o777, 0o600)

    def test_key_command_that_is_a_pasted_key_is_refused_unrun(self):
        with mock.patch.object(ar.subprocess, "run") as run:
            for fn in (lambda: ar.read_key("gsb", FAKE_KEY, ar.Scrubber()),):
                with self.assertRaises(ar.UsageError) as cm:
                    fn()
                self.assertIn("looks like a key", str(cm.exception))
                self.assertNotIn(FAKE_KEY, str(cm.exception))
            run.assert_not_called()
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        with mock.patch.object(ar.subprocess, "run") as run:
            code, out, err = self.cli("update", "--yes", "--key-command", FAKE_KEY)
            self.assertEqual(code, 2)
            self.assertNotIn(FAKE_KEY, out + err)
            run.assert_not_called()

    def test_disclosure_key_line_says_whether_the_variable_is_set(self):
        out = io.StringIO()
        net = argparse_ns = type("A", (), {"dry_run": False, "key_command": None})()
        ar.disclose([("Key", ar._key_line(net, "gsb"))], out)
        self.assertIn("ACTUALIS_GSB_KEY (not set)", out.getvalue())
        os.environ["ACTUALIS_VT_KEY"] = FAKE_KEY
        self.assertEqual(ar._key_line(net, "vt"), "$ACTUALIS_VT_KEY (set, not shown)")
        self.assertNotIn(FAKE_KEY, ar._key_line(net, "vt"))

    def test_key_shape_is_enforced_without_echo(self):
        for bad in ("short", "a" * 513, 'abc"def' + "0" * 16, "x y " + "0" * 16, "é" * 20):
            with self.assertRaises(ar.UsageError) as cm:
                ar.read_key("gsb", None, ar.Scrubber(), env={"ACTUALIS_GSB_KEY": bad})
            self.assertNotIn(bad, str(cm.exception))
        self.assertEqual(ar.read_key("vt", None, ar.Scrubber(), env={"ACTUALIS_VT_KEY": "a" * 64}), "a" * 64)

    def test_session_failure_names_the_exception_type(self):
        receipt = self.tmp / "r.json"
        err = io.StringIO()
        with self.assertRaises(ar.NetError):
            with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=str(receipt), out=err):
                raise ar.NetError("boom")
        self.assertIn("(stopped: NetError)", err.getvalue())
        self.assertEqual(json.loads(receipt.read_text())["failure"], "NetError")

    def test_session_leaves_a_foreign_in_flight_file_when_it_wrote_none(self):
        self.rep.mkdir()
        (self.rep / "in-flight.json").write_text("other")
        with mock.patch.object(ar, "write_json", side_effect=OSError("no")):
            with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO()):
                pass
        self.assertTrue((self.rep / "in-flight.json").exists())


def R_b64(text: str) -> bytes:
    return __import__("base64").b64decode(text)


def rice_lists(entries: dict) -> dict:
    """A hashLists:batchGet body with full (non-partial) lists, each list's
    prefixes Rice-encoded the way Google does, checksum included."""
    lists = []
    for name in R.LISTS:
        ps = sorted(set(entries.get(name, [])))
        lists.append(R.hash_list(name, ps))
    return {"hashLists": lists}


class TestRice(unittest.TestCase):
    def test_google_worked_example(self):
        vals = ar.rice_decode(489866504, 30, 2, bytes.fromhex("7400d2971bed497400"))
        self.assertEqual([v.to_bytes(4, "big").hex() for v in vals], ["1d32c508", "291bc542", "f7a502e5"])

    def test_round_trip_through_the_test_encoder(self):
        ps = sorted({R.prefix(f"h{i}.example/") for i in range(500)})
        hl = R.hash_list("mw-4b", ps)
        self.assertEqual(ar.apply_list_update(b"", hl), b"".join(ps))

    def test_long_unary_run_decodes_but_overflow_raises(self):
        first, k, n, data = R.rice_encode([5, 1005], 3)
        self.assertEqual(ar.rice_decode(first, k, n, R_b64(data)), [5, 1005])
        with self.assertRaises(ValueError):
            ar.rice_decode(0xFFFFFF00, 3, 1, b"\xff" * 200)

    def test_rejects_truncated_and_out_of_range(self):
        with self.assertRaises(ValueError):
            ar.rice_decode(1, 30, 2, b"\x00")
        with self.assertRaises(ValueError):
            ar.rice_decode(0xFFFFFFF0, 3, 1, b"\xff\xff\x00")        # overflows 32 bits
        with self.assertRaises(ValueError):
            ar.apply_list_update(b"", {"additionsFourBytes": {"riceParameter": 2, "entriesCount": 1,
                                                                "firstValue": 1, "encodedData": "AA=="}})

    def test_partial_update_removes_then_adds(self):
        old = sorted({R.prefix(f"o{i}.example/") for i in range(5)})
        add = R.prefix("new.example/")
        new = sorted([p for i, p in enumerate(old) if i not in (1, 3)] + [add])
        hl = R.hash_list("mw-4b", [add], removals=[1, 3], partial=True, checksum_of=new)
        self.assertEqual(ar.apply_list_update(b"".join(old), hl), b"".join(new))

    def test_removal_index_past_end_is_rejected(self):
        hl = R.hash_list("mw-4b", [], removals=[9], partial=True, checksum_of=[])
        with self.assertRaises(ValueError):
            ar.apply_list_update(b"\x00\x00\x00\x01", hl)

    def test_durations(self):
        self.assertEqual(ar.parse_duration("3.5s"), 3.5)
        self.assertEqual(ar.parse_duration("1800s"), 1800.0)
        self.assertEqual(ar.parse_duration(None), 0.0)
        self.assertEqual(ar.parse_duration("-5s"), 0.0)
        self.assertEqual(ar.parse_duration("9" * 400 + "s"), 0.0)


class TestUpdate(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY

    def serve(self, *bodies):
        s = R.FakeProvider({"/v5/hashLists:batchGet": [(200, b) if isinstance(b, dict) else b for b in bodies]})
        self.addCleanup(s.close)
        return s

    def test_first_update_writes_lists_and_state(self):
        s = self.serve(rice_lists({"mw-4b": [R.prefix("evil.example/")]}))
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(s.requests), 1)
        q = s.requests[0]["query"]
        self.assertEqual(sorted(q["names"]), sorted(R.LISTS))
        self.assertNotIn("key", q)
        self.assertEqual(s.requests[0]["headers"]["x-goog-api-key"], FAKE_KEY)
        d = af.load_reputation(self.rep)
        self.assertEqual(d.status, "ok", d.error)
        self.assertEqual(d.lists["mw-4b"], R.prefix("evil.example/"))
        self.assertIn("network used: 1 request to safebrowsing.googleapis.com", err)

    def test_reply_with_swapped_list_names_is_refused(self):
        body = rice_lists({"mw-4b": [R.prefix("evil.example/")]})
        body["hashLists"][0]["name"] = "se-4b"
        s = self.serve(body)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1, err)
        self.assertFalse((self.rep / "gsb" / "state.json").exists())

    def test_update_recovers_from_unhashable_state_name(self):
        (self.rep / "gsb").mkdir(parents=True)
        (self.rep / "gsb" / "state.json").write_text(json.dumps({"schema": 1, "lists": [{"name": ["mw-4b"]}]}))
        self.assertEqual(af.load_reputation(self.rep).status, "corrupt")
        s = self.serve(rice_lists({"mw-4b": [R.prefix("evil.example/")]}))
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(s.requests[0]["query"]["names"]), len(R.LISTS))
        self.assertEqual(af.load_reputation(self.rep).status, "ok")

    def test_not_due_sends_nothing(self):
        s = self.serve(rice_lists({}))
        self.cli("update", "--yes", http_factory=s.factory)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0)
        self.assertEqual(len(s.requests), 1)
        self.assertIn("lists are current", err)

    def test_checksum_mismatch_falls_back_to_full_fetch(self):
        bad = rice_lists({"mw-4b": [R.prefix("evil.example/")]})
        bad["hashLists"][0]["sha256Checksum"] = R.b64(b"\x00" * 32)
        good = {"hashLists": [R.hash_list("mw-4b", [R.prefix("evil.example/")])]}   # only the retried list
        s = self.serve(bad, good)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(s.requests), 2)
        self.assertNotIn("version", s.requests[1]["query"])

    def test_second_mismatch_writes_nothing(self):
        bad = rice_lists({"mw-4b": [R.prefix("evil.example/")]})
        bad["hashLists"][0]["sha256Checksum"] = R.b64(b"\x00" * 32)
        s = self.serve(bad, {"hashLists": [bad["hashLists"][0]]})
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual(af.load_reputation(self.rep).status, "absent")

    def test_403_is_a_runtime_error_with_no_key_in_output(self):
        s = self.serve((403, {"error": {"message": f"API key not valid: {FAKE_KEY}"}}))
        receipt = self.tmp / "r.json"
        code, out, err = self.cli("update", "--yes", "--receipt", str(receipt), http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertIn("403", err)
        self.assertNotIn(FAKE_KEY, out + err + receipt.read_text())

    def test_dry_run_reads_no_key_and_sends_nothing(self):
        os.environ.pop("ACTUALIS_GSB_KEY")
        s = self.serve(rice_lists({}))
        code, _, err = self.cli("update", "--dry-run", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(s.requests, [])
        self.assertIn("nothing sent", err)

    def test_redirect_is_not_followed(self):
        s = R.FakeProvider({"/v5/hashLists:batchGet": [(302, b"", {"Location": "/v5/other"})],
                            "/v5/other": [(200, rice_lists({}))]})
        self.addCleanup(s.close)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual([r["path"] for r in s.requests], ["/v5/hashLists:batchGet"])

    def test_redirect_handler_refuses(self):
        self.assertIsNone(ar._NoRedirect().redirect_request(None, None, 302, "", {}, "http://x/"))

    def test_huge_wait_is_clamped(self):
        body = rice_lists({})
        for hl in body["hashLists"]:
            hl["minimumWaitDuration"] = "1e300s"
        s = self.serve(body)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        d = af.load_reputation(self.rep)
        self.assertEqual(d.status, "ok", d.error)
        limit = datetime.now(timezone.utc) + timedelta(hours=24, minutes=1)
        for st in d.state.values():
            self.assertLessEqual(st["next_update_at"], limit)
        self.assertEqual(ar.parse_duration("1e12s"), 86400.0)

    def test_bad_version_is_not_stored(self):
        body = rice_lists({})
        body["hashLists"][0]["version"] = R.b64(b"v" * 3100)     # over the 4096-character limit
        s = self.serve(body)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        st = json.loads((self.rep / "gsb" / "state.json").read_text())
        self.assertIsNone([e for e in st["lists"] if e["name"] == "mw-4b"][0]["version"])
        self.assertIsNotNone([e for e in st["lists"] if e["name"] == "se-4b"][0]["version"])

    def test_bad_status_line_is_a_runtime_error(self):
        import socket
        import threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            c, _ = srv.accept()
            c.recv(4096)
            c.sendall(b"garbage\r\n\r\n")
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session, endpoints={ar.GSB_HOST: f"127.0.0.1:{srv.getsockname()[1]}"},
                       scheme="http", proxies={})
        with self.assertRaises(ar.NetError):
            http.get(ar.GSB_HOST, "/x", sent={}, describe="x")

    def test_scheme_is_restricted(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        with self.assertRaises(ValueError):
            ar.Http(session, scheme="ftp")

    def _snapshot(self):
        return {str(p.relative_to(self.rep)): p.read_bytes() for p in sorted(self.rep.rglob("*"))
                if p.is_file() and p.name not in ("network-log.jsonl", "in-flight.json")}

    def test_failed_partial_update_leaves_cache_untouched(self):
        old = sorted({R.prefix(f"o{i}.example/") for i in range(3)})
        R.write_cache(self.rep, {"mw-4b": old}, fetched_at=datetime.now(timezone.utc) - timedelta(hours=2))
        before = self._snapshot()
        bad_removal = R.hash_list("mw-4b", [], removals=[9], partial=True, checksum_of=[])
        wrong = R.hash_list("mw-4b", [R.prefix("n.example/")])
        wrong["sha256Checksum"] = R.b64(b"\x00" * 32)
        s = self.serve({"hashLists": [bad_removal] + [R.hash_list(n, [], partial=True, checksum_of=[])
                                                      for n in R.LISTS[1:]]},
                       {"hashLists": [wrong]})
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1, err)
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(af.load_reputation(self.rep).status, "ok")

    def test_failed_request_is_receipted_and_logged(self):
        s = self.serve((500, b"boom"))
        receipt = self.tmp / "r.json"
        code, _, _ = self.cli("update", "--yes", "--receipt", str(receipt), http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(receipt.read_text())["requests"][0]["status"], 500)
        lines = (self.rep / "network-log.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["requests"], 1)

    def test_oversized_response_is_refused(self):
        s = self.serve((200, b"x" * 2048))
        old = ar.LIST_RESPONSE_MAX
        ar.LIST_RESPONSE_MAX = 1024
        try:
            code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        finally:
            ar.LIST_RESPONSE_MAX = old
        self.assertEqual(code, 1)
        self.assertIn("over", err)

    def test_key_never_appears_anywhere(self):
        s = self.serve((500, f"boom {FAKE_KEY}".encode()))
        receipt = self.tmp / "r.json"
        code, out, err = self.cli("update", "--yes", "--receipt", str(receipt), http_factory=s.factory)
        blob = out + err + receipt.read_text()
        for p in self.rep.rglob("*"):
            if p.is_file():
                blob += p.read_text(errors="replace")
        self.assertNotIn(FAKE_KEY, blob)

    def test_unknown_host_is_refused(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session, endpoints={ar.GSB_HOST: "127.0.0.1:9"}, scheme="http")
        with self.assertRaises(ar.NetError):
            http.get("evil.example", "/", sent={}, describe="x")

    def test_real_client_verifies_certificates(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session)
        self.assertEqual(http.scheme, "https")
        self.assertEqual(http.context.verify_mode, __import__("ssl").CERT_REQUIRED)
        self.assertTrue(http.context.check_hostname)
        self.assertEqual(set(http.endpoints), {ar.GSB_HOST, ar.VT_HOST})


@unittest.skipUnless(__import__("shutil").which("openssl"), "needs openssl to mint a throwaway certificate")
class TestTlsRefusesUntrustedCert(CompanionCase):
    def test_self_signed_server_is_refused(self):
        import ssl
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        cert, key = self.tmp / "c.pem", self.tmp / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True, timeout=60)
        hits = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sctx.load_cert_chain(str(cert), str(key))
        srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session, endpoints={ar.GSB_HOST: f"127.0.0.1:{srv.server_address[1]}"})  # real https context
        with self.assertRaises(ar.NetError):
            http.get(ar.GSB_HOST, "/v5/hashLists:batchGet", sent={}, describe="x")
        self.assertEqual(hits, [])


def net_json(path: Path, candidates=(), hosts=()) -> Path:
    path.write_text(json.dumps({"hosts": [{"host": h, "count": 1} for h in hosts],
                                "reputation": {"enabled": True, "candidates": [
                                    {"prefix_b64": R.b64(R.prefix(e)), "expressions": 1} for e in candidates],
                                    "totals": {"skipped": 2}}}))
    return path


class TestConfirm(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        R.write_cache(self.rep, {"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")]})

    def search(self, *full_hashes, cache="1800s"):
        return {"fullHashes": [{"fullHash": R.b64(R.full(e)),
                                "fullHashDetails": [{"threatType": t, "attributes": attrs}]}
                               for e, t, attrs in full_hashes], "cacheDuration": cache}

    def test_sends_prefixes_and_decoys_never_hosts(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, self.search(("evil.example/", "MALWARE", [])))]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", ["evil.example/", "odd.example/"], hosts=["evil.example"])
        code, _, err = self.cli("confirm", str(nj), "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        q = s.requests[0]["query"]["hashPrefixes"]
        self.assertEqual(len(q), 30)
        self.assertIn(R.b64(R.prefix("evil.example/")), q)
        self.assertNotIn("evil.example", json.dumps(s.requests))
        self.assertIn("run actualis again within 30 minutes", err)
        d = af.load_reputation(self.rep)
        now = datetime.now(timezone.utc)
        self.assertEqual(af.gsb_verdict("evil.example", "", d, now)["state"], "listed")
        self.assertEqual(af.gsb_verdict("odd.example", "", d, now)["state"], "not-listed")

    def test_decoy_hits_are_dropped(self):
        decoy_answer = {"fullHashes": [{"fullHash": R.b64(b"\x01\x02\x03\x04" + b"\0" * 28),
                                        "fullHashDetails": [{"threatType": "MALWARE"}]}], "cacheDuration": "300s"}
        s = R.FakeProvider({"/v5/hashes:search": [(200, decoy_answer)]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", ["evil.example/"])
        self.cli("confirm", str(nj), "--yes", http_factory=s.factory)
        conf = json.loads((self.rep / "gsb" / "confirmations.json").read_text())
        self.assertEqual([e["prefix"] for e in conf["entries"]], [R.b64(R.prefix("evil.example/"))])
        self.assertEqual(conf["entries"][0]["full_hashes"], [])

    def test_canary_is_stored_as_not_enforceable(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, self.search(("evil.example/", "MALWARE", ["CANARY"])))]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes", http_factory=s.factory)
        e = json.loads((self.rep / "gsb" / "confirmations.json").read_text())["entries"][0]
        self.assertEqual((e["full_hashes"][0]["threat_types"], e["full_hashes"][0]["canary"]), ([], True))

    def test_no_candidates_sends_nothing(self):
        s = R.FakeProvider()
        self.addCleanup(s.close)
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json")), "--yes", http_factory=s.factory)
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("no candidates", err)

    def test_report_without_reputation_is_a_usage_error(self):
        p = self.tmp / "n.json"
        p.write_text(json.dumps({"hosts": [], "reputation": {"enabled": False, "candidates": []}}))
        code, _, err = self.cli("confirm", str(p), "--yes")
        self.assertEqual(code, 2)
        self.assertIn("--reputation", err)

    def test_dry_run_lists_prefixes(self):
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn(R.b64(R.prefix("evil.example/")), err)
        self.assertIn("29 random decoys", err)

    def test_many_candidates_are_chunked_under_1000(self):
        cands = [f"h{i}.example/" for i in range(1500)]
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", cands)), "--yes", http_factory=s.factory)
        self.assertEqual(len(s.requests), 2)
        self.assertTrue(all(len(r["query"]["hashPrefixes"]) <= 1000 for r in s.requests))

    def test_key_command_not_run_without_consent_possible(self):
        nj = net_json(self.tmp / "n.json", ["evil.example/"])
        with mock.patch.object(ar.subprocess, "run") as run:
            code, _, err = self.cli("confirm", str(nj), "--key-command", "x")
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        run.assert_not_called()

    def test_dry_run_reads_no_key(self):
        nj = net_json(self.tmp / "n.json", ["evil.example/"])
        with mock.patch.object(ar.subprocess, "run") as run:
            code, _, _ = self.cli("confirm", str(nj), "--key-command", "x", "--dry-run")
        self.assertEqual(code, 0)
        run.assert_not_called()

    def test_decoys_are_list_prefixes_and_not_real(self):
        pool = [bytes([i // 256, i % 256, 7, 9]) for i in range(300)]
        R.write_cache(self.rep, {"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")] + pool[:150],
                                 "se-4b": pool[150:]})
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", ["evil.example/", "odd.example/"])
        self.cli("confirm", str(nj), "--yes", http_factory=s.factory)
        q = [ar._b64(x) for x in s.requests[0]["query"]["hashPrefixes"]]
        real = {R.prefix("evil.example/"), R.prefix("odd.example/")}
        decoys = [p for p in q if p not in real]
        self.assertEqual(len(q), len(set(q)))
        self.assertEqual(len(decoys), 28)
        self.assertTrue(all(p in set(pool) for p in decoys))

    def test_make_decoys_falls_back_to_random_and_avoids_reals(self):
        real = {b"\x00\x00\x00\x01"}
        d = ar.make_decoys(real, 30, [b"\x00\x00\x00\x01\x00\x00\x00\x02"])
        self.assertEqual(len(d), 29)
        self.assertEqual(len(set(d)), 29)
        self.assertNotIn(b"\x00\x00\x00\x01", d)
        self.assertIn(b"\x00\x00\x00\x02", d)

    def test_window_follows_cache_duration(self):
        for cache, want in (("300s", "within 5 minutes"), ("1800s", "within 30 minutes"),
                            ("86400s", "within 30 minutes"), ("45s", "within 45 seconds")):
            s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": cache})]})
            self.addCleanup(s.close)
            _, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes",
                                 http_factory=s.factory)
            self.assertIn(want, err)

    def test_missing_cache_duration_warns(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, {})]})
        self.addCleanup(s.close)
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes",
                                http_factory=s.factory)
        self.assertEqual(code, 0)
        self.assertIn("Google gave no cache time; this result cannot be used to mark a host listed.", err)

    def test_only_enforceable_threat_types(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s", "fullHashes": [
            {"fullHash": R.b64(R.full("evil.example/")), "fullHashDetails": [
                {"threatType": "THREAT_TYPE_UNSPECIFIED"}, {"threatType": "SOMETHING_NEW"},
                {"threatType": "SOCIAL_ENGINEERING"}]}]})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes", http_factory=s.factory)
        e = json.loads((self.rep / "gsb" / "confirmations.json").read_text())["entries"][0]
        self.assertEqual(e["full_hashes"][0]["threat_types"], ["SOCIAL_ENGINEERING"])

    def test_mixed_enforceable_and_canary_is_listed(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "1800s", "fullHashes": [
            {"fullHash": R.b64(R.full("evil.example/")), "fullHashDetails": [
                {"threatType": "MALWARE"}, {"threatType": "UNWANTED_SOFTWARE", "attributes": ["CANARY"]}]}]})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes", http_factory=s.factory)
        h = json.loads((self.rep / "gsb" / "confirmations.json").read_text())["entries"][0]["full_hashes"][0]
        self.assertEqual((h["threat_types"], h["canary"]), (["MALWARE"], True))
        d = af.load_reputation(self.rep)
        self.assertEqual(af.gsb_verdict("evil.example", "", d, datetime.now(timezone.utc))["state"], "listed")

    def test_partial_failure_keeps_first_chunk_and_receipt(self):
        cands = [f"h{i}.example/" for i in range(1500)]
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"}), (500, {"error": "x"})]})
        self.addCleanup(s.close)
        rcp = self.tmp / "r.json"
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", cands)), "--yes",
                                "--receipt", str(rcp), http_factory=s.factory)
        self.assertEqual(code, 1, err)
        conf = json.loads((self.rep / "gsb" / "confirmations.json").read_text())
        self.assertEqual(len(conf["entries"]), 970)
        self.assertEqual([r["status"] for r in json.loads(rcp.read_text())["requests"]], [200, 500])

    def test_971_candidates_second_request_has_30_prefixes(self):
        cands = [f"h{i}.example/" for i in range(971)]
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", cands)), "--yes", http_factory=s.factory)
        self.assertEqual([len(r["query"]["hashPrefixes"]) for r in s.requests], [970, 30])

    def test_all_chunked_entries_are_stored(self):
        cands = [f"h{i}.example/" for i in range(1500)]
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", cands)), "--yes", http_factory=s.factory)
        self.assertEqual(len(json.loads((self.rep / "gsb" / "confirmations.json").read_text())["entries"]), 1500)

    def test_unreadable_old_confirmations_are_reported(self):
        (self.rep / "gsb").mkdir(parents=True, exist_ok=True)
        (self.rep / "gsb" / "confirmations.json").write_text("{not json")
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        _, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes",
                             http_factory=s.factory)
        self.assertIn("could not be read", err)


def vt_body(m=0, s=0):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": m, "suspicious": s, "harmless": 60,
                                                             "undetected": 10, "timeout": 0}}}}


class TestVirusTotal(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_VT_KEY"] = FAKE_KEY
        self.slept = []

    def run_vt(self, routes, hosts, *extra):
        s = R.FakeProvider(routes)
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", hosts=hosts)
        code, out, err = self.cli("virustotal", str(nj), "--yes", *extra, http_factory=s.factory,
                                  sleep=self.slept.append)
        return code, err, s

    def test_found_unknown_and_threshold(self):
        code, err, s = self.run_vt({"/api/v3/domains/bad.example": [(200, vt_body(5))],
                                    "/api/v3/domains/new.example": [(404, {"error": {"code": "NotFoundError"}})]},
                                   ["bad.example", "new.example"], "--vt-threshold", "3")
        self.assertEqual(code, 0, err)
        self.assertEqual(s.requests[0]["headers"]["x-apikey"], FAKE_KEY)
        d = af.load_reputation(self.rep)
        self.assertEqual(d.vt_threshold, 3)
        self.assertEqual(d.vt["bad.example"]["stats"]["malicious"], 5)
        self.assertEqual(d.vt["new.example"]["status"], "unknown")

    def test_private_hosts_never_sent(self):
        code, err, s = self.run_vt({}, ["10.0.0.1", "printer.local", "intranet", "db.internal"])
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("no public hosts", err)

    def test_non_canonical_hosts_never_sent(self):
        code, err, s = self.run_vt({}, ["a/b.example", "x.example/../y", "a b.example"])
        self.assertEqual((code, s.requests), (0, []))

    def test_non_global_hosts_never_sent(self):
        hosts = ["0.1.2.3", "100.64.0.1", "192.0.0.8", "192.0.2.5", "198.18.0.1", "198.51.100.7",
                 "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255", "pc.localdomain", "a.corp",
                 "a.home", "a.intranet", "a.private", "a.test", "a.invalid"]
        code, err, s = self.run_vt({}, hosts)
        self.assertEqual((code, s.requests), (0, []))

    def test_threshold_is_kept_when_not_given(self):
        r = {"/api/v3/domains/a.example": [(200, vt_body())], "/api/v3/domains/b.example": [(200, vt_body())]}
        self.run_vt(r, ["a.example"], "--vt-threshold", "5")
        self.run_vt(r, ["b.example"])
        doc = json.loads((self.rep / "vt" / "results.json").read_text())
        self.assertEqual(doc["vt_threshold"], 5)

    def test_explicit_threshold_is_saved_even_when_nothing_is_sent(self):
        r = {"/api/v3/domains/a.example": [(200, vt_body())]}
        self.run_vt(r, ["a.example"], "--vt-threshold", "5")
        code, err, s = self.run_vt({}, ["a.example"], "--vt-threshold", "1")
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("threshold set to 1", err)
        self.assertEqual(json.loads((self.rep / "vt" / "results.json").read_text())["vt_threshold"], 1)
        self.assertEqual(len(json.loads((self.rep / "vt" / "results.json").read_text())["results"]), 1)

    def test_dry_run_does_not_save_the_threshold(self):
        r = {"/api/v3/domains/a.example": [(200, vt_body())]}
        self.run_vt(r, ["a.example"], "--vt-threshold", "5")
        self.run_vt({}, ["b.example"], "--vt-threshold", "1", "--dry-run")
        self.assertEqual(json.loads((self.rep / "vt" / "results.json").read_text())["vt_threshold"], 5)

    def test_stats_accept_only_plain_non_negative_ints(self):
        body = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 1e999, "suspicious": True, "harmless": "5", "undetected": -3, "timeout": 7}}}}
        raw = json.dumps(body).encode()
        self.assertEqual(ar._vt_stats(raw), {"malicious": 0, "suspicious": 0, "harmless": 0,
                                             "undetected": 0, "timeout": 7})

    def test_403_5xx_and_unreadable_bodies_stop(self):
        for status, body, word in ((403, {"error": {"message": FAKE_KEY}}, "rejected"),
                                   (503, {"error": {}}, "HTTP 503"), (200, b"not json", "not readable"),
                                   (200, {"data": []}, "not readable")):
            code, err, s = self.run_vt({"/api/v3/domains/a.example": [(status, body)]}, ["a.example"])
            self.assertEqual(code, 1, (status, err))
            self.assertIn(word, err)
            self.assertNotIn(FAKE_KEY, err)

    def test_results_schema_and_pruning(self):
        old = datetime.now(timezone.utc) - timedelta(days=8)
        R.write_cache(self.rep, vt=[R.vt_result("old.example", 0, at=old)])
        self.run_vt({"/api/v3/domains/a.example": [(200, vt_body(1))],
                     "/api/v3/domains/b.example": [(404, {})]}, ["a.example", "b.example"])
        doc = json.loads((self.rep / "vt" / "results.json").read_text())
        self.assertEqual([r["host"] for r in doc["results"]], ["a.example", "b.example"])
        self.assertEqual([r["status"] for r in doc["results"]], ["found", "unknown"])
        for r in doc["results"]:
            self.assertTrue(r["checked_at"].endswith("+00:00"))
            datetime.fromisoformat(r["checked_at"])

    def test_unreadable_results_file_is_reported(self):
        (self.rep / "vt").mkdir(parents=True)
        (self.rep / "vt" / "results.json").write_text("{nope")
        code, err, s = self.run_vt({"/api/v3/domains/a.example": [(200, vt_body())]}, ["a.example"])
        self.assertEqual(code, 0)
        self.assertIn("could not be read; its results and today's count were reset", err)

    def test_request_is_counted_even_when_it_fails(self):
        self.run_vt({"/api/v3/domains/a.example": [(503, {})]}, ["a.example"])
        doc = json.loads((self.rep / "vt" / "results.json").read_text())
        self.assertEqual(doc["daily"]["count"], 1)

    def test_day_rollover_resets_the_count(self):
        t = [datetime(2026, 10, 30, 23, 58, tzinfo=timezone.utc)]
        def clock():
            v = t[0]
            t[0] = v + timedelta(minutes=1)
            return v
        s = R.FakeProvider({"/api/v3/domains/a.example": [(200, vt_body())],
                            "/api/v3/domains/b.example": [(200, vt_body())]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", hosts=["a.example", "b.example"])
        self.cli("virustotal", str(nj), "--yes", http_factory=s.factory, sleep=self.slept.append, now=clock)
        doc = json.loads((self.rep / "vt" / "results.json").read_text())
        self.assertEqual(doc["daily"], {"date": "2026-10-31", "count": 1})

    def test_throttled_to_four_a_minute(self):
        hosts = [f"h{i}.example" for i in range(6)]
        self.run_vt({f"/api/v3/domains/{h}": [(200, vt_body())] for h in hosts}, hosts)
        self.assertEqual(self.slept, [15.0] * 5)

    def test_429_stops_and_keeps_what_was_checked(self):
        code, err, s = self.run_vt({"/api/v3/domains/a.example": [(200, vt_body())],
                                    "/api/v3/domains/b.example": [(429, {"error": {"code": "QuotaExceededError"}})]},
                                   ["a.example", "b.example", "c.example"])
        self.assertEqual(code, 1)
        self.assertIn("quota", err)
        self.assertEqual(len(s.requests), 2)
        self.assertIn("a.example", af.load_reputation(self.rep).vt)

    def test_recently_checked_hosts_are_skipped(self):
        R.write_cache(self.rep, vt=[R.vt_result("a.example", 0)])
        code, err, s = self.run_vt({"/api/v3/domains/b.example": [(200, vt_body())]}, ["a.example", "b.example"])
        self.assertEqual([r["path"] for r in s.requests], ["/api/v3/domains/b.example"])
        self.assertIn("a.example", af.load_reputation(self.rep).vt)

    def test_daily_budget_caps_the_run(self):
        fixed = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
        today = fixed.date().isoformat()
        (self.rep / "vt").mkdir(parents=True)
        (self.rep / "vt" / "results.json").write_text(json.dumps(
            {"schema": 1, "vt_threshold": 2, "daily": {"date": today, "count": ar.VT_DAILY - 1}, "results": []}))
        s = R.FakeProvider({"/api/v3/domains/a.example": [(200, vt_body())]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", hosts=["a.example", "b.example"])
        self.cli("virustotal", str(nj), "--yes", http_factory=s.factory, sleep=self.slept.append,
                 now=lambda: fixed)
        self.assertEqual([r["path"] for r in s.requests], ["/api/v3/domains/a.example"])
        self.assertEqual(json.loads((self.rep / "vt" / "results.json").read_text())["daily"]["count"], ar.VT_DAILY)
        s = R.FakeProvider()
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", hosts=["b.example"])
        code, _, err = self.cli("virustotal", str(nj), "--yes", http_factory=s.factory, now=lambda: fixed)
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("budget", err)

    def test_rejected_key_stops(self):
        code, err, s = self.run_vt({"/api/v3/domains/a.example": [(401, {"error": {}})]}, ["a.example"])
        self.assertEqual(code, 1)
        self.assertIn("rejected", err)
        self.assertNotIn(FAKE_KEY, err)

    def test_dry_run_prints_hostnames_and_sends_nothing(self):
        s = R.FakeProvider()
        self.addCleanup(s.close)
        os.environ.pop("ACTUALIS_VT_KEY")
        with mock.patch.object(ar.subprocess, "run") as run:
            code, _, err = self.cli("virustotal", str(net_json(self.tmp / "n.json", hosts=["bad.example"])),
                                    "--dry-run", "--key-command", "x", http_factory=s.factory)
        run.assert_not_called()
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("bad.example", err)
        self.assertIn("in plain text to VirusTotal", err)

    def test_key_command_not_run_without_a_terminal_or_yes(self):
        nj = net_json(self.tmp / "n.json", hosts=["bad.example"])
        with mock.patch.object(ar.subprocess, "run") as run:
            code, _, err = self.cli("virustotal", str(nj), "--key-command", "x")
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        run.assert_not_called()

    def test_ip_uses_the_ip_endpoint(self):
        code, err, s = self.run_vt({"/api/v3/ip_addresses/8.8.8.8": [(200, vt_body())]}, ["8.8.8.8"])
        self.assertEqual([r["path"] for r in s.requests], ["/api/v3/ip_addresses/8.8.8.8"])


class ProtobufReaderTest(unittest.TestCase):
    """Safe Browsing v5 answers in protobuf only (alt=json gives HTTP 400)."""

    def test_hash_list_round_trip_matches_the_json_shape(self):
        hl = R.hash_list("mw-4b", [R.prefix("a.example/"), R.prefix("b.example/")], wait="1800s")
        got = ar.pb_hash_lists(R.pb_hash_lists({"hashLists": [hl]}))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["name"], "mw-4b")
        self.assertEqual(got[0]["additionsFourBytes"], hl["additionsFourBytes"])
        self.assertEqual(got[0]["sha256Checksum"], hl["sha256Checksum"])
        self.assertEqual(ar.parse_duration(got[0]["minimumWaitDuration"]), 1800.0)
        self.assertEqual(ar.apply_list_update(b"", got[0]), ar.apply_list_update(b"", hl))

    def test_unknown_and_fixed_width_fields_are_skipped(self):
        body = R._pb(1, R._pb(1, b"mw-4b") + b"\x6d\x01\x02\x03\x04" + R._pb(15, 7)
                     + b"\x61" + b"\x00" * 8)
        self.assertEqual(ar.pb_hash_lists(body), [{"name": "mw-4b"}])

    def test_malformed_input_raises_value_error(self):
        for bad in (b"{\"hashLists\": []}", b"\x0a\x05mw", b"\x0a", b"\x08" + b"\xff" * 11, b"\x00\x01",
                    b"\x0b\x00", R._pb(1, R._pb(1, b"\xff\xfe"))):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ar.pb_hash_lists(bad)

    def test_search_reads_packed_and_unpacked_attributes(self):
        h = R.full("evil.example/")
        det_packed = R._pb(1, 1) + R._pb(2, b"\x01")                 # MALWARE, [CANARY] packed
        det_plain = R._pb(1, 3) + R._pb(2, 0)                        # UNWANTED_SOFTWARE, unspecified
        det_new = R._pb(1, 42)
        body = R._pb(1, R._pb(1, h) + R._pb(2, det_packed) + R._pb(2, det_plain) + R._pb(2, det_new)) \
            + R._pb(2, R._pb(1, 300) + R._pb(2, 500_000_000))
        doc = ar.pb_search(body)
        self.assertEqual(ar.parse_duration(doc["cacheDuration"]), 300.5)
        dets = doc["fullHashes"][0]["fullHashDetails"]
        self.assertEqual(doc["fullHashes"][0]["fullHash"], R.b64(h))
        self.assertEqual([(d["threatType"], d["attributes"]) for d in dets],
                         [("MALWARE", ["CANARY"]), ("UNWANTED_SOFTWARE", ["THREAT_ATTRIBUTE_UNSPECIFIED"]),
                          ("THREAT_TYPE_42", [])])

    def test_empty_search_response_has_no_hashes(self):
        self.assertEqual(ar.pb_search(b""), {"fullHashes": []})


class TlsFloorTest(unittest.TestCase):
    def test_default_context_refuses_old_tls(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        self.assertGreaterEqual(ar.Http(session).context.minimum_version, ssl.TLSVersion.TLSv1_2)
