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

    def test_unimplemented_commands_are_a_usage_error(self):
        for argv in (("confirm", "x.json"), ("virustotal", "x.json")):
            code, _, err = self.cli(*argv)
            self.assertEqual(code, 2)
            self.assertIn("not implemented yet", err)
            self.assertNotIn("Traceback", err)

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
        s = self.serve((302, b""))
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual(len(s.requests), 1)

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
