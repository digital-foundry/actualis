"""Host reputation, actualis side: expressions, the cache loader, the matcher,
flags and the gate. Every host is invented; the cache is written by
tests/_reputation.py into the temp home."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_X import af  # noqa: E402
import _reputation as R  # noqa: E402


class TestIsolation(unittest.TestCase):
    def test_cache_dirs_are_inside_the_temp_home(self):
        for var in ("XDG_CACHE_HOME", "ACTUALIS_REPUTATION_DIR", "LOCALAPPDATA"):
            self.assertTrue(os.environ[var].startswith(_fixtures.TEMP_HOME), var)
        self.assertTrue(str(af.reputation_dir()).startswith(_fixtures.TEMP_HOME))

    def test_no_socket_leaves_the_machine(self):
        with self.assertRaises(PermissionError):
            socket.getaddrinfo("safebrowsing.googleapis.com", 443)
        with self.assertRaises(PermissionError):
            socket.create_connection(("192.0.2.1", 443), timeout=1)


class TestExpressions(unittest.TestCase):
    def test_google_rice_example_hashes(self):
        # The three expressions of Google's Local Database worked example.
        self.assertEqual(af.sb_hash("a.example.com/")[:4].hex(), "291bc542")
        self.assertEqual(af.sb_hash("b.example.com/")[:4].hex(), "1d32c508")
        self.assertEqual(af.sb_hash("y.example.com/")[:4].hex(), "f7a502e5")

    def test_host_suffixes_last_five_labels_never_tld(self):
        self.assertEqual(af.sb_expressions("a.b.c.d.e.f.g"),
                         ["a.b.c.d.e.f.g/", "c.d.e.f.g/", "d.e.f.g/", "e.f.g/", "f.g/"])
        self.assertEqual(af.sb_expressions("evil.example"), ["evil.example/"])
        self.assertEqual(af.sb_expressions("x.evil.example"), ["x.evil.example/", "evil.example/"])

    def test_ip_has_only_itself(self):
        self.assertEqual(af.sb_expressions("8.8.8.8"), ["8.8.8.8/"])

    def test_paths_exact_then_prefixes_no_query(self):
        self.assertEqual(af.sb_expressions("a.b.example", "/1/2.html?param=1#frag"),
                         ["a.b.example/1/2.html", "a.b.example/", "a.b.example/1/",
                          "b.example/1/2.html", "b.example/", "b.example/1/"])

    def test_path_prefixes_capped_at_four_from_root(self):
        exprs = af.sb_expressions("h.example", "/1/2/3/4/5/6.html")
        self.assertEqual(exprs, ["h.example/1/2/3/4/5/6.html", "h.example/", "h.example/1/",
                                 "h.example/1/2/", "h.example/1/2/3/"])

    def test_path_canonicalisation(self):
        self.assertEqual(af.sb_expressions("h.example", "/a/./b/../c//d")[0], "h.example/a/c/d")
        self.assertEqual(af.sb_expressions("h.example", "/%2541%2542")[0], "h.example/AB")
        self.assertEqual(af.sb_expressions("h.example", "/a b")[0], "h.example/a%20b")

    def test_private_hosts_are_skipped(self):
        for h in ("localhost", "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.1.1",
                  "printer.local", "app.localhost", "db.internal", "intranet", "[::1]", "[2001:db8::1]"):
            self.assertTrue(af.reputation_skip(h), h)
        for h in ("evil.example", "8.8.8.8", "registry.npmjs.org"):
            self.assertFalse(af.reputation_skip(h), h)

    def test_mark_falls_back_to_ascii(self):
        self.assertEqual(af.NET_MARK.translate(af._GLYPH_TABLE), "[+net]")


class CacheCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=_fixtures.TEMP_HOME)
        self.root = Path(self._tmp.name) / "rep"

    def tearDown(self):
        self._tmp.cleanup()


class TestLoader(CacheCase):
    def test_absent(self):
        d = af.load_reputation(self.root)
        self.assertEqual((d.status, d.lists), ("absent", {}))

    def test_ok_reads_all_lists(self):
        R.write_cache(self.root, {"mw-4b": [R.prefix("evil.example/")]})
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "ok", d.error)
        self.assertEqual(set(d.lists), set(af.REPUTATION_LISTS))
        self.assertEqual(d.lists["mw-4b"], R.prefix("evil.example/"))
        self.assertIsNotNone(d.oldest)

    def test_corrupt_checksum(self):
        R.write_cache(self.root, {"mw-4b": [R.prefix("evil.example/")]})
        f = next((self.root / "gsb").glob("mw-4b.*.prefixes"))
        f.write_bytes(b"\x00\x00\x00\x01")
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("mw-4b", d.error)

    def test_corrupt_missing_list(self):
        R.write_cache(self.root)
        state = json.loads((self.root / "gsb" / "state.json").read_text())
        state["lists"] = state["lists"][1:]
        (self.root / "gsb" / "state.json").write_text(json.dumps(state))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    def test_corrupt_not_json_or_wrong_schema(self):
        R.write_cache(self.root)
        (self.root / "gsb" / "state.json").write_text("{nope")
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")
        (self.root / "gsb" / "state.json").write_text(json.dumps({"schema": 2, "lists": []}))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    def test_corrupt_file_name_escapes_the_directory(self):
        R.write_cache(self.root)
        state = json.loads((self.root / "gsb" / "state.json").read_text())
        state["lists"][0]["file"] = "../../etc/passwd"
        (self.root / "gsb" / "state.json").write_text(json.dumps(state))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_corrupt_symlinked_file(self):
        R.write_cache(self.root)
        f = next((self.root / "gsb").glob("se-4b.*.prefixes"))
        real = self.root / "elsewhere"
        real.write_bytes(f.read_bytes())
        f.unlink()
        f.symlink_to(real)
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("symlink", d.error)

    def test_corrupt_unsorted_list(self):
        R.write_cache(self.root)
        gsb = self.root / "gsb"
        blob = b"\x00\x00\x00\x02\x00\x00\x00\x01"
        sha = hashlib.sha256(blob).hexdigest()
        state = json.loads((gsb / "state.json").read_text())
        e = state["lists"][0]
        fname = f"{e['name']}.{sha[:16]}.prefixes"
        (gsb / fname).write_bytes(blob)
        e.update(file=fname, sha256=sha, prefix_count=2)
        (gsb / "state.json").write_text(json.dumps(state))
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("not sorted", d.error)

    def test_nested_json_fails_closed(self):
        deep = b"[" * 300000 + b"]" * 300000
        R.write_cache(self.root, vt=[])
        (self.root / "gsb" / "confirmations.json").write_bytes(deep)
        (self.root / "vt" / "results.json").write_bytes(deep)
        d = af.load_reputation(self.root)
        self.assertEqual((d.status, d.confirmations, d.vt), ("ok", {}, {}))
        self.assertTrue(d.confirmations_error)
        self.assertTrue(d.vt_error)
        (self.root / "gsb" / "state.json").write_bytes(deep)
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_corrupt_symlinked_state(self):
        R.write_cache(self.root)
        s = self.root / "gsb" / "state.json"
        real = self.root / "state.real"
        real.write_bytes(s.read_bytes())
        s.unlink()
        s.symlink_to(real)
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    def test_corrupt_fetched_in_the_future(self):
        R.write_cache(self.root, fetched_at=datetime.now(timezone.utc) + timedelta(days=3))
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("future", d.error)

    def test_bad_confirmations_are_ignored_not_fatal(self):
        R.write_cache(self.root)
        (self.root / "gsb" / "confirmations.json").write_text("[1,2")
        d = af.load_reputation(self.root)
        self.assertEqual((d.status, d.confirmations), ("ok", {}))
        self.assertIsNotNone(d.confirmations_error)

    def test_vt_and_threshold(self):
        R.write_cache(self.root, vt=[R.vt_result("evil.example", 5)], vt_threshold=3)
        d = af.load_reputation(self.root)
        self.assertEqual(d.vt_threshold, 3)
        self.assertEqual(d.vt["evil.example"]["stats"]["malicious"], 5)

    def test_last_network_reads_the_newest_valid_line(self):
        R.write_cache(self.root, log=[{"at": "2026-10-30T14:02:00+00:00", "provider": "gsb"},
                                      {"at": "2026-10-30T15:00:00+00:00", "provider": "vt"}])
        with open(self.root / "network-log.jsonl", "a") as fh:
            fh.write("{broken\n")
        self.assertEqual(af.reputation_last_network(self.root),
                         {"at": "2026-10-30T15:00:00+00:00", "provider": "vt"})
        self.assertIsNone(af.reputation_last_network(self.root / "nope"))


if __name__ == "__main__":
    unittest.main()
