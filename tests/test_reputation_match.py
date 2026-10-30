"""Host reputation, actualis side: expressions, the cache loader, the matcher,
flags and the gate. Every host is invented; the cache is written by
tests/_reputation.py into the temp home."""
from __future__ import annotations

import hashlib
import os
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_X import af  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
