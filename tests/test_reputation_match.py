"""Host reputation, actualis side: expressions, the cache loader, the matcher,
flags and the gate. Every host is invented; the cache is written by
tests/_reputation.py into the temp home."""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
