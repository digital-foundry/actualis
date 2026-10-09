"""--ioc FILE: offline matching of agent downloads against a known-bad list.

Every fixture is built in code. The spec is ioc-spec.md (N2a, pass 3); the
test names carry its §10 ids.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(spec)
    sys.modules["actualis"] = af
    spec.loader.exec_module(af)

TS = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


class TestVersions(unittest.TestCase):
    def test_semver_precedence(self):                                   # T-VER-1
        chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                 "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        keys = [af._ioc_semver_key(v) for v in chain]
        self.assertNotIn(None, keys)
        for a, b in zip(keys, keys[1:]):
            self.assertLess(a, b)
        self.assertEqual(af._ioc_semver_key("1.0.0+build.5"), af._ioc_semver_key("1.0.0"))
        self.assertEqual(af._ioc_semver_key("v1.2.3"), af._ioc_semver_key("1.2.3"))
        self.assertLess(af._ioc_semver_key("1.9.0"), af._ioc_semver_key("1.10.0"))
        for bad in ("1.2", "4", "01.2.3", "1.2.3-01", "latest", "^1.2.3", "1.2.3.4", "", "1.2.x",
                    "١.2.3"):
            self.assertIsNone(af._ioc_semver_key(bad), bad)

    def test_go_pseudo_versions(self):                                  # T-VER-2
        pseudo = af._ioc_semver_key("v0.0.0-20210101000000-abcdefabcdef")
        self.assertIsNotNone(pseudo)
        self.assertLess(pseudo, af._ioc_semver_key("v0.0.0"))
        self.assertLess(af._ioc_semver_key("v1.2.4-0.20210101000000-abcdefabcdef"),
                        af._ioc_semver_key("v1.2.4"))
        self.assertGreater(af._ioc_semver_key("v1.2.4-0.20210101000000-abcdefabcdef"),
                           af._ioc_semver_key("v1.2.3"))
        self.assertEqual(af._ioc_semver_key("v2.0.0+incompatible"), af._ioc_semver_key("v2.0.0"))

    def test_pep440(self):                                              # T-VER-3
        k = af._ioc_pep440_key
        self.assertEqual(k("1.0"), k("1.0.0"))
        chain = ["1.0.dev0", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1"]
        for a, b in zip(chain, chain[1:]):
            self.assertLess(k(a), k(b), (a, b))
        self.assertGreater(k("1!0.1"), k("2.0"))
        self.assertEqual(k("1.0+local.7"), k("1.0"))
        self.assertEqual(k("1.0alpha1"), k("1.0a1"))
        self.assertEqual(k("1.0beta1"), k("1.0b1"))
        for spelling in ("1.0c1", "1.0pre1", "1.0preview1", "1.0-rc.1"):
            self.assertEqual(k(spelling), k("1.0rc1"), spelling)
        self.assertLess(k("1.0a1.dev1"), k("1.0a1"))
        self.assertLess(k("1.0.post1.dev1"), k("1.0.post1"))
        self.assertGreater(k("1.0.post1.dev1"), k("1.0"))
        self.assertEqual(k("V1.0"), k("1.0"))
        for bad in ("latest", "1.0-foo", "", "x" * 129):
            self.assertIsNone(k(bad), bad)

    def test_triple_equals_is_string_equality(self):                    # T-VER-3
        spec = af._ioc_parse_spec("pypi", "===1.0-foo")
        self.assertTrue(af._ioc_spec_contains("pypi", spec, "1.0-foo"))
        self.assertFalse(af._ioc_spec_contains("pypi", spec, "1.0-FOO"))
        self.assertFalse(af._ioc_spec_contains("pypi", spec, "1.0"))
