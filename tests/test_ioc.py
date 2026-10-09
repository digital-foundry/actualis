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


EXAMPLE = """\
# Shai-Hulud wave 1, converted from the Wiz CSV, 2025-09-17
npm:@ctrl/tinycolor@=4.1.1||=4.1.2   id=GHSA-0000-0000-0000 label=shai-hulud from=2025-09-14 until=2025-09-17
npm:eslint-config-prettier@8.10.1||9.1.1||10.1.6||10.1.7   id=MAL-2025-6022
pypi:Requests_Darwin.Lite            # PEP 503 normalises to requests-darwin-lite
crates:evil_crate@>=0.1.0,<0.1.5
go:github.com/evil/mod@<v1.4.2
oci:ghcr.io/evil/img@=sha256:3f2a0000000000000000000000000000000000000000000000000000000000ff
brew:python@3.12                     # the whole thing is the formula name
rubygems:rest-client                 # accepted, not checkable
host:webhook.site                    label=exfil
host:github.com/evil-org
host:=203.0.113.7
"""


class IocFiles:
    """Write IOC files into a temp dir and load them."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, content, name="iocs.txt"):
        path = self.dir / name
        if isinstance(content, str):
            content = content.encode("utf-8")
        path.write_bytes(content)
        return str(path)

    def load(self, content, name="iocs.txt", err=None):
        path = self.write(content, name)
        with redirect_stderr(err if err is not None else io.StringIO()):
            return af.load_ioc([path])

    def fails(self, content, *needles, name="iocs.txt"):
        with self.assertRaises(ValueError) as cm:
            self.load(content, name)
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("--ioc"), msg)
        for n in needles:
            self.assertIn(n, msg)
        return msg


def entries(ioc):
    out = [e for es in ioc.packages.values() for e in es]
    out += [e for es in ioc.host_suffix.values() for e in es]
    out += [e for es in ioc.host_exact.values() for e in es]
    return sorted(out, key=lambda e: (e.source, e.line or 0))


def only(ioc):
    es = entries(ioc)
    assert len(es) == 1, es
    return es[0]


class TestLineFormat(IocFiles, unittest.TestCase):
    def test_example_lines(self):                                       # T-LINE-1
        ioc = self.load(EXAMPLE)
        got = {e.line: e for e in entries(ioc)}
        e = got[2]
        self.assertEqual((e.kind, e.eco, e.name, e.spec_text, e.ref, e.label, e.frm, e.until),
                         ("package", "npm", "@ctrl/tinycolor", "=4.1.1||=4.1.2", "GHSA-0000-0000-0000",
                          "shai-hulud", date(2025, 9, 14), date(2025, 9, 17)))
        self.assertEqual(got[3].spec_text, "=8.10.1||=9.1.1||=10.1.6||=10.1.7")
        self.assertEqual(got[3].ref, "MAL-2025-6022")
        self.assertEqual((got[4].eco, got[4].name, got[4].spec), ("pypi", "requests-darwin-lite", None))
        self.assertEqual((got[5].eco, got[5].name, got[5].spec_text), ("crates", "evil-crate", ">=0.1.0,<0.1.5"))
        self.assertEqual((got[6].eco, got[6].name, got[6].spec_text), ("go", "github.com/evil/mod", "<v1.4.2"))
        self.assertEqual((got[7].eco, got[7].name), ("oci", "ghcr.io/evil/img"))
        self.assertTrue(got[7].spec_text.startswith("=sha256:3f2a"))
        self.assertEqual((got[8].eco, got[8].name, got[8].spec), ("brew", "python@3.12", None))
        self.assertNotIn(9, got)
        self.assertEqual((got[10].kind, got[10].host, got[10].path, got[10].exact_host, got[10].label),
                         ("host", "webhook.site", "", False, "exfil"))
        self.assertEqual((got[11].host, got[11].path), ("github.com", "/evil-org"))
        self.assertEqual((got[12].host, got[12].exact_host), ("203.0.113.7", True))
        src = ioc.sources[0]
        self.assertEqual(src["entries"], {"package": 7, "host": 3})
        self.assertEqual(src["not_checkable"], {"rubygems": 1})
        self.assertEqual(src["format"], "lines")
        self.assertEqual(len(src["sha256"]), 64)
        self.assertTrue(ioc.has_window)
        self.assertEqual(set(ioc.packages), {("npm", "@ctrl/tinycolor"), ("npm", "eslint-config-prettier"),
                                             ("pypi", "requests-darwin-lite"), ("crates", "evil-crate"),
                                             ("go", "github.com/evil/mod"), ("oci", "ghcr.io/evil/img"),
                                             ("brew", "python@3.12")})
        self.assertEqual(set(ioc.host_suffix), {"webhook.site", "github.com"})
        self.assertEqual(set(ioc.host_exact), {"203.0.113.7"})

    def test_comments_blank_bom_crlf_and_no_final_eol(self):            # T-LINE-2
        ioc = self.load(b"\xef\xbb\xbf# head\r\n\r\n   \t\r\n  npm:a  # trailing\r\nnpm:b")
        self.assertEqual([(e.name, e.line) for e in entries(ioc)], [("a", 4), ("b", 5)])
        self.fails("npm:a#b\n", "line 1", "#")
        self.fails("npm:a id=x#y\n", "line 1")

    def test_ecosystem_aliases(self):                                   # T-LINE-3
        words = {"PyPI": "pypi", "pip": "pypi", "crates.io": "crates", "cargo": "crates",
                 "rust": "crates", "golang": "go", "docker": "oci", "container": "oci",
                 "homebrew": "brew", "NPM": "npm"}
        for word, eco in words.items():
            name = "github.com/x/y" if eco == "go" else "xyz"
            self.assertEqual(only(self.load(f"{word}:{name}\n")).eco, eco, word)
        msg = self.fails("npn:foo\n", 'unknown ecosystem "npn"', "known: npm pypi crates go oci brew")
        self.assertIn("not-checkable", msg)
        ioc = self.load("rubygems:x\nvscode:x\nnpm:y\n")
        self.assertEqual(ioc.sources[0]["not_checkable"], {"rubygems": 1, "vscode": 1})

    def test_scoped_npm(self):                                          # T-LINE-4
        e = only(self.load("npm:@s/n@1.2.3\n"))
        self.assertEqual((e.name, e.spec_text), ("@s/n", "=1.2.3"))
        self.assertIsNone(only(self.load("npm:@s/n\n")).spec)
        self.fails("npm:@s/n@\n", "line 1")

    def test_brew_never_splits(self):                                   # T-LINE-5
        e = only(self.load("brew:python@3.12\n"))
        self.assertEqual((e.name, e.spec), ("python@3.12", None))
        self.assertEqual(only(self.load("brew:User/Tap/Name\n")).name, "user/tap/name")

    def test_oci(self):                                                 # T-LINE-6
        e = only(self.load("oci:localhost:5000/x/y@=v1\n"))
        self.assertEqual((e.name, e.spec_text), ("localhost:5000/x/y", "=v1"))
        digest = "sha256:" + "ab" * 32
        self.assertEqual(only(self.load(f"oci:nginx@={digest}\n")).spec_text, "=" + digest)
        self.assertEqual(only(self.load("oci:docker.io/library/nginx@=1.25\n")).name, "nginx")
        self.fails("oci:nginx@=latest\n", "latest")
        self.fails("oci:nginx@>=1.25\n", "line 1")

    def test_rejections(self):                                          # T-LINE-7
        cases = {
            "npm:x@^1.2.0": "^ and ~ ranges are not accepted",
            "npm:x@~1.2.0": "^ and ~ ranges are not accepted",
            "npm:x@1.x": "wildcards are not accepted",
            "npm:x@1.*": "wildcards are not accepted",
            "npm:x@1.2.3,1.2.4": "a comma means AND",
            "npm:x@=1.2.3,=1.2.4": "a comma means AND",
            "npm:x@latest": "latest moves",
            "npm:x@1.2": "write 1.2.0",
            "npm:x@1.2.3||": "empty clause",
            "npm:x@||1.2.3": "empty clause",
            "npm:x@>=1.0.0,,<2.0.0": "empty comparator",
            "npm:x@>=1.0.0, <2.0.0": "key=value",
            "npm:x foo=1": 'unknown attribute "foo"',
            "npm:x id=a id=b": "repeated",
            "npm:x from=2025-02-30": "date",
            "npm:x from=2025-09-14 until=2025-09-13": "until",
            "host:https://x.io": "not a host",
            "host:x.io:8080": "not a host",
            "host:*.x.io": "not a host",
            "host:[::1]": "not a host",
            "npm:BAD NAME": "key=value",
            "pypi:-bad-": "not a valid pypi name",
            "go:nodot/mod": "not a valid go name",
        }
        for line, hint in cases.items():
            with self.subTest(line=line):
                self.fails(line + "\n", "line 1", hint)

    def test_any_version_spellings(self):                               # T-LINE-8
        for spec in ("", "@*", "@>=0", "@>=0.0.0"):
            self.assertIsNone(only(self.load(f"npm:x{spec}\n")).spec, spec)

    def test_broad_host_warning(self):                                  # T-LINE-9
        err = io.StringIO()
        ioc = self.load("npm:x\nhost:github.com\nhost:github.com/evil\n", err=err)
        self.assertEqual(len(entries(ioc)), 3)
        self.assertEqual(err.getvalue().count("matches every download from github.com; add a path"), 1)
        self.assertIn("line 2: host:github.com", err.getvalue())

    def test_caps(self):                                                # T-LINE-10
        self.fails("npm:x@=" + "1" * 129 + "\n", "over 128")
        self.fails("npm:x " + "#" * (1 << 20) + "\n", "line 1", "1 MiB")
        lines = "".join(f"npm:p{i}\n" for i in range(af.IOC_ENTRIES_MAX + 1))
        self.fails(lines, "over 1,000,000 entries; split by ecosystem")

    def test_nothing_checkable(self):                                   # T-LINE-11
        self.fails("", "none of the 0 entries can be checked")
        msg = self.fails("rubygems:a\nrubygems:b\nmaven:c\n", "none of the 3 entries can be checked")
        self.assertIn("rubygems 2", msg)
        self.assertIn("maven 1", msg)


class TestLoadErrors(IocFiles, unittest.TestCase):
    def test_unreadable_inputs_name_the_file(self):                     # T-CLI-1
        missing = str(self.dir / "nope.txt")
        with self.assertRaises(ValueError) as cm:
            af.load_ioc([missing])
        self.assertIn(f"--ioc {missing}: cannot read", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            af.load_ioc([str(self.dir)])
        self.assertIn("cannot read", str(cm.exception))
        self.fails(b"npm:a\nnpm:\xff\n", "iocs.txt line 2", "UTF-8")
        self.fails("npm:a\nnpm:b@^1.0.0\n", "iocs.txt line 2")

    def test_order_sets_source_and_duplicates_count(self):              # T-CLI-4
        a = self.write("npm:x\n", "a.txt")
        b = self.write("npm:x\nhost:evil.io\n", "b.txt")
        ioc = af.load_ioc([b, a])
        xs = ioc.packages[("npm", "x")]
        self.assertEqual([(e.source, e.line) for e in xs], [(0, 1), (1, 1)])
        self.assertEqual([Path(s["path"]).name for s in ioc.sources], ["b.txt", "a.txt"])
