"""tools/pii-gate.py: the gate that keeps personal data out of the public repo.

Every seeded value here is synthetic, and each is built by concatenation at
run time, so this file passes the gate it tests.
"""
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("pii_gate", ROOT / "tools" / "pii-gate.py")
pg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pg)

NAME = "mbeckett"
HOME = "/Users/" + NAME
EMAIL = "jordan.ruiz" + "@" + "gmail.com"
PHONE = "(617) 555-" + "2368"
TAILNET = "studio.tail9f3c." + "ts" + ".net"
PUBLIC_IP = "52.14." + "7.201"
TOKEN = "ghp_" + "Zq81LmP0vT6sR2wXy9KcQe"


def gate(**kw):
    return pg.Gate(kw.pop("allow", set()), kw.pop("terms", []), pg._load_secret_rxs())


def hits(line, in_tests=False, **kw):
    return gate(**kw).scan_line(line, in_tests=in_tests)


class Detectors(unittest.TestCase):
    def test_each_detector_fires_on_seeded_synthetic_pii(self):
        cases = {
            "home-path": [f"cd {HOME}/src", "C:\\Users\\" + "mbeckett\\src", "/home/" + "mbeckett/x"],
            "email": [f"mail {EMAIL} today", f"mailto:{EMAIL}", f"Email:{EMAIL}",
                      f"contact/{EMAIL}"],
            "phone": [f"call {PHONE}", "+4420" + "79460958", "(617)555-" + "2368",
                      "+44 20 " + "7946 0958"],
            "tailnet": [f"ssh {TAILNET}"],
            "ip": [f"curl http://{PUBLIC_IP}/x", "052.014." + "007.201",
                   "2600:1f18" + ":4a3:6900::1"],
            "uuid": ["session 3f2b8c1e-9a4d-" + "4e7b-b2c5-8d1f6a0e9c47"],
            "secret": [f"export GH={TOKEN}", "Authorization: Bearer " + "Zq81LmP0vT6sR2wX",
                       "ghp%5F" + TOKEN[4:], "\uff47\uff48\uff50_" + TOKEN[4:]],
        }
        for det, lines in cases.items():
            for line in lines:
                with self.subTest(det=det, line=line):
                    self.assertIn(det, hits(line))

    def test_placeholders_and_reserved_values_pass(self):
        for line in ("/Users/x/proj", "/home/runner/work", "/Users/you/.claude",
                     "ops" + "@example.com", "a" + "@corp.example", "x" + "@h.test",
                     "security" + "@digitalfoundry.tech", "noreply" + "@anthropic.com",
                     "git clone git" + "@github.com:o/r.git",
                     "git clone https://TOKEN" + "@github.com/o/r",
                     "10.0.0.1 192.168.1.1 192.0.2.7 198.51.100.7 203.0.113.9 100.64.0.1",
                     "127.0.0.1 224.0.0.1 8.8.8.8", "version 1.2.3.4.5",
                     "2001:db8::1 fe80::1 ::1 at 12:34:56", "std::vector<int>",
                     "scp ci:tok" + "@h:/srv", "ssh://git" + "@gitlab.com/x/y.git",
                     "id 1234567890123 and 2026-11-01 10:00",
                     "(617) 555-" + "0142",
                     "00000000-0000-4000-8000-000000000001",
                     "0a1b2c3d-1111-4222-8333-444455556666",
                     "12345678-1234-1234-1234-123456789abc"):
            with self.subTest(line=line):
                self.assertEqual(hits(line), [])

    def test_a_form_feed_cannot_split_a_match_or_shift_line_numbers(self):
        self.assertIn("home-path", hits("/Users/\x0c" + NAME))
        found = gate().scan_file("docs/a.md", "a\x0cb\nreach " + EMAIL + "\n")
        self.assertEqual(found, [(2, "email")])

    def test_reserved_ranges_are_read_the_same_on_every_python(self):
        """ipaddress's is_global differs across patch releases (macOS 3.9 in
        CI disagreed with 3.9 locally); the gate uses its own range list."""
        for v in ("0.1.2.3", "100.64.0.1", "100.127.255.254", "192.0.0.8", "192.0.2.5",
                  "198.18.0.1", "198.19.255.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                  "::ffff:10.0.0.1", "2001:db8::1", "fd00::1", "fe80::1", "::1"):
            with self.subTest(v=v):
                self.assertTrue(pg._ip_ok(v))
        for v in ("100.63.0.1", "100.128.0.1", "198.17.0.1", "198.20.0.1", "2600:1f18" + "::1"):
            with self.subTest(v=v):
                self.assertFalse(pg._ip_ok(v))

    def test_secret_is_not_checked_under_tests(self):
        self.assertEqual(hits(f"export GH={TOKEN}", in_tests=True), [])


class Evasion(unittest.TestCase):
    def test_encoded_forms_are_decoded(self):
        name = NAME
        for line in ("&#x2F;Users&#x2F;" + name, "&#47;home&#47;" + name,
                     "%2FUsers%2F" + name, "\\u002fUsers\\u002f" + name,
                     "%26%23x2F%3BUsers%26%23x2F%3B" + name,     # percent over HTML
                     "\\/Users\\/" + name):
            with self.subTest(line=line):
                self.assertIn("home-path", hits(line))

    def test_lookalikes_and_invisible_characters_are_canonicalised(self):
        for line in ("/Us\u0435rs/" + NAME,                  # Cyrillic e
                     "/Us\u200bers/" + NAME,                 # zero-width space
                     "\uff0fUsers\uff0f" + NAME,             # fullwidth solidus
                     "jordan.ruiz\uff20" + "gmail.com"):           # fullwidth @
            with self.subTest(line=repr(line)):
                self.assertNotEqual(hits(line), [])

    def test_text_that_never_settles_is_a_hit(self):
        line = "%" + "25" * (pg.MAX_PASSES + 2) + "41"
        self.assertIn("decode", hits(line))


class Allowances(unittest.TestCase):
    def test_inline_marker_needs_a_reason(self):
        self.assertEqual(hits(f"{EMAIL}  # pii-ok: synthetic sender in a fixture"), [])
        self.assertIn("email", hits(f"{EMAIL}  # pii-ok:"))

    def test_allow_entry_matches_exact_value_case_folded(self):
        self.assertEqual(hits(f"to {EMAIL}", allow={EMAIL.upper()}), [])
        self.assertIn("email", hits(f"to {EMAIL}", allow={"other" + EMAIL}))

    def test_allow_file_entries_need_a_reason(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".pii-allow"
            p.write_text(f"# comment\n\n{EMAIL} # synthetic fixture\n", encoding="utf-8")
            self.assertEqual(pg.load_allow(p), {EMAIL})
            for bad in (f"{EMAIL}\n", f"{EMAIL} # \n", f"{EMAIL}#no-space-separator\n"):
                with self.subTest(bad=bad):
                    p.write_text(bad, encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        pg.load_allow(p)


class Terms(unittest.TestCase):
    def test_literal_terms_match_whole_words_after_canonicalising(self):
        terms = pg.parse_terms("# private list\nMorgan Beckett\n/qu[a4]rry\\s+lane/\n")
        for line in ("Thanks, morgan beckett", "morgan  beckett", "morgan-beckett",
                     "Morgan_Beckett"):
            with self.subTest(line=line):
                self.assertIn("term", hits(line, terms=terms))
        self.assertIn("term", hits("M\u043ergan Beckett wrote this", terms=terms))
        self.assertIn("term", hits("12 QU4RRY  Lane", terms=terms))
        self.assertEqual(hits("Morgan Becketts", terms=terms), [])

    def test_attribution_lines_may_carry_the_name(self):
        terms = pg.parse_terms("Morgan Beckett\n")
        self.assertEqual(hits("Copyright 2026 Morgan Beckett", terms=terms), [])
        self.assertEqual(hits("# Copyright 2026 Morgan Beckett", terms=terms), [])
        self.assertEqual(hits('authors = [{name = "Morgan Beckett"}]', terms=terms), [])
        self.assertIn("term", hits("Morgan Beckett, 12 Quarry Lane (copyright)", terms=terms))

    def test_an_empty_terms_list_fails_closed(self):
        for text in ("", "# only a comment\n\n"):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                pg.parse_terms(text)

    def test_an_invalid_regex_fails_closed_without_echoing_it(self):
        with self.assertRaises(SystemExit) as cm:
            pg.parse_terms("/secretname(/\n")
        self.assertNotIn("secretname", str(cm.exception))


@unittest.skipUnless(shutil.which("git"), "needs git")
class CommandLine(unittest.TestCase):
    def _repo(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for rel, text in files.items():
            (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(d) / rel).write_text(text, encoding="utf-8")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"]):
            subprocess.run(cmd, cwd=d, check=True, capture_output=True)
        return d

    def _run(self, argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        old = dict(os.environ)
        try:
            if env is not None:
                os.environ.clear()
                os.environ.update(env)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = pg.main(argv)
        finally:
            os.environ.clear()
            os.environ.update(old)
        return rc, out.getvalue() + err.getvalue()

    def test_reports_location_and_detector_never_the_value(self):
        d = self._repo({"docs/a.md": f"ok\nreach {EMAIL} or {PHONE}\n", "img.png": EMAIL})
        rc, out = self._run(["--root", d])
        self.assertEqual(rc, 1)
        self.assertIn("docs/a.md:2: email", out)
        self.assertIn("docs/a.md:2: phone", out)
        self.assertNotIn("img.png", out)
        for value in (EMAIL, "jordan", "gmail", "2368"):
            self.assertNotIn(value, out)

    def test_non_ascii_names_and_stray_bytes_are_still_scanned(self):
        d = self._repo({"docs/caf\u00e9.md": f"{EMAIL}\n"})
        (Path(d) / "latin1.md").write_bytes(b"caf\xe9 " + EMAIL.encode() + b"\n")
        subprocess.run(["git", "add", "-A"], cwd=d, check=True, capture_output=True)
        rc, out = self._run(["--root", d])
        self.assertEqual(rc, 1)
        self.assertIn(":1: email", out)
        self.assertIn("latin1.md:1: email", out)
        self.assertEqual(out.count(": email"), 2, out)

    def test_an_unreadable_allow_file_fails_closed(self):
        d = self._repo({"a.md": "clean\n"})
        (Path(d) / ".pii-allow").write_bytes(b"\xff\xfe junk # reason\n")
        rc, out = self._run(["--root", d])
        self.assertEqual(rc, 2)

    def test_full_mode_fails_closed_without_a_terms_list(self):
        d = self._repo({"a.md": "clean\n"})
        env = {k: v for k, v in os.environ.items()
               if k not in (pg.TERMS_ENV, "OP_SERVICE_ACCOUNT_TOKEN")}
        rc, out = self._run(["--root", d, "--full"], env=env)
        self.assertEqual(rc, 2)

    def test_full_mode_reads_the_terms_file_and_keeps_terms_out_of_the_log(self):
        d = self._repo({"a.md": "notes from Morgan Beckett\n"})
        terms = Path(tempfile.mkdtemp()) / "terms.txt"
        self.addCleanup(shutil.rmtree, terms.parent, ignore_errors=True)
        terms.write_text("Morgan Beckett\n", encoding="utf-8")
        rc, out = self._run(["--root", d, "--full"], env=dict(os.environ, **{pg.TERMS_ENV: str(terms)}))
        self.assertEqual(rc, 1)
        self.assertIn("a.md:1: term", out)
        self.assertNotIn("Beckett", out)

    def test_this_repository_is_clean(self):
        rc, out = self._run([])
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
