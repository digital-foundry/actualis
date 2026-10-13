"""--network --html: one self-contained page. Everything escaped, nothing
fetched, the embedded JSON equal to --network --json. All synthetic."""
from __future__ import annotations

import base64
import hashlib
import html.parser
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(spec)
    sys.modules["actualis"] = af
    spec.loader.exec_module(af)


class TestShares(unittest.TestCase):
    def test_shares_add_up_and_floor_non_zero(self):
        self.assertEqual(af._net_shares([1, 1000, 0], 20), [1, 19, 0])
        self.assertEqual(sum(af._net_shares([3, 5, 7], 1000)), 1000)
        self.assertEqual(af._net_shares([0, 0, 0], 10), [0, 0, 0])

    def test_terminal_bar_uses_the_same_shares(self):
        t = {"unasked": 7, "unknown": 2, "asked": 1}
        bar = af._net_approval_bar(t, 30)
        cells = af._net_shares([7, 2, 1], 30)
        self.assertEqual([bar.count("\u2588"), bar.count("\u2592"), bar.count("\u2591")], cells)


TS0 = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
HOSTILE = '"><img src=x onerror=1></script><script>alert(1)</script>‮]]>'


def fleet(n=6, with_prompts=False):
    f = af.Fleet()
    f.with_prompts = with_prompts
    for k in range(n):
        tool, args = (("WebFetch", {"url": f"https://h1.example/{HOSTILE}"}) if k == 1
                      else ("Bash", {"command": f"npm i pkg{k}@1.0.{k}"}))
        f.add_tool("proj-" + HOSTILE if k == 0 else f"proj-{k % 2}", tool, args,
                   TS0 + timedelta(days=k), "bypassPermissions" if k % 2 else "default",
                   session=f"{k % 2:08x}-0000-4000-8000-000000000000", call_id=f"toolu_{k:03d}",
                   why=HOSTILE if k == 2 else "Because.", prompt="secret plan" if k == 3 else None)
    return f


def page(f=None, filters=(), with_prompts=False, raw=False):
    f = f or fleet(with_prompts=with_prompts)
    return af.render_network_html(af.network_json(f, raw), filters=list(filters),
                                  version="9.9.9", with_prompts=with_prompts)


class Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.refs, self._in = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "src"):
            if k in a:
                self.refs.append(a[k])
        if tag == "script":
            self._in = a.get("type", "")
            self.scripts.append([self._in, ""])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in = None

    def handle_data(self, data):
        if self._in is not None:
            self.scripts[-1][1] += data


def parse(p):
    s = Scripts()
    s.feed(p)
    return s


class TestPage(unittest.TestCase):
    def test_hostile_strings_only_escaped(self):
        f = fleet()
        self.assertEqual(len(af.network_json(f)["items"]), 6)     # the hostile URL is an item
        p = page(f)
        self.assertNotIn("<img", p)
        self.assertNotIn("<script>alert", p)
        self.assertNotIn("‮", p)
        runnable = [s for s in parse(p).scripts if s[0] != "application/json"]
        self.assertEqual(len(runnable), 1)
        self.assertEqual(runnable[0][1], af._NET_HTML_SCRIPT)

    def test_embedded_json_equals_network_json(self):
        f = fleet()
        p = page(f)
        [blob] = [s[1] for s in parse(p).scripts if s[0] == "application/json"]
        self.assertEqual(json.loads(blob), json.loads(json.dumps(af.network_json(f))))
        self.assertIn(hashlib.sha256(blob.encode()).hexdigest(), p)

    def test_prompts_only_with_the_flag(self):
        self.assertNotIn("secret plan", page())
        self.assertNotIn("<th data-k=\"10\">prompt</th>", page())
        p = page(with_prompts=True)
        self.assertIn("secret plan", p)
        self.assertIn(">prompt</th>", p)

    def test_csp_hash_matches_the_script(self):
        p = page()
        h = base64.b64encode(hashlib.sha256(af._NET_HTML_SCRIPT.encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{h}'", p)
        self.assertIn("default-src 'none'", p)

    def test_no_external_references(self):
        p = page()
        for ref in parse(p).refs:
            self.assertNotRegex(ref, r"^(https?:|//)")
        self.assertNotRegex(p, r"url\(\s*['\"]?(https?:|//)")

    def test_items_embedded_once(self):
        self.assertEqual(page().count("toolu_003"), 2)     # the items table and the JSON

    def test_deterministic(self):
        self.assertEqual(page(), page())

    def test_secret_redacted_unless_raw(self):
        f = af.Fleet()
        secret = "sk-ant-api03-" + "Q" * 40
        f.add_tool("p", "Bash", {"command": f"curl https://a.example/x?key={secret}"}, TS0, "auto")
        self.assertNotIn("Q" * 20, page(f))
        self.assertIn("Q" * 20, page(f, raw=True))

    def test_empty(self):
        p = page(af.Fleet())
        self.assertIn("No downloads were recorded", p)
        self.assertNotIn("<svg", p)

    def test_truncated_says_more(self):
        with mock.patch.object(af, "NETWORK_ITEMS_CAP", 3):
            p = page(fleet(8))
        self.assertIn("5 more not listed", p)
        self.assertIn("in listed items", p)

    def test_far_dates_render(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "npm i a"}, datetime(2001, 1, 1, tzinfo=timezone.utc), "auto")
        f.add_tool("p", "Bash", {"command": "npm i b"}, datetime(9999, 12, 31, tzinfo=timezone.utc), "auto")
        p = page(f)
        self.assertLessEqual(p.count("<title>"), 130)
        self.assertIn("9999-12-31", p)

    def test_filters_named(self):
        self.assertIn("host h1.example", page(filters=["host h1.example"]))


class TestWrite(unittest.TestCase):
    def test_never_overwrites_and_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "actualis-network.html").write_text("keep")
            (d / "actualis-network-2.html").write_text("keep2")
            p = af.write_network_html("<p>x</p>", d)
            self.assertEqual(p.name, "actualis-network-3.html")
            self.assertEqual((d / "actualis-network.html").read_text(), "keep")
            self.assertEqual(p.read_text(), "<p>x</p>")

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            p = af.write_network_html("x", Path(d))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_dangling_symlink_is_skipped_not_followed_or_looped(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "actualis-network.html").symlink_to(d / "missing-target")
            p = af.write_network_html("x", d)
            self.assertEqual(p.name, "actualis-network-2.html")
            self.assertFalse((d / "missing-target").exists())

    def test_endless_collisions_give_up(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(af.os, "open", side_effect=FileExistsError):
                with self.assertRaises(FileExistsError):
                    af.write_network_html("x", Path(d))

    def test_race_takes_next_name(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            real = af.network_html_path
            def racing(out_dir):
                p = real(out_dir)
                if p.name == "actualis-network.html":
                    p.write_text("other writer")
                return p
            with mock.patch.object(af, "network_html_path", side_effect=racing):
                p = af.write_network_html("mine", d)
            self.assertEqual((d / "actualis-network.html").read_text(), "other writer")
            self.assertEqual(p.read_text(), "mine")


SID = "cccc3333-0000-4000-8000-000000000003"


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "projects"
        (self.root / "-Users-x-proj").mkdir(parents=True)
        recs = [{"type": "assistant", "timestamp": "2026-10-07T14:22:00Z",
                 "permissionMode": "bypassPermissions", "sessionId": SID,
                 "message": {"id": "m1", "role": "assistant", "usage": {"input_tokens": 1, "output_tokens": 1},
                             "content": [{"type": "tool_use", "id": "toolu_01", "name": "Bash",
                                          "input": {"command": "npm i lodash@4.17.21"}}]}}]
        (self.root / "-Users-x-proj" / f"{SID}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n")
        self.home = base / "home"
        self.home.mkdir()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"), "NO_COLOR": "1"}
        old = os.getcwd()
        os.chdir(self.home)
        try:
            with mock.patch.dict(os.environ, env), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main([*argv, "--root", str(self.root), "--days", "3650"])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old)
        return code, out.getvalue(), err.getvalue()

    def test_writes_into_cwd_and_prints_path(self):
        code, out, err = self.run_main("--network", "--html")
        self.assertEqual(code, 0, err)
        p = Path(out.strip())
        self.assertEqual(p.resolve(), (self.home / "actualis-network.html").resolve())
        self.assertIn("lodash", p.read_text())

    def test_out_dir_and_embedded_equals_json(self):
        d = self.home / "reports"
        d.mkdir()
        code, out, _ = self.run_main("--network", "--html", "--out", str(d))
        self.assertEqual(code, 0)
        page_text = Path(out.strip()).read_text()
        blob = [s[1] for s in parse(page_text).scripts if s[0] == "application/json"][0]
        _, js, _ = self.run_main("--network", "--json")
        self.assertEqual(json.loads(blob), json.loads(js))

    def test_argument_errors(self):
        for argv, msg in ((["--html"], "--html requires --network"),
                          (["--network", "--html", "--json"], "--html writes a file")):
            code, _, err = self.run_main(*argv)
            self.assertEqual(code, 2)
            self.assertIn(msg, err)
        code, _, err = self.run_main("--network", "--html", "--with-prompts")
        self.assertEqual(code, 0, err)

    def test_out_rules(self):
        code, _, err = self.run_main("--network", "--out", str(self.home))
        self.assertEqual(code, 2)
        self.assertIn("--out applies only to --card or --html", err)
        code, _, err = self.run_main("--style", "terminal")
        self.assertEqual(code, 2)
        self.assertIn("--style applies only to --card", err)

    def test_missing_dir(self):
        code, _, err = self.run_main("--network", "--html", "--out", str(self.home / "nope"))
        self.assertEqual(code, 1)
        self.assertIn("is not a directory", err)
