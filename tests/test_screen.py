"""Seen on screen: credentials and personal data in browser and computer-use
tool results, and screenshots listed but never read.

Every fixture is synthetic and built here: invented addresses on reserved or
invented domains, a fictional phone number, a Luhn-valid card number that is
no one's, and credential-shaped strings made up for the test.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
sys.modules["actualis"] = af
spec.loader.exec_module(af)
af.SRC_TEXT = (ROOT / "actualis.py").read_text(encoding="utf-8")
af.SRC_PATH = ROOT / "actualis.py"

SID = "11111111-2222-4333-8444-555555555555"
PROJECT_DIR = "-Users-x-canaryshop"

# Synthetic values. None may ever reach a report, --json, --share or a card.
EMAIL = "jordan.canary@mailbox-demo.net"  # pii-ok: invented address the detector under test must find
SPILL_EMAIL = "buyer.canary@shop-demo.net"  # pii-ok: invented address the detector under test must find
PHONE = "297-736-4021"  # pii-ok: area code 297 is reserved (N9X), never assigned
CARD = "4539 1488 0343 6467"                       # Luhn-valid, Visa range, invented
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GITHUB = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
VALUES = (EMAIL, SPILL_EMAIL, PHONE, CARD, CARD.replace(" ", ""), STRIPE, GITHUB,
          "2977364021", "jordan.canary", "buyer.canary")

PAGE_TEXT = (f"Account settings\nEmail: {EMAIL}\nSupport (617) 555-0142\nMobile {PHONE}\n"
             f"Card {CARD} exp 12/29\nKey {STRIPE}\n")
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\0" * 3000).decode()
SHOT = "mcp-plugin_playwright_playwright-blob-1700000000000-abc123.png"


def call(tid, name, ts, inp=None):
    return {"type": "assistant", "sessionId": SID, "timestamp": ts, "uuid": "a" + tid,
            "message": {"id": "m" + tid, "role": "assistant", "model": "claude-sonnet-4-5",
                        "usage": {"input_tokens": 10, "output_tokens": 5},
                        "content": [{"type": "tool_use", "id": tid, "name": name,
                                     "input": inp or {}}]}}


def result(tid, content, ts):
    return {"type": "user", "sessionId": SID, "timestamp": ts, "uuid": "r" + tid,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid, "content": content}]},
            "toolUseResult": content}


def spill_text(name):
    return (f"<persisted-output>\nOutput too large (120.0KB). Full output saved to: "
            f"/Users/x/.claude/projects/{PROJECT_DIR}/{SID}/tool-results/{name}\n\n"
            f"Preview (first 2KB):\n- textbox \"Email\": {SPILL_EMAIL}\n</persisted-output>")


def fixture_records():
    """One Claude in Chrome page read, one Playwright snapshot spilled to
    tool-results, one inline screenshot, and one screenshot saved to
    tool-results."""
    return [
        call("t1", "mcp__claude-in-chrome__get_page_text", "2026-11-01T10:00:00Z", {"tabId": 1}),
        result("t1", [{"type": "text", "text": PAGE_TEXT}], "2026-11-01T10:00:01Z"),
        call("t2", "mcp__plugin_playwright_playwright__browser_snapshot", "2026-11-01T10:01:00Z"),
        result("t2", [{"type": "text", "text": spill_text("toolu_pw1.txt")}], "2026-11-01T10:01:01Z"),
        call("t3", "mcp__claude-in-chrome__computer", "2026-11-01T10:02:00Z", {"action": "screenshot"}),
        result("t3", [{"type": "text", "text": "Successfully captured screenshot"},
                      {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                                   "data": PNG}}], "2026-11-01T10:02:01Z"),
        call("t4", "mcp__plugin_playwright_playwright__browser_take_screenshot", "2026-11-01T10:03:00Z"),
        result("t4", [{"type": "text", "text": f"[Image: source: /Users/x/.claude/projects/{PROJECT_DIR}/"
                                               f"{SID}/tool-results/{SHOT}]"}], "2026-11-01T10:03:01Z"),
    ]


def write_fleet(root, records, spills=None, name=SID):
    d = Path(root) / PROJECT_DIR
    spill = d / name / "tool-results"
    spill.mkdir(parents=True, exist_ok=True)
    for fname, body in (spills if spills is not None else default_spills()).items():
        (spill / fname).write_bytes(body if isinstance(body, bytes) else body.encode())
    (d / f"{name}.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return spill


def default_spills():
    return {"toolu_pw1.txt": f"- textbox \"Email\": {SPILL_EMAIL}\n- text: Token {GITHUB}\n",
            SHOT: b"\x89PNG" + b"\0" * 500}


def scan(root, since=None):
    f = af.Fleet()
    f.suppressions = {}
    f.scan([Path(root)], since, None, progress=False)
    return f


def text_of(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()


class ScreenCase(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name) / "projects"
        self.spill = write_fleet(self.root, fixture_records())
        self.fleet = scan(self.root)
        self.data = af.screen_json(self.fleet)

    def tearDown(self):
        self._td.cleanup()


class TestFixtures(ScreenCase):

    def test_page_text_snapshot_and_screenshots_are_read(self):
        d = self.data
        self.assertEqual(d["results_scanned"], 4)
        self.assertEqual(d["spilled_files_read"], 1)
        self.assertEqual(d["credentials"], 2)
        self.assertEqual(d["personal_data"], 4)          # two addresses, one phone, one card
        self.assertEqual(d["by_detector"]["email"], 2)
        self.assertEqual(d["by_detector"]["phone"], 1)  # 555-0142 is fiction, not counted
        self.assertEqual(d["by_detector"]["card"], 1)
        self.assertEqual(d["sessions"], 1)

    def test_rows_are_per_session_tool_and_detector(self):
        rows = {(r["family"], r["tool"].rsplit("__", 1)[-1], r["detector"]): r
                for r in self.data["findings"]}
        self.assertIn(("claude-in-chrome", "get_page_text", "email"), rows)
        self.assertIn(("playwright", "browser_snapshot", "email"), rows)
        self.assertIn(("playwright", "browser_snapshot", "GitHub PAT"), rows)
        row = rows[("claude-in-chrome", "get_page_text", "card")]
        self.assertEqual((row["session"], row["kind"], row["priority"], row["results"]),
                         (SID, "personal", None, 1))
        self.assertEqual(row["first_seen"], "2026-11-01")
        self.assertEqual(self.data["findings"][0]["kind"], "credential")

    def test_a_spilled_preview_and_its_file_count_once(self):
        """The inline preview repeats the start of the file: one result, one count."""
        row = next(r for r in self.data["findings"]
                   if r["tool"].endswith("browser_snapshot") and r["detector"] == "email")
        self.assertEqual(row["results"], 1)

    def test_screenshots_are_listed_with_size_and_saved_path(self):
        shots = {r["tool"].rsplit("__", 1)[-1]: r for r in self.data["screenshots"]}
        self.assertEqual(shots["computer"]["count"], 1)
        self.assertEqual(shots["computer"]["bytes"], len(base64.b64decode(PNG)))
        self.assertEqual(shots["computer"]["saved"], [])
        saved = shots["browser_take_screenshot"]
        self.assertEqual((saved["count"], saved["bytes"]), (1, 504))
        self.assertEqual(saved["saved"], [str(self.spill / SHOT)])
        self.assertEqual(self.data["screenshots_total"], 2)
        self.assertIn("not inspected", self.data["screenshots_note"])

    def test_screenshots_are_never_decoded(self):
        with mock.patch.object(af.base64, "b64decode", side_effect=AssertionError("decoded")), \
                mock.patch.object(af.base64, "standard_b64decode", side_effect=AssertionError("decoded")):
            f = scan(self.root)
        self.assertEqual(af.screen_json(f)["screenshots_total"], 2)

    def test_a_saved_screenshot_is_never_opened(self):
        real = af._open_regular
        opened = []

        def spy(path, binary=False):
            opened.append(Path(path).name)
            return real(path, binary)
        with mock.patch.object(af, "_open_regular", spy):
            scan(self.root)
        self.assertNotIn(SHOT, opened)
        self.assertIn("toolu_pw1.txt", opened)

    def test_credentials_join_the_rotation_list_marked_screen(self):
        payload = af.to_json(self.fleet)
        kinds = {tuple(s["types"]): s for s in payload["secrets"]}
        self.assertEqual(kinds[("Stripe key",)]["source"], "screen")
        self.assertEqual(kinds[("Stripe key",)]["priority"], "critical")
        self.assertEqual(kinds[("GitHub PAT",)]["source"], "screen")
        self.assertIn("AF004", [c["id"] for c in payload["coach"]])

    def test_a_credential_in_a_command_and_on_screen_is_both(self):
        self.fleet.add_tool("canaryshop", "Bash", {"command": f"export K={STRIPE}"},
                            datetime(2026, 11, 2, tzinfo=timezone.utc))
        payload = af.to_json(self.fleet)
        row = next(s for s in payload["secrets"] if s["types"] == ["Stripe key"])
        self.assertEqual((row["source"], row["uses"]), ("both", 2))
        out = text_of(lambda: af.render(self.fleet, af.C(False), False, 12))
        self.assertIn("cmd+screen", out)

    def test_command_only_credentials_say_command(self):
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("p", "Bash", {"command": f"export K={STRIPE}"}, None)
        self.assertEqual(af.to_json(f)["secrets"][0]["source"], "command")
        self.assertEqual(af.to_json(f)["screen"]["results_scanned"], 0)

    def test_on_screen_only_value_shaped_credentials_count(self):
        """Page text is `Label: value` everywhere. A name beside a value is a shell
        heuristic; on a real corpus 99 of 106 such hits were one page's labels."""
        f = af.Fleet()
        f.suppressions = {}
        page = ("API_TOKEN: abcdefghij0123456789\nSESSION_EXPIRES_AT: 20261101T100000Z\n"
                "KEY: settings_panel_heading_main\nDB postgres://app:Zq8vLm2pXr4t@db.shop-demo.net/x\n")
        f.add_tool_result("p", "mcp__claude-in-chrome__get_page_text", page, None, call_id="c1")
        kinds = {r["detector"] for r in af.screen_json(f)["findings"]}
        self.assertEqual(kinds, {"postgres password (remote)"})
        self.assertEqual([sorted(e["kinds"]) for e in f.secrets.values()],
                         [["postgres password (remote)"]])

    def test_the_coverage_check_lists_screenshots_and_is_not_a_gap(self):
        cov = af.coverage(self.fleet)
        row = next(c for c in cov["checks"] if c["check"] == "screen")
        self.assertEqual((row["examined"], row["why_not"]), (4, {"screenshot": 2}))
        self.assertEqual(cov["gaps"], [])
        self.assertNotIn("screen", [c["check"] for c in af.coverage(af.Fleet())["checks"]])


class TestNoValueLeaks(ScreenCase):

    def outputs(self):
        # A shell command with a mode, so every card mode has something to draw.
        self.fleet.add_tool("canaryshop", "Bash", {"command": "make build"},
                            datetime(2026, 11, 1, 11, tzinfo=timezone.utc), "auto")
        outs = {"report": text_of(lambda: af.render(self.fleet, af.C(False), False, 12)),
                "json": json.dumps(af.to_json(self.fleet), ensure_ascii=False),
                "json-raw": json.dumps(af.to_json(self.fleet, raw=True), ensure_ascii=False),
                "share": text_of(lambda: af.render_share(self.fleet, af.C(False)))}
        for mode in ("cost", "supervision", "volume"):
            outs["card-" + mode] = json.dumps(af.card_model(self.fleet, mode), ensure_ascii=False)
        return outs

    def test_no_value_is_ever_printed(self):
        for name, text in self.outputs().items():
            for value in VALUES:
                with self.subTest(output=name, value=value):
                    self.assertNotIn(value, text)

    def test_share_and_card_leak_nothing_identifying(self):
        ids = [r["id"] for r in self.data["findings"]]
        self.assertTrue(ids)
        for name, text in self.outputs().items():
            if not name.startswith(("share", "card")):
                continue
            for needle in ids + [SID, SID[:8], "canaryshop", "tool-results", SHOT,
                                 "claude-in-chrome", "playwright", "screen"]:
                with self.subTest(output=name, needle=needle):
                    self.assertNotIn(needle, text)

    def test_the_report_says_screenshots_were_not_inspected(self):
        out = self.outputs()["report"]
        self.assertIn("SEEN ON SCREEN", out)
        self.assertIn("content not inspected", out)
        self.assertIn(af.SCREEN_NOT_INSPECTED.split(":")[0], out)
        self.assertIn(f"saved {self.spill / SHOT}", out)

    def test_every_emitted_path_is_declared(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from test_actualis import TestJSONSchemaFreeze as T
        payload = af.to_json(self.fleet)
        paths = [p for p, _t in T._walk(payload) if p.startswith(("screen", "secrets"))]
        self.assertIn("screen.findings[].detector", paths)
        self.assertIn("screen.screenshots[].saved[]", paths)
        for path, actual in T._walk(payload):
            want = T._declared(path, af.JSON_SCHEMA)
            self.assertIsNotNone(want, path)
            if not (actual == "int" and "float" in want):
                self.assertIn(actual, want.split("|"), path)
        self.assertEqual(payload["schema_version"], 1)


class TestReadSurface(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.root = self.base / "projects"

    def tearDown(self):
        self._td.cleanup()

    def test_a_spill_outside_the_session_directory_is_not_followed(self):
        outside = self.base / "outside.txt"
        outside.write_text(f"secret page {EMAIL}\n")
        spill = write_fleet(self.root, fixture_records()[:4], spills={})
        try:
            os.symlink(outside, spill / "toolu_pw1.txt")
        except (OSError, NotImplementedError):
            self.skipTest("no symlinks here")
        d = af.screen_json(scan(self.root))
        self.assertEqual((d["spilled_files_read"], d["spilled_files_unreadable"]), (0, 1))
        self.assertNotIn("buyer", json.dumps(d))
        self.assertEqual(d["by_detector"].get("email"), 2)   # the page and the inline preview

    def test_a_path_in_the_text_is_never_used_as_a_path(self):
        """Only the file name after tool-results/ is taken, and only from the session's own directory."""
        elsewhere = self.base / "tool-results"
        elsewhere.mkdir()
        (elsewhere / "toolu_pw1.txt").write_text(f"Token {GITHUB}\n")
        recs = [call("t1", "mcp__claude-in-chrome__get_page_text", "2026-11-01T10:00:00Z"),
                result("t1", f"saved to {elsewhere}/toolu_pw1.txt and tool-results/../../etc",
                       "2026-11-01T10:00:01Z")]
        write_fleet(self.root, recs, spills={})
        d = af.screen_json(scan(self.root))
        self.assertEqual(d["spilled_files_read"], 0)
        self.assertEqual(d["spilled_files_missing"], 1)
        self.assertEqual(d["credentials"], 0)

    def test_other_tools_results_are_not_read(self):
        recs = [call("b1", "Bash", "2026-11-01T10:00:00Z", {"command": "cat page.html"}),
                result("b1", PAGE_TEXT, "2026-11-01T10:00:01Z"),
                call("r1", "Read", "2026-11-01T10:01:00Z", {"file_path": "/x"}),
                result("r1", PAGE_TEXT, "2026-11-01T10:01:01Z")]
        write_fleet(self.root, recs, spills={})
        f = scan(self.root)
        self.assertEqual(af.screen_json(f)["results_scanned"], 0)
        self.assertEqual(f.secrets, {})

    def test_results_without_browser_calls_are_not_decoded(self):
        """The prefilter still skips tool_result lines in a file with no browser call."""
        recs = [call("b1", "Bash", "2026-11-01T10:00:00Z", {"command": "ls"}),
                result("b1", PAGE_TEXT, "2026-11-01T10:00:01Z")]
        write_fleet(self.root, recs, spills={})
        self.assertEqual(scan(self.root).lines_read, 1)

    def test_a_resumed_sessions_copy_is_counted_once(self):
        write_fleet(self.root, fixture_records())
        write_fleet(self.root, fixture_records(), name="99999999-2222-4333-8444-555555555555")
        d = af.screen_json(scan(self.root))
        self.assertEqual(d["results_scanned"], 4)
        self.assertEqual(d["screenshots_total"], 2)
        self.assertTrue(all(r["results"] == 1 for r in d["findings"]))

    def test_results_before_the_window_are_left_out(self):
        write_fleet(self.root, fixture_records())
        f = scan(self.root, since=datetime(2026, 11, 2, tzinfo=timezone.utc))
        d = af.screen_json(f)
        self.assertEqual((d["results_scanned"], d["screenshots_total"]), (0, 0))
        self.assertEqual(f.secrets, {})

    def test_network_only_reads_no_results(self):
        write_fleet(self.root, fixture_records())
        f = af.Fleet(network_only=True)
        f.suppressions = {}
        f.scan([self.root], None, None, progress=False)
        self.assertEqual(af.screen_json(f)["results_scanned"], 0)

    def test_hostile_content_shapes_do_not_raise(self):
        recs = [call("t1", "mcp__claude-in-chrome__read_page", "2026-11-01T10:00:00Z")]
        for i, content in enumerate((None, 7, {"x": 1}, [None, 3, {"type": "image"},
                                     {"type": "image", "source": {"data": 5}},
                                     {"type": "text", "text": None}])):
            recs[0]["message"]["content"][0]["id"] = "t1"
            recs.append(result("t1", content, "2026-11-01T10:00:01Z"))
        write_fleet(self.root, recs, spills={})
        af.screen_json(scan(self.root))


class TestScreenOnlyRun(unittest.TestCase):
    """A run whose only records are browser and computer-use activity (no
    usage record) still reports what the agent saw, rather than exiting as if
    nothing matched."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name) / "projects"
        recs = fixture_records()
        for r in recs:
            r["message"].pop("usage", None)
            r["message"].pop("model", None)
        write_fleet(self.root, recs)

    def tearDown(self):
        self._td.cleanup()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = af.main([*argv, "--root", str(self.root)])
        return code, out.getvalue(), err.getvalue()

    def test_the_report_prints_seen_on_screen(self):
        code, out, err = self.run_main()
        self.assertEqual(code, af.EXIT_OK, err)
        self.assertIn("SEEN ON SCREEN", out)
        self.assertIn("content not inspected", out)
        self.assertNotIn("none matched", err)
        for value in VALUES:
            self.assertNotIn(value, out + err)

    def test_json_carries_screen(self):
        code, out, err = self.run_main("--json")
        self.assertEqual(code, af.EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["messages"], 0)
        self.assertEqual(payload["screen"]["results_scanned"], 4)
        self.assertEqual(payload["screen"]["screenshots_total"], 2)
        self.assertEqual(payload["screen"]["credentials"], 2)

    def test_an_empty_run_still_hits_the_dead_end(self):
        empty = Path(self._td.name) / "empty"
        (empty / PROJECT_DIR).mkdir(parents=True)
        recs = [call("b1", "Read", "2026-11-01T10:00:00Z", {"file_path": "/x"})]
        recs[0]["message"].pop("usage")
        (empty / PROJECT_DIR / "s.jsonl").write_text(json.dumps(recs[0]) + "\n")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = af.main(["--root", str(empty)])
        self.assertEqual(code, af.EXIT_CANNOT_RUN)


class TestFamilies(unittest.TestCase):

    def test_names(self):
        cases = {
            "mcp__claude-in-chrome__get_page_text": "claude-in-chrome",
            "mcp__claude-in-chrome__computer": "claude-in-chrome",
            "mcp__plugin_playwright_playwright__browser_snapshot": "playwright",
            "mcp__playwright__browser_snapshot": "playwright",
            "mcp__plugin_chrome-devtools-mcp_chrome-devtools__take_snapshot": "chrome-devtools",
            "mcp__chrome-devtools__list_console_messages": "chrome-devtools",
            "computer": "computer-use",
            "mcp__computer-use__screenshot": "computer-use",
            "Bash": None, "Read": None, "WebFetch": None, "mcp__github__get_issue": None,
            None: None, 5: None, "x" * 500: None,
        }
        for name, want in cases.items():
            with self.subTest(name=name):
                self.assertEqual(af.screen_family(name), want)


class TestPersonalData(unittest.TestCase):

    def detectors(self, text):
        return sorted(d for d, _ in af.personal_data(text))

    def test_email(self):
        self.assertEqual(self.detectors(f"write to {EMAIL}."), ["email"])
        for text in ("dev@example.com", "a@b.example.org", "x@host.test", "x@y.invalid",
                     "logo@2x.png", "icon@3x.webp", "noreply@mailbox-demo.net",  # pii-ok: invented sender, a case the detector skips
                     "git@github.com:org/repo", "postgres://app:Zq8vLm2pXr4t@db.shop-demo.net/x",
                     "https://jordan@shop-demo.net/"):
            with self.subTest(text=text):
                self.assertEqual(self.detectors(text), [])

    def test_a_mailto_link_is_an_address(self):
        self.assertEqual(self.detectors(f"<a href=\"mailto:{EMAIL}\">"), ["email"])

    def test_email_id_ignores_case(self):
        self.assertEqual(af.personal_data(EMAIL), af.personal_data(EMAIL.upper()))

    def test_phone(self):
        for text in ("call 297-736-4021", "(297) 736-4021", "297.736.4021", "+1 297 736 4021",  # pii-ok: reserved 297; Ofcom drama ranges
                     "+44 20 7946 0958", "+447700900123"):  # pii-ok: Ofcom drama ranges
            with self.subTest(text=text):
                self.assertEqual(self.detectors(text), ["phone"])
        for text in ("(617) 555-0142", "617-555-0199", "id 2127364021", "2026-11-12",
                     "v1.297.736.4021", "+12", "build 297-736-40215"):
            with self.subTest(text=text):
                self.assertEqual(self.detectors(text), [])

    def test_the_same_number_written_two_ways_is_one(self):
        self.assertEqual(len(af.personal_data("297-736-4021 or (297) 736-4021")), 1)  # pii-ok: reserved 297

    def test_card_needs_luhn_a_network_range_and_is_not_a_test_number(self):
        self.assertEqual(self.detectors(f"card {CARD}"), ["card"])
        self.assertEqual(self.detectors(CARD.replace(" ", "")), ["card"])
        for text in ("4539 1488 0343 6468",                        # Luhn fails
                     "4242 4242 4242 4242", "4111111111111111",     # test numbers, by shape
                     "378282246310005", "6011111111111117",         # published test numbers
                     "1234567812345670",                            # Luhn-valid, no network
                     "order 7992739871300000"):                     # Luhn-valid id, no network
            with self.subTest(text=text):
                self.assertEqual(self.detectors(text), [])

    def test_luhn(self):
        self.assertTrue(af._luhn("79927398713"))
        self.assertFalse(af._luhn("79927398710"))

    def test_values_are_fingerprints_only(self):
        for det, fp in af.personal_data(PAGE_TEXT):
            with self.subTest(det=det):
                self.assertRegex(fp, r"^[0-9a-f]{8}$")
                for value in VALUES:
                    self.assertNotIn(value, fp)

    def test_long_hostile_text_is_linear(self):
        sys.path.insert(0, str(ROOT / "tests"))
        import _timing
        for text in ("9" * 200_000, "+1" + " 1" * 100_000, "a" * 200_000 + "@",
                     ("a." * 100_000) + "@x", "4 " * 100_000):
            with self.subTest(text=text[:12]):
                t = _timing.clock()
                af.personal_data(text)
                self.assertLess(_timing.clock() - t, _timing.budget(0.5))


if __name__ == "__main__":
    unittest.main()
