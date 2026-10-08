"""Calculations that must not depend on where, when or how they run.

Each class pins one defect found by the 2026-10-08 calculation audit.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
sys.modules["actualis"] = af
spec.loader.exec_module(af)
af.SRC_TEXT = (ROOT / "actualis.py").read_text(encoding="utf-8")
af.SRC_PATH = ROOT / "actualis.py"


def _usage_line(mid, ts, branch):
    return json.dumps({
        "timestamp": ts, "type": "assistant", "uuid": ts, "gitBranch": branch,
        "message": {"id": mid, "model": "claude-sonnet-5",
                    "usage": {"input_tokens": 10, "output_tokens": 1000,
                              "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}},
    })


class TestFileOrderDoesNotChangeTotals(unittest.TestCase):
    """The same message in two transcripts is counted once; which copy is kept
    decides its day and branch. That choice must not depend on the order the
    filesystem lists files in, which differs between machines."""

    def _scan(self, tmp, reverse):
        real = Path.glob

        def ordered(self, pattern):
            return iter(sorted(real(self, pattern), reverse=reverse))

        with mock.patch.object(Path, "glob", ordered):
            f = af.Fleet()
            f.scan([Path(tmp)], None, None, progress=False)
        return dict(f.cost_by_day), dict(f.cost_by_branch)

    def test_permuted_listing_gives_identical_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "-Users-x-proj"
            d.mkdir()
            (d / "a.jsonl").write_text(_usage_line("dup", "2026-08-01T10:00:00Z", "trunk") + "\n")
            (d / "b.jsonl").write_text(_usage_line("dup", "2026-08-05T10:00:00Z", "feat/x") + "\n")
            self.assertEqual(self._scan(tmp, reverse=False), self._scan(tmp, reverse=True))


class TestAF012CountsClaudeMessagesOnly(unittest.TestCase):
    """Codex and Copilot units are sessions, which never repeat. Counting them
    toward AF012's 500-message threshold raised a false critical."""

    def test_codex_only_fleet_does_not_fire(self):
        f = af.Fleet()
        ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for _ in range(600):
            f.add_codex_session("p", "gpt-5.2-codex",
                                {"input_tokens": 10, "cached_input_tokens": 0,
                                 "output_tokens": 5, "total_tokens": 15}, ts)
        self.assertNotIn("AF012", [x.id for x in af.coach(f)])
        self.assertEqual(af.failing_findings(f, "critical"), [])


class TestRefusalWeeksUseTheIsoYear(unittest.TestCase):
    def test_week_one_belongs_to_its_iso_year(self):
        f = af.Fleet()
        for day in (datetime(2025, 12, 29, tzinfo=timezone.utc),
                    datetime(2027, 1, 1, tzinfo=timezone.utc)):
            f._record_refusal("user-rejected", "p", day, None)
        self.assertEqual(sorted(f.refusal_week), ["2026-W01", "2026-W53"])


class TestMcpWindowMatchesTheCli(unittest.TestCase):
    def test_days_snaps_to_the_same_cutoff(self):
        seen = []
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(af, "transcript_roots", return_value=[Path(tmp)]), \
                mock.patch.object(af, "codex_roots", return_value=[]), \
                mock.patch.object(af, "copilot_roots", return_value=[]), \
                mock.patch.object(af.Fleet, "scan", lambda self, roots, since, *a, **k: seen.append(since)):
            af._MCPCache().fleet(7)
        self.assertEqual(seen, [af.window_start(7)])


class TestAggregatorPricesAreKnown(unittest.TestCase):
    """A model priced from an aggregator or the vendor's docs has a sourced
    price. Only family inference and the default ceiling are unpriced."""

    def test_rates_for_known(self):
        self.assertTrue(af.rates_for("gpt-5.2-codex", None)[3])
        self.assertTrue(af.rates_for("claude-opus-5", None)[3])
        self.assertFalse(af.rates_for("claude-does-not-exist", None)[3])

    def test_codex_aggregator_session_is_not_unpriced(self):
        f = af.Fleet()
        f.add_codex_session("p", "gpt-5.2-codex",
                            {"input_tokens": 1000, "cached_input_tokens": 0,
                             "output_tokens": 500, "total_tokens": 1500},
                            datetime(2026, 8, 1, tzinfo=timezone.utc))
        self.assertEqual((dict(f.unknown_models), f.cost_unknown), ({}, 0.0))
        self.assertEqual(dict(f.aggregator_models), {"gpt-5.2-codex": 1})


if __name__ == "__main__":
    unittest.main()
