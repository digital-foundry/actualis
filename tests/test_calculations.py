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


class TestCurrentGenerationPricing(unittest.TestCase):
    """C1: Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1 and Mythos 5.1, with a
    cache-read multiplier that belongs to the model."""

    NEW = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5",
           "claude-fable-5-1", "claude-mythos-5-1")
    MILLION = {"input_tokens": 1_000_000, "output_tokens": 1_000_000,
               "cache_read_input_tokens": 1_000_000,
               "cache_creation": {"ephemeral_1h_input_tokens": 1_000_000,
                                  "ephemeral_5m_input_tokens": 0}}

    def _cost(self, model, usage):
        f = af.Fleet()
        f.add_usage("p", model, usage, None)
        return f.total_cost, f

    def test_every_new_id_is_a_vendor_rate(self):
        for m in self.NEW:
            self.assertEqual(af.rate_for(m).tier, af.VENDOR, m)

    def test_golden_cost_per_model_with_cache_reads(self):
        # input + output + 1h write (2.00x) + cache read at the model's multiplier
        golden = {"claude-opus-5-5": 4 + 20 + 8 + 0.20,       # 32.20
                  "claude-sonnet-5-5": 2 + 10 + 4 + 0.10,     # 16.10
                  "claude-fable-5-1": 10 + 50 + 20 + 0.25,    # 80.25
                  "claude-mythos-5-1": 10 + 50 + 20 + 0.25}   # 80.25
        for m, want in golden.items():
            cost, _ = self._cost(m, self.MILLION)
            self.assertAlmostEqual(cost, want, places=6, msg=m)

    def test_older_models_keep_the_default_multiplier(self):
        cost, _ = self._cost("claude-opus-5", self.MILLION)
        self.assertAlmostEqual(cost, 5 + 25 + 10 + 0.50, places=6)
        self.assertAlmostEqual(af.rate_for("claude-fable-5").cache_read, 0.10)

    def test_multipliers(self):
        self.assertEqual(af.rate_for("claude-opus-5-5").cache_read, 0.05)
        self.assertEqual(af.rate_for("claude-sonnet-5-5").cache_read, 0.05)
        self.assertEqual(af.rate_for("claude-fable-5-1").cache_read, 0.025)
        self.assertEqual(af.rate_for("claude-mythos-5-1").cache_read, 0.025)

    def test_haiku_55_tier_boundary(self):
        base = af.Fleet()
        base.add_usage("p", "claude-haiku-5-5",
                       {"input_tokens": 99_999, "output_tokens": 1000}, None)
        self.assertAlmostEqual(base.total_cost,
                               99_999 / 1e6 * 0.10 + 1000 / 1e6 * 0.50, places=9)
        over = af.Fleet()
        over.add_usage("p", "claude-haiku-5-5",
                       {"input_tokens": 100_001, "output_tokens": 1000}, None)
        self.assertAlmostEqual(over.total_cost,
                               100_001 / 1e6 * 0.50 + 1000 / 1e6 * 2.50, places=9)

    def test_haiku_55_prompt_counts_cache_tokens(self):
        # 40,000 fresh + 50,000 read + 10,001 written = 100,001 -> long tier.
        usage = {"input_tokens": 40_000, "output_tokens": 0,
                 "cache_read_input_tokens": 50_000,
                 "cache_creation": {"ephemeral_1h_input_tokens": 10_001,
                                    "ephemeral_5m_input_tokens": 0}}
        cost, _ = self._cost("claude-haiku-5-5", usage)
        want = (40_000 * 0.50 + 50_000 * 0.50 * 0.10 + 10_001 * 0.50 * 2.0) / 1e6
        self.assertAlmostEqual(cost, want, places=9)

    def test_other_cost_paths_use_the_base_haiku_rate(self):
        # Copilot never sees the long tier; it must not raise or reprice.
        got = af.copilot_session_cost({"inputTokens": 200_000, "outputTokens": 0},
                                      "claude-haiku-5-5")
        self.assertAlmostEqual(got, 200_000 / 1e6 * 0.10, places=9)

    def test_sonnet_55_cache_savings(self):
        # 1M reads: $2.00 uncached versus $0.10 actual.
        _, f = self._cost("claude-sonnet-5-5", {"cache_read_input_tokens": 1_000_000})
        self.assertAlmostEqual(f.cache_uncached["p"] - f.cache_actual["p"], 1.90, places=6)

    def test_copilot_uses_the_model_multiplier(self):
        got = af.copilot_session_cost(
            {"inputTokens": 1_000_000, "cacheReadTokens": 1_000_000}, "claude-fable-5-1")
        self.assertAlmostEqual(got, 0.25, places=6)

    def test_subagent_floor_uses_the_model_multiplier(self):
        f = af.Fleet()
        f.add_subagent({"resolvedModel": "claude-mythos-5-1",
                        "usage": {"cache_read_input_tokens": 1_000_000}}, None)
        self.assertAlmostEqual(f.sub_cost_floor, 0.25, places=6)

    def test_future_sibling_infers_the_newest_generation(self):
        r = af.rate_for("claude-sonnet-5-7")
        self.assertEqual(r.tier, af.FAMILY)
        self.assertEqual((r.input, r.output), (2.0, 10.0))
        self.assertEqual(r.cache_read, 0.05)
        self.assertIn("claude-sonnet-5-5", r.note)

    def test_dated_id_is_that_model(self):
        r = af.rate_for("claude-haiku-4-5-20251001")
        self.assertEqual((r.input, r.output), (1.0, 5.0))

    def test_retired_models_still_never_set_the_family_rate(self):
        r = af.rate_for("claude-opus-5-9")
        self.assertEqual((r.input, r.output), (4.0, 20.0))

    def test_pricing_verified_date(self):
        self.assertEqual(af.PRICING_VERIFIED, "2026-10-08")
