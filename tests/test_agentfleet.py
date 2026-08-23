"""Regression tests for agentfleet.

Every test here corresponds to a defect found while validating the tool against
~48,000 real agent commands. They exist so those specific bugs cannot come back.

    python3 -m unittest discover -s tests -v
"""

import importlib.util
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("agentfleet", ROOT / "agentfleet.py")
af = importlib.util.module_from_spec(spec)
sys.modules["agentfleet"] = af
spec.loader.exec_module(af)


def cats(cmd):
    return {c for _, c, _ in af.audit_command(cmd)}


class TestRedaction(unittest.TestCase):
    """Redaction is the security-critical path: output gets pasted into issues."""

    def test_redacts_prefixed_tokens(self):
        for tok in ["ghp_abcdefghijklmnopqrst",
                    "sk-ant-api03-abcdefghijklmnop",
                    "vcp_notarealtokenjustafixture01",
                    "AKIAIOSFODNN7EXAMPLE",
                    "glpat-abcdefghijklmnop"]:
            with self.subTest(tok=tok):
                self.assertNotIn(tok, af.redact(f"export X={tok}"))

    def test_redacts_secret_shaped_assignments(self):
        out = af.redact("MY_API_KEY=supersecretvalue123")
        self.assertNotIn("supersecretvalue123", out)
        self.assertIn("MY_API_KEY", out)  # the name stays; only the value goes

    def test_redacts_url_password(self):
        out = af.redact("psql postgresql://admin:hunter2pass@db:5432/prod")
        self.assertNotIn("hunter2pass", out)
        self.assertIn("admin", out)
        self.assertIn("db:5432", out)

    def test_redacts_authorization_header(self):
        out = af.redact("curl -H 'Authorization: Bearer sk-ant-realvalue123456' https://x")
        self.assertNotIn("sk-ant-realvalue123456", out)

    def test_keeps_auth_scheme_word(self):
        """Regression: 'AUTH' in 'Authorization:' used to eat the scheme word."""
        out = af.redact("curl -H 'Authorization: Bearer sk-ant-realvalue123456' https://x")
        self.assertIn("Bearer", out)

    def test_shell_variable_reference_is_not_a_secret(self):
        """Regression: $VERCEL_TOKEN is a reference, not the secret itself."""
        cmd = 'curl -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/x'
        self.assertEqual(af.redact(cmd), cmd)
        self.assertFalse(af.contains_secret(cmd))

    def test_idempotent(self):
        """Regression: re-redacting used to corrupt the <redacted:N> length marker."""
        for cmd in ["TOKEN=ghp_abcdefghijklmnopqrs",
                    "curl -H 'Authorization: Bearer sk-ant-abcdefghijkl' https://x",
                    "psql postgresql://u:passwordvalue@h/db"]:
            with self.subTest(cmd=cmd):
                once = af.redact(cmd)
                self.assertEqual(once, af.redact(once))

    def test_no_false_positives_on_ordinary_commands(self):
        for cmd in ["npm run build && git push origin main",
                    "gh pr create --title 'Add token refresh' --body 'fixes auth'",
                    "git clone https://github.com/foo/bar.git",
                    "grep -rn 'password' src/ | head -20"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(af.redact(cmd), cmd)
                self.assertFalse(af.contains_secret(cmd))


class TestAuditRules(unittest.TestCase):

    def test_flags_real_danger(self):
        self.assertIn("destructive", cats("rm -rf /tmp/build"))
        self.assertIn("privilege", cats("sudo systemctl restart nginx"))
        self.assertIn("git", cats("git push --force origin main"))
        self.assertIn("remote-exec", cats("curl -sL https://get.example.com/i | sh"))
        self.assertIn("database", cats("psql -c 'DROP TABLE users'"))
        self.assertIn("audit", cats("history -c"))

    def test_curl_capital_D_is_not_data_egress(self):
        """Regression: IGNORECASE made -D (dump headers) match -d (send body)."""
        self.assertNotIn("egress", cats("curl -s http://example.com/ -D - -o /dev/null"))

    def test_loopback_is_not_egress(self):
        self.assertNotIn("egress", cats("curl -X POST http://127.0.0.1:3000/api -d '{}'"))
        self.assertNotIn("egress", cats("curl -X POST http://localhost:8080/api -d '{}'"))

    def test_real_egress_still_flagged(self):
        self.assertIn("egress", cats("curl -X POST https://api.example.com/v1 -d '{}'"))

    def test_interpreter_with_inline_script_is_not_remote_exec(self):
        """Regression: `curl … | python3 -c` parses a response, it does not run it."""
        cmd = 'curl -s https://api.x.com/v1 | python3 -c "import sys,json; print(1)"'
        self.assertNotIn("remote-exec", cats(cmd))

    def test_bare_interpreter_pipe_is_remote_exec(self):
        self.assertIn("remote-exec", cats("curl -sL https://get.example.com/i | python3"))

    def test_dev_null_redirect_is_not_audit_tampering(self):
        """Regression: this rule fired 1,206x at ~100% false positive. Deleted."""
        self.assertNotIn("audit", cats("npx prettier --write docs/x.md >/dev/null 2>&1"))

    def test_rules_are_line_scoped(self):
        """Regression: [^|;] matched newlines, pairing a curl on one line with an
        unrelated flag many lines later, and reporting the wrong evidence line."""
        cmd = "curl -s https://example.com/health\necho done\nsomething -d value"
        self.assertNotIn("egress", cats(cmd))

    def test_evidence_is_the_matching_line(self):
        cmd = 'STAGE=/tmp/stage\ncd "$STAGE"\nrm -rf "$STAGE"\necho done'
        matches = af.audit_command(cmd)
        evidence = [ln for _, cat, ln in matches if cat == "destructive"]
        self.assertTrue(evidence)
        self.assertIn("rm -rf", evidence[0])
        self.assertNotIn("STAGE=/tmp/stage", evidence[0])


class TestCommandHead(unittest.TestCase):

    def test_skips_env_assignments(self):
        self.assertEqual(af.command_head("STAGE=/tmp/x TOKEN=y vercel deploy --prod"), "vercel")

    def test_skips_cd_prefix(self):
        self.assertEqual(af.command_head("cd /Users/a/proj && git push"), "git")

    def test_skips_shell_keywords(self):
        self.assertEqual(af.command_head("for f in *.py; do ruff check $f; done"), "ruff")

    def test_plain_command(self):
        self.assertEqual(af.command_head("grep -rn foo src/"), "grep")

    def test_bare_cd_still_reports_cd(self):
        self.assertEqual(af.command_head("cd /tmp"), "cd")


class TestPricing(unittest.TestCase):

    def test_cache_multipliers(self):
        self.assertEqual(af.CACHE_READ_MULT, 0.10)
        self.assertEqual(af.CACHE_WRITE_5M_MULT, 1.25)
        self.assertEqual(af.CACHE_WRITE_1H_MULT, 2.00)

    def test_sonnet5_intro_pricing_expires(self):
        before = datetime(2026, 8, 1, tzinfo=timezone.utc)
        after = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.assertEqual(af.rates_for("claude-sonnet-5", before)[:2], (2.0, 10.0))
        self.assertEqual(af.rates_for("claude-sonnet-5", after)[:2], (3.0, 15.0))

    def test_unknown_model_is_flagged_not_silently_guessed(self):
        *_, known = af.rates_for("claude-does-not-exist", None)
        self.assertFalse(known)

    def test_provider_is_reported(self):
        self.assertEqual(af.rates_for("claude-opus-5", None)[2], "anthropic")
        self.assertEqual(af.rates_for("gpt-5.2-codex", None)[2], "openai")

    def test_cost_math_end_to_end(self):
        """1M of each bucket on Opus ($5 in / $25 out) = 5 + 25 + 10 + 6.25 + 0.5."""
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {
            "input_tokens": 1_000_000,
            "output_tokens": 1_000_000,
            "cache_read_input_tokens": 1_000_000,
            "cache_creation": {"ephemeral_1h_input_tokens": 1_000_000,
                               "ephemeral_5m_input_tokens": 1_000_000},
        }, None)
        self.assertAlmostEqual(f.total_cost, 46.75, places=6)

    def test_legacy_transcript_flat_cache_total(self):
        """Older transcripts only carry the flat total; assume 5m TTL."""
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"cache_creation_input_tokens": 1_000_000}, None)
        self.assertAlmostEqual(f.total_cost, 6.25, places=6)


class TestCodex(unittest.TestCase):
    """Codex reports usage differently from Claude Code in two ways that will
    silently corrupt totals if handled like Anthropic's."""

    def test_cached_is_a_subset_of_input_not_an_addition(self):
        """OpenAI: input_tokens INCLUDES cached. Billing all of it at full rate
        overcharges; the cached portion bills at 0.10x."""
        usage = {"input_tokens": 1_000_000, "cached_input_tokens": 900_000,
                 "output_tokens": 100_000}
        cost = af.codex_session_cost(usage, "gpt-5.2-codex")
        expected = (0.1 * 1.75) + (0.9 * 1.75 * 0.10) + (0.1 * 14.0)
        self.assertAlmostEqual(cost, expected, places=6)

    def test_reasoning_tokens_are_not_added_to_output(self):
        a = af.codex_session_cost(
            {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 1_000_000}, "gpt-5.2-codex")
        b = af.codex_session_cost(
            {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 1_000_000,
             "reasoning_output_tokens": 900_000}, "gpt-5.2-codex")
        self.assertEqual(a, b)

    def test_fully_cached_session_is_cheap(self):
        usage = {"input_tokens": 1_000_000, "cached_input_tokens": 1_000_000, "output_tokens": 0}
        self.assertAlmostEqual(af.codex_session_cost(usage, "gpt-5.2-codex"), 0.175, places=6)

    def test_session_total_is_the_max_not_the_sum(self):
        """total_token_usage is cumulative and token_count events repeat.
        Summing them inflates a session's cost by orders of magnitude."""
        f = af.Fleet()
        final = {"input_tokens": 1_000_000, "cached_input_tokens": 0, "output_tokens": 0}
        f.add_codex_session("proj", "gpt-5.2-codex", final, None)
        self.assertAlmostEqual(f.total_cost, 1.75, places=6)
        self.assertEqual(f.units_by_agent["codex"], 1)

    def test_agents_are_tracked_separately(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1_000_000}, None)
        f.add_codex_session("p", "gpt-5.2-codex", {"output_tokens": 1_000_000}, None)
        self.assertAlmostEqual(f.cost_by_agent["claude-code"], 25.0, places=6)
        self.assertAlmostEqual(f.cost_by_agent["codex"], 14.0, places=6)

    def test_codex_shell_commands_join_the_same_audit(self):
        f = af.Fleet()
        f.add_tool("proj", "Bash", {"command": "rm -rf /tmp/build"}, None)
        self.assertEqual(f.tools["Bash"], 1)
        self.assertTrue(any(x["severity"] == "high" for x in f.flags))


class TestRoots(unittest.TestCase):

    def test_discovers_multiple_roots(self):
        """Regression: only one config root was scanned, silently missing 97% of
        the fleet on a machine where CLAUDE_CONFIG_DIR is set."""
        roots = af.transcript_roots()
        self.assertIsInstance(roots, list)
        self.assertEqual(len(roots), len({r.resolve() for r in roots}), "roots must be deduped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
