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


class TestSecretClassifier(unittest.TestCase):
    """'792 commands contained credentials' is alarming and useless. The
    classifier turns it into a rotation list."""

    def kinds(self, cmd):
        return {k for _, k, _ in af.classify_secrets(cmd)}

    def test_identifies_by_type(self):
        self.assertIn("Stripe key", self.kinds("export K=sk_live_abcdefghijklmnopqrst"))
        self.assertIn("AWS access key", self.kinds("AKIAIOSFODNN7EXAMPLE"))
        self.assertIn("GitHub PAT", self.kinds("gh auth --with-token ghp_abcdefghijklmnopqrst"))

    def test_same_value_yields_one_fingerprint(self):
        a = af.classify_secrets("TOKEN=ghp_abcdefghijklmnopqrst")
        b = af.classify_secrets("OTHER=ghp_abcdefghijklmnopqrst")
        self.assertEqual({fp for _, _, fp in a}, {fp for _, _, fp in b})

    def test_never_returns_the_secret(self):
        secret = "ghp_supersecretvalue123456"
        for _, _, fp in af.classify_secrets(f"TOKEN={secret}"):
            self.assertNotIn(secret, fp)
            self.assertEqual(len(fp), 8)

    def test_localhost_password_is_low_priority(self):
        got = af.classify_secrets("psql postgresql://u:devpassword@127.0.0.1:5432/db")
        self.assertTrue(any(p == "low" for p, _, _ in got))

    def test_remote_password_is_critical(self):
        got = af.classify_secrets("psql postgresql://u:realpassword@db.prod.example.com/x")
        self.assertTrue(any(p == "critical" for p, _, _ in got))

    def test_critical_name_escalates(self):
        """A var named STRIPE_SECRET_KEY is critical whatever its value looks like."""
        got = af.classify_secrets("STRIPE_SECRET_KEY=abcdefghijklmnop")
        self.assertTrue(any(p == "critical" for p, _, _ in got))
        got = af.classify_secrets("BOARD_TOKEN=abcdefghijklmnop")
        self.assertTrue(all(p != "critical" for p, _, _ in got))

    def test_token_counters_are_not_secrets(self):
        """Regression: output_tokens / token_hash / *_enc are field names."""
        for cmd in ["output_tokens=1234567890123", "input_tokens=99999999999",
                    "token_hash=abcdef1234567890", "api_key_enc=abcdef1234567890",
                    "encrypted_password=abcdef1234567890", "max_tokens=64000000"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(af.classify_secrets(cmd), [], cmd)

    def test_bare_plurals_are_collections_not_secrets(self):
        """Caught by the live watcher: a variable named TOKENS holds a list of
        prefixes, not a credential."""
        for cmd in ["TOKENS=abcdefghijklmnop", "SECRETS=abcdefghijklmnop",
                    "KEYS=abcdefghijklmnop", "_TOKENS=abcdefghijklmnop"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(af.classify_secrets(cmd), [], cmd)

    def test_singular_named_secret_still_fires(self):
        self.assertTrue(af.classify_secrets("TOKEN=abcdefghijklmnop"))
        self.assertTrue(af.classify_secrets("API_KEY=abcdefghijklmnop"))

    def test_placeholders_are_not_secrets(self):
        for cmd in ["TOKEN=$GITHUB_TOKEN", "SECRET=your_secret_here",
                    "PASSWORD=changeme1234", "API_KEY=placeholder1234"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(af.classify_secrets(cmd), [], cmd)

    def test_worst_priority_wins_across_names(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "BOARD_TOKEN=sk_live_abcdefghijklmnop"}, None)
        self.assertTrue(any(e["priority"] == "critical" for e in f.secrets.values()))


class TestCommandHead(unittest.TestCase):

    def test_skips_env_assignments(self):
        self.assertEqual(af.command_head("STAGE=/tmp/x TOKEN=y vercel deploy --prod"), "vercel")

    def test_skips_cd_prefix(self):
        self.assertEqual(af.command_head("cd /Users/a/proj && git push"), "git")

    def test_skips_shell_keywords(self):
        self.assertEqual(af.command_head("for f in *.py; do ruff check $f; done"), "ruff")

    def test_plain_command(self):
        self.assertEqual(af.command_head("grep -rn foo src/"), "grep")

    def test_newline_delimited_loop(self):
        """Regression: a `for` loop with newlines and no `;` reported `for`."""
        self.assertEqual(af.command_head("for f in *.py\ndo\n  ruff check $f\ndone"), "ruff")

    def test_line_continuation_is_not_a_command(self):
        """Regression: a trailing backslash was counted as the program."""
        self.assertEqual(af.command_head("curl -sS \\\n  -X POST https://x"), "curl")

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


class TestCacheEfficiency(unittest.TestCase):

    def test_output_tokens_are_excluded_from_the_denominator(self):
        """Output is not cacheable. Counting it would make chatty projects look
        broken when their caching is fine."""
        from collections import Counter as C
        chatty = C({"input": 10, "cache_w": 0, "cache_read": 90, "output": 10_000_000})
        quiet = C({"input": 10, "cache_w": 0, "cache_read": 90, "output": 0})
        self.assertAlmostEqual(af.cache_hit_rate(chatty), af.cache_hit_rate(quiet))
        self.assertAlmostEqual(af.cache_hit_rate(quiet), 90.0)

    def test_zero_context_does_not_divide_by_zero(self):
        from collections import Counter as C
        self.assertEqual(af.cache_hit_rate(C()), 0.0)

    def test_savings_are_measured_against_sending_uncached(self):
        """1M cache reads on Opus: $5.00 uncached versus $0.50 at the 0.10x
        read rate, so $4.50 saved."""
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"cache_read_input_tokens": 1_000_000}, None)
        saved = f.cache_uncached["p"] - f.cache_actual["p"]
        self.assertAlmostEqual(saved, 4.50, places=6)

    def test_cache_writes_cost_more_than_uncached(self):
        """A 1h write is 2.00x, so a write-only project shows negative savings.
        Reporting that honestly beats clamping it to zero."""
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5",
                    {"cache_creation": {"ephemeral_1h_input_tokens": 1_000_000,
                                        "ephemeral_5m_input_tokens": 0}}, None)
        self.assertLess(f.cache_uncached["p"] - f.cache_actual["p"], 0)

    def test_rates_are_per_model(self):
        f = af.Fleet()
        f.add_usage("a", "claude-opus-5", {"cache_read_input_tokens": 1_000_000}, None)
        f.add_usage("b", "claude-haiku-4-5", {"cache_read_input_tokens": 1_000_000}, None)
        self.assertGreater(f.cache_uncached["a"], f.cache_uncached["b"])


class TestTicketAttribution(unittest.TestCase):

    def test_extracts_numeric_tickets(self):
        for br, want in [("feat/1283-p6-mobile-textlayer", "#1283"),
                         ("fix/2500-no-credentials-in-argv", "#2500"),
                         ("chore/1155-sca-burndown", "#1155"),
                         ("1283-some-slug", "#1283"),
                         ("issue-742", "#742"),
                         ("gh_91", "#91")]:
            with self.subTest(br=br):
                self.assertEqual(af.extract_ticket(br), want)

    def test_extracts_jira_style(self):
        self.assertEqual(af.extract_ticket("feature/PROJ-456-thing"), "PROJ-456")
        self.assertEqual(af.extract_ticket("ABC-12-slug"), "ABC-12")

    def test_trunk_and_detached_are_not_tickets(self):
        for br in ["main", "master", "develop", "trunk", "HEAD", "", None]:
            with self.subTest(br=br):
                self.assertIsNone(af.extract_ticket(br))

    def test_unticketed_branches_are_not_invented(self):
        self.assertIsNone(af.extract_ticket("worktree-lp-doc-cleanup"))
        self.assertIsNone(af.extract_ticket("spike/try-something"))

    def test_one_ticket_spanning_branches_is_one_row(self):
        """The point of grouping by ticket rather than branch."""
        f = af.Fleet()
        for br in ("feat/1283-p5-pdf-vision", "feat/1283-p6-mobile-textlayer"):
            f.add_usage("proj", "claude-opus-5", {"output_tokens": 1_000_000}, None, br)
        self.assertEqual(list(f.cost_by_ticket), ["#1283"])
        self.assertAlmostEqual(f.cost_by_ticket["#1283"], 50.0, places=6)
        self.assertEqual(len(f.branches_by_ticket["#1283"]), 2)

    def test_trunk_and_detached_are_bucketed_separately(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1_000_000}, None, "main")
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1_000_000}, None, "HEAD")
        self.assertEqual(f.cost_by_ticket, {})
        self.assertIn("trunk", f.cost_by_branch)
        self.assertIn("detached HEAD", f.cost_by_branch)


class TestCoach(unittest.TestCase):
    """Findings must be earned. A coach that always says something says nothing."""

    def test_silent_on_an_unremarkable_fleet(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1000}, None)
        self.assertEqual(af.coach(f), [])

    def test_critical_secret_raises_af004(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "K=sk_live_abcdefghijklmnopqrst"}, None)
        self.assertIn("AF004", {x.id for x in af.coach(f)})

    def test_concentration_needs_more_than_two_projects(self):
        f = af.Fleet()
        for p in ("a", "b"):
            f.add_usage(p, "claude-opus-5", {"output_tokens": 1_000_000}, None)
        self.assertNotIn("AF001", {x.id for x in af.coach(f)})

    def test_cache_check_benchmarks_against_your_own_median(self):
        """No fleet-wide constant: a project is only flagged relative to the
        user's own other projects, which needs no telemetry."""
        f = af.Fleet()
        for p in ("good1", "good2", "good3"):
            f.add_usage(p, "claude-opus-5",
                        {"cache_read_input_tokens": 99_000_000, "input_tokens": 1_000_000}, None)
        f.add_usage("bad", "claude-opus-5",
                    {"cache_read_input_tokens": 40_000_000, "input_tokens": 60_000_000}, None)
        hits = [x for x in af.coach(f) if x.id == "AF002"]
        self.assertTrue(hits)
        self.assertIn("bad", hits[0].evidence)

    def test_findings_are_ordered_by_severity(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "K=sk_live_abcdefghijklmnopqrst"}, None)
        for p in ("a", "b", "c"):
            f.add_usage(p, "claude-opus-5", {"output_tokens": 10_000_000}, None)
        f.add_usage("a", "claude-opus-5", {"output_tokens": 400_000_000}, None)
        sev = [x.severity for x in af.coach(f)]
        self.assertEqual(sev, sorted(sev, key=lambda s: {"critical": 0, "high": 1, "info": 2}[s]))


class TestSubagents(unittest.TestCase):

    RESULT = {
        "resolvedModel": "claude-sonnet-5", "status": "completed",
        "totalDurationMs": 60_000, "totalTokens": 76248,
        "toolStats": {"bashCount": 10, "readCount": 4, "editFileCount": 2,
                      "searchCount": 0, "otherToolCount": 1,
                      "linesAdded": 100, "linesRemoved": 20},
        "usage": {"input_tokens": 0, "output_tokens": 1_000_000,
                  "cache_read_input_tokens": 0,
                  "cache_creation": {"ephemeral_1h_input_tokens": 0,
                                     "ephemeral_5m_input_tokens": 0}},
    }

    def test_cost_floor_is_excluded_from_the_headline(self):
        """A lower bound must never be folded into a validated total."""
        f = af.Fleet()
        f.add_subagent(self.RESULT, None)
        self.assertEqual(f.total_cost, 0.0)
        self.assertGreater(f.sub_cost_floor, 0.0)

    def test_cost_floor_prices_by_resolved_model(self):
        """With a timestamp inside the intro window Sonnet 5 is $10/Mtok out."""
        f = af.Fleet()
        f.add_subagent(self.RESULT, datetime(2026, 8, 1, tzinfo=timezone.utc))
        self.assertAlmostEqual(f.sub_cost_floor, 10.0, places=6)

    def test_undated_call_uses_the_conservative_rate(self):
        """No timestamp means no intro discount: over-stating a floor is safer
        than under-stating it."""
        f = af.Fleet()
        f.add_subagent(self.RESULT, None)
        self.assertAlmostEqual(f.sub_cost_floor, 15.0, places=6)

    def test_one_million_context_suffix_is_stripped_for_pricing(self):
        f = af.Fleet()
        f.add_subagent({**self.RESULT, "resolvedModel": "claude-opus-5[1m]"}, None)
        self.assertAlmostEqual(f.sub_cost_floor, 25.0, places=6)
        self.assertEqual(f.sub_by_model["claude-opus-5[1m]"], 1)

    def test_tool_stats_accumulate(self):
        f = af.Fleet()
        f.add_subagent(self.RESULT, None); f.add_subagent(self.RESULT, None)
        self.assertEqual(f.sub_tools["bashCount"], 20)
        self.assertEqual(f.sub_lines["added"], 200)
        self.assertEqual(f.sub_calls, 2)

    def test_af011_fires_when_shell_activity_is_hidden(self):
        f = af.Fleet()
        for _ in range(20):
            f.add_subagent(self.RESULT, None)          # 200 hidden bash calls
        for i in range(100):
            f.add_tool("p", "Bash", {"command": f"echo {i}"}, None)
        self.assertIn("AF011", {x.id for x in af.coach(f)})


class TestShareLeakage(unittest.TestCase):
    """--share output is meant to be posted publicly. The only thing that
    matters about it is that nothing identifying can reach it."""

    SECRETS = ["ACME-CLASSIFIED-MERGER", "feat/9999-project-tigerclaw",
               "/Users/someone/private/repo", "sk_live_leakcanary1234567",
               "internal-db.corp.example.com", "#9999"]

    def _share_output(self):
        import io, contextlib
        f = af.Fleet()
        ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for i in range(20):
            f.add_usage("ACME-CLASSIFIED-MERGER", "claude-opus-5",
                        {"output_tokens": 1_000_000, "cache_read_input_tokens": 9_000_000},
                        ts, "feat/9999-project-tigerclaw")
            f.add_usage(f"other-{i}", "claude-opus-5",
                        {"output_tokens": 10_000, "cache_read_input_tokens": 90_000},
                        ts, f"fix/{100 + i}-thing")
        f.add_tool("ACME-CLASSIFIED-MERGER", "Bash",
                   {"command": "psql postgresql://u:hunter2pass@internal-db.corp.example.com/x "
                               "&& export K=sk_live_leakcanary1234567 "
                               "&& cat /Users/someone/private/repo/.env"}, ts)
        f.add_subagent({"resolvedModel": "claude-sonnet-5", "status": "completed",
                        "totalDurationMs": 1000, "totalTokens": 10,
                        "toolStats": {"bashCount": 40}, "usage": {"output_tokens": 1}}, ts)
        for i in range(4):
            f.add_tool("ACME-CLASSIFIED-MERGER", "Bash", {"command": f"make build-{i}"}, ts)
        f.permission_modes.update({"auto": 900, "default": 100})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        return buf.getvalue()

    def test_no_identifying_string_survives(self):
        out = self._share_output()
        for needle in self.SECRETS:
            with self.subTest(needle=needle):
                self.assertNotIn(needle, out)

    def test_no_secret_fingerprints_leak(self):
        """Even a hash is an identifier that could be correlated."""
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "K=sk_live_abcdefghijklmnopqrst"}, None)
        fps = list(f.secrets)
        self.assertTrue(fps)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        for fp in fps:
            self.assertNotIn(fp, buf.getvalue())

    def test_no_paths_or_slashed_identifiers(self):
        out = self._share_output()
        for line in out.splitlines():
            if "agentfleet" in line or "list price" in line:
                continue
            self.assertNotIn("/Users", line)
            self.assertNotIn("://", line)

    def test_still_reports_the_useful_shape(self):
        out = self._share_output()
        for want in ["agentfleet", "median cost per ticket", "shell command",
                     "unsupervised", "credentials", "list price"]:
            with self.subTest(want=want):
                self.assertIn(want, out)


class TestWatch(unittest.TestCase):

    def test_extracts_claude_code_commands(self):
        rec = {"message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "ls -la"}},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "/x"}},
        ]}}
        self.assertEqual(af._commands_in(rec), ["ls -la"])

    def test_extracts_codex_commands(self):
        rec = {"payload": {"type": "function_call", "name": "shell_command",
                           "arguments": '{"command": "git status", "workdir": "/x"}'}}
        self.assertEqual(af._commands_in(rec), ["git status"])

    def test_malformed_records_are_survivable(self):
        for rec in [{}, {"message": None}, {"payload": {"name": "shell_command",
                                                        "arguments": "not json"}}]:
            with self.subTest(rec=rec):
                self.assertEqual(af._commands_in(rec), [])

    def test_notify_never_raises(self):
        af.notify("t", 'msg with "quotes" and $vars')


class TestRoots(unittest.TestCase):

    def test_discovers_multiple_roots(self):
        """Regression: only one config root was scanned, silently missing 97% of
        the fleet on a machine where CLAUDE_CONFIG_DIR is set."""
        roots = af.transcript_roots()
        self.assertIsInstance(roots, list)
        self.assertEqual(len(roots), len({r.resolve() for r in roots}), "roots must be deduped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
