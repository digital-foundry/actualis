#!/usr/bin/env python3
"""
Actualis — what actually ran.

Local. Read-only. Honest about limits.

Reads Claude Code's local session transcripts and produces a fleet-wide report:
spend by model and project, tool activity, and a deterministic audit of every
shell command your agents ran.

No network. No telemetry. No dependencies. Reads only files already on your disk.

Copyright (C) 2026 Digital Foundry Solutions, LLC
Licensed under the GNU Affero General Public License v3 or later. See LICENSE.
This program comes with ABSOLUTELY NO WARRANTY.

Usage:
    python3 actualis.py                 # full report, all time
    python3 actualis.py --days 30       # last 30 days
    python3 actualis.py --bash          # shell audit only
    python3 actualis.py --json          # machine-readable
    python3 actualis.py --project foo   # filter to matching projects
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from collections import Counter, OrderedDict, defaultdict
from typing import NamedTuple
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

__version__ = "0.2.2"

# --------------------------------------------------------------------------
# Pricing
#
# USD per million tokens, Anthropic first-party API rates.
# Source: Anthropic pricing, verified 2026-08-22.
# Cache multipliers apply to the model's INPUT rate:
#   read           0.10x
#   write  5m TTL  1.25x
#   write  1h TTL  2.00x
#
# These are list API rates. If you are on a Claude subscription (Pro/Max) your
# actual outlay is the flat subscription fee. Read the totals below as
# "what this would have cost at API list price" — an opportunity-cost figure
# and a consumption signal, not a bill.
# --------------------------------------------------------------------------

CACHE_READ_MULT = 0.10
CACHE_WRITE_5M_MULT = 1.25
CACHE_WRITE_1H_MULT = 2.00
# Older transcripts record only a flat cache_creation_input_tokens with no TTL
# split, so the multiplier has to be assumed. It used to assume 5m (1.25x) and
# the README called the result "may under-price slightly".
#
# Measured 2026-08-26 across 71,903 deduplicated records that DO carry the
# split: 95.2% of cache-write tokens are 1h, 4.8% are 5m. Assuming 5m where the
# real mix is 95% 1h under-prices that component by 57%.
#
# So it assumes 1h. That is the more expensive reading, which matches how
# unknown model rates are handled: a bill that surprises you downward is a
# better failure than one that surprises you upward. The assumed volume is
# counted and reported, so this is never a silent adjustment.
CACHE_WRITE_ASSUMED_MULT = CACHE_WRITE_1H_MULT

# Two providers, two cache conventions. Getting this backwards overcharges:
#
#   anthropic  input_tokens EXCLUDES cached. cache_read is a separate bucket at
#              0.10x, cache writes cost 1.25x (5m TTL) or 2.00x (1h TTL).
#   openai     input_tokens INCLUDES cached_input_tokens. Cached portion bills at
#              0.10x, the rest at full rate. There is no cache-write premium, and
#              reasoning_output_tokens is a subset of output_tokens, not an addition.
# Rate provenance. A cost tool that cannot say where a number came from is
# asking to be trusted rather than checked, so every rate carries its source.
# VENDOR means the provider's own published price list; AGGREGATOR means a
# third party, used only where the vendor does not publish that model id.
# Rate provenance, as an ordered pecking order rather than a boolean.
#
# A cost tool that cannot say where a number came from is asking to be trusted
# rather than checked. "Aggregator" alone was too coarse: it lumped a reputable
# third party together with an outright guess, and said nothing about how stale
# either was. Each tier below is strictly weaker than the one above it, and
# RATE_TIERS fixes that order in one place so the report, the JSON and the tests
# cannot disagree about which of two numbers is better founded.
VENDOR = "vendor"            # the provider's own published price list
VENDOR_DOC = "vendor-doc"    # provider docs, changelog or blog, not the price list
AGGREGATOR = "aggregator"    # a third party that tracks prices
FAMILY = "family"            # inferred from a sibling model in the same family
DEFAULT = "default"          # the catch-all ceiling, used when nothing else fits

RATE_TIERS = (VENDOR, VENDOR_DOC, AGGREGATOR, FAMILY, DEFAULT)

# How far a rate can drift out of date before the report stops presenting it
# without comment. Model prices move on the order of months, so a table older
# than a quarter is a number worth doubting rather than quoting.
PRICING_VERIFIED = "2026-08-24"
PRICING_STALE_DAYS = 90

RATE_SOURCES = {
    "anthropic": "https://platform.claude.com/docs/en/about-claude/pricing",
    "openai": "https://developers.openai.com/api/docs/pricing",
    AGGREGATOR: "https://pricepertoken.com",
}


class Rate(NamedTuple):
    """One model's price, and the provenance of that price."""
    input: float          # $ per million input tokens
    output: float         # $ per million output tokens
    provider: str
    tier: str             # one of RATE_TIERS
    note: str = ""
    # A retired model is still priced correctly for historical transcripts, but
    # must not set the ceiling for a model that does not exist yet: opus-4-1 at
    # $15/$75 would price a future Opus at three times the current rate.
    retired: bool = False

    @property
    def confident(self) -> bool:
        """Sourced from the provider itself, rather than inferred or guessed."""
        return self.tier in (VENDOR, VENDOR_DOC)


PRICING: dict[str, Rate] = {
    "claude-fable-5":     Rate(10.0, 50.0, "anthropic", VENDOR),
    "claude-mythos-5":    Rate(10.0, 50.0, "anthropic", VENDOR),
    "claude-opus-5":      Rate(5.0, 25.0, "anthropic", VENDOR),
    "claude-opus-4-8":    Rate(5.0, 25.0, "anthropic", VENDOR),
    "claude-opus-4-7":    Rate(5.0, 25.0, "anthropic", VENDOR),
    "claude-opus-4-6":    Rate(5.0, 25.0, "anthropic", VENDOR),
    "claude-opus-4-5":    Rate(5.0, 25.0, "anthropic", VENDOR),
    "claude-opus-4-1":    Rate(15.0, 75.0, "anthropic", VENDOR,
                               "retired, still billable on Bedrock and GCP",
                               retired=True),
    "claude-sonnet-5":    Rate(2.0, 10.0, "anthropic", VENDOR),
    "claude-sonnet-4-6":  Rate(3.0, 15.0, "anthropic", VENDOR),
    "claude-sonnet-4-5":  Rate(3.0, 15.0, "anthropic", VENDOR),
    "claude-haiku-4-5":   Rate(1.0, 5.0, "anthropic", VENDOR),
    "claude-haiku-3-5":   Rate(0.80, 4.0, "anthropic", VENDOR),

    "gpt-5.2":            Rate(1.75, 14.0, "openai", VENDOR),
    "gpt-5.3-codex":      Rate(1.75, 14.0, "openai", VENDOR),
    # OpenAI publishes no `gpt-5.2-codex` line. This matches what they charge
    # for gpt-5.2 and gpt-5.3-codex, which is corroboration and not confirmation.
    "gpt-5.2-codex":      Rate(1.75, 14.0, "openai", AGGREGATOR,
                               "pricepertoken.com, 2026-08-22; no vendor line exists"),
}

# Model ids are versioned, so a new release lands in a family whose prices are
# already known. Matching the family is a far better guess than the global
# ceiling, and it is reported as an inference rather than as a fact.
_FAMILY_PATTERNS = (
    (re.compile(r"^claude-(opus|sonnet|haiku|fable|mythos)\b"), "anthropic"),
    (re.compile(r"^(gpt|o[1-9])\b"), "openai"),
)

OPENAI_CACHED_MULT = 0.10

# Claude Sonnet 5 launched at $2/$10 as introductory pricing "through
# 2026-08-31", and this file used to switch to $3/$15 after that date. Anthropic
# has since made $2/$10 the standard price and cancelled the increase, so the
# date gate is gone: it would have silently overstated every Sonnet 5 session
# from September onward by 50%.
# Unknown models are priced at the top of what we actually know for that
# provider, so the fallback is an UPPER bound among current models — never a
# silent guess in the cheap direction. It is still only a bound: a premium model
# priced above everything in the table (o1-pro, say) would be understated, which
# is why cost from unknown models is accumulated separately and reported as a
# share of the headline rather than quietly folded into it.
# When nothing better is available. Opus-tier, so an unknown Anthropic model is
# over-stated rather than under-stated: a bill that surprises you downward is a
# far better failure than one that surprises you upward.
DEFAULT_RATES = Rate(5.0, 25.0, "anthropic", DEFAULT,
                     "no rate known for this model; priced at the ceiling")


def _provider_ceiling(provider: str) -> Rate | None:
    """The most expensive rate we actually know for a provider.

    Used when a model is recognisably from a provider but is not in the table.
    Deliberately the ceiling and not the median: this is a bound, and it is
    reported as one.
    """
    known = [r for r in PRICING.values()
             if r.provider == provider and not r.retired]
    if not known:
        return None
    worst = max(known, key=lambda r: (r.output, r.input))
    return Rate(worst.input, worst.output, provider, DEFAULT,
                f"unknown {provider} model; priced at the most expensive "
                f"{provider} rate on file")


def _family_rate(model: str) -> Rate | None:
    """The nearest known sibling in the same model family.

    `claude-sonnet-4-9` ships and is not in the table. Every Sonnet we know is
    within a factor of 1.5, so the family is a far better estimate than the
    global ceiling -- but it is still an inference and says so.
    """
    for pattern, provider in _FAMILY_PATTERNS:
        m = pattern.match(model)
        if not m:
            continue
        family = m.group(0)
        siblings = {k: r for k, r in PRICING.items()
                    if k.startswith(family) and not r.retired}
        if not siblings:
            continue
        # Highest-priced sibling, for the same reason the ceiling is used above.
        name, best = max(siblings.items(), key=lambda kv: (kv[1].output, kv[1].input))
        return Rate(best.input, best.output, provider, FAMILY,
                    f"not in the table; priced as {name}, the most expensive "
                    f"known {family} model")
    return None


def rate_for(model: str) -> Rate:
    """Resolve a model to a rate, best source first.

    exact table entry -> nearest sibling in the same family -> the most
    expensive rate known for that provider -> the global ceiling. Every step
    returns a Rate carrying the tier that answered, so the report can say how
    the number was reached instead of presenting all four as equally solid.
    """
    hit = PRICING.get(model)
    if hit:
        return hit
    fam = _family_rate(model)
    if fam:
        return fam
    for _pattern, provider in _FAMILY_PATTERNS:
        if _pattern.match(model):
            ceiling = _provider_ceiling(provider)
            if ceiling:
                return ceiling
    return DEFAULT_RATES


def rates_for(model: str, when: datetime | None) -> tuple[float, float, str, bool, str]:
    """Back-compatible shape: (input, output, provider, is_known, tier).

    `when` is retained for rates that vary by date. None are date-dependent
    today; the parameter stays so a future scheduled change does not require
    every caller to be touched again.
    """
    r = rate_for(model)
    # Known means the price has a source (price list, vendor docs, aggregator).
    # Only family inference and the default ceiling are estimates.
    return (r.input, r.output, r.provider, r.tier in (VENDOR, VENDOR_DOC, AGGREGATOR), r.tier)


def window_start(days: int, now: datetime | None = None) -> datetime:
    """The cutoff for `--days N`, snapped to a date boundary.

    It used to be `now - N days`, a rolling timestamp that lands mid-day. That
    let records from the partial start date AND N further dates survive, so a
    seven-day window reported eight active days -- the denominator of a headline
    rate exceeding its own window, on a tool that sells being honest about
    limits.

    `--days N` now means the last N calendar days INCLUDING today, in UTC, which
    is both what people mean by it and the only reading that makes active_days
    bounded by N. Every daily aggregate in this file is already keyed on a UTC
    date, so this makes the cutoff agree with the buckets it filters.
    """
    now = now or datetime.now(timezone.utc)
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start_of_today - timedelta(days=max(days, 1) - 1)


def pricing_age_days(today: datetime | None = None) -> int:
    """How stale the table is, computed offline from a date in the source.

    The tool makes no network calls, so it cannot know whether a price changed.
    It can know how long it has been since anyone checked, which is the honest
    thing to report.
    """
    verified = datetime.strptime(PRICING_VERIFIED, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    now = today or datetime.now(timezone.utc)
    return max((now - verified).days, 0)


# --------------------------------------------------------------------------
# Shell command audit
#
# Deterministic pattern matching. No model in the loop, no heuristics that
# vary between runs. A command either matches a rule or it does not.
#
# These flag commands worth LOOKING at. A flag is not an accusation: most
# `rm -rf` calls are a build directory. The point is that you should be able
# to see them at all, which today you cannot.
# --------------------------------------------------------------------------

Rule = tuple[str, str, str]  # (severity, category, regex)

BASH_RULES: list[Rule] = [
    # --- destructive filesystem ---
    ("high", "destructive",      r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR])\b"),
    ("high", "destructive",      r"\b(mkfs|fdisk|diskutil\s+erase)\b"),
    ("high", "destructive",      r"\bdd\s+.*\bof=/dev/"),
    ("med",  "destructive",      r"\btruncate\s+-s\s*0\b"),
    ("med",  "destructive",      r"\bfind\b.*-delete\b"),

    # --- privilege escalation ---
    ("high", "privilege",        r"(^|[;&|]\s*)sudo\b"),
    ("high", "privilege",        r"(^|[;&|]\s*)su\s+-"),
    ("med",  "privilege",        r"\bchmod\s+(-R\s+)?0?777\b"),
    ("med",  "privilege",        r"\bchown\s+-R\s+root\b"),

    # --- remote code execution ---
    ("high", "remote-exec",      r"\b(curl|wget)\b[^|;\n]{0,512}\|\s*(sudo\s+)?(ba|z|k)?sh\b"),
    # An interpreter with an inline-script flag (-c/-e/-m) treats stdin as DATA,
    # so `curl … | python3 -c '…'` is parsing a response, not running downloaded
    # code. Only the bare interpreter form executes what was fetched.
    ("high", "remote-exec",      r"\b(curl|wget)\b[^|;\n]{0,512}\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b"
                                 r"(?!\s+-(?:c|e|m|p)\b)"),
    ("med",  "remote-exec",      r"\bnpx\s+(-y\s+)?https?://"),
    ("med",  "remote-exec",      r"\bpip\s+install\b[^|;\n]{0,512}\bhttps?://"),

    # --- credential and secret access ---
    ("high", "credentials",      r"(cat|less|more|head|tail|strings|cp|scp|base64)\b[^|;\n]{0,512}"
                                 r"(\.env(\.[a-z]+)?|id_[rd]sa|\.pem|\.p12|credentials|\.netrc|\.npmrc|\.pypirc)\b"),
    ("high", "credentials",      r"\bsecurity\s+find-(generic|internet)-password\b"),
    ("med",  "credentials",      r"\b(printenv|env)\b\s*(\||$)"),
    ("med",  "credentials",      r"\b(AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN)\s*="),
    ("high", "credentials",      r"\bgh\s+auth\s+token\b"),

    # --- data egress ---
    # Case-sensitive on the flags: curl -D (dump headers) is not curl -d (send body).
    # Skipped entirely when the command only talks to loopback.
    ("high", "egress",           r"(?!.*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))"
                                 r"\bcurl\b[^|;\n]{0,512}\s(?-i:-d|--data|--data-raw|--data-binary|-F|--form|-T|--upload-file)\b"),
    ("med",  "egress",           r"\b(scp|rsync)\b[^|;\n]{0,512}\s[^\s]+@[^\s]+:"),

    # --- git danger ---
    ("high", "git",              r"\bgit\s+push\b[^|;\n]{0,512}\s(--force|-f)\b"),
    ("high", "git",              r"\bgit\s+(filter-branch|filter-repo)\b"),
    ("med",  "git",              r"\bgit\s+reset\s+--hard\b"),
    ("med",  "git",              r"\bgit\s+clean\s+-[a-zA-Z]*f"),
    ("med",  "git",              r"\bgit\s+checkout\s+(main|master|prod\w*)\b.*\s--\s"),

    # --- publish and deploy ---
    ("high", "publish",          r"\b(npm|pnpm|yarn)\s+publish\b"),
    ("high", "publish",          r"\b(twine\s+upload|cargo\s+publish|gem\s+push)\b"),
    ("high", "publish",          r"\b(kubectl|helm)\b.*\b(delete|destroy)\b"),
    ("high", "publish",          r"\bterraform\s+(apply|destroy)\b(?!.*-plan)"),
    ("med",  "publish",          r"\b(vercel|netlify|fly|wrangler)\s+deploy\b"),
    ("high", "publish",          r"\baws\s+s3\s+(rm|sync)\b[^|;\n]{0,512}--delete\b"),

    # --- database ---
    ("high", "database",         r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b"),
    ("high", "database",         r"\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)"),
    ("med",  "database",         r"\b(psql|mysql|mongosh)\b[^|;\n]{0,512}-c\b"),

    # --- history and audit tampering ---
    ("high", "audit",            r"\bhistory\s+-c\b"),
    ("high", "audit",            r"\b(unset\s+HISTFILE|export\s+HISTSIZE=0)\b"),
    # Deliberately NOT flagged: `cmd >/dev/null 2>&1`. Tested against 48k real
    # commands it fired 1,206 times at ~100% false positive. Silencing a build
    # tool is not audit tampering, and a rule that noisy destroys trust in the
    # rules that matter.
]

COMPILED_RULES = [(sev, cat, re.compile(pat, re.IGNORECASE)) for sev, cat, pat in BASH_RULES]

SEVERITY_ORDER = {"high": 0, "med": 1}


# --------------------------------------------------------------------------
# Commands whose real content is not in the transcript
#
# The README has always said pattern matching has a ceiling. That is true and
# it is also vague: it does not distinguish "we looked and found nothing" from
# "there was nothing here to look at". Those are different facts and only one
# of them is a blind spot.
#
# A command that runs $CMD, evals a string, or executes a script whose contents
# live in a file is UNREADABLE, not merely unmatched. Counting those turns a
# silent gap into a stated one -- and on a real corpus it is 3.11% of commands,
# which is a number worth printing instead of a caveat worth ignoring.
#
# Deliberately counted, never flagged. This is not an accusation: running a
# script is normal. It is a statement about what the audit could and could not
# see.
# --------------------------------------------------------------------------

UNREADABLE_SHAPES = (
    ("runs a variable", re.compile(r"(?:^|[|&;(]\s*)\s*[\"']?\$[A-Za-z_{]")),
    ("eval", re.compile(r"\beval\b")),
    ("pipes a download to a shell",
     re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b")),
    ("runs a local script",
     re.compile(r"(?:^|[|&;]\s*)\s*\.?/[\w./-]+\.(?:sh|bash|zsh|py|rb|pl)\b")),
    ("sources a file",
     re.compile(r"(?:^|[|&;]\s*)\s*(?:source|\.)\s+[\w./$~-]+")),
    ("shell -c with a variable", re.compile(r"\b(?:ba|z|)sh\s+-c\s+[\"']?\$")),
    # Roadmap S2: shapes that hide a download from every rule above. Each is
    # linear: a start is a literal token and every repeat is bounded or cannot
    # overlap the next start.
    # $'\x63url' spells a program with escapes. Only a hex, unicode or octal
    # escape can spell a letter, so IFS=$'\n' is not counted.
    ("ANSI-C quoting", re.compile(r"\$'(?:[^'\\\n]|\\[^xuU0-7\n]){0,256}\\[xuU0-7]")),
    ("pipes a substitution to a shell",
     # The scan stops at the next `$(` or backtick, which is itself a start,
     # so no character is scanned twice.
     re.compile(r"(?:\$\(|`)(?:[^|\n`$]|\$(?!\()){0,512}\|\s*(?:sudo\s+)?(?:busybox\s+)?(?:ba|z|k|da|)sh\b")),
    ("inline script reaching the network",
     re.compile(r"(?m)^(?=[^\n]*?\b(?:python[0-9.]*|node|perl)\s+(?:-\S+\s+){0,8}?-[ce]\s)"
                r"(?=[^\n]*(?:\b(?:urllib|requests|fetch|http\.client|socket)|LWP)\b)")),
)


class AuditConfigId(ValueError):
    """--suppress was given the id of the audit-config finding."""


def flag_id(severity: str, categories: list[str], program: str) -> str:
    """A stable id for a class of shell-audit finding.

    Keyed on severity, category and program rather than on the command text, so
    the id survives the command changing slightly and suppressing one thing
    suppresses the class a person actually means: "rm being flagged destructive
    is expected in this repository", not "this exact rm invocation".
    """
    basis = f"{severity}:{','.join(sorted(categories))}:{program}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:8]


# One id for every audit-config finding, whatever program wrote the file: it can
# never be suppressed, so --suppress can refuse it by name.
AUDIT_CONFIG_ID = flag_id("high", ["audit-config"], "audit-config")


def unreadable_shapes(cmd: str) -> list[str]:
    """Which parts of this command the transcript does not actually contain."""
    text = cmd[:MAX_SCAN_TOTAL]
    return [name for name, rx in UNREADABLE_SHAPES if rx.search(text)]


def audit_command(cmd: str) -> list[tuple[str, str, str]]:
    """Return [(severity, category, matching_line)] for every rule that fires.

    Agent commands are frequently multi-line scripts. Reporting the first line
    of a 40-line heredoc tells you nothing, so each match carries the line that
    actually triggered it.
    """
    # Every rule's character classes exclude \n, so no rule can match across a
    # line break. Scanning is therefore per line, and the whole-command retry
    # this used to do was both redundant and the entire cost: it doubled the
    # work on the slowest possible input.
    lines = [ln[:MAX_SCAN_LINE] for ln in (cmd.splitlines() or [cmd])[:MAX_SCAN_LINES]]
    out: list[tuple[str, str, str]] = []
    for sev, cat, rx in COMPILED_RULES:
        for ln in lines:
            if rx.search(ln):
                out.append((sev, cat, clean(ln.strip())))
                break
    return out


# --------------------------------------------------------------------------
# Secret redaction
#
# This tool's output is meant to be shared: pasted into issues, screenshotted,
# published. Agent transcripts contain live credentials. Redaction is ON by
# default and --no-redact is an explicit, deliberate opt-out.
# --------------------------------------------------------------------------

# Known credential prefixes, longest-first so the more specific ones win.
_TOKEN_PREFIXES = [
    "github_pat_", "sk-ant-api", "sk-ant-", "dop_v1_", "glpat-", "xoxb-", "xoxp-",
    "shpat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "vcp_", "npm_", "sk-", "pk-",
    "AKIA", "ASIA", "AIza", "ya29.", "hf_", "lin_api_", "rk_live_", "sk_live_",
    "sbp_",
]

# ONE list of what a credential is called, used by both redaction and
# classification. They used to be separate and had drifted: AUTH_HEADER was
# masked in output but never reached the rotation list, so `secrets` undercounted
# and nothing said so. Two lists that must agree will not stay agreeing.
#
# `KEY` on its own is deliberately included despite the false-positive risk --
# STRIPE_KEY, SIGNING_KEY and OPENAI_KEY are all real and were all missed. The
# risk is handled by _NOT_SECRET_NAMES below rather than by refusing to look.
# PAT is word-bounded on purpose: unbounded it matches PATH, PATTERN and PATCH.
_SECRET_NAME_WORDS = (
    r"SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY"
    r"|CREDENTIALS?|AUTH|BEARER|SESSION|COOKIE|DSN|PASSPHRASE"
)

# KEY and PAT are short and appear inside ordinary words -- FORKEY, KEYBOARD,
# PATH, PATTERN, PATCH. Both are matched only on a word boundary.
_SHORT_SECRET_WORDS = r"(?<![A-Za-z])(?:KEYS?|PAT)(?![A-Za-z])"

_SECRET_PATTERNS = [
    # KEY=value / KEY: value for anything that smells like a secret
    # Same name list as classification, by construction. A value masked here
    # must also be counted there, or the rotation list silently undercounts.
    re.compile(
        r"(?i)\b([A-Z0-9_]{0,40}(?:" + _SECRET_NAME_WORDS +
        r"|" + _SHORT_SECRET_WORDS + r")[A-Z0-9_]{0,40})"
        r"(\s*[=:]\s*)(['\"]?)"
        r"(?!(?:Bearer|Basic|Digest|Token|None|null|true|false)\b)"
        r"([^\s'\";|&]{6,})"
    ),
    # bare tokens by known prefix
    re.compile(r"\b(" + "|".join(re.escape(p) for p in _TOKEN_PREFIXES) + r")([A-Za-z0-9_\-]{8,})"),
    # Authorization headers. `token` is GitHub's scheme word for a PAT.
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)([^\s'\"]{8,})"),
    # postgres://user:pass@host and friends
    re.compile(r"([a-z][a-z0-9+.\-]{0,20}://[^\s:/@]{1,128}:)([^\s@/]{3,256})(@)"),
]


_MASKED = "<redacted"


_SHELL_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


# A four-character prefix is a useful hint on a 40-character token and a
# meaningful fraction of a 10-character password, so the prefix is only shown
# once the secret is long enough for four characters to be negligible. The exact
# length is a fingerprint that confirms a guess, so it is bucketed instead.
_MASK_PREFIX_MIN = 24
_LENGTH_BUCKETS = ((32, "24-32"), (48, "33-48"), (64, "49-64"), (128, "65-128"))


def _length_bucket(n: int) -> str:
    for hi, label in _LENGTH_BUCKETS:
        if n <= hi:
            return label
    return "128+"


def _mask(s: str) -> str:
    if _MASKED in s:          # already redacted; re-masking would corrupt the marker
        return s
    if _SHELL_REF.match(s):   # "$VERCEL_TOKEN" is a reference; the secret is elsewhere
        return s
    if len(s) < _MASK_PREFIX_MIN:
        return "<redacted>"
    return f"{s[:4]}…<redacted:{_length_bucket(len(s))}>"


# Userinfo in a URL, with or without a password: `https://TOKEN@host/`.
# The lookbehind and the length cap keep the scheme scan linear; the userinfo runs
# greedily to the LAST `@` before the path, as curl and url_host read it.
_URL_USERINFO = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}://)([^/?#\s'\"]+)@")
# scp-style remote `[user[:secret]@]host:path`. Plain `git@host:` is not a secret,
# so only a `:` in the userinfo or a long userinfo is masked.
# Linear by construction: a match may start after `=`, so the user class must
# not contain `=` (or one `=`-dense token is scanned once per `=`, which took
# 5.6 s on 32 KB), and the password class is bounded for the same reason. The
# `=` exclusion also keeps `X=` in `X=user:pw@h:/p` visible.
_SCP_USERINFO = re.compile(r"(?<![^\s'\"=])([^\s@:/'\"=]+(?::[^\s@/'\"]{0,256})?)@([A-Za-z0-9.-]+):")


# Credentials passed as option values. Each rule starts on a literal option
# token behind (?<!\S), so there is one start per option, and every class is
# bounded and cannot run into the next start: linear on any input. Only the
# credential is masked; the user part of user:password stays readable.
#   curl -u/--user/-U/--proxy-user user:PASS, with a space, `=` or nothing.
#   `//` after the colon is a URL (`pip install -U git+https://…`), not a password.
_OPT_USERPASS = re.compile(r"(?<!\S)(-u|-U|--user|--proxy-user)(=|\s+)?(['\"]?)"
                           r"([^\s:'\"]{1,128}:)(?!//)([^\s'\"]{1,256})")
#   wget --password / --http-password / --ftp-password / --proxy-password PASS,
#   and docker login --password PASS, with a space or `=`.
_OPT_PASSWORD = re.compile(r"(?<!\S)(--(?:http-|ftp-|proxy-)?password)(\s+|=)(['\"]?)(?!-)([^\s'\"]{1,256})")
#   docker login -p PASS. Only for `docker login`: -p is a port, a parent flag
#   or a profile everywhere else (mkdir -p, ssh -p 22), and mysql -pPASS and
#   sshpass -p are deliberately left for a program-aware follow-up.
_OPT_DOCKER_LOGIN_P = re.compile(r"(?<!\S)(docker\s+login\b[^\n;|&]{0,512}?\s-p)(\s+|=)?(['\"]?)"
                                 r"(?!-)([^\s'\"]{1,256})")
# (rule, credential group). The same table drives redact() and classify_secrets().
_OPTION_SECRETS = ((_OPT_USERPASS, 5), (_OPT_PASSWORD, 4), (_OPT_DOCKER_LOGIN_P, 4))
# Every command passes through both detectors, and almost none holds any of
# these. One search decides whether the option rules (and, in classification,
# the header rule) need to run at all.
_OPTION_HINT = re.compile(r"(?i)authorization|(?<!\S)-u|--(?:user|proxy-user|(?:http-|ftp-|proxy-)?password)|docker")


# The user an option password belongs to, when the segment names one apart
# from user:password: `docker login -u bob -p …`, `wget --user=bob --password …`.
_OPT_USER_NAME = re.compile(r"(?<!\S)(?:-u|--username|--user)(?:=|\s+)['\"]?([^\s'\"=:]{1,128})")


_SEGMENT_SEP = re.compile(r"[;|&\n]")


# One option spelled two ways is one location: curl's -u is --user, -U is
# --proxy-user, and docker login's -p is --password. Case is kept otherwise:
# -U is not -u.
_OPT_SYNONYMS = {"--user": "-u", "--proxy-user": "-U", "-p": "--password"}


class _SecretLocations:
    """Ids for person-chosen credentials from WHERE they appear, never from
    their value.

    A person chose the password, so sha256(value)[:8] published in a report,
    a CI log or a committed suppressions file would confirm a guess offline.
    The id hashes the location instead: program, option and user for an
    option password; the variable name and program for a PASSWORD variable;
    user@host for a URL or scp password. Two passwords at one location share
    one id; docs/secrets.md says so, and the run counts distinct values.

    Segment bounds are found once per command and each segment's user is
    looked up once, so many credentials in one long command stay linear.
    """

    def __init__(self, cmd: str):
        self.cmd = cmd
        self.seps = [m.start() for m in _SEGMENT_SEP.finditer(cmd)]
        self.users: dict[int, str] = {}
        self.prefixes: dict[int, list] = {}      # segment start -> [pos, tokens, clean]
        self.passes = 0

    @staticmethod
    def make(basis: str) -> str:
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:8]

    def segment(self, pos: int) -> tuple[int, int]:
        lo, hi = 0, len(self.seps)           # first separator at or after pos
        while lo < hi:
            mid = (lo + hi) // 2
            if self.seps[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        start = self.seps[lo - 1] + 1 if lo else 0
        end = self.seps[lo] if lo < len(self.seps) else len(self.cmd)
        return start, end

    def program(self, pos: int) -> str:
        """The program of the segment holding `pos`: its first word past
        assignments and prefixes, or "". A bounded look."""
        start, end = self.segment(pos)
        head = self.cmd[start:min(end, start + 512)].split()
        words = _net_strip_prefixes(head)[0]
        return _net_base(words[0]).lower() if words else ""

    def prefix_tokens(self, pos: int) -> "list[str] | None":
        """Dequoted tokens of the segment holding `pos`, up to `pos`. Grown from
        the last call while no quote is open, so many options in one long
        segment stay linear; None when the pass budget is spent (the caller then
        masks)."""
        start, _end = self.segment(pos)
        cached = self.prefixes.get(start)
        if cached is not None and cached[2] and cached[0] <= pos:
            between = self.cmd[cached[0]:pos]
            cached[1].extend(_net_tokens(between))
            cached[2] = not _net_split(between)[1]
            cached[0] = pos
            return cached[1]
        if self.passes >= _USERPASS_PASSES:
            return None
        self.passes += 1
        text = self.cmd[start:pos]
        entry = self.prefixes[start] = [pos, _net_tokens(text), not _net_split(text)[1]]
        return entry[1]

    def option(self, m: "re.Match", rx: "re.Pattern") -> str:
        start, end = self.segment(m.start())
        if rx is _OPT_DOCKER_LOGIN_P:
            program, option = "docker", "-p"
        else:
            program, option = self.program(m.start()), m.group(1)
        option = _OPT_SYNONYMS.get(option, option)
        if rx is _OPT_USERPASS:
            user = m.group(4)[:-1]
        else:
            if start not in self.users:
                u = _OPT_USER_NAME.search(self.cmd, start, end)
                self.users[start] = u.group(1) if u else ""
            user = self.users[start]
        return self.make(f"opt:{program}:{option}:{user}")


# `-u user:pw` fails CLOSED: it is masked and counted unless the program that
# RECEIVES the option is one where `-u`/`--user` means a user or uid:gid.
# That program is found on the dequoted tokens before the match, over the
# whole segment, past the wrappers the network extractor skips (sudo env
# timeout nice nohup xargs), a shell's -c string, eval, `su -c`, `ssh HOST …`
# and `docker exec|run CTR …`. In `docker exec -u root:wheel ctr cmd` docker
# receives the first -u; in `sudo curl -u a:b` curl does. Anything not
# recognised, and a budget of tokenising passes spent, masks. A purely numeric
# pair (`1000:1000`) is never a credential.
_USERPASS_NOT_CREDENTIAL = frozenset({
    "docker", "podman", "sudo", "su", "ssh", "chown", "chgrp", "id", "useradd", "usermod",
    "install", "ps", "kill", "pkill", "lsof", "crontab", "systemctl", "git",
    "env", "doas", "nice", "timeout"})
_USERPASS_CONTAINER_SUBS = frozenset({"exec", "run", "create"})
_USERPASS_SSH_VALUE = frozenset("-p -i -l -o -F -J -L -R -D -b -c -e -m -O -S -w -W -E -B -I -Q".split())
_USERPASS_PASSES = 32                        # full tokenising passes per command


def _userpass_receiver(toks: list[str], depth: int = 0) -> tuple[str, str]:
    """(program, docker subcommand) that the option following `toks` belongs to;
    ("", "") when it cannot be told."""
    head_toks = toks[:256]                   # the wrapper structure is at the front
    rest = _net_strip_prefixes(head_toks)[0]
    if not rest:
        for t in reversed(head_toks):
            if _net_base(t).lower() in _NET_PREFIXES:
                return _net_base(t).lower(), ""
        return "", ""
    head = _net_base(rest[0]).lower()
    if depth >= 4:
        return head, ""
    inner: list[str] | None = None
    sub = ""
    if head in _NET_SHELLS:
        k = _net_shell_c_index(rest[:64])
        inner = _net_tokens(rest[k + 1]) if k else None
    elif head == "eval" and len(rest) > 1:
        inner = _net_tokens(" ".join(rest[1:]))
    elif head == "su":
        k = next((n for n, t in enumerate(rest[:64]) if t in ("-c", "--command")), 0)
        inner = _net_tokens(rest[k + 1]) if k and k + 1 < len(rest) else None
    elif head == "ssh":
        n = 1
        while n < len(rest) and rest[n].startswith("-") and len(rest[n]) > 1:
            n += 2 if rest[n] in _USERPASS_SSH_VALUE else 1
        inner = _net_tokens(" ".join(rest[n + 1:])) if len(rest) > n + 1 else None
    elif head in ("docker", "podman") and len(rest) > 1:
        sub = next((t for t in rest[1:8] if not t.startswith("-")), "")
        if sub in _USERPASS_CONTAINER_SUBS:
            n = rest.index(sub) + 1
            while n < len(rest) and rest[n].startswith("-") and len(rest[n]) > 1:
                n += 2 if rest[n] in _DOCKER_VALUE else 1
            inner = rest[n + 1:] if len(rest) > n + 1 else None   # past the container or image
    if inner:
        return _userpass_receiver(inner, depth + 1)
    return head, sub


def _userpass_exempt(where: "_SecretLocations", m: "re.Match") -> bool:
    """True when this `-u X:Y` is not a credential: a uid:gid, or the option of a
    program where it means something else."""
    user, pw = m.group(4)[:-1], m.group(5)
    if user.isdigit() and pw.isdigit():
        return True
    toks = where.prefix_tokens(m.start())
    if toks is None:
        return False
    prog, sub = _userpass_receiver(toks)
    if prog not in _USERPASS_NOT_CREDENTIAL:
        return False
    return sub in _USERPASS_CONTAINER_SUBS if prog in ("docker", "podman") else True


def _option_secret(value: str) -> bool:
    """An option value worth masking and counting. A uid:gid pair, a shell
    reference and a placeholder are none of them, and both detectors agree."""
    return not (_looks_like_placeholder(value) or is_vendor_example(value))


def _option_mask(group: int, where: "_SecretLocations | None" = None):
    def sub(m: "re.Match") -> str:
        v = m.group(group)
        if not _option_secret(v) or (where is not None and _userpass_exempt(where, m)):
            return m.group(0)
        return m.group(0)[:m.start(group) - m.start(0)] + _mask(v) + m.group(0)[m.end(group) - m.start(0):]
    return sub


def _scp_mask(m: "re.Match") -> str:
    u = m.group(1)
    if ":" in u or len(u) > 20:
        return f"{_mask(u)}@{m.group(2)}:"
    return m.group(0)


def redact(text: str) -> str:
    """Remove credential material from a command string. Idempotent."""
    if not text:
        return text
    truncated = False
    if text.endswith(TRUNCATED_MARK):        # idempotent: strip our own marker first
        text, truncated = text[:-len(TRUNCATED_MARK)], True
    if len(text) > MAX_SCAN_TOTAL:
        text, truncated = text[:MAX_SCAN_TOTAL], True
    out = _redact_scanned(text)
    return out + TRUNCATED_MARK if truncated else out


def _redact_scanned(out: str) -> str:
    # Order matters: the Authorization header rule must run before the generic
    # KEY=value rule, or "AUTH" in "Authorization:" makes it eat the scheme word.
    out = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    if _OPTION_HINT.search(out):
        for rx, group in _OPTION_SECRETS:
            where = _SecretLocations(out) if rx is _OPT_USERPASS and rx.search(out) else None
            out = rx.sub(_option_mask(group, where), out)
    out = _SECRET_PATTERNS[3].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}{m.group(3)}", out)
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask(m.group(4))}", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    out = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}@", out)
    out = _SCP_USERINFO.sub(_scp_mask, out)
    return out


def contains_secret(text: str) -> bool:
    """True when redaction would change the text.

    Compared against the SAME truncated input redact() works on. Comparing
    against the full text made every command longer than MAX_SCAN_TOTAL report
    as containing a secret, because truncation alone made the strings differ.
    """
    if not text:
        return False
    head = text[:MAX_SCAN_TOTAL]
    return redact(head) != head


# Words that are never the command being run.
# Two kinds of header, and they need opposite handling.
# `for x in LIST`, `case x in`, `select x in` are followed by a variable and a
# word list -- nothing there is a program, so the rest of the segment is
# abandoned. `if CMD`, `while CMD`, `until CMD` are followed by a COMMAND whose
# exit status is tested, so scanning must continue into it. Treating them alike
# made `if docker info; then echo up` report `echo`.
_HEADER_KEYWORDS = {"for", "while", "until", "if", "case", "select", "function", "elif"}
_HEADERS_TAKING_A_WORD_LIST = {"for", "case", "select", "function"}
_BODY_KEYWORDS = {"do", "then", "else", "fi", "done", "esac", "in", "{", "(", "!"}
_PREFIX_WORDS = {"sudo", "env", "exec", "time", "nohup", "command", "builtin", "nice", "xargs"}
_TAKES_PATH_ARG = {"cd", "pushd", "popd"}
# `[` and `test` really are programs, but in `if [ -f x ]; then cat x` they are
# the CONDITION and `cat` is the work. Reporting `[` as the most-run program is
# technically true and useless.
_CONDITION_WORDS = {"[", "[[", "]", "]]", "test"}
_FUNCTION_DEF = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\(\)$")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# `2>/dev/null`, `>out`, `>>log`, `2>&1`, `<in` — a redirection is never the
# program. Skipping `cd` plus its path argument used to leave the redirect as
# the first surviving token, so `cd /tmp 2>/dev/null` reported `2>/dev/null`.
_REDIRECT = re.compile(r"^\d*(?:>>?|<<?|&>|>&)")
# `TOK=$(grep -oE … )` — the program is inside the substitution, not the
# assignment. Skipping the whole token walked the parser onto the next one,
# which is usually a flag, so this reported `-oE`.
_ASSIGN_SUBST = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=[\"']?(?:\$\(|`)([A-Za-z0-9_./+-]+)")


# --------------------------------------------------------------------------
# Untrusted text
#
# Transcripts contain whatever an agent typed, fetched, or was fed — including
# content from web pages and files. Anything from a transcript is untrusted and
# must be neutralised before it reaches a terminal, a log, or JSON.
#
# Terminal escapes are the live risk: a command carrying \x1b[2J clears the
# reader's screen, and cursor-movement or overwrite sequences can HIDE the
# dangerous part of a command from the audit that exists to show it. For a tool
# whose threat model includes a prompt-injected agent, that is the attack.
# --------------------------------------------------------------------------

# C0/C1 controls defeat ANSI escapes. The Unicode ranges defeat the same attack
# carried out without any escape: a right-to-left override visually reverses the
# tail of a command in most terminals, and zero-width characters split a token so
# it reads as something it is not. Both hide the dangerous part of a command from
# the audit that exists to show it, which is the threat this module names.
#   200b-200f  zero-width space/joiners, LRM/RLM
#   2028-202e  line/paragraph separators, the bidi embedding and override set
#   2060-2064  word joiner and invisible operators
#   2066-2069  bidi isolates
#   feff       zero-width no-break space (BOM)
# Built from a named table rather than one opaque class, so a reader can audit
# what is stripped and why without decoding hex ranges -- and so that adding a
# range later requires stating a reason.
_STRIPPED_RANGES = (
    (0x00, 0x08, "C0 controls below tab"),
    (0x0B, 0x1F, "C0 controls above newline, including ESC (0x1B) and CR (0x0D)"),
    (0x7F, 0x9F, "DEL and the C1 control block"),
    (0x200B, 0x200F, "zero-width space and joiners, LRM and RLM"),
    (0x2028, 0x202E, "line and paragraph separators, bidi embedding and override"),
    (0x2060, 0x2064, "word joiner and the invisible operators"),
    (0x2066, 0x2069, "bidi isolates"),
    (0xFEFF, 0xFEFF, "zero-width no-break space, the BOM"),
)

# Tab (0x09) and newline (0x0A) are the only whitespace controls that survive.
# CARRIAGE RETURN DOES NOT. A bare \r returns the cursor to column zero, so a
# command can overwrite what was already printed above it -- which is precisely
# the hiding this module exists to prevent, and is why it is not treated as a
# harmless newline.
_CONTROL = re.compile(
    "[" + "".join(f"\\u{lo:04x}-\\u{hi:04x}" for lo, hi, _why in _STRIPPED_RANGES) + "]"
)

# Bound the work any single command can cause. audit_command runs ~40 patterns
# with wide character classes; a 140,000-character line took 164 seconds before
# these caps, which is a denial of service reachable from transcript content.
MAX_SCAN_LINE = 4096
MAX_SCAN_LINES = 400
# classify_secrets and redact must see the WHOLE command, since a credential can
# sit anywhere in it, so they are bounded by total length rather than per line.
# Real commands carrying secrets are small; a 40,000-character single line is
# pathological and cost 4 seconds unbounded.
MAX_SCAN_TOTAL = 32768
MAX_SCAN_HARD = 1 << 20          # past this a command is counted unreadable, not scanned
SCAN_OVERLAP = 1024              # windows of an oversized command overlap by this much
TRUNCATED_MARK = "…[truncated]"


def scan_windows(cmd: str) -> list[str]:
    """A command as windows of MAX_SCAN_TOTAL overlapping by SCAN_OVERLAP, so a
    name or token split by a boundary lies whole in one window. Linear in the
    command, which is first cut to MAX_SCAN_HARD."""
    cmd = cmd[:MAX_SCAN_HARD]
    if len(cmd) <= MAX_SCAN_TOTAL:
        return [cmd]
    step = MAX_SCAN_TOTAL - SCAN_OVERLAP
    out, i = [], 0
    while True:
        out.append(cmd[i:i + MAX_SCAN_TOTAL])
        if i + MAX_SCAN_TOTAL >= len(cmd):
            return out
        i += step


def clean(text: str | None) -> str:
    """Strip control characters from untrusted text.

    Tab and newline survive. Carriage return does not: see _STRIPPED_RANGES.
    """
    if not text:
        return ""
    return _CONTROL.sub("", text.replace("\t", " "))


# --------------------------------------------------------------------------
# Ticket attribution
#
# Cost per project answers "where did the money go" at a granularity nobody
# budgets in. Branch names almost always carry the issue number, so the same
# data answers "what did issue #412 cost", which is the unit engineering and
# finance already think in.
#
# One ticket often spans several branches (feat/412-p5-…, feat/412-p6-…), so
# grouping by ticket rather than branch is the point of the exercise.
# --------------------------------------------------------------------------

TRUNK_BRANCHES = {"main", "master", "develop", "dev", "trunk", "release"}

# "issue-742" is issue 742, not project ISSUE ticket 742, so the generic
# tracker prefixes must be matched before the Jira-style project-key rule.
_TRACKER_WORDS = r"issue|issues|gh|pr|bug|ticket|task|story|card"

_TICKET_PATTERNS = [
    re.compile(rf"^(?:[a-z]+/)?(?:{_TRACKER_WORDS})[-_]?(\d{{1,6}})\b", re.I),
    re.compile(rf"^[a-z]+/(?!(?:{_TRACKER_WORDS})\b)([A-Z][A-Z0-9]+-\d+)", re.I),
    re.compile(rf"^(?!(?:{_TRACKER_WORDS})\b)([A-Z][A-Z0-9]+-\d+)", re.I),
    re.compile(r"^[a-z]+/(\d{1,6})\b", re.I),            # feat/412-slug
    re.compile(r"^(\d{2,6})-"),                           # 412-slug
]


def extract_ticket(branch: str | None) -> str | None:
    """The issue id a branch refers to, or None for trunk and ad-hoc work."""
    if not branch:
        return None
    b = branch.strip()
    if b in TRUNK_BRANCHES or b == "HEAD":
        return None
    for rx in _TICKET_PATTERNS:
        m = rx.match(b)
        if m:
            tok = m.group(1)
            return f"#{tok}" if tok.isdigit() else tok.upper()
    return None


def branch_bucket(branch: str | None) -> str:
    """Where unticketed work is reported."""
    if not branch:
        return "unknown"
    if branch in TRUNK_BRANCHES:
        return "trunk"
    if branch == "HEAD":
        return "detached HEAD"
    return branch


# --------------------------------------------------------------------------
# Secret classification
#
# "792 commands contained credentials" is alarming and useless. What you need
# is the distinct-secret count, the type, and an order to rotate in. Secrets
# are identified by sha256 prefix so the same value seen 200 times counts once
# and the value itself is never stored, printed, or written to JSON.
#
# Priority: critical = money or database god-mode. high = service credentials.
# low = local development, not worth rotating.
# --------------------------------------------------------------------------

SECRET_TYPES: list[tuple[str, str, "re.Pattern[str]"]] = [
    ("critical", "Stripe key",       re.compile(r"\b(?:sk|rk)_live_([A-Za-z0-9]{16,})")),
    ("critical", "AWS access key",   re.compile(r"\b(?:AKIA|ASIA)([A-Z0-9]{12,})")),
    ("critical", "Anthropic key",    re.compile(r"\bsk-ant-[a-z0-9-]{0,20}([A-Za-z0-9_\-]{16,})")),
    ("critical", "OpenAI key",       re.compile(r"\bsk-(?!ant)[A-Za-z0-9]{2,}-([A-Za-z0-9_\-]{16,})")),
    ("critical", "JWT / service key", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.([A-Za-z0-9_\-]{20,})")),
    ("high",     "GitHub PAT",       re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)([A-Za-z0-9_]{16,})")),
    ("high",     "Google API key",   re.compile(r"\bAIza([A-Za-z0-9_\-]{16,})")),
    ("high",     "Slack token",      re.compile(r"\bxox[baprs]-([A-Za-z0-9\-]{16,})")),
    ("high",     "Vercel token",     re.compile(r"\bvcp_([A-Za-z0-9]{16,})")),
    ("high",     "GitLab PAT",       re.compile(r"\bglpat-([A-Za-z0-9_\-]{16,})")),
    ("high",     "DigitalOcean",     re.compile(r"\bdop_v1_([a-f0-9]{32,})")),
    ("high",     "HuggingFace",      re.compile(r"\bhf_([A-Za-z0-9]{16,})")),
    # Added 2026-08-26 from corpus evidence: 58 occurrences, one consistent
    # shape, sbp_ followed by exactly 40 alphanumerics. A Supabase personal
    # access token carries full account authority, so critical rather than high.
    ("critical", "Supabase PAT",     re.compile(r"\bsbp_([A-Za-z0-9]{40})")),
]

# Considered and REJECTED, 2026-08-26, with the measurement rather than a guess:
#
#   re_   Resend API keys start `re_`, and the corpus contains 180 matches for
#         `re_` plus 16+ opaque characters -- across 37 distinct shapes, every
#         one a lowercase word with separators (`re_deploy-preview-branch`).
#         No digits, no mixed case, no entropy. All 180 are identifiers. A
#         two-letter prefix is too generic to carry a detector, and adding it
#         would have produced 180 false positives and zero true ones here.
#
# The general rule this encodes: a prefix earns a place by being distinctive
# enough that ordinary text does not collide with it, not by belonging to a
# provider somebody has heard of.

# Connection strings. Loopback is dev credential churn, not an incident.
_URL_CRED = re.compile(r"([a-z][a-z0-9+.\-]{0,20})://([^\s:/@]{1,128}):([^\s@/]{6,256})@([^\s/:\"']{1,255})")
_LOCAL_HOST = re.compile(r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$", re.I)

# Secret-shaped assignments, minus the field names that merely *sound* like one.
_NAMED_SECRET = re.compile(
    r"\b([A-Za-z0-9_]{0,40}(?:" + _SECRET_NAME_WORDS + r"|" + _SHORT_SECRET_WORDS + r")"
    r"[A-Za-z0-9_]{0,40})"
    r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{12,})", re.IGNORECASE)

# These are column names, metric names, and already-encrypted columns. They
# match the "sounds like a secret" pattern and are not secrets.
_NOT_SECRET_NAMES = re.compile(
    r"(?i)^(?:"
    r"(?:input|output|total|cache[a-z_]*|reasoning[a-z_]*|max|min|num|n)_?tokens?"
    r"|tokens?_?(?:count|used|remaining|limit|usage|per[a-z_]*)"
    r"|[a-z_]*_(?:enc|encrypted|hash|hashed|digest|fingerprint)"
    r"|(?:encrypted|hashed)_[a-z_]*"
    r"|[a-z_]*token_(?:id|type|name|expiry|expires[a-z_]*)"
    # `KEY` earns its place in the name list by catching STRIPE_KEY and
    # SIGNING_KEY, but most things called *_KEY are not credentials: they are
    # database keys, cache keys, filenames, or the NAME of a key rather than a
    # key. Each of these was checked against a real false-positive battery.
    # Database keys, cache keys, and keys that are public by definition. NOT
    # api/ssh/gpg: API_KEY is the canonical credential name, and an env var
    # holding an SSH or GPG key holds the private half.
    r"|(?:primary|foreign|sort|partition|cache|composite|shard|idempotency"
    r"|license|licence|public|row|range|hash)_keys?"
    r"|keys?_(?:id|name|file|path|dir|prefix|pattern|type|size|format|algorithm)"
    r"|[a-z_]*_keys?_(?:id|name|file|path|type)"
    # Published on purpose. A Supabase anon key and anything a framework
    # prefixes NEXT_PUBLIC_ or EXPO_PUBLIC_ is meant to ship to the browser.
    # Telling someone to rotate one teaches them to ignore the tool.
    r"|[a-z_]*(?:anon|publishable)_keys?"
    r"|(?:next|expo|vite|react_app|public)_public[a-z_]*"
    r"|[a-z_]*public_[a-z_]*keys?"
    # Idempotency and deduplication keys are identifiers, not credentials.
    r"|[a-z_]*(?:dedupe?|dedup|idempotenc[a-z]*|correlation|trace|request)_keys?"
    r"|key(?:board|word|stone|note|frame|space)[a-z_]*"
    r"|[a-z_]*monkey[a-z_]*"
    # --- from a corpus review, 2026-08-26 -------------------------------
    # 49 distinct name-based detections on a real corpus were reviewed by hand.
    # 18 were wrong. They were not one-offs; they fell into these shapes, and
    # each line below names the case that produced it.
    #
    # A trigger word that is only the START of a longer, ordinary word.
    # AUTHOR matched because it begins with AUTH -- the same class of defect as
    # KEY matching inside FORKEY.
    r"|author[a-z_]*|[a-z_]*_author[a-z_]*"
    r"|cookie(?:less|count|jar|name|path|domain|banner|consent)[a-z_]*"
    # An identifier is not a credential. AUTH_PROVIDER_ID, _SESSION_ID.
    r"|[a-z_]*(?:secret|token|session|auth|key|cookie|credential)s?_ids?"
    r"|[a-z_]*_(?:provider|client|tenant|account|user|org)_ids?"
    # Public by design. A Turnstile or reCAPTCHA SITE key is meant to ship to a
    # browser; only its paired SECRET is secret. EMBED_TURNSTILE_SITE_KEY.
    r"|[a-z_]*site_keys?"
    # Configuration that happens to contain a trigger word.
    # SESSION_RECORDING_SAMPLE_RATE, SESSION_REPLAY_CONFIG, COOKIELESS.
    r"|[a-z_]*(?:session|cookie|token|auth)_(?:recording|replay|storage|timeout"
    r"|duration|sample|config|enabled|disabled|mode|strategy|policy|ttl)[a-z_]*"
    r"|[a-z_]*_(?:sample_rate|opt_in|opt_out|enabled|disabled|count|rate"
    r"|duration_milliseconds|config)$"
    # Build settings and tool-generated names, not application configuration.
    # TINFOPLIST_KEY_LSAPPLICATIONCATEGORYTYPE.
    r"|t?infoplist_[a-z_]*|[a-z_]*_build_settings?[a-z_]*"
    # An object or handle in code, not a value. DB_SESSION.
    r"|(?:db|database|sql|orm|http|requests?|client|async)_session[a-z_]*"
    # Apple's appAccountToken is a UUID identifying a purchase, not a secret.
    r"|app_?account_?token[a-z_]*"
    # A PLURAL names a collection -- a list of accepted key names, a count --
    # not one credential. The existing rule caught bare plurals; these are the
    # qualified ones. UNRECOGNIZED_KEYS.
    # Only `keys` and `tokens`: those plurals reliably name a list. CREDENTIALS,
    # SECRETS and COOKIES routinely name a single blob -- a service-account
    # bundle, a cookie jar -- and silencing SERVICE_CREDENTIALS would be a false
    # negative on a real secret, which is the worse error of the two.
    r"|[a-z_]*_(?:keys|tokens)"
    # A name that reads as a boolean or an action is a flag, not a value.
    # RUN_AND_PERSIST_IC_SESSION.
    r"|(?:run|use|enable|disable|is|has|should|allow|skip|with|without)_[a-z_]*"
    r"|[a-z_]*(?:secret|token|password|key|credential)s?_(?:name|id|label|ref|alias|arn|uri|url|var)"
    # A bare plural names a COLLECTION (a list of prefixes, a count), not one
    # credential. Caught in the wild: this file's own regex literal listing
    # secret-ish words tripped the scanner while it was being edited.
    r"|_?(?:tokens|secrets|keys|passwords|credentials|api_keys)"
    r")$")


# --------------------------------------------------------------------------
# Vendor example credentials
#
# Every cloud vendor publishes a fake credential in its own documentation, and
# those strings end up in tutorials, README files, test fixtures and issue
# threads. They are not credentials and never were.
#
# Reporting one as critical is worse than a normal false positive. Since
# --fail-on shipped, it fails somebody's pipeline; and it lands on the person
# evaluating this tool for the first time, following the vendor's own docs,
# who reasonably concludes the detector cries wolf. A security tool gets about
# one false positive of this kind before it stops being trusted.
#
# Each entry names where it comes from, so the list can be checked rather than
# believed.

_VENDOR_EXAMPLES = {
    # AWS publishes these throughout its CLI and SDK documentation.
    "AKIAIOSFODNN7EXAMPLE",                      # AWS docs: access key id
    "ASIAIOSFODNN7EXAMPLE",                      # AWS docs: temporary access key id
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS docs: secret access key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY", # AWS docs: variant with 'z'
    # Other vendors publish examples too (Google Maps, Stripe docs). They are
    # deliberately absent: an entry here must be verifiable against the
    # vendor's own documentation, and a plausible-looking string invented from
    # memory is exactly the kind of unchecked claim this tool exists to avoid.
    # Add them with a source, or not at all.
}

# AWS builds every example credential the same way: the body ends in EXAMPLE.
# Matching that catches the ones not enumerated above without suppressing an
# arbitrary string that merely contains the word. A real key ending in exactly
# EXAMPLE has probability (1/36)^7, about one in 78 billion, which is a worse
# risk than the false positive it removes only if you have 78 billion keys.
_AWS_EXAMPLE = re.compile(r"^(?:AKIA|ASIA)[A-Z0-9]*EXAMPLE$")


def is_vendor_example(value: str) -> bool:
    """A credential the vendor itself publishes as fake."""
    return value in _VENDOR_EXAMPLES or _AWS_EXAMPLE.match(value) is not None


def _looks_like_placeholder(v: str) -> bool:
    low = v.lower()
    return (v.isdigit()
            or _SHELL_REF.match(v) is not None
            or _MASKED in v
            or low in {"true", "false", "null", "none", "undefined", "changeme", "example"}
            or low.startswith(("your_", "your-", "xxx", "<", "$(", "placeholder",
                               "dummy", "test_", "fake", "changeme", "example",
                               "insert_", "replace_", "todo")))


_PASSWORD_NAME = re.compile(r"(?i)PASS(?:WORD|WD|PHRASE)")


# A variable named STRIPE_SECRET_KEY is critical whether or not its value
# happens to carry a recognisable live-key prefix.
_CRITICAL_NAMES = re.compile(
    r"(?i)(stripe|aws|service_role|servicerole|private_key|master|root|prod|payment|billing)")


def _priority_for_name(name: str) -> str:
    return "critical" if _CRITICAL_NAMES.search(name) else "high"


def classify_secrets(cmd: str, value_digests: dict[str, set[str]] | None = None
                     ) -> list[tuple[str, str, str]]:
    """Return [(priority, type, sha256[:8])] for each distinct secret in a command.

    The secret value is hashed immediately and never retained. For an id taken
    from where a password appears rather than from its value, `value_digests`,
    when given, receives id -> {sha256(value)}, so the caller can tell how many
    different passwords one id stands for. The caller keeps those digests in
    memory only and never emits them.
    """
    cmd = cmd[:MAX_SCAN_TOTAL]
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    # Characters of the values the c596778 detectors (prefixes, URL passwords
    # of 6+, named secrets of 12+) count. Those keep their value ids, and a
    # later detector does not count the same value again under a location id.
    legacy = bytearray(len(cmd))

    def add(priority: str, kind: str, value: str, fp: str | None = None,
            span: tuple[int, int] | None = None) -> None:
        if _looks_like_placeholder(value) or is_vendor_example(value):
            return
        if span is not None:
            if fp and any(legacy[span[0]:span[1]]):
                return                           # already counted, by value
            if not fp:
                legacy[span[0]:span[1]] = b"\x01" * (span[1] - span[0])
        if fp and value_digests is not None:     # a location id: remember which values
            value_digests.setdefault(fp, set()).add(
                hashlib.sha256(value.encode("utf-8", "replace")).hexdigest())
        fp = fp or hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
        if fp in seen:
            return
        seen.add(fp)
        out.append((priority, kind, fp))

    for priority, kind, rx in SECRET_TYPES:
        for m in rx.finditer(cmd):
            add(priority, kind, m.group(0), span=m.span(0))

    for m in _URL_CRED.finditer(cmd):
        scheme, _user, pw, host = m.groups()
        local = _LOCAL_HOST.match(host) is not None
        add("low" if local else "critical",
            clean(f"{scheme} password ({'local' if local else 'remote'})")[:48], pw,
            span=m.span(3))

    for m in _NAMED_SECRET.finditer(cmd):
        name, value = m.group(1), m.group(2)
        # Template placeholders arrive wrapped -- __X__, {{X}}, %X% -- and the
        # decoration is not part of the name. Strip it so a single exclusion
        # covers every spelling instead of one per template syntax.
        if _NOT_SECRET_NAMES.match(name.strip("_{}%$<>")):
            continue
        add(_priority_for_name(name), clean(name.upper())[:48], value, span=m.span(2))

    # Everything below was first counted in this wave. A person may have chosen
    # any of it, so each gets an id from where it appears (_SecretLocations),
    # never sha256(value)[:8].
    where = _SecretLocations(cmd)

    # Roadmap S1: every form redact() masks is counted here too, through the
    # same compiled rules, so the rotation list and the masking cannot drift.
    if _OPTION_HINT.search(cmd):
        for rx, group in _OPTION_SECRETS:
            for m in rx.finditer(cmd):
                if rx is _OPT_USERPASS and _userpass_exempt(where, m):
                    continue
                add("high", "password option", m.group(group), where.option(m, rx), m.span(group))
        for m in _SECRET_PATTERNS[2].finditer(cmd):
            scheme = m.group(1).split(":", 1)[1].split()[0].lower()
            add("high", "Authorization header", m.group(2),
                where.make(f"hdr:{where.program(m.start())}:{scheme}"), m.span(2))
    # A password is short. _NAMED_SECRET wants 12 characters, which suits a
    # token; PGPASSWORD=hunter2pass was masked and never counted.
    if _PASSWORD_NAME.search(cmd):
        for m in _SECRET_PATTERNS[0].finditer(cmd):
            name = m.group(1)
            if _PASSWORD_NAME.search(name) and not _NOT_SECRET_NAMES.match(name.strip("_{}%$<>")):
                add(_priority_for_name(name), clean(name.upper())[:48], m.group(4),
                    where.make(f"name:{name.upper()}:{where.program(m.start())}"), m.span(4))
    if "@" not in cmd:
        return out
    for m in _URL_USERINFO.finditer(cmd):
        user, sep, pw = m.group(2).partition(":")
        host = re.split(r"[\s/:?#'\"]", cmd[m.end():m.end() + 256], maxsplit=1)[0].lower()
        if sep and pw:
            local = _LOCAL_HOST.match(host) is not None
            scheme = m.group(1)[:-3]
            add("low" if local else "critical",
                clean(f"{scheme} password ({'local' if local else 'remote'})")[:48], pw,
                where.make(f"url:{user}@{host}"), (m.end() - len(pw) - 1, m.end() - 1))
        elif len(user) > 20:
            add("high", "URL userinfo token", user, where.make(f"urltoken:{host}"),
                (m.start(2), m.end(2)))
    for m in _SCP_USERINFO.finditer(cmd):
        user, sep, pw = m.group(1).partition(":")
        host = m.group(2).lower()
        if sep and pw:
            add("critical", "scp password", pw, where.make(f"scp:{user}@{host}"),
                (m.end(1) - len(pw), m.end(1)))
        elif len(user) > 20:
            add("high", "scp userinfo token", user, where.make(f"scptoken:{host}"), m.span(1))

    return out


_HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


def _without_heredocs(cmd: str) -> str:
    """Drop heredoc bodies before looking for a program.

    A heredoc carries data -- a JSON payload, a commit message, a file being
    written. Splitting the command on newlines turned each of those lines into
    its own candidate segment, so a bare path inside a document became "the
    program" on 121 real commands. The `cat <<EOF` line itself is kept; only
    the body between it and its terminator is removed.
    """
    if "<<" not in cmd:
        return cmd
    out, lines = [], cmd.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = _HEREDOC.search(line)
        i += 1
        if not m:
            continue
        terminator = m.group(1)
        while i < len(lines) and lines[i].strip() != terminator:
            i += 1
        i += 1                      # skip the terminator itself
    return "\n".join(out)


def _shell_tokens(segment: str) -> list[str]:
    """Split on whitespace, treating a quoted span as part of its token.

    Two mistakes are possible here and this file has made both.

    `segment.split()` tears a quoted path apart, so
    `M="/Users/x/My Folder/f"` yields `Folder/f"` -- and since the assignment
    before it is skipped, that fragment gets returned as the program.

    Dropping quoted spans instead loses the program when the program IS quoted:
    `"$P" --check x.md` becomes `--check x.md`, and a filename is returned. The
    content has to be kept and the quotes removed, so a quoted token stays one
    token and stays readable.
    """
    out, buf, quote = [], [], ""
    for ch in segment:
        if quote:
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch.isspace():
            if buf:
                out.append("".join(buf)); buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def command_head(cmd: str) -> str | None:
    """The program actually being run.

    Agent commands are rarely a bare invocation. They arrive as
    `VAR=x cd path && for f in *.py; do tool $f; done`, and naively taking the
    first token reports `VAR=x` or `for`, which tells you nothing about what ran.
    """
    # Newlines delimit segments too: a `for … \n do …` loop has no `;` at all,
    # and without splitting on them the whole loop reads as one segment starting
    # with `for`, which then reports `for` as the program.
    for segment in re.split(r"&&|\|\||;|\||\n", _without_heredocs(cmd).strip()):
        tokens = _shell_tokens(segment)
        if not tokens:
            continue
        if tokens[0] in _HEADERS_TAKING_A_WORD_LIST:
            continue  # `for x in LIST`: the body is a later segment
        if _CONDITION_WORDS.intersection(tokens):
            # `if [ -f x ]` is its own segment once split on `;`, and every
            # token in it belongs to the test rather than to the work. Skipping
            # only the `[` returned its operand instead.
            continue
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if _ASSIGNMENT.match(tok):
                inner = _ASSIGN_SUBST.match(tok)
                if inner:
                    if inner.group(1) in _HEADERS_TAKING_A_WORD_LIST:
                        # `out=$(for n in …)` opens the substitution with a loop
                        # header, so what follows in this segment is the loop's
                        # own operands. Abandon it, exactly as a bare header
                        # does -- otherwise the loop VARIABLE is returned.
                        break
                    return inner.group(1)     # `TOK=$(grep …)` runs grep
                continue                      # plain environment assignment
            if tok in _BODY_KEYWORDS or tok in _PREFIX_WORDS:
                continue                      # `do tool …`, `sudo tool …`
            if tok in _HEADERS_TAKING_A_WORD_LIST:
                break                         # `for i in …`: operands, not a program
            if tok in _HEADER_KEYWORDS:
                continue                      # `if CMD`: the operand IS a program
            if tok == "\\":
                continue                      # line continuation, not a program
            if tok.startswith("#"):
                break                         # comment: nothing after it runs
            if _FUNCTION_DEF.match(tok):
                # `verify() { rm -rf x; }` defines a function; it does not run
                # one. Skip the name so the body's real program is reported.
                continue
            if _REDIRECT.match(tok):
                continue                      # redirection, not a program
            if tok.startswith("-"):
                continue                      # a flag is never the program
            if tok in _TAKES_PATH_ARG:
                skip_next = True              # `cd /some/path && real-cmd`
                continue
            return tok
    # Nothing in any segment looked like a program. Fall back to the first
    # token, except when it opens a comment -- a command that is only a comment
    # ran nothing, and reporting `#` as a program put it in the flag tables.
    first = cmd.strip().split()
    if not first or first[0].startswith("#"):
        return None
    return first[0]


_TEST_PROGRAMS = frozenset({"pytest", "jest", "vitest", "mocha", "rspec",
                            "phpunit", "tox", "nox", "ava", "karma"})
# Programs whose `test` subcommand runs a test suite.
_TEST_SUBCOMMAND = frozenset({"npm", "pnpm", "yarn", "bun", "go", "cargo", "make",
                              "dotnet", "deno", "mix", "swift", "gradle", "mvn"})
_INSTALLERS = {   # program -> the subcommands that install something
    "pip": {"install"}, "pip3": {"install"}, "pipx": {"install"},
    "brew": {"install", "upgrade"}, "apt": {"install"}, "apt-get": {"install"},
    "dnf": {"install"}, "yum": {"install"}, "apk": {"add"}, "gem": {"install"},
    "npm": {"install", "i", "ci", "add"}, "pnpm": {"install", "i", "add"},
    "yarn": {"install", "add"}, "bun": {"install", "i", "add"},
    "cargo": {"install", "add"}, "go": {"install", "get"}, "uv": {"add", "sync"},
}


def command_category(cmd: str) -> str:
    """git, test, install or other: the only shape of a command a card shows.

    A command head can identify (`./acme-deploy`); four fixed words cannot. The
    head alone is not enough -- `npm test` and `npm i` share it -- so the token
    after the program decides.
    """
    head = command_head(cmd)
    if not head:
        return "other"
    if head == "git":
        return "git"
    toks = cmd.split()
    names = [t.rsplit("/", 1)[-1] for t in toks]
    rest = toks[names.index(head) + 1:] if head in names else []
    sub = rest[0] if rest else ""
    if head in _TEST_PROGRAMS:
        return "test"
    if head.startswith("python") and rest[:2] in (["-m", "pytest"], ["-m", "unittest"]):
        return "test"
    if head in _TEST_SUBCOMMAND and (
            sub == "test" or (sub == "run" and len(rest) > 1 and rest[1].startswith("test"))):
        return "test"
    if head == "uv" and rest[:2] in (["pip", "install"], ["tool", "install"]):
        return "install"
    if sub in _INSTALLERS.get(head, ()):
        return "install"
    return "other"


# --- network inventory -------------------------------------------------------
#
# What an agent downloaded, and from where. Only commands and tool calls the
# transcript shows are read; a script that downloads (`bash install.sh`,
# `make`, `npm run x`, a postinstall hook) is out of sight and not guessed at.
# The tokenizer is _shell_tokens(), the same one command_head() uses, so the
# inventory and the audit agree on what a command is.

NETWORK_REGISTRY: dict[str, str] = {
    "npm": "registry.npmjs.org", "pypi": "pypi.org", "brew": "formulae.brew.sh",
    "crates": "crates.io", "go": "proxy.golang.org", "oci": "registry-1.docker.io",
}
NETWORK_ITEMS_CAP = 2000

_NET_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# scp-style git remote: [user@]host.tld:owner/repo
_NET_SCP = re.compile(r"^(?:[^@/\s]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,}):(?!//)(\S+)$")
_NET_EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
# A full MAJOR.MINOR.PATCH: the only npm, crates or go version that names one release.
# `4`, `4.1`, `^4.1.2`, `4.x`, `latest` and `v1.2` (a go prefix query) are ranges or tags.
_NET_FULL_VERSION = re.compile(r"^=?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_NET_GO_VERSION = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_OCI_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})
_NET_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NET_PREFIX_VALUE_FLAGS = {"sudo": {"-u", "-g", "-C", "-h", "-p"}, "nice": {"-n"}, "env": {"-u", "-C"},
                           "timeout": {"-s", "--signal", "-k", "--kill-after"},
                           "stdbuf": {"-i", "-o", "-e"}, "doas": {"-u", "-C"},
                           "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a",
                                     "--max-args", "--max-procs", "--max-lines", "--delimiter",
                                     "--eof", "--max-chars", "--arg-file", "--replace"}}
# Words that run the command after them: skipped, with their own flags.
_NET_PREFIXES = frozenset({"sudo", "env", "time", "nice", "nohup", "command", "exec",
                           "timeout", "stdbuf", "doas", "busybox", "xargs"})
# Shell grammar that can stand before a command in a segment: `do curl …`,
# `if curl …`, `! curl …`, `{ curl …`. A `for x in …` header is not here: it is
# followed by a word list, not a command, and reads as no download.
_NET_CONTROL_WORDS = frozenset({"while", "until", "if", "then", "else", "elif", "do",
                                "!", "{", "}", "(", ")"})
# `-c`, and any single-dash cluster holding c: bash -lc, sh -xc, zsh -ec.
# A letters-only check plus `"c" in t`: `-[A-Za-z]*c[A-Za-z]*` backtracks once
# per `c` and took 3 s on a 32 KB token.
_NET_SHELL_FLAGS = re.compile(r"^-[A-Za-z]+$")


def _net_base(path: str) -> str:
    """The last path component. Path(x).name, at a fraction of the cost on
    the per-command hot path."""
    return path.rsplit("/", 1)[-1]


# A command holding none of these cannot name a download: no quote, escape,
# substitution or group to hide a program in, and no program name the
# extractors know (each name below is a substring of every spelling read:
# pip covers pip3 and pipx, uv covers uvx, npm covers pnpm, bun covers bunx,
# go covers cargo, gh is gh). Such a command skips tokenising entirely.
_NET_MAY_DOWNLOAD = re.compile(r"['\"\\$`(]|curl|wget|git|gh|npm|npx|yarn|bun|pip|uv|brew|go|docker|podman")


def _net_shell_c(t: str) -> bool:
    return "c" in t and _NET_SHELL_FLAGS.match(t) is not None


def _net_shell_c_index(tokens: list[str]) -> int:
    """Where a shell's -c (or -lc, -xc, …) is, when a command string follows; else 0."""
    return next((k for k in range(1, len(tokens) - 1) if _net_shell_c(tokens[k])), 0)
_NET_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_NET_BACKTICK = re.compile(r"`([^`]*)`")


def url_host(url: str) -> str | None:
    """Lowercased host of a URL or scp-style git remote, without user or port.

    None for anything that is not one: a remote name, a path, or a URL built
    from a shell variable, whose host cannot be known from the transcript.
    """
    if not url or "$" in url or "`" in url:
        return None
    if _NET_URL.match(url):
        rest = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
        host = rest.rsplit("@", 1)[-1]
        if host.startswith("["):             # IPv6 literal: keep the brackets, drop the port
            return host[:host.find("]") + 1].lower() if "]" in host else None
        return host.split(":", 1)[0].lower().removesuffix(".") or None
    m = _NET_SCP.match(url)
    return m.group(1).lower().removesuffix(".") if m else None


def url_path(url: str) -> str:
    """The path of a URL or scp-style remote, starting with '/', or ''."""
    if _NET_URL.match(url or ""):
        rest = re.split(r"[?#]", url.split("://", 1)[1], maxsplit=1)[0]
        return rest[rest.find("/"):] if "/" in rest else ""
    m = _NET_SCP.match(url or "")
    return "/" + m.group(2) if m else ""


def _net_item(kind: str, program: str, **kw) -> dict:
    item = {"kind": kind, "program": program, "host": None, "host_inferred": False,
            "url": None, "dest": None, "source": None, "ecosystem": None, "package": None,
            "version": None, "pinned": False, "exec": False, "dynamic": False, "alias": None}
    item.update(kw)
    return item


def _net_url_item(kind: str, program: str, url: str, **kw) -> dict:
    host = url_host(url)
    return _net_item(kind, program, host=host, url=url,
                     dynamic=host is None and ("$" in url or "`" in url), **kw)


def _net_registry_item(program: str, ecosystem: str, name: str | None, version: str | None,
                       registry: str | None, exec_: bool = False,
                       exact: "re.Pattern" = _NET_FULL_VERSION) -> dict:
    host = url_host(registry) if registry else None
    return _net_item("install", program, ecosystem=ecosystem, package=name, version=version,
                     pinned=bool(version and exact.match(version)), exec=exec_,
                     host=host or NETWORK_REGISTRY[ecosystem], host_inferred=not host)


def _net_lockfile(program: str, ecosystem: str, registry: str | None = None) -> dict:
    item = _net_registry_item(program, ecosystem, None, None, registry)
    item["pinned"] = True
    return item


def _net_positionals(args: list[str], takes_value: frozenset = frozenset()) -> tuple[list[str], dict]:
    """Split argv into positionals and options. An option in `takes_value`
    consumes the next token; `--opt=value` is split; everything after `--`
    is positional."""
    pos: list[str] = []
    opts: dict[str, str] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos += args[i + 1:]
            break
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            opts[k] = v
        elif a.startswith("-") and len(a) > 1:
            if a in takes_value and i + 1 < len(args):
                opts[a] = args[i + 1]
                i += 1
            else:
                opts[a] = ""
        else:
            pos.append(a)
        i += 1
    return pos, opts


# The character loops in _net_split and _net_tokens are exact and slow. A text
# with none of these characters splits the same way in one C-level call, which
# is most commands. A fuzz of 200,000 random strings found no difference.
_NET_SPLIT_SLOW = re.compile(r"['\"\\]|>\|")
_NET_SPLIT_OPS = re.compile(r"(&&|\|\||\|&|[;|\n])")
_NET_TOKENS_SLOW = re.compile(r"['\"\\<>&()]")


def _net_split(text: str, seps: list[str] | None = None) -> tuple[list[str], bool]:
    """Split on && || |& ; | and newline, outside quotes. Returns the parts and
    whether a quote was left open (the last part is then unusable). `seps`,
    when given, receives the operator after each part ("" after the last)."""
    if not _NET_SPLIT_SLOW.search(text):     # nothing quoted or escaped: one C-level split
        pieces = _NET_SPLIT_OPS.split(text)
        if seps is not None:
            seps += ["|" if p == "|&" else p for p in pieces[1::2]] + [""]
        return pieces[0::2], False
    parts, buf, quote, i = [], [], "", 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote != "'" and i + 1 < len(text):
            buf.append(text[i:i + 2])        # an escaped character opens and closes nothing
            i += 2
            continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif text.startswith(("&&", "||", "|&"), i):
            parts.append("".join(buf))
            if seps is not None:
                seps.append("|" if text.startswith("|&", i) else text[i:i + 2])   # |& pipes stderr too
            buf = []
            i += 2
            continue
        elif ch == "|" and buf and buf[-1] == ">":
            buf.append(ch)                   # `>|` is a clobber redirection, not a pipe
        elif ch in ";|\n":
            parts.append("".join(buf))
            if seps is not None:
                seps.append(ch)
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    if seps is not None:
        seps.append("")
    return parts, bool(quote)


def _net_strip_prefixes(tokens: list[str]) -> tuple[list[str], bool]:
    """The command a segment runs, past assignments, control-flow words and
    wrappers, and whether it came through `xargs` (its arguments may then
    arrive on stdin, out of sight)."""
    i, via_xargs = 0, False
    while i < len(tokens):
        t = tokens[i]
        if _NET_ASSIGN.match(t) or t in _NET_CONTROL_WORDS:
            i += 1
            continue
        if t in _NET_PREFIXES:
            takes = _NET_PREFIX_VALUE_FLAGS.get(t, set())
            via_xargs = via_xargs or t == "xargs"
            i += 1
            while i < len(tokens) and tokens[i].startswith("-") and len(tokens[i]) > 1:
                i += 2 if tokens[i] in takes else 1
            if t == "timeout" and i < len(tokens):
                i += 1                       # the DURATION
            continue
        break
    return tokens[i:], via_xargs


def _net_close_paren(text: str, start: int) -> int:
    """Index of the ')' closing a '$(' whose body starts at `start`, or -1.
    Parentheses inside quoted spans do not count; a backslash escapes outside
    single quotes. One forward pass."""
    depth, j = 1, start
    while j < len(text):
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch in "\"'":
            j += 1
            while j < len(text) and text[j] != ch:
                j += 2 if (ch == '"' and text[j] == "\\") else 1
            if j >= len(text):
                return -1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _net_feeds_shell(before: str, process: bool) -> bool:
    """Whether a substitution that starts right after `before` is run by a
    shell as code. For `$(…)`: `sh -c "$(…)"`, where the output is the
    script. For a process substitution `<(…)`: `bash <(…)`, `source <(…)`,
    `. <(…)`. `before` is a bounded window, so this is constant work."""
    cut = max(before.rfind(c) for c in ";&|\n(") + 1
    words = [w.strip("\"'") for w in before[cut:].split()]
    words = _net_strip_prefixes([w for w in words if w])[0]
    if not words:
        return False
    prog = _net_base(words[0])
    if process:
        return (prog in _NET_SHELLS or prog in ("source", ".")) \
            and all(w.startswith("-") for w in words[1:])
    return prog in _NET_SHELLS and len(words) > 1 and _net_shell_c(words[-1])


def _net_substitutions(text: str, feeds: list[bool] | None = None) -> tuple[list[str], str]:
    """The bodies of every $( ... ), <( ... ) and `...` in `text`, outermost
    first (an inner one is found again when its body is read), and `text`
    with them blanked. Parentheses are matched by depth, so `$(a $(b))` is
    one body. `feeds`, when given, receives for each body whether a shell
    runs its output as code (_net_feeds_shell)."""
    bodies: list[str] = []
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith(("$(", "<("), i):
            end = _net_close_paren(text, i + 2)
            if end < 0:
                out.append(text[i:])         # unbalanced: nothing later can balance either
                break
            bodies.append(text[i + 2:end])
            if feeds is not None:
                feeds.append(_net_feeds_shell(text[max(0, i - 256):i], text[i] == "<"))
            out.append(" ")
            i = end + 1
            continue
        out.append(text[i])
        i += 1
    rest = "".join(out)
    ticks = [m.group(1) for m in _NET_BACKTICK.finditer(rest)]
    bodies += ticks
    if feeds is not None:
        feeds += [False] * len(ticks)
    return bodies, _NET_BACKTICK.sub(" ", rest)


# Redirection operators, longest first. `>|` reaches here only from _net_split,
# which keeps the `|` of a clobber with its `>`.
_NET_REDIRECT_OPS = ("&>>", "&>", "<<<", "<<", "<>", "<&", "<", ">>", ">&", ">|", ">")


def _net_tokens(segment: str, operators: bool = False) -> list[str]:
    """Like _shell_tokens, but a backslash escapes: `\\"` is a quote character,
    not a quote. Kept here so command_head() keeps its behaviour.

    With `operators`, an unquoted `(` or `)` separates words, and an unquoted redirection (`>`, `2>&1`, `&>f`, `< f`,
    `<<< w`, `>| f`, attached or not) is dropped with its target, and a word
    is cut where an unquoted `<` or `>` starts one: `https://a.io>/tmp/x`
    is the URL `https://a.io`. A redirection is never a package or a host."""
    if not _NET_TOKENS_SLOW.search(segment):  # no quote, escape or operator: plain words
        return segment.split()
    out, buf, quote, started, i = [], [], "", False, 0
    discard = False                          # the next word is a redirection target
    while i < len(segment):
        ch = segment[i]
        if ch == "\\" and quote != "'" and i + 1 < len(segment):
            nxt = segment[i + 1]
            if quote == '"' and nxt not in '"\\$`':
                buf.append(ch)
            buf.append(nxt)
            started = True
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
        elif ch in "\"'":
            quote, started = ch, True
        elif ch.isspace():
            if buf or started:
                if not discard:
                    out.append("".join(buf))
                discard = False
                buf, started = [], False
        elif operators and ch in "()":
            if (buf or started) and not discard:
                out.append("".join(buf))
            if buf or started:
                discard = False
            buf, started = [], False
        elif operators and (ch in "<>" or segment.startswith("&>", i)):
            op = next(o for o in _NET_REDIRECT_OPS if segment.startswith(o, i))
            word = "".join(buf)
            if (buf or started) and not word.isdigit() and not discard:
                out.append(word)                 # `a.io>f`: the word ends here; `2>f`: 2 is the fd
            buf, started, discard = [], False, True
            i += len(op)
            continue
        else:
            buf.append(ch)
            started = True
        i += 1
    if (buf or started) and not discard:
        out.append("".join(buf))
    return out


def _net_segments(cmd: str, depth: int = 0) -> tuple[list[tuple[list[str], bool, bool, str]], int]:
    """Token lists for every simple command in `cmd`, nested ones included
    ($(...), <(...), backticks, bash -lc "...", eval "..."), each with whether
    it ran under xargs, whether its output is run by a shell, and its raw text;
    and how many segments could not be tokenised because a quote was left
    open or nesting went deeper than is read."""
    out: list[tuple[list[str], bool, bool, str]] = []
    unparsed = 0
    text = _without_heredocs(cmd)
    # The character-level pass is skipped when there is nothing for it to find.
    feeds: list[bool] = []
    bodies, text = (_net_substitutions(text, feeds) if "$(" in text or "`" in text or "<(" in text
                    else ([], text))
    if depth < 3:
        for body, feed in zip(bodies, feeds):
            inner, bad = _net_segments(body, depth + 1)
            # `sh -c "$(curl …)"`, `bash <(curl …)`: what the body prints is run.
            out += [(t, x, True, r) for t, x, _, r in inner] if feed else inner
            unparsed += bad
    elif bodies:
        unparsed += 1                        # nested deeper than we read: say so
    seps: list[str] = []
    parts, open_quote = _net_split(text, seps)
    if open_quote:
        parts = parts[:-1]
        unparsed += 1
    stripped = [_net_strip_prefixes(_net_tokens(p, operators=True)) for p in parts]
    # `curl … | sh`, `| sudo bash`, `| busybox sh`, `| tee f | sh`: a shell at
    # any later stage of the same pipeline, on the dequoted names. Worked
    # backwards once, so a long pipeline stays linear.
    downstream = [False] * (len(stripped) + 1)
    for n in range(len(stripped) - 2, -1, -1):
        if seps[n] == "|":
            nxt = stripped[n + 1][0]
            downstream[n] = downstream[n + 1] or (
                bool(nxt) and _net_base(nxt[0]) in _NET_SHELLS and not _net_shell_c_index(nxt))
    for n, (tokens, via_xargs) in enumerate(stripped):
        if not tokens:
            continue
        prog = _net_base(tokens[0])
        flag = _net_shell_c_index(tokens) if prog in _NET_SHELLS else 0
        into_shell = downstream[n]
        # `eval ARGS` runs its arguments joined by spaces, as `bash -c` would.
        nested = (tokens[flag + 1] if flag else
                  " ".join(tokens[1:]) if prog == "eval" and len(tokens) > 1 else None)
        if nested is not None:
            if depth >= 3:
                unparsed += 1                # nested deeper than we read
            else:
                inner, bad = _net_segments(nested, depth + 1)
                out += inner
                unparsed += bad
                continue
        out.append((tokens, via_xargs, into_shell, parts[n]))
    return out, unparsed


_CURL_VALUE = frozenset(
    "-o --output -H --header -d --data --data-raw --data-binary --data-urlencode -X --request "
    "-u --user -A --user-agent -e --referer -b --cookie -c --cookie-jar -F --form -T --upload-file "
    "-w --write-out -m --max-time --connect-timeout -x --proxy --retry -r --range --cacert --cert "
    "--key -K --config --resolve --url -E".split())
_WGET_VALUE = frozenset("-O --output-document -P --directory-prefix -o --output-file -U --user-agent "
                        "--header -t --tries -T --timeout -e --execute".split())
_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree"})
_GIT_CLONE_VALUE = frozenset("--depth -b --branch -o --origin --reference --filter -c --config "
                             "-j --jobs --template --separate-git-dir".split())
_GH_DOWNLOAD_VALUE = frozenset({"-R", "--repo", "-p", "--pattern", "-D", "--dir", "-O", "--output",
                                "-A", "--archive"})
_NPM_VALUE = frozenset("--registry --prefix -w --workspace --tag --cache -C --dir --filter".split())
_NPM_INSTALL = {"npm": {"i", "install", "add"}, "pnpm": {"add", "install", "i"},
                "yarn": {"add", "install"}, "bun": {"add", "install", "i"}}
_NPX_VALUE = frozenset({"-p", "--package", "--registry", "-c", "--call"})
_PIP_VALUE = frozenset("-r --requirement -c --constraint -i --index-url --extra-index-url -t --target "
                       "--prefix --root -e --editable -f --find-links --python -p --platform".split())
_UVX_VALUE = frozenset({"--from", "--with", "-p", "--python", "--index-url", "-i"})
_CARGO_VALUE = frozenset({"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path",
                          "--registry", "--index", "-F", "--features", "--root"})
_GO_VALUE = frozenset({"-C", "-modfile", "-tags", "-ldflags", "-o"})
_DOCKER_VALUE = frozenset("-v --volume -e --env -p --publish --name -w --workdir --network --entrypoint "
                          "-u --user --platform --env-file -l --label --mount -h --hostname --add-host "
                          "--cpus -m --memory --restart --pull --log-driver --gpus".split())
_PIP_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^,;\s]*)")


def _net_is_url_arg(a: str) -> bool:
    return "://" in a or "$" in a or "`" in a


def _net_curl(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _CURL_VALUE)
    urls = [u for u in pos if _net_is_url_arg(u)] + ([opts["--url"]] if opts.get("--url") else [])
    dest = opts.get("-o") or opts.get("--output") or (
        "(remote name)" if "-O" in opts or "--remote-name" in opts else None)
    return [_net_url_item("fetch", "curl", u, dest=dest) for u in urls]


def _net_wget(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _WGET_VALUE)
    dest = (opts.get("-O") or opts.get("--output-document") or opts.get("-P")
            or opts.get("--directory-prefix"))
    return [_net_url_item("fetch", "wget", u, dest=dest) for u in pos if _net_is_url_arg(u)]


def _net_git_sub(args: list[str]) -> tuple[str, list[str]]:
    """The git subcommand and its arguments, past the global options."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in _GIT_GLOBAL_VALUE else 1
    return (args[i], args[i + 1:]) if i < len(args) else ("", [])


NET_REMOTES_CAP = 256
_GIT_REMOTE_ADD_VALUE = frozenset({"-t", "-m", "--track", "--master"})


def _net_git_remote_names(args: list[str]) -> "list[str] | None":
    """For a command that touches several remotes (`fetch --all`, `pull --all`,
    `remote update [NAMES]`): the names it names, or None for every remote.
    Returns [] for any other command."""
    sub, rest = _net_git_sub(args)
    if sub in ("fetch", "pull"):
        _, opts = _net_positionals(rest, frozenset({"--depth", "-j", "--jobs"}))
        return None if "--all" in opts else []
    if sub == "remote" and rest[:1] == ["update"]:
        pos, _ = _net_positionals(rest[1:])
        return pos or None
    return []


def _net_git_remotes(args: list[str], remotes: dict[str, str]) -> None:
    """Track, in order, the URL each remote name stands for in this session:
    `git remote add|set-url NAME URL`, and the `origin` a `git clone URL` makes."""
    sub, rest = _net_git_sub(args)
    if sub == "clone":
        pos, opts = _net_positionals(rest, _GIT_CLONE_VALUE)
        name = opts.get("-o") or opts.get("--origin") or "origin"
        if pos and (len(remotes) < NET_REMOTES_CAP or name in remotes):
            remotes[name] = pos[0]
    elif sub == "remote" and rest[:1] in (["add"], ["set-url"]):
        # -t BRANCH and -m MASTER take a value; -f, --tags, --no-tags, --mirror=… do not.
        pos, _ = _net_positionals(rest[1:], _GIT_REMOTE_ADD_VALUE)
        if len(pos) >= 2 and (len(remotes) < NET_REMOTES_CAP or pos[0] in remotes):
            remotes[pos[0]] = pos[1]


def _net_git_remote_name(args: list[str]) -> str | None:
    """The remote a fetch, pull or dry-run push names (`origin` when none is
    given), or None for any other command or when a URL is given directly."""
    sub, rest = _net_git_sub(args)
    if sub not in ("fetch", "pull", "push"):
        return None
    pos, _ = _net_positionals(rest, frozenset({"--depth", "-j", "--jobs"}))
    if not pos:
        return "origin"
    return None if _NET_URL.match(pos[0]) or url_host(pos[0]) else pos[0]


def _net_git(args: list[str]) -> list[dict]:
    sub, rest = _net_git_sub(args)
    if not sub:
        return []
    if sub == "clone":
        pos, _ = _net_positionals(rest, _GIT_CLONE_VALUE)
        if not pos:
            return []
        return [_net_url_item("clone", "git", pos[0], dest=pos[1] if len(pos) > 1 else None)]
    if sub in ("fetch", "pull"):
        pos, _ = _net_positionals(rest, frozenset({"--depth", "-j", "--jobs"}))
        if pos and (_NET_URL.match(pos[0]) or url_host(pos[0])):
            return [_net_url_item("clone", "git", pos[0])]
        return [_net_item("clone", "git")]
    if sub == "submodule" and rest[:1] == ["update"]:
        return [_net_item("clone", "git")]
    if sub == "remote" and rest[:1] == ["update"]:
        return [_net_item("clone", "git")]
    if sub == "remote" and rest[:1] == ["add"]:
        pos, opts = _net_positionals(rest[1:], _GIT_REMOTE_ADD_VALUE)
        if len(pos) >= 2 and ("-f" in opts or "--fetch" in opts):    # fetches at once
            return [_net_url_item("clone", "git", pos[1])]
        return []
    if sub == "push" and ("--dry-run" in rest or "-n" in rest):    # contacts the remote
        pos, _ = _net_positionals(rest, frozenset({"--repo", "-o", "--push-option"}))
        if pos and (_NET_URL.match(pos[0]) or url_host(pos[0])):
            return [_net_url_item("clone", "git", pos[0])]
        return [_net_item("clone", "git")]
    return []


def _net_gh(args: list[str]) -> list[dict]:
    if args[:2] == ["repo", "clone"] and len(args) > 2:
        repo = args[2]
        url = repo if "://" in repo or url_host(repo) else f"https://github.com/{repo}"
        return [_net_url_item("clone", "gh", url)]
    if args[:2] == ["release", "download"]:
        _, opts = _net_positionals(args[2:], _GH_DOWNLOAD_VALUE)
        dest = opts.get("-D") or opts.get("--dir") or opts.get("-O") or opts.get("--output")
        repo = opts.get("-R") or opts.get("--repo")
        if repo:
            return [_net_url_item("fetch", "gh", f"https://github.com/{repo}", dest=dest)]
        return [_net_item("fetch", "gh", host="github.com", dest=dest)]
    return []


def _net_npm_package(program: str, spec: str, registry: str | None, exec_: bool = False) -> dict | None:
    forge = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
    prefix = spec.split(":", 1)[0]
    if prefix in forge and ":" in spec and "://" not in spec:
        repo = spec.split(":", 1)[1].split("#", 1)[0]
        return _net_item("install", program, ecosystem="npm", host=forge[prefix], package=spec,
                         url=f"https://{forge[prefix]}/{repo}", exec=exec_)
    if "://" in spec:
        url = spec[4:] if spec.startswith("git+") else spec
        return _net_url_item("install", program, url, ecosystem="npm", exec=exec_)
    if spec.startswith((".", "/", "~", "file:")):
        return None
    at = spec.find("@", 1)
    name, version = (spec, None) if at < 0 else (spec[:at], spec[at + 1:] or None)
    alias = None
    if version and version.startswith("npm:"):       # x@npm:evil@1.0.0 installs evil as x
        alias, target = name, version[4:]
        at = target.find("@", 1)
        name, version = (target, None) if at < 0 else (target[:at], target[at + 1:] or None)
    item = _net_registry_item(program, "npm", name, version, registry, exec_)
    item["alias"] = alias
    return item


def _net_npm(prog: str, args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _NPM_VALUE)
    registry = opts.get("--registry")
    lockfile = ((prog == "npm" and pos[:1] == ["ci"])
                or (prog == "pnpm" and pos[:1] == ["install"] and "--frozen-lockfile" in opts)
                or (prog == "yarn" and pos[:1] in ([], ["install"]) and "--immutable" in opts))
    if lockfile:
        return [_net_lockfile(prog, "npm", registry)]
    if prog == "yarn" and not pos:
        pos = ["install"]
    if not pos or pos[0] not in _NPM_INSTALL[prog]:
        return []
    if len(pos) == 1:
        return [_net_registry_item(prog, "npm", None, None, registry)]
    found = (_net_npm_package(prog, s, registry) for s in pos[1:])
    return [i for i in found if i]


def _net_npx(prog: str, args: list[str]) -> list[dict]:
    label = "pnpm dlx" if prog == "pnpm" else prog
    if prog == "pnpm":
        args = args[1:]                      # drop "dlx"
    pos, opts = _net_positionals(args, _NPX_VALUE)
    spec = opts.get("-p") or opts.get("--package") or (pos[0] if pos else None)
    if not spec:
        return []
    item = _net_npm_package(label, spec, opts.get("--registry"), exec_=True)
    return [item] if item else []


def _net_pip_package(program: str, spec: str, registry: str | None, exec_: bool = False) -> dict | None:
    if spec == "@" or spec.startswith((".", "/", "~")):
        return None
    if "://" in spec:
        url = spec.split("+", 1)[1] if spec.startswith("git+") else spec
        return _net_url_item("install", program, url, ecosystem="pypi", exec=exec_)
    if "@" in spec:                          # uvx / pipx style name@version
        name, _, ver = spec.partition("@")
        spec = f"{name}=={ver}"
    m = _PIP_SPEC.match(spec)
    if not m:
        return None
    exact = m.group(3) in ("==", "===") and "*" not in m.group(4)
    version = (m.group(3) if m.group(3) == "===" else "") + m.group(4) if exact else None
    return _net_registry_item(program, "pypi", m.group(1), version, registry, exec_,
                              exact=re.compile(r"^(?:===)?v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$"))


def _net_pip(prog: str, args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _PIP_VALUE)
    if not pos or pos[0] != "install":
        return []
    registry = opts.get("-i") or opts.get("--index-url")
    out: list[dict] = []
    req = opts.get("-r") or opts.get("--requirement")
    if req:
        item = _net_registry_item(prog, "pypi", None, None, registry)
        item["source"] = req
        out.append(item)
    for spec in pos[1:]:
        item = _net_pip_package(prog, spec, registry)
        if item:
            out.append(item)
    return out


def _net_uv(args: list[str]) -> list[dict]:
    if args[:2] == ["pip", "install"]:
        return _net_pip("uv pip", args[1:])
    if args[:1] == ["add"]:
        return _net_pip("uv", ["install"] + args[1:])
    if args[:1] == ["sync"]:
        return [_net_lockfile("uv", "pypi")]
    return []


def _net_uvx(prog: str, args: list[str]) -> list[dict]:
    exec_ = True
    if prog == "pipx":
        if not args or args[0] not in ("run", "install"):
            return []
        exec_, args = args[0] == "run", args[1:]
    pos, opts = _net_positionals(args, _UVX_VALUE)
    spec = opts.get("--from") or (pos[0] if pos else None)
    if not spec:
        return []
    item = _net_pip_package(prog, spec, opts.get("-i") or opts.get("--index-url"), exec_=exec_)
    return [item] if item else []


def _net_brew(args: list[str]) -> list[dict]:
    pos, _ = _net_positionals(args)
    if not pos or pos[0] not in ("install", "reinstall", "tap"):
        return []
    if pos[0] == "tap":                      # clones github.com/<owner>/homebrew-<repo>
        return [_net_item("clone", "brew", host="github.com", host_inferred=True,
                          url=f"https://github.com/{owner}/homebrew-{repo}")
                for owner, _, repo in (t.partition("/") for t in pos[1:]) if repo]
    return [_net_registry_item("brew", "brew", f, None, None) for f in pos[1:]]


def _net_cargo(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _CARGO_VALUE)
    if not pos or pos[0] not in ("install", "add") or opts.get("--path"):
        return []
    prog = f"cargo {pos[0]}"                 # `cargo add` edits a manifest; `cargo install` builds a binary
    if opts.get("--git"):
        return [_net_url_item("install", prog, opts["--git"], ecosystem="crates",
                              package=pos[1] if len(pos) > 1 else None)]
    version = opts.get("--version") or opts.get("--vers")
    out = []
    for spec in pos[1:]:
        name, _, ver = spec.partition("@")
        ver = ver or version
        # install: a bare full version is exact. add: only a leading `=` is.
        # (`cargo install x@1.2.3` is treated like `--version 1.2.3`; not verified against cargo.)
        exact = bool(ver and _NET_FULL_VERSION.match(ver) and (pos[0] == "install" or ver.startswith("=")))
        item = _net_registry_item(prog, "crates", name, ver.lstrip("=") if exact else ver, None)
        item["pinned"] = exact
        out.append(item)
    return out


def _net_go(args: list[str]) -> list[dict]:
    pos, _ = _net_positionals(args, _GO_VALUE)
    if not pos or pos[0] not in ("install", "get"):
        return []
    out = []
    for spec in pos[1:]:
        mod, _, ver = spec.partition("@")
        first = mod.split("/", 1)[0]
        if spec.startswith((".", "/")) or "." not in first:
            continue                         # local package or standard library
        out.append(_net_item("install", "go", ecosystem="go", package=mod, version=ver or None,
                             pinned=bool(ver and _NET_GO_VERSION.match(ver)),
                             host=first.lower()))
    return out


def _oci_name(name: str) -> tuple[str, str | None]:
    """(package, registry host or None) for an image name without tag or digest.

    Lowercased; Docker Hub spelled out (`docker.io/`, `index.docker.io/`,
    `registry-1.docker.io/`) or implied is one package, with `library/` dropped
    (`docker.io/library/nginx`, `library/nginx` and `nginx` are all `nginx`).
    Any other explicit registry stays in the name."""
    name = name.lower()
    first = name.split("/", 1)[0]
    if "/" in name and (first in _OCI_HUB_HOSTS):
        name, first = name.split("/", 1)[1], ""
        hub = True
    elif "/" in name and ("." in first or ":" in first or first == "localhost"):
        return name, first.split(":", 1)[0]
    else:
        hub = False
    if name.startswith("library/"):
        name = name[len("library/"):]
    return name, (NETWORK_REGISTRY["oci"] if hub else None)


def _net_docker(prog: str, args: list[str]) -> list[dict]:
    if not args or args[0] not in ("pull", "run"):
        return []
    pos, _ = _net_positionals(args[1:], _DOCKER_VALUE)
    if not pos:
        return []
    ref = pos[0]
    name, _, digest = ref.partition("@")
    last = name.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    pkg, host = _oci_name(name[:len(name) - len(tag) - 1] if tag else name)
    return [_net_item("install", prog, ecosystem="oci", package=pkg, version=digest or tag,
                      pinned=digest.startswith("sha256:"),
                      host=host or NETWORK_REGISTRY["oci"], host_inferred=not host)]


def _net_extract(tokens: list[str]) -> list[dict]:
    prog, args = _net_base(tokens[0]), tokens[1:]
    if re.fullmatch(r"python(?:\d(?:\.\d+)?)?", prog) and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    if prog == "curl":
        return _net_curl(args)
    if prog == "wget":
        return _net_wget(args)
    if prog == "git":
        return _net_git(args)
    if prog == "gh":
        return _net_gh(args)
    if prog in ("npx", "bunx") or (prog == "pnpm" and args[:1] == ["dlx"]):
        return _net_npx(prog, args)
    if prog in _NPM_INSTALL:
        return _net_npm(prog, args)
    if prog in ("pip", "pip3"):
        return _net_pip(prog, args)
    if prog == "uv":
        return _net_uv(args)
    if prog in ("uvx", "pipx"):
        return _net_uvx(prog, args)
    if prog == "brew":
        return _net_brew(args)
    if prog == "cargo":
        return _net_cargo(args)
    if prog == "go":
        return _net_go(args)
    if prog in ("docker", "podman"):
        return _net_docker(prog, args)
    return []


def network_items_from_command(cmd: str, piped_to_shell: list[str] | None = None,
                               remotes: dict[str, str] | None = None) -> tuple[list[dict], int]:
    """Every download the command shows, and how many segments could not be read.

    `piped_to_shell`, when given, receives the raw text of each curl or wget
    segment whose output a shell runs: remote code execution, seen on the
    dequoted command (`cu''rl … | s''h`) that the audit regexes miss.

    `remotes`, when given, is one session's git remote names and the URLs they
    were added with; it is read to resolve `git pull NAME` and updated by
    `git remote add` and `git clone`, so a remote added in one command and
    pulled in the next keeps its host. Pass a fresh dict per session, never shared."""
    text = (cmd or "")[:MAX_SCAN_TOTAL]
    if not _NET_MAY_DOWNLOAD.search(text):
        return [], 0
    segments, unparsed = _net_segments(text)
    found: list[dict] = []
    for tokens, via_xargs, into_shell, raw in segments:
        got = _net_extract(tokens)
        prog = _net_base(tokens[0])
        if prog == "git" and remotes is not None:
            hostless = len(got) == 1 and got[0]["host"] is None and not got[0]["dynamic"]
            name = _net_git_remote_name(tokens[1:])
            if hostless and name in remotes:
                got = [_net_url_item("clone", "git", remotes[name], host_inferred=True)]
            elif hostless:
                names = _net_git_remote_names(tokens[1:])
                urls = list(dict.fromkeys(remotes.values() if names is None
                                          else [remotes[n] for n in names if n in remotes]))
                if names is not None and any(n not in remotes for n in names):
                    urls = list(dict.fromkeys(remotes.values()))    # a group name: every remote
                if urls and (names is None or names):
                    got = [_net_url_item("clone", "git", u, host_inferred=True) for u in urls]
            _net_git_remotes(tokens[1:], remotes)
        if via_xargs and not got and prog in ("curl", "wget"):
            got = [_net_item("fetch", prog, dynamic=True)]   # the URLs came on stdin
        if into_shell and piped_to_shell is not None and prog in ("curl", "wget") and got:
            piped_to_shell.append(raw)
        found += got
    return found, unparsed


_NET_TOOL_WORDS = ("fetch", "browse", "download", "http")


def network_items_from_tool(name: str, tool_input: dict) -> list[dict]:
    """A non-shell tool call that reaches the network. A search keeps no query:
    the query is the user's words, not a destination."""
    n = (name or "").lower()
    if n in ("bash", "shell_command"):
        return []
    if n in ("websearch", "web_search"):
        return [_net_item("search", name)]
    if n in ("webfetch", "web_fetch") or any(w in n for w in _NET_TOOL_WORDS):
        inp = tool_input if isinstance(tool_input, dict) else {}
        url = next((inp[k] for k in ("url", "uri", "href") if isinstance(inp.get(k), str)), None)
        return [_net_url_item("fetch", name, url) if url else _net_item("fetch", name)]
    return []


AUDIT_CONFIG_FILES = (".actualis-network-trust", ".actualis-suppressions")
_FILE_WRITE_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit", "create",
                               "edit_file", "str_replace_editor", "str_replace_based_edit_tool"})
_WRITE_REDIRECT = re.compile(r">>?(.*)$", re.S)
_FILE_MUTATORS = frozenset({"mv", "cp", "rm", "ln", "truncate", "install"})


# The user-level file (suppression_paths()[0]) is `.../actualis/suppressions`.
_AUDIT_CONFIG_TEXT = re.compile(r"\.actualis-|actualis/suppressions", re.I)
# Programs that only read: a segment naming a config file is not a write when its
# program is one of these. Anything else that names the file trips the wire.
_READ_ONLY_PROGRAMS = frozenset({"cat", "less", "more", "head", "tail", "grep", "rg", "wc", "diff",
                                 "ls", "stat", "file", "sha256sum", "shasum", "md5"})
_READ_ONLY_GIT = frozenset({"diff", "log", "show", "status"})
_ACTUALIS_PROGRAMS = frozenset({"actualis", "actualis.py"})


_AUDIT_CONFIG_NAMES = (".actualis-network-trust", ".actualis-suppressions")
_SHELL_VAR = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
# What the user-level path variables stand for, unless the command assigns them.
_PATH_VARS = {"HOME": "~", "XDG_CONFIG_HOME": "~/.config"}
_GLOB_CHARS = frozenset("*?[")
# Cheap gate, applied to the command with quotes and backslashes removed: the
# name can be split (`.actu''alis-…`), so the raw text is not tested.
_DEQUOTE = str.maketrans("", "", "'\"\\")
_AUDIT_GATE = re.compile(r"actualis|suppress|network-trust|(?:^|[\s/>=])\.[a-z0-9_-]{3,}[*?\[]")


def _glob_match(pattern: str, name: str) -> bool:
    """Could shell glob `pattern` match `name`? Translated by hand (no fnmatch).
    A pattern with fewer than three literal characters (`.*`, `?`) or an
    unreasonable size is not taken for an audit-config name."""
    if len(pattern) > 128 or pattern.count("*") > 6:
        return False
    if not any(c in _GLOB_CHARS for c in pattern):
        return pattern == name
    out, literal, i = [], 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if not out or out[-1] != "[^/]*":
                out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[" and pattern.find("]", i + 2) > 0:
            end = pattern.find("]", i + 2)
            body = pattern[i + 1:end]
            neg = body[:1] in ("!", "^")
            out.append("[" + ("^" if neg else "") + re.sub(r"([\\\]\[^])", r"\\\1", body[1:] if neg else body) + "]")
            i = end
            literal += 1
        else:
            out.append(re.escape(c))
            literal += 1
        i += 1
    if literal < 3:
        return False
    try:
        return re.fullmatch("".join(out), name) is not None
    except re.error:                         # a reversed range such as [e-c]
        return False


def _is_audit_config(path: str, glob: bool = False) -> bool:
    """Is `path` one of the files that decide what is reported?

    Case-insensitive (APFS and NTFS are), with `//`, `/./` and a trailing `/`
    collapsed. With `glob`, a pattern that could match either project name, or
    `suppressions` under `actualis`, counts."""
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p not in ("", ".")]
    if not parts:
        return False
    base, parent = parts[-1], parts[-2] if len(parts) > 1 else ""
    if base in _AUDIT_CONFIG_NAMES or (base == SUPPRESSION_FILENAME and parent == "actualis"):
        return True
    if not (glob and any(c in _GLOB_CHARS for c in path)):
        return False
    return (any(_glob_match(base, n) for n in _AUDIT_CONFIG_NAMES)
            or (_glob_match(base, SUPPRESSION_FILENAME) and _glob_match(parent, "actualis")))


def _runs_actualis_suppress(words: list[str]) -> bool:
    """`actualis --suppress`, `python3 actualis.py --suppress`, `uvx actualis
    --suppressions`, `pipx run actualis --suppress=ID`: the CLI writes the user file.
    Read past the same prefixes and wrappers the extractor skips (env A=1 …)."""
    words = _net_strip_prefixes(words)[0]
    for i, w in enumerate(words[:6]):
        if _net_base(w).lower() in _ACTUALIS_PROGRAMS:
            return any(a.lower().startswith("--suppress") for a in words[i + 1:])
    return False


def _expand_vars(tok: str, env: dict[str, str]) -> str:
    """`$NAME` and `${NAME}` replaced by what this command assigned, or by the
    user-level path variables; anything else is left as written."""
    if "$" not in tok:
        return tok
    def sub(m: "re.Match") -> str:
        name = m.group(1) or m.group(2)
        return env.get(name) or _PATH_VARS.get(name) or m.group(0)
    return _SHELL_VAR.sub(sub, tok)


def writes_audit_config(cmd: str) -> bool:
    """A heuristic: does a segment of `cmd` write one of the audit config files?

    Read on the dequoted text. `NAME=value` assignments earlier in the command
    are substituted into `$NAME`, `cd DIR` is remembered for relative targets,
    and `//`, `/./` are collapsed. A redirect or output-option target that
    names a config file always counts; so does any argument of a program that
    is not a known reader. Reads, redirections to /dev/null, `&N` duplications
    and redirections into other files do not count.
    """
    env: dict[str, str] = {}
    cwd = ""

    def names(path: str) -> bool:
        if _is_audit_config(path, glob=True):
            return True
        return bool(cwd) and not path.startswith(("/", "~")) and _is_audit_config(f"{cwd}/{path}", glob=True)

    # `>|` (clobber) holds a pipe character that _net_split would cut on.
    for segment in _net_split(cmd.replace(">|", ">"))[0]:
        toks = _net_tokens(segment)
        k = 0
        while k < len(toks) and (_NET_ASSIGN.match(toks[k]) or toks[k] in ("export", "declare", "readonly", "local")):
            if "=" in toks[k] and _NET_ASSIGN.match(toks[k]) and len(env) < 256:
                name, _, value = toks[k].partition("=")
                env[name] = _expand_vars(value, env)[:1024]
            k += 1
        toks = [_expand_vars(t, env) for t in toks]
        for i, tok in enumerate(toks):
            m = _WRITE_REDIRECT.search(tok)
            if m:
                target = m.group(1) or (toks[i + 1] if i + 1 < len(toks) else "")
                if names(target):
                    return True
        words = [t for t in toks if t not in ("sudo", "env", "command", "nohup") and "=" not in t.split("/")[0]]
        if not words:
            continue
        prog = words[0].rsplit("/", 1)[-1]
        if prog in ("cd", "pushd") and len(words) > 1:
            target = words[1]
            cwd = target if target.startswith(("/", "~")) or not cwd else f"{cwd}/{target}"
            cwd = cwd[:512]
            continue
        if _runs_actualis_suppress(toks):
            return True
        sub = next((w for w in words[1:] if not w.startswith("-")), "")
        reader = prog in _READ_ONLY_PROGRAMS or (prog == "git" and sub in _READ_ONLY_GIT)
        # Conservative: a segment that names a config file and is not a known
        # reader is a write until shown otherwise (python -c open(...), cp x .,
        # dd of=, rsync, curl -o, git checkout).
        if not reader and (_AUDIT_CONFIG_TEXT.search(" ".join(toks))
                           or any(names(w) for w in words[1:])):
            return True
        # A reader that is told to write: `git diff --output=F`, `sort -o F`.
        # (A redirect target was checked above, for every program.)
        for j, w in enumerate(toks):
            if w in ("-o", "-O", "--output"):
                val = toks[j + 1] if j + 1 < len(toks) else ""
            elif w.startswith("--output="):
                val = w[len("--output="):]
            elif w[:2] in ("-o", "-O") and not w.startswith("--"):
                val = w[2:]
            else:
                continue
            if names(val):
                return True
    return False


def network_approval(mode: str | None) -> str:
    """asked / unasked / unknown, from the mode key the call ran under.

    The same is_ungated_mode() that --share and --card read, so "unasked" here
    cannot disagree with "unsupervised" there. Claude Code writes no record
    for a call a person approved, so outside auto or bypass it is unknown:
    an allowlist rule in settings may have let it through silently.
    """
    if mode == "copilot:prompted":
        return "asked"
    return "unasked" if mode and is_ungated_mode(mode) else "unknown"


NETWORK_TRUST_FILE = ".actualis-network-trust"
_TRUST_ENTRY = re.compile(r"^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)"
                          r"(/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?/?$")


def parse_trust(entries: list[str], source: str = "--network-trust") -> list[tuple[str, str]]:
    """Trust entries as (host, "/path" or ""). A bad entry is an error, never
    a silent skip: a typo in a trust list would otherwise trust nothing, or
    worse, be read as something broader than meant."""
    out: list[tuple[str, str]] = []
    for raw in entries:
        e = raw.strip()
        if not e:
            continue
        host, _, path = e.partition("/")
        m = _TRUST_ENTRY.match(host.lower().removesuffix(".") + ("/" + path.lower() if path else ""))
        if "://" in e or "*" in e or not m:
            raise ValueError(f"{source}: network trust entry {raw.strip()!r} is not a host or "
                             "host/path (no scheme, port or wildcard)")
        out.append((m.group(1), (m.group(2) or "").rstrip("/")))
    return out


def load_network_trust_sources(cli: list[str] | None, cwd: Path | None = None
                               ) -> tuple[list[tuple[str, str]], list[dict]]:
    """Trust entries from --network-trust (comma-separated, repeatable), then
    ./.actualis-network-trust, plus where each came from. The file's hash is
    recorded because the audited agent can write it."""
    trust: list[tuple[str, str]] = []
    sources: list[dict] = []
    flag_entries: list[str] = []
    for value in cli or []:
        flag_entries += [e.strip() for e in value.split(",") if e.strip()]
    if cli:
        trust += parse_trust(flag_entries, "--network-trust")
        sources.append({"source": "flag", "entries": [h + p for h, p in parse_trust(flag_entries)]})
    path = (cwd or Path.cwd()) / NETWORK_TRUST_FILE
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return trust, sources
    file_trust: list[tuple[str, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        file_trust += parse_trust([line.split("#", 1)[0]], f"{NETWORK_TRUST_FILE} line {n}")
    trust += file_trust
    sources.append({"source": "file", "path": str(path.resolve()),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "entries": [h + p for h, p in file_trust]})
    return trust, sources


def load_network_trust(cli: list[str] | None, cwd: Path | None = None) -> list[tuple[str, str]]:
    return load_network_trust_sources(cli, cwd)[0]


def _net_item_path(item: dict) -> str | None:
    """Lowercased path, "" when there is none, None when it cannot be known
    (a dot segment or an encoded dot could walk out of a trusted prefix)."""
    if item.get("url"):
        path = url_path(item["url"])
    else:
        pkg = item.get("package") or ""
        path = "/" + pkg.split("/", 1)[1] if item.get("ecosystem") == "go" and "/" in pkg else ""
    if any(seg in (".", "..") or "%2e" in seg.lower() for seg in path.split("/")):
        return None
    return path.lower()


def network_trusted(item: dict, trust: list[tuple[str, str]]) -> bool:
    """Host suffix on a label boundary; path prefix on a segment boundary.
    An item with no known host is never trusted."""
    host = (item.get("host") or "").removesuffix(".")
    if not host:
        return False
    path = _net_item_path(item)
    for h, p in trust:
        if host != h and not host.endswith("." + h):
            continue
        if not p:
            return True
        if path is not None and (path == p or path.startswith(p + "/")):
            return True
    return False


def apply_network_policy(fleet: "Fleet", trust: list[tuple[str, str]], strict: bool,
                         sources: list[dict] | None = None) -> None:
    """Mark trusted items, and in strict mode turn each untrusted, unapproved,
    not-failed group (program, host) into one medium shell-audit flag. Run once,
    after the scan."""
    fleet.network_trust = [h + p for h, p in trust]
    fleet.network_strict = strict
    fleet.network_trust_sources = sources or []
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in fleet.network_items:
        item["trusted"] = network_trusted(item, trust)
        # A remote name (`git pull origin`) has no host the transcript can show, and
        # is not built from a variable: it stays in the inventory, never a finding.
        hostless = item["host"] is None and not item["dynamic"]
        if strict and not hostless and not item["trusted"] and item["approval"] != "asked" \
           and item["failed"] is not True:
            groups.setdefault((item["program"], item["host"] or "?"), []).append(item)
    for (program, host), group in sorted(groups.items()):
        fid = flag_id("med", ["network-unasked"], f"{program}@{host}")
        suppressed = fid in fleet.suppressions
        if suppressed:
            fleet.suppressed_flags += 1
        latest = max(group, key=lambda i: (i["ts"] or "", i["project"]))
        where = "a URL built from a variable" if host == "?" else host
        fleet.flags.append({
            "id": fid, "severity": "med", "categories": ["network-unasked"],
            "program": program, "project": latest["project"], "when": latest["ts"],
            "evidence": f"{len(group)} unasked download(s) via {program} from {where}"[:240],
            "had_secret": False, "suppressed": suppressed,
            "suppressed_reason": fleet.suppressions.get(fid, ""),
        })


NETWORK_ITEM_KEYS = ("kind", "program", "host", "host_inferred", "url", "dest", "source",
                     "ecosystem", "package", "version", "pinned", "exec", "dynamic", "alias",
                     "failed", "approval", "trusted", "agent", "project", "session", "ts")


def network_json(fleet: "Fleet", raw: bool = False) -> dict:
    """The `network` key of --json. Every list has a total order, so the same
    input gives the same bytes."""
    items = fleet.network_items
    approval = Counter(i["approval"] for i in items)
    kinds = Counter(i["kind"] for i in items)

    hosts: dict[str, dict] = {}
    for i in items:
        if not i["host"]:
            continue
        h = hosts.setdefault(i["host"], {"host": i["host"], "count": 0, "unasked": 0,
                                         "first_seen": None, "trusted": False})
        h["count"] += 1
        h["unasked"] += 1 if i["approval"] == "unasked" else 0
        if i["ts"] and (h["first_seen"] is None or i["ts"] < h["first_seen"]):
            h["first_seen"] = i["ts"]
        h["trusted"] = h["trusted"] or i["trusted"]

    packages: dict[tuple[str, str], dict] = {}
    for i in items:
        if not i["package"]:
            continue
        p = packages.setdefault((i["ecosystem"] or "", i["package"]), {
            "ecosystem": i["ecosystem"], "name": i["package"], "versions": set(),
            "pinned": True, "exec": False, "count": 0})
        p["count"] += 1
        if i["version"]:
            p["versions"].add(i["version"])
        p["pinned"] = p["pinned"] and i["pinned"]
        p["exec"] = p["exec"] or i["exec"]

    def public(i: dict) -> dict:
        out = {k: i[k] for k in NETWORK_ITEM_KEYS}
        if not raw:
            for k in ("url", "dest", "source"):
                if out[k]:
                    out[k] = redact(out[k])
        return out

    # Every field that can differ is in the key, so no two distinct items tie.
    order = sorted(items, key=lambda i: tuple(str(i[k] or "") for k in (
        "ts", "agent", "project", "program", "host", "url", "package", "version", "kind",
        "dest", "source", "session", "approval")), reverse=True)
    return {
        "totals": {"items": len(items), "asked": approval["asked"], "unasked": approval["unasked"],
                   "unknown": approval["unknown"],
                   "failed": sum(1 for i in items if i["failed"] is True),
                   "unparsed_segments": fleet.network_unparsed},
        "by_kind": {k: kinds.get(k, 0) for k in ("install", "clone", "fetch", "search")},
        "hosts": sorted(hosts.values(), key=lambda h: (-h["count"], h["host"])),
        "packages": [{**p, "versions": sorted(p["versions"])}
                     for _, p in sorted(packages.items(), key=lambda kv: (-kv[1]["count"], kv[0]))],
        "items": [public(i) for i in order[:NETWORK_ITEMS_CAP]],
        "items_truncated": len(items) > NETWORK_ITEMS_CAP,
        "strict": fleet.network_strict,
        "trust": list(fleet.network_trust),
        "trust_sources": [{"source": t["source"], "path": t.get("path"),
                           "sha256": t.get("sha256"), "entries": list(t["entries"])}
                          for t in fleet.network_trust_sources],
    }


# --------------------------------------------------------------------------
# Suppressions
#
# A detector that cries wolf gets ignored, so there has to be a way to tell it
# it is wrong. Two rules shape this:
#
# A suppression NEVER removes a finding from the count. If suppressing something
# deleted it, the report would start lying by omission and a reader could not
# tell a clean scan from a heavily suppressed one. Suppressed findings stay
# counted, stay in --json, and the total is stated.
#
# The format is a plain text file rather than JSON or TOML: it has to be
# greppable, diffable, reviewable in a pull request, and editable by hand six
# months later by someone who did not write it. Every entry carries a reason
# for the same reason.
# --------------------------------------------------------------------------

_FINGERPRINT = re.compile(r"[0-9a-f]{8}")
_ADDED_MARKER = re.compile(r"\s*\(added \d{4}-\d{2}-\d{2}\)\s*$")

SUPPRESSION_FILENAME = "suppressions"
PROJECT_SUPPRESSIONS = ".actualis-suppressions"


def suppression_paths() -> list[Path]:
    """Where suppressions are read from, least specific first.

    A project-local file can be committed so a team shares one list; the user
    file covers everything on this machine. Both are read; neither is required.
    """
    out = []
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    out.append(Path(base).expanduser() / "actualis" / SUPPRESSION_FILENAME)
    out.append(Path.cwd() / PROJECT_SUPPRESSIONS)
    return out


def load_suppressions() -> dict[str, str]:
    """fingerprint -> reason. Malformed lines are skipped, never fatal."""
    out: dict[str, str] = {}
    for path in suppression_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fp, _, reason = line.partition(" ")
            fp = clean(fp)[:64]
            if not fp:
                continue
            # `(added YYYY-MM-DD)` is written by --suppress, not typed by a
            # person. Strip it so the reason a caller sees is only the reason.
            reason = _ADDED_MARKER.sub("", clean(reason)).strip()
            out[fp] = reason or "(no reason given)"
    return out


def add_suppression(fingerprint: str, reason: str) -> Path:
    """Append one entry to the user's suppression file, creating it if needed."""
    fingerprint = clean(fingerprint).strip()[:64]
    if not fingerprint:
        raise ValueError("a fingerprint is required")
    # Every id this tool emits is sha256[:8]. Accepting anything else writes a
    # suppression that can never match, and the user walks away believing they
    # silenced something. Caught in testing when a shell passed seven ids as one.
    if fingerprint.lower() == AUDIT_CONFIG_ID:
        raise AuditConfigId(
            f"{fingerprint} is the audit-config finding. It cannot be suppressed: the files it "
            "names decide what is reported, so a suppression of it would be the same edit it "
            "reports. Review the write instead.")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise ValueError(
            f"{fingerprint!r} is not an id from this tool. Ids are eight hex "
            f"characters, shown beside each finding. One per --suppress.")
    reason = clean(reason).strip()[:200] or "(no reason given)"
    path = suppression_paths()[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(
            "# actualis suppressions\n"
            "#\n"
            "# One finding per line: <fingerprint> <why it is not a real finding>\n"
            "# Suppressed findings are still counted and still appear in --json.\n"
            "# They are held back from the actionable list, not hidden.\n"
            "#\n"
            "# Remove a line to un-suppress. Committing a copy as "
            f"{PROJECT_SUPPRESSIONS} shares it with a team.\n\n",
            encoding="utf-8")
    today = datetime.now(timezone.utc).date().isoformat()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"{fingerprint}  {reason}  (added {today})\n")
    return path


_URL_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def _percent_encode(text: str) -> str:
    """Percent-encode for a query string.

    Hand-rolled rather than urllib.parse.quote on purpose. urllib is the
    networking package, and the no-network guarantee is worth more as an
    absolute -- "this file imports nothing that can open a socket" -- than as a
    rule with an exception for the one function that happens to be pure string
    handling. Both the CI import allowlist and a test enforce that absolute.
    """
    out = []
    for byte in text.encode("utf-8"):
        ch = chr(byte)
        out.append(ch if ch in _URL_SAFE else f"%{byte:02X}")
    return "".join(out)


def report_url(kind: str, detail: str) -> str:
    """A pre-filled issue URL. Printed, never opened, never requested.

    The tool makes no network calls, and that includes not quietly phoning home
    with a report. The user decides whether to open it.
    """
    title = _percent_encode(f"False positive: {kind}")
    body = _percent_encode(
        f"**What was flagged:** {kind}\n\n"
        f"**Why it is not a credential:**\n\n_(please describe)_\n\n"
        f"**Detail actualis reported:**\n\n```\n{detail}\n```\n\n"
        f"_No command text or secret value is included above; fill in only what "
        f"you are comfortable sharing._\n")
    return (f"https://github.com/digital-foundry/actualis/issues/new"
            f"?labels=false-positive&title={title}&body={body}")


# --------------------------------------------------------------------------
# Transcript scanning
# --------------------------------------------------------------------------

def no_transcripts_message() -> str:
    """Why nothing was found, and what to do about it.

    The free tool is the distribution strategy, so its worst moment should not
    be its first. `no transcripts found` then exit told a new user nothing about
    what was looked for -- and it is the exact message someone sees if they
    install before running an agent, or if their config lives somewhere the
    defaults do not cover.
    """
    lines = ["actualis: no agent transcripts found.", "", "Looked in:"]
    checked = [
        (Path(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")).expanduser() / "projects",
         "Claude Code", "CLAUDE_CONFIG_DIR"),
        (Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser() / "sessions",
         "Codex", "CODEX_HOME"),
        (Path(os.environ.get("COPILOT_HOME", "~/.copilot")).expanduser() / "session-state",
         "Copilot CLI", "COPILOT_HOME"),
    ]
    for path, label, env in checked:
        parent_exists = path.parent.is_dir()
        if path.is_dir():
            state = "exists but holds no sessions yet"
        elif parent_exists:
            state = f"{label} is installed but has not been run"
        else:
            state = f"no sign of {label} on this machine"
        lines.append(f"  {path}")
        lines.append(f"      {state}")
        if os.environ.get(env):
            lines.append(f"      (from ${env})")
    lines += [
        "",
        "If your config lives elsewhere, point at it:",
        "  CLAUDE_CONFIG_DIR=/path/to/config actualis",
        "  CODEX_HOME=/path/to/codex actualis",
        "  COPILOT_HOME=/path/to/copilot actualis",
        "  actualis --root /path/to/a/transcript/directory",
        "",
        "Nothing is wrong with the install. There is simply nothing to read yet:",
        "this tool only reports on sessions an agent has already written.",
    ]
    return "\n".join(lines)


def dead_end_message(fleet: "Fleet", args) -> str:
    """Why this run found nothing, and what to change.

    `no matching activity found` covered three unrelated situations: nothing
    installed, sessions present but filtered out, and a --root pointed at the
    wrong directory. Only the last two are the user's to fix, and the fix
    differs. This runs only when the report is empty, so it can afford to go
    back to disk and look.
    """
    roots = list(fleet.roots)
    if not roots and not args.root:
        return no_transcripts_message()

    if args.root:
        roots = [Path(args.root).expanduser()]

    # What is actually on disk, ignoring every filter this run applied.
    files, newest = 0, None
    for root in roots:
        for f in root.rglob("*.jsonl"):
            files += 1
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest:
                newest = mtime

    where = ", ".join(str(r) for r in roots)
    if files == 0:
        return (f"actualis: no session files under {where}.\n"
                "  The directory exists but holds no .jsonl transcripts. If your agent\n"
                "  stores sessions elsewhere, pass that directory with --root.")

    # Files exist, so a filter removed all of them. Name the one that did it.
    plural = "" if files == 1 else "s"
    lines = [f"actualis: {files:,} session file{plural} found, "
             "none matched this run's filters."]
    if args.days is not None:
        lines.append(f"  --days {args.days} keeps only sessions since "
                     f"{window_start(args.days, datetime.now(timezone.utc)):%Y-%m-%d}.")
        if newest is not None:
            last = datetime.fromtimestamp(newest, timezone.utc)
            age = (datetime.now(timezone.utc) - last).days
            lines.append(f"  The newest session is {last:%Y-%m-%d} ({age} days ago). "
                         f"Try --days {max(age + 1, 1)}.")
    if args.project:
        lines.append(f"  --project {args.project!r} matched no project name. "
                     "Drop it to see every project.")
    if args.agent != "all":
        lines.append(f"  --agent {args.agent} reads only that vendor. "
                     "Drop it to read every agent.")
    if args.days is None and not args.project and args.agent == "all":
        lines.append("  No filters were applied, so these files carry no usage records --\n"
                     "  they may be from a different tool, or truncated.")
    return "\n".join(lines)


def transcript_roots() -> list[Path]:
    """Every Claude Code transcript directory on this machine.

    CLAUDE_CONFIG_DIR relocates the config dir, but a machine can easily have
    both (a relocated one plus the default). Reporting on only one of them and
    calling the result a "fleet" is exactly the failure this tool exists to fix,
    so scan all of them and say which.
    """
    seen: list[Path] = []
    candidates = [Path.home() / ".claude"]
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    if env:
        candidates += [Path(part).expanduser() for part in env.split(os.pathsep) if part]
    for base in candidates:
        proj = base / "projects"
        try:
            if proj.is_dir() and proj.resolve() not in {p.resolve() for p in seen}:
                seen.append(proj)
        except OSError:
            continue
    return seen


def pretty_project(slug: str) -> str:
    """Turn a path-slug directory name into something readable."""
    s = slug.lstrip("-")
    home = str(Path.home()).lstrip("/").replace("/", "-")
    if s.startswith(home):
        s = s[len(home):].lstrip("-")
    for prefix in ("Documents-", "Projects-", "code-", "src-", "github-", "dev-"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return clean(s or slug)


def parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def codex_roots() -> list[Path]:
    """Codex writes append-only session rollouts under $CODEX_HOME/sessions."""
    base = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    sess = base / "sessions"
    return [sess] if sess.is_dir() else []


def codex_session_cost(usage: dict, model: str) -> float:
    """Cost of one Codex session from its final cumulative usage.

    OpenAI reports cached_input_tokens as a SUBSET of input_tokens, and
    reasoning_output_tokens as a subset of output_tokens. Adding either to its
    parent double-counts.
    """
    r = rate_for(model)
    in_rate, out_rate, provider = r.input, r.output, r.provider
    if provider != "openai":
        # This came out of a Codex rollout, so it is OpenAI whatever the model
        # string looked like. Without this an unrecognised Codex model was
        # billed at Anthropic rates with no cache discount at all.
        ceiling = _provider_ceiling("openai") or DEFAULT_RATES
        in_rate, out_rate, provider = ceiling.input, ceiling.output, "openai"
    total_in = usage.get("input_tokens", 0) or 0
    cached = usage.get("cached_input_tokens", 0) or 0
    out = usage.get("output_tokens", 0) or 0
    if provider == "openai":
        fresh = max(total_in - cached, 0)
        return (fresh / 1e6 * in_rate
                + cached / 1e6 * in_rate * OPENAI_CACHED_MULT
                + out / 1e6 * out_rate)
    return total_in / 1e6 * in_rate + out / 1e6 * out_rate


def copilot_roots() -> list[Path]:
    """Copilot CLI writes one directory per session under $COPILOT_HOME/session-state."""
    base = Path(os.environ.get("COPILOT_HOME", Path.home() / ".copilot")).expanduser()
    sess = base / "session-state"
    return [sess] if sess.is_dir() else []


def _copilot_context(ctx: dict, cwd: str, branch: str) -> tuple[str, str]:
    """Take cwd and branch from a Copilot context, only where they are non-empty strings."""
    for key in ("gitRoot", "cwd"):
        v = ctx.get(key)
        if isinstance(v, str) and v:
            cwd = v
            break
    b = ctx.get("branch")
    if isinstance(b, str) and b:
        branch = b
    return cwd, branch


# permission.completed result kinds that let the command run. Every other kind
# is a refusal; a person declining arrives as denied-interactively-by-user.
COPILOT_APPROVED = frozenset({"approved", "approved-for-location"})

# Refusal kinds that mean a person said no, rather than a policy. Copilot's
# value was captured from a real denial in a scratch session.
HUMAN_REFUSALS = frozenset({"user-rejected", "copilot:denied-interactively-by-user"})


def copilot_model(raw: str) -> str:
    """Copilot writes Anthropic ids with dots (`claude-haiku-4.5`); the price
    table uses dashes (`claude-haiku-4-5`). Without this, every Claude model run
    through Copilot was priced as a family guess instead of its published rate."""
    m = clean(raw)[:48] or "unknown"
    if m.startswith("claude-"):
        m = re.sub(r"(?<=\d)\.(?=\d)", "-", m)
    return m


def copilot_session_cost(usage: dict, model: str) -> float:
    """Cost of one model's share of one Copilot session.

    Measured on 17 local sessions: inputTokens INCLUDES cacheReadTokens and
    cacheWriteTokens, for Anthropic and OpenAI models alike, and
    reasoningTokens is a subset of outputTokens. Adding either back
    double-counts. Cache writes carry no TTL, so they are priced at the same
    assumed rate as a Claude record with no TTL split.
    """
    r = rate_for(model)
    total_in = usage.get("inputTokens", 0) or 0
    rd = usage.get("cacheReadTokens", 0) or 0
    wr = usage.get("cacheWriteTokens", 0) or 0
    out = usage.get("outputTokens", 0) or 0
    fresh = max(total_in - rd - wr, 0)
    read_mult = OPENAI_CACHED_MULT if r.provider == "openai" else CACHE_READ_MULT
    return (fresh / 1e6 * r.input
            + rd / 1e6 * r.input * read_mult
            + wr / 1e6 * r.input * CACHE_WRITE_ASSUMED_MULT
            + out / 1e6 * r.output)


class Fleet:
    def __init__(self) -> None:
        self.messages = 0
        self.cost_by_agent: dict[str, float] = defaultdict(float)
        self.units_by_agent: Counter = Counter()
        self.cost_by_model: dict[str, float] = defaultdict(float)
        self.msgs_by_model: Counter = Counter()
        self.cost_by_project: dict[str, float] = defaultdict(float)
        self.cost_by_day: dict[str, float] = defaultdict(float)
        self.tokens_by_project: dict[str, Counter] = defaultdict(Counter)
        # Input-side cost as billed, and what the same context would have cost
        # with no caching at all. Accumulated per message because the rate
        # varies by model and cannot be recovered from totals afterwards.
        self.cache_actual: dict[str, float] = defaultdict(float)
        self.cache_uncached: dict[str, float] = defaultdict(float)
        self.msgs_by_project: Counter = Counter()
        self.cost_by_ticket: dict[str, float] = defaultdict(float)
        self.msgs_by_ticket: Counter = Counter()
        self.branches_by_ticket: dict[str, set] = defaultdict(set)
        self.dates_by_ticket: dict[str, list] = defaultdict(list)
        self.projects_by_ticket: dict[str, set] = defaultdict(set)
        self.cost_by_branch: dict[str, float] = defaultdict(float)
        # Subagents. Kept OUT of total_cost on purpose: only a lower bound on
        # their spend is recoverable, and folding an estimate into a validated
        # number would quietly corrupt it.
        self.sub_calls = 0
        self.sub_by_model: Counter = Counter()
        self.sub_cost_floor = 0.0
        self.sub_tools: Counter = Counter()
        self.sub_lines: Counter = Counter()
        self.sub_ms = 0
        self.sub_status: Counter = Counter()
        self.denials_by_project: Counter = Counter()
        self.bash_by_project: Counter = Counter()
        self.effort_mix: Counter = Counter()
        self.tokens = Counter()  # input/output/cache_w_1h/cache_w_5m/cache_read
        self.tools: Counter = Counter()
        self.bash_total = 0
        self.bash_first_token: Counter = Counter()
        # Shell commands per UTC date, and how many ran in a mode that does not
        # stop for approval. bash_moded_by_day is the denominator: a command
        # whose mode was never recorded is neither supervised nor unsupervised,
        # and guessing either way would bias the card's headline number.
        self.bash_by_day: Counter = Counter()
        self.bash_moded_by_day: Counter = Counter()
        self.unsupervised_by_day: Counter = Counter()
        self.bash_categories: Counter = Counter()
        self.agents_seen: set[str] = set()
        # Copilot bills in premium requests as well as tokens. Fractional
        # (0.33 per request on some models), and never converted to dollars:
        # the conversion depends on a plan this tool cannot see.
        self.premium_requests_by_agent: dict[str, float] = defaultdict(float)
        # Copilot sessions with activity but no session.shutdown record. Their
        # usage is unknowable, so they are counted rather than estimated.
        self.copilot_unpriced = 0
        # The permission mode in force, carried across records within one file.
        self._mode: str | None = None
        self.flags: list[dict] = []
        # Network inventory. `network` keeps refused calls (flagged
        # `_refused`) so a later refusal record can find them by call id;
        # everything downstream reads `network_items`, which drops them.
        self.network: list[dict] = []
        self.network_unparsed = 0
        self.network_trust: list[str] = []
        self.network_trust_sources: list[dict] = []
        self.network_strict = False
        self._net_by_call: dict[str, list[int]] = {}
        self._git_remotes: dict[tuple[str, str], dict[str, str]] = {}   # per (agent, session)
        # Location-based secret id -> sha256 of every value seen under it, for
        # this run only. Never written to JSON, a report or a log.
        self._location_values: dict[str, set[str]] = {}
        # Set by _add_network for the command add_tool is reading: the raw
        # text of a curl or wget segment whose output a shell runs, or "".
        self._net_remote_exec = ""
        self.flag_counts: Counter = Counter()
        self.permission_modes: Counter = Counter()
        self.denials: Counter = Counter()
        # Refusals joined to the command they actually blocked. A refused
        # command is never sent to a provider, so this exists only here: no
        # API-layer view of the same session has any record of it.
        self.refusals = 0
        self.refusals_joined = 0
        self.refusal_tool: dict[str, Counter] = defaultdict(Counter)
        self.refusal_program: dict[str, Counter] = defaultdict(Counter)
        self.refusal_project: dict[str, Counter] = defaultdict(Counter)
        self.refusal_week: dict[str, Counter] = defaultdict(Counter)
        # Commands the audit could not read, as opposed to commands it read and
        # found nothing in. Counted, never flagged.
        self.unreadable = 0
        self.unreadable_shapes: Counter = Counter()
        # Commands past the 32 KB scan cap: counted once, flagged, and the checks
        # that must not be evaded by padding run over the rest in windows.
        self.oversized_commands = 0
        # A shell-audit finding can be wrong too. Secrets got suppression in
        # 0.1.3 and flags did not, which is arbitrary from a user's side: an
        # `rm -rf build` flagged every run forever leaves only the options of
        # ignoring the section or ignoring the tool.
        self.suppressed_flags = 0
        self.secret_exposures = 0
        self.secret_projects: Counter = Counter()
        # (priority, type, fingerprint) -> {uses, first, last, projects}
        self.secrets: dict[str, dict] = {}   # sha256[:8] -> record
        # Loaded once per scan. A suppressed finding is held back from the
        # actionable list, never removed from the count -- see the Suppressions
        # section for why that distinction is the whole design.
        self.suppressions: dict[str, str] = load_suppressions()
        self.unknown_models: Counter = Counter()
        # Models priced from a third party because the vendor publishes no rate
        # for that id. Counted separately from unknown models: the number is
        # probably right, but nobody authoritative has said so.
        self.aggregator_models: Counter = Counter()
        # Spend split by how the rate was arrived at. A total that mixes
        # published prices with inferences is only as trustworthy as its worst
        # component, and the reader cannot know that unless it is shown.
        self.cost_by_tier: dict[str, float] = defaultdict(float)
        self.models_by_tier: dict[str, set] = defaultdict(set)
        # Cost attributable to models with no published rate. Reported as a
        # share of the headline so a reader can bound how wrong it might be.
        self.cost_unknown = 0.0
        # Claude Code re-emits the same assistant record while a response
        # streams: identical message id, identical usage, a fresh record uuid.
        # Billing each occurrence overstated real spend by 2.13x on a live
        # corpus, where 50.9% of usage records were repeats. The Codex path has
        # always guarded its own version of this; this is the Claude equivalent.
        self.seen_message_ids: set[str] = set()
        self.duplicate_usage_records = 0
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.roots: list[Path] = []
        self.files_scanned = 0
        self.bytes_scanned = 0

    # -- ingest ------------------------------------------------------------

    def add_usage(self, project: str, model: str, usage: dict, ts: datetime | None,
                  branch: str | None = None) -> None:
        # Sanitise at the boundary of the data structure rather than at one call
        # site, so no future caller can bypass it.
        project = clean(project)[:120] or "unknown"
        model = clean(model)[:48] or "unknown"
        branch = (clean(branch)[:120] or None) if branch else None
        cc = usage.get("cache_creation") or {}
        w1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
        w5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        assumed = 0
        if not w1h and not w5m:
            # Older transcript with no TTL split. Priced at the 1h rate and
            # counted separately so the assumption is visible in the report.
            assumed = usage.get("cache_creation_input_tokens", 0) or 0

        inp = usage.get("input_tokens", 0) or 0
        out = usage.get("output_tokens", 0) or 0
        rd = usage.get("cache_read_input_tokens", 0) or 0

        in_rate, out_rate, _provider, known, src = rates_for(model, ts)
        if not known:
            self.unknown_models[model] += 1
        elif src == AGGREGATOR:
            self.aggregator_models[model] += 1

        cost = (
            inp / 1e6 * in_rate
            + out / 1e6 * out_rate
            + w1h / 1e6 * in_rate * CACHE_WRITE_1H_MULT
            + w5m / 1e6 * in_rate * CACHE_WRITE_5M_MULT
            + assumed / 1e6 * in_rate * CACHE_WRITE_ASSUMED_MULT
            + rd / 1e6 * in_rate * CACHE_READ_MULT
        )

        if not known:
            self.cost_unknown += cost
        self.cost_by_tier[src] += cost
        self.models_by_tier[src].add(model)

        self.messages += 1
        self.agents_seen.add("claude-code")
        self.cost_by_agent["claude-code"] += cost
        self.units_by_agent["claude-code"] += 1
        self.msgs_by_model[model] += 1
        self.cost_by_model[model] += cost
        self.cost_by_project[project] += cost
        self.tokens["input"] += inp
        self.tokens["output"] += out
        self.tokens["cache_w_1h"] += w1h
        self.tokens["cache_w_5m"] += w5m
        self.tokens["cache_w_assumed"] += assumed
        self.tokens["cache_read"] += rd
        pt = self.tokens_by_project[project]
        pt["input"] += inp; pt["output"] += out
        pt["cache_w"] += w1h + w5m + assumed; pt["cache_read"] += rd
        self.msgs_by_project[project] += 1

        self.cache_actual[project] += (
            inp / 1e6 * in_rate
            + w1h / 1e6 * in_rate * CACHE_WRITE_1H_MULT
            + w5m / 1e6 * in_rate * CACHE_WRITE_5M_MULT
            + assumed / 1e6 * in_rate * CACHE_WRITE_ASSUMED_MULT
            + rd / 1e6 * in_rate * CACHE_READ_MULT)
        self.cache_uncached[project] += (inp + w1h + w5m + assumed + rd) / 1e6 * in_rate

        bucket = branch_bucket(branch)
        self.cost_by_branch[bucket] += cost
        ticket = extract_ticket(branch)
        if ticket:
            self.cost_by_ticket[ticket] += cost
            self.msgs_by_ticket[ticket] += 1
            self.branches_by_ticket[ticket].add(branch)
            self.projects_by_ticket[ticket].add(project)
            if ts:
                self.dates_by_ticket[ticket].append(ts.date().isoformat())

        if ts:
            self.cost_by_day[ts.date().isoformat()] += cost
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

    def add_codex_session(self, project: str, model: str, usage: dict,
                          ts: datetime | None) -> None:
        """Record one Codex session from its FINAL cumulative usage.

        `total_token_usage` is cumulative across the session and `token_count`
        events repeat, so summing either over-counts badly. The last total is
        the session total, exactly.
        """
        cost = codex_session_cost(usage, model)
        _, _, _, known, tier = rates_for(model, None)
        self.cost_by_tier[tier] += cost
        self.models_by_tier[tier].add(model)
        if not known:
            self.unknown_models[model] += 1
            self.cost_unknown += cost
        elif tier == AGGREGATOR:
            self.aggregator_models[model] += 1

        self.messages += 1
        self.agents_seen.add("codex")
        self.cost_by_agent["codex"] += cost
        self.units_by_agent["codex"] += 1
        self.msgs_by_model[model] += 1
        self.cost_by_model[model] += cost
        self.cost_by_project[project] += cost
        cached = usage.get("cached_input_tokens", 0) or 0
        self.tokens["input"] += max((usage.get("input_tokens", 0) or 0) - cached, 0)
        self.tokens["cache_read"] += cached
        self.tokens["output"] += usage.get("output_tokens", 0) or 0
        if ts:
            self.cost_by_day[ts.date().isoformat()] += cost
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

    def add_copilot_session(self, project: str, model: str, usage: dict,
                            ts: datetime | None, branch: str | None = None) -> None:
        """One model's usage in one Copilot session, from session.shutdown.

        modelMetrics is the session's final per-model total, written once, so
        each (session, model) pair is recorded exactly once -- the same guard
        add_codex_session applies to Codex's cumulative totals.
        """
        project = clean(project)[:120] or "unknown"
        model = copilot_model(model)
        branch = (clean(branch)[:120] or None) if branch else None
        cost = copilot_session_cost(usage, model)
        _, _, _, known, tier = rates_for(model, None)
        self.cost_by_tier[tier] += cost
        self.models_by_tier[tier].add(model)
        if not known:
            self.unknown_models[model] += 1
            self.cost_unknown += cost
        elif tier == AGGREGATOR:
            self.aggregator_models[model] += 1

        self.messages += 1
        self.agents_seen.add("copilot")
        self.cost_by_agent["copilot"] += cost
        self.msgs_by_model[model] += 1
        self.cost_by_model[model] += cost
        self.cost_by_project[project] += cost
        rd = usage.get("cacheReadTokens", 0) or 0
        wr = usage.get("cacheWriteTokens", 0) or 0
        self.tokens["input"] += max((usage.get("inputTokens", 0) or 0) - rd - wr, 0)
        self.tokens["cache_read"] += rd
        self.tokens["cache_w_assumed"] += wr
        self.tokens["output"] += usage.get("outputTokens", 0) or 0

        self.cost_by_branch[branch_bucket(branch)] += cost
        ticket = extract_ticket(branch)
        if ticket:
            self.cost_by_ticket[ticket] += cost
            self.msgs_by_ticket[ticket] += 1
            self.branches_by_ticket[ticket].add(branch)
            self.projects_by_ticket[ticket].add(project)
            if ts:
                self.dates_by_ticket[ticket].append(ts.date().isoformat())
        if ts:
            self.cost_by_day[ts.date().isoformat()] += cost
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

    def scan_codex(self, roots: list[Path], since: datetime | None,
                   project_filter: str | None) -> None:
        for root in roots:
            for f in sorted(root.rglob("rollout-*.jsonl")):
                self._scan_codex_file(f, since, project_filter)

    def _scan_codex_file(self, path: Path, since: datetime | None,
                         project_filter: str | None) -> None:
        try:
            st = path.stat()
        except OSError:
            return
        if since is not None and st.st_mtime < (since.timestamp() - 3600):
            return
        self.bytes_scanned += st.st_size
        self.files_scanned += 1

        cwd = model = session = None
        policy: str | None = None
        best: dict | None = None
        best_total = -1
        last_ts: datetime | None = None
        pending: list[tuple[str, datetime | None, str | None]] = []

        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    payload = rec.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    kind = rec.get("type")

                    if kind == "session_meta":
                        cwd = payload.get("cwd") or cwd
                        session = payload.get("id") or session
                    elif kind == "turn_context":
                        cwd = payload.get("cwd") or cwd
                        # Harness-written, but a tampered file reaches the terminal
                        # through these as surely as through a command: clean them.
                        model = clean(payload.get("model"))[:48] or model
                        pol = clean(payload.get("approval_policy"))[:48]
                        if pol:
                            policy = f"codex:{pol}"
                            self.permission_modes[policy] += 1
                        sb = payload.get("sandbox_policy")
                        if isinstance(sb, dict) and sb.get("type"):
                            self.permission_modes[f"sandbox:{clean(str(sb['type']))[:48]}"] += 1
                    elif kind == "event_msg" and payload.get("type") == "token_count":
                        info = payload.get("info") or {}
                        tot = info.get("total_token_usage")
                        if isinstance(tot, dict):
                            n = tot.get("total_tokens", 0) or 0
                            if n > best_total:      # cumulative: keep the maximum
                                best_total, best = n, tot
                            if ts:
                                last_ts = ts
                    elif payload.get("type") == "function_call" and \
                            payload.get("name") == "shell_command":
                        try:
                            args = json.loads(payload.get("arguments") or "{}")
                        except (json.JSONDecodeError, ValueError):
                            continue
                        cmd = args.get("command")
                        if cmd:
                            pending.append((cmd, ts, policy))
                            cwd = args.get("workdir") or cwd
        except OSError:
            return

        if since and last_ts and last_ts < since:
            return
        project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "unknown"
        if project_filter and project_filter.lower() not in project.lower():
            return

        for cmd, ts, mode in pending:
            # Normalise Codex's shell_command onto the same "Bash" tool name the
            # Claude Code path uses, so the audit is one cross-agent view.
            self.add_tool(project, "Bash", {"command": cmd}, ts, mode,
                          session=session, agent="codex")

        if best:
            self.add_codex_session(project, model or "unknown", best, last_ts)

    def scan_copilot(self, roots: list[Path], since: datetime | None,
                     project_filter: str | None) -> None:
        for root in roots:
            for f in sorted(root.glob("*/events.jsonl")):
                self._scan_copilot_file(f, since, project_filter)

    def _scan_copilot_file(self, path: Path, since: datetime | None,
                           project_filter: str | None) -> None:
        """One Copilot CLI session. Two passes over memory, one over disk:
        whether a command was prompted is only known once every
        permission.requested in the session has been seen."""
        try:
            st = path.stat()
        except OSError:
            return
        if since is not None and st.st_mtime < (since.timestamp() - 3600):
            return
        self.bytes_scanned += st.st_size
        self.files_scanned += 1

        cwd = branch = None
        shutdown: dict | None = None
        shutdown_ts: datetime | None = None
        calls: list[tuple[str, str, str, datetime | None, dict]] = []   # (id, tool, command, ts, args)
        prompted: set[str] = set()
        prompted_any: set[str] = set()
        refusals: list[tuple[str, str, datetime | None]] = []     # (kind, id, ts)
        subagents: list[tuple[dict, datetime | None]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    data = rec.get("data")
                    if not isinstance(data, dict):
                        continue
                    kind = rec.get("type")
                    ts = parse_ts(rec.get("timestamp"))
                    if kind in ("session.start", "session.context_changed"):
                        ctx = data.get("context") if kind == "session.start" else data
                        if isinstance(ctx, dict):
                            cwd, branch = _copilot_context(ctx, cwd, branch)
                    elif kind == "tool.execution_start":
                        name = str(data.get("toolName") or "?")
                        args = data.get("arguments")
                        cmd = args.get("command") if isinstance(args, dict) else None
                        cmd = cmd if name == "bash" and isinstance(cmd, str) else ""
                        calls.append((str(data.get("toolCallId") or ""), name, cmd, ts,
                                      args if isinstance(args, dict) else {}))
                    elif kind == "permission.requested":
                        req = data.get("permissionRequest")
                        if isinstance(req, dict) and req.get("toolCallId"):
                            prompted_any.add(str(req["toolCallId"]))
                        if isinstance(req, dict) and req.get("kind") == "shell" \
                                and req.get("toolCallId"):
                            prompted.add(str(req["toolCallId"]))
                    elif kind == "permission.completed":
                        result = data.get("result")
                        rk = result.get("kind") if isinstance(result, dict) else None
                        if rk and rk not in COPILOT_APPROVED:
                            refusals.append((f"copilot:{clean(str(rk))[:40]}",
                                             str(data.get("toolCallId") or ""), ts))
                    elif kind == "subagent.completed":
                        subagents.append((data, ts))
                    elif kind == "session.shutdown":
                        shutdown, shutdown_ts = data, ts
        except OSError:
            return

        project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "copilot"
        if project_filter and project_filter.lower() not in project.lower():
            return

        def in_window(t: datetime | None) -> bool:
            return not (since and t and t < since)

        active = False
        joined: dict[str, tuple[str, str]] = {}
        sid = path.parent.name
        for call_id, name, cmd, ts, targs in calls:
            if not in_window(ts):
                continue
            active = True
            if cmd:
                mode = "copilot:prompted" if call_id in prompted else "copilot:auto"
                self.permission_modes[mode] += 1
                # Normalised onto "Bash", as Codex is, so the audit is one view.
                self.add_tool(project, "Bash", {"command": cmd}, ts, mode,
                              session=sid, call_id=call_id, agent="copilot")
                if call_id:
                    joined[call_id] = ("Bash", cmd[:MAX_SCAN_LINE])
            else:
                # The arguments go to the network inventory only; add_tool
                # counts nothing else for a non-Bash tool.
                net_mode = "copilot:prompted" if call_id in prompted_any else "copilot:auto"
                self.add_tool(project, name, targs, ts, net_mode,
                              session=sid, call_id=call_id, agent="copilot")
                if call_id:
                    joined[call_id] = (name, "")
        for kind, call_id, ts in refusals:
            if in_window(ts):
                active = True
                self._network_outcome(f"copilot:{call_id}", refused=True)
                self.denials[kind] += 1
                self.denials_by_project[project] += 1
                self._record_refusal(kind, project, ts, joined.get(call_id))
        for data, ts in subagents:
            if in_window(ts):
                # Copilot gives a token total with no input/output split, so no
                # usage is passed and no cost floor is recorded.
                self.add_subagent({"resolvedModel": copilot_model(str(data.get("model") or "")),
                                   "status": "completed",
                                   "totalDurationMs": data.get("durationMs") or 0,
                                   "toolStats": {}}, ts)
        if active:
            self.agents_seen.add("copilot")

        if shutdown is None:
            if active:
                self.copilot_unpriced += 1
            return
        if not in_window(shutdown_ts):
            return
        metrics = shutdown.get("modelMetrics")
        priced = False
        if isinstance(metrics, dict):
            for model, m in metrics.items():
                usage = m.get("usage") if isinstance(m, dict) else None
                if isinstance(usage, dict):
                    self.add_copilot_session(project, str(model), usage, shutdown_ts, branch)
                    priced = True
        if priced:
            self.units_by_agent["copilot"] += 1
        pr = shutdown.get("totalPremiumRequests")
        if isinstance(pr, (int, float)) and not isinstance(pr, bool):
            self.premium_requests_by_agent["copilot"] += float(pr)

    def add_refusal(self, kind: str, rec: dict, project: str,
                    ts: datetime | None, calls: dict[str, tuple[str, str]]) -> None:
        """Attribute one refusal to the tool call it blocked.

        The refusal record carries no tool_use block of its own; it points back
        through `tool_use_id` on its tool_result. Reading only the refusal
        record tells you a refusal happened and nothing about what was refused.
        """
        hit = None
        msg = rec.get("message")
        blocks = msg.get("content") if isinstance(msg, dict) else None
        if isinstance(blocks, list):
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    hit = calls.get(b.get("tool_use_id") or "")
                    if hit:
                        break
        self._record_refusal(kind, project, ts, hit)

    def _record_refusal(self, kind: str, project: str, ts: datetime | None,
                        call: tuple[str, str] | None) -> None:
        """Count one refusal, and attribute it when the blocked call is known."""
        self.refusals += 1
        self.refusal_project[project][kind] += 1
        if ts:
            # %G, the ISO year, pairs with %V: 2025-12-29 is 2026-W01.
            self.refusal_week[ts.strftime("%G-W%V")][kind] += 1
        if not call:
            return
        name, cmd = call
        self.refusals_joined += 1
        self.refusal_tool[kind][clean(name)[:48] or "?"] += 1
        if name == "Bash" and cmd:
            head = command_head(cmd)
            if head:
                self.refusal_program[kind][clean(head)[:40]] += 1

    def add_subagent(self, result: dict, ts: datetime | None) -> None:
        """One completed subagent run.

        `totalTokens` is NOT the run total. It equals the sum of the final
        message's usage in 873 of 873 observed cases and scales only ~2x from a
        4-tool run to a 45-tool run, which is context growth, not summation. The
        cumulative spend of a subagent's turns is not present in the parent
        transcript, so what is recorded here is an explicit FLOOR.
        """
        self.sub_calls += 1
        model = clean(result.get("resolvedModel") or "unknown")[:48] or "unknown"
        self.sub_by_model[model] += 1
        self.sub_status[result.get("status") or "?"] += 1
        self.sub_ms += result.get("totalDurationMs") or 0

        stats = result.get("toolStats") or {}
        for k in ("bashCount", "readCount", "editFileCount", "searchCount", "otherToolCount"):
            self.sub_tools[k] += stats.get(k, 0) or 0
        self.sub_lines["added"] += stats.get("linesAdded", 0) or 0
        self.sub_lines["removed"] += stats.get("linesRemoved", 0) or 0

        u = result.get("usage")
        if isinstance(u, dict):
            base = model.replace("[1m]", "")
            in_rate, out_rate, _prov, _known, _src = rates_for(base, ts)
            cc = u.get("cache_creation") or {}
            self.sub_cost_floor += (
                (u.get("input_tokens", 0) or 0) / 1e6 * in_rate
                + (u.get("output_tokens", 0) or 0) / 1e6 * out_rate
                + (cc.get("ephemeral_1h_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_WRITE_1H_MULT
                + (cc.get("ephemeral_5m_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_WRITE_5M_MULT
                + (u.get("cache_read_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_READ_MULT)

    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                 mode: str | None = None, *, session: str | None = None,
                 call_id: str | None = None, agent: str | None = None) -> None:
        project = clean(project)[:120] or "unknown"
        name = clean(name)[:48] or "?"
        self.tools[name] += 1
        self._net_remote_exec = ""
        self._add_network(project, name, tool_input or {}, ts, mode, session, call_id, agent)
        self._audit_config_write(project, name, tool_input or {}, ts)
        if name != "Bash":
            return
        cmd = (tool_input or {}).get("command") or ""
        if not cmd:
            return
        self.bash_total += 1
        self.bash_by_project[project] += 1
        self.bash_categories[command_category(cmd)] += 1
        if ts:
            day = ts.date().isoformat()
            self.bash_by_day[day] += 1
            if mode:
                self.bash_moded_by_day[day] += 1
                if is_ungated_mode(mode):
                    self.unsupervised_by_day[day] += 1
        head = command_head(cmd)
        if head:
            self.bash_first_token[clean(head)[:40]] += 1

        shapes = unreadable_shapes(cmd)
        if shapes:
            self.unreadable += 1
            for name in shapes:
                self.unreadable_shapes[name] += 1
        windows = scan_windows(cmd)
        oversized = len(cmd) > MAX_SCAN_TOTAL
        if oversized:
            self._add_oversized(project, head, cmd, ts, counted=bool(shapes))

        if any(contains_secret(w) for w in windows):
            self.secret_exposures += 1
            self.secret_projects[project] += 1

        _rank = {"critical": 0, "high": 1, "low": 2}
        found_secrets: list[tuple[str, str, str]] = []
        seen_fp: set[str] = set()
        for w in windows:                    # one secret seen in two windows is one
            for item in classify_secrets(w, self._location_values):
                if item[2] not in seen_fp:
                    seen_fp.add(item[2])
                    found_secrets.append(item)
        for priority, kind, fp in found_secrets:
            e = self.secrets.setdefault(fp, {
                "priority": priority, "kinds": set(), "uses": 0,
                "first": None, "last": None, "projects": set(),
                "suppressed": fp in self.suppressions,
                "suppressed_reason": self.suppressions.get(fp, ""),
                "distinct_values": 1})
            # A location id is one user's password at one option, not one value.
            # A suppression recorded for one password must not silence another:
            # once a second value is seen under it in this run, it is unsuppressed.
            n = len(self._location_values.get(fp, ()))
            if n > 1:
                e["distinct_values"] = n
                if fp in self.suppressions:
                    e["suppressed"] = False
                    e["suppressed_reason"] = f"suppression covers one value; {n} seen"
            # the same value may appear under several names; keep the worst
            if _rank[priority] < _rank[e["priority"]]:
                e["priority"] = priority
            e["kinds"].add(kind)
            e["uses"] += 1
            e["projects"].add(project)
            if ts:
                day = ts.date().isoformat()
                e["first"] = min(e["first"] or day, day)
                e["last"] = max(e["last"] or day, day)

        matches = audit_command(cmd)
        if oversized and not any(cat == "remote-exec" for _, cat, _ in matches):
            matches += self._oversized_remote_exec(cmd, windows)
        # Roadmap S2: `cu''rl … | s''h` and `curl … | busybox sh` evade the
        # remote-exec regex on the raw text; the network tokenizer reads them
        # dequoted. One flag per command: added only when the rule did not fire.
        if self._net_remote_exec and not any(cat == "remote-exec" for _, cat, _ in matches):
            # The line holding the fetch that the shell runs, not just any pipe.
            frag = self._net_remote_exec
            line = next((ln for ln in cmd.splitlines() if frag in ln), None) \
                or next((ln for ln in cmd.splitlines() if "|" in ln), cmd)
            matches.append(("high", "remote-exec", clean(line[:MAX_SCAN_LINE].strip())))
        if not matches:
            return
        worst = min(matches, key=lambda m: SEVERITY_ORDER.get(m[0], 9))
        for sev, cat, _ in matches:
            self.flag_counts[f"{sev}:{cat}"] += 1
        # Report the line that fired the worst rule, not line 1 of the script.
        evidence = next(ln for sev, _, ln in matches if sev == worst[0])
        cats = sorted({c for _, c, _ in matches})
        prog = clean(head or "?")[:40]
        fid = flag_id(worst[0], cats, prog)
        suppressed = fid in self.suppressions
        if suppressed:
            self.suppressed_flags += 1
        self.flags.append({
            "id": fid,
            "severity": worst[0],
            "categories": cats,
            "program": prog,
            "project": project,
            "when": ts.isoformat() if ts else None,
            "evidence": evidence[:240],
            "had_secret": contains_secret(cmd),
            "suppressed": suppressed,
            "suppressed_reason": self.suppressions.get(fid, ""),
        })

    def _add_oversized(self, project: str, head: str | None, cmd: str,
                       ts: datetime | None, counted: bool) -> None:
        self.oversized_commands += 1
        if not counted:
            self.unreadable += 1             # not already counted under a shape
        prog = clean(head or "?")[:40]
        fid = flag_id("med", ["oversized-command"], prog)
        suppressed = fid in self.suppressions
        if suppressed:
            self.suppressed_flags += 1
        self.flag_counts["med:oversized-command"] += 1
        self.flags.append({
            "id": fid, "severity": "med", "categories": ["oversized-command"],
            "program": prog, "project": project, "when": ts.isoformat() if ts else None,
            "evidence": (f"a command of {len(cmd):,} characters; only the first 32 KB were "
                         "fully audited" + ("; the rest past 1 MiB was not read"
                                            if len(cmd) > MAX_SCAN_HARD else "")),
            "had_secret": False, "suppressed": suppressed,
            "suppressed_reason": self.suppressions.get(fid, ""),
        })

    @staticmethod
    def _oversized_remote_exec(cmd: str, windows: list[str]) -> list[tuple[str, str, str]]:
        """The remote-exec rules over the part of an oversized command past the
        cut: raw text in 4 KB chunks (the length the rules are bounded for) with
        1 KB overlap, and the dequoted `cu''rl … | s''h` shape per window."""
        rules = [(sev, rx) for sev, cat, rx in COMPILED_RULES if cat == "remote-exec"]
        text = cmd[:MAX_SCAN_HARD]
        for i in range(MAX_SCAN_TOTAL - SCAN_OVERLAP - MAX_SCAN_LINE, len(text), 3072):
            chunk = text[max(i, 0):max(i, 0) + MAX_SCAN_LINE]
            for sev, rx in rules:
                m = rx.search(chunk)
                if m:
                    lo = max(m.start() - 80, 0)
                    return [(sev, "remote-exec", clean(chunk[lo:lo + 200].strip()))]
        for w in windows[1:]:
            piped: list[str] = []
            try:
                network_items_from_command(w, piped)
            except Exception:                # noqa: BLE001 -- counted as oversized already
                continue
            if piped:
                return [("high", "remote-exec", clean(piped[0][:200].strip()))]
        return []

    # -- scan --------------------------------------------------------------

    def scan(self, roots: list[Path], since: datetime | None, project_filter: str | None,
             progress: bool) -> None:
        if not roots:
            return
        self.roots.extend(roots)
        dirs: list[Path] = []
        for r in roots:
            try:
                dirs.extend(d for d in r.iterdir() if d.is_dir())
            except OSError as exc:
                print(f"actualis: cannot read {r}: {exc.strerror or exc}",
                      file=sys.stderr)
        dirs.sort()
        for i, d in enumerate(dirs, 1):
            project = pretty_project(d.name)
            if project_filter and project_filter.lower() not in project.lower():
                continue
            if progress:
                print(f"\r  scanning {i}/{len(dirs)}  {project[:48]:<48}",
                      end="", file=sys.stderr, flush=True)
            # Sorted: which copy of a repeated message is kept decides its day,
            # branch and ticket, so the order must not be the filesystem's.
            for f in sorted(d.glob("*.jsonl")):
                self._scan_file(f, project, since)
        if progress:
            print("\r" + " " * 72 + "\r", end="", file=sys.stderr, flush=True)

    def _scan_file(self, path: Path, project: str, since: datetime | None) -> None:
        try:
            st = path.stat()
            size = st.st_size
        except OSError:
            return
        # A file not written since the cutoff cannot hold a record after it.
        # An hour of slack absorbs clock skew and copied timestamps. On a real
        # fleet this turns --days 1 from reading 1,784 files into reading 7.
        if since is not None and st.st_mtime < (since.timestamp() - 3600):
            return
        self.files_scanned += 1
        self.bytes_scanned += size
        # tool_use_id -> (tool name, command). Scoped to this file: a refusal
        # always answers a tool call in the same session, so nothing needs to
        # survive across files and memory stays bounded on a large fleet.
        self._mode = None
        calls: dict[str, tuple[str, str]] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    # Cheap prefilter: skip lines that cannot contribute to any
                    # counter. Must include the permission fields, which live on
                    # records that carry neither usage nor tool_use.
                    counts = not ('"usage"' not in line and '"tool_use"' not in line
                                  and '"permissionMode"' not in line
                                  and '"toolDenialKind"' not in line)
                    # A line admitted only for its error result feeds the
                    # network inventory alone, so no existing counter moves.
                    if not counts and '"is_error":true' not in line \
                            and '"is_error": true' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue

                    if counts:
                        self._ingest_claude(rec, project, since, calls)
                    else:
                        ts = parse_ts(rec.get("timestamp"))
                        if not (since and ts and ts < since):
                            self._network_results(rec)
        except OSError:
            return

    def _audit_config_write(self, project: str, name: str, tool_input: dict,
                            ts: datetime | None) -> None:
        """The audited agent writing the files that decide what is reported.

        Never suppressible: an agent able to edit .actualis-suppressions could
        otherwise silence this finding with the same edit. Codex apply_patch
        edits are not read, so they are not seen here.
        """
        evidence = None
        program = name
        if name == "Bash":
            cmd = tool_input.get("command")
            if isinstance(cmd, str):
                for n, w in enumerate(scan_windows(cmd)):
                    if _AUDIT_GATE.search(w.lower().translate(_DEQUOTE)) and writes_audit_config(w):
                        # Model-written text: escapes and newlines out, as everywhere else.
                        # Past the first window no command text is shown.
                        evidence = (clean(redact(w)).replace("\n", " ") if n == 0 else
                                    f"a {len(cmd):,}-character command writes an audit config "
                                    "file past its first 32 KB")
                        program = clean(command_head(cmd) or "Bash")[:40]
                        break
        elif name.lower() in _FILE_WRITE_TOOLS and tool_input.get("command") != "view":
            for key in ("file_path", "path", "notebook_path"):
                target = tool_input.get(key)
                if isinstance(target, str) and _is_audit_config(target):
                    evidence = clean(f"{name} wrote {target.replace(chr(92), '/').rsplit('/', 1)[-1]}")
                    break
        if evidence is None:
            return
        self.flags.append({
            "id": AUDIT_CONFIG_ID,
            "severity": "high",
            "categories": ["audit-config"],
            "program": program,
            "project": project,
            "when": ts.isoformat() if ts else None,
            "evidence": evidence[:240],
            "had_secret": False,
            "suppressed": False,
            "suppressed_reason": "",
        })

    def _ingest_claude(self, rec: dict, project: str, since: "datetime | None",
                       calls: dict) -> None:
        """Ingest one Claude Code record, whatever framed it.

        Split out because the same records reach us two ways: the `.jsonl`
        transcripts on a developer's disk, and the JSON array the Claude Code
        GitHub Action writes on a CI runner. Same records, different framing --
        so this stays the only place that knows what a record *means*, and a
        change to that meaning cannot apply to one source and not the other.
        """
        ts = parse_ts(rec.get("timestamp"))
        mode = clean(str(rec.get("permissionMode") or ""))[:48]
        if mode:
            # Stays in force for the tool calls that follow it, even when this
            # record is itself older than the window.
            self._mode = str(mode)
        if since and ts and ts < since:
            return
        self._network_results(rec)

        if mode:
            self.permission_modes[mode] += 1
        denial = clean(str(rec.get("toolDenialKind") or ""))[:48]
        if denial:
            self.denials[denial] += 1
            self.denials_by_project[project] += 1
            self.add_refusal(denial, rec, project, ts, calls)
        eff = rec.get("effort")
        if eff:
            self.effort_mix[str(eff)] += 1

        msg = rec.get("message")
        if not isinstance(msg, dict):
            return

        usage = msg.get("usage")
        if isinstance(usage, dict):
            # One billable message, however many records carry it.
            mid = msg.get("id")
            if mid and mid in self.seen_message_ids:
                self.duplicate_usage_records += 1
            else:
                if mid:
                    self.seen_message_ids.add(mid)
                self.add_usage(project, msg.get("model") or "unknown",
                               usage, ts, rec.get("gitBranch"))

        tur = rec.get("toolUseResult")
        if isinstance(tur, dict) and tur.get("toolStats") is not None:
            self.add_subagent(tur, ts)

        content = msg.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    self.add_tool(project, block.get("name") or "?",
                                  block.get("input") or {}, ts, self._mode,
                                  session=rec.get("sessionId"), call_id=block.get("id"),
                                  agent="claude")
                    if block.get("id"):
                        calls[block["id"]] = (
                            block.get("name") or "?",
                            ((block.get("input") or {}).get("command") or "")
                            [:MAX_SCAN_LINE])

    def _add_network(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                     mode: str | None, session: str | None, call_id: str | None,
                     agent: str | None) -> None:
        if name == "Bash":
            cmd = tool_input.get("command")
            if not isinstance(cmd, str) or not cmd:
                return
            piped: list[str] = []
            # Remotes are per (agent, session), never across sessions; a call with
            # no session id tracks within its own command only.
            remotes = {}
            if session:
                key = (agent or ("codex" if (mode or "").startswith("codex:")
                                 else "copilot" if (mode or "").startswith("copilot:") else "claude"),
                       str(session))
                remotes = self._git_remotes.setdefault(key, {})
            try:
                found, unparsed = network_items_from_command(cmd, piped, remotes)
            except Exception:                   # noqa: BLE001 -- one bad command must not end the scan
                found, unparsed, piped = [], 1, []
            self.network_unparsed += unparsed
            self._net_remote_exec = piped[0].strip() if piped else ""
        else:
            found = network_items_from_tool(name, tool_input)
        if not found:
            return
        if not agent:
            agent = ("codex" if (mode or "").startswith("codex:")
                     else "copilot" if (mode or "").startswith("copilot:") else "claude")
        for item in found:
            for k, v in item.items():           # transcript text must not reach a terminal
                if isinstance(v, str):
                    item[k] = clean(v).replace("\n", " ")
            item.update(approval=network_approval(mode), agent=agent, project=project,
                        session=clean(str(session))[:80] if session else None,
                        ts=ts.isoformat() if ts else None,
                        failed=False if agent == "claude" else None, trusted=False)
            if call_id:
                self._net_by_call.setdefault(f"{agent}:{call_id}", []).append(len(self.network))
            self.network.append(item)

    def _network_outcome(self, key: str, refused: bool) -> None:
        """A call's result: refused calls leave the inventory, errors mark it failed."""
        for i in self._net_by_call.pop(key, ()):
            if refused:
                self.network[i]["_refused"] = True
            else:
                self.network[i]["failed"] = True

    def _network_results(self, rec: dict) -> None:
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        if not self._net_by_call or not isinstance(content, list):
            return
        refused = bool(rec.get("toolDenialKind"))
        for b in content:
            if isinstance(b, dict) and b.get("type") == "tool_result" \
                    and (refused or b.get("is_error")):
                self._network_outcome(f"claude:{b.get('tool_use_id') or ''}", refused)

    @property
    def network_items(self) -> list[dict]:
        return [i for i in self.network if not i.get("_refused")]

    def scan_execution_log(self, path: Path, project: str,
                           since: "datetime | None") -> None:
        """Scan the execution log a CI run leaves behind.

        The Claude Code GitHub Action writes every SDK event to
        $RUNNER_TEMP/claude-execution-output.json and exposes the path as its
        `execution_file` output. It is a JSON array rather than
        newline-delimited, but the records are the ones _ingest_claude already
        understands -- their own README describes them as "top-level events
        with `type`; assistant text is nested under `message.content`".

        Reading that documented output rather than guessing at ~/.claude on the
        runner is deliberate. The action drives Claude Code through the SDK, so
        whether a transcript directory exists there at all is an internal
        detail that could change without notice. `execution_file` is a
        published contract.

        No substring prefilter here. The JSONL path skips lines before parsing
        because a real fleet is thousands of files; one execution log is a
        single document that must be parsed whole regardless.
        """
        try:
            st = path.stat()
        except OSError:
            return
        self.files_scanned += 1
        self.bytes_scanned += st.st_size
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                records = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError, RecursionError):
            return
        if not isinstance(records, list):
            return
        self._mode = None
        calls: dict[str, tuple[str, str]] = {}
        for rec in records:
            if isinstance(rec, dict):
                self._ingest_claude(rec, project, since, calls)

    # -- derived -----------------------------------------------------------

    @property
    def total_cost(self) -> float:
        return sum(self.cost_by_model.values())

    @property
    def actionable_flags(self) -> list:
        return [f for f in self.flags if not f.get("suppressed")]

    @property
    def suppressed_secrets(self) -> int:
        return sum(1 for e in self.secrets.values() if e.get("suppressed"))

    @property
    def actionable_secrets(self) -> dict[str, dict]:
        """Findings not marked as false positives on this machine."""
        return {k: v for k, v in self.secrets.items() if not v.get("suppressed")}

    @property
    def confident_cost(self) -> float:
        """Spend priced from a provider's own published rates."""
        return sum(v for k, v in self.cost_by_tier.items()
                   if k in (VENDOR, VENDOR_DOC))

    @property
    def confident_pct(self) -> float:
        total = self.total_cost
        return (self.confident_cost / total * 100) if total else 100.0

    @property
    def span_days(self) -> float:
        """Elapsed time from first record to last, in days.

        A duration, not a count of dates. Activity on the 1st and the 3rd spans
        two days and touches three dates -- so this is deliberately NOT what the
        report compares active_days against. See span_dates.
        """
        if not (self.first_ts and self.last_ts):
            return 0.0
        return max((self.last_ts - self.first_ts).total_seconds() / 86400.0, 1.0)

    @property
    def span_dates(self) -> int:
        """Calendar dates covered, inclusive of both ends.

        The right denominator for active_days, which is also a count of dates.
        Comparing a date count against an elapsed duration made a contiguous
        window read as "30 active days of 29" -- off by one by construction,
        every time, which reads as a bug because it looks like one.
        """
        if not (self.first_ts and self.last_ts):
            return 0
        return (self.last_ts.date() - self.first_ts.date()).days + 1

    @property
    def active_days(self) -> int:
        """Days with any recorded spend.

        Rates must be derived from this, not from the calendar span. One stale
        session from six months ago stretches the span and silently divides the
        weekly rate by five, understating a real burn rate.
        """
        return len([d for d, v in self.cost_by_day.items() if v > 0]) or 1


# --------------------------------------------------------------------------
# Coach
#
# The report says what happened. The coach says what to do about it, which is
# the difference between a dashboard and a tool that changes behaviour.
#
# Findings carry stable IDs so they can be documented, suppressed, and quoted
# ("I keep getting AF002"). The model is ShellCheck, not a mascot: personality
# comes from being specific, and a cost report that talks like a cartoon is a
# report nobody forwards to their CFO.
#
# Benchmarks are computed against YOURSELF — project against project, week
# against week. That delivers most of the value of comparative benchmarking
# with none of the telemetry, and keeps the no-network promise intact.
# --------------------------------------------------------------------------

MIN_PROJECT_COST = 25.0     # ignore noise projects in comparisons
MIN_PROJECT_MSGS = 200


class Finding:
    __slots__ = ("id", "severity", "title", "evidence", "action", "impact")

    def __init__(self, fid, severity, title, evidence, action, impact=None):
        self.id, self.severity, self.title = fid, severity, title
        self.evidence, self.action, self.impact = evidence, action, impact


def cache_hit_rate(t: Counter) -> float:
    """Share of INPUT context served from cache.

    Output tokens are not cacheable, so including them in the denominator
    understates the rate and makes projects with chatty output look broken.
    """
    denom = t["input"] + t["cache_w"] + t["cache_read"]
    return (t["cache_read"] / denom * 100) if denom else 0.0


def _median(xs: list[float]) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    mid = len(xs) // 2
    return xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2


def coach(fleet: "Fleet") -> list[Finding]:
    """Observations worth acting on, ranked. Empty list is a valid answer."""
    out: list[Finding] = []
    total = fleet.total_cost

    # --- AF001 spend concentration -----------------------------------------
    projects = sorted(fleet.cost_by_project.items(), key=lambda kv: -kv[1])
    if projects and total > 0:
        name, cost = projects[0]
        share = cost / total * 100
        if share >= 50 and len(projects) > 2:
            out.append(Finding(
                "AF001", "info", "Spend is concentrated in one project",
                f"{name} is {share:.0f}% of all spend ({money(cost)} of {money(total)}) "
                f"across {len(projects)} projects.",
                "Not a problem by itself, but it means fleet-wide averages describe "
                "one project. Read per-project numbers, not the total."))

    # --- AF002 cache efficiency vs your own median -------------------------
    ratios: dict[str, float] = {}
    for proj, t in fleet.tokens_by_project.items():
        if (t["input"] + t["cache_w"] + t["cache_read"]) > 1_000_000 and \
                fleet.cost_by_project.get(proj, 0) >= MIN_PROJECT_COST:
            ratios[proj] = cache_hit_rate(t)
    if len(ratios) >= 3:
        med = _median(list(ratios.values()))
        for proj, r in sorted(ratios.items(), key=lambda kv: kv[1]):
            if r < med - 15 and r < 90:
                waste = max(fleet.cache_uncached.get(proj, 0) * (med - r) / 100
                            * (1 - CACHE_READ_MULT), 0.0)
                out.append(Finding(
                    "AF002", "high", "Cache efficiency below your own median",
                    f"{proj} reads {r:.0f}% of tokens from cache; your median project "
                    f"is {med:.0f}%. Something in that project changes the prompt "
                    f"prefix on most requests.",
                    "Look for a timestamp, a random id, or unsorted JSON early in the "
                    "context. Stable content must come first.",
                    f"~{money(waste)} of avoidable spend at current volume"))

    # --- AF003 unsupervised execution --------------------------------------
    auto = ungated_modes(fleet.permission_modes)
    modes = sum(fleet.permission_modes.values())
    if modes > 500:
        pct = auto / modes * 100
        if pct >= 75:
            out.append(Finding(
                "AF003", "high", "Most agent activity is unsupervised",
                f"{pct:.0f}% of {num(modes)} recorded turns ran in an auto or bypass "
                f"permission mode, across {num(fleet.bash_total)} shell commands.",
                "Defensible for throughput, but it means the permission system is not "
                "the control you may think it is. Pair it with deny rules for paths "
                "that should never be touched."))

    # --- AF004 outstanding critical secrets --------------------------------
    # actionable_secrets, not secrets: a finding derived from a suppressed one
    # must be suppressed too, or suppression silences the symptom and leaves
    # the diagnosis -- and --fail-on still breaks the build.
    crit = [(fp, e) for fp, e in fleet.actionable_secrets.items()
            if e["priority"] == "critical"]
    if crit:
        kinds = Counter(k for _, e in crit for k in e["kinds"])
        out.append(Finding(
            "AF004", "critical", "Critical credentials sit in plaintext history",
            f"{len(crit)} distinct critical secrets across "
            f"{len({p for _, e in crit for p in e['projects']})} projects. "
            f"Most common: {', '.join(k for k, _ in kinds.most_common(3))}.",
            "Rotate these first, then decide a retention policy for transcripts. "
            "Rotation fixes exposure; it does not clean the archive."))

    # --- AF005 how long a secret has been sitting there --------------------
    dated = [(fp, e) for fp, e in fleet.actionable_secrets.items()
             if e["first"] and e["priority"] != "low"]
    if dated and fleet.last_ts:
        oldest_fp, oldest = min(dated, key=lambda kv: kv[1]["first"])
        try:
            age = (fleet.last_ts.date() - datetime.fromisoformat(oldest["first"]).date()).days
        except ValueError:
            age = 0
        if age >= 30:
            out.append(Finding(
                "AF005", "high", "A credential has been exposed for a long time",
                f"{', '.join(sorted(oldest['kinds']))} ({oldest_fp}) first appeared "
                f"{oldest['first']}, {age} days ago, and was used {oldest['uses']} times.",
                "Age matters more than count. Anything unrotated since then should be "
                "treated as compromised, not merely exposed."))

    # --- AF006 agent friction, project vs your own median ------------------
    rates = {p: fleet.denials_by_project[p] / m * 100
             for p, m in fleet.msgs_by_project.items()
             if m >= MIN_PROJECT_MSGS}
    if len(rates) >= 3:
        med = _median(list(rates.values()))
        for proj, r in sorted(rates.items(), key=lambda kv: -kv[1]):
            if r > max(med * 3, 1.0):
                out.append(Finding(
                    "AF006", "info", "The agent is being corrected more here",
                    f"{proj} rejects or blocks {r:.1f}% of turns; your median project "
                    f"is {med:.1f}%.",
                    "Usually a context problem rather than a model problem. A CLAUDE.md "
                    "in that project describing its conventions is the cheapest fix."))

    # --- AF007 week-over-week trend ----------------------------------------
    days = sorted(fleet.cost_by_day.items())
    if len(days) >= 14:
        last7 = sum(v for _, v in days[-7:])
        prev7 = sum(v for _, v in days[-14:-7])
        if prev7 > 50:
            change = (last7 - prev7) / prev7 * 100
            if abs(change) >= 40:
                direction = "up" if change > 0 else "down"
                out.append(Finding(
                    "AF007", "info", f"Spend is {direction} sharply week over week",
                    f"Last 7 active days {money(last7)} versus {money(prev7)} the week "
                    f"before, {change:+.0f}%.",
                    "Worth knowing which project moved before it becomes a surprise."))

    # --- AF008 effort mix --------------------------------------------------
    if fleet.effort_mix:
        tot_e = sum(fleet.effort_mix.values())
        premium = sum(v for k, v in fleet.effort_mix.items() if k in ("high", "xhigh", "max"))
        if tot_e > 200 and premium / tot_e > 0.95:
            out.append(Finding(
                "AF008", "info", "Every task runs at premium reasoning effort",
                f"{premium / tot_e * 100:.0f}% of {num(tot_e)} turns ran at high effort "
                f"or above.",
                "Correct for hard work and wasteful for mechanical edits. Dropping "
                "routine turns to low or medium effort is the cheapest available saving."))

    # --- AF009 ticket cost outliers, against your own median ---------------
    if len(fleet.cost_by_ticket) >= 8:
        costs = list(fleet.cost_by_ticket.values())
        med = _median(costs)
        top_t, top_c = max(fleet.cost_by_ticket.items(), key=lambda kv: kv[1])
        if med > 0 and top_c > med * 8:
            brs = len(fleet.branches_by_ticket[top_t])
            out.append(Finding(
                "AF009", "info", "One ticket cost far more than your typical ticket",
                f"{top_t} cost {money(top_c)} across {brs} branch(es) and "
                f"{num(fleet.msgs_by_ticket[top_t])} messages. Your median ticket is "
                f"{money(med)} over {len(costs)} tickets.",
                "Either it was genuinely large, or it was underscoped and got restarted. "
                "The branch count usually tells you which."))

    # --- AF010 work that cannot be attributed ------------------------------
    trunk = fleet.cost_by_branch.get("trunk", 0.0)
    detached = fleet.cost_by_branch.get("detached HEAD", 0.0)
    if total > 100 and (trunk + detached) / total > 0.35:
        pct = (trunk + detached) / total * 100
        out.append(Finding(
            "AF010", "info", "A large share of spend is not attributable to a ticket",
            f"{pct:.0f}% of spend ({money(trunk + detached)}) happened on trunk or in a "
            f"detached HEAD, so it cannot be tied to an issue.",
            "Fine for exploration and ops work. If you ever want per-ticket chargeback "
            "to be credible, branch naming is the cheapest thing to fix."))

    # --- AF011 shell activity the audit cannot see -------------------------
    sub_bash = fleet.sub_tools.get("bashCount", 0)
    if sub_bash and fleet.bash_total:
        blind = sub_bash / (fleet.bash_total + sub_bash) * 100
        if blind >= 10:
            out.append(Finding(
                "AF011", "high", "Shell activity is partly invisible to the audit",
                f"{num(sub_bash)} shell commands ran inside {num(fleet.sub_calls)} "
                f"subagent runs, {blind:.0f}% of all shell activity. Their command text "
                f"is never written to the parent transcript.",
                "Subagents inherit the parent's permissions but not its visibility. If "
                "the audit matters to you, prefer doing shell work in the main loop, or "
                "treat these runs as unreviewed."))

    # --- AF012 deduplication appears to have stopped working ---------------
    # docs/json.md says a zero repeat count on a large scan is suspicious. That
    # sentence was the only thing checking it, and a sentence checks nothing.
    # If a transcript format stops emitting message ids, cost silently doubles
    # -- the exact 0.1.0 defect, reintroduced by a vendor change rather than by
    # us, with nothing to say so.
    # Claude Code messages only: Codex and Copilot units are whole sessions,
    # which are never re-emitted, so counting them here raised a false critical.
    claude_messages = fleet.units_by_agent["claude-code"]
    if claude_messages >= 500 and fleet.duplicate_usage_records == 0:
        out.append(Finding(
            "AF012", "critical", "Deduplication collapsed nothing, which should be impossible",
            f"{num(claude_messages)} Claude Code messages were counted and not one repeated record "
            f"was collapsed. On a scan this size that has not been observed in real "
            f"transcripts: an agent re-emits an assistant record while a response "
            f"streams, so repeats are normal and their absence is not.",
            "Most likely the transcript format stopped carrying a message id, in which "
            "case every record is being billed again and cost is roughly double. Check "
            "`actualis --json | jq '.duplicate_usage_records_skipped'` against a raw "
            "count of distinct message ids before trusting any figure here."))

    # --- AF013 the rate table is old ---------------------------------------
    # The report already prints a staleness line, but a warning that exists only
    # in rendered text is invisible to --coach, to --json and to the MCP server,
    # which is where anything programmatic reads from.
    age = pricing_age_days()
    if age > PRICING_STALE_DAYS:
        sev = "high" if age > PRICING_STALE_DAYS * 2 else "info"
        out.append(Finding(
            "AF013", sev, "The rate table has not been checked in a long time",
            f"Prices were last verified {PRICING_VERIFIED}, {age} days ago. "
            f"The tool makes no network calls, so it cannot know whether a rate "
            f"changed -- only how long since anyone looked.",
            "Re-check the provider pages, or run `python3 tools/price-check.py --fetch` "
            "from a checkout. Every cost figure here inherits this age."))

    order = {"critical": 0, "high": 1, "info": 2}
    out.sort(key=lambda f: order.get(f.severity, 9))
    return out


# --- comparing two runs -----------------------------------------------------

# Severity vocabularies differ between the three entity families, so rank them
# on one scale to say "got worse" rather than just "changed".
DIFF_MAX_ROWS = 15

_SEVERITY_RANK = {"low": 0, "info": 0, "med": 1, "medium": 1,
                  "high": 2, "critical": 3}


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(str(severity).lower(), -1)


def load_report(path: Path) -> dict:
    """Read a saved --json payload, refusing anything we cannot compare.

    A diff against a payload from a different schema is worse than no diff: it
    silently reports every renamed key as a change. Refuse instead.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not an actualis report (expected an object)")
    if "schema_version" not in data:
        raise ValueError(
            f"{path} has no schema_version, so it is not an actualis --json report")
    got = data["schema_version"]
    if got != JSON_SCHEMA_VERSION:
        raise ValueError(
            f"{path} uses schema_version {got}; this build writes "
            f"{JSON_SCHEMA_VERSION}. Regenerate the baseline with this version "
            "rather than comparing across schemas.")
    return data


def _by_id(rows: object) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict) and r.get("id"):
                out[str(r["id"])] = r
    return out


def _flag_kinds(payload: dict) -> dict[str, dict]:
    """Flag ids name a *kind* of command, not one occurrence, so count them."""
    bash = payload.get("bash")
    rows = bash.get("flags") if isinstance(bash, dict) else None
    out: dict[str, dict] = {}
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("id"):
                continue
            fid = str(r["id"])
            cur = out.setdefault(fid, {"id": fid, "severity": r.get("severity", ""),
                                       "program": r.get("program", ""),
                                       "categories": r.get("categories") or [],
                                       "count": 0})
            cur["count"] += 1
    return out


def diff_reports(old: dict, new: dict) -> dict:
    """What appeared, what went away, and what got worse."""
    families = [
        ("secrets", _by_id(old.get("secrets")), _by_id(new.get("secrets")),
         "priority", "credential"),
        ("findings", _by_id(old.get("coach")), _by_id(new.get("coach")),
         "severity", "finding"),
        ("flags", _flag_kinds(old), _flag_kinds(new), "severity", "command kind"),
    ]
    out: dict = {"families": {}, "totals": {}}
    for name, o, n, sev_key, noun in families:
        appeared = [n[k] for k in n if k not in o]
        resolved = [o[k] for k in o if k not in n]
        worse, better, moved = [], [], []
        for k in n:
            if k not in o:
                continue
            ro, rn = _rank(o[k].get(sev_key, "")), _rank(n[k].get(sev_key, ""))
            if rn > ro:
                worse.append((o[k], n[k]))
            elif rn < ro:
                better.append((o[k], n[k]))
            elif "count" in n[k] and n[k]["count"] != o[k].get("count"):
                moved.append((o[k], n[k]))
        out["families"][name] = {"noun": noun, "sev_key": sev_key,
                                 "appeared": appeared, "resolved": resolved,
                                 "worse": worse, "better": better, "moved": moved}
    for key in ("cost_usd", "messages"):
        ov, nv = old.get(key), new.get(key)
        if isinstance(ov, (int, float)) and isinstance(nv, (int, float)):
            out["totals"][key] = (ov, nv)
    out["windows"] = (
        (old.get("window") or {}).get("from"), (old.get("window") or {}).get("to"),
        (new.get("window") or {}).get("from"), (new.get("window") or {}).get("to"))
    out["digests"] = (old.get("report_sha256"), new.get("report_sha256"))
    return out


def _label(row: dict, family: str) -> str:
    if family == "secrets":
        types = ", ".join(row.get("types") or []) or "unknown type"
        where = ", ".join(row.get("projects") or [])
        return f"{types}" + (f"  in {where}" if where else "")
    if family == "findings":
        return str(row.get("title") or "")
    prog = row.get("program") or "?"
    cats = ", ".join(row.get("categories") or [])
    return f"{prog}" + (f"  ({cats})" if cats else "")


def render_diff(d: dict, c: C) -> None:
    rule(c, "DIFF")
    of, ot, nf, nt = d["windows"]
    print(f"  baseline   {of or '?'} → {ot or '?'}")
    print(f"  this run   {nf or '?'} → {nt or '?'}")
    od, nd = d["digests"]
    if od and nd and od == nd:
        print(f"\n  {c.ok}Identical report.{c.off} {c.dim}Same digest ({od[:16]}), "
              f"so nothing below changed.{c.off}\n")
        return

    changed = False
    for family, blk in d["families"].items():
        noun = blk["noun"]
        rows = []
        for r in blk["appeared"]:
            sev = r.get(blk["sev_key"], "")
            rows.append((_rank(sev), "new", sev, _label(r, family), ""))
        for r in blk["resolved"]:
            sev = r.get(blk["sev_key"], "")
            rows.append((_rank(sev), "gone", sev, _label(r, family), ""))
        for ro, rn in blk["worse"]:
            rows.append((_rank(rn.get(blk["sev_key"], "")), "worse",
                         rn.get(blk["sev_key"], ""), _label(rn, family),
                         f"was {ro.get(blk['sev_key'], '')}"))
        for ro, rn in blk["better"]:
            rows.append((_rank(rn.get(blk["sev_key"], "")), "better",
                         rn.get(blk["sev_key"], ""), _label(rn, family),
                         f"was {ro.get(blk['sev_key'], '')}"))
        for ro, rn in blk["moved"]:
            delta = rn["count"] - ro.get("count", 0)
            rows.append((_rank(rn.get(blk["sev_key"], "")), "count",
                         rn.get(blk["sev_key"], ""), _label(rn, family),
                         f"{ro.get('count', 0)} → {rn['count']} ({delta:+d})"))
        if not rows:
            continue
        changed = True
        print(f"\n  {c.bold}{noun}s{c.off}")
        ordered = sorted(rows, key=lambda r: (-r[0], r[1]))
        shown, dropped = ordered[:DIFF_MAX_ROWS], len(ordered) - DIFF_MAX_ROWS
        for _, kind, sev, label, note in shown:
            col = (c.red if kind in ("new", "worse") and _rank(sev) >= 2
                   else c.ok if kind in ("gone", "better")
                   else c.yellow if kind in ("new", "worse") else c.dim)
            mark = {"new": "+", "gone": "-", "worse": "^", "better": "v",
                    "count": "~"}[kind]
            tail = f"  {c.dim}{note}{c.off}" if note else ""
            print(f"    {col}{mark}{c.off} {sev:<8} {label}{tail}")
        if dropped > 0:
            # Never truncate silently: a hidden row reads as "nothing there".
            print(f"    {c.dim}... and {dropped} more, lowest severity first. "
                  f"Compare the saved payloads directly to see every row.{c.off}")

    if not changed:
        print(f"\n  {c.dim}No credential, finding or command-kind changed. "
              f"The digests differ on volume alone.{c.off}")

    if d["totals"]:
        print(f"\n  {c.bold}totals{c.off}")
        for key, (ov, nv) in d["totals"].items():
            delta = nv - ov
            arrow = "+" if delta > 0 else ""
            if key == "cost_usd":
                print(f"    cost      ${ov:,.2f} → ${nv:,.2f}  "
                      f"{c.dim}({arrow}{delta:,.2f}){c.off}")
            else:
                print(f"    {key:<9} {ov:,} → {nv:,}  {c.dim}({arrow}{delta:,}){c.off}")
    print()


def replay(fingerprint: str, events: list[ReplayEvent]) -> dict:
    """The incident: what the credential saw, and what ran while it was live."""
    sightings = [e for e in events
                 if any(f == fingerprint for _, _, f in classify_secrets(e.cmd))]
    if not sightings:
        return {}

    first, last = sightings[0].ts, sightings[-1].ts
    window = [e for e in events if first <= e.ts <= last]

    kinds: set[str] = set()
    for e in sightings:
        for pri, kind, f in classify_secrets(e.cmd):
            if f == fingerprint:
                kinds.add(f"{pri} {kind}")

    # Proximity, not clock overlap. A command in an unrelated project that
    # merely ran during the window almost certainly never had this credential
    # in context, and counting it as blast radius overstates the incident.
    # An incident report that overstates is worse than none.
    seen_sessions = {e.session for e in sightings if e.session}
    seen_projects = {e.project for e in sightings if e.project}

    same_session = [e for e in window if e.session and e.session in seen_sessions]
    same_project = [e for e in window
                    if e.project in seen_projects
                    and not (e.session and e.session in seen_sessions)]
    elsewhere = [e for e in window
                 if e.project not in seen_projects
                 and not (e.session and e.session in seen_sessions)]

    investigate = [e for e in same_session
                   if any(cat in REACHABLE_CATEGORIES
                          for _, cat, _ in audit_command(e.cmd))]

    def programs(rows: list[ReplayEvent], n: int) -> dict:
        c: Counter = Counter()
        for e in rows:
            head = command_head(e.cmd)
            if head:
                c[head] += 1
        return dict(c.most_common(n))

    def strs(rows, attr) -> list:
        return sorted({getattr(e, attr) for e in rows if getattr(e, attr)})

    return {
        "document": "incident",
        "schema_version": INCIDENT_SCHEMA_VERSION,
        "version": __version__,
        "fingerprint": fingerprint,
        "types": sorted(kinds),
        "window": {
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "days": round((last - first).total_seconds() / 86400, 2),
            "sightings": len(sightings),
        },
        "exposure": {
            "sessions": strs(sightings, "session"),
            "projects": strs(sightings, "project"),
            "branches": strs(sightings, "branch"),
            "vendors": strs(sightings, "vendor"),
        },
        "blast_radius": {
            "note": "graded by proximity, not by time alone. same_session had the "
                    "credential in context; elsewhere merely overlapped the window "
                    "and is reported for completeness, not as exposure",
            "same_session": {"commands": len(same_session),
                             "projects": strs(same_session, "project"),
                             "branches": strs(same_session, "branch")},
            "same_project": {"commands": len(same_project)},
            "elsewhere": {"commands": len(elsewhere),
                          "projects": strs(elsewhere, "project")},
            "programs": programs(same_session, 15),
        },
        "investigate": {
            "commands": len(investigate),
            "note": "commands in the sessions that saw it which touch egress, "
                    "credentials or a database -- the subset that could plausibly "
                    "have used the credential rather than merely coexisted with it",
            "programs": programs(investigate, 10),
        },
        "limits": list(INCIDENT_LIMITS),
    }


def clip(text: str, width: int) -> str:
    """Cut a list-like line to width at a separator, not mid-token.

    A hard slice produced output that reads as corrupted rather than
    abbreviated: a session id ending "...-bdf3-", a program list ending "mak",
    and worst, the overflow marker itself sliced to "(+2 mo" -- so the one
    element whose job was to say "there is more" was the element destroyed.
    """
    if len(text) <= width:
        return text
    cut = text[:width - 1]
    best = max((cut.rfind(sep) for sep in (", ", "  ", " ")), default=-1)
    if best > 0:
        return cut[:best].rstrip(" ,") + "\u2026"
    return cut.rstrip(" ,") + "\u2026"


def render_replay(inc: dict, c: C) -> None:
    w, ex, br, iv = inc["window"], inc["exposure"], inc["blast_radius"], inc["investigate"]
    rule(c, f"INCIDENT  {inc['fingerprint']}")
    print(f"  credential   {c.red}{', '.join(inc['types']) or 'unclassified'}{c.off}")
    print(f"  first seen   {w['first_seen'][:19].replace('T', ' ')}")
    print(f"  last seen    {w['last_seen'][:19].replace('T', ' ')}")
    print(f"  exposed for  {c.bold}{w['days']} days{c.off} across {w['sightings']} appearances")

    print(f"\n  {c.bold}WHERE IT APPEARED{c.off}")
    for label, key in (("projects", "projects"), ("branches", "branches"),
                       ("sessions", "sessions"), ("vendors", "vendors")):
        vals = ex[key]
        if not vals:
            continue
        # Reserve the overflow marker's width before clipping the values, so
        # "and there are more" survives instead of being the first casualty.
        marker = f"  (+{len(vals)-3} more)" if len(vals) > 3 else ""
        shown = clip(", ".join(vals[:3]), 62 - len(marker)) + marker
        print(f"    {label:<10} {len(vals):>4}   {c.dim}{shown}{c.off}")

    ss, sp, el = br["same_session"], br["same_project"], br["elsewhere"]
    print(f"\n  {c.bold}BLAST RADIUS{c.off}  {c.dim}graded by proximity, not clock overlap{c.off}")
    print(f"    same session  {ss['commands']:>6}   had the credential in context")
    if ss["branches"]:
        print(f"      branches    {len(ss['branches']):>6}   {c.dim}{clip(', '.join(ss['branches'][:4]), 56)}{c.off}")
    print(f"    same project  {sp['commands']:>6}   {c.dim}other sessions, same project{c.off}")
    print(f"    elsewhere     {el['commands']:>6}   {c.dim}overlapped in time only, "
          f"{len(el['projects'])} unrelated projects{c.off}")
    if br["programs"]:
        top = "  ".join(f"{k}:{v}" for k, v in list(br["programs"].items())[:8])
        print(f"    programs      {c.dim}{clip(top, 66)}{c.off}")

    denom = ss["commands"] or 1
    print(f"\n  {c.bold}INVESTIGATE{c.off}  {c.dim}in-session, touching egress, credentials or a database{c.off}")
    print(f"    commands      {c.yellow}{iv['commands']:>6}{c.off}   "
          f"{c.dim}({iv['commands']/denom*100:.1f}% of the {ss['commands']} in-session){c.off}")
    if iv["programs"]:
        print(f"    programs      {c.dim}" + clip("  ".join(f"{k}:{v}" for k, v in iv["programs"].items()), 66) + f"{c.off}")

    print(f"\n  {c.bold}WHAT THIS DOES NOT ESTABLISH{c.off}")
    for lim in inc["limits"]:
        for i, chunk in enumerate(_wrap(lim, 70)):
            print(f"    {c.dim}{'- ' if i == 0 else '  '}{chunk}{c.off}")
    print()


def render_aisvs(findings: list[AisvsFinding], c: C) -> None:
    rule(c, "OWASP AISVS")
    print(f"  {c.dim}Mapped against AISVS {AISVS_VERSION}. AISVS says what to verify and,")
    print(f"  being vendor-neutral, never how. This is the how, for the part a")
    print(f"  transcript can answer.{c.off}\n")

    mark = {FAILING: (c.red, "NOT HOLDING"), CONSISTENT: (c.ok, "consistent"),
            UNKNOWN: (c.dim, "no evidence")}
    for f in findings:
        col, label = mark[f.state]
        print(f"  {col}{label:<12}{c.off} {c.bold}{f.control:<7}{c.off} "
              f"{c.dim}L{f.level}{c.off}")
        for line in _wrap("Verify that " + f.text + ".", 68):
            print(f"               {c.dim}{line}{c.off}")
        for i, line in enumerate(_wrap(f.detail, 68)):
            print(f"               {'-> ' if i == 0 else '   '}{line}")
        print()

    failing = sum(1 for f in findings if f.state == FAILING)
    lead = (f"{failing} of {len(findings)} controls are demonstrably NOT holding on "
            "this machine. That is a hard claim: the evidence is in your transcripts."
            if failing else
            f"Nothing in these transcripts contradicts any of the {len(findings)} "
            "controls. That is not the same as meeting them, and on a small or "
            "empty corpus it mostly means there was nothing to see.")
    print(f"  {c.bold}What this is and is not{c.off}")
    for line in (
        lead,
        "The rest are marked consistent or no-evidence, and neither means pass. "
        "Almost every AISVS control verifies ENFORCEMENT -- that a runtime blocks, "
        "that a filter strips. This tool reads what already happened and cannot "
        "inspect a runtime.",
        "So it falsifies. It can show a control is broken. It cannot show one is "
        "met, and it does not claim to.",
        f"Control text quoted from {AISVS_SOURCE} at {AISVS_VERSION}. Levels are theirs.",
    ):
        for line2 in _wrap(line, 72):
            print(f"    {c.dim}{line2}{c.off}")
        print()


def render_coach(findings: list[Finding], c: C) -> None:
    rule(c, "COACH")
    if not findings:
        print(f"  {c.ok}Nothing worth flagging.{c.off} "
              f"{c.dim}Cache efficiency, supervision, secrets and trend all look "
              f"unremarkable.{c.off}")
        return
    for f in findings:
        col = (c.red if f.severity == "critical"
               else c.yellow if f.severity == "high" else c.cyan)
        print(f"\n  {col}{f.id}{c.off}  {c.bold}{f.title}{c.off}")
        for line in _wrap(f.evidence, 84):
            print(f"        {line}")
        if f.impact:
            print(f"        {c.yellow}{f.impact}{c.off}")
        for line in _wrap("→ " + f.action, 84):
            print(f"        {c.dim}{line}{c.off}")
    print()


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur); cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


# --------------------------------------------------------------------------
# Watch mode
#
# A prototype of the menu-bar app, in the terminal. Whatever the status line
# shows here is what a tray icon would show. Holds no state on disk: it starts
# at end-of-file and only reports what happens from now on, so running it is
# not a decision you have to undo.
# --------------------------------------------------------------------------

def notify(title: str, message: str) -> None:
    """Best-effort native notification. Never raises, never blocks for long."""
    import subprocess
    try:
        if sys.platform == "darwin":
            # AppleScript string literals use the same \" and \\ escapes JSON does,
            # and AppleScript performs no substitution inside a literal, so there is
            # nothing for transcript content to break out into. ensure_ascii=False
            # keeps non-ASCII readable rather than printing \uXXXX.
            script = (f"display notification {json.dumps(message, ensure_ascii=False)} "
                      f"with title {json.dumps(title, ensure_ascii=False)}")
            subprocess.run(["osascript", "-e", script], timeout=5,
                           capture_output=True, check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["notify-send", "--", title, message], timeout=5,
                           capture_output=True, check=False)
        elif sys.platform == "win32":
            # The text is passed through the environment and referenced by name.
            # It MUST NOT be interpolated into the command: PowerShell evaluates
            # $(...) and backtick escapes inside a double-quoted string, and this
            # text comes from a transcript, so building the command by string
            # formatting hands command execution to whatever an agent typed.
            env = dict(os.environ, ACTUALIS_NOTIFY_TEXT=f"{title}: {message}")
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", "Write-Output $Env:ACTUALIS_NOTIFY_TEXT"],
                           timeout=5, capture_output=True, check=False, env=env)
    except Exception:
        pass  # a missing notifier must never take the watcher down


def _jsonl_files(roots: list[Path], codex: list[Path],
                 copilot: list[Path] | None = None) -> list[Path]:
    out: list[Path] = []
    for r in roots:
        try:
            out.extend(f for d in sorted(r.iterdir()) if d.is_dir() for f in sorted(d.glob("*.jsonl")))
        except OSError:
            continue
    for r in codex:
        try:
            out.extend(r.rglob("rollout-*.jsonl"))
        except OSError:
            continue
    for r in copilot or []:
        try:
            out.extend(r.glob("*/events.jsonl"))
        except OSError:
            continue
    return out


def watch(roots: list[Path], codex: list[Path], interval: float, c: C,
          quiet: bool, raw: bool, copilot: list[Path] | None = None) -> int:
    import time

    # Python block-buffers stdout when it is not a terminal. For a watcher that
    # means an alert can sit unwritten in a 4KB buffer for hours, which defeats
    # the entire point of running it in the background.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    offsets: dict[Path, int] = {}
    for f in _jsonl_files(roots, codex, copilot):
        try:
            offsets[f] = f.stat().st_size      # start at EOF: history is not news
        except OSError:
            pass

    seen_secrets: set[str] = set()
    cmds = flagged = crit = 0
    started = datetime.now(timezone.utc)

    srcs = ", ".join(str(r) for r in (roots + codex + (copilot or [])))
    print(f"{c.bold}actualis watch{c.off} {c.dim}· {len(offsets)} files · every "
          f"{interval:g}s · ctrl-c to stop{c.off}")
    print(f"{c.dim}watching {srcs}{c.off}")
    print(f"{c.dim}Starting from now. Existing history is not replayed.{c.off}\n")

    try:
        while True:
            for f in _jsonl_files(roots, codex, copilot):
                try:
                    size = f.stat().st_size
                except OSError:
                    continue
                start = offsets.get(f)
                if start is None:
                    offsets[f] = 0 if size < 1_000_000 else size   # new file: read it
                    start = offsets[f]
                if size < start:                 # truncated or rotated
                    start = 0
                if size == start:
                    continue
                try:
                    with f.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(start)
                        chunk = fh.read()
                        offsets[f] = fh.tell()
                except OSError:
                    continue

                project = ("copilot" if f.name == "events.jsonl"
                           else pretty_project(f.parent.name))
                for line in chunk.splitlines():
                    if ('"tool_use"' not in line and '"function_call"' not in line
                            and '"tool.execution_start"' not in line):
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    for command in _commands_in(rec):
                        cmds += 1
                        for pri, kind, fp in classify_secrets(command):
                            if fp in seen_secrets or pri == "low":
                                continue
                            seen_secrets.add(fp)
                            crit += 1
                            msg = f"{kind} in {project}"
                            # flush: under a service manager stdout is a file,
                            # so it is block-buffered. Without this an alert can
                            # sit unwritten for hours -- which is the whole
                            # point of the feature, lost to an 8KB buffer.
                            print(f"\r{c.red}▲ SECRET{c.off}  {msg}  {c.dim}{fp}{c.off}"
                                  + " " * 20, flush=True)
                            notify("actualis: credential exposed", msg)
                        hits = audit_command(command)
                        high = [h for h in hits if h[0] == "high"]
                        if high:
                            flagged += 1
                            cats = ",".join(sorted({h[1] for h in high}))
                            line_txt = high[0][2] if raw else redact(high[0][2])
                            print(f"\r{c.yellow}▲ {cats}{c.off}  {line_txt[:88]}"
                                  f"  {c.dim}{project[:28]}{c.off}" + " " * 10,
                                  flush=True)
                            if not quiet:
                                notify(f"actualis: {cats}", line_txt[:120])

            mins = (datetime.now(timezone.utc) - started).total_seconds() / 60
            # The heartbeat is a live status line for a terminal. Redirected to a
            # log it would write ~1.3 MB a day of carriage returns, so it is
            # suppressed and only real events get recorded.
            if sys.stdout.isatty():
                print(f"\r{c.dim}  {mins:5.1f}m · {cmds} commands · "
                      f"{flagged} flagged · {crit} secrets{c.off}", end="", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        if sys.stdout.isatty():
            print(f"\r{' ' * 72}\r", end="")
        print(f"{c.bold}stopped{c.off} after {mins:.1f}m · {cmds} commands · "
              f"{flagged} flagged · {crit} distinct secrets")
        return 0


def _commands_in(rec: dict) -> list[str]:
    """Every shell command in one transcript record, across every agent format."""
    out: list[str] = []
    msg = rec.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), list):
        for b in msg["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Bash":
                cmd = (b.get("input") or {}).get("command")
                if cmd:
                    out.append(cmd)
    payload = rec.get("payload")
    if isinstance(payload, dict) and payload.get("name") == "shell_command":
        try:
            args = json.loads(payload.get("arguments") or "{}")
        except (json.JSONDecodeError, ValueError):
            args = {}
        if args.get("command"):
            out.append(args["command"])
    data = rec.get("data")
    if rec.get("type") == "tool.execution_start" and isinstance(data, dict) \
            and data.get("toolName") == "bash":
        args = data.get("arguments")
        cmd = args.get("command") if isinstance(args, dict) else None
        if isinstance(cmd, str) and cmd:
            out.append(cmd)
    return out


# --------------------------------------------------------------------------
# Explanations
#
# Every figure this tool prints should be answerable: where it came from, how it
# was computed, what it assumes, and how to check it without trusting this tool.
# A number you cannot interrogate is a number you should not act on.
#
# Each entry carries the same four parts on purpose, so the shape is predictable:
# what it measures, the formula, the assumptions, and an independent check.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# What each vendor's transcript actually gives you
#
# Three agents are supported, unevenly, and until now nothing said how. Someone
# comparing a Claude Code project against a Codex one was comparing different
# measurements without being told which.
#
# Kept beside the code that consumes each field so a reader can check a claim
# here against the parser that makes it. A test asserts every capability names
# the field it depends on.
# --------------------------------------------------------------------------

YES, PARTIAL, NO = "yes", "partial", "no"

VENDOR_CAPABILITIES = (
    # capability,            claude,  codex,   copilot, the field it rests on
    ("Cost and token usage", YES,     YES,     YES,     "message.usage / token_count / "
                                                        "session.shutdown modelMetrics; a Copilot "
                                                        "session with no shutdown record is "
                                                        "counted unpriced, never estimated"),
    ("Per-message dedup",    YES,     PARTIAL, PARTIAL, "message.id; Codex reports a cumulative "
                                                        "session total, so the max is taken; "
                                                        "Copilot writes one final total per "
                                                        "model at shutdown"),
    ("Shell command text",   YES,     YES,     YES,     "tool_use Bash / function_call "
                                                        "shell_command / tool.execution_start bash"),
    ("Project attribution",  YES,     YES,     YES,     "cwd / session context gitRoot"),
    ("Git branch",           YES,     NO,      YES,     "gitBranch / session context branch; "
                                                        "Codex rollouts carry no branch, so cost "
                                                        "per ticket excludes Codex"),
    ("Tool refusals",        YES,     NO,      YES,     "toolDenialKind joined by tool_use_id; "
                                                        "Codex writes no per-refusal record at "
                                                        "all; Copilot's permission.completed "
                                                        "joined by toolCallId, where a person "
                                                        "declining is denied-interactively-by-user"),
    ("Permission mode",      YES,     YES,     YES,     "permissionMode / approval_policy / "
                                                        "permission.requested per toolCallId; a "
                                                        "Copilot command allow-listed in config "
                                                        "is never prompted and counts as auto"),
    ("Sandbox policy",       NO,      YES,     NO,      "sandbox_policy; Claude Code and Copilot "
                                                        "CLI have no equivalent"),
    ("Subagent activity",    PARTIAL, NO,      PARTIAL, "toolUseResult.toolStats / "
                                                        "subagent.completed totals; command text "
                                                        "is never written to the parent transcript"),
    ("Subagent cost",        NO,      NO,      NO,      "only each run's final message survives, "
                                                        "so a floor is reported and excluded from "
                                                        "the total; Copilot gives a token total "
                                                        "with no input/output split"),
    ("Cache TTL split",      PARTIAL, NO,      NO,      "cache_creation ephemeral_1h/5m; older "
                                                        "records carry a flat total, and OpenAI "
                                                        "and Copilot have no equivalent"),
    ("Reasoning effort",     YES,     NO,      NO,      "effort"),
)

_VENDOR_COLUMN = {"claude": 1, "codex": 2, "copilot": 3}


def vendor_gaps(vendor: str) -> list[tuple[str, str]]:
    """Capabilities this vendor does not fully provide, with the reason."""
    idx = _VENDOR_COLUMN.get(vendor, 2)
    return [(row[0], row[4]) for row in VENDOR_CAPABILITIES if row[idx] != YES]


EXPLAIN: dict[str, dict[str, object]] = {
    "sources": {
        "measures": "Which files every number is derived from.",
        "formula": [
            "Claude Code  ~/.claude/projects/**/*.jsonl  (plus $CLAUDE_CONFIG_DIR)",
            "Codex        $CODEX_HOME/sessions/**/rollout-*.jsonl",
            "Copilot CLI  $COPILOT_HOME/session-state/*/events.jsonl  (default ~/.copilot)",
            "",
            "Files are opened read-only. Nothing is written, cached, or sent.",
            "Every directory actually scanned is printed in the report header.",
        ],
        "assumes": [
            "The agents wrote an accurate record. This tool reads it; it does not",
            "witness the work independently.",
        ],
        "verify": "ls ~/.claude/projects/*/ | head   # the raw data is yours to read",
    },
    "cost": {
        "measures": "What the recorded token usage would cost at provider list prices.",
        "formula": [
            "one billable message is counted ONCE, keyed on its message id. A",
            "transcript repeats the same assistant record while a response streams,",
            "so the record count is not the message count.",
            "",
            "per message, using that message's model:",
            "  input        x rate",
            "  output       x rate",
            "  cache write  x rate x 2.00  (1h TTL)  or  x 1.25  (5m TTL)",
            "  cache read   x rate x 0.10",
            "",
            "OpenAI differs: input_tokens INCLUDES cached, so the cached portion is",
            "billed at 0.10x and only the remainder at full rate.",
        ],
        "assumes": [
            "List prices, hardcoded and dated in the source. They drift.",
            "On a Pro/Max subscription you pay a flat fee, so this is an",
            "opportunity-cost figure and a consumption signal, NOT a bill.",
            "OpenAI rates come from a third-party aggregator, not OpenAI's page.",
            "That a repeated message id means a repeated record, not repeated work.",
            "Versions before 0.1.1 did not assume this and billed every record,",
            "which overstated a real corpus by 2.13x. If you have a figure from",
            "0.1.0, re-run it.",
            "Models with no published rate are priced at the top of the known range",
            "for their provider; that share is reported separately so you can",
            "subtract it.",
        ],
        "verify": ("actualis --json | jq '.cost_usd, .duplicate_usage_records_skipped, "
                   ".cost_usd_from_unpriced_models'"),
    },
    "vendors": {
        "measures": "What each agent's transcript actually contains, and what it does not.",
        "formula": [
            "capability                claude   codex    copilot",
        ] + [f"  {cap:<24}{c:<9}{x:<9}{p}" for cap, c, x, p, _why in VENDOR_CAPABILITIES] + [
            "",
            "Every row names the transcript field it rests on; see",
            "VENDOR_CAPABILITIES in the source.",
        ],
        "assumes": [
            "Nothing. This is a statement about the data, not about the agents.",
            "A section fed by a field one vendor does not write is single-vendor,",
            "and comparing two projects on different agents compares different",
            "measurements.",
        ],
        "verify": "actualis --json | jq '.vendors'",
    },
    "copilot": {
        "measures": "How a GitHub Copilot CLI session is read, and what it cannot show.",
        "formula": [
            "Source    $COPILOT_HOME/session-state/<session>/events.jsonl (~/.copilot)",
            "Commands  tool.execution_start where toolName is bash",
            "Project   session context gitRoot, else cwd; the latest value wins",
            "Cost      session.shutdown modelMetrics, once per model per session.",
            "          inputTokens already includes cache reads and writes, so",
            "          fresh input = inputTokens - cacheReadTokens - cacheWriteTokens",
            "Prompted  a bash call with a shell permission.requested for its toolCallId",
            "Auto      every other bash call",
            "Refusal   permission.completed whose result.kind is not approved or",
            "          approved-for-location",
            "Premium   session.shutdown totalPremiumRequests, never converted to dollars",
        ],
        "assumes": [
            "A person declining a prompt is recorded as denied-interactively-by-user,",
            "confirmed on a real session. Any other kind that is not approved is",
            "counted as a refusal by the policy.",
            "A denied command still has its tool.execution_start, so it counts as an",
            "attempted shell command, as a refused Claude Code tool call does.",
            "A command allow-listed in Copilot's config is never prompted, so it",
            "counts as auto -- unsupervised -- even though a person approved the rule.",
            "A session with no session.shutdown record is counted unpriced. No cost",
            "is estimated for it.",
            "Cache writes carry no TTL, so they are priced at the 1h rate, the same",
            "assumption as a Claude record with no TTL split. If Copilot uses",
            "5-minute caching, this overstates its cost (by about 12% on observed",
            "sessions).",
            "session.db is not read; events.jsonl carries everything used here.",
        ],
        "verify": ("jq -c 'select(.type==\"session.shutdown\") | .data.modelMetrics' "
                   "~/.copilot/session-state/*/events.jsonl"),
    },
    "diff": {
        "measures": "What changed between a saved report and this one.",
        "formula": [
            "  actualis --json > baseline.json     # today",
            "  actualis --diff baseline.json       # next week",
            "",
            "Three families are compared, each by a stable id:",
            "  credentials    secrets[].id     fingerprint of the secret itself",
            "  findings       coach[].id       AF0nn",
            "  command kinds  bash.flags[].id  severity + categories + program",
            "",
            "  +  appeared since the baseline      -  no longer present",
            "  ^  higher severity than before      v  lower severity",
            "  ~  same severity, different count",
            "",
            "A flag id names a KIND of command, not one occurrence, so the same",
            "id appearing more often shows as a count change rather than as new.",
        ],
        "assumes": [
            "Both reports came from this schema version. A baseline written by a",
            "different schema is refused rather than compared, because a renamed",
            "key is indistinguishable from a real change.",
            "Absence is not proof of rotation: a credential drops out when it stops",
            "appearing in the window, which --days alone can cause.",
        ],
        "verify": "actualis --json > /tmp/a.json && actualis --diff /tmp/a.json  "
                  "# identical run reports no change",
    },
    "verify": {
        "measures": "Whether this build did what it claims: no network, no writes.",
        "formula": [
            "  actualis --self-check        # exits non-zero if any check fails",
            "",
            "imports    every module the shipped source imports, at any depth.",
            "           A Python process cannot open a network connection without",
            "           socket, so socket's absence is stronger evidence than",
            "           'we never called requests'.",
            "integrity  a sample of your transcripts, sha256 + size + mtime,",
            "           taken before a real scan and again after.",
            "tree       every file under the transcript roots, counted before and",
            "           after, so a created or deleted file is visible.",
            "writes     the only paths this build can write to, named in full.",
            "identity   this file's own sha256, to compare with the published wheel.",
        ],
        "assumes": [
            "That the interpreter and the operating system are honest. A compiled",
            "extension, a patched interpreter, or a modified copy of this file",
            "could defeat every check above.",
            "Passing is a FLOOR, not a guarantee: it describes the run you just",
            "made, not every run this build could make. The stronger check is to",
            "watch the process from outside, which --self-check prints for you.",
        ],
        "verify": "actualis --self-check --days 1  # then read the source: one file",
    },
    "aisvs": {
        "measures": "Which OWASP AISVS controls your transcripts show are NOT holding.",
        "formula": [
            "  actualis --aisvs",
            "",
            "AISVS 1.0 is a numbered, levelled, pass/fail requirement set for AI",
            "systems. Chapter C9 covers agentic action; Appendix C covers AI",
            "coding tools. It says what to verify and, being vendor-neutral,",
            "never how -- and it hands host hardening to CIS Benchmarks, which",
            "do not cover coding agents at all.",
            "",
            "This maps what is already measured onto the controls a transcript",
            "can speak to:",
            "  9.5.4   secrets not in observable context  <- secrets[]",
            "  9.2.1   approval gates block high impact   <- permission_modes",
            "  9.2.2   approvals show full parameters     <- refusals join",
            "  9.3.1   least-privilege tool sandbox       <- flagged commands",
            "  AC.3.2  context stripping is enforced      <- secrets[]",
            "  AC.5.1  the chain can be replayed          <- --replay",
            "  12.1.1  interactions are logged            <- transcripts read",
        ],
        "assumes": [
            "Nothing, and that is the point. It FALSIFIES rather than verifies.",
            "Almost every AISVS control is about ENFORCEMENT -- that a runtime",
            "blocks, that a filter strips. This tool reads what already happened",
            "and cannot inspect a runtime.",
            "So `not holding` is a hard claim backed by evidence in your own",
            "transcripts. `consistent` and `no evidence` are NOT passes, and",
            "nothing here should be reported as a passing audit.",
            "Control text is quoted from the AISVS repository; levels are theirs.",
        ],
        "verify": "actualis --aisvs   # then read the control text at github.com/OWASP/AISVS",
    },
    "replay": {
        "measures": "What happened while one leaked credential was live.",
        "formula": [
            "  actualis --replay <id>          # id from the credential table",
            "  actualis --replay <id> --json   # an incident record",
            "",
            "window     first sighting of that fingerprint -> last sighting",
            "exposure   the sessions, projects and branches it appeared in",
            "radius     every command inside the window, GRADED BY PROXIMITY:",
            "             same session   had the credential in context",
            "             same project   other sessions, same project",
            "             elsewhere      overlapped in time only",
            "investigate  in-session commands touching egress, credentials or",
            "             a database -- the subset worth actually reading",
            "",
            "Graded rather than counted because a command in an unrelated",
            "project that merely ran during the window almost certainly never",
            "had the credential in context. Counting it would turn 42 things",
            "worth reading into 7,553 things nobody will read.",
        ],
        "assumes": [
            "That the window bounds the exposure. A credential created before",
            "the first sighting, or used outside an agent session, is invisible.",
            "That proximity approximates access. It is a strong heuristic and",
            "not a proof: same-session means the credential was in that",
            "session's context, not that any particular command used it.",
            "Absence of a sighting after last_seen is NOT evidence of rotation.",
            "Neither vendor records a machine identity, so 'where' is a working",
            "directory and a transcript root, never a host.",
        ],
        "verify": "actualis --json | jq -r '.secrets[0].id' | xargs actualis --replay",
    },
    "suppressions": {
        "measures": "Findings you have marked as false positives on this machine.",
        "formula": [
            "Read, least specific first, from:",
            "  $XDG_CONFIG_HOME/actualis/suppressions  (or ~/.config/...)",
            "  ./.actualis-suppressions                (commit to share with a team)",
            "",
            "One finding per line: <id> <why it is not a real finding>",
            "",
            "  actualis --suppress <id> --reason \"test fixture in CI config\"",
            "  actualis --suppressions",
        ],
        "assumes": [
            "Nothing. A suppression is your judgement, recorded, not a claim by",
            "this tool that the finding was wrong.",
            "A suppressed finding is STILL COUNTED and still appears in --json.",
            "It is held back from the actionable list, never hidden -- a scan",
            "with many suppressions must not look like a clean one.",
        ],
        "verify": "actualis --json | jq '.suppressed_secrets, [.secrets[]|select(.suppressed)]'",
    },
    "refusals": {
        "measures": "What was stopped before it ran, and which gate stopped it.",
        "formula": [
            "A refusal is its own transcript record carrying toolDenialKind. It",
            "holds no tool_use block: it points back at the call it blocked",
            "through tool_use_id on its tool_result.",
            "",
            "  index every tool_use id -> (tool name, command)",
            "  for each refusal: look up its tool_use_id",
            "  program = the head of that command, not its first token",
            "",
            "user-rejected     a human declined",
            "automode-blocked  the auto-mode policy declined",
            "automode-unavailable  the deciding model was unreachable",
        ],
        "assumes": [
            "That a refusal answers a call in the same session file. Anything",
            "unjoined is reported separately rather than dropped.",
            "This machine only. Refusals are NOT deduplicated across developers,",
            "and they are bounded by how long transcripts are kept.",
            "A refusal is not a verdict. It says a gate fired, not that firing",
            "was correct.",
        ],
        "verify": "actualis --json | jq '.refusals.total, .refusals.by_program'",
    },
    "network": {
        "measures": "Downloads and fetches the agents made, and whether a person approved each.",
        "formula": [
            "The inventory is a tripwire, not a guarantee. It reads only what the",
            "transcript shows. Shell commands are split on && || ; | and newlines",
            "(outside quotes), on the dequoted text, so cu''rl and \"cu\"rl read as curl.",
            "Also read, as commands of their own:",
            "  command substitution $(...) and backticks, and process substitution",
            "  <(...), to three levels;",
            "  the string after a shell's -c, including combined flags (bash -lc,",
            "  sh -xc), and the arguments of eval;",
            "  the bodies of if/while/until/for loops, { } and ( ) groups, and a leading !.",
            "Skipped to reach the command: sudo env time nice nohup command exec",
            "timeout stdbuf doas busybox xargs, and VAR=value. Under xargs the",
            "arguments may arrive on stdin, so a bare `xargs curl` is recorded as a",
            "fetch with a variable host.",
            "Recognised programs: curl wget git gh npm pnpm yarn bun npx bunx pip",
            "pip3 uv uvx pipx brew cargo go docker podman.",
            "Counted as unreadable (totals.unparsed_segments), not skipped silently:",
            "a segment with a quote left open, and substitution nested deeper than",
            "3 levels.",
            "A git remote is resolved to the URL it was added or cloned with earlier",
            "in the same session; a remote name that resolves to nothing has no host",
            "and is listed, not flagged.",
            "Tool calls: WebFetch,",
            "WebSearch, web_fetch, web_search, and any tool named like",
            "fetch/browse/download/http.",
            "",
            "approval  asked    Copilot asked the person before the call",
            "          unasked  the call ran in auto or bypass mode, Codex 'never', or a",
            "                   Copilot standing rule",
            "          unknown  default mode: an allowlist rule may have approved it",
            "                   without asking; the transcript does not say",
            "",
            "--network-strict makes each untrusted, unasked or unknown, not-failed",
            "(program, host) group a medium finding. --network-trust HOST[/PATH] and",
            "./.actualis-network-trust list trusted sources: host suffix on a label",
            "boundary, path prefix on a segment boundary. The report prints where trust",
            "came from, with the file's path and hash.",
            "",
            "audit-config is a tripwire too. It is a high finding that cannot be",
            "suppressed, raised when an agent writes .actualis-network-trust,",
            ".actualis-suppressions or ~/.config/actualis/suppressions (a redirect,",
            "tee, a Write/Edit tool), runs actualis --suppress, or runs any command",
            "that names one of those files and is not a known reader (cat, grep,",
            "git diff, ...). Matching is case-insensitive.",
        ],
        "assumes": [
            "Out of sight, and not guessed at:",
            "  - downloads inside scripts, Makefiles, npm scripts and postinstall",
            "    hooks (bash install.sh, make, npm run);",
            "  - code that fetches: python -c, node -e, perl, ruby, php, and nc,",
            "    /dev/tcp, openssl s_client;",
            "  - names built at run time: $CMD, aliases, brace expansion {curl,URL},",
            "    ANSI-C quoting $'\\x63url', env -S, and a URL arriving on stdin",
            "    (echo '...' | sh, bash <<< '...', a here-document);",
            "  - a command after a single & (true & curl ...);",
            "  - programs not recognised: aria2c, httpie, scp, rsync, nc, npm exec,",
            "    yarn dlx, pip download, gem, apt-get, cargo binstall;",
            "  - a URL written without a scheme (curl host/path).",
            "Codex apply_patch writes, and writes made by a script, are not seen",
            "as audit-config writes.",
            "A registry install with no URL is attributed to the ecosystem's default",
            "registry (host_inferred: true). Failed is known for Claude Code only.",
            "pinned means an exact version only: a full MAJOR.MINOR.PATCH for npm and",
            "go (go with a leading v), == for pypi, an @sha256: digest for images. For",
            "crates, cargo add is pinned only with =1.2.3 (x@1.2.3 is a caret",
            "requirement) and cargo install --version 1.2.3 is exact.",
        ],
        "verify": "actualis --json | jq '.network.totals, .network.hosts[:5]'",
    },
    "cache": {
        "measures": "Share of input context served from cache, and what that saved.",
        "formula": [
            "hit rate = cache_read / (input + cache_write + cache_read)",
            "saved    = (cost of sending the same context uncached) - (cost actually billed)",
            "",
            "Output tokens are excluded from the denominator because they cannot be",
            "cached; including them makes a chatty project look broken.",
        ],
        "assumes": [
            "The counterfactual is that the same context would have been sent.",
            "A write-heavy project can show NEGATIVE savings, since a 1h cache",
            "write costs 2.00x. That is reported rather than clamped to zero.",
        ],
        "verify": "actualis --json | jq '.cache'",
    },
    "tickets": {
        "measures": "Cost attributed to an issue, via the branch a message was written on.",
        "formula": [
            "gitBranch is recorded on every message. The issue id is extracted from it:",
            "  feat/412-slug -> #412     PROJ-456-slug -> PROJ-456     issue-742 -> #742",
            "",
            "One ticket often spans several branches, so grouping is by ticket.",
            "Trunk and detached HEAD get their own buckets and are NOT attributed.",
        ],
        "assumes": [
            "Branch names carry the issue number. Where they do not, the work is",
            "reported as unattributed rather than guessed at.",
        ],
        "verify": "actualis --json | jq '.by_ticket[0], .by_branch'",
    },
    "secrets": {
        "measures": "Distinct credentials appearing in recorded shell commands.",
        "formula": [
            "Command text is matched against known token prefixes, connection-string",
            "shapes, and secret-shaped assignments. Each hit is hashed immediately to",
            "sha256[:8]; the value is never stored, printed, or written to JSON.",
            "A password a person may have chosen (an option such as curl -u, a short",
            "PASSWORD variable, a short URL or scp password) is fingerprinted by where",
            "it appeared instead, so a published id cannot confirm a guess.",
            "",
            "A secret is a VALUE: the same one under two variable names is one row,",
            "and the worst priority wins.",
        ],
        "assumes": [
            "Pattern matching has a ceiling. Dynamically built values, secrets read",
            "from files, and anything inside a subagent are NOT detectable.",
            "This raises the floor on visibility. It is not a security boundary.",
            "",
            "Credentials a vendor publishes in its own documentation -- AWS's",
            "AKIAIOSFODNN7EXAMPLE and the rest -- are excluded. They are not",
            "secrets, and reporting one fails a build over a key that was never",
            "valid. A real key that merely contains EXAMPLE is still reported.",
        ],
        "verify": "grep -rl 'sk_live_' ~/.claude/projects/ | head   # find them yourself",
    },
    "subagents": {
        "measures": "Work done by subagents, and the part of it that cannot be seen.",
        "formula": [
            "Each Agent tool result carries resolvedModel, toolStats and totalTokens.",
            "",
            "totalTokens is NOT the run total: it equals the sum of the run's FINAL",
            "message usage in every observed case, and scales only ~2x from a 4-tool",
            "run to a 45-tool run, which is context growth rather than summation.",
            "So the cost shown is an explicit FLOOR and is excluded from the headline.",
        ],
        "assumes": [
            "Subagent shell commands are counted but their text is never written to",
            "the parent transcript, so none of them can be audited.",
        ],
        "verify": "actualis --json | jq '.subagents'",
    },
    "shell": {
        "measures": "Commands the agents ran, and which are worth a look.",
        "formula": [
            "Every recorded Bash invocation is matched against ~40 deterministic",
            "patterns in nine categories. No model is involved and no score drifts:",
            "a command either matches a rule or it does not.",
            "",
            "Rules are line-scoped and quantifier-bounded, so a pathological command",
            "cannot hang the scan.",
        ],
        "assumes": [
            "A flag means 'worth looking at', not 'wrong'. Most rm -rf calls are a",
            "build directory. Current flag rate is about 3.8%.",
        ],
        "verify": "actualis --json | jq '.bash.flag_counts'",
    },
    "coach": {
        "measures": "Findings worth acting on, benchmarked against your own history.",
        "formula": [
            "Each finding AF001-AF011 has a documented threshold. Comparisons are",
            "against YOUR OWN median: project vs project, week vs week, ticket vs",
            "your median ticket.",
            "",
            "There is no telemetry and no population. Nothing is compared to other",
            "users, because nothing about you leaves the machine.",
        ],
        "assumes": [
            "A finding is earned. On an unremarkable fleet the coach says nothing.",
        ],
        "verify": "actualis --why AF002   # the threshold and your actual values",
    },
    "agents": {
        "measures": "Whether installed agent binaries are what they claim to be.",
        "formula": [
            "macOS: codesign --verify --strict, then the Team ID is compared against",
            "a pinned expectation per tool. A modified binary fails verification.",
            "",
            "Proves: it came from that publisher and has not been altered since.",
            "Does NOT prove: that the software is safe.",
        ],
        "assumes": [
            "Unsigned is not malicious. npm and script installs are never signed.",
            "Implemented for macOS only; elsewhere it reports 'unassessed'.",
        ],
        "verify": "codesign --display --verbose=4 $(which claude)",
    },
}


def render_explain(topic: str | None, c: C) -> int:
    if not topic or topic not in EXPLAIN:
        rule(c, "EXPLAIN")
        print(f"  {c.dim}Every figure is answerable. Pick a topic:{c.off}\n")
        for k, v in EXPLAIN.items():
            print(f"    {c.bold}{k:<11}{c.off} {v['measures']}")
        print(f"\n  {c.dim}actualis --explain cost{c.off}")
        print(f"  {c.dim}actualis --why AF002      explain one finding, with your numbers{c.off}\n")
        return 0 if not topic else 1

    e = EXPLAIN[topic]
    rule(c, f"EXPLAIN  {topic}")
    print(f"  {e['measures']}\n")
    print(f"  {c.bold}How it is computed{c.off}")
    for line in e["formula"]:
        print(f"    {c.dim}{line}{c.off}" if line else "")
    print(f"\n  {c.bold}What it assumes{c.off}")
    for line in e["assumes"]:
        print(f"    {line}")
    print(f"\n  {c.bold}Check it without trusting this tool{c.off}")
    print(f"    {c.cyan}{e['verify']}{c.off}\n")
    return 0


def render_why(fid: str, fleet: Fleet, c: C) -> int:
    """Explain one finding against the user's actual numbers."""
    fid = fid.upper()
    found = [f for f in coach(fleet) if f.id == fid]
    rule(c, f"WHY  {fid}")
    if not found:
        known = sorted({x.id for x in coach(fleet)})
        print(f"  {fid} is not firing on your data.")
        if known:
            print(f"  {c.dim}Currently firing: {', '.join(known)}{c.off}")
        print(f"  {c.dim}All findings and their thresholds: docs/findings.md{c.off}\n")
        return 1
    f = found[0]
    col = c.red if f.severity == "critical" else (c.yellow if f.severity == "high" else c.cyan)
    print(f"  {col}{f.severity.upper()}{c.off}  {c.bold}{f.title}{c.off}\n")
    print(f"  {c.bold}Why it fired, with your numbers{c.off}")
    for line in _wrap(f.evidence, 84):
        print(f"    {line}")
    if f.impact:
        print(f"\n  {c.bold}Estimated impact{c.off}\n    {c.yellow}{f.impact}{c.off}")
    print(f"\n  {c.bold}What to do{c.off}")
    for line in _wrap(f.action, 84):
        print(f"    {line}")
    print(f"\n  {c.dim}Threshold and method: docs/findings.md#{fid.lower()}{c.off}")
    print(f"  {c.dim}Underlying data:      actualis --json{c.off}\n")
    return 0


# --------------------------------------------------------------------------
# Agent platform verification
#
# This tool reads what agents did. A reasonable next question is whether the
# agent itself is what it claims to be — a modified `claude` binary could do
# anything and would still write a plausible-looking transcript.
#
# On macOS that is answerable: Developer ID signatures bind a binary to a
# publisher and break on modification. Team IDs below were observed on real
# installs and are pinned so an unexpected signer is visible.
#
# WHAT THIS PROVES: the binary came from that publisher and has not been altered
# since signing. WHAT IT DOES NOT PROVE: that the software is safe, or that the
# publisher is trustworthy. Unsigned is not the same as malicious — npm-installed
# tools are scripts and are never code-signed.
# --------------------------------------------------------------------------

KNOWN_PUBLISHERS = {
    "Q6L2SF6YDW": "Anthropic PBC",
    "2DC432GLL2": "OpenAI OpCo, LLC",
    "UBF8T346G9": "Microsoft Corporation",
    "EQHXZ8M8AV": "Google LLC",
}

# Which team is expected to sign which tool. A valid signature from the WRONG
# publisher is the interesting case, and it is invisible without this.
EXPECTED_SIGNER = {
    "claude": "Q6L2SF6YDW",
    "codex": "2DC432GLL2",
}

AGENT_COMMANDS = [
    ("Claude Code", "claude"),
    ("Codex", "codex"),
    ("GitHub Copilot CLI", "copilot"),
    ("Gemini CLI", "gemini"),
    ("Cursor Agent", "cursor-agent"),
    ("Aider", "aider"),
    ("Cline", "cline"),
    ("OpenCode", "opencode"),
]

# status -> (glyph, meaning)
AGENT_STATUS = {
    "verified":       ("OK",   "signed by the expected publisher"),
    "wrong-signer":   ("WARN", "validly signed, but not by the expected publisher"),
    "signed-unknown": ("?",    "validly signed by a publisher not in the pin list"),
    "unsigned":       ("-",    "no code signature; normal for script-based tools"),
    "tampered":       ("FAIL", "signature present but INVALID: binary was modified"),
    "unknown":        ("?",    "could not be assessed"),
}


def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int | None, str]:
    """(exit code, combined output). The code is None when the command could not
    be run at all — missing binary, timeout, permission. That is a different fact
    from a non-zero exit and callers must not conflate the two."""
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception:
        return None, ""


def _which(cmd: str) -> str | None:
    import shutil
    p = shutil.which(cmd)
    return os.path.realpath(p) if p else None


def verify_agent(label: str, cmd: str) -> dict | None:
    """Assess one agent binary. Returns None when it is not installed."""
    path = _which(cmd)
    if not path:
        return None

    info: dict = {"agent": label, "command": cmd, "path": path,
                  "status": "unknown", "signer": None, "team_id": None,
                  "identifier": None, "detail": ""}

    try:
        info["size_bytes"] = os.path.getsize(path)
    except OSError:
        pass

    if sys.platform != "darwin":
        info["detail"] = ("code-signature verification is implemented for macOS only; "
                          "this platform is reported as unassessed rather than trusted")
        return info

    code, out = _run(["codesign", "--display", "--verbose=4", path])
    if code is None:
        info["detail"] = ("codesign could not be run, so this binary was not "
                          "assessed; it is not a claim that it is unsigned")
        return info
    if "not signed at all" in out or (code != 0 and "Identifier=" not in out):
        info["status"] = "unsigned"
        info["detail"] = "no code signature (expected for npm and script installs)"
        return info

    for line in out.splitlines():
        if line.startswith("TeamIdentifier="):
            info["team_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1].strip()
        elif line.startswith("Authority=") and info["signer"] is None:
            info["signer"] = line.split("=", 1)[1].strip()

    vcode, vout = _run(["codesign", "--verify", "--strict", path])
    if vcode is None:
        info["status"] = "unknown"
        info["detail"] = "signature present but verification could not be run"
        return info
    if vcode != 0:
        info["status"] = "tampered"
        info["detail"] = (vout.strip().splitlines() or ["signature verification failed"])[0]
        return info

    team = info["team_id"]
    if team in (None, "not set"):
        info["status"] = "signed-unknown"
        info["detail"] = "signed but carries no team identifier"
    elif cmd in EXPECTED_SIGNER:
        if team == EXPECTED_SIGNER[cmd]:
            info["status"] = "verified"
            info["detail"] = f"signature valid, team {team} as expected"
        else:
            info["status"] = "wrong-signer"
            info["detail"] = (f"signed by {team} but {EXPECTED_SIGNER[cmd]} was expected "
                              f"for {cmd}")
    elif team in KNOWN_PUBLISHERS:
        info["status"] = "verified"
        info["detail"] = f"signature valid, {KNOWN_PUBLISHERS[team]}"
    else:
        info["status"] = "signed-unknown"
        info["detail"] = f"signature valid, publisher {team} is not pinned"
    return info


def verify_agents() -> list[dict]:
    out = []
    for label, cmd in AGENT_COMMANDS:
        r = verify_agent(label, cmd)
        if r:
            out.append(r)
    return out


def render_agents(rows: list[dict], c: C) -> None:
    rule(c, "AGENT PLATFORMS")
    if not rows:
        print(f"  {c.dim}No agent binaries found on PATH.{c.off}")
        return
    for r in rows:
        glyph, _ = AGENT_STATUS.get(r["status"], ("?", ""))
        col = {"verified": c.ok, "tampered": c.red, "wrong-signer": c.red,
               "unsigned": c.dim, "signed-unknown": c.yellow}.get(r["status"], c.dim)
        print(f"\n  {col}{glyph:<4}{c.off} {c.bold}{r['agent']}{c.off}"
              f"  {c.dim}{r['command']}{c.off}")
        if r.get("signer"):
            print(f"       {r['signer']}")
        print(f"       {c.dim}{r['detail']}{c.off}")
        print(f"       {c.dim}{r['path'][:88]}{c.off}")
    print(f"\n  {c.dim}A valid signature proves the binary came from that publisher and has")
    print(f"  not been modified since. It does not prove the software is safe, and")
    print(f"  unsigned does not mean malicious: script-based tools are never signed.")
    print(f"  Verify independently: codesign --display --verbose=4 <path>{c.off}")
    print()


# --------------------------------------------------------------------------
# MCP server
#
# Lets the agent query its own cost and exposure mid-session: "what did this
# ticket cost", "do I have credentials exposed". Speaks JSON-RPC over stdio, so
# there is no port, no daemon, and no new trust surface.
#
# Implemented against the standard library rather than the MCP SDK. A tool whose
# entire pitch is "one auditable file, no supply chain" cannot take a dependency
# to talk a line-delimited JSON protocol.
#
# Compatibility: the 2026-07-28 revision made the protocol stateless and retired
# the initialize handshake, but older clients still send it. Answering both is a
# superset and costs nothing.
#
# SECURITY: everything returned here is read by a model and written back into a
# transcript, which this tool then scans. So it returns aggregates, types,
# fingerprints and counts — never a secret value, and never raw command text.
# --------------------------------------------------------------------------

MCP_PROTOCOL_VERSIONS = ["2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"]

MCP_TOOLS = [
    {
        "name": "fleet_summary",
        "description": "Overall coding-agent activity: spend, tokens, cache efficiency, "
                       "top projects, and how much ran unsupervised.",
        "inputSchema": {"type": "object", "properties": {
            "days": {"type": "integer", "description": "only the last N days"},
            "project": {"type": "string", "description": "filter to projects matching this"},
        }},
    },
    {
        "name": "ticket_cost",
        "description": "What a ticket cost in agent time and money, derived from branch "
                       "names. Omit `ticket` to list the most expensive.",
        "inputSchema": {"type": "object", "properties": {
            "ticket": {"type": "string", "description": "e.g. '#412' or 'PROJ-456'"},
            "limit": {"type": "integer", "description": "how many to list, default 15"},
        }},
    },
    {
        "name": "exposed_secrets",
        "description": "Credentials found in the agent's own command history, as a "
                       "rotation list. Returns type, priority, an 8-char fingerprint and "
                       "dates. Never returns a secret value.",
        "inputSchema": {"type": "object", "properties": {
            "priority": {"type": "string", "enum": ["critical", "high", "low", "all"]},
        }},
    },
    {
        "name": "coach_findings",
        "description": "Things worth acting on, benchmarked against this user's own "
                       "history: cache efficiency, unsupervised execution, stale "
                       "credentials, cost outliers.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "explain",
        "description": "How a number is computed, what it assumes, and how to verify it "
                       "independently. Topics: sources, cost, cache, tickets, secrets, "
                       "subagents, shell, coach, agents.",
        "inputSchema": {"type": "object", "properties": {
            "topic": {"type": "string"}}, "required": ["topic"]},
    },
    {
        "name": "verify_agents",
        "description": "Which agent platforms are installed and whether their binaries "
                       "are validly signed by the expected publisher. Detects a modified "
                       "binary.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shell_audit",
        "description": "Summary of shell commands the agents ran: counts by risk "
                       "category, permission modes, and how much is invisible because it "
                       "happened inside subagents. Returns counts, not command text.",
        "inputSchema": {"type": "object", "properties": {
            "project": {"type": "string"},
        }},
    },
]


# A scan is expensive, so results are cached — but the key comes from the
# caller, so the cache must be bounded or a client choosing keys freely retains
# an unbounded number of Fleets and triggers an unbounded number of scans.
MCP_CACHE_MAX = 8
MCP_MAX_DAYS = 3650
MCP_MAX_PROJECT = 200


def clamp_days(v: object) -> int | None:
    """Client-supplied window, bounded. bool is an int in Python and must not pass."""
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return min(max(v, 1), MCP_MAX_DAYS)


class _MCPCache:
    """A scan takes ~80s over a large fleet, so hold it — but only a few, LRU."""

    def __init__(self) -> None:
        self._store: OrderedDict[tuple, Fleet] = OrderedDict()

    def fleet(self, days: int | None = None, project: str | None = None) -> Fleet:
        key = (days, project)
        if key in self._store:
            self._store.move_to_end(key)
        else:
            f = Fleet()
            # The same cutoff as the CLI's --days, so the two never disagree.
            since = window_start(days) if days else None
            roots = transcript_roots()
            if roots:
                f.scan(roots, since, project, progress=False)
            croots = codex_roots()
            if croots:
                f.roots.extend(croots)
                f.scan_codex(croots, since, project)
            proots = copilot_roots()
            if proots:
                f.roots.extend(proots)
                f.scan_copilot(proots, since, project)
            self._store[key] = f
            while len(self._store) > MCP_CACHE_MAX:
                self._store.popitem(last=False)
        return self._store[key]


def _mcp_call(name: str, args: dict, cache: _MCPCache) -> dict:
    project = args.get("project")
    f = cache.fleet(clamp_days(args.get("days")),
                    project[:MCP_MAX_PROJECT] if isinstance(project, str) else None)

    if name == "fleet_summary":
        ctx = Counter()
        for t in f.tokens_by_project.values():
            ctx.update(t)
        modes = sum(f.permission_modes.values())
        unsup = ungated_modes(f.permission_modes)
        top = sorted(f.cost_by_project.items(), key=lambda kv: -kv[1])[:8]
        return {
            "window": {"from": f.first_ts.isoformat() if f.first_ts else None,
                       "to": f.last_ts.isoformat() if f.last_ts else None,
                       "active_days": f.active_days},
            "messages": f.messages,
            "cost_usd_list_price": round(f.total_cost, 2),
            "cost_usd_from_unpriced_models": round(f.cost_unknown, 2),
            "duplicate_usage_records_skipped": f.duplicate_usage_records,
            "cost_note": "provider list prices; a subscription bills a flat fee, so read "
                         "this as consumption rather than a bill",
            "cache_hit_rate_pct": round(cache_hit_rate(ctx), 1),
            "cache_saved_usd": round(sum(f.cache_uncached.values())
                                     - sum(f.cache_actual.values()), 2),
            "by_agent": {k: round(v, 2) for k, v in f.cost_by_agent.items()},
            "top_projects": [{"project": p, "cost_usd": round(c, 2)} for p, c in top],
            "shell_commands": f.bash_total,
            "unsupervised_pct": round(unsup / modes * 100, 1) if modes else None,
        }

    if name == "ticket_cost":
        want = args.get("ticket")
        rows = sorted(f.cost_by_ticket.items(), key=lambda kv: -kv[1])
        if want:
            key = want if want.startswith("#") or "-" in want else f"#{want}"
            match = [(t, c) for t, c in rows if t.lower() == key.lower()]
            if not match:
                return {"found": False, "ticket": want,
                        "hint": "branch names must carry the issue number for this to work"}
            t, c = match[0]
            return {"found": True, "ticket": t, "cost_usd": round(c, 2),
                    "messages": f.msgs_by_ticket[t],
                    "branches": sorted(f.branches_by_ticket[t]),
                    "active_days": len(set(f.dates_by_ticket.get(t, [])))}
        lim = args.get("limit") if isinstance(args.get("limit"), int) else 15
        med = _median(list(f.cost_by_ticket.values())) if f.cost_by_ticket else 0
        return {"ticket_count": len(rows), "median_ticket_usd": round(med, 2),
                "unattributed_usd": round(f.cost_by_branch.get("trunk", 0)
                                          + f.cost_by_branch.get("detached HEAD", 0), 2),
                "tickets": [{"ticket": t, "cost_usd": round(c, 2),
                             "branches": len(f.branches_by_ticket[t])} for t, c in rows[:lim]]}

    if name == "exposed_secrets":
        want = args.get("priority", "all")
        rank = {"critical": 0, "high": 1, "low": 2}
        rows = sorted(f.secrets.items(), key=lambda kv: (rank.get(kv[1]["priority"], 9),
                                                         -kv[1]["uses"]))
        if want in rank:
            rows = [r for r in rows if r[1]["priority"] == want]
        return {
            "distinct_secrets": len(rows),
            "worth_rotating": sum(1 for _, e in rows if e["priority"] != "low"),
            "note": "a fingerprint is sha256[:8] of the value, or for a password, of "
                    "where it appeared; values are never stored or returned",
            "secrets": [{"priority": e["priority"], "types": sorted(e["kinds"]),
                         "fingerprint": fp, "uses": e["uses"],
                         "first_seen": e["first"], "last_seen": e["last"],
                         "projects": sorted(e["projects"]),
                         "distinct_values": e.get("distinct_values", 1)} for fp, e in rows[:50]],
        }

    if name == "explain":
        topic = str(args.get("topic", "")).lower()
        e = EXPLAIN.get(topic)
        if not e:
            return {"topics": sorted(EXPLAIN), "error": f"unknown topic: {topic}"}
        return {"topic": topic, "measures": e["measures"], "formula": e["formula"],
                "assumes": e["assumes"], "verify_independently": e["verify"]}

    if name == "verify_agents":
        rows = verify_agents()
        return {"agents": rows,
                "note": "a valid signature proves origin and integrity, not safety; "
                        "unsigned is normal for npm and script installs"}

    if name == "coach_findings":
        return {"findings": [{"id": x.id, "severity": x.severity, "title": x.title,
                              "evidence": x.evidence, "action": x.action,
                              "impact": x.impact} for x in coach(f)]}

    if name == "shell_audit":
        sub = f.sub_tools.get("bashCount", 0)
        total = f.bash_total + sub
        return {
            "shell_commands": f.bash_total,
            "invisible_in_subagents": sub,
            "invisible_pct": round(sub / total * 100, 1) if total else 0,
            "invisible_note": "subagent command text is never written to the parent "
                              "transcript, so it cannot be audited",
            "flagged_by_category": dict(f.flag_counts),
            "permission_modes": dict(f.permission_modes),
            "denials": dict(f.denials),
            "most_run": dict(f.bash_first_token.most_common(15)),
            "refusals": {
                "total": f.refusals,
                "joined_to_a_command": f.refusals_joined,
                "by_gate": {k: dict(v.most_common(8))
                            for k, v in sorted(f.refusal_tool.items())},
                "by_program": {k: dict(v.most_common(12))
                               for k, v in sorted(f.refusal_program.items())},
                "note": "a refused command is never sent to a provider, so these "
                        "exist only in the local transcript. Program names only, "
                        "never the command text.",
            },
            "note": "counts only; command text is deliberately not returned, because "
                    "anything returned here is written back into a transcript",
        }

    raise ValueError(f"unknown tool: {name}")


def mcp_serve() -> int:
    """JSON-RPC over stdio. Nothing but protocol may be written to stdout."""
    cache = _MCPCache()
    out = sys.stdout

    def send(obj: dict) -> None:
        out.write(json.dumps(obj) + "\n")
        out.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        method, rid = req.get("method"), req.get("id")

        # Notifications carry no id and get no reply.
        if rid is None and str(method or "").startswith("notifications/"):
            continue

        try:
            if method == "initialize":
                asked = (req.get("params") or {}).get("protocolVersion")
                result = {
                    "protocolVersion": asked if asked in MCP_PROTOCOL_VERSIONS
                                       else MCP_PROTOCOL_VERSIONS[0],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "actualis", "version": __version__},
                }
            elif method in ("tools/list", "server/discover"):
                result = {"tools": MCP_TOOLS, "ttlMs": 3_600_000, "cacheScope": "session"}
            elif method == "tools/call":
                params = req.get("params") or {}
                payload = _mcp_call(params.get("name"), params.get("arguments") or {}, cache)
                result = {"content": [{"type": "text",
                                       "text": json.dumps(payload, indent=2)}],
                          "structuredContent": payload,
                          "isError": False}
            elif method == "ping":
                result = {}
            else:
                if rid is not None:
                    send({"jsonrpc": "2.0", "id": rid,
                          "error": {"code": -32601, "message": f"method not found: {method}"}})
                continue
        except ValueError as exc:
            # Deliberate, client-facing: the message is the caller's own tool name.
            if rid is not None:
                send({"jsonrpc": "2.0", "id": rid,
                      "error": {"code": -32602, "message": str(exc)[:200]}})
            continue
        except Exception as exc:                      # never take the server down
            # Exception text routinely carries absolute filesystem paths, and this
            # reply is written straight into the agent's transcript — the artefact
            # this tool exists to keep clean. The detail goes to stderr instead,
            # which is the same reasoning shell_audit already applies to command text.
            print(f"actualis mcp: {type(exc).__name__}: {exc}", file=sys.stderr)
            if rid is not None:
                send({"jsonrpc": "2.0", "id": rid,
                      "error": {"code": -32603,
                                "message": f"internal error ({type(exc).__name__})"}})
            continue

        if rid is not None:
            send({"jsonrpc": "2.0", "id": rid, "result": result})
    return 0


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    def __init__(self, on: bool):
        self.dim = "\033[2m" if on else ""
        self.bold = "\033[1m" if on else ""
        self.red = "\033[31m" if on else ""
        self.yellow = "\033[33m" if on else ""
        self.green = "\033[32m" if on else ""
        self.cyan = "\033[36m" if on else ""
        self.ok = "\033[32m" if on else ""
        self.off = "\033[0m" if on else ""


def money(x: float) -> str:
    return f"${x:,.2f}"


def num(x: int) -> str:
    return f"{x:,}"


# --------------------------------------------------------------------------
# Output encoding
#
# The report uses a handful of non-ASCII glyphs. On a stream whose codec cannot
# represent them -- a Windows console or a redirect under a legacy locale --
# printing them raises UnicodeEncodeError and the whole run dies with a
# traceback instead of a report. The README claims cross-platform, and CI does
# test Windows, but only through in-process StringIO captures, which have no
# codec at all; nothing ever wrote to a real pipe there.
#
# Rather than crash or emit replacement characters, degrade to ASCII that says
# the same thing.

_GLYPH_FALLBACK = {
    "·": "*",      # separator between inline stats
    "—": "--",
    "…": "...",
    "▲": "!",      # a --watch alert
    "→": "->",
    "×": "x",      # cache multiplier
    "─": "-",      # section rule
    "█": "#",      # bar chart
}
_GLYPH_TABLE = str.maketrans(_GLYPH_FALLBACK)


def _stream_handles_glyphs(stream) -> bool:
    enc = getattr(stream, "encoding", None)
    if not enc:
        return True                    # StringIO and friends: no codec to fail
    try:
        "".join(_GLYPH_FALLBACK).encode(enc)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class _AsciiFallbackStream:
    """A text stream that swaps glyphs its codec cannot encode.

    Deliberately NOT used for --json: translating there would silently rewrite
    the data (a project name containing a middle dot would come back changed),
    and a machine-readable payload must be reproduced exactly.
    """

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(text.translate(_GLYPH_TABLE))

    def __getattr__(self, name):
        return getattr(self._stream, name)


def make_output_printable(json_mode: bool) -> None:
    """Guarantee that printing a report cannot raise on this terminal."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None or _stream_handles_glyphs(stream):
            continue
        if json_mode and name == "stdout":
            # JSON is defined in terms of Unicode; give it a codec that can
            # carry it rather than rewriting its content.
            try:
                stream.reconfigure(encoding="utf-8")
                continue
            except (AttributeError, OSError, ValueError):
                pass
        # errors="replace" is the backstop: it catches user data and any glyph
        # not in the table above, so a stray character can never be fatal.
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
        setattr(sys, name, _AsciiFallbackStream(stream))


def rule(c: C, title: str = "", width: int = 74) -> None:
    if title:
        pad = width - len(title) - 3
        print(f"\n{c.bold}{title}{c.off} {c.dim}{'─' * max(pad, 0)}{c.off}")
    else:
        print(f"{c.dim}{'─' * width}{c.off}")


def render_network(fleet: Fleet, c: C, top: int, raw: bool = False) -> None:
    """NETWORK: what came in, and from where; unasked first. Rows come from
    network_json, which is redacted unless raw; fleet.network_items is only
    counted here, never printed."""
    n = network_json(fleet, raw)
    t = n["totals"]
    rule(c, "NETWORK")
    if not t["items"]:
        print(f"  {c.dim}no downloads seen{c.off}")
        return
    print(f"  {num(t['items'])} download{'' if t['items'] == 1 else 's'} · {c.yellow}{num(t['unasked'])} unasked{c.off}"
          f" · {num(t['unknown'])} unknown"
          + (f" · {num(t['failed'])} failed" if t["failed"] else ""))
    if t["unknown"]:
        print(f"  {c.dim}unknown = default mode, where an allowlist rule may have approved it "
              f"without asking{c.off}")
    if fleet.network_trust_sources:
        parts = []
        for src in fleet.network_trust_sources:
            k = len(src["entries"])
            count = f"({k} {'entry' if k == 1 else 'entries'})"
            if src["source"] == "file":
                parts.append(f".actualis-network-trust {src.get('path')} "
                             f"sha256 {(src.get('sha256') or '')[:12]} {count}")
            else:
                parts.append(f"--network-trust {count}")
        print(f"  {c.dim}trust: {' · '.join(parts)}{c.off}")
    items = fleet.network_items

    eco = Counter(i["ecosystem"] for i in items if i["kind"] == "install" and i["ecosystem"])
    unpinned = sum(1 for p in n["packages"] if not p["pinned"])
    if eco:
        parts = " · ".join(f"{k} {num(v)}" for k, v in sorted(eco.items(), key=lambda kv: (-kv[1], kv[0])))
        print(f"  {'INSTALLED':<11} {parts}"
              + (f"   {c.dim}{num(unpinned)} unpinned package(s){c.off}" if unpinned else ""))

    clones = Counter(i["host"] or "(remote name)" for i in items if i["kind"] == "clone")
    if clones:
        parts = " · ".join(f"{h} {num(v)}" for h, v in sorted(clones.items(), key=lambda kv: (-kv[1], kv[0]))[:top])
        print(f"  {'CLONED':<11} {num(sum(clones.values()))}   {parts}")

    fetches = [i for i in items if i["kind"] in ("fetch", "search")]
    if fetches:
        fhosts = {i["host"] for i in fetches if i["host"]}
        print(f"  {'FETCHED':<11} {num(len(fetches))}   {num(len(fhosts))} host(s)")

    rows = [i for i in n["items"] if i["approval"] in ("unasked", "unknown")]
    rows.sort(key=lambda i: i["approval"] != "unasked")   # stable: newest-first within each
    last = None
    for i in rows[:top]:
        label = i["approval"].upper() if i["approval"] != last else ""
        last = i["approval"]
        what = i["url"] or i["package"] or ""
        room = 32 - len(i["program"]) - 1
        if what and len(what) > room:
            what = what[:max(room - 1, 1)] + "\u2026"
        target = f"{i['program']} {what}".rstrip()
        print(f"  {label:<9}{clip(i['host'] or '?', 26):<26} {target[:32]:<32}"
              f" {c.dim}{clip(i['project'], 10):<10} {(i['ts'] or '')[:10]} {i['approval']}{c.off}")


def render(fleet: Fleet, c: C, bash_only: bool, top: int, raw: bool = False) -> None:
    span = fleet.span_days
    active = fleet.active_days

    if not bash_only:
        rule(c, "FLEET")
        rng = "no data"
        if fleet.first_ts and fleet.last_ts:
            rng = (f"{fleet.first_ts.date()} → {fleet.last_ts.date()}  "
                   f"({span:.0f} days)")
        print(f"  window        {rng}")
        print(f"  transcripts   {num(fleet.files_scanned)} files, "
              f"{fleet.bytes_scanned / 1e9:.2f} GB")
        for r in fleet.roots:
            print(f"  {c.dim}source        {r}{c.off}")
        print(f"  messages      {num(fleet.messages)}")
        # Printed so a screenshot of this report can be checked against the
        # --json payload it came from. Same fleet, same digest.
        print(f"  {c.dim}digest        {report_digest(_to_json_body(fleet)):.16}"
              f"  (sha256, first 16){c.off}")
        if fleet.duplicate_usage_records:
            # Shown rather than hidden: this number is the difference between
            # the old headline and the real one, and a reader who saw the old
            # figure deserves to see why it moved.
            print(f"  {c.dim}repeats       {num(fleet.duplicate_usage_records)} "
                  f"records collapsed (one message, many transcript rows){c.off}")
        # A total mixing published prices with inferences is only as sound as
        # its weakest component. Saying so costs one line; not saying it lets an
        # estimate read as a measurement.
        if fleet.total_cost > 0 and fleet.confident_pct < 99.5:
            tiers = ", ".join(f"{k} {money(v)}" for k, v in
                              sorted(fleet.cost_by_tier.items(),
                                     key=lambda kv: RATE_TIERS.index(kv[0])))
            print(f"  {c.dim}priced from   {fleet.confident_pct:.0f}% published rates "
                  f"· {tiers}{c.off}")
        age = pricing_age_days()
        if age > PRICING_STALE_DAYS:
            print(f"  {c.yellow}▲ rates       last verified {PRICING_VERIFIED}, "
                  f"{age} days ago. Prices move; treat this as dated.{c.off}")
        if fleet.cost_unknown > 0:
            print(f"  {c.dim}unpriced      {money(fleet.cost_unknown)} of the total "
                  f"is from models with no published rate{c.off}")
        tok = sum(fleet.tokens.values())
        print(f"  tokens        {num(tok)}")
        print(f"  {c.bold}cost{c.off}          {c.bold}{money(fleet.total_cost)}{c.off} "
              f"{c.dim}notional, at API list price{c.off}")
        if fleet.copilot_unpriced:
            n_u = fleet.copilot_unpriced
            print(f"  {c.dim}{n_u} Copilot session{'s' if n_u != 1 else ''} "
                  f"unpriced (no shutdown record){c.off}")
        if active >= 2:
            per_day = fleet.total_cost / active
            print(f"  {c.dim}per active day {money(per_day)}"
                  f"   ·  per week {money(per_day * 7)}"
                  f"   ·  {active} active days of {fleet.span_dates}{c.off}")

        rule(c, "TOKENS")
        for k, label in (("input", "input"), ("output", "output"),
                         ("cache_w_1h", "cache write 1h  ×2.00"),
                         ("cache_w_5m", "cache write 5m  ×1.25"),
                         ("cache_w_assumed", "cache write ?   ×2.00"),
                         ("cache_read", "cache read      ×0.10")):
            v = fleet.tokens.get(k, 0)
            # The assumed bucket is only shown when it is non-zero: a row of
            # zeroes explaining an inference nobody's data triggered is noise.
            if k == "cache_w_assumed" and not v:
                continue
            pct = (v / tok * 100) if tok else 0
            print(f"  {label:<22} {num(v):>16}  {c.dim}{pct:5.1f}%{c.off}")
        if fleet.tokens.get("cache_w_assumed"):
            print(f"  {c.dim}cache write ? is a record with no TTL split; priced at the "
                  f"1h rate.{c.off}")
            print(f"  {c.dim}See --explain cache. Measured mix on records that do carry "
                  f"it: 95% 1h.{c.off}")

        if len(fleet.cost_by_agent) > 1:
            rule(c, "BY AGENT")
            print(f"  {'agent':<22} {'units':>9} {'cost':>13}   share")
            for a, cost in sorted(fleet.cost_by_agent.items(), key=lambda kv: -kv[1]):
                share = (cost / fleet.total_cost * 100) if fleet.total_cost else 0
                unit = "messages" if a == "claude-code" else "sessions"
                print(f"  {a:<22} {num(fleet.units_by_agent[a]):>9} {money(cost):>13}   "
                      f"{c.dim}{share:5.1f}%  {unit}{c.off}")

        rule(c, "BY MODEL")
        print(f"  {'model':<22} {'msgs':>9} {'cost':>13}   share")
        for m, cost in sorted(fleet.cost_by_model.items(), key=lambda kv: -kv[1]):
            share = (cost / fleet.total_cost * 100) if fleet.total_cost else 0
            print(f"  {m:<22} {num(fleet.msgs_by_model[m]):>9} {money(cost):>13}   "
                  f"{c.dim}{share:5.1f}%{c.off}")

        rule(c, f"BY PROJECT  (top {top})")
        projects = sorted(fleet.cost_by_project.items(), key=lambda kv: -kv[1])
        for p, cost in projects[:top]:
            share = (cost / fleet.total_cost * 100) if fleet.total_cost else 0
            bar = "█" * max(int(share / 3), 0)
            hi = c.yellow if share >= 50 else ""
            print(f"  {money(cost):>12}  {hi}{share:5.1f}%{c.off} {c.cyan}{bar}{c.off} {p[:44]}")
        if len(projects) > top:
            rest = sum(v for _, v in projects[top:])
            print(f"  {money(rest):>12}  {c.dim}{len(projects) - top} more{c.off}")
        if projects:
            top_share = projects[0][1] / fleet.total_cost * 100 if fleet.total_cost else 0
            if top_share >= 50:
                print(f"\n  {c.yellow}▲{c.off} {top_share:.0f}% of all spend is one project: "
                      f"{c.bold}{projects[0][0]}{c.off}")

        if fleet.tokens_by_project:
            rows = []
            for proj, t in fleet.tokens_by_project.items():
                ctx = t["input"] + t["cache_w"] + t["cache_read"]
                # Same eligibility as AF002, or the section flags projects the
                # coach will never mention. A $4 worktree at 78% is noise.
                if ctx < 1_000_000 or fleet.cost_by_project.get(proj, 0) < MIN_PROJECT_COST:
                    continue
                rows.append((proj, cache_hit_rate(t), ctx,
                             fleet.cache_uncached[proj] - fleet.cache_actual[proj],
                             fleet.cost_by_project.get(proj, 0.0)))
            if rows:
                rows.sort(key=lambda r: -r[2])
                med_pre = _median([r[1] for r in rows])
                shown = rows[:top]
                # A project called out as an outlier must be visible, even when
                # it is too small to make the top-N by context volume.
                shown += [r for r in rows[top:] if r[1] < med_pre - 15]
                saved = sum(fleet.cache_uncached.values()) - sum(fleet.cache_actual.values())
                allctx = Counter()
                for t in fleet.tokens_by_project.values():
                    allctx.update(t)
                fleet_rate = cache_hit_rate(allctx)
                med = _median([r[1] for r in rows])

                rule(c, "CACHE EFFICIENCY")
                print(f"  fleet hit rate  {c.bold}{fleet_rate:.1f}%{c.off} of input context "
                      f"served from cache")
                print(f"  saved           {c.bold}{money(saved)}{c.off} {c.dim}versus sending "
                      f"the same context uncached{c.off}")
                print(f"\n  {'hit rate':>9}  {'context':>14}  {'saved':>11}  project")
                for proj, rate, ctx, sv, _cost in shown:
                    col = c.ok if rate >= med else (c.yellow if rate >= med - 15 else c.red)
                    print(f"  {col}{rate:>8.1f}%{c.off}  {num(ctx):>14}  {money(sv):>11}  "
                          f"{proj[:40]}")
                low = [r for r in rows if r[1] < med - 15]
                if low:
                    print(f"\n  {c.yellow}▲{c.off} {len(low)} project(s) more than 15 points "
                          f"below your median of {med:.1f}%. See AF002.")
                else:
                    print(f"\n  {c.dim}No project is more than 15 points below your median "
                          f"of {med:.1f}%.{c.off}")

        if fleet.cost_by_ticket:
            tickets = sorted(fleet.cost_by_ticket.items(), key=lambda kv: -kv[1])
            ticketed = sum(fleet.cost_by_ticket.values())
            trunk = fleet.cost_by_branch.get("trunk", 0.0)
            detached = fleet.cost_by_branch.get("detached HEAD", 0.0)

            rule(c, f"BY TICKET  (top {min(top, len(tickets))} of {len(tickets)})")
            print(f"  {'cost':>11}  {'ticket':<10} {'msgs':>8}  {'days':>5}  where")
            for t, cost in tickets[:top]:
                days = fleet.dates_by_ticket.get(t, [])
                span = f"{len(set(days))}" if days else "?"
                brs = fleet.branches_by_ticket[t]
                where = ", ".join(sorted(brs)[:2])
                if len(brs) > 2:
                    where += f" +{len(brs) - 2}"
                print(f"  {money(cost):>11}  {c.bold}{t:<10}{c.off} "
                      f"{num(fleet.msgs_by_ticket[t]):>8}  {span:>5}  {where[:44]}")

            multi = [t for t, b in fleet.branches_by_ticket.items() if len(b) > 1]
            print(f"\n  {c.dim}{money(ticketed)} attributed to {len(tickets)} tickets"
                  + (f" ({len(multi)} spanning several branches)" if multi else "")
                  + f"  ·  {money(trunk)} on trunk"
                  + (f"  ·  {money(detached)} detached HEAD" if detached else "")
                  + f"{c.off}")
            if detached > 0:
                print(f"  {c.dim}Detached HEAD is usually a git worktree; that spend "
                      f"cannot be attributed to a ticket.{c.off}")

        if fleet.sub_calls:
            rule(c, "SUBAGENTS")
            hrs = fleet.sub_ms / 3_600_000
            print(f"  {num(fleet.sub_calls)} runs  ·  {hrs:.1f} hours wall-clock  ·  "
                  f"{num(fleet.sub_lines['added'])} lines added, "
                  f"{num(fleet.sub_lines['removed'])} removed")
            for m, n in fleet.sub_by_model.most_common():
                print(f"    {num(n):>6}  {m}")
            print(f"\n  {c.dim}tool activity{c.off}  "
                  f"bash {num(fleet.sub_tools['bashCount'])}  ·  "
                  f"read {num(fleet.sub_tools['readCount'])}  ·  "
                  f"edit {num(fleet.sub_tools['editFileCount'])}")
            print(f"  {c.dim}cost floor{c.off}     {money(fleet.sub_cost_floor)} "
                  f"{c.dim}— a LOWER BOUND, not a total, and excluded from the "
                  f"headline figure{c.off}")
            print(f"  {c.dim}Only each run's final message is recorded in the parent")
            print(f"  transcript, so the cumulative cost of a subagent's turns cannot")
            print(f"  be recovered. It is not estimated here.{c.off}")

        rule(c, "TOOL CALLS")
        total_tools = sum(fleet.tools.values())
        for name, n in fleet.tools.most_common(10):
            pct = n / total_tools * 100 if total_tools else 0
            print(f"  {name:<22} {num(n):>9}  {c.dim}{pct:5.1f}%{c.off}")

    # ---- shell audit -----------------------------------------------------

    if fleet.unreadable:
        pct = fleet.unreadable / fleet.bash_total * 100 if fleet.bash_total else 0
        print(f"\n  {c.dim}unreadable{c.off}  {num(fleet.unreadable)} commands "
              f"({pct:.1f}%) ran something this transcript does not contain")
        for name, n in fleet.unreadable_shapes.most_common(6):
            print(f"    {c.dim}{name:<30}{num(n):>7}{c.off}")
        print(f"  {c.dim}Not a finding. A script is normal; this is what the audit "
              f"could not see.{c.off}")

    if fleet.oversized_commands:
        print(f"\n  {c.yellow}▲{c.off} {num(fleet.oversized_commands)} commands over 32 KB "
              f"were only partly audited")

    if fleet.refusals:
        rule(c, "REFUSALS")
        print(f"  {c.dim}What was stopped, and by whom. A refused command is never "
              f"sent,{c.off}")
        print(f"  {c.dim}so this exists only in your local transcripts.{c.off}")
        if "codex" in fleet.cost_by_agent:
            print(f"  {c.yellow}▲{c.off} {c.dim}Codex writes no per-refusal record, so "
                  f"its sessions are absent here.{c.off}")
        print()
        gates = sorted(fleet.refusal_tool,
                       key=lambda k: -sum(fleet.refusal_tool[k].values()))
        for kind in gates:
            who = "a human" if kind in HUMAN_REFUSALS else "the policy"
            n = sum(fleet.refusal_tool[kind].values())
            print(f"  {c.bold}{kind}{c.off}  {c.dim}{n} · {who}{c.off}")
            tools = ", ".join(f"{t} {v}" for t, v in fleet.refusal_tool[kind].most_common(4))
            print(f"    tools     {tools}")
            progs = fleet.refusal_program.get(kind)
            if progs:
                print(f"    programs  "
                      + "  ".join(f"{p}:{v}" for p, v in progs.most_common(8)))
        if len(fleet.refusal_week) > 1:
            wk = sorted(fleet.refusal_week.items())
            spark = "  ".join(f"{w.split('-W')[1]}:{sum(v.values())}" for w, v in wk[-8:])
            print(f"\n  {c.dim}by week   {spark}{c.off}")
        print(f"  {c.dim}This machine only. Refusals are not deduplicated across "
              f"developers.{c.off}")
        print()

    rule(c, "SHELL AUDIT")
    total_tools = sum(fleet.tools.values())
    share = fleet.tools.get("Bash", 0) / total_tools * 100 if total_tools else 0
    print(f"  bash calls    {num(fleet.bash_total)}  "
          f"{c.dim}{share:.0f}% of all agent tool calls{c.off}")
    sub_bash = fleet.sub_tools.get("bashCount", 0)
    if sub_bash:
        blind = sub_bash / (fleet.bash_total + sub_bash) * 100
        print(f"  {c.yellow}unauditable{c.off}   {num(sub_bash)} more shell commands ran "
              f"inside subagents {c.dim}({blind:.0f}% of all shell activity){c.off}")
        print(f"  {c.dim}Their command text is not written to the parent transcript, so "
              f"nothing below covers them.{c.off}")

    if fleet.permission_modes:
        modes = "  ".join(f"{k}={num(v)}" for k, v in fleet.permission_modes.most_common(5))
        print(f"  permission    {modes}")
    if fleet.denials:
        den = "  ".join(f"{k}={num(v)}" for k, v in fleet.denials.most_common(5))
        print(f"  denied        {den}")

    print(f"\n  {c.dim}most-run commands{c.off}")
    for cmd, n in fleet.bash_first_token.most_common(12):
        print(f"    {num(n):>7}  {cmd[:40]}")

    if fleet.secrets:
        order = {"critical": 0, "high": 1, "low": 2}
        rows = sorted(fleet.secrets.items(),
                      key=lambda kv: (order.get(kv[1]["priority"], 9), -kv[1]["uses"]))
        distinct = len(rows)
        actionable = sum(1 for _, e in rows
                         if e["priority"] != "low" and not e.get("suppressed"))
        suppressed = fleet.suppressed_secrets

        print(f"\n  {c.red}▲ {num(distinct)} distinct secrets{c.off} exposed across "
              f"{num(fleet.secret_exposures)} commands "
              f"{c.dim}({num(actionable)} worth rotating"
              + (f", {num(suppressed)} suppressed" if suppressed else "")
              + f"){c.off}")
        print(f"\n  {'':<9} {'type':<26} {'uses':>6}  {'first':<11} {'last':<11} id")
        for fp, e in rows[:24]:
            pri = e["priority"]
            col = c.red if pri == "critical" else (c.yellow if pri == "high" else c.dim)
            mark = "ROTATE" if pri == "critical" else ("rotate" if pri == "high" else "dev")
            if e.get("suppressed"):
                col, mark = c.dim, "muted"
            kind = ", ".join(sorted(e["kinds"]))
            print(f"    {col}{mark:<7}{c.off} {kind[:26]:<26} {num(e['uses']):>6}  "
                  f"{(e['first'] or '?'):<11} {(e['last'] or '?'):<11} {c.dim}{fp}{c.off}")
            if e.get("distinct_values", 1) > 1:
                print(f"            {c.dim}{e['distinct_values']} distinct values"
                      + (f"; {e['suppressed_reason']}" if e.get("suppressed_reason", "").startswith(
                          "suppression covers") else "") + f"{c.off}")
        if len(rows) > 24:
            print(f"    {c.dim}… {len(rows) - 24} more{c.off}")
        print(f"\n    {c.dim}id is a fingerprint of the secret, or for a password, of where it")
        print(f"    appeared; the value is never stored or printed. Same secret reused 200")
        print(f"    times counts once. Rotate in the order shown, then purge the")
        print(f"    transcripts that carry them.{c.off}")
        # In place, where the finding is, rather than in documentation nobody
        # reads at the moment they disagree with it.
        print(f"\n    {c.dim}Not a credential? Say so:{c.off}")
        print(f"      actualis --suppress <id> --reason \"why it is not\"")
        print(f"    {c.dim}It stays counted and stays in --json; it leaves this list.{c.off}")
        first_wrong = next((fp for fp, e in rows if not e.get("suppressed")), None)
        if first_wrong:
            kinds = ", ".join(sorted(fleet.secrets[first_wrong]["kinds"]))[:40]
            print(f"    {c.dim}Wrong for everyone, not just you? Report it:{c.off}")
            print(f"      {c.dim}{report_url(kinds, 'id ' + first_wrong)[:96]}…{c.off}")

    highs = [f for f in fleet.actionable_flags if f["severity"] == "high"]
    meds = [f for f in fleet.actionable_flags if f["severity"] == "med"]

    print(f"\n  {c.dim}flagged{c.off}   "
          f"{c.red}{len(highs)} high{c.off}   {c.yellow}{len(meds)} medium{c.off}   "
          f"{c.dim}of {num(fleet.bash_total)} commands"
          + (f", {num(fleet.suppressed_flags)} suppressed" if fleet.suppressed_flags else "")
          + f"{c.off}")

    if fleet.flag_counts:
        print(f"\n  {c.dim}by category{c.off}")
        for key, n in sorted(fleet.flag_counts.items(), key=lambda kv: -kv[1]):
            sev, cat = key.split(":", 1)
            col = c.red if sev == "high" else c.yellow
            print(f"    {col}{sev:<5}{c.off} {cat:<14} {num(n):>7}")

    if highs:
        print(f"\n  {c.red}high-severity{c.off} {c.dim}(most recent 15, matching line shown){c.off}")
        for f in sorted(highs, key=lambda x: x["when"] or "", reverse=True)[:15]:
            when = (f["when"] or "")[:10]
            cats = ",".join(f["categories"])
            line = f["evidence"] if raw else redact(f["evidence"])
            mark = f" {c.red}[secret]{c.off}" if f.get("had_secret") else ""
            print(f"\n    {c.dim}{when}{c.off} {c.red}{cats}{c.off}{mark}")
            print(f"    {line[:150]}")
            print(f"      {c.dim}{f['project'][:66]}{c.off}")

    render_network(fleet, c, top, raw)

    if not bash_only:
        render_coach(coach(fleet), c)

    if fleet.unknown_models:
        print(f"\n  {c.yellow}▲{c.off} unpriced models seen, billed at Opus-tier rates: "
              f"{', '.join(fleet.unknown_models)}")

    if fleet.aggregator_models:
        print(f"\n  {c.yellow}▲{c.off} priced from a third party, not the vendor's own "
              f"list: {', '.join(fleet.aggregator_models)}")
        print(f"    {c.dim}The rate is probably right; nobody authoritative has "
              f"published it.{c.off}")

    print()
    print(f"{c.dim}  Ask how any of this was computed:  actualis --explain")
    print(f"  Ask why a finding fired:            actualis --why AF004{c.off}")
    print()
    print(f"{c.dim}  Costs are Anthropic API list prices (verified 2026-08-22). On a Pro/Max")
    print(f"  subscription your actual outlay is the flat fee; read this as consumption.")
    print(f"  Flags mean 'worth looking at', not 'wrong'. Nothing left this machine.")
    if not raw:
        print(f"  Credentials are redacted; --no-redact disables that.{c.off}")
    else:
        print(f"  {c.red}--no-redact is on: this output may contain live secrets.{c.off}")
    print()


def render_share(fleet: "Fleet", c: C) -> None:
    """A postable summary containing nothing that identifies you.

    Emits shapes only: totals, rates, distributions, and generic finding titles.
    Never a project name, branch, ticket id, path, command, or fingerprint.
    Everything printed here is derived from counts, and the leak test in
    tests/ asserts that identifying strings cannot reach this output.
    """
    tok = sum(fleet.tokens.values())
    ctx = Counter()
    for t in fleet.tokens_by_project.values():
        ctx.update(t)
    hit = cache_hit_rate(ctx)
    saved = sum(fleet.cache_uncached.values()) - sum(fleet.cache_actual.values())

    projects = sorted(fleet.cost_by_project.values(), reverse=True)
    conc = (projects[0] / fleet.total_cost * 100) if projects and fleet.total_cost else 0

    modes = sum(fleet.permission_modes.values())
    unsup = ungated_modes(fleet.permission_modes)
    unsup_pct = (unsup / modes * 100) if modes else 0

    sub_bash = fleet.sub_tools.get("bashCount", 0)
    blind = (sub_bash / (fleet.bash_total + sub_bash) * 100) if (fleet.bash_total + sub_bash) else 0

    tools_total = sum(fleet.tools.values())
    bash_pct = (fleet.bash_total / tools_total * 100) if tools_total else 0

    crit = sum(1 for e in fleet.secrets.values() if e["priority"] == "critical")
    rotate = sum(1 for e in fleet.secrets.values() if e["priority"] != "low")

    tickets = sorted(fleet.cost_by_ticket.values())
    med_ticket = _median(tickets) if tickets else 0.0

    b = c.bold
    o = c.off
    d = c.dim

    print(f"\n{b}  ACTUALIS{o} {d}· what actually ran{o}\n")
    print(f"  {fleet.active_days} active days   "
          f"{len(fleet.cost_by_agent)} agent(s)   "
          f"{num(fleet.messages)} messages   {num(tok)} tokens")
    print()
    print(f"  {b}{money(fleet.total_cost)}{o} at API list price"
          + (f"   ·   {money(fleet.total_cost / fleet.active_days)}/active day"
             if fleet.active_days > 1 else ""))
    if saved > 0:
        print(f"  {b}{hit:.1f}%{o} of input context from cache, saving "
              f"{b}{money(saved)}{o} against sending it uncached")
    if conc >= 25:
        print(f"  {b}{conc:.0f}%{o} of spend in a single project")
    if tickets:
        print(f"  {b}{money(med_ticket)}{o} median cost per ticket, "
              f"over {num(len(tickets))} tickets")
    print()
    plural = "" if fleet.bash_total == 1 else "s"
    print(f"  {b}{num(fleet.bash_total)}{o} shell command{plural}   "
          f"{d}{bash_pct:.0f}% of all tool calls{o}")
    if modes:
        print(f"  {b}{unsup_pct:.0f}%{o} of turns ran unsupervised")
    if sub_bash:
        print(f"  {b}{blind:.0f}%{o} of shell activity happened inside subagents, "
              f"where the commands are not recorded")
    if fleet.secrets:
        print(f"  {b}{num(len(fleet.secrets))}{o} distinct credentials found in command "
              f"history   {d}{num(crit)} critical, {num(rotate)} worth rotating{o}")

    if fleet.msgs_by_model:
        # Through the same gate as the card: a fine-tune id is identifying.
        shown: Counter = Counter()
        for m, n in fleet.msgs_by_model.items():
            if m != "<synthetic>":
                shown[card_model_name(m)] += n
        print(f"\n  {d}models{o}  " + "   ".join(
            f"{m} {n / sum(fleet.msgs_by_model.values()) * 100:.0f}%"
            for m, n in shown.most_common(4)))

    findings = coach(fleet)
    if findings:
        print(f"\n  {d}coach{o}   " + "  ".join(f.id for f in findings))
        for f in findings[:4]:
            print(f"    {d}{f.id}  {f.title}{o}")

    print(f"\n  {d}Generated locally by actualis. No project names, branches,")
    print(f"  paths, commands or identifiers are included in this summary.")
    print(f"  Costs are Anthropic and OpenAI list prices; a subscription bills a")
    print(f"  flat fee, so read this as consumption.{o}\n")


# --------------------------------------------------------------------------
# Card
#
# --share for people who scroll rather than read: one image, one number. The
# pipeline is Fleet -> card_model -> layout -> draw ops -> SVG and PNG, and
# only card_model reads Fleet. Everything it returns is a count, a fixed word,
# or a public model name, which is what the leak test checks -- so the layouts
# and writers below it cannot leak by construction.
# --------------------------------------------------------------------------

CARD_MODES = ("supervision", "cost", "volume")
CARD_STYLES = ("hero", "terminal")
CARD_INSTALL = "uv tool install actualis"
CARD_MIN_TREND_DAYS = 3
_CARD_CATEGORIES = ("git", "test", "install", "other")


class CardError(Exception):
    """This window cannot be drawn honestly in this mode. The message says why."""


def card_model_name(model: str) -> str:
    """A model id only when it is a public catalog name in the price table.

    Everything else -- a fine-tune, a private deployment, a family guess -- is
    `custom`. A family match would let `ft:gpt-5-acme-internal` through.
    """
    return model if model in PRICING else "custom"


def _whole_money(x: float) -> str:
    return f"${x:,.0f}"


def _fraction(x: float) -> str:
    return f"{x:,.2f}".rstrip("0").rstrip(".")


def card_window(fleet: "Fleet", days: int | None, today: date | None = None) -> list[str]:
    """ISO dates the card covers, oldest first. With --days, the last N dates
    including today, matching window_start; otherwise first to last record."""
    if days:
        end = today or datetime.now(timezone.utc).date()
        return [(end - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    dates = sorted(set(fleet.cost_by_day) | set(fleet.bash_by_day))
    if not dates:
        return []
    start = date.fromisoformat(dates[0])
    span = (date.fromisoformat(dates[-1]) - start).days + 1
    return [(start + timedelta(days=i)).isoformat() for i in range(span)]


def card_model(fleet: "Fleet", mode: str, days: int | None = None,
               today: date | None = None) -> dict:
    """Every number and word a card shows, and nothing else."""
    window = card_window(fleet, days, today)
    n = len(window)
    commands = fleet.bash_total
    if mode in ("supervision", "volume") and commands == 0:
        raise CardError("no shell commands in window — try --days or --card cost")
    agents = str(len(fleet.agents_seen))
    refused = num(fleet.refusals)
    m: dict = {"mode": mode, "days": n, "label": f"ACTUALIS · LAST {n} DAYS"}

    if mode == "supervision":
        moded = sum(fleet.bash_moded_by_day.values())
        unsup = sum(fleet.unsupervised_by_day.values())
        if moded:
            m["hero"] = f"{unsup / moded * 100:.0f}%"
            m["caption"] = "of my agents' shell commands ran with nobody approving them"
            m["share"] = (f"{m['hero']} of my coding agents' shell commands ran "
                          f"unsupervised in the last {n} days. {CARD_INSTALL}")
        else:
            m["hero"] = "—"
            m["caption"] = "no permission mode was recorded for these commands"
            m["share"] = (f"My coding agents ran {num(commands)} shell commands in "
                          f"the last {n} days. {CARD_INSTALL}")
        m.update(header="SUPERVISION", hero_label="unsupervised",
                 stats=[(num(commands), "commands"), (refused, "refused"), (agents, "agents")],
                 bars=[("auto", float(unsup), num(unsup)),
                       ("you", float(moded - unsup), num(moded - unsup)),
                       ("refused", float(fleet.refusals), refused)],
                 series=[(fleet.unsupervised_by_day[d] / fleet.bash_moded_by_day[d] * 100)
                         if fleet.bash_moded_by_day[d] else None for d in window],
                 series_max=100.0)
    elif mode == "cost":
        total = fleet.total_cost
        saved = max(sum(fleet.cache_uncached.values()) - sum(fleet.cache_actual.values()), 0.0)
        priced = total > 0
        m["hero"] = _whole_money(total) if priced else "—"
        m["caption"] = f"at API list price, last {n} days" if priced else "no priced usage in window"
        m["share"] = (f"My coding agents used {m['hero']} of compute at API list price "
                      f"in the last {n} days. {CARD_INSTALL}" if priced else
                      f"What my coding agents actually ran, last {n} days. {CARD_INSTALL}")
        stats = [(_whole_money(total / fleet.active_days) if priced else "—", "per active day"),
                 (_whole_money(saved) if priced else "—", "cache saved"), (agents, "agents")]
        premium = fleet.premium_requests_by_agent.get("copilot", 0.0)
        if premium:
            stats.append((_fraction(premium), "premium requests"))
        by_name: Counter = Counter()
        for model, cost in fleet.cost_by_model.items():
            by_name[card_model_name(model)] += cost
        m.update(header="COST", hero_label="at list price", stats=stats,
                 bars=[(name, cost, _whole_money(cost)) for name, cost in by_name.most_common(3)],
                 series=[fleet.cost_by_day.get(d, 0.0) for d in window])
    elif mode == "volume":
        tools = sum(fleet.tools.values())
        m.update(header="SHELL", hero=num(commands), hero_label="commands",
                 caption="shell commands my agents ran",
                 share=(f"My coding agents ran {num(commands)} shell commands in the "
                        f"last {n} days. {CARD_INSTALL}"),
                 stats=[(f"{commands / tools * 100:.0f}%" if tools else "—", "of tool calls"),
                        (refused, "refused"), (agents, "agents")],
                 bars=[(cat, float(fleet.bash_categories[cat]), num(fleet.bash_categories[cat]))
                       for cat in _CARD_CATEGORIES],
                 series=[float(fleet.bash_by_day.get(d, 0)) for d in window])
    else:
        raise ValueError(f"unknown card mode {mode!r}")

    if mode != "supervision":
        m["series_max"] = max([v for v in m["series"] if v] or [1.0])
    active = sum(1 for v in m["series"]
                 if v is not None and (mode == "supervision" or v > 0))
    m["trend"] = active >= CARD_MIN_TREND_DAYS
    return m


# CARD_FONT glyphs are from Spleen 2.2.0 (8x16), redistributed under its license:
# Copyright (c) 2018-2026, Frederic Cambus
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

CARD_FONT: dict[str, str] = {
    ' ': '00000000000000000000000000000000',
    '!': '00001818181818181800181800000000',
    '"': '00666666660000000000000000000000',
    '#': '00006c6cfe6c6c6c6cfe6c6c00000000',
    '$': '00107ed0d0d07c16161616fc10000000',
    '%': '000006666c0c18183036666000000000',
    '&': '0000386c6c6c3870dacccc7a00000000',
    "'": '00181818180000000000000000000000',
    '(': '000e183030606060603030180e000000',
    ')': '0070180c0c060606060c0c1870000000',
    '*': '00000000663c18ff183c660000000000',
    '+': '000000000018187e1818000000000000',
    ',': '00000000000000000000181830000000',
    '-': '000000000000007e0000000000000000',
    '.': '00000000000000000000181800000000',
    '/': '0006060c0c181830306060c0c0000000',
    '0': '00007cc6c6cedef6e6c6c67c00000000',
    '1': '00001838785818181818187e00000000',
    '2': '00007cc606060c183060c6fe00000000',
    '3': '00007cc606063c060606c67c00000000',
    '4': '0000c0c0ccccccccfe0c0c0c00000000',
    '5': '0000fec6c0c0fc060606c67c00000000',
    '6': '00007cc6c0c0fcc6c6c6c67c00000000',
    '7': '0000fec606060c183030303000000000',
    '8': '00007cc6c6c67cc6c6c6c67c00000000',
    '9': '00007cc6c6c6c67e0606c67c00000000',
    ':': '00000000001818000000181800000000',
    ';': '00000000001818000000181830000000',
    '<': '0000060c1830606030180c0600000000',
    '=': '00000000007e00007e00000000000000',
    '>': '00006030180c06060c18306000000000',
    '?': '00007cc6060c18303000303000000000',
    '@': '0000007cc2dadadadadec07c00000000',
    'A': '00007cc6c6c6fec6c6c6c6c600000000',
    'B': '0000fcc6c6c6fcc6c6c6c6fc00000000',
    'C': '00007ec0c0c0c0c0c0c0c07e00000000',
    'D': '0000fcc6c6c6c6c6c6c6c6fc00000000',
    'E': '00007ec0c0c0f8c0c0c0c07e00000000',
    'F': '00007ec0c0c0f8c0c0c0c0c000000000',
    'G': '00007ec0c0c0dec6c6c6c67e00000000',
    'H': '0000c6c6c6c6fec6c6c6c6c600000000',
    'I': '00007e18181818181818187e00000000',
    'J': '00007e1818181818181818f000000000',
    'K': '0000c6c6c6ccf8ccc6c6c6c600000000',
    'L': '0000c0c0c0c0c0c0c0c0c07e00000000',
    'M': '0000c6eefed6c6c6c6c6c6c600000000',
    'N': '0000c6c6e6e6d6d6cecec6c600000000',
    'O': '00007cc6c6c6c6c6c6c6c67c00000000',
    'P': '0000fcc6c6c6fcc0c0c0c0c000000000',
    'Q': '00007cc6c6c6c6c6c6d6d67c180c0000',
    'R': '0000fcc6c6c6fcc6c6c6c6c600000000',
    'S': '00007ec0c0c07c06060606fc00000000',
    'T': '0000ff18181818181818181800000000',
    'U': '0000c6c6c6c6c6c6c6c6c67e00000000',
    'V': '0000c6c6c6c6c6c6c66c381000000000',
    'W': '0000c6c6c6c6c6c6d6feeec600000000',
    'X': '0000c6c6c66c386cc6c6c6c600000000',
    'Y': '0000c6c6c6c67e06060606fc00000000',
    'Z': '0000fe06060c183060c0c0fe00000000',
    '[': '003e303030303030303030303e000000',
    '\\': '00c0c06060303018180c0c0606000000',
    ']': '007c0c0c0c0c0c0c0c0c0c0c7c000000',
    '^': '0010386cc60000000000000000000000',
    '_': '0000000000000000000000000000fe00',
    '`': '0030180c000000000000000000000000',
    'a': '00000000007c067ec6c6c67e00000000',
    'b': '0000c0c0c0fcc6c6c6c6c6fc00000000',
    'c': '00000000007ec0c0c0c0c07e00000000',
    'd': '00000606067ec6c6c6c6c67e00000000',
    'e': '00000000007ec6c6fec0c07e00000000',
    'f': '00001e3030307c303030303000000000',
    'g': '00000000007ec6c6c6c6c67c0606fc00',
    'h': '0000c0c0c0fcc6c6c6c6c6c600000000',
    'i': '00001818003818181818181c00000000',
    'j': '00001818001818181818181818187000',
    'k': '0000c0c0c0ccd8f0f0d8ccc600000000',
    'l': '00003030303030303030301c00000000',
    'm': '0000000000ecd6d6d6d6c6c600000000',
    'n': '0000000000fcc6c6c6c6c6c600000000',
    'o': '00000000007cc6c6c6c6c67c00000000',
    'p': '0000000000fcc6c6c6c6c6fcc0c0c000',
    'q': '00000000007ec6c6c6c6c67e06060600',
    'r': '00000000007ec6c0c0c0c0c000000000',
    's': '00000000007ec0c07c0606fc00000000',
    't': '00003030307c30303030301e00000000',
    'u': '0000000000c6c6c6c6c6c67e00000000',
    'v': '0000000000c6c6c6c66c381000000000',
    'w': '0000000000c6c6d6d6d6d66e00000000',
    'x': '0000000000c66c38386cc6c600000000',
    'y': '0000000000c6c6c6c6c6c67e0606fc00',
    'z': '0000000000fe060c183060fe00000000',
    '{': '000e181818187070181818180e000000',
    '|': '00181818181818181818181818000000',
    '}': '0070181818180e0e1818181870000000',
    '~': '000000000000327e4c00000000000000',
    '\xb7': '00000000000000181800000000000000',
    '\u2581': '0000000000000000000000000000ffff',
    '\u2582': '000000000000000000000000ffffffff',
    '\u2583': '00000000000000000000ffffffffffff',
    '\u2584': '0000000000000000ffffffffffffffff',
    '\u2585': '000000000000ffffffffffffffffffff',
    '\u2586': '00000000ffffffffffffffffffffffff',
    '\u2587': '0000ffffffffffffffffffffffffffff',
    '\u2588': 'ffffffffffffffffffffffffffffffff',
    '\u2591': '11441144114411441144114411441144',
    '\u2500': '00000000000000ff0000000000000000',
    '\u2014': '000000000000007e0000000000000000',
}


CARD_W, CARD_H = 1200, 630
CARD_PALETTE = {"bg": "#0d1117", "fg": "#e6edf3", "muted": "#8b949e",
                "rule": "#30363d", "accent": "#f0883e"}


class Text(NamedTuple):
    x: int
    y: int
    scale: int
    colour: str
    text: str


class Rect(NamedTuple):
    x: int
    y: int
    w: int
    h: int
    colour: str


class Polyline(NamedTuple):
    points: tuple
    colour: str
    width: int


def _bresenham(x0: int, y0: int, x1: int, y1: int):
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        yield x0, y0
        if x0 == x1 and y0 == y1:
            return
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def _runs(pixels: set) -> list[tuple[int, int, int, int]]:
    out: list[tuple[int, int, int, int]] = []
    for x, y in sorted(pixels, key=lambda p: (p[1], p[0])):
        if out and out[-1][1] == y and out[-1][0] + out[-1][2] == x:
            px, py, pw, ph = out[-1]
            out[-1] = (px, py, pw + 1, ph)
        else:
            out.append((x, y, 1, 1))
    return out


def op_rects(op) -> list[tuple[int, int, int, int]]:
    """The exact pixels one draw op covers, as (x, y, w, h) runs.

    Both writers consume this and nothing else, so the SVG and the PNG cannot
    disagree about a single pixel.
    """
    if isinstance(op, Rect):
        return [(op.x, op.y, op.w, op.h)]
    if isinstance(op, Text):
        s, out = op.scale, []
        for i, ch in enumerate(op.text):
            bits = CARD_FONT.get(ch) or CARD_FONT["?"]
            gx = op.x + i * 8 * s
            for row in range(16):
                byte, col = int(bits[row * 2:row * 2 + 2], 16), 0
                while col < 8:
                    if byte & (0x80 >> col):
                        start = col
                        while col < 8 and byte & (0x80 >> col):
                            col += 1
                        out.append((gx + start * s, op.y + row * s, (col - start) * s, s))
                    else:
                        col += 1
        return out
    # Polyline: integer Bresenham, every point stamped as a width x width square.
    pixels: set = set()
    half = op.width // 2
    for (x0, y0), (x1, y1) in zip(op.points, op.points[1:]):
        for x, y in _bresenham(x0, y0, x1, y1):
            for dy in range(op.width):
                for dx in range(op.width):
                    pixels.add((x - half + dx, y - half + dy))
    return _runs(pixels)


def rasterize(ops) -> bytearray:
    """RGB pixels, row-major from the top left. Ops paint in order, clipped."""
    buf = bytearray(bytes.fromhex(CARD_PALETTE["bg"][1:]) * (CARD_W * CARD_H))
    for op in ops:
        px = bytes.fromhex(op.colour[1:])
        for x, y, w, h in op_rects(op):
            x0, y0 = max(x, 0), max(y, 0)
            x1, y1 = min(x + w, CARD_W), min(y + h, CARD_H)
            if x0 >= x1 or y0 >= y1:
                continue
            run = px * (x1 - x0)
            for yy in range(y0, y1):
                o = (yy * CARD_W + x0) * 3
                buf[o:o + len(run)] = run
    return buf


def _png_chunk(tag: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + tag + body
            + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))


def png_bytes(ops) -> bytes:
    """An 8-bit RGB PNG of the ops, from the standard library alone."""
    buf, stride = rasterize(ops), CARD_W * 3
    raw = b"".join(b"\x00" + bytes(buf[y * stride:(y + 1) * stride]) for y in range(CARD_H))
    ihdr = struct.pack(">IIBBBBB", CARD_W, CARD_H, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(raw, 9)) + _png_chunk(b"IEND", b""))


def svg_text(ops) -> str:
    """The same pixels as png_bytes, as integer-aligned paths in paint order.

    No <text> elements: a glyph is pixels, so nothing on a card can be copied,
    searched or indexed as text.
    """
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{CARD_W}" height="{CARD_H}" '
             f'viewBox="0 0 {CARD_W} {CARD_H}" shape-rendering="crispEdges">',
             f'<rect width="{CARD_W}" height="{CARD_H}" fill="{CARD_PALETTE["bg"]}"/>']
    for op in ops:
        d = "".join(f"M{x} {y}h{w}v{h}h{-w}z" for x, y, w, h in op_rects(op))
        if d:
            parts.append(f'<path fill="{op.colour}" d="{d}"/>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


HERO_RULE_X = 856
_HERO_LEFT, _HERO_WIDTH = 64, 768
_SPARK_BOX = (64, 416, 768, 120)          # x, y, w, h
TERM_X, TERM_Y, CELL_W, CELL_H, TERM_COLS = 24, 24, 24, 48, 48
# Card glyphs are written as escapes: they only ever reach the card font, never
# a terminal, so they have no _GLYPH_FALLBACK entry, and the source-glyph test
# requires every literal non-ASCII character in this file to have one.
_BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
_BAR_FULL, _BAR_EMPTY = "\u2588", "\u2591"


def _spark_points(series: list, vmax: float) -> tuple:
    x, y, w, h = _SPARK_BOX
    n = len(series)
    pts = []
    for i, v in enumerate(series):
        if v is None:
            continue
        px = x + (i * w // (n - 1) if n > 1 else 0)
        frac = min(max(v / vmax, 0.0), 1.0) if vmax else 0.0
        pts.append((px, y + h - int(round(frac * h))))
    return tuple(pts)


def _blocks(series: list, vmax: float, width: int) -> str:
    """One block per day, or per bucket of days when the window is wider."""
    step = max(1, -(-len(series) // width))
    cells = []
    for i in range(0, len(series), step):
        vals = [v for v in series[i:i + step] if v is not None]
        if not vals:
            cells.append(" ")
            continue
        level = min(7, int(max(vals) / vmax * 8)) if vmax else 0
        cells.append(_BLOCKS[level])
    return "".join(cells)


def layout_hero(m: dict) -> list:
    """Layout A: one big number, a caption, three or four stats, a trend."""
    P = CARD_PALETTE
    ops: list = [Text(64, 48, 2, P["muted"], m["label"])]
    hero = m["hero"]
    scale = next((s for s in (10, 8, 6) if len(hero) * 8 * s <= _HERO_WIDTH), 4)
    ops.append(Text(_HERO_LEFT, 112, scale, P["accent"], hero))
    for i, line in enumerate(_wrap(m["caption"], 32)[:2]):
        ops.append(Text(_HERO_LEFT, 296 + i * 52, 3, P["fg"], line))
    ops.append(Rect(HERO_RULE_X, 112, 2, 400, P["rule"]))
    for i, (value, label) in enumerate(m["stats"][:4]):
        y = 112 + i * 104
        # x4 holds 9 characters before the canvas edge; a longer value drops
        # to x3 (12) rather than being truncated into a different number.
        ops.append(Text(888, y, 4 if len(value) <= 9 else 3, P["fg"], value[:12]))
        ops.append(Text(888, y + 68, 2, P["muted"], label[:16]))
    if m["trend"]:
        ops.append(Polyline(_spark_points(m["series"], m["series_max"]), P["accent"], 4))
    else:
        ops.append(Text(_HERO_LEFT, 456, 2, P["muted"], "not enough days for a trend"))
    ops.append(Text(_HERO_LEFT, 574, 2, P["muted"], CARD_INSTALL))
    return ops


def layout_terminal(m: dict) -> list:
    """Layout C: the card as a terminal session, on a 24x48 character grid."""
    P = CARD_PALETTE

    def at(col: int, row: int, colour: str, s: str, scale: int = 3) -> Text:
        return Text(TERM_X + col * CELL_W, TERM_Y + row * CELL_H, scale, colour, s)

    header = m["header"]
    ops: list = [at(0, 0, P["accent"], "$"),
                 at(2, 0, P["muted"], f"actualis --card {m['mode']}"),
                 at(0, 1, P["fg"], "ACTUALIS · what actually ran"),
                 at(0, 2, P["muted"], header + " " + "─" * (TERM_COLS - len(header) - 1))]
    hero_x, hero_y = TERM_X, TERM_Y + 3 * CELL_H
    ops.append(Text(hero_x, hero_y, 6, P["accent"], m["hero"]))
    label_col = len(m["hero"]) * 2 + 1          # a x6 glyph spans two x3 cells
    ops.append(at(label_col, 4, P["fg"], m["hero_label"][:TERM_COLS - label_col]))
    bars = m["bars"][:4]
    top = max([v for _, v, _ in bars] or [0.0]) or 1.0
    for i, (label, value, text) in enumerate(bars):
        row = 5 + i
        filled = int(round(28 * value / top))
        ops.append(at(0, row, P["muted"], label.replace("claude-", "")[:11]))
        if filled:
            ops.append(at(12, row, P["accent"], _BAR_FULL * filled))
        if filled < 28:
            ops.append(at(12 + filled, row, P["rule"], _BAR_EMPTY * (28 - filled)))
        if len(text) <= 7:
            ops.append(at(41, row, P["fg"], text))
        else:   # x2 fits 10 characters in the same 7 cells
            ops.append(Text(TERM_X + 41 * CELL_W, TERM_Y + row * CELL_H + 16, 2,
                            P["fg"], text[:10]))
    spark_row = 6 + max(len(bars), 3)    # one blank row after the bars
    ops.append(at(0, spark_row, P["muted"], f"{m['days']}d"[:4]))
    if m["trend"]:
        ops.append(at(5, spark_row, P["accent"], _blocks(m["series"], m["series_max"], 40)))
    else:
        ops.append(at(5, spark_row, P["muted"], "not enough days for a trend"))
    ops.append(at(TERM_COLS - len(CARD_INSTALL), 11, P["muted"], CARD_INSTALL))
    return ops


def card_paths(out_dir: Path) -> tuple:
    """The first actualis-card[-N] where neither the .svg nor the .png exists.

    Both files move together: a card whose SVG is -2 and PNG is -1 is two
    different cards with one name.
    """
    n = 1
    while True:
        stem = "actualis-card" if n == 1 else f"actualis-card-{n}"
        svg, png = out_dir / f"{stem}.svg", out_dir / f"{stem}.png"
        if not svg.exists() and not png.exists():
            return svg, png
        n += 1


def write_card(m: dict, style: str, out_dir: Path) -> tuple:
    """Write one card. Mode "x" makes never-overwrite hold even under a race."""
    ops = layout_hero(m) if style == "hero" else layout_terminal(m)
    svg_data, png_data = svg_text(ops), png_bytes(ops)   # render before opening anything
    svg, png = card_paths(out_dir)
    with svg.open("x", encoding="utf-8", newline="\n") as fh:
        fh.write(svg_data)
    try:
        with png.open("xb") as fh:
            fh.write(png_data)
    except BaseException:
        try:
            svg.unlink()
        except OSError:
            pass
        raise
    return svg, png


# --------------------------------------------------------------------------
# The --json contract
#
# Everything downstream agrees with this: the tray, the MCP server, and anything
# a user builds on `actualis --json`. It is frozen, and JSON_SCHEMA below is the
# freeze — a flat map of dotted path to type, checked against real output by the
# test suite so a key cannot be removed or retyped by accident.
#
# Within a major schema version:
#   MAY   add a new key, add a new enum value, add an array element field
#   MAY   change a description, a note string, or the ORDER of keys
#   NEVER remove a key, rename one, or change its type
#   NEVER change the meaning of an existing key
#
# Path syntax:
#   a.b    a fixed key
#   a.*    a map whose KEYS are data (project names, model ids, dates)
#   a[].b  a field on each element of an array
#   "x|null" a value that is legitimately absent
#
# Bump JSON_SCHEMA_VERSION only for a breaking change, and say so in CHANGELOG.
# --------------------------------------------------------------------------

JSON_SCHEMA_VERSION = 1

JSON_SCHEMA: dict[str, str] = {
    "schema_version": "int",
    "version": "str",
    "report_sha256": "str",
    "window.from": "str|null",
    "window.to": "str|null",
    "window.days": "float",
    "window.active_days": "int",
    "scanned.files": "int",
    "scanned.bytes": "int",
    "scanned.roots": "array",
    "scanned.roots[]": "str",
    "messages": "int",
    "cost_usd": "float",
    "cost_usd_from_unpriced_models": "float",
    "copilot_unpriced_sessions": "int",
    "pricing.verified": "str",
    "pricing.age_days": "int",
    "pricing.stale": "bool",
    "pricing.stale_after_days": "int",
    "pricing.tier_order": "array",
    "pricing.tier_order[]": "str",
    "pricing.confident_pct": "float",
    "pricing.cost_by_tier.*": "float",
    "pricing.models_by_tier.*": "array",
    "pricing.models_by_tier.*[]": "str",
    "pricing.sources.*": "str",
    "pricing.note": "str",
    "cost_note": "str",
    "duplicate_usage_records_skipped": "int",
    "duplicate_note": "str",
    "tokens.*": "int",
    "by_agent.*": "float",
    "subagents.runs": "int",
    "subagents.by_model.*": "int",
    "subagents.status.*": "int",
    "subagents.cost_floor_usd": "float",
    "subagents.cost_floor_note": "str",
    "subagents.tools.*": "int",
    "subagents.lines.*": "int",
    "subagents.wall_clock_hours": "float",
    "by_model.*": "float",
    "cache.fleet_hit_rate_pct": "float",
    "cache.saved_usd": "float",
    "cache.by_project.*.hit_rate_pct": "float",
    "cache.by_project.*.context_tokens": "int",
    "cache.by_project.*.saved_usd": "float",
    "by_ticket": "array",
    "by_ticket[].ticket": "str",
    "by_ticket[].cost_usd": "float",
    "by_ticket[].messages": "int",
    "by_ticket[].branches": "array",
    "by_ticket[].branches[]": "str",
    "by_ticket[].projects": "array",
    "by_ticket[].projects[]": "str",
    "by_ticket[].active_days": "int",
    "by_ticket[].first_seen": "str",
    "by_ticket[].last_seen": "str",
    "by_branch.*": "float",
    "by_project.*": "float",
    "by_day.*": "float",
    "tools.*": "int",
    "bash.total": "int",
    "bash.commands.*": "int",
    "bash.flag_counts.*": "int",
    "bash.oversized_commands": "int",
    "bash.flags": "array",
    "bash.flags[].id": "str",
    "bash.flags[].program": "str",
    "bash.flags[].suppressed": "bool",
    "bash.flags[].suppressed_reason": "str",
    "bash.flags[].severity": "str",
    "bash.flags[].categories": "array",
    "bash.flags[].categories[]": "str",
    "bash.flags[].project": "str",
    "bash.flags[].when": "str|null",
    "bash.flags[].evidence": "str",
    "bash.flags[].had_secret": "bool",
    "coach": "array",
    "coach[].id": "str",
    "coach[].severity": "str",
    "coach[].title": "str",
    "coach[].evidence": "str",
    "coach[].action": "str",
    "coach[].impact": "str|null",
    "secret_exposures": "int",
    "suppressed_secrets": "int",
    "suppression_note": "str",
    "secrets[].suppressed": "bool",
    "secrets[].suppressed_reason": "str",
    "secrets": "array",
    "secrets[].id": "str",
    "secrets[].priority": "str",
    "secrets[].types": "array",
    "secrets[].types[]": "str",
    "secrets[].uses": "int",
    "secrets[].projects": "array",
    "secrets[].projects[]": "str",
    "secrets[].first_seen": "str",
    "secrets[].last_seen": "str",
    "secrets[].distinct_values": "int",
    "secret_projects.*": "int",
    "redacted": "bool",
    "permission_modes.*": "int",
    "denials.*": "int",
    "suppressed_flags": "int",
    "vendors.capabilities": "array",
    "vendors.capabilities[].capability": "str",
    "vendors.capabilities[].claude": "str",
    "vendors.capabilities[].codex": "str",
    "vendors.capabilities[].copilot": "str",
    "vendors.capabilities[].depends_on": "str",
    "vendors.note": "str",
    "unreadable_commands.count": "int",
    "unreadable_commands.pct_of_commands": "float",
    "unreadable_commands.by_shape.*": "int",
    "unreadable_commands.note": "str",
    "refusals.total": "int",
    "refusals.joined_to_a_command": "int",
    "refusals.join_note": "str",
    "refusals.scope_note": "str",
    "refusals.by_gate.*.*": "int",
    "refusals.by_program.*.*": "int",
    "refusals.by_project.*.*": "int",
    "refusals.by_week.*.*": "int",
    "network.totals.items": "int",
    "network.totals.asked": "int",
    "network.totals.unasked": "int",
    "network.totals.unknown": "int",
    "network.totals.failed": "int",
    "network.totals.unparsed_segments": "int",
    "network.by_kind.install": "int",
    "network.by_kind.clone": "int",
    "network.by_kind.fetch": "int",
    "network.by_kind.search": "int",
    "network.hosts": "array",
    "network.hosts[].host": "str",
    "network.hosts[].count": "int",
    "network.hosts[].unasked": "int",
    "network.hosts[].first_seen": "str|null",
    "network.hosts[].trusted": "bool",
    "network.packages": "array",
    "network.packages[].ecosystem": "str",
    "network.packages[].name": "str",
    "network.packages[].versions": "array",
    "network.packages[].versions[]": "str",
    "network.packages[].pinned": "bool",
    "network.packages[].exec": "bool",
    "network.packages[].count": "int",
    "network.items": "array",
    "network.items[].kind": "str",
    "network.items[].program": "str",
    "network.items[].host": "str|null",
    "network.items[].host_inferred": "bool",
    "network.items[].url": "str|null",
    "network.items[].dest": "str|null",
    "network.items[].source": "str|null",
    "network.items[].ecosystem": "str|null",
    "network.items[].package": "str|null",
    "network.items[].version": "str|null",
    "network.items[].pinned": "bool",
    "network.items[].exec": "bool",
    "network.items[].dynamic": "bool",
    "network.items[].alias": "str|null",
    "network.items[].failed": "bool|null",
    "network.items[].approval": "str",
    "network.items[].trusted": "bool",
    "network.items[].agent": "str",
    "network.items[].project": "str",
    "network.items[].session": "str|null",
    "network.items[].ts": "str|null",
    "network.items_truncated": "bool",
    "network.strict": "bool",
    "network.trust": "array",
    "network.trust[]": "str",
    "network.trust_sources": "array",
    "network.trust_sources[].source": "str",
    "network.trust_sources[].entries": "array",
    "network.trust_sources[].entries[]": "str",
    "network.trust_sources[].path": "str|null",
    "network.trust_sources[].sha256": "str|null",
    "unknown_models.*": "int",
    "aggregator_priced_models.*": "int",
}

def canonical_json(payload: dict) -> str:
    """The exact bytes the report hash is taken over.

    Sorted keys and no incidental whitespace, so two runs over the same data
    produce the same string regardless of dict ordering. ensure_ascii=False
    keeps the bytes identical to what a UTF-8 reader sees rather than escaping
    non-ASCII into a second representation.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def report_digest(payload: dict) -> str:
    """sha256 of the report, excluding the digest field itself.

    Self-referential by construction otherwise: the hash cannot cover a field
    whose value is the hash. Removing exactly that one key is what makes the
    figure independently recomputable, and REPORT_DIGEST_EXCLUDES names it in
    one place so the emitter and any verifier cannot disagree.
    """
    body = {k: v for k, v in payload.items() if k not in REPORT_DIGEST_EXCLUDES}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


REPORT_DIGEST_EXCLUDES = frozenset({"report_sha256"})

# --------------------------------------------------------------------------
# Exit codes
#
# A pipeline depends on these, so they are fixed and documented rather than
# whatever the code happens to return.
#
#   0    nothing at or above the threshold, or no threshold was asked for
#   1    the tool could not run: no transcripts, an unreadable --root
#   2    a command line usage error -- argparse owns this one, not us
#   3    findings at or above --fail-on
#   130  interrupted
#
# Findings are 3, not 1 and not 2. 1 already meant "could not run" before
# --fail-on existed. 2 is argparse's exit for a bad invocation, and a pipeline
# that cannot tell "a credential is exposed" from "you mistyped a flag" will
# eventually be told to ignore both.
# --------------------------------------------------------------------------

EXIT_OK = 0
EXIT_CANNOT_RUN = 1
EXIT_USAGE = 2        # argparse's, reserved rather than used
EXIT_FINDINGS = 3

# What each threshold includes. Ordered, so a lower threshold is a superset.
FAIL_ON_LEVELS = ("critical", "high", "any")


def failing_findings(fleet: Fleet, level: str) -> list[str]:
    """Reasons this fleet trips `--fail-on LEVEL`, most severe first.

    Only ACTIONABLE findings count. A suppressed finding is a decision someone
    recorded with a reason; letting it fail a build anyway would make
    suppression pointless and teach people to delete findings instead.
    """
    if level not in FAIL_ON_LEVELS:
        return []
    want_high = level in ("high", "any")
    want_any = level == "any"
    out = []

    crit = [e for e in fleet.actionable_secrets.values() if e["priority"] == "critical"]
    if crit:
        out.append(f"{len(crit)} critical credential(s) in agent context")
    if want_high:
        high = [e for e in fleet.actionable_secrets.values() if e["priority"] == "high"]
        if high:
            out.append(f"{len(high)} high-priority credential(s)")
    if want_any:
        low = [e for e in fleet.actionable_secrets.values() if e["priority"] == "low"]
        if low:
            out.append(f"{len(low)} low-priority credential(s)")

    for finding in coach(fleet):
        if finding.severity == "critical" or (want_high and finding.severity == "high") \
           or (want_any and finding.severity == "info"):
            out.append(f"{finding.id} {finding.title}")

    if want_high:
        fl = [f for f in fleet.actionable_flags if f["severity"] == "high"]
        if fl:
            out.append(f"{len(fl)} high-severity shell command(s) flagged")
    if want_any:
        fl = [f for f in fleet.actionable_flags if f["severity"] == "med"]
        net = [f for f in fl if f["categories"] == ["network-unasked"]]
        fl = [f for f in fl if f["categories"] != ["network-unasked"]]
        if fl:
            out.append(f"{len(fl)} medium-severity shell command(s) flagged")
        if net:
            out.append(f"{len(net)} unasked download group(s) from untrusted sources")
    return out


def to_json(fleet: Fleet, raw: bool = False) -> dict:
    payload = _to_json_body(fleet, raw)
    payload["report_sha256"] = report_digest(payload)
    return payload


def _to_json_body(fleet: Fleet, raw: bool = False) -> dict:
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "version": __version__,
        "window": {
            "from": fleet.first_ts.isoformat() if fleet.first_ts else None,
            "to": fleet.last_ts.isoformat() if fleet.last_ts else None,
            "days": round(fleet.span_days, 2),
            "active_days": fleet.active_days,
        },
        "scanned": {"files": fleet.files_scanned, "bytes": fleet.bytes_scanned,
                    "roots": [str(r) for r in fleet.roots]},
        "messages": fleet.messages,
        "cost_usd": float(round(fleet.total_cost, 4)),
        "cost_usd_from_unpriced_models": float(round(fleet.cost_unknown, 4)),
        "copilot_unpriced_sessions": int(fleet.copilot_unpriced),
        "pricing": {
            "verified": PRICING_VERIFIED,
            "age_days": pricing_age_days(),
            "stale": pricing_age_days() > PRICING_STALE_DAYS,
            "stale_after_days": PRICING_STALE_DAYS,
            "tier_order": list(RATE_TIERS),
            "confident_pct": float(round(fleet.confident_pct, 2)),
            "cost_by_tier": {k: float(round(v, 4))
                             for k, v in sorted(fleet.cost_by_tier.items())},
            "models_by_tier": {k: sorted(v)
                               for k, v in sorted(fleet.models_by_tier.items())},
            "sources": dict(RATE_SOURCES),
            "note": "tier_order runs best to worst. vendor is a published price; "
                    "family and default are inferences, and a total is only as "
                    "sound as its weakest component.",
        },
        "cost_note": "models with no published rate are priced at the top of the "
                     "known range for their provider, so that share is an upper "
                     "bound among current models rather than a measurement",
        "duplicate_usage_records_skipped": fleet.duplicate_usage_records,
        "duplicate_note": "one billable message can appear many times in a "
                          "transcript while a response streams; repeats are "
                          "counted once, by message id",
        "tokens": dict(fleet.tokens),
        "by_agent": {k: round(v, 4) for k, v in fleet.cost_by_agent.items()},
        "subagents": {
            "runs": fleet.sub_calls,
            "by_model": dict(fleet.sub_by_model.most_common()),
            "status": dict(fleet.sub_status),
            "cost_floor_usd": round(fleet.sub_cost_floor, 4),
            "cost_floor_note": "lower bound only; cumulative subagent spend is not "
                               "recoverable from the parent transcript",
            "tools": dict(fleet.sub_tools),
            "lines": dict(fleet.sub_lines),
            "wall_clock_hours": round(fleet.sub_ms / 3_600_000, 2),
        },
        "by_model": {k: round(v, 4) for k, v in
                     sorted(fleet.cost_by_model.items(), key=lambda kv: -kv[1])},
        "cache": {
            "fleet_hit_rate_pct": round(cache_hit_rate(
                Counter({k: sum(t[k] for t in fleet.tokens_by_project.values())
                         for k in ("input", "cache_w", "cache_read")})), 2),
            "saved_usd": float(round(sum(fleet.cache_uncached.values())
                                     - sum(fleet.cache_actual.values()), 4)),
            "by_project": {
                p: {"hit_rate_pct": round(cache_hit_rate(t), 2),
                    "context_tokens": t["input"] + t["cache_w"] + t["cache_read"],
                    "saved_usd": round(fleet.cache_uncached[p] - fleet.cache_actual[p], 4)}
                for p, t in sorted(fleet.tokens_by_project.items(),
                                   key=lambda kv: -(kv[1]["input"] + kv[1]["cache_w"]
                                                    + kv[1]["cache_read"]))
                if (t["input"] + t["cache_w"] + t["cache_read"]) >= 1_000_000},
        },
        "by_ticket": [
            {"ticket": t, "cost_usd": round(cost, 4),
             "messages": fleet.msgs_by_ticket[t],
             "branches": sorted(fleet.branches_by_ticket[t]),
             "projects": sorted(fleet.projects_by_ticket[t]),
             "active_days": len(set(fleet.dates_by_ticket.get(t, []))),
             "first_seen": min(fleet.dates_by_ticket[t]) if fleet.dates_by_ticket.get(t) else None,
             "last_seen": max(fleet.dates_by_ticket[t]) if fleet.dates_by_ticket.get(t) else None}
            for t, cost in sorted(fleet.cost_by_ticket.items(), key=lambda kv: -kv[1])
        ],
        "by_branch": {k: round(v, 4) for k, v in
                      sorted(fleet.cost_by_branch.items(), key=lambda kv: -kv[1])},
        "by_project": {k: round(v, 4) for k, v in
                       sorted(fleet.cost_by_project.items(), key=lambda kv: -kv[1])},
        "by_day": dict(sorted(fleet.cost_by_day.items())),
        "tools": dict(fleet.tools.most_common()),
        "bash": {
            "total": fleet.bash_total,
            "commands": dict(fleet.bash_first_token.most_common(50)),
            "flag_counts": dict(fleet.flag_counts),
            "oversized_commands": fleet.oversized_commands,
            "flags": fleet.flags if raw else [
                {**f, "evidence": redact(f["evidence"])} for f in fleet.flags
            ],
        },
        "coach": [{"id": f.id, "severity": f.severity, "title": f.title,
                   "evidence": f.evidence, "action": f.action, "impact": f.impact}
                  for f in coach(fleet)],
        "secret_exposures": fleet.secret_exposures,
        "suppressed_secrets": fleet.suppressed_secrets,
        "suppression_note": "suppressed findings are still counted and still "
                            "listed here; they are held back from the actionable "
                            "list, not hidden. A scan with many suppressions "
                            "should look different from a clean one.",
        "secrets": [
            {"priority": e["priority"], "types": sorted(e["kinds"]), "id": fp,
             "uses": e["uses"], "first_seen": e["first"], "last_seen": e["last"],
             "projects": sorted(e["projects"]),
             "suppressed": bool(e.get("suppressed")),
             "suppressed_reason": e.get("suppressed_reason", ""),
             "distinct_values": e.get("distinct_values", 1)}
            for fp, e in sorted(
                fleet.secrets.items(),
                key=lambda kv: ({"critical": 0, "high": 1, "low": 2}.get(kv[1]["priority"], 9),
                                -kv[1]["uses"]))
        ],
        "secret_projects": dict(fleet.secret_projects),
        "redacted": not raw,
        "permission_modes": dict(fleet.permission_modes),
        "denials": dict(fleet.denials),
        "suppressed_flags": fleet.suppressed_flags,
        "vendors": {
            "capabilities": [
                {"capability": cap, "claude": c, "codex": x, "copilot": p, "depends_on": why}
                for cap, c, x, p, why in VENDOR_CAPABILITIES
            ],
            "note": "a section fed by a field one vendor does not write is "
                    "single-vendor. Comparing two projects on different agents "
                    "compares different measurements.",
        },
        "unreadable_commands": {
            "count": fleet.unreadable,
            "pct_of_commands": float(round(
                fleet.unreadable / fleet.bash_total * 100, 2)) if fleet.bash_total else 0.0,
            "by_shape": dict(fleet.unreadable_shapes.most_common()),
            "note": "the transcript does not contain what these commands actually "
                    "ran -- a variable, an eval, a script whose contents live in a "
                    "file. Counted, not flagged: this is what the audit could not "
                    "see, not an accusation.",
        },
        "refusals": {
            "total": fleet.refusals,
            "joined_to_a_command": fleet.refusals_joined,
            "join_note": "a refusal points at the tool call it blocked through "
                         "tool_use_id; anything unjoined means the call was not "
                         "in the same session file",
            "by_gate": {k: dict(v.most_common())
                        for k, v in sorted(fleet.refusal_tool.items())},
            "by_program": {k: dict(v.most_common(25))
                           for k, v in sorted(fleet.refusal_program.items())},
            "by_project": {k: dict(v.most_common())
                           for k, v in sorted(fleet.refusal_project.items())},
            "by_week": {k: dict(v.most_common())
                        for k, v in sorted(fleet.refusal_week.items())},
            "scope_note": "this machine only; refusals are not deduplicated "
                          "across developers and are bounded by transcript retention",
        },
        "network": network_json(fleet, raw),
        "unknown_models": dict(fleet.unknown_models),
        "aggregator_priced_models": dict(fleet.aggregator_models),
    }


# --------------------------------------------------------------------------
# Background service
#
# The README used to carry a plist template with __PLACEHOLDERS__ and a sed
# line to fill them. That is a recipe, and recipes get mistyped. These are
# generated with the paths already resolved on the machine that will run them.
#
# The unit goes to stdout and the install commands to stderr, so
# `actualis --service launchd > file` writes a valid file and still tells you
# what to do with it. Nothing here writes anything: the read-only guarantee is
# the product, and it does not get an exception for convenience.

SERVICE_KINDS = ("launchd", "systemd", "newsyslog")
SERVICE_LABEL = "app.actualis.watch"
SERVICE_LOG = "~/Library/Logs/actualis-watch.log"


def _actualis_command() -> list[str]:
    """How to invoke this build, resolved now rather than guessed later.

    A service manager has no PATH worth relying on, so both parts are absolute.
    """
    import shutil                      # local, as elsewhere in this file

    # argv[0] first, because it is THIS build. Asking PATH instead means a
    # venv or pipx install that is not on PATH generates a unit pointing at
    # some other installation, and the service then runs a different version
    # than the one that wrote it -- silently, and possibly for months.
    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if argv0 and argv0.suffix != ".py":
        try:
            resolved = argv0.resolve()
            if resolved.is_file() and os.access(resolved, os.X_OK):
                return [str(resolved)]
        except OSError:
            pass

    entry = shutil.which("actualis")
    if entry:
        return [str(Path(entry).resolve())]

    # Running from a source checkout: name the interpreter explicitly, since a
    # service manager will not consult a shebang or a virtualenv for us.
    return [sys.executable, str(Path(__file__).resolve())]


def _xml_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def service_unit(kind: str, interval: float = 4.0, quiet: bool = False) -> str:
    # `--interval 4.0` is valid but reads like a mistake in a unit file.
    secs = f"{interval:g}"
    argv = _actualis_command() + ["--watch", "--interval", secs]
    if quiet:
        argv.append("--quiet")
    log = Path(SERVICE_LOG).expanduser()

    if kind == "launchd":
        args = "\n".join(f"      <string>{_xml_escape(a)}</string>" for a in argv)
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Generated by actualis {__version__} on this machine; paths are already
     resolved. A LaunchAgent, not a LaunchDaemon, on purpose: notifications
     only post inside your logged-in session, and it should hold exactly your
     permissions and no more. -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <!-- stdout is a file here, so Python would block-buffer it and an alert
         could sit unwritten for hours. -->
    <key>PYTHONUNBUFFERED</key>
    <string>1</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{_xml_escape(str(log))}</string>
  <key>StandardErrorPath</key>
  <string>{_xml_escape(str(log))}</string>
</dict>
</plist>
'''

    if kind == "systemd":
        cmd = " ".join(argv)
        return f'''# Generated by actualis {__version__} on this machine.
# A user unit, not a system one: it must run as you, with your permissions.
# Logs go to the journal, which rotates on its own -- read them with
#   journalctl --user -u actualis-watch -f
[Unit]
Description=actualis --watch: alert on credentials and risky commands
Documentation=https://actualis.app
After=default.target

[Service]
Type=simple
ExecStart={cmd}
Restart=always
RestartSec=10
# stdout is a pipe to the journal, so Python would block-buffer it.
Environment=PYTHONUNBUFFERED=1
# It only ever reads. Say so to the service manager as well as in the README.
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=default.target
'''

    # newsyslog: macOS has no journald, so rotation is opt-in and needs root.
    #
    # Flags are NC, not the usual GJ: G means "this path is a glob", which it is
    # not, and there is no process to signal (N) because launchd -- not
    # actualis -- opened this file. That has a consequence worth stating in the
    # file itself rather than burying in a doc, so it is a comment below.
    return f'''# Generated by actualis {__version__}. Optional: macOS log rotation.
# Only events are logged (the heartbeat is suppressed when stdout is not a
# terminal), so this file grows slowly -- but it grows.
#
# launchd holds this file open, so after a rotation the agent keeps writing to
# the OLD file until it restarts. Rotation is therefore not fully automatic on
# macOS. Kick the agent to make it pick up the new file:
#
#   launchctl kickstart -k gui/$(id -u)/{SERVICE_LABEL}
#
# On Linux this problem does not exist: the journal handles it.
#
# logfile                       owner:group  mode count size(KB) when flags
{log}  {os.environ.get("USER", "root")}:staff  644  5  1024  *  NC
'''


def service_install_notes(kind: str) -> str:
    log = Path(SERVICE_LOG).expanduser()
    if kind == "launchd":
        return f"""
Install (one command):

  actualis --service launchd > ~/Library/LaunchAgents/{SERVICE_LABEL}.plist &&
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/{SERVICE_LABEL}.plist

Uninstall (one command):

  launchctl bootout gui/$(id -u)/{SERVICE_LABEL} &&
    rm ~/Library/LaunchAgents/{SERVICE_LABEL}.plist

Check it, read it:

  launchctl print gui/$(id -u)/{SERVICE_LABEL} | head -20
  tail -f {log}

Log rotation is opt-in on macOS and needs root:

  actualis --service newsyslog | sudo tee /etc/newsyslog.d/actualis.conf

launchd holds the log open, so after a rotation the agent keeps writing to the
old file until it restarts. Kick it to pick up the new one:

  launchctl kickstart -k gui/$(id -u)/{SERVICE_LABEL}

If notifications do not appear, allow them for Script Editor in
System Settings > Notifications.
"""
    if kind == "systemd":
        return """
Install (one command):

  actualis --service systemd > ~/.config/systemd/user/actualis-watch.service &&
    systemctl --user daemon-reload &&
    systemctl --user enable --now actualis-watch

Uninstall (one command):

  systemctl --user disable --now actualis-watch &&
    rm ~/.config/systemd/user/actualis-watch.service &&
    systemctl --user daemon-reload

Check it, read it:

  systemctl --user status actualis-watch
  journalctl --user -u actualis-watch -f

Logs go to the journal and rotate with it; there is no file to prune.
To keep it running after you log out:  loginctl enable-linger $USER
"""
    return """
Install (needs root, because /etc does):

  actualis --service newsyslog | sudo tee /etc/newsyslog.d/actualis.conf

Uninstall:

  sudo rm /etc/newsyslog.d/actualis.conf
"""


# --------------------------------------------------------------------------
# Self-check
#
# docs/verify/ told a sceptic how they could verify the privacy claims. Almost
# nobody follows a page of instructions, and the claims ARE the product. This
# runs the checks instead, on the user's own machine, against their own files.
#
# It is a floor, not a guarantee, and it says so: it proves that THIS run did
# not do the things claimed, not that no run ever could.

# Any network operation in pure Python goes through socket. If socket was never
# imported, this process could not have opened a connection -- which is a much
# stronger statement than "we did not call requests".
_NETWORK_MODULES = (
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib",
    "imaplib", "telnetlib", "xmlrpc", "asyncio", "selectors", "socketserver",
    "requests", "httpx", "urllib3", "aiohttp",
)

# Both import forms, anchored so that prose in a docstring cannot masquerade
# as one -- `from a non-zero exit and callers` matched a looser pattern and
# reported a module named "a". Indented imports are matched too: a lazy
# `import socket` inside a function is exactly what this check exists to catch.
_IMPORT_RE = re.compile(
    r"^[ \t]*(?:"
    r"import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+\w+)?[ \t]*(?:\#.*)?$"
    r"|from[ \t]+([\w.]+)[ \t]+import[ \t]"
    r")", re.M)


def imports_in(src: str) -> list[str]:
    """Top-level module names imported anywhere in a Python source string."""
    names = set()
    for a, b in _IMPORT_RE.findall(src):
        name = (a or b).split(".")[0]
        if name:
            names.add(name)
    return sorted(names)


SELF_CHECK_SAMPLE = 200      # files hashed before and after; whole-corpus is slow


def _digest_file(path: Path) -> tuple[str, int, float] | None:
    try:
        st = path.stat()
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest(), st.st_size, st.st_mtime
    except OSError:
        return None


def _tree_state(roots: list[Path]) -> dict[str, tuple[int, float]]:
    """Every file under the roots, by size and mtime. Cheap; no hashing."""
    state: dict[str, tuple[int, float]] = {}
    for root in roots:
        try:
            for f in root.rglob("*"):
                if f.is_file():
                    try:
                        st = f.stat()
                    except OSError:
                        continue
                    state[str(f)] = (st.st_size, st.st_mtime)
        except OSError:
            continue
    return state


def self_check(c: C, days: int | None = 7, root: str | None = None) -> int:
    """Verify the privacy claims by executing them. Returns an exit code.

    Honours --root: if you tell the tool which directory to read, that is the
    directory whose integrity you want proven. Ignoring it meant --self-check
    verified a corpus the user had not asked about.
    """
    rule(c, "SELF CHECK")
    ok = True

    def result(passed: bool, label: str, detail: str) -> None:
        nonlocal ok
        if not passed:
            ok = False
        mark = f"{c.ok}pass{c.off}" if passed else f"{c.red}FAIL{c.off}"
        print(f"  [{mark}]  {c.bold}{label}{c.off}")
        for line in _wrap(detail, 78):
            print(f"          {c.dim}{line}{c.off}")

    skips = 0

    def skipped(label: str, why: str) -> None:
        nonlocal skips
        skips += 1
        # "Prints what it checked AND what it could not" -- a check silently
        # not run reads as a check that passed.
        print(f"  [{c.dim}skip{c.off}]  {c.bold}{label}{c.off}")
        for line in _wrap(why, 78):
            print(f"          {c.dim}{line}{c.off}")

    roots = ([Path(root).expanduser()] if root
             else transcript_roots() + codex_roots() + copilot_roots())
    if roots:
        result(True, "the only directories this run reads",
               "; ".join(str(r) for r in roots))

    # 1. What this build imports at all. Read from the source, so it describes
    #    the shipped file rather than whatever is loaded right now.
    try:
        imported = imports_in(Path(__file__).read_text(encoding="utf-8"))
    except OSError:
        imported = []
    net_in_source = [m for m in imported if m in _NETWORK_MODULES]
    result(not net_in_source,
           "no networking module is imported by this build",
           f"imports: {', '.join(imported) or 'none'}. "
           + ("Networking found: " + ", ".join(net_in_source) if net_in_source
              else "None of these can open a socket."))

    # 2. Sample the transcripts, hash them, scan, hash again. The checks below
    #    need a corpus; the ones above and below them do not, and skipping the
    #    whole run when there is nothing to read would hide the ones that are
    #    always meaningful.
    sample: list[Path] = []
    for root in roots:
        for f in root.rglob("*.jsonl"):
            sample.append(f)
            if len(sample) >= SELF_CHECK_SAMPLE:
                break
        if len(sample) >= SELF_CHECK_SAMPLE:
            break
    if not roots or not sample:
        why = ("No transcript directories on this machine."
               if not roots else
               "Transcript directories exist but hold no session files yet.")
        skipped("transcripts unmodified by the scan",
                why + " Nothing was read, so there is nothing to compare. "
                "Run an agent, then run this again.")
        skipped("no file created or deleted under the transcript roots",
                "Same reason: there is no tree to compare.")
    else:
        _self_check_corpus(roots, sample, result, c, days)

    # 3. Where this build is allowed to write, named explicitly.
    writable = [str(p) for p in suppression_paths()]
    result(True, "the only write paths in this build",
           "Suppressions, and only when you pass --suppress: "
           + "; ".join(writable)
           + ". A card, and only when you pass --card: actualis-card[-N].svg and "
           "actualis-card[-N].png in the current directory, or in --out. Neither "
           "is ever overwritten.")

    # 4. What the binary itself is, so it can be compared with what was published.
    try:
        me = Path(__file__)
        d = _digest_file(me)
        if d:
            result(True, "this build, by content",
                   f"{me.name} {d[1]:,} bytes, sha256 {d[0][:32]}... "
                   "Compare with the published wheel to confirm you are running "
                   "what was released.")
    except OSError:
        pass

    print(f"\n  {c.bold}What this does not prove{c.off}")
    for line in (
        "This checked THIS run on THIS machine. It is a floor, not a guarantee.",
        "It cannot rule out a compiled extension, a modified copy, or anything "
        "the operating system did on the tool's behalf.",
        "For a stronger answer, watch the process yourself. On macOS: "
        "sudo lsof -p $(pgrep -f actualis) | grep -i tcp   -- expect nothing. "
        "On Linux: strace -f -e trace=network actualis --days 1.",
    ):
        for out in _wrap(line, 78):
            print(f"    {c.dim}{out}{c.off}")
    # "All checks passed" while two were skipped is the exact kind of overclaim
    # this whole feature exists to avoid.
    if not ok:
        verdict = f"{c.red}A check failed. Do not trust this build.{c.off}"
    elif skips:
        verdict = (f"{c.ok}Every check that could run passed{c.off}, "
                   f"{c.yellow}{skips} could not run{c.off} on this machine.")
    else:
        verdict = f"{c.ok}All checks passed.{c.off}"
    print(f"\n  {verdict}\n")
    return EXIT_OK if ok else EXIT_FINDINGS


def _self_check_corpus(roots: list[Path], sample: list[Path], result, c: C,
                       days: int | None) -> None:
    """The checks that need something to read.

    Split out so that the checks which do NOT need a corpus -- the import scan,
    the write path, this build's own digest -- are never skipped along with
    them. A machine with no transcripts can still verify most of the claims.
    """
    before = {f: _digest_file(f) for f in sample}
    tree_before = _tree_state(roots)

    fleet = Fleet()
    since = window_start(days, datetime.now(timezone.utc)) if days else None
    fleet.scan(roots, since, None, progress=False)
    copilot = [r for r in roots if r in copilot_roots()]
    if copilot:
        fleet.scan_copilot(copilot, since, None)

    changed = [str(f) for f in sample if _digest_file(f) != before[f]]
    result(not changed,
           f"transcripts unmodified by the scan "
           f"({len(sample)} file{'' if len(sample) == 1 else 's'} hashed)",
           "Content, size and mtime are identical before and after. "
           + ("Changed: " + ", ".join(changed[:3]) if changed
              else "A read-only tool leaves no trace, and this is that claim "
                   "executed rather than asserted."))

    tree_after = _tree_state(roots)
    added = sorted(set(tree_after) - set(tree_before))
    removed = sorted(set(tree_before) - set(tree_after))
    # An agent writing to its own transcript DURING the check is expected and
    # is not this tool's doing; report it as an observation rather than a fail.
    touched = [k for k in set(tree_before) & set(tree_after)
               if tree_before[k] != tree_after[k]]
    result(not added and not removed,
           "no file created or deleted under the transcript roots",
           f"{len(tree_before):,} file{'' if len(tree_before) == 1 else 's'} "
           f"before, {len(tree_after):,} after."
           + (f" Added: {len(added)}, removed: {len(removed)}."
              if (added or removed) else ""))
    if touched:
        print(f"          {c.dim}{len(touched)} file(s) changed while the check ran. "
              f"A live agent session writes to its own transcript; that is the "
              f"agent, not this tool.{c.off}")


# --------------------------------------------------------------------------
# OWASP AISVS mapping
#
# AISVS 1.0 (24 June 2026) is a numbered, levelled, pass/fail requirement set
# for AI systems. Chapter C9 covers agentic action and Appendix C covers AI
# coding tools specifically. It is the closest published thing to a standard
# for how these tools should be operated.
#
# What it does NOT have, by design, is an audit procedure. Every requirement
# says "Verify that ..." and stops, because AISVS is vendor-neutral and cannot
# name a config file. Its scope section hands host hardening to CIS
# Benchmarks, which do not cover coding agents at all.
#
# That gap is where this sits. But the claim has to be exact, because almost
# every AISVS control verifies ENFORCEMENT -- "the runtime blocks", "controls
# automatically strip" -- and this tool observes OUTCOMES. It reads what
# already happened; it cannot inspect a runtime.
#
# So this FALSIFIES. When a credential appears in a recorded command, 9.5.4 is
# demonstrably not holding, and that is a harder claim than any verification.
# When nothing appears, that is consistent with 9.5.4 holding and is not proof
# of it -- the same distinction the secret detector already makes between
# "nothing matched" and "nothing is there".
#
# Control text is quoted from the AISVS repository at 1.0. Levels are theirs.

AISVS_VERSION = "1.0"
AISVS_SOURCE = "https://github.com/OWASP/AISVS"

# state -> how the report should read it
FAILING = "failing"        # direct counter-evidence: the control is not holding
CONSISTENT = "consistent"  # nothing contradicts it; NOT a pass
UNKNOWN = "unknown"        # this tool cannot see the answer


class AisvsFinding(NamedTuple):
    control: str
    level: int
    text: str
    state: str
    detail: str


def _aisvs_9_5_4(fleet: "Fleet") -> tuple[str, str]:
    live = fleet.actionable_secrets
    if not live:
        return CONSISTENT, ("no credential appeared in any recorded command. "
                            "That is consistent with the control, not proof of "
                            "it: detection is pattern-based and a bespoke "
                            "token has no shape to match.")
    crit = sum(1 for e in live.values() if e["priority"] == "critical")
    return FAILING, (f"{len(live)} distinct credentials appeared in recorded "
                     f"commands, {crit} critical. A credential in a tool call "
                     f"parameter is exactly what this control forbids.")


def is_ungated_mode(key: str) -> bool:
    """One permission-mode key that does not stop for approval.

    The single definition. ungated_modes, --share and --card all read it, so
    the three cannot disagree about what "unsupervised" means again.
    """
    k = key.lower()
    return "auto" in k or "bypass" in k or key == "codex:never"


def ungated_modes(modes: "Counter") -> int:
    """Turns recorded in a mode that does not stop for approval.

    One definition, because there were two and they disagreed. The coach
    matched `auto`/`bypass` as substrings; the AISVS 9.2.1 mapping matched the
    literal key `"auto"` plus `codex:never`. Claude Code writes `auto` on some
    builds and `bypassPermissions` on others -- the documented CLI value is
    `bypassPermissions` -- so a corpus using the documented name was reported
    as *consistent* with a control it plainly failed. Understating a failing
    control is the worse direction of error for this tool.
    """
    return sum(v for k, v in modes.items() if is_ungated_mode(k))


def _aisvs_9_2_1(fleet: "Fleet") -> tuple[str, str]:
    modes = fleet.permission_modes
    total = sum(modes.values())
    if not total:
        return UNKNOWN, "no permission mode was recorded in these transcripts."
    ungated = ungated_modes(modes)
    pct = ungated / total * 100
    if pct >= 50:
        return FAILING, (f"{pct:.1f}% of {total:,} recorded turns ran in a mode "
                         f"that does not stop for approval. A gate that is off "
                         f"cannot block anything.")
    return CONSISTENT, (f"{100-pct:.1f}% of {total:,} turns ran in a mode that "
                        f"can require approval. Whether the runtime actually "
                        f"blocked is not visible from a transcript.")


def _aisvs_9_2_2(fleet: "Fleet") -> tuple[str, str]:
    if not fleet.refusals:
        return UNKNOWN, ("no refusal was recorded, so there is nothing to show "
                         "an approval prompt was ever presented.")
    joined = fleet.refusals_joined
    return CONSISTENT, (f"{fleet.refusals} refusals recorded, {joined} "
                        f"joined back to the exact command that was blocked. "
                        f"The command text was therefore available at the gate.")


def _aisvs_9_3_1(fleet: "Fleet") -> tuple[str, str]:
    high = sum(v for k, v in fleet.flag_counts.items() if k.startswith("high:"))
    if not fleet.bash_total:
        return UNKNOWN, "no shell activity recorded."
    if high:
        return FAILING, (f"{high:,} commands matched high-severity shapes "
                         f"(destructive, egress, credential reads) out of "
                         f"{fleet.bash_total:,}. Those ran; a least-privilege "
                         f"sandbox that permits them is not least-privilege "
                         f"for this agent.")
    return CONSISTENT, f"no high-severity command shape in {fleet.bash_total:,} commands."


def _aisvs_ac_3_2(fleet: "Fleet") -> tuple[str, str]:
    live = fleet.actionable_secrets
    if not live:
        return CONSISTENT, "nothing matched, which is not the same as nothing present."
    return FAILING, (f"{len(live)} credentials reached the context anyway. If a "
                     f"stripping control is deployed it is not catching these.")


def _aisvs_ac_5_1(fleet: "Fleet") -> tuple[str, str]:
    if not fleet.messages:
        return UNKNOWN, "nothing recorded."
    return CONSISTENT, (f"{fleet.messages:,} messages are on disk and readable, "
                        f"and `--replay` reconstructs the chain for any one "
                        f"credential fingerprint. Retention beyond this "
                        f"machine is not visible.")


def _aisvs_12_1_1(fleet: "Fleet") -> tuple[str, str]:
    if not fleet.files_scanned:
        return UNKNOWN, "no transcripts found."
    unread = fleet.unreadable
    detail = (f"{fleet.files_scanned:,} transcript files carry session context "
              f"and per-message telemetry.")
    if unread:
        detail += (f" {unread:,} commands could not be parsed by this tool, so "
                   f"logging exists but is not fully machine-readable.")
    return CONSISTENT, detail


AISVS_MAP = (
    ("9.5.4", 2, "secrets and credentials required by an agent at runtime are not "
                 "exposed within the model's observable context, including the "
                 "context window, system prompts, or tool call parameters",
     _aisvs_9_5_4),
    ("9.2.1", 1, "the agent runtime blocks execution of privileged, high-impact, "
                 "or irreversible actions until explicit human approval is "
                 "received and verified", _aisvs_9_2_1),
    ("9.2.2", 1, "approval requests display canonicalized and complete action "
                 "parameters, such as diffs, commands, recipients, amounts",
     _aisvs_9_2_2),
    ("9.3.1", 1, "each tool/plugin executes in a least-privilege sandbox or is "
                 "otherwise isolated from model operations", _aisvs_9_3_1),
    ("AC.3.2", 1, "technical controls automatically strip sensitive material from "
                  "any context window sent to an AI tool", _aisvs_ac_3_2),
    ("AC.5.1", 1, "prompt-and-response pairs are logged with stable correlation "
                  "identifiers, so that an investigator can later replay the "
                  "whole chain", _aisvs_ac_5_1),
    ("12.1.1", 1, "AI interactions are logged with session context and "
                  "AI-specific telemetry", _aisvs_12_1_1),
)


def aisvs_findings(fleet: "Fleet") -> list[AisvsFinding]:
    out = []
    for control, level, text, fn in AISVS_MAP:
        state, detail = fn(fleet)
        out.append(AisvsFinding(control, level, text, state, detail))
    return out


# --------------------------------------------------------------------------
# Blast-radius replay
#
# The report tells you a credential was exposed. It cannot tell you what
# happened while it was live, which is the only question a security person
# actually has. This answers it: one fingerprint in, an incident report out.
#
# It runs its own pass over the transcripts rather than reusing the scan.
# Answering it from the normal report would mean retaining every command with
# full attribution on every run -- tens of thousands of them -- to serve an
# operation almost nobody performs. A rare, targeted question gets a targeted
# read.
#
# An incident is a different document from the fleet report, so it carries its
# own version and its own frozen schema.

INCIDENT_SCHEMA_VERSION = 1

INCIDENT_SCHEMA = {
    "document": "str",
    "schema_version": "int",
    "version": "str",
    "fingerprint": "str",
    "types": "array",
    "types[]": "str",
    "window.first_seen": "str",
    "window.last_seen": "str",
    "window.days": "float",
    "window.sightings": "int",
    "exposure.sessions": "array",
    "exposure.sessions[]": "str",
    "exposure.projects": "array",
    "exposure.projects[]": "str",
    "exposure.branches": "array",
    "exposure.branches[]": "str",
    "exposure.vendors": "array",
    "exposure.vendors[]": "str",
    "blast_radius.note": "str",
    "blast_radius.same_session.commands": "int",
    "blast_radius.same_session.projects": "array",
    "blast_radius.same_session.projects[]": "str",
    "blast_radius.same_session.branches": "array",
    "blast_radius.same_session.branches[]": "str",
    "blast_radius.same_project.commands": "int",
    "blast_radius.elsewhere.commands": "int",
    "blast_radius.elsewhere.projects": "array",
    "blast_radius.elsewhere.projects[]": "str",
    "blast_radius.programs": "*",
    "blast_radius.programs.*": "int",
    "investigate.commands": "int",
    "investigate.note": "str",
    "investigate.programs": "*",
    "investigate.programs.*": "int",
    "limits": "array",
    "limits[]": "str",
}

# Reachability: which commands could plausibly have USED the credential rather
# than merely coexisted with it. Narrows an investigation; proves nothing.
REACHABLE_CATEGORIES = ("egress", "credentials", "database")

INCIDENT_LIMITS = (
    "The window is first-seen to last-seen in recorded transcripts. A credential "
    "created earlier, or used outside an agent session, is not visible here.",
    "Neither vendor records a machine identity. Transcript root and working "
    "directory are the closest available proxy and are reported as such.",
    "Reachability is a heuristic over command shape, not proof of use. It "
    "narrows what to investigate; it does not establish what happened.",
    "Absence of a sighting after last_seen is not evidence of rotation.",
)


class ReplayEvent:
    """One recorded shell command, with everything the transcript attributes."""

    __slots__ = ("ts", "cmd", "session", "project", "branch", "vendor", "root")

    def __init__(self, ts, cmd, session, project, branch, vendor, root):
        self.ts = ts
        self.cmd = cmd
        self.session = session
        self.project = project
        self.branch = branch
        self.vendor = vendor
        self.root = root


def _claude_events(roots: list[Path], since: datetime | None) -> list[ReplayEvent]:
    out: list[ReplayEvent] = []
    for root in roots:
        for f in sorted(root.rglob("*.jsonl")):
            project = pretty_project(f.parent.name)
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if '"Bash"' not in line:
                        continue          # cheap prefilter; most records are not
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    if ts is None or (since and ts < since):
                        continue
                    for cmd in _commands_in(rec):
                        if cmd:
                            out.append(ReplayEvent(
                                ts, cmd,
                                rec.get("sessionId") or rec.get("session_id") or "",
                                project, rec.get("gitBranch") or "",
                                "claude", str(root)))
    return out


def _codex_events(roots: list[Path], since: datetime | None) -> list[ReplayEvent]:
    """Codex records no git branch, so those stay empty rather than invented."""
    out: list[ReplayEvent] = []
    for root in roots:
        for f in sorted(root.rglob("rollout-*.jsonl")):
            cwd = ""
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if "shell_command" not in line and "session_meta" not in line \
                            and "turn_context" not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    payload = rec.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    if rec.get("type") in ("session_meta", "turn_context"):
                        cwd = payload.get("cwd") or cwd
                        continue
                    if payload.get("type") != "function_call" or \
                            payload.get("name") != "shell_command":
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    if ts is None or (since and ts < since):
                        continue
                    try:
                        args = json.loads(payload.get("arguments") or "{}")
                    except (json.JSONDecodeError, ValueError):
                        continue
                    cmd = args.get("command") if isinstance(args, dict) else None
                    if isinstance(cmd, list):
                        cmd = " ".join(str(x) for x in cmd)
                    if cmd:
                        out.append(ReplayEvent(
                            ts, str(cmd), f.stem,
                            pretty_project(Path(cwd).name if cwd else "codex"),
                            "", "codex", str(root)))
    return out


def _copilot_events(roots: list[Path], since: datetime | None) -> list[ReplayEvent]:
    """Copilot records the branch, so unlike Codex it is carried through."""
    out: list[ReplayEvent] = []
    for root in roots:
        for f in sorted(root.glob("*/events.jsonl")):
            cwd = branch = ""
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if "tool.execution_start" not in line and "session.start" not in line \
                            and "session.context_changed" not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict) or not isinstance(rec.get("data"), dict):
                        continue
                    kind = rec.get("type")
                    if kind in ("session.start", "session.context_changed"):
                        ctx = rec["data"].get("context") if kind == "session.start" else rec["data"]
                        if isinstance(ctx, dict):
                            cwd, branch = _copilot_context(ctx, cwd, branch)
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    if ts is None or (since and ts < since):
                        continue
                    for cmd in _commands_in(rec):
                        out.append(ReplayEvent(
                            ts, cmd, f.parent.name,
                            pretty_project(Path(cwd).name if cwd else "copilot"),
                            str(branch), "copilot", str(root)))
    return out


def replay_events(since: datetime | None = None,
                  root: str | None = None) -> list[ReplayEvent]:
    """Every recorded command across every vendor, oldest first."""
    if root:
        base = [Path(root).expanduser()]
        events = _claude_events(base, since) + _codex_events(base, since) \
            + _copilot_events(base, since)
    else:
        events = _claude_events(transcript_roots(), since)
        events += _codex_events(codex_roots(), since)
        events += _copilot_events(copilot_roots(), since)
    events.sort(key=lambda e: e.ts)
    return events


# --------------------------------------------------------------------------
# Shell completions
#
# Generated from the parser rather than hand-written, so a new flag cannot be
# missing from them and a renamed --explain topic cannot go stale. The one
# thing deliberately NOT completed is --suppress: its values are finding ids
# from the user's own report, and producing them means a full scan, which on a
# real corpus takes minutes. A tab key that hangs the terminal is worse than a
# tab key that does nothing.

COMPLETION_SHELLS = ("bash", "zsh", "fish")

_VALUE_HINT = {          # option -> how the shell should complete its argument
    "--root": "dir",
    "--ci-log": "file",
    "--diff": "file",
    "--out": "dir",
}


def _finding_ids() -> list[str]:
    """Every AFxxx this build can emit, read out of the source, not a copy.

    A hand-kept list here would drift from coach() silently. If the source is
    unreadable (frozen build), complete nothing rather than complete wrongly.
    """
    try:
        src = Path(__file__).read_text(encoding="utf-8")
    except OSError:
        return []
    return sorted(set(re.findall(r'"(AF\d{3})"', src)))


def _completion_spec() -> list[tuple[str, list[str], str]]:
    """(option, fixed values, value-hint) for every flag the parser defines."""
    spec = []
    for action in build_parser()._actions:
        for opt in action.option_strings:
            if opt.startswith("--") is False:
                continue
            values: list[str] = []
            if action.choices:
                values = [str(v) for v in action.choices]
            elif opt == "--explain":
                values = sorted(EXPLAIN)
            elif opt == "--why":
                values = _finding_ids()
            takes_arg = action.nargs != 0
            spec.append((opt, values, _VALUE_HINT.get(opt, "" if not takes_arg else "none")))
    return spec


def completion_script(shell: str) -> str:
    spec = _completion_spec()
    flags = [opt for opt, _, _ in spec]
    header = (f"# actualis {shell} completion, generated by "
              f"`actualis --completions {shell}` (v{__version__}).\n"
              "# Regenerate after upgrading; do not edit by hand.\n")

    if shell == "bash":
        cases = []
        for opt, values, hint in spec:
            if values:
                cases.append(f'        {opt}) COMPREPLY=($(compgen -W "'
                             f'{" ".join(values)}" -- "$cur")); return;;')
            elif hint == "dir":
                cases.append(f'        {opt}) COMPREPLY=($(compgen -d -- "$cur")); return;;')
            elif hint == "file":
                cases.append(f'        {opt}) COMPREPLY=($(compgen -f -- "$cur")); return;;')
        return header + (
            "_actualis() {\n"
            '    local cur prev\n'
            '    cur="${COMP_WORDS[COMP_CWORD]}"\n'
            '    prev="${COMP_WORDS[COMP_CWORD-1]}"\n'
            "    case \"$prev\" in\n"
            + "\n".join(cases) + "\n"
            "    esac\n"
            f'    COMPREPLY=($(compgen -W "{" ".join(flags)}" -- "$cur"))\n'
            "}\n"
            "complete -F _actualis actualis\n")

    if shell == "zsh":
        lines = []
        for opt, values, hint in spec:
            desc = ""
            arg = ""
            if values:
                arg = f"=:value:({' '.join(values)})"
            elif hint == "dir":
                arg = "=:directory:_files -/"
            elif hint == "file":
                arg = "=:file:_files"
            elif hint == "none":
                arg = "=:value:"
            lines.append(f"    '{opt}{arg}{desc}' \\")
        # #compdef must be the very first line or zsh ignores the file, and
        # the body runs bare: the completion system calls this file, so a
        # self-invoking wrapper would run _arguments outside a completion
        # context and error.
        return ("#compdef actualis\n" + header
                + "_arguments -s \\\n"
                + "\n".join(lines) + "\n"
                + "    && return 0\n")

    # fish
    out = [header]
    for opt, values, hint in spec:
        name = opt[2:]
        base = f"complete -c actualis -l {name}"
        if values:
            out.append(f'{base} -x -a "{" ".join(values)}"')
        elif hint == "dir":
            out.append(f"{base} -r -F")
        elif hint == "file":
            out.append(f"{base} -r -F")
        elif hint == "none":
            out.append(f"{base} -x")
        else:
            out.append(base)
    return "\n".join(out) + "\n"



# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """The parser, built separately so completions can be generated FROM it.

    A completion script that hardcodes its own copy of the flag list is wrong
    the moment a flag is added, and nothing fails to tell you.
    """
    ap = argparse.ArgumentParser(
        prog="actualis",
        description="What actually ran. Local, read-only, honest about limits.",
    )
    ap.add_argument("--days", type=int, metavar="N", help="only the last N days")
    ap.add_argument("--project", metavar="SUBSTR", help="only projects matching SUBSTR")
    ap.add_argument("--diff", metavar="OLD.json",
                    help="compare against a saved --json report")
    ap.add_argument("--top", type=int, default=12, metavar="N", help="projects to list (default 12)")
    ap.add_argument("--bash", action="store_true", help="shell audit only")
    ap.add_argument("--coach", action="store_true", help="coaching findings only")
    ap.add_argument("--aisvs", action="store_true",
                    help="map findings to OWASP AISVS controls")
    ap.add_argument("--explain", nargs="?", const="", metavar="TOPIC",
                    help="how a number is computed, what it assumes, how to check it")
    ap.add_argument("--replay", metavar="ID",
                    help="incident report for one credential fingerprint")
    ap.add_argument("--why", metavar="AFxxx",
                    help="explain one coach finding against your actual numbers")
    ap.add_argument("--agents", action="store_true",
                    help="which agent platforms are installed, and whether their "
                         "binaries are validly signed by the expected publisher")
    ap.add_argument("--mcp", action="store_true",
                    help="run as an MCP server over stdio so an agent can query itself")
    ap.add_argument("--share", action="store_true",
                    help="postable summary with nothing identifying in it")
    ap.add_argument("--card", nargs="?", const="supervision", choices=CARD_MODES,
                    metavar="MODE",
                    help="write a shareable SVG and PNG card: supervision (default), "
                         "cost or volume. Nothing identifying is on it")
    ap.add_argument("--style", choices=CARD_STYLES, default="hero",
                    help="--card layout: hero (default) or terminal")
    ap.add_argument("--out", metavar="DIR",
                    help="--card: directory to write into (default: current directory)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--watch", action="store_true",
                    help="live monitor: alert on new secrets and risky commands")
    ap.add_argument("--interval", type=float, default=4.0, metavar="SEC",
                    help="--watch poll interval (default 4)")
    ap.add_argument("--quiet", action="store_true",
                    help="--watch: notify on secrets only, not every flagged command")
    ap.add_argument("--agent", choices=["all", "claude", "codex", "copilot"], default="all",
                    help="which agents to include (default: all)")
    ap.add_argument("--no-redact", action="store_true",
                    help="do NOT redact credentials from output (unsafe to share)")
    ap.add_argument("--fail-on", metavar="LEVEL", choices=FAIL_ON_LEVELS,
                    help="exit 3 if any unsuppressed finding is at or above "
                         f"LEVEL ({', '.join(FAIL_ON_LEVELS)}); 2 is a usage error. "
                         "For gating a pipeline. Still changes nothing and blocks nothing.")
    ap.add_argument("--network-trust", metavar="HOST[/PATH],...", action="append",
                    help="trusted download sources for --network-strict; also read from "
                         "./.actualis-network-trust")
    ap.add_argument("--network-strict", action="store_true",
                    help="make every unasked download from an untrusted source a medium finding")
    ap.add_argument("--suppress", metavar="ID",
                    help="mark a finding as a false positive on this machine. "
                         "It stays counted; it leaves the actionable list.")
    ap.add_argument("--reason", metavar="TEXT",
                    help="why --suppress is correct. Recorded so the file is "
                         "reviewable later.")
    ap.add_argument("--suppressions", action="store_true",
                    help="list current suppressions and where they come from")
    ap.add_argument("--root", metavar="DIR", help="transcript directory")
    ap.add_argument("--ci-log", metavar="FILE",
                    help="audit a Claude Code Action execution log (JSON array)")
    ap.add_argument("--service", choices=SERVICE_KINDS, metavar="KIND",
                    help="print a launchd, systemd or newsyslog unit for --watch")
    ap.add_argument("--self-check", action="store_true",
                    help="verify the privacy claims on your own machine")
    ap.add_argument("--completions", choices=COMPLETION_SHELLS, metavar="SHELL",
                    help="print a completion script for bash, zsh or fish")
    ap.add_argument("--version", action="version", version=f"actualis {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    # Before ANY output: every mode below prints, and on a stream whose codec
    # cannot carry the report's glyphs, printing raises rather than degrades.
    make_output_printable(args.json)

    if args.card and args.json:
        ap.error("--card writes files; it cannot also emit --json.")
    if args.card:
        for flag, on in (("--fail-on", args.fail_on), ("--diff", args.diff),
                         ("--why", args.why), ("--share", args.share),
                         ("--watch", args.watch), ("--mcp", args.mcp),
                         ("--replay", args.replay),
                         ("--self-check", args.self_check),
                         ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--explain", args.explain is not None),
                         ("--agents", args.agents),
                         ("--completions", args.completions),
                         ("--service", args.service)):
            if on:
                ap.error(f"--card writes files; it cannot be combined with {flag}.")
        card_dir = Path(args.out).expanduser() if args.out else Path.cwd()
        if not card_dir.is_dir():
            print(f"actualis: {card_dir} is not a directory.\n"
                  "  --out takes the directory the card is written into.", file=sys.stderr)
            return EXIT_CANNOT_RUN
    if args.service:
        # Unit to stdout, instructions to stderr: `> file` must yield a file
        # that works, and still tell the user what to do with it.
        print(service_unit(args.service, args.interval, args.quiet), end="")
        print(service_install_notes(args.service), file=sys.stderr)
        return EXIT_OK

    if args.self_check:
        return self_check(C(use_color()), args.days, args.root)

    if args.completions:
        print(completion_script(args.completions), end="")
        return EXIT_OK

    if args.replay:
        if not _FINGERPRINT.fullmatch(args.replay):
            ap.error(f"--replay takes a credential fingerprint: eight hex "
                     f"characters, as printed in the report. Got {args.replay!r}.")

    if args.diff and args.json:
        ap.error("--diff renders a comparison; it cannot also emit --json. "
                 "Save this run with --json, then diff the two files.")
    if not args.card and (args.style != "hero" or args.out):
        ap.error("--style and --out apply only to --card.")

    since = None
    if args.days:
        since = window_start(args.days)

    if args.suppressions:
        c = C(use_color())
        rule(c, "SUPPRESSIONS")
        for path in suppression_paths():
            mark = "" if path.exists() else f"  {c.dim}(none){c.off}"
            print(f"  {c.dim}{path}{c.off}{mark}")
        current = load_suppressions()
        print()
        if not current:
            print(f"  {c.dim}Nothing suppressed. Add one with:{c.off}")
            print(f"    actualis --suppress <id> --reason \"why\"")
        for fp, why in sorted(current.items()):
            if fp == AUDIT_CONFIG_ID:
                why = f"ignored: audit-config findings cannot be suppressed ({why})"
            print(f"  {fp}  {c.dim}{why}{c.off}")
        print(f"\n  {c.dim}Suppressed findings are still counted and still appear "
              f"in --json.{c.off}")
        return 0

    if args.suppress:
        c = C(use_color())
        try:
            path = add_suppression(args.suppress, args.reason or "")
        except AuditConfigId as exc:
            ap.error(str(exc))
        except ValueError as exc:
            sys.exit(f"actualis: {exc}")
        print(f"  suppressed {args.suppress} in {path}")
        if not args.reason:
            print(f"  {c.yellow}▲{c.off} no --reason given. In six months nobody "
                  f"will know why this is here.")
        print(f"  {c.dim}It stays counted; it leaves the actionable list. "
              f"Remove the line to undo.{c.off}")
        return 0

    if args.mcp:
        return mcp_serve()

    if args.explain is not None:
        return render_explain(args.explain or None, C(use_color()))

    if args.agents:
        rows = verify_agents()
        if args.json:
            json.dump({"agents": rows}, sys.stdout, indent=2)
            print()
        else:
            render_agents(rows, C(use_color()))
        return 0

    if args.watch:
        if args.root:
            root = Path(args.root).expanduser()
            w_roots, w_codex, w_copilot = (
                ([], [root], []) if args.agent == "codex"
                else ([], [], [root]) if args.agent == "copilot"
                else ([root], [], []))
        else:
            w_roots = transcript_roots() if args.agent in ("all", "claude") else []
            w_codex = codex_roots() if args.agent in ("all", "codex") else []
            w_copilot = copilot_roots() if args.agent in ("all", "copilot") else []
        return watch(w_roots, w_codex, max(args.interval, 0.5),
                     C(use_color()), args.quiet, args.no_redact, w_copilot)

    if args.replay:
        since_r = window_start(args.days, datetime.now(timezone.utc)) if args.days else None
        if not args.json and sys.stderr.isatty():
            print("  reading transcripts...", end="", file=sys.stderr, flush=True)
        events = replay_events(since_r, args.root)
        if not args.json and sys.stderr.isatty():
            print("\r" + " " * 30 + "\r", end="", file=sys.stderr, flush=True)
        inc = replay(args.replay, events)
        if not inc:
            print(f"actualis: {args.replay} does not appear in these transcripts.\n"
                  "  Fingerprints come from the report's credential table, or "
                  "`actualis --json | jq -r '.secrets[].id'`.", file=sys.stderr)
            return EXIT_CANNOT_RUN
        if args.json:
            json.dump(inc, sys.stdout, indent=2)
            print()
        else:
            render_replay(inc, C(use_color()))
        return EXIT_OK

    # Loaded here, after every mode that never scans: a malformed trust file
    # must not break --explain, --agents, --suppressions and the rest.
    try:
        network_trust, trust_sources = load_network_trust_sources(args.network_trust)
    except ValueError as exc:
        ap.error(str(exc))

    fleet = Fleet()
    progress = not args.json and sys.stderr.isatty()

    if args.ci_log:
        # A CI runner has no transcript directory to discover -- the agent ran
        # in this job and the action wrote one JSON array. Handled before
        # --root because the two are different shapes, and the --root error
        # message says so explicitly ("not a file").
        log = Path(args.ci_log).expanduser()
        if not log.is_file():
            sys.exit(f"actualis: {log} is not a file.\n"
                     "  --ci-log takes the Claude Code Action's execution_file "
                     "output,\n  normally $RUNNER_TEMP/claude-execution-output.json.")
        # Name the project after the repository when CI tells us, so the report
        # reads like the thing being audited rather than a temp path.
        repo = os.environ.get("GITHUB_REPOSITORY") or ""
        project = clean(repo.split("/")[-1]) if repo else "ci"
        fleet.roots.append(log)
        fleet.scan_execution_log(log, project, since)
    elif args.root:
        # --root names a directory; --agent says how to read it. Routing every
        # --root to the Claude parser meant `--root X --agent codex` silently
        # parsed Codex rollouts as Claude transcripts and reported nothing.
        root = Path(args.root).expanduser()
        if not root.is_dir():
            # Checked here rather than after the scan: scan() would otherwise
            # print its own generic "cannot read" first and bury this one.
            sys.exit(f"actualis: {root} is not a directory.\n"
                     "  --root takes a transcript directory, not a file or a project.")
        if args.agent == "codex":
            fleet.roots.append(root)
            fleet.scan_codex([root], since, args.project)
        elif args.agent == "copilot":
            fleet.roots.append(root)
            fleet.scan_copilot([root], since, args.project)
        else:
            fleet.scan([root], since, args.project, progress=progress)
    else:
        if args.agent in ("all", "claude"):
            roots = transcript_roots()
            if roots:
                fleet.scan(roots, since, args.project, progress=progress)
            elif args.agent == "claude":
                sys.exit(no_transcripts_message())
        if args.agent in ("all", "codex"):
            croots = codex_roots()
            if croots:
                fleet.roots.extend(croots)
                fleet.scan_codex(croots, since, args.project)
            elif args.agent == "codex":
                sys.exit(no_transcripts_message())
        if args.agent in ("all", "copilot"):
            proots = copilot_roots()
            if proots:
                fleet.roots.extend(proots)
                fleet.scan_copilot(proots, since, args.project)
            elif args.agent == "copilot":
                sys.exit(no_transcripts_message())

    if fleet.messages == 0 and fleet.bash_total == 0:
        print(dead_end_message(fleet, args), file=sys.stderr)
        return EXIT_CANNOT_RUN

    apply_network_policy(fleet, network_trust, args.network_strict, trust_sources)

    if args.diff:
        try:
            baseline = load_report(Path(args.diff).expanduser())
        except ValueError as exc:
            print(f"actualis: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        render_diff(diff_reports(baseline, to_json(fleet, raw=args.no_redact)),
                    C(use_color()))
        return EXIT_OK

    if args.why:
        return render_why(args.why, fleet, C(use_color()))

    if args.card:
        out_dir = card_dir
        try:
            model = card_model(fleet, args.card, args.days)
        except CardError as exc:
            print(f"actualis: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        try:
            svg, png = write_card(model, args.style, out_dir)
        except OSError as exc:
            print(f"actualis: cannot write the card to {out_dir}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_CANNOT_RUN
        print(f"  {svg}\n  {png}\n\n  {model['share']}")
        return EXIT_OK

    if args.json:
        json.dump(to_json(fleet, raw=args.no_redact), sys.stdout, indent=2)
        print()
    elif args.share:
        render_share(fleet, C(use_color()))
    elif args.aisvs:
        render_aisvs(aisvs_findings(fleet), C(use_color()))
    elif args.coach:
        render_coach(coach(fleet), C(use_color()))
    else:
        render(fleet, C(use_color()), bash_only=args.bash, top=args.top, raw=args.no_redact)

    if args.fail_on:
        reasons = failing_findings(fleet, args.fail_on)
        # stderr, so `--json` on stdout stays byte-identical and a pipeline can
        # capture the report and the verdict separately.
        if reasons:
            print(f"actualis: FAIL at --fail-on {args.fail_on}", file=sys.stderr)
            for r in reasons:
                print(f"  - {r}", file=sys.stderr)
            print(f"  {len(fleet.secrets) - len(fleet.actionable_secrets)} suppressed "
                  f"finding(s) were not counted.", file=sys.stderr)
            return EXIT_FINDINGS
        print(f"actualis: PASS at --fail-on {args.fail_on}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        os._exit(0)
