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
import sys
from collections import Counter, OrderedDict, defaultdict
from typing import NamedTuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

__version__ = "0.1.5"

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
    return (r.input, r.output, r.provider, r.tier == VENDOR, r.tier)


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
)


def flag_id(severity: str, categories: list[str], program: str) -> str:
    """A stable id for a class of shell-audit finding.

    Keyed on severity, category and program rather than on the command text, so
    the id survives the command changing slightly and suppressing one thing
    suppresses the class a person actually means: "rm being flagged destructive
    is expected in this repository", not "this exact rm invocation".
    """
    basis = f"{severity}:{','.join(sorted(categories))}:{program}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:8]


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
    # Authorization headers
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)([^\s'\"]{8,})"),
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


def redact(text: str) -> str:
    """Remove credential material from a command string. Idempotent."""
    if not text:
        return text
    out = text[:MAX_SCAN_TOTAL]
    # Order matters: the Authorization header rule must run before the generic
    # KEY=value rule, or "AUTH" in "Authorization:" makes it eat the scheme word.
    out = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    out = _SECRET_PATTERNS[3].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}{m.group(3)}", out)
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask(m.group(4))}", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
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


def _looks_like_placeholder(v: str) -> bool:
    low = v.lower()
    return (v.isdigit()
            or _SHELL_REF.match(v) is not None
            or _MASKED in v
            or low in {"true", "false", "null", "none", "undefined", "changeme", "example"}
            or low.startswith(("your_", "your-", "xxx", "<", "$(", "placeholder",
                               "dummy", "test_", "fake", "changeme", "example",
                               "insert_", "replace_", "todo")))


# A variable named STRIPE_SECRET_KEY is critical whether or not its value
# happens to carry a recognisable live-key prefix.
_CRITICAL_NAMES = re.compile(
    r"(?i)(stripe|aws|service_role|servicerole|private_key|master|root|prod|payment|billing)")


def _priority_for_name(name: str) -> str:
    return "critical" if _CRITICAL_NAMES.search(name) else "high"


def classify_secrets(cmd: str) -> list[tuple[str, str, str]]:
    """Return [(priority, type, sha256[:8])] for each distinct secret in a command.

    The secret value is hashed immediately and never retained.
    """
    cmd = cmd[:MAX_SCAN_TOTAL]
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(priority: str, kind: str, value: str) -> None:
        if _looks_like_placeholder(value):
            return
        fp = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
        if fp in seen:
            return
        seen.add(fp)
        out.append((priority, kind, fp))

    for priority, kind, rx in SECRET_TYPES:
        for m in rx.finditer(cmd):
            add(priority, kind, m.group(0))

    for m in _URL_CRED.finditer(cmd):
        scheme, _user, pw, host = m.groups()
        local = _LOCAL_HOST.match(host) is not None
        add("low" if local else "critical",
            clean(f"{scheme} password ({'local' if local else 'remote'})")[:48], pw)

    for m in _NAMED_SECRET.finditer(cmd):
        name, value = m.group(1), m.group(2)
        # Template placeholders arrive wrapped -- __X__, {{X}}, %X% -- and the
        # decoration is not part of the name. Strip it so a single exclusion
        # covers every spelling instead of one per template syntax.
        if _NOT_SECRET_NAMES.match(name.strip("_{}%$<>")):
            continue
        add(_priority_for_name(name), clean(name.upper())[:48], value)

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
            if _REDIRECT.match(tok):
                continue                      # redirection, not a program
            if tok.startswith("-"):
                continue                      # a flag is never the program
            if tok in _TAKES_PATH_ARG:
                skip_next = True              # `cd /some/path && real-cmd`
                continue
            return tok
    first = cmd.strip().split()
    return first[0] if first else None


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
        self.flags: list[dict] = []
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

        self.messages += 1
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

        cwd = model = None
        best: dict | None = None
        best_total = -1
        last_ts: datetime | None = None
        pending: list[tuple[str, datetime | None]] = []

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
                    elif kind == "turn_context":
                        cwd = payload.get("cwd") or cwd
                        model = payload.get("model") or model
                        pol = payload.get("approval_policy")
                        if pol:
                            self.permission_modes[f"codex:{pol}"] += 1
                        sb = payload.get("sandbox_policy")
                        if isinstance(sb, dict) and sb.get("type"):
                            self.permission_modes[f"sandbox:{sb['type']}"] += 1
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
                            pending.append((cmd, ts))
                            cwd = args.get("workdir") or cwd
        except OSError:
            return

        if since and last_ts and last_ts < since:
            return
        project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "unknown"
        if project_filter and project_filter.lower() not in project.lower():
            return

        for cmd, ts in pending:
            # Normalise Codex's shell_command onto the same "Bash" tool name the
            # Claude Code path uses, so the audit is one cross-agent view.
            self.add_tool(project, "Bash", {"command": cmd}, ts)

        if best:
            self.add_codex_session(project, model or "unknown", best, last_ts)

    def add_refusal(self, kind: str, rec: dict, project: str,
                    ts: datetime | None, calls: dict[str, tuple[str, str]]) -> None:
        """Attribute one refusal to the tool call it blocked.

        The refusal record carries no tool_use block of its own; it points back
        through `tool_use_id` on its tool_result. Reading only the refusal
        record tells you a refusal happened and nothing about what was refused.
        """
        self.refusals += 1
        self.refusal_project[project][kind] += 1
        if ts:
            self.refusal_week[ts.strftime("%Y-W%V")][kind] += 1

        msg = rec.get("message")
        blocks = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(blocks, list):
            return
        for b in blocks:
            if not isinstance(b, dict) or b.get("type") != "tool_result":
                continue
            hit = calls.get(b.get("tool_use_id") or "")
            if not hit:
                continue
            name, cmd = hit
            self.refusals_joined += 1
            self.refusal_tool[kind][clean(name)[:48] or "?"] += 1
            if name == "Bash" and cmd:
                head = command_head(cmd)
                if head:
                    self.refusal_program[kind][clean(head)[:40]] += 1
            return

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

    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None) -> None:
        project = clean(project)[:120] or "unknown"
        name = clean(name)[:48] or "?"
        self.tools[name] += 1
        if name != "Bash":
            return
        cmd = (tool_input or {}).get("command") or ""
        if not cmd:
            return
        self.bash_total += 1
        self.bash_by_project[project] += 1
        head = command_head(cmd)
        if head:
            self.bash_first_token[clean(head)[:40]] += 1

        shapes = unreadable_shapes(cmd)
        if shapes:
            self.unreadable += 1
            for name in shapes:
                self.unreadable_shapes[name] += 1

        if contains_secret(cmd):
            self.secret_exposures += 1
            self.secret_projects[project] += 1

        _rank = {"critical": 0, "high": 1, "low": 2}
        for priority, kind, fp in classify_secrets(cmd):
            e = self.secrets.setdefault(fp, {
                "priority": priority, "kinds": set(), "uses": 0,
                "first": None, "last": None, "projects": set(),
                "suppressed": fp in self.suppressions,
                "suppressed_reason": self.suppressions.get(fp, "")})
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
            for f in d.glob("*.jsonl"):
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
        calls: dict[str, tuple[str, str]] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    # Cheap prefilter: skip lines that cannot contribute to any
                    # counter. Must include the permission fields, which live on
                    # records that carry neither usage nor tool_use.
                    if ('"usage"' not in line and '"tool_use"' not in line
                            and '"permissionMode"' not in line
                            and '"toolDenialKind"' not in line):
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(rec, dict):
                        continue

                    ts = parse_ts(rec.get("timestamp"))
                    if since and ts and ts < since:
                        continue

                    mode = rec.get("permissionMode")
                    if mode:
                        self.permission_modes[mode] += 1
                    denial = rec.get("toolDenialKind")
                    if denial:
                        self.denials[denial] += 1
                        self.denials_by_project[project] += 1
                        self.add_refusal(str(denial), rec, project, ts, calls)
                    eff = rec.get("effort")
                    if eff:
                        self.effort_mix[str(eff)] += 1

                    msg = rec.get("message")
                    if not isinstance(msg, dict):
                        continue

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
                                              block.get("input") or {}, ts)
                                if block.get("id"):
                                    calls[block["id"]] = (
                                        block.get("name") or "?",
                                        ((block.get("input") or {}).get("command") or "")
                                        [:MAX_SCAN_LINE])
        except OSError:
            return

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
    auto = sum(v for k, v in fleet.permission_modes.items()
               if "auto" in k.lower() or "bypass" in k.lower())
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
    crit = [(fp, e) for fp, e in fleet.secrets.items() if e["priority"] == "critical"]
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
    dated = [(fp, e) for fp, e in fleet.secrets.items()
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
    if fleet.messages >= 500 and fleet.duplicate_usage_records == 0:
        out.append(Finding(
            "AF012", "critical", "Deduplication collapsed nothing, which should be impossible",
            f"{num(fleet.messages)} messages were counted and not one repeated record "
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


def _jsonl_files(roots: list[Path], codex: list[Path]) -> list[Path]:
    out: list[Path] = []
    for r in roots:
        try:
            out.extend(f for d in r.iterdir() if d.is_dir() for f in d.glob("*.jsonl"))
        except OSError:
            continue
    for r in codex:
        try:
            out.extend(r.rglob("rollout-*.jsonl"))
        except OSError:
            continue
    return out


def watch(roots: list[Path], codex: list[Path], interval: float, c: C,
          quiet: bool, raw: bool) -> int:
    import time

    # Python block-buffers stdout when it is not a terminal. For a watcher that
    # means an alert can sit unwritten in a 4KB buffer for hours, which defeats
    # the entire point of running it in the background.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    offsets: dict[Path, int] = {}
    for f in _jsonl_files(roots, codex):
        try:
            offsets[f] = f.stat().st_size      # start at EOF: history is not news
        except OSError:
            pass

    seen_secrets: set[str] = set()
    cmds = flagged = crit = 0
    started = datetime.now(timezone.utc)

    srcs = ", ".join(str(r) for r in (roots + codex))
    print(f"{c.bold}actualis watch{c.off} {c.dim}· {len(offsets)} files · every "
          f"{interval:g}s · ctrl-c to stop{c.off}")
    print(f"{c.dim}watching {srcs}{c.off}")
    print(f"{c.dim}Starting from now. Existing history is not replayed.{c.off}\n")

    try:
        while True:
            for f in _jsonl_files(roots, codex):
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

                project = pretty_project(f.parent.name)
                for line in chunk.splitlines():
                    if '"tool_use"' not in line and '"function_call"' not in line:
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
                            print(f"\r{c.red}▲ SECRET{c.off}  {msg}  {c.dim}{fp}{c.off}"
                                  + " " * 20)
                            notify("actualis: credential exposed", msg)
                        hits = audit_command(command)
                        high = [h for h in hits if h[0] == "high"]
                        if high:
                            flagged += 1
                            cats = ",".join(sorted({h[1] for h in high}))
                            line_txt = high[0][2] if raw else redact(high[0][2])
                            print(f"\r{c.yellow}▲ {cats}{c.off}  {line_txt[:88]}"
                                  f"  {c.dim}{project[:28]}{c.off}" + " " * 10)
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
    """Every shell command in one transcript record, across both agent formats."""
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
# Two agents are supported, unevenly, and until now nothing said how. Someone
# comparing a Claude Code project against a Codex one was comparing different
# measurements without being told which.
#
# Kept beside the code that consumes each field so a reader can check a claim
# here against the parser that makes it. A test asserts every capability names
# the field it depends on.
# --------------------------------------------------------------------------

YES, PARTIAL, NO = "yes", "partial", "no"

VENDOR_CAPABILITIES = (
    # capability,            claude,   codex,   the field it rests on
    ("Cost and token usage", YES,      YES,     "message.usage / token_count"),
    ("Per-message dedup",    YES,      PARTIAL, "message.id; Codex reports a cumulative "
                                                "session total instead, so the max is taken"),
    ("Shell command text",   YES,      YES,     "tool_use Bash / function_call shell_command"),
    ("Project attribution",  YES,      YES,     "cwd"),
    ("Git branch",           YES,      NO,      "gitBranch; Codex rollouts carry no branch, "
                                                "so cost per ticket is Claude Code only"),
    ("Tool refusals",        YES,      NO,      "toolDenialKind joined by tool_use_id; Codex "
                                                "writes no per-refusal record at all"),
    ("Permission mode",      YES,      YES,     "permissionMode / approval_policy"),
    ("Sandbox policy",       NO,       YES,     "sandbox_policy; Claude Code has no equivalent"),
    ("Subagent activity",    PARTIAL,  NO,      "toolUseResult.toolStats; command text is never "
                                                "written to the parent transcript"),
    ("Subagent cost",        NO,       NO,      "only each run's final message survives, so a "
                                                "floor is reported and excluded from the total"),
    ("Cache TTL split",      PARTIAL,  NO,      "cache_creation ephemeral_1h/5m; older records "
                                                "carry a flat total and OpenAI has no equivalent"),
    ("Reasoning effort",     YES,      NO,      "effort"),
)


def vendor_gaps(vendor: str) -> list[tuple[str, str]]:
    """Capabilities this vendor does not fully provide, with the reason."""
    idx = 1 if vendor == "claude" else 2
    return [(cap, why) for cap, c, x, why in VENDOR_CAPABILITIES
            if (c if idx == 1 else x) != YES]


EXPLAIN: dict[str, dict[str, object]] = {
    "sources": {
        "measures": "Which files every number is derived from.",
        "formula": [
            "Claude Code  ~/.claude/projects/**/*.jsonl  (plus $CLAUDE_CONFIG_DIR)",
            "Codex        $CODEX_HOME/sessions/**/rollout-*.jsonl",
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
            "capability                claude   codex",
        ] + [f"  {cap:<24}{c:<9}{x}" for cap, c, x, _why in VENDOR_CAPABILITIES] + [
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
            "",
            "A secret is a VALUE: the same one under two variable names is one row,",
            "and the worst priority wins.",
        ],
        "assumes": [
            "Pattern matching has a ceiling. Dynamically built values, secrets read",
            "from files, and anything inside a subagent are NOT detectable.",
            "This raises the floor on visibility. It is not a security boundary.",
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
            since = (datetime.now(timezone.utc) - timedelta(days=days)) if days else None
            roots = transcript_roots()
            if roots:
                f.scan(roots, since, project, progress=False)
            croots = codex_roots()
            if croots:
                f.roots.extend(croots)
                f.scan_codex(croots, since, project)
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
        unsup = sum(v for k, v in f.permission_modes.items()
                    if "auto" in k.lower() or "bypass" in k.lower())
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
            "note": "fingerprints are sha256[:8]; values are never stored or returned",
            "secrets": [{"priority": e["priority"], "types": sorted(e["kinds"]),
                         "fingerprint": fp, "uses": e["uses"],
                         "first_seen": e["first"], "last_seen": e["last"],
                         "projects": sorted(e["projects"])} for fp, e in rows[:50]],
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


def rule(c: C, title: str = "", width: int = 74) -> None:
    if title:
        pad = width - len(title) - 3
        print(f"\n{c.bold}{title}{c.off} {c.dim}{'─' * max(pad, 0)}{c.off}")
    else:
        print(f"{c.dim}{'─' * width}{c.off}")


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

    if fleet.refusals:
        rule(c, "REFUSALS")
        print(f"  {c.dim}What was stopped, and by whom. A refused command is never "
              f"sent,{c.off}")
        print(f"  {c.dim}so this exists only in your local transcripts.{c.off}")
        if "codex" in fleet.cost_by_agent:
            print(f"  {c.yellow}▲{c.off} {c.dim}Claude Code only. Codex writes no "
                  f"per-refusal record, so its sessions are absent here.{c.off}")
        print()
        gates = sorted(fleet.refusal_tool,
                       key=lambda k: -sum(fleet.refusal_tool[k].values()))
        for kind in gates:
            who = "a human" if kind == "user-rejected" else "the policy"
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
        if len(rows) > 24:
            print(f"    {c.dim}… {len(rows) - 24} more{c.off}")
        print(f"\n    {c.dim}id is sha256[:8] of the secret; the value is never stored or")
        print(f"    printed. Same secret reused 200 times counts once. Rotate in the order")
        print(f"    shown, then purge the transcripts that carry them.{c.off}")
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
    unsup = sum(v for k, v in fleet.permission_modes.items()
                if "auto" in k.lower() or "bypass" in k.lower())
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
        print(f"\n  {d}models{o}  " + "   ".join(
            f"{m} {n / sum(fleet.msgs_by_model.values()) * 100:.0f}%"
            for m, n in fleet.msgs_by_model.most_common(4) if m != "<synthetic>"))

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
    "secret_projects.*": "int",
    "redacted": "bool",
    "permission_modes.*": "int",
    "denials.*": "int",
    "suppressed_flags": "int",
    "vendors.capabilities": "array",
    "vendors.capabilities[].capability": "str",
    "vendors.capabilities[].claude": "str",
    "vendors.capabilities[].codex": "str",
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
             "suppressed_reason": e.get("suppressed_reason", "")}
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
                {"capability": cap, "claude": c, "codex": x, "depends_on": why}
                for cap, c, x, why in VENDOR_CAPABILITIES
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
        "unknown_models": dict(fleet.unknown_models),
        "aggregator_priced_models": dict(fleet.aggregator_models),
    }


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="actualis",
        description="What actually ran. Local, read-only, honest about limits.",
    )
    ap.add_argument("--days", type=int, metavar="N", help="only the last N days")
    ap.add_argument("--project", metavar="SUBSTR", help="only projects matching SUBSTR")
    ap.add_argument("--top", type=int, default=12, metavar="N", help="projects to list (default 12)")
    ap.add_argument("--bash", action="store_true", help="shell audit only")
    ap.add_argument("--coach", action="store_true", help="coaching findings only")
    ap.add_argument("--explain", nargs="?", const="", metavar="TOPIC",
                    help="how a number is computed, what it assumes, how to check it")
    ap.add_argument("--why", metavar="AFxxx",
                    help="explain one coach finding against your actual numbers")
    ap.add_argument("--agents", action="store_true",
                    help="which agent platforms are installed, and whether their "
                         "binaries are validly signed by the expected publisher")
    ap.add_argument("--mcp", action="store_true",
                    help="run as an MCP server over stdio so an agent can query itself")
    ap.add_argument("--share", action="store_true",
                    help="postable summary with nothing identifying in it")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--watch", action="store_true",
                    help="live monitor: alert on new secrets and risky commands")
    ap.add_argument("--interval", type=float, default=4.0, metavar="SEC",
                    help="--watch poll interval (default 4)")
    ap.add_argument("--quiet", action="store_true",
                    help="--watch: notify on secrets only, not every flagged command")
    ap.add_argument("--agent", choices=["all", "claude", "codex"], default="all",
                    help="which agents to include (default: all)")
    ap.add_argument("--no-redact", action="store_true",
                    help="do NOT redact credentials from output (unsafe to share)")
    ap.add_argument("--suppress", metavar="ID",
                    help="mark a finding as a false positive on this machine. "
                         "It stays counted; it leaves the actionable list.")
    ap.add_argument("--reason", metavar="TEXT",
                    help="why --suppress is correct. Recorded so the file is "
                         "reviewable later.")
    ap.add_argument("--suppressions", action="store_true",
                    help="list current suppressions and where they come from")
    ap.add_argument("--root", metavar="DIR", help="transcript directory")
    ap.add_argument("--version", action="version", version=f"actualis {__version__}")
    args = ap.parse_args(argv)

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
            print(f"  {fp}  {c.dim}{why}{c.off}")
        print(f"\n  {c.dim}Suppressed findings are still counted and still appear "
              f"in --json.{c.off}")
        return 0

    if args.suppress:
        c = C(use_color())
        try:
            path = add_suppression(args.suppress, args.reason or "")
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
            w_roots, w_codex = ([], [root]) if args.agent == "codex" else ([root], [])
        else:
            w_roots = transcript_roots() if args.agent in ("all", "claude") else []
            w_codex = codex_roots() if args.agent in ("all", "codex") else []
        return watch(w_roots, w_codex, max(args.interval, 0.5),
                     C(use_color()), args.quiet, args.no_redact)

    fleet = Fleet()
    progress = not args.json and sys.stderr.isatty()

    if args.root:
        # --root names a directory; --agent says how to read it. Routing every
        # --root to the Claude parser meant `--root X --agent codex` silently
        # parsed Codex rollouts as Claude transcripts and reported nothing.
        root = Path(args.root).expanduser()
        if args.agent == "codex":
            fleet.roots.append(root)
            fleet.scan_codex([root], since, args.project)
        else:
            fleet.scan([root], since, args.project, progress=progress)
    else:
        if args.agent in ("all", "claude"):
            roots = transcript_roots()
            if roots:
                fleet.scan(roots, since, args.project, progress=progress)
            elif args.agent == "claude":
                sys.exit("actualis: no Claude Code transcripts found.")
        if args.agent in ("all", "codex"):
            croots = codex_roots()
            if croots:
                fleet.roots.extend(croots)
                fleet.scan_codex(croots, since, args.project)
            elif args.agent == "codex":
                sys.exit("actualis: no Codex sessions found under $CODEX_HOME/sessions.")

    if fleet.messages == 0 and fleet.bash_total == 0:
        print("actualis: no matching activity found.", file=sys.stderr)
        return 1

    if args.why:
        return render_why(args.why, fleet, C(use_color()))

    if args.json:
        json.dump(to_json(fleet, raw=args.no_redact), sys.stdout, indent=2)
        print()
    elif args.share:
        render_share(fleet, C(use_color()))
    elif args.coach:
        render_coach(coach(fleet), C(use_color()))
    else:
        render(fleet, C(use_color()), bash_only=args.bash, top=args.top, raw=args.no_redact)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        os._exit(0)
