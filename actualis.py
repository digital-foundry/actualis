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
import base64
import hashlib
import html as _html
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

__version__ = "0.5.1"

# --------------------------------------------------------------------------
# Pricing
#
# USD per million tokens, Anthropic first-party API rates.
# Source: Anthropic pricing, verified 2026-10-08.
# Cache multipliers apply to the model's INPUT rate:
#   read           0.10x by default; 0.05x Opus 5.5 / Sonnet 5.5,
#                  0.025x Fable 5.1 / Mythos 5.1 (Rate.cache_read)
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
# No price at all: a model whose vendor publishes none (gemini-3.5-flash, every
# Qwen model). Its tokens are counted and its cost is not: zero is added, the
# model is listed as unpriced, and nothing is guessed. Last, below DEFAULT,
# because a ceiling is at least a bound and this is not even that.
UNPRICED = "unpriced"

RATE_TIERS = (VENDOR, VENDOR_DOC, AGGREGATOR, FAMILY, DEFAULT, UNPRICED)

# How far a rate can drift out of date before the report stops presenting it
# without comment. Model prices move on the order of months, so a table older
# than a quarter is a number worth doubting rather than quoting.
PRICING_VERIFIED = "2026-10-08"
PRICING_STALE_DAYS = 90

RATE_SOURCES = {
    "anthropic": "https://platform.claude.com/docs/en/about-claude/pricing",
    "openai": "https://developers.openai.com/api/docs/pricing",
    "google": "https://ai.google.dev/gemini-api/docs/pricing",
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
    # Cache reads cost this multiple of the input rate. 0.10 unless the model's
    # row says otherwise, so a cheaper read is a property of the model.
    cache_read: float = CACHE_READ_MULT
    # A row with long_prompt reprices a whole message once its prompt exceeds
    # long_prompt_tokens. Applied by Fleet.add_usage and Fleet.add_model_usage.
    long_prompt: "Rate | None" = None
    # The prompt size above which long_prompt applies, per row, on every cost
    # path. Haiku 5.5 switches at 100,000; Gemini Pro models at 200,000.
    long_prompt_tokens: int = 100_000

    @property
    def confident(self) -> bool:
        """Sourced from the provider itself, rather than inferred or guessed."""
        return self.tier in (VENDOR, VENDOR_DOC)


LONG_PROMPT_TOKENS = 100_000

PRICING: dict[str, Rate] = {
    "claude-fable-5-1":   Rate(10.0, 50.0, "anthropic", VENDOR, cache_read=0.025),
    "claude-mythos-5-1":  Rate(10.0, 50.0, "anthropic", VENDOR, cache_read=0.025),
    "claude-opus-5-5":    Rate(4.0, 20.0, "anthropic", VENDOR, cache_read=0.05),
    "claude-sonnet-5-5":  Rate(2.0, 10.0, "anthropic", VENDOR, cache_read=0.05),
    # Prompt > 100,000 tokens (input + cache read + cache write of one message)
    # prices the whole message at 0.50 / 2.50.
    "claude-haiku-5-5":   Rate(0.10, 0.50, "anthropic", VENDOR,
                               long_prompt=Rate(0.50, 2.50, "anthropic", VENDOR)),
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
    # Claude Opus 4 and Sonnet 4 launched at these prices (2025-05-22). Both are
    # retired; the rows exist so their dated ids price as themselves rather than
    # as the newest sibling.
    "claude-opus-4":      Rate(15.0, 75.0, "anthropic", VENDOR, "retired", retired=True),
    "claude-sonnet-5":    Rate(2.0, 10.0, "anthropic", VENDOR),
    "claude-sonnet-4-6":  Rate(3.0, 15.0, "anthropic", VENDOR),
    "claude-sonnet-4-5":  Rate(3.0, 15.0, "anthropic", VENDOR),
    "claude-sonnet-4":    Rate(3.0, 15.0, "anthropic", VENDOR, "retired", retired=True),
    "claude-haiku-4-5":   Rate(1.0, 5.0, "anthropic", VENDOR),
    # Keyed as the API names it (claude-3-5-haiku-20241022); the 3.x ids put
    # the version before the family word.
    "claude-3-5-haiku":   Rate(0.80, 4.0, "anthropic", VENDOR),

    "gpt-5.2":            Rate(1.75, 14.0, "openai", VENDOR),
    "gpt-5.3-codex":      Rate(1.75, 14.0, "openai", VENDOR),
    # OpenAI publishes no `gpt-5.2-codex` line. This matches what they charge
    # for gpt-5.2 and gpt-5.3-codex, which is corroboration and not confirmation.
    "gpt-5.2-codex":      Rate(1.75, 14.0, "openai", AGGREGATOR,
                               "pricepertoken.com, 2026-08-22; no vendor line exists"),

    # Google Gemini API, Standard paid tier, USD per 1M tokens.
    # Source: https://ai.google.dev/gemini-api/docs/pricing ("Last updated
    # 2026-10-13 UTC", fetched 2026-10-13). Output is "including thinking
    # tokens", so thoughts are billed at the output rate. Cached input is a
    # tenth of input on every row but gemini-4-argon (a twentieth). Pro models
    # reprice the whole message when its prompt exceeds 200,000 tokens.
    # Context-cache storage is billed per hour and is not in any transcript.
    # Rows that change price on a date are in PRICE_CHANGES below.
    # Not priced on that page, so absent here and reported unpriced:
    # gemini-3-pro-preview, gemini-3.5-flash, gemini-3-flash, gemini-3.7-flash.
    "gemini-2.5-pro":     Rate(1.25, 10.0, "google", VENDOR, cache_read=0.10,
                               long_prompt=Rate(2.50, 15.0, "google", VENDOR, cache_read=0.10),
                               long_prompt_tokens=200_000),
    "gemini-3.1-pro-preview": Rate(2.0, 12.0, "google", VENDOR, cache_read=0.10,
                                   long_prompt=Rate(4.0, 18.0, "google", VENDOR, cache_read=0.10),
                                   long_prompt_tokens=200_000),
    "gemini-3.1-pro-preview-customtools": Rate(
        2.0, 12.0, "google", VENDOR, cache_read=0.10,
        long_prompt=Rate(4.0, 18.0, "google", VENDOR, cache_read=0.10),
        long_prompt_tokens=200_000),
    # Text, image and video input; audio input is $1.00 and not modelled.
    "gemini-2.5-flash":   Rate(0.30, 2.50, "google", VENDOR, cache_read=0.10),
    "gemini-2.5-flash-lite": Rate(0.10, 0.40, "google", VENDOR, cache_read=0.10),
    "gemini-3-flash-preview": Rate(0.50, 3.0, "google", VENDOR, cache_read=0.10),
    "gemini-3.1-flash-lite": Rate(0.25, 1.50, "google", VENDOR, cache_read=0.10),
    "gemini-3.5-flash-lite": Rate(0.30, 2.50, "google", VENDOR, cache_read=0.10),
    "gemini-3.6-flash":   Rate(0.75, 3.75, "google", VENDOR, cache_read=0.10),
    "gemini-3.8-flash":   Rate(0.75, 3.75, "google", VENDOR, cache_read=0.10),
    "gemini-4-argon":     Rate(2.0, 10.0, "google", VENDOR, cache_read=0.05),
}

# Published price changes, applied by the date of the message they price
# (UTC): model -> ((first day of the new price, new rate), ...), oldest first.
# A record with no timestamp is priced at the PRICING row, the price in force
# when the table was last checked. Same source as the Gemini rows above.
PRICE_CHANGES: dict[str, tuple] = {
    # "$0.75 through 2026-12-31, then $1.50" (input; output and cache alike).
    "gemini-3.6-flash": ((date(2027, 1, 1), Rate(1.50, 7.50, "google", VENDOR, cache_read=0.10)),),
    "gemini-3.8-flash": ((date(2027, 1, 1), Rate(1.50, 7.50, "google", VENDOR, cache_read=0.10)),),
    # "$2.00 through 2026-11-30, then $4.00".
    "gemini-4-argon":   ((date(2026, 12, 1), Rate(4.0, 20.0, "google", VENDOR, cache_read=0.05)),),
}

# Model families whose vendor publishes no price for an id missing from the
# table: Google's unpriced Gemini ids, Gemma, and Qwen. Never priced by family
# or ceiling (a Claude ceiling on a Flash model would overstate it 10-30x).
_NO_PRICE_FAMILIES = re.compile(r"^(?:gemini|gemma|qwen|qwq)", re.I)

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
        # A dated id (claude-haiku-4-5-20251001) is that model, not a new one.
        # Retired rows count here: a dated id of a retired model is that model,
        # and pricing it as the newest sibling understates history 3-5x.
        dated = [k for k in PRICING
                 if k.startswith(family) and re.fullmatch(re.escape(k) + r"-\d{8}", model)]
        if dated:
            # That model's own row, with that row's own source: the id names
            # it exactly, so nothing about the price is inferred.
            name = max(dated, key=len)
            best = PRICING[name]
            return best._replace(note=f"dated id; priced as {name}")
        siblings = {k: r for k, r in PRICING.items()
                    if k.startswith(family) and not r.retired}
        if not siblings:
            continue
        # Newest generation in the family, not the dearest sibling: the highest
        # version number wins, and on a tie the more expensive one.
        def newest(kv: tuple[str, Rate]) -> tuple:
            ver = tuple(int(n) for n in re.findall(r"\d+", kv[0][len(family):]))
            return (ver, kv[1].output, kv[1].input)
        name, best = max(siblings.items(), key=newest)
        return best._replace(provider=provider, tier=FAMILY,
                             note=f"not in the table; priced as {name}, the newest "
                                  f"known {family} model")
    return None


# A date (`-20250514`, Vertex's `@20250514`) or Anthropic's `-0` alias suffix
# names a model already in the table, not a new one.
_MODEL_ID_SUFFIX = re.compile(r"(?:-\d{8}|@\d{8}|-0)$")


def _base_model_id(model: str) -> str:
    """The table key a dated or `-0` id stands for: claude-opus-4-0 is
    claude-opus-4, claude-sonnet-4@20250514 is claude-sonnet-4."""
    for _ in range(2):                       # claude-opus-4-0-20250514
        model = _MODEL_ID_SUFFIX.sub("", model)
    return model


def unpriced_rate(model: str) -> Rate:
    """A model with no published price: zero, tier UNPRICED. Its tokens still
    count; its cost is unknown and is never filled in with a guess."""
    m = (model or "").lower()
    provider = ("google" if m.startswith(("gemini", "gemma"))
                else "alibaba" if m.startswith(("qwen", "qwq")) else "unknown")
    return Rate(0.0, 0.0, provider, UNPRICED,
                "no published rate for this model; tokens shown, cost not counted")


def rate_at(model: str, when: datetime | None) -> Rate:
    """rate_for, with PRICE_CHANGES applied for the UTC date of `when`."""
    r = rate_for(model)
    changes = PRICE_CHANGES.get(model) or PRICE_CHANGES.get(_base_model_id(model))
    if changes and when is not None:
        try:
            day = when.astimezone(timezone.utc).date() if when.tzinfo else when.date()
        except (OverflowError, ValueError):
            return r
        for start, new in changes:
            if day >= start:
                r = new
    return r


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
    base = _base_model_id(model)
    if base != model and base in PRICING:
        # The id names that exact model, so it keeps the row's own tier: a
        # dated Sonnet is priced from Anthropic's list, not inferred.
        kind = "dated id" if re.search(r"[-@]\d{8}$", model) else "alias id"
        return PRICING[base]._replace(note=f"{kind}; priced as {base}")
    if _NO_PRICE_FAMILIES.match(model):
        return unpriced_rate(model)
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

    `when` prices a model by the date of the message: PRICE_CHANGES holds
    the rates that change on a date.
    """
    r = rate_at(model, when)
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
    # Combined (-rf, -fr) or split (-r -f, --recursive --force) flags, after up
    # to 8 other options. Every repeat is bounded, so the scan stays linear.
    # A cluster may hold other letters too (-rfv, -frd, -r -fv); each lookahead
    # is bounded, so a long run of letters is scanned a bounded number of times.
    ("high", "destructive",      r"\brm\s+(?:-\S{1,64}\s+){0,8}?"
                                 r"(-(?=[a-z]{0,63}r)(?=[a-z]{0,63}f)[a-z]{2,64}"
                                 r"|(?:-(?=[a-z]{0,63}r)[a-z]{1,64}|--recursive)\s+(?:-\S{1,64}\s+){0,8}?"
                                 r"(?:-(?=[a-z]{0,63}f)[a-z]{1,64}|--force)"
                                 r"|(?:-(?=[a-z]{0,63}f)[a-z]{1,64}|--force)\s+(?:-\S{1,64}\s+){0,8}?"
                                 r"(?:-(?=[a-z]{0,63}r)[a-z]{1,64}|--recursive))\b"),
    ("high", "destructive",      r"\b(mkfs|fdisk|diskutil\s+erase)\b"),
    # `dd ... of=/dev/`: anchored at the line start, the prefix runs to the
    # FIRST `dd`, so a line of many `dd` words is scanned once, not once per word
    # (`\bdd\s+.*\bof=/dev/` was O(n^2) per line). Same matches.
    ("high", "destructive",      r"^(?:(?!\bdd\s)[^\n])*\bdd\s[^\n]*\bof=/dev/"),
    ("med",  "destructive",      r"\btruncate\s+-s\s*0\b"),
    # Anchored like the dd rule: the prefix runs to the FIRST find, so a line of
    # many `find` words is scanned once (`\bfind\b.*-delete` was O(n^2)).
    ("med",  "destructive",      r"^(?:(?!\bfind\b)[^\n])*\bfind\b[^\n]*-delete\b"),

    # --- privilege escalation ---
    # Only where sudo / su is the program run (after a separator, a keyword
    # such as then/do, an assignment or a wrapper): decided in code by
    # _at_command_start, so `apt install sudo` and `echo sudo` stay quiet.
    ("high", "privilege",        r"\bsudo\b"),
    ("high", "privilege",        r"\bsu\s+-"),
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
                                 r"(\.env(\.[a-z]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|\.pem|\.p12|credentials|\.netrc|\.npmrc|\.pypirc)\b"),
    ("high", "credentials",      r"\bsecurity\s+find-(generic|internet)-password\b"),
    ("med",  "credentials",      r"\b(printenv|env)\b\s*(\||$)"),
    ("med",  "credentials",      r"\b(AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN)\s*="),
    ("high", "credentials",      r"\bgh\s+auth\s+token\b"),

    # --- data egress ---
    # Case-sensitive on the flags: curl -D (dump headers) is not curl -d (send body).
    # Skipped when every destination of that curl is loopback: decided in code
    # by _curl_to_loopback_only, not by a lookahead, because "localhost" in a
    # header or a query string is not where the data goes.
    ("high", "egress",           r"\bcurl\b[^|;\n]{0,512}\s(?-i:-d|--data|--data-raw|--data-binary|-F|--form|-T|--upload-file|--json)\b"),
    # Decided in code, linearly (_scp_egress_hits); the pattern says what it matches.
    ("med",  "egress",           r"\b(scp|rsync)\b[^|;\n]{0,512}\s[^\s@]+@[^\s@:]+:"),

    # --- git danger ---
    ("high", "git",              r"\bgit\s+push\b[^|;\n]{0,512}\s(--force|-f)\b"),
    ("high", "git",              r"\bgit\s+(filter-branch|filter-repo)\b"),
    ("med",  "git",              r"\bgit\s+reset\s+--hard\b"),
    ("med",  "git",              r"\bgit\s+clean\s+-[a-zA-Z]*f"),
    ("med",  "git",              r"^(?:(?!\bgit\s+checkout\s+(?:main|master|prod\w*)\b)[^\n])*"
                                 r"\bgit\s+checkout\s+(main|master|prod\w*)\b[^\n]*\s--\s"),

    # --- publish and deploy ---
    ("high", "publish",          r"\b(npm|pnpm|yarn)\s+publish\b"),
    ("high", "publish",          r"\b(twine\s+upload|cargo\s+publish|gem\s+push)\b"),
    ("high", "publish",          r"^(?:(?!\b(?:kubectl|helm)\b)[^\n])*\b(kubectl|helm)\b[^\n]*\b(delete|destroy)\b"),
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

# One entry per BASH_RULES row, in the same order: lowercase literals of which
# at least one must occur in a line for that rule to be able to match it. A
# line holding none of them skips the regex. Written by hand from each rule,
# never derived by parsing it, and each literal is a run the regex requires
# contiguously (no \s inside one). None means the rule always runs.
# re.IGNORECASE matches exactly four non-ASCII characters to ASCII letters
# (U+0130 and U+0131 to i, U+017F to s, U+212A to k); _fold_lower maps them
# before lowering, so no match is skipped. Checked against the unfiltered path
# by tests/test_audit_prefilter.py.
RULE_PREFILTERS: list[tuple[str, ...] | None] = [
    ("rm",),                                            # rm -rf
    ("mkfs", "fdisk", "diskutil"),
    ("of=/dev/",),                                      # dd ... of=/dev/
    ("truncate",),
    ("-delete",),                                       # find ... -delete
    ("sudo",),
    ("su",),                                            # su -
    ("777",),                                           # chmod 777
    ("chown",),
    ("curl", "wget"),                                   # ... | sh
    ("curl", "wget"),                                   # ... | python
    ("npx",),
    ("pip",),
    (".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".p12", "credentials", ".netrc", ".npmrc", ".pypirc"),
    ("find-generic-password", "find-internet-password"),
    ("env",),                                           # printenv | env
    ("aws_secret_access_key", "anthropic_api_key", "openai_api_key", "github_token"),
    ("auth",),                                          # gh auth token
    ("curl",),                                          # curl -d / --data / -F / -T
    ("scp", "rsync"),
    ("push",),                                          # git push --force
    ("filter-branch", "filter-repo"),
    ("--hard",),                                        # git reset --hard
    ("clean",),
    ("checkout",),
    ("publish",),                                       # npm publish
    ("twine", "cargo", "gem"),
    ("kubectl", "helm"),
    ("terraform",),
    ("deploy",),
    ("--delete",),                                      # aws s3 rm|sync --delete
    ("drop", "truncate"),
    ("delete",),                                        # DELETE FROM
    ("psql", "mysql", "mongosh"),
    ("history",),
    ("histfile", "histsize=0"),
]

# A second, cheaper gate for the rules whose regex is costly on a long line of
# their start word (`curl ` x 200,000 cost ~2 s): a lowercase literal of which
# at least one MUST also occur in the line, because the regex requires it
# (curl … | sh needs a `|`; curl -d needs `-d`, `-f`, `-t` or `--json` in some
# spelling). Keyed by the rule's pattern; never derived by parsing it.
_RULE_REQUIRES_BY_PATTERN: dict[str, tuple[str, ...]] = {
    r"\b(curl|wget)\b[^|;\n]{0,512}\|\s*(sudo\s+)?(ba|z|k)?sh\b": ("|",),
    r"\b(curl|wget)\b[^|;\n]{0,512}\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b"
    r"(?!\s+-(?:c|e|m|p)\b)": ("|",),
    r"\bcurl\b[^|;\n]{0,512}\s(?-i:-d|--data|--data-raw|--data-binary|-F|--form|-T|--upload-file|--json)\b":
        ("-d", "-f", "-t", "--json"),
    r"\b(scp|rsync)\b[^|;\n]{0,512}\s[^\s@]+@[^\s@:]+:": ("@",),
    r"\bgit\s+push\b[^|;\n]{0,512}\s(--force|-f)\b": ("-f",),
    r"\b(psql|mysql|mongosh)\b[^|;\n]{0,512}-c\b": ("-c",),
    r"\bpip\s+install\b[^|;\n]{0,512}\bhttps?://": ("http",),
}
RULE_REQUIRES: list[tuple[str, ...] | None] = [_RULE_REQUIRES_BY_PATTERN.get(p) for _s, _c, p in BASH_RULES]
# Rules anchored at the line start (`^…`) are linear on a whole line of any
# length and are run on whole lines; the rest are bounded and read a long line
# in overlapping MAX_SCAN_LINE pieces.
_WHOLE_LINE_RULES = frozenset(i for i, (_s, _c, p) in enumerate(BASH_RULES) if p.startswith("^"))

_ASCII_FOLD = str.maketrans({"\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"})


def _fold_lower(text: str) -> str:
    """Lowercase text for the prefilters, with the characters re.IGNORECASE
    matches to an ASCII letter mapped to that letter first."""
    return text.lower() if text.isascii() else text.translate(_ASCII_FOLD).lower()

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

# One `\s*` after the separator, never two: `[|&;(]\s*)\s*` splits a whitespace
# run in O(n^2) ways before the next token fails (13 s on one 32 KB command).
UNREADABLE_SHAPES = (
    ("runs a variable", re.compile(r"(?:^|[|&;(])\s*[\"']?\$[A-Za-z_{]")),
    ("eval", re.compile(r"\beval\b")),
    ("pipes a download to a shell",
     re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b")),
    ("runs a local script",
     re.compile(r"(?:^|[|&;])\s*\.?/[\w./-]+\.(?:sh|bash|zsh|py|rb|pl)\b")),
    ("sources a file",
     re.compile(r"(?:^|[|&;])\s*(?:source|\.)\s+[\w./$~-]+")),
    ("shell -c with a variable", re.compile(r"\b(?:ba|z|)sh\s+-c\s+[\"']?\$")),
    # Shapes that hide a download from every rule above. Each is
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

# Lowercase literals per UNREADABLE_SHAPES row, as RULE_PREFILTERS is per rule.
SHAPE_PREFILTERS: list[tuple[str, ...] | None] = [
    ("$",),                                             # runs a variable
    ("eval",),
    ("curl", "wget"),
    (".sh", ".bash", ".zsh", ".py", ".rb", ".pl"),      # runs a local script
    ("source", "."),
    ("-c",),                                            # shell -c with a variable
    ("$'",),                                            # ANSI-C quoting
    ("$(", "`"),                                        # pipes a substitution to a shell
    ("urllib", "requests", "fetch", "http.client", "socket", "lwp"),
]


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
    low = _fold_lower(text)
    return [name for (name, rx), lits in zip(UNREADABLE_SHAPES, SHAPE_PREFILTERS)
            if (lits is None or any(x in low for x in lits)) and rx.search(text)]


def _unreadable_shapes_unfiltered(cmd: str) -> list[str]:
    """unreadable_shapes with no prefilter: the reference the tests compare against."""
    text = cmd[:MAX_SCAN_TOTAL]
    return [name for name, rx in UNREADABLE_SHAPES if rx.search(text)]


# The curl egress rule, whose loopback exemption is decided in code.
_CURL_EGRESS_RULE = next(i for i, (_s, c, p) in enumerate(BASH_RULES)
                         if c == "egress" and p.startswith(r"\bcurl"))
_CURL_WORD = re.compile(r"\bcurl\b", re.IGNORECASE)
_CURL_SEGMENT_END = re.compile(r"[|;\n]|&&|\bcurl\b", re.IGNORECASE)
# Options the egress check must not mistake for a destination, beyond the ones
# the network view already knows take a value.
_CURL_EGRESS_VALUE = frozenset("--json --data-ascii --form-string -U --proxy-user --connect-to "
                               "-Y -y -z -C --oauth2-bearer".split())
_CURL_REROUTE = frozenset("--resolve --connect-to --preproxy --doh-url --socks4 --socks4a "
                          "--socks5 --socks5-hostname".split())
_BARE_HOST = re.compile(r"^(?:[^@/\s]+@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?(?:[/?#]\S*)?$")


def _curl_to_loopback_only(segment: str) -> bool:
    """True when every destination of one curl invocation (its URLs, bare
    hosts, --url and --proxy) is loopback. "localhost" in a header, a referer or
    a query string is not a destination. An unknown host ($VAR) is not
    provably loopback, and neither is an invocation with no destination."""
    toks = _net_tokens(segment)
    if toks and _net_base(toks[0]).lower() == "curl":
        toks = toks[1:]
    # These send the request somewhere other than the host the URL names
    # (`--resolve localhost:443:203.0.113.9`), so the URL proves nothing.
    if any(t.split("=", 1)[0] in _CURL_REROUTE for t in toks):
        return False
    pos, opts = _net_positionals(toks, _CURL_VALUE | _CURL_EGRESS_VALUE)
    hosts: list[str] = []
    for d in pos + [opts[k] for k in ("--url", "-x", "--proxy") if opts.get(k)]:
        if "$" in d or "`" in d:
            return False
        if "://" in d:
            h = url_host(d)
            if h is None:
                return False
            hosts.append(h)
            continue
        m = _BARE_HOST.match(d)
        if m and ("." in m.group(1) or m.group(1).lower() == "localhost" or m.group(1).startswith("[")):
            hosts.append(m.group(1).lower())
    return bool(hosts) and all(_LOCAL_HOST.match(h) for h in hosts)


_SUDO_RULE = next(i for i, (_s, _c, p) in enumerate(BASH_RULES) if p == r"\bsudo\b")
_SU_RULE = next(i for i, (_s, _c, p) in enumerate(BASH_RULES) if p == r"\bsu\s+-")
# Words that may stand before the program of a command: shell keywords and the
# wrappers that run the command after them.
_COMMAND_LEAD_WORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{", "(",
                                 "time", "nohup", "exec", "command", "builtin", "env", "nice", "xargs",
                                 "timeout", "coproc", "setsid", "doas", "stdbuf", "caffeinate", "watch"})
_COMMAND_SEPARATORS = ";&|({`\n"
_PATH_DIR_TAIL = re.compile(r"[\w.+-]*(?:/[\w.+-]*)*/$")


def _at_command_start(ln: str, start: int) -> bool:
    """Whether the word at ln[start] is the program of a command: what comes
    before it, back to the last separator, is only keywords, wrappers (with
    their flags), assignments, or a shell's `-c "` / `eval "`. Bounded to 256
    characters back; a run longer than that with no separator counts as a
    command start, so padding cannot hide one."""
    lo = max(0, start - 256)
    before = ln[lo:start]
    if before.endswith("/"):
        # `/usr/bin/sudo`: the directory is part of the program word (R3C1).
        m = _PATH_DIR_TAIL.search(before)
        before = before[:m.start()] if m else before
    cut = max(before.rfind(c) for c in _COMMAND_SEPARATORS)
    if cut < 0 and lo > 0:
        return True                          # cannot see the start: fail closed
    words = before[cut + 1:].split()
    if words and words[-1] in ('"', "'"):
        # `bash -c "sudo …"`, `eval 'sudo …'`: the string is a command.
        return len(words) > 1 and (_net_shell_c(words[-2]) or words[-2].lower() == "eval")
    if before[-1:] in ('"', "'"):
        return False                         # `echo "sudo …"`: text
    for w in words:
        if (_net_base(w).lower() not in _COMMAND_LEAD_WORDS and not _NET_ASSIGN.match(w)
                and not w.startswith("-") and not w.isdigit()):
            return False
    return True


# The scp/rsync egress rule. Its regex retried the target after every start
# word and every `@` (8.8 s on 1 MiB of `scp N @@@@…`), so it is decided here:
# each target `user@host:` once, then the nearest scp/rsync word before it.
_SCP_EGRESS_RULE = next(i for i, (_s, c, p) in enumerate(BASH_RULES)
                        if c == "egress" and p.startswith(r"\b(scp"))
_SCP_WORD = re.compile(r"\b(?:scp|rsync)\b", re.IGNORECASE)
_SCP_TARGET = re.compile(r"(?<=\s)[^\s@]+@[^\s@:]+:")


def _scp_egress_hits(ln: str) -> bool:
    """What the egress pattern matches, in linear time: a target
    `user@host:` after a blank, with an scp/rsync word at most 512 characters
    before that blank and no `|`, `;` or newline between."""
    words = [m.end() for m in _SCP_WORD.finditer(ln)]
    if not words:
        return False
    w = 0
    for t in _SCP_TARGET.finditer(ln):
        blank = t.start() - 1
        while w < len(words) and words[w] <= blank:
            w += 1
        if w == 0:
            continue
        end = words[w - 1]                   # the last scp/rsync word ending before the blank
        if blank - end <= 512 and ln.find("|", end, blank) < 0 and ln.find(";", end, blank) < 0:
            return True
    return False


def _rule_hits(i: int, rx: "re.Pattern[str]", ln: str) -> bool:
    if i == _SUDO_RULE or i == _SU_RULE:
        return any(_at_command_start(ln, m.start()) for m in rx.finditer(ln))
    if i == _SCP_EGRESS_RULE:
        return _scp_egress_hits(ln)
    if i != _CURL_EGRESS_RULE:
        return rx.search(ln) is not None
    # Each curl is judged on its own arguments: a loopback curl does not hide a
    # second curl on the same line. Segments end at the next curl, so the
    # tokenising is linear in the line.
    for w in _CURL_WORD.finditer(ln):
        if rx.match(ln, w.start()):
            rest = ln[w.end():]
            cut = _CURL_SEGMENT_END.search(rest)
            if not _curl_to_loopback_only(ln[w.start():w.end() + (cut.start() if cut else len(rest))]):
                return True
    return False


# Characters str.splitlines() breaks on but bash does not: inside a word they
# are ordinary characters. For the rules they are blanks, so `cat \r ~/.ssh/id_rsa`
# (cat still prints the key) reads like `cat   ~/.ssh/id_rsa`.
_AUDIT_BLANKS = re.compile("[\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]")
# Quoting, escapes and substitutions: only then can the commands the shared
# lexer reads differ from the raw lines.
_AUDIT_NEEDS_LEX = re.compile(r"['\"\\$`]|\{[^\s{}]*?(?:,|\.\.)")     # or a brace expansion


def _audit_lines(cmd: str) -> tuple[list[str], list[str]]:
    """What the rules read: (pieces, wholes).

    Every line of the command up to MAX_SCAN_HARD, split on \n only (as bash
    splits), plus the commands the shared lexer reads that the raw lines do not
    show (dequoted words, `bash -c` strings, eval, here-strings and heredocs fed
    to a shell, substitution bodies), so the audit and the network inventory
    agree on what the commands are. Nothing is skipped: a line longer than
    MAX_SCAN_LINE is read in pieces overlapping by SCAN_OVERLAP (more than the
    512 every bounded rule spans) for the bounded rules, and whole for the
    anchored ones. Past MAX_SCAN_HARD the Fleet reports the command oversized."""
    text = cmd[:MAX_SCAN_HARD]
    if "\r" in text:
        text = text.replace("\r\n", "\n")
    if not text.isascii() or _AUDIT_BLANKS.search(text):
        text = _AUDIT_BLANKS.sub(" ", text)
    lines = text.split("\n")
    shown: dict[str, str] = {}
    if _AUDIT_NEEDS_LEX.search(text):
        raw = set(lines)
        for ln, as_written in _shell_walk(cmd[:MAX_SCAN_HARD])[3]:
            ln = _AUDIT_BLANKS.sub(" ", ln)
            if ln not in raw:
                lines.append(ln)
                shown.setdefault(ln, as_written)
    pieces: list[str] = []
    wholes: list[str] = []
    seen: set[str] = set()
    step = MAX_SCAN_LINE - SCAN_OVERLAP
    for ln in lines:
        if ln in seen:
            continue
        seen.add(ln)
        wholes.append(ln)
        if len(ln) <= MAX_SCAN_LINE:
            pieces.append(ln)
            continue
        k = 0
        while True:
            pieces.append(ln[k:k + MAX_SCAN_LINE])
            if ln in shown:
                shown.setdefault(pieces[-1], shown[ln])
            if k + MAX_SCAN_LINE >= len(ln):
                break
            k += step
    _AUDIT_SHOWN.clear()
    _AUDIT_SHOWN.update(shown)
    return pieces or [""], wholes or [""]


# Evidence for a line the lexer derived: the command as written, not dequoted.
# Set by the last _audit_lines call and read straight after it.
_AUDIT_SHOWN: dict[str, str] = {}


def _audit_evidence(i: int, rx: "re.Pattern[str]", ln: str) -> str:
    if ln in _AUDIT_SHOWN:
        ln = _AUDIT_SHOWN[ln][:MAX_SCAN_LINE]
    if len(ln) > MAX_SCAN_LINE:              # a whole long line: the part up to the match
        m = rx.search(ln)
        end = m.end() if m else MAX_SCAN_LINE
        ln = ln[max(0, end - MAX_SCAN_LINE):end]
    return clean(ln.strip())


def audit_command(cmd: str) -> list[tuple[str, str, str]]:
    """Return [(severity, category, matching_line)] for every rule that fires.

    Agent commands are frequently multi-line scripts. Reporting the first line
    of a 40-line heredoc tells you nothing, so each match carries the line that
    actually triggered it.
    """
    # Every rule's character classes exclude \n, so no rule can match across a
    # line break. Scanning is therefore per line (see _audit_lines).
    pieces, wholes = _audit_lines(cmd)
    lows = [_fold_lower(ln) for ln in pieces]
    whole = "\n".join(lows)
    whole_lows: list[str] | None = None
    out: list[tuple[str, str, str]] = []
    for i, ((sev, cat, rx), lits, req) in enumerate(zip(COMPILED_RULES, RULE_PREFILTERS, RULE_REQUIRES)):
        if lits is not None and not any(x in whole for x in lits):
            continue                         # no line can hold one: skip every line
        if req is not None and not any(x in whole for x in req):
            continue
        if i in _WHOLE_LINE_RULES:
            if whole_lows is None:
                whole_lows = [_fold_lower(ln) for ln in wholes]
            lines, lls = wholes, whole_lows
        else:
            lines, lls = pieces, lows
        for ln, low in zip(lines, lls):
            if ((lits is None or any(x in low for x in lits))
                    and (req is None or any(x in low for x in req)) and _rule_hits(i, rx, ln)):
                out.append((sev, cat, _audit_evidence(i, rx, ln)))
                break
    return out


def _audit_command_unfiltered(cmd: str) -> list[tuple[str, str, str]]:
    """audit_command with every rule run on every line: the reference the
    prefilter is tested against."""
    pieces, wholes = _audit_lines(cmd)
    out: list[tuple[str, str, str]] = []
    for i, (sev, cat, rx) in enumerate(COMPILED_RULES):
        for ln in (wholes if i in _WHOLE_LINE_RULES else pieces):
            if _rule_hits(i, rx, ln):
                out.append((sev, cat, _audit_evidence(i, rx, ln)))
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
    "github_pat_", "sk-ant-api", "sk-ant-", "dop_v1_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
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

# A prefixed token starts on a word boundary, or right after the `m` that ends
# an SGR colour code (`\033[1m`, `\e[32m`, `\x1b[0;31m`, and the `31m` clean()
# leaves of a raw C1 CSI one). The `m` touches the prefix, so `\b` alone missed
# `printf '\e[32mghp_…'` and printed the token. The rules keep their plain `\b`
# (an alternation there makes every scan about three times slower); when
# _SGR_TOUCH finds such an `m` before a letter, the same rules run again
# anchored after it (_AFTER_SGR). Fixed-width lookbehind: constant work.
_AFTER_SGR = r"(?<=[\[0-9;]m)"
_SGR_TOUCH = re.compile(r"[\[0-9;]m(?=[A-Za-z])")
# An SGR colour code written into a command before a value, `TOKEN=\e[1;4m…`:
# literal (`\033[`, `\e[`, `\x1b[`, `\u001b[`) or what clean() leaves of a raw one.
_SGR_TEXT = r"(?:(?:\\(?:033|[eE]|x1[bB]|u001[bB]))?\[[0-9;]{0,16}m)"

# A backslash may escape each quote around a name or value: a JSON body
# inside a double-quoted argument, `curl -d "{\"password\":\"…\"}"`.
_SECRET_PATTERNS = [
    # KEY=value / KEY: value for anything that smells like a secret
    # Same name list as classification, by construction. A value masked here
    # must also be counted there, or the rotation list silently undercounts.
    re.compile(
        r"(?i)\b([A-Z0-9_]{0,40}(?:" + _SECRET_NAME_WORDS +
        r"|" + _SHORT_SECRET_WORDS + r")[A-Z0-9_]{0,40})"
        # A closing quote may sit between the name and the separator: a JSON
        # body, {"password":"…"}, names its secrets that way.
        r"(\\?['\"]?\s*[=:]\s*)(\\?(?:\$(?=['\"]))?['\"]?" + _SGR_TEXT + r"?)"
        # A PEM header is left to the PEM pass, which has already masked the body.
        r"(?!(?:Bearer|Basic|Digest|Token|None|null|true|false)\b|-----BEGIN )"
        # Inside quotes `;`, `|`, `&` and spaces belong to the value
        # (DB_PASSWORD='Xy7;kQ2#mN9p'), so a quoted value runs to its closing
        # quote, never across a line, however long (_kv_hits widens the bounded
        # match to it). With no closing quote on the line it is read as an
        # unquoted value. An escaped quote's value stops before the backslash
        # of its closing \".
        r"((?<=')[^'\n]{6,256}"
        r"|(?<=\\\")[^\"\\\n]{6,256}"
        r"|(?<=\")[^\"\n]{6,256}"
        r"|[^\s'\";|&]{6,})"
    ),
    # bare tokens by known prefix
    re.compile(r"\b(" + "|".join(re.escape(p) for p in _TOKEN_PREFIXES) + r")([A-Za-z0-9_\-]{8,})"),
    # Authorization headers. `token` is GitHub's scheme word for a PAT.
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)([^\s'\"]{8,})"),
    # postgres://user:pass@host and friends
    re.compile(r"([a-z][a-z0-9+.\-]{0,20}://[^\s:/@]{1,128}:)([^\s@/]{3,256})(@)"),
]


_MASKED = "<redacted"

_KV_NO_SQ = re.compile(r"[^'\n]*")
_KV_NO_DQ = re.compile(r'[^"\n]*')
_KV_NO_DQ_BS = re.compile(r'[^"\\\n]*')
_KV_ANSI_C = re.compile(r"(?:[^'\\\n]|\\.)*")
_KV_UNQUOTED = re.compile(r"[^\s'\";|&]*")


def _kv_value_end(text: str, s: int, e: int, opening: str) -> int:
    """Where a KEY=value value that starts at `s` ends: a quoted one at its
    closing quote on the line, else (no closing quote) where an unquoted value
    would; an unquoted one where the rule's match ended."""
    if opening.endswith("$'"):
        k = _KV_ANSI_C.match(text, s).end()
        if text.startswith("'", k):
            return k
    elif opening.endswith("\\\""):
        k = _KV_NO_DQ_BS.match(text, s).end()
        if text.startswith('\\"', k):
            return k
        k = _KV_NO_DQ.match(text, s).end()
        if text.startswith('"', k):
            return k
    elif opening.endswith('"'):
        k = _KV_NO_DQ.match(text, s).end()
        if text.startswith('"', k):
            return k
    elif opening.endswith("'"):
        k = _KV_NO_SQ.match(text, s).end()
        if text.startswith("'", k):
            return k
    else:
        return e
    return _KV_UNQUOTED.match(text, s).end()


def _kv_cookie_header(m: "re.Match") -> bool:
    """A Cookie header (`Cookie: a=1; sid=…`): its pairs are _cookie_hits' to read."""
    return m.group(1).lower() == "cookie" and ":" in m.group(2)


def _kv_hits(text: str):
    """(match, start, end) of each KEY=value value, widened to the whole value
    (_kv_value_end); a Cookie header is skipped (see _cookie_hits). Each
    search resumes past the value, so the scan stays linear: a quoted value's
    scan stops at the next quote of its kind, which ends any later start's."""
    rx = _SECRET_PATTERNS[0]
    pos, n = 0, len(text)
    while pos <= n:
        m = rx.search(text, pos)
        if m is None:
            return
        if _kv_cookie_header(m):
            pos = m.start(4)
            continue
        s, e = m.span(4)
        e = _kv_value_end(text, s, e, m.group(3))
        if e - s >= 6:
            yield m, s, e
        pos = max(e, m.start() + 1)

# A PEM private-key block, or an armored PGP one (`gpg --export-secret-keys
# --armor` writes `PRIVATE KEY BLOCK`). The body runs to the END line or,
# unterminated, to the end of the text: no length cap leaves a tail of the key
# printed. A greedy tempered scan from a literal start with nothing after it
# never backtracks, and a match consumes every later header it runs over:
# linear. Fewer than 16 body characters is a placeholder.
_PEM_PRIVATE_KEY = re.compile(r"(-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----)"
                              r"((?:(?!-----END )[\s\S]){16,})")


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
# A value's class is bounded so the scan stays linear, and the mask then takes
# the WHOLE value (_option_hits): an unquoted one to the next blank or quote,
# however long (an AWS session token runs to 1,000 characters), and a quoted
# one, spaces and all, to its closing quote on the line ('…', "…", $'…').
# Group 3 is the opening quote.
_OPT_QUOTE = r"(\$['\"]|['\"]|)"
#   curl -u/--user/-U/--proxy-user user:PASS, with a space, `=` or nothing.
#   `//` after the colon is a URL (`pip install -U git+https://…`), not a password.
_OPT_USERPASS = re.compile(r"(?<!\S)(-u|-U|--user|--proxy-user)(=|\s+)?" + _OPT_QUOTE +
                           r"([^\s:'\"]{1,128}:)(?!//)([^\s'\"]{1,256})")
#   wget --password / --http-password / --ftp-password / --proxy-password PASS,
#   and docker login --password PASS, with a space or `=`.
_OPT_PASSWORD = re.compile(r"(?<!\S)(--(?:http-|ftp-|proxy-)?password)(\s+|=)" + _OPT_QUOTE +
                           r"(?!-)([^\s'\"]{1,256})")
#   docker login -p PASS. Only for `docker login`: -p is a port, a parent flag
#   or a profile everywhere else (mkdir -p, ssh -p 22), and mysql -pPASS and
#   sshpass -p are deliberately left for a program-aware follow-up.
_OPT_DOCKER_LOGIN_P = re.compile(r"(?<!\S)(docker\s+login\b[^\n;|&]{0,512}?\s-p)(\s+|=)?" + _OPT_QUOTE +
                                 r"(?!-)([^\s'\"]{1,256})")
#   aws configure set [profile.]aws_secret_access_key|aws_session_token VALUE
_OPT_AWS_CONFIGURE = re.compile(r"(?<!\S)(aws\s+configure\s+set\s+(?:[\w-]{1,64}\.)?"
                                r"(?:aws_secret_access_key|aws_session_token))(\s+)" + _OPT_QUOTE +
                                r"(?!-)([^\s'\"]{1,256})", re.IGNORECASE)
#   gh secret set NAME [options] --body|-b VALUE
_OPT_GH_SECRET_BODY = re.compile(r"(?<!\S)(gh\s+secret\s+set\b[^\n;|&]{0,512}?\s(?:-b|--body))"
                                 r"(\s+|=)" + _OPT_QUOTE + r"(?!-)([^\s'\"]{1,256})")
#   Any long option named for a credential, VALUE after a space or `=`:
#   --token, --api-key, --apikey, --client-secret, --access-token, --auth-token,
#   --secret, --secret-key, --password, --passphrase. Not a flag that only names
#   one (--no-password, --ask-password), and not a BuildKit secret mount
#   (docker build --secret id=x,src=y), which names a file.
_OPT_CREDENTIAL_FLAG = re.compile(
    r"(?<!\S)(--(?!(?:no|ask|prompt|skip|show|print|require|use|with|without|read)-)[a-z0-9-]{0,40}?"
    r"(?:token|secret|secret-key|api-key|apikey|password|passwd|passphrase))(\s+|=)" + _OPT_QUOTE +
    # Quoted, a value may hold spaces (a passphrase): its first six characters
    # are read up to any quote, and _option_hits widens it to the closing one.
    r"(?!-)(?!(?:id|src|source|env|type|target|required)=)((?<=['\"])[^'\"\n]{6,256}|[^\s'\"]{6,256})",
    re.IGNORECASE)
#   curl -b/--cookie NAME=VALUE[; NAME=VALUE…], with a space, `=` or nothing
#   (`-bsid=…`). Without `=` the value is a cookie file. Every pair is read
#   by _cookie_hits, as in a Cookie header.
_OPT_CURL_COOKIE = re.compile(r"(?<!\S)(curl\b[^\n;|&]{0,512}?\s(?:-b|--cookie))(\s+|=)?" + _OPT_QUOTE)
#   A .netrc entry written by a command: machine HOST login USER password PASS.
_OPT_NETRC = re.compile(r"(?<![^\s'\"])((?:machine\s+[^\s'\"]{1,255}|default)\s+login\s+[^\s'\"]{1,255}\s+password)(\s+)"
                        + _OPT_QUOTE +
                        r"(?!-)([^\s'\"]{1,256})")
# (rule, credential group). The same table drives redact() and classify_secrets().
_OPTION_SECRETS = ((_OPT_USERPASS, 5), (_OPT_PASSWORD, 4), (_OPT_DOCKER_LOGIN_P, 4),
                   (_OPT_AWS_CONFIGURE, 4), (_OPT_GH_SECRET_BODY, 4),
                   (_OPT_CREDENTIAL_FLAG, 4), (_OPT_NETRC, 4))

# The rest of a value from its first character: to the closing quote on the
# line for each opening quote (a backslash escapes inside "…" and $'…'), to the
# next blank or quote unquoted. One class per scan: linear.
_VALUE_REST = {"'": re.compile(r"[^'\n]*"), '"': re.compile(r'(?:[^"\\\n]|\\.)*'),
               "$'": re.compile(r"(?:[^'\\\n]|\\.)*"), '$"': re.compile(r'(?:[^"\\\n]|\\.)*'),
               "": re.compile(r"[^\s'\"]*")}


def _option_hits(rx: "re.Pattern[str]", group: int, text: str):
    """(match, start, end) of each credential an option rule finds in `text`,
    the span widened to the whole value (see _OPT_QUOTE). The next search
    starts past the widened value, so every character is read a bounded
    number of times."""
    pos, n = 0, len(text)
    while pos <= n:
        m = rx.search(text, pos)
        if m is None:
            return
        s, e = m.span(group)
        e = max(e, _VALUE_REST.get(m.group(3), _VALUE_REST[""]).match(text, s).end())
        yield m, s, e
        pos = max(e, m.start() + 1)
# Every command passes through both detectors, and almost none holds any of
# these. One search decides whether the option rules (and, in classification,
# the header rule) need to run at all.
_OPTION_HINT = re.compile(r"(?i)authorization|(?<!\S)-u|--(?:user|proxy-user|(?:http-|ftp-|proxy-)?password)|docker"
                          r"|aws\s+configure|gh\s+secret|--[a-z0-9-]{0,40}?(?:token|secret|key|pass)|curl|machine"
                          r"|default\s+login")


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
        elif rx is _OPT_AWS_CONFIGURE:
            program, option = "aws", m.group(1).split()[-1].lower()
        elif rx is _OPT_GH_SECRET_BODY:
            name = m.group(1).split()[3] if len(m.group(1).split()) > 3 else ""
            program, option = "gh", f"secret:{name}"
        elif rx is _OPT_CREDENTIAL_FLAG:
            program, option = self.program(m.start()), m.group(1).lower()
        elif rx is _OPT_NETRC:
            words = m.group(1).split()
            if words[0] == "default":            # `default login USER password …`
                return self.make(f"netrc:default:{words[2]}")
            return self.make(f"netrc:{words[1].lower()}:{words[3]}")
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
_USERPASS_COMPOSE_VALUE = frozenset({"-f", "--file", "-p", "--project-name", "--profile",
                                     "--project-directory", "--env-file", "--ansi", "--parallel"})
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
        def skip(n: int, values: frozenset) -> int:
            while n < len(rest) and rest[n].startswith("-") and len(rest[n]) > 1:
                n += 2 if rest[n] in values else 1
            return n
        n = skip(1, _DOCKER_VALUE)
        if n < len(rest) and rest[n] in ("container", "compose"):    # docker compose exec, docker container run
            n = skip(n + 1, _USERPASS_COMPOSE_VALUE)
        sub = rest[n] if n < len(rest) else ""
        if sub in _USERPASS_CONTAINER_SUBS:
            n = skip(n + 1, _DOCKER_VALUE)
            inner = rest[n + 1:] if len(rest) > n + 1 else None      # past the container, image or service
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


def _mask_spans(text: str, spans: "list[tuple[int, int]]", mask=None) -> str:
    """`text` with each (start, end) span, in order and not overlapping, masked."""
    if not spans:
        return text
    mask = mask or _mask_value
    out: list[str] = []
    at = 0
    for s, e in spans:
        if s < at:
            continue
        out += [text[at:s], mask(text[s:e])]
        at = e
    out.append(text[at:])
    return "".join(out)


def _option_sub(rx: "re.Pattern[str]", group: int, text: str,
                where: "_SecretLocations | None" = None) -> str:
    """Mask every credential an option rule finds, each value whole."""
    return _mask_spans(text, [(s, e) for m, s, e in _option_hits(rx, group, text)
                              if _option_secret(text[s:e])
                              and not (where is not None and _userpass_exempt(where, m))])


# A Cookie header (`-H 'Cookie: a=1; sid=…'`, `Set-Cookie:`, JSON "Cookie": "…")
# names several NAME=VALUE pairs. Each pair is read on its own (_cookie_hits):
# a value is masked, and counted as a cookie, when its name sounds like a
# credential (sid, session, token, auth, jwt, csrf…) and it has 6 or more
# characters, when it has a credential's shape (a known prefix, a JWT), or when
# it is opaque (16 or more characters mixing letters and digits). `theme=dark`
# stays readable. The header name stands alone (`XCookie:` is a variable,
# read by the KEY=value rule), exactly as that rule's name group would read it.
_COOKIE_HEADER = re.compile(r"(?i)(?<![A-Za-z0-9_])cookie(\\?['\"]?\s*:\s*)(\\?['\"]?)")
_COOKIE_HINT = re.compile(r"(?i)cookie|(?<!\S)-b")
_COOKIE_REGION = re.compile(r"[^'\"\n\\]*")
_COOKIE_CRED_NAME = re.compile(r"(?i)sess|sid|tok|auth|jwt|[cx]srf|secret|pass|key|cred|bearer|access|refresh"
                               r"|login|remember|sig")
_COOKIE_OPAQUE = re.compile(r"[A-Za-z0-9_\-.%+/=:]{16,}")


def _cookie_secret(name: str, value: str) -> bool:
    if not value or _MASKED in value or not _option_secret(value):
        return False
    if len(value) >= 6 and _COOKIE_CRED_NAME.search(name):
        return True
    if _COOKIE_OPAQUE.fullmatch(value) and any(c.isdigit() for c in value) \
            and any(c.isalpha() for c in value):
        return True
    return bool(_SECRET_PATTERNS[1].search(value)
                or any(rx.search(value) for rx in _COOKIE_SHAPES))


def _cookie_pairs(text: str, s: int, e: int):
    """(NAME, value start, value end) of each NAME=VALUE pair in text[s:e],
    split on `;`. A value ends at a blank. One pass."""
    i = s
    while i < e:
        j = text.find(";", i, e)
        j = e if j < 0 else j
        k = text.find("=", i, j)
        if k > i:
            name = text[i:k].strip()
            ve = _COOKIE_VALUE.match(text, k + 1, j).end()
            if name:
                yield name, k + 1, ve
        i = j + 1


_COOKIE_VALUE = re.compile(r"[^\s;]*")


def _cookie_hits(text: str):
    """(NAME, start, end, at) of every cookie value that is a credential (see
    _COOKIE_HEADER), in a Cookie header or a curl -b/--cookie value; `at` is
    where the header or option starts. A header holding no NAME=VALUE pair is
    one value, NAME "COOKIE". Linear: each search resumes past what it read."""
    if not _COOKIE_HINT.search(text):
        return []
    hits: list[tuple[str, int, int, int]] = []
    pos = 0
    while True:
        m = _COOKIE_HEADER.search(text, pos)
        if m is None:
            break
        s = m.end()
        e = _COOKIE_REGION.match(text, s).end()
        while e > s and text[e - 1] in " \t":
            e -= 1
        pairs = list(_cookie_pairs(text, s, e))
        if pairs:
            hits += [(n, a, b, m.start()) for n, a, b in pairs if _cookie_secret(n, text[a:b])]
        elif e - s >= 6 and _option_secret(text[s:e]) and _MASKED not in text[s:e]:
            hits.append(("COOKIE", s, e, m.start()))
        pos = max(e, m.end(), m.start() + 1)
    pos = 0
    while "curl" in text:
        m = _OPT_CURL_COOKIE.search(text, pos)
        if m is None:
            break
        q, s = m.group(3), m.end()
        e = (_VALUE_REST[q] if q else _SECRET_UNQUOTED_REST).match(text, s).end()
        hits += [(n, a, b, m.start()) for n, a, b in _cookie_pairs(text, s, e)
                 if _cookie_secret(n, text[a:b])]
        pos = max(e, m.start() + 1)
    hits.sort(key=lambda h: h[1])
    return hits


_SECRET_UNQUOTED_REST = re.compile(r"[^\s'\";|&]*")


def _scp_mask(m: "re.Match") -> str:
    u = m.group(1)
    if ":" in u or len(u) > 20:
        return f"{_mask(u)}@{m.group(2)}:"
    return m.group(0)


def _unhide(text: str) -> str:
    """The text a reader sees: raw SGR codes and every character clean() strips
    removed. Redaction and classification both work on this, so ESC, a
    zero-width space or a soft hyphen inside a token cannot split it past the
    rules and then vanish from the output, leaving the token whole."""
    if "\x1b" in text or "\x9b" in text:
        text = _RAW_SGR.sub("", text)
    return _CONTROL.sub("", text)


def redact(text: str) -> str:
    """Remove credential material from a command string. Idempotent.

    Characters clean() strips are stripped here first (see _unhide), so the
    output never holds them; tab and newline survive."""
    if not text:
        return text
    text = _unhide(text)
    truncated = False
    if text.endswith(TRUNCATED_MARK):        # idempotent: strip our own marker first
        text, truncated = text[:-len(TRUNCATED_MARK)], True
    if len(text) > MAX_SCAN_TOTAL:
        text, truncated = text[:MAX_SCAN_TOTAL], True
    out = _redact_scanned(text)
    return out + TRUNCATED_MARK if truncated else out


def _redact_scanned(out: str) -> str:
    # Order matters. A pass must never mask the anchor a later pass needs: the
    # PEM pass runs first, because its body spans spaces and newlines that end
    # every other value class. Run later, `PRIVATE_KEY="-----BEGIN …` lost only
    # the word `-----BEGIN` to the KEY=value pass, and with it the header the PEM
    # pass anchors on, so the whole key body printed.
    if "PRIVATE KEY" in out:
        out = _PEM_PRIVATE_KEY.sub(_pem_mask, out)
    # The Authorization header rule must run before the generic KEY=value rule,
    # or "AUTH" in "Authorization:" makes it eat the scheme word.
    out = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    # Each credential pair of a Cookie header or curl -b, before the KEY=value
    # rule (which leaves the header to this pass).
    out = _mask_spans(out, [(a, b) for _n, a, b, _at in _cookie_hits(out)], _mask)
    if _OPTION_HINT.search(out):
        for rx, group in _OPTION_SECRETS:
            where = _SecretLocations(out) if rx is _OPT_USERPASS and rx.search(out) else None
            out = _option_sub(rx, group, out, where)
    # A marker's own `:` (`https://ghp_…<redacted:33-48>@h`) is not a URL
    # password, and the four characters a mask shows (`sk-ant-api03-T…<redacted`)
    # are not a fresh token: re-masking either broke idempotence.
    out = _SECRET_PATTERNS[3].sub(lambda m: m.group(0) if _MASKED in m.group(1)
                                  else f"{m.group(1)}{_mask(m.group(2))}{m.group(3)}", out)
    out = _mask_spans(out, [(s, e) for _m, s, e in _kv_hits(out)])
    sgr = _SGR_TOUCH.search(out) is not None
    for rx in (_SECRET_PATTERNS[1], _SGR_PREFIX) if sgr else (_SECRET_PATTERNS[1],):
        out = rx.sub(lambda m: m.group(0) if m.string.startswith("…" + _MASKED, m.end())
                     else f"{m.group(1)}{_mask(m.group(2))}", out)
    # Everything classify_secrets() reports by type is masked too, so the two
    # can never drift (a JWT, xoxa-/xoxr-/xoxs- once printed in full).
    for rx in _REDACT_SECRET_TYPES + (_SGR_REDACT_SECRET_TYPES if sgr else ()):
        out = rx.sub(lambda m: _mask(m.group(0)), out)
    if _ESCAPE_TOUCH.search(out):
        out = _redact_after_escapes(out)
    out = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}@", out)
    out = _SCP_USERINFO.sub(_scp_mask, out)
    if ":" in out and "@" in out:
        out = _mask_spans(out, [(s, e) for s, e, _u, _h in _scp_long_hits(out)], _mask)
    return out


# An escape written into a command and glued to the token after it: a
# backslash escape (`\n`, `\t`, `\x20`, `\040`, `\u0020`), an escape sequence
# of any final byte (`\e[2K`, `\033[H`, `\x1b[38:2:1:2:3m`, `\e(B`), or what
# clean() leaves of a raw CSI (`[2K`). Its last character is a letter or digit,
# so `\b` finds no word boundary before the token (`printf 'x\nghp_…'`). The
# prefix rules then run again over a view of the text with each such escape
# blanked (_escape_view): same length, so a match's span is the token's span in
# the text. One linear pass to blank, then the usual linear rules.
_ESCAPE_SEQ = (r"(?:(?:\\(?:033|[eE]|x1[bB]|u001[bB]))?\[[0-9;:?<=>]{0,32}[ -/]{0,4}[@-~]"
               r"|\\(?:033|[eE]|x1[bB]|u001[bB])[()*+][0-9A-Za-z]"
               r"|\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-7]{1,3}|[abefnrtvE]))")
_ESCAPE_TOUCH = re.compile(_ESCAPE_SEQ + r"(?=[A-Za-z])")


def _escape_view(text: str) -> str:
    return _ESCAPE_TOUCH.sub(lambda m: " " * len(m.group(0)), text)


def _redact_after_escapes(out: str) -> str:
    """The prefix rules, the shape rules and the netrc rule once more, over
    _escape_view(out), masking what they find in `out`."""
    view = _escape_view(out)
    spans = [(m.start(2), m.end(2)) for m in _SECRET_PATTERNS[1].finditer(view)
             if _MASKED not in out[m.start(2):m.end(2)] and not out.startswith("…" + _MASKED, m.end())]
    out = _mask_spans(out, spans, _mask)
    view = _escape_view(out)
    spans = sorted(m.span(0) for rx in _ESCAPE_SECRET_TYPES for m in rx.finditer(view)
                   if _MASKED not in out[m.start(0):m.end(0)])
    out = _mask_spans(out, spans, _mask)
    if "password" in out:
        view = _escape_view(out)
        out = _mask_spans(out, [(s, e) for _m, s, e in _option_hits(_OPT_NETRC, 4, view)
                                if _option_secret(out[s:e])])
    return out


# scp-style userinfo whose password is longer than _SCP_USERINFO reads (256):
# the bounded match is widened to the value's end and kept only when `@HOST:`
# follows. Each search resumes past the widened value: linear.
_SCP_LONG = re.compile(r"(?<![^\s'\"=])([^\s@:/'\"=]{1,256}:[^\s@/'\"]{256})(?=[^\s@/'\"])")
_SCP_LONG_REST = re.compile(r"[^\s@/'\"]*")
_SCP_HOST = re.compile(r"@([A-Za-z0-9.-]+):")


def _scp_long_hits(text: str):
    """(start, end, user, host) of each over-long scp `user:password@host:`."""
    pos, n = 0, len(text)
    while pos < n:
        m = _SCP_LONG.search(text, pos)
        if m is None:
            return
        e = _SCP_LONG_REST.match(text, m.end()).end()
        h = _SCP_HOST.match(text, e)
        if h and _MASKED not in text[m.start():e]:
            yield m.start(), e, text[m.start():text.find(":", m.start())], h.group(1)
        pos = max(e, m.start() + 1)


def _mask_value(v: str) -> str:
    """_mask for a KEY=value value that may already hold markers from an
    earlier pass (`TOKEN=s3cr3t,postgres://u:<redacted>@h,more`). The text
    around each marker is masked, keeping a URL's `scheme://user:` before it and
    its `@host/path` after it; _mask alone would skip the whole value, and
    masking only the text before the first marker printed everything after it
    (`DSN=postgres://u:<redacted>@h/x,API_KEY=…`)."""
    out: list[str] = []
    while True:
        i = v.find(_MASKED)
        if i < 0:
            if v:
                out.append(_mask(v))
            return "".join(out)
        head = v[:i]
        if head and not (len(head) == 5 and head.endswith("…")):    # our own prefix display
            url = re.search(r"[a-z][a-z0-9+.\-]{0,20}://[^\s:/@]{0,128}:?$", head)
            secret = head[:url.start()] if url else head
            if secret:
                out.append(_mask(secret))
                head = head[len(secret):]
        out.append(head)
        j = v.find(">", i)
        if j < 0:
            out.append(v[i:])
            return "".join(out)
        # The marker, then the host and path of the URL it sits in.
        keep = re.match(r">(?:@[A-Za-z0-9.\-\[\]:]{0,255})?(?:/[^,;&=?#\s]{0,256})?", v[j:j + 520])
        out.append(v[i:j] + keep.group(0))
        v = v[j + keep.end():]


def _pem_mask(m: "re.Match") -> str:
    body = m.group(2).strip()
    while body.startswith("\\n"):             # a JSON string's escaped newline
        body = body[2:].lstrip()
    return f"{m.group(1)}\n{_mask(body)}\n" if _MASKED not in body else m.group(0)


def contains_secret(text: str) -> bool:
    """True when redaction would change the text.

    Compared against the SAME truncated input redact() works on. Comparing
    against the full text made every command longer than MAX_SCAN_TOTAL report
    as containing a secret, because truncation alone made the strings differ.
    """
    if not text:
        return False
    head = _unhide(text[:MAX_SCAN_HARD])[:MAX_SCAN_TOTAL]
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
_SUDO_VALUE_FLAGS = frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-U", "-r", "-t"})
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
#   fe00-fe0f, e0100-e01ef  variation selectors (an emoji loses only its
#              presentation hint)
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
    (0x00AD, 0x00AD, "soft hyphen: invisible, splits a token"),
    (0x034F, 0x034F, "combining grapheme joiner: invisible"),
    (0x061C, 0x061C, "Arabic letter mark, a bidi control like LRM and RLM"),
    (0x115F, 0x1160, "Hangul choseong and jungseong fillers: blank"),
    (0x180E, 0x180E, "Mongolian vowel separator: invisible"),
    (0x3164, 0x3164, "Hangul filler: blank"),
    (0xFFA0, 0xFFA0, "halfwidth Hangul filler: blank"),
    (0xFFF9, 0xFFFB, "interlinear annotation controls"),
    (0xD800, 0xDFFF, "lone UTF-16 surrogates (JSON \\ud800): no encoder accepts them, "
                     "so one crashed every writer"),
    (0xE0000, 0xE007F, "Unicode tag characters: invisible, carry hidden ASCII text"),
    (0xFE00, 0xFE0F, "variation selectors: invisible, 256 of them carry hidden bytes"),
    (0xE0100, 0xE01EF, "variation selectors supplement: the rest of those 256"),
)

# Tab (0x09) and newline (0x0A) are the only whitespace controls that survive.
# CARRIAGE RETURN DOES NOT. A bare \r returns the cursor to column zero, so a
# command can overwrite what was already printed above it -- which is precisely
# the hiding this module exists to prevent, and is why it is not treated as a
# harmless newline.
_CONTROL = re.compile(
    "[" + "".join(f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi, _why in _STRIPPED_RANGES) + "]"
)
# A raw SGR colour code (ESC [ or C1 CSI, then digits, then m). Redaction drops
# it whole rather than leaving `[1m` against the token that follows.
_RAW_SGR = re.compile(r"(?:\x1b\[|\x9b)[0-9;]{0,16}m")

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


def _redacted_excerpt(text: str, start: int, end: int) -> str:
    """About 200 characters of `text` around [start, end), redacted BEFORE it is
    cut: the context begins at the last separator (; | & newline) at least 80
    characters back, so no `KEY=` or `Authorization: Bearer` prefix is split from
    its value, and the cut falls in text that is already masked."""
    lo = max(start - 80, 0)
    window = text[max(lo - 4096, 0):lo]
    sep = max((window.rfind(c) for c in ";|&\n"), default=-1)
    lo = max(lo - 4096, 0) + sep + 1 if sep >= 0 else lo
    return redact(clean(text[lo:min(end + 120, lo + MAX_SCAN_TOTAL)])).strip()[-240:]


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
    A non-string (a transcript field can hold any JSON value) is empty.
    """
    if not text or not isinstance(text, str):
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

# A Jira project key is uppercase. Matched case-insensitively, every word
# before a version number was a ticket (renovate/node-18.x was NODE-18), so
# only the branch prefix and the tracker words ignore case.
_TICKET_PATTERNS = [
    re.compile(rf"^(?:[a-z]+/)?(?:{_TRACKER_WORDS})[-_]?(\d{{1,6}})\b", re.I),
    # A CVE id is one ticket, not project CVE's ticket 2024 for every CVE of a
    # year (hotfix/CVE-2024-1234 was CVE-2024).
    re.compile(r"^(?:[a-z]+/)?(CVE-\d{4}-\d{4,7})\b", re.I),
    re.compile(rf"^(?i:[a-z]+)/(?!(?i:{_TRACKER_WORDS})\b)([A-Z][A-Z0-9]+-\d+)"),
    re.compile(rf"^(?!(?i:{_TRACKER_WORDS})\b)([A-Z][A-Z0-9]+-\d+)"),
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
    # Shapes redaction already masked by prefix but nothing counted, so they
    # never reached the rotation list or --fail-on. The classic OpenAI key has
    # no second hyphen; the lookahead keeps sk-proj-… to the row above.
    ("critical", "OpenAI key",       re.compile(r"\bsk-(?!ant-)([A-Za-z0-9]{40,})(?![A-Za-z0-9_\-])")),
    ("high",     "npm token",        re.compile(r"\bnpm_([A-Za-z0-9]{36})")),
    ("high",     "Shopify token",    re.compile(r"\bshpat_([a-fA-F0-9]{32})")),
    ("high",     "Linear API key",   re.compile(r"\blin_api_([A-Za-z0-9]{32,})")),
    ("high",     "Google OAuth token", re.compile(r"\bya29\.([A-Za-z0-9_\-]{20,})")),
    # The body of a PEM private key, to the END line.
    ("critical", "private key",      _PEM_PRIVATE_KEY),
]

# A cookie value with one of these shapes is a credential whatever its name.
_COOKIE_SHAPES = tuple(rx for _prio, kind, rx in SECRET_TYPES if kind != "private key")

# What redaction masks for each row: the match, and for a JWT its signature
# too (the row stops at the payload, which is what its id is taken from).
_REDACT_SECRET_TYPES = tuple(
    re.compile(rx.pattern + r"(?:\.[A-Za-z0-9_\-]+)?") if kind == "JWT / service key" else rx
    for _prio, kind, rx in SECRET_TYPES)

# The same rules anchored right after an SGR colour code's `m` (_AFTER_SGR),
# for classification and for redaction. Run only when _SGR_TOUCH finds one.
def _after_sgr(rx: "re.Pattern[str]") -> "re.Pattern[str]":
    return re.compile(_AFTER_SGR + rx.pattern[2:])


_SGR_PREFIX = _after_sgr(_SECRET_PATTERNS[1])
# The rules _redact_after_escapes and classify_secrets run over _escape_view.
_ESCAPE_SECRET_TYPES = tuple(rx for rx in _REDACT_SECRET_TYPES if rx.pattern.startswith(r"\b"))
_ESCAPE_CLASSIFY_TYPES = tuple(t for t in SECRET_TYPES if t[2].pattern.startswith(r"\b"))
_SGR_SECRET_TYPES = tuple((prio, kind, _after_sgr(rx)) for prio, kind, rx in SECRET_TYPES
                          if rx.pattern.startswith(r"\b"))
_SGR_REDACT_SECRET_TYPES = tuple(_after_sgr(rx) for rx in _REDACT_SECRET_TYPES
                                 if rx.pattern.startswith(r"\b"))

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
    # Quotes may be backslash-escaped (JSON inside a double-quoted argument),
    # and an SGR colour code may sit before the value (`TOKEN=\e[1m…`).
    r"\\?['\"]?\s*[=:]\s*\\?['\"]?" + _SGR_TEXT + r"?([A-Za-z0-9_\-\.]{12,})", re.IGNORECASE)

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
    # Not AUTHORIZATION, the header that carries a credential.
    r"|author(?!i[sz]ation)[a-z_]*|[a-z_]*_author(?!i[sz]ation)[a-z_]*"
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
_COOKIE_NAME = re.compile(r"(?i)COOKIE")


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
    # The same text redact() masks: stripped characters out first, so a token
    # split by one is counted as the token it shows as.
    cmd = _unhide(cmd[:MAX_SCAN_HARD])[:MAX_SCAN_TOTAL]
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

    types = SECRET_TYPES + list(_SGR_SECRET_TYPES) if _SGR_TOUCH.search(cmd) else SECRET_TYPES
    for priority, kind, rx in types:
        for m in rx.finditer(cmd):
            add(priority, kind, m.group(0), span=m.span(0))
    # A token glued to an escape (`printf 'x\nghp_…'`): the rules again over
    # the text with the escapes blanked, as redact() masks it.
    view = _escape_view(cmd) if _ESCAPE_TOUCH.search(cmd) else None
    if view is not None:
        for priority, kind, rx in _ESCAPE_CLASSIFY_TYPES:
            for m in rx.finditer(view):
                add(priority, kind, m.group(0), span=m.span(0))

    for m in _URL_CRED.finditer(cmd):
        scheme, _user, pw, host = m.groups()
        local = _LOCAL_HOST.match(host) is not None
        add("low" if local else "critical",
            clean(f"{scheme} password ({'local' if local else 'remote'})")[:48], pw,
            span=m.span(3))

    for m in _NAMED_SECRET.finditer(cmd):
        name, value = m.group(1), m.group(2)
        if name.lower() == "cookie" and ":" in cmd[m.end(1):m.start(2)]:
            continue                             # a Cookie header: _cookie_hits reads its pairs
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

    # Every form redact() masks is counted here too, through the
    # same compiled rules, so the rotation list and the masking cannot drift.
    for name, a, b, at in _cookie_hits(cmd):
        add("high", "cookie", cmd[a:b], where.make(f"cookie:{where.program(at)}:{name.upper()}"), (a, b))
    if _OPTION_HINT.search(cmd):
        for rx, group in _OPTION_SECRETS:
            for m, a, b in _option_hits(rx, group, cmd):
                if rx is _OPT_USERPASS and _userpass_exempt(where, m):
                    continue
                add("high", "password option", cmd[a:b], where.option(m, rx), (a, b))
        if view is not None and "password" in view:
            for m, a, b in _option_hits(_OPT_NETRC, 4, view):
                add("high", "password option", cmd[a:b], where.option(m, _OPT_NETRC), (a, b))
        for m in _SECRET_PATTERNS[2].finditer(cmd):
            scheme = m.group(1).split(":", 1)[1].split()[0].lower()
            add("high", "Authorization header", m.group(2),
                where.make(f"hdr:{where.program(m.start())}:{scheme}"), m.span(2))
    # A password is short. _NAMED_SECRET wants 12 characters, which suits a
    # token; PGPASSWORD=hunter2pass was masked and never counted.
    if _PASSWORD_NAME.search(cmd):
        for m, a, b in _kv_hits(cmd):
            name = m.group(1)
            if _PASSWORD_NAME.search(name) and not _NOT_SECRET_NAMES.match(name.strip("_{}%$<>")):
                add(_priority_for_name(name), clean(name.upper())[:48], cmd[a:b],
                    where.make(f"name:{name.upper()}:{where.program(m.start())}"), (a, b))
    # A variable named for a cookie (`SESSION_COOKIE=…`) is masked by the
    # KEY=value rule. A Cookie header's pairs were counted above (_cookie_hits).
    if _COOKIE_NAME.search(cmd):
        for m, a, b in _kv_hits(cmd):
            name = m.group(1)
            if _COOKIE_NAME.search(name) and not _NOT_SECRET_NAMES.match(name.strip("_{}%$<>")):
                add("high", "cookie", cmd[a:b],
                    where.make(f"cookie:{where.program(m.start())}:{name.upper()}"), (a, b))
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
    for a, b, user, host in _scp_long_hits(cmd):
        add("critical", "scp password", cmd[a + len(user) + 1:b], where.make(f"scp:{user}@{host.lower()}"),
            (a + len(user) + 1, b))

    return out


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
    # Split by the shared splitter, outside quotes: `PASSWORD="abc;def" ./run`
    # is one command whose program is ./run, never `def`.
    for segment in _net_split(_without_heredocs(cmd).strip())[0]:
        tokens = _shell_tokens(segment)
        if not tokens:
            continue
        if tokens[0] in _HEADERS_TAKING_A_WORD_LIST:
            continue  # `for x in LIST`: the body is a later segment
        lead = next((t for t in tokens if not (_ASSIGNMENT.match(t) or t in _BODY_KEYWORDS
                                               or t in _PREFIX_WORDS or t in _HEADER_KEYWORDS)), None)
        if lead in _CONDITION_WORDS:
            # `if [ -f x ]` is its own segment once split on `;`, and every
            # token in it belongs to the test rather than to the work. Skipping
            # only the `[` returned its operand instead. Only when the test IS
            # the command: `npm test` runs npm.
            continue
        skip_next = False
        after_sudo = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if after_sudo and tok in _SUDO_VALUE_FLAGS:
                skip_next = True              # `sudo -u postgres psql`: postgres is the user
                continue
            after_sudo = tok == "sudo" or (after_sudo and tok.startswith("-"))
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
    first = [t for t in cmd.strip().split() if not _ASSIGNMENT.match(t)][:1]
    if not first or first[0].startswith("#"):
        return None
    return first[0]


# A pasted token run as a command makes the token itself the "program", and
# program names are counted and displayed (most run, refusals by program,
# MCP shell_audit). Anything that looks like a credential is counted under
# this placeholder instead, so the value never reaches an output.
CREDENTIAL_HEAD = "(credential)"


def safe_head(head: str) -> str:
    """A program name fit to count and display: a credential becomes CREDENTIAL_HEAD."""
    return CREDENTIAL_HEAD if contains_secret(head) or classify_secrets(head) else head


def display_head(cmd: str) -> str | None:
    """command_head(), cleaned, cut to 40 and with credentials replaced."""
    head = command_head(cmd) if cmd else None
    return clean(safe_head(head))[:40] if head else None


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
NET_UNREADABLE_PROGRAM = "(unreadable)"     # the program of a command read only in part (R10)

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
_NET_PREFIX_VALUE_FLAGS = {"sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-D", "-U", "--user", "--group",
                                    "--chdir", "--host", "--prompt", "--role", "--type", "--close-from",
                                    "--other-user"},
                           "nice": {"-n", "--adjustment"}, "env": {"-u", "-C", "--unset", "--chdir"},
                           "timeout": {"-s", "--signal", "-k", "--kill-after"},
                           "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
                           "doas": {"-u", "-C"},
                           "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a",
                                     "--max-args", "--max-procs", "--max-lines", "--delimiter",
                                     "--eof", "--max-chars", "--arg-file", "--replace"},
                           "exec": {"-a"}, "caffeinate": {"-t", "-w"}, "arch": {"-arch", "-e", "-d"},
                           "flock": {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"},
                           "watch": {"-n", "--interval", "-q", "--equexit"}}
# Words that run the command after them: skipped, with their own flags.
_NET_PREFIXES = frozenset({"sudo", "env", "time", "nice", "nohup", "command", "exec",
                           "timeout", "stdbuf", "doas", "busybox", "xargs", "coproc", "setsid",
                           "caffeinate", "arch", "flock", "watch"})
# Shell grammar that can stand before a command in a segment: `do curl …`,
# `if curl …`, `! curl …`, `{ curl …`. A `for x in …` header is not here: it is
# followed by a word list, not a command, and reads as no download.
_NET_CONTROL_WORDS = frozenset({"while", "until", "if", "then", "else", "elif", "do",
                                "!", "{", "}", "(", ")", "esac"})
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
# Case-insensitive: on a case-insensitive filesystem (macOS) `CURL` is curl.
# A `{` that may start a brace expansion (`cu{r,}l`, `h{1..3}`). The class
# excludes `{`, so each start scans to the next one at most: linear.
_NET_BRACE_HINT = r"\{[^\s{}]*?(?:,|\.\.)"
_NET_MAY_DOWNLOAD = re.compile(r"['\"\\$`(]|curl|wget|git|gh|npm|npx|yarn|bun|pip|uv|brew|go|docker|podman|"
                               + _NET_BRACE_HINT, re.I)


def _net_shell_c(t: str) -> bool:
    return "c" in t and _NET_SHELL_FLAGS.match(t) is not None


def _net_shell_c_index(tokens: list[str]) -> int:
    """Where a shell's -c (or -lc, -xc, …) is, when a command string follows; else 0."""
    return next((k for k in range(1, len(tokens) - 1) if _net_shell_c(tokens[k])), 0)
_NET_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh", "yash", "csh", "tcsh"}


_NET_PCT = re.compile(rb"%([0-9A-Fa-f]{2})")
NET_HOST_MAX = 1024
# A host after normalisation: labels of letters, digits, `-` and `_` (curl
# accepts `_`), one optional trailing dot already dropped.
_NET_HOST_OK = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
_NET_IPV4_PART = re.compile(r"0[xX][0-9A-Fa-f]*|[0-9]+")
_NET_IPV6_GROUP = re.compile(r"[0-9a-f]{1,4}")


def _ipv4_canon(labels: list[str]) -> str | None:
    """Dotted quad for an IPv4 address in any form inet_aton and curl accept
    (`101058054`, `0x06060606`, `6.6.1542`, `06.06.06.06`), or None when the
    numbers do not make one."""
    if not 1 <= len(labels) <= 4:
        return None
    nums = []
    for p in labels:
        if len(p) > 34 or not _NET_IPV4_PART.fullmatch(p):
            return None                      # no 32-bit number is longer (and int() caps digits)
        if p[:2].lower() == "0x":
            nums.append(int(p[2:] or "0", 16))
        elif len(p) > 1 and p[0] == "0":
            if not all(c in "01234567" for c in p):
                return None
            nums.append(int(p, 8))
        else:
            nums.append(int(p))
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + nums[-1]
    return ".".join(str((value >> s) & 255) for s in (24, 16, 8, 0))


def _ipv6_canon(inner: str) -> str | None:
    """`[…]` in RFC 5952 form, or the dotted quad of an IPv4-mapped address
    (`::ffff:6.6.6.6`); None when it does not parse (a zone id included)."""
    inner = inner.lower()
    if "%" in inner or inner.count("::") > 1:
        return None

    def groups(text: str) -> list[int] | None:
        out: list[int] = []
        parts = text.split(":") if text else []
        for k, p in enumerate(parts):
            if "." in p and k == len(parts) - 1:
                if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", p) or any(int(x) > 255 for x in p.split(".")):
                    return None
                a, b, c, d = (int(x) for x in p.split("."))
                out += [a * 256 + b, c * 256 + d]
            elif _NET_IPV6_GROUP.fullmatch(p):
                out.append(int(p, 16))
            else:
                return None
        return out
    head, sep, tail = inner.partition("::")
    h, t = groups(head), groups(tail)
    if h is None or t is None:
        return None
    if sep:
        if len(h) + len(t) > 7:
            return None
        g = h + [0] * (8 - len(h) - len(t)) + t
    elif len(h) == 8:
        g = h
    else:
        return None
    if g[:5] == [0] * 5 and g[5] == 0xFFFF:
        return f"{g[6] >> 8}.{g[6] & 255}.{g[7] >> 8}.{g[7] & 255}"
    best, at = 0, -1                         # the longest run of two or more zero groups
    k = 0
    while k < 8:
        if g[k] == 0:
            e = k
            while e < 8 and g[e] == 0:
                e += 1
            if e - k > best and e - k >= 2:
                best, at = e - k, k
            k = e
        else:
            k += 1
    hexes = [format(x, "x") for x in g]
    if at < 0:
        return "[" + ":".join(hexes) + "]"
    return "[" + ":".join(hexes[:at]) + "::" + ":".join(hexes[at + best:]) + "]"


_IDNA_DEVIATIONS = re.compile("[\u00df\u1e9e\u03c2\u200c\u200d]")


def _host_canon(host: str) -> str | None:
    """A URL's host as curl and the URL standard resolve it (ruling R15):
    percent-decoded, IDNA-mapped, lower-cased, without a trailing dot, an IPv4
    address in any numeric form as a dotted quad, an IPv6 address in RFC 5952
    form (an IPv4-mapped one as its dotted quad). None when it cannot be
    normalised with confidence: the caller marks the item unresolved."""
    if len(host) > NET_HOST_MAX:
        return None                          # longer than any DNS name, even percent-encoded
    if "%" in host:
        try:
            host = _NET_PCT.sub(lambda m: bytes([int(m.group(1), 16)]), host.encode("utf-8")).decode("utf-8")
        except (UnicodeError, ValueError):
            return None
        if "%" in host:
            return None
    if host.startswith("["):
        return _ipv6_canon(host[1:-1]) if host.endswith("]") else None
    if not host.isascii():
        # Python's codec is IDNA 2003; curl (libidn2) and browsers use UTS 46,
        # non-transitional. They differ on the deviation characters: 2003 maps
        # sharp s (U+00DF) to "ss", final sigma (U+03C2) to sigma and drops the
        # joiners (U+200C, U+200D); UTS 46 keeps them, so "stra\u00dfe.example"
        # is xn--strae-oqa.example to curl, not strasse.example. Without a
        # UTS 46 table, a host holding one is not normalised (fail closed:
        # unresolved, never trusted). Capital sharp s (U+1E9E) lowercases to U+00DF.
        if _IDNA_DEVIATIONS.search(host):
            return None
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    host = host.lower()
    host = host[:-1] if host.endswith(".") else host
    if not host or not _NET_HOST_OK.fullmatch(host):
        return None
    labels = host.split(".")
    if _NET_IPV4_PART.fullmatch(labels[-1]):
        return _ipv4_canon(labels)           # a numeric last label: an address or nothing
    return host


def _url_host_parts(url: str) -> tuple[str | None, bool]:
    """(url_host(url), unresolved): unresolved is True when `url` is a URL
    whose literal host could not be normalised (R15), as opposed to no host
    at all or one built from a variable."""
    if not url:
        return None, False
    if _NET_URL.match(url):
        rest = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
        host = rest.rsplit("@", 1)[-1]
        if host.startswith("["):             # IPv6 literal: the brackets, then an optional port
            host = host[:host.find("]") + 1] if "]" in host else host
        else:
            host = host.split(":", 1)[0]     # a variable in the port hides nothing (R3B4)
        if "$" in host or "`" in host or _LEX_PH in host:
            return None, False
        if not host:
            return None, False
        canon = _host_canon(host)
        return canon, canon is None
    if "$" in url.split(":", 1)[0] or "`" in url.split(":", 1)[0]:
        return None, False
    m = _NET_SCP.match(url)
    if not m:
        return None, False
    canon = _host_canon(m.group(1))
    return canon, canon is None


def url_host(url: str) -> str | None:
    """Normalised host of a URL or scp-style git remote, without user or port
    (see _host_canon).

    None for anything that is not one: a remote name, a path, a URL whose
    host is built from a shell variable and cannot be known from the
    transcript, or a host that cannot be normalised. A variable in the path,
    query or port (`…/releases/$VER/x`, `:$PORT`) leaves the literal host
    readable.
    """
    return _url_host_parts(url)[0]


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
    host, unresolved = _url_host_parts(url)
    item = _net_item(kind, program, host=host, url=url,
                     dynamic="$" in url or "`" in url or unresolved, **kw)
    if unresolved:
        item["_unresolved"] = "host-unresolved"   # a literal host not normalised (R15)
    return item


def _net_registry_item(program: str, ecosystem: str, name: str | None, version: str | None,
                       registry: str | None, exec_: bool = False,
                       exact: "re.Pattern" = _NET_FULL_VERSION) -> dict:
    host, unresolved = _url_host_parts(registry) if registry else (None, False)
    if registry and not host:
        # A registry is named but its host cannot be read (`--registry "$R"`, a
        # path): not the public default. Built from a variable, it is dynamic.
        item = _net_item("install", program, ecosystem=ecosystem, package=name, version=version,
                         pinned=bool(version and exact.match(version)), exec=exec_,
                         dynamic="$" in registry or "`" in registry or unresolved)
        if unresolved:
            item["_unresolved"] = "host-unresolved"
        return item
    return _net_item("install", program, ecosystem=ecosystem, package=name, version=version,
                     pinned=bool(version and exact.match(version)), exec=exec_,
                     host=host or NETWORK_REGISTRY[ecosystem], host_inferred=not host)


def _net_lockfile(program: str, ecosystem: str, registry: str | None = None) -> dict:
    item = _net_registry_item(program, ecosystem, None, None, registry)
    item["pinned"] = True
    return item


_NET_CLUSTER = re.compile(r"^-[A-Za-z]{2,}$")


def _net_cluster_takes(a: str, takes_value: frozenset) -> bool:
    """A single-dash cluster (`-sH`, `-fsSX`) whose last letter takes a value,
    the next word. When an earlier letter takes one, the rest of the cluster
    is that value (`-ofile`, `-Oout`) and nothing more is consumed."""
    if not _NET_CLUSTER.match(a) or "-" + a[-1] not in takes_value:
        return False
    return not any("-" + ch in takes_value for ch in a[1:-1])


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
            elif _net_cluster_takes(a, takes_value) and i + 1 < len(args):
                opts["-" + a[-1]] = args[i + 1]  # `-sH "X: y"`: the last letter takes the value
                opts[a] = ""
                i += 1
            else:
                opts[a] = ""
        else:
            pos.append(a)
        i += 1
    return pos, opts


# The character loops in _net_split and _net_tokens are exact. A text with none
# of these characters splits the same way in one C-level call, which is most
# commands. A fuzz of 200,000 random strings found no difference.
_NET_SPLIT_SLOW = re.compile(r"['\"\\#$]|>\|")
# A lone `&` (run in the background) separates commands too; `&>`, `>&` and
# `<&` are redirections, which _net_tokens reads.
_NET_SPLIT_OPS = re.compile(r"(&&|\|\||\|&|(?<![<>])&(?![>&])|[;|\n])")
_NET_TOKENS_SLOW = re.compile(r"['\"\\<>&()#$]")
_NET_TOKENS_STOP = re.compile(r"[\s'\"\\<>&()#$]")
# The exact path jumps from one of these to the next; the text between is copied.
_NET_SPLIT_STOP = re.compile(r"[\\'\"#$&|;\n]")
# The rest of a double-quoted span after its opening quote, through the closing
# one; and of an ANSI-C $'…' span after `$'`. Each alternative starts with a
# different character, so the scan is linear.
_NET_DQ_REST = re.compile(r'(?:[^"\\]|\\.)*"', re.S)
_NET_ANSI_REST = re.compile(r"(?:[^'\\]|\\.)*'", re.S)
# A `#` starts a comment only at the start of a word.
_NET_WORD_BREAK = frozenset(" \t\n;&|()<>")


def _net_split(text: str, seps: list[str] | None = None,
               amps: list[int] | None = None) -> tuple[list[str], bool]:
    """Split on && || |& ; | & and newline, outside quotes and comments (bash
    rules: '…' is literal, "…" and $'…' honour a backslash, a `#` at the start
    of a word comments out the rest of its line). Returns the parts and whether
    a quote was left open (the last part is then unusable). `seps`, when given,
    receives the operator after each part ("" after the last); a lone `&` is
    given as ";", and `amps`, when given, receives the index of each part it
    ends (run in the background: a subshell)."""
    if not _NET_SPLIT_SLOW.search(text):     # nothing quoted or escaped: one C-level split
        pieces = _NET_SPLIT_OPS.split(text)
        if seps is not None:
            seps += ["|" if p == "|&" else ";" if p == "&" else p for p in pieces[1::2]] + [""]
        if amps is not None:
            amps += [k for k, p in enumerate(pieces[1::2]) if p == "&"]
        return pieces[0::2], False
    parts: list[str] = []
    buf: list[str] = []
    open_quote, i, n = False, 0, len(text)
    esc_end = -1                             # just after the last escaped character
    while i < n:
        m = _NET_SPLIT_STOP.search(text, i)
        if m is None:
            buf.append(text[i:])
            break
        j = m.start()
        if j > i:
            buf.append(text[i:j])
            i = j
        ch = text[i]
        if ch == "\\":
            buf.append(text[i:i + 2])        # an escaped character opens and closes nothing
            i += 2
            esc_end = i
            continue
        if ch == "'" or ch == '"' or (ch == "$" and text.startswith("$'", i)):
            if ch == "'":
                k = text.find("'", i + 1)
                end = k + 1 if k >= 0 else -1
            else:
                q = _NET_DQ_REST.match(text, i + 1) if ch == '"' else _NET_ANSI_REST.match(text, i + 2)
                end = q.end() if q else -1
            if end < 0:
                buf.append(text[i:])
                open_quote = True
                break
            buf.append(text[i:end])
            i = end
            continue
        if ch == "$":
            buf.append(ch)
            i += 1
            continue
        if ch == "#":
            # `a\ #b` and `a\;#b`: an escaped blank or operator is part of the word
            if i == 0 or (i != esc_end and text[i - 1] in _NET_WORD_BREAK):
                k = text.find("\n", i)       # a comment: to the end of its line
                i = n if k < 0 else k
            else:
                buf.append(ch)
                i += 1
            continue
        prev = text[i - 1] if i else ""
        if text.startswith(("&&", "||", "|&"), i):
            parts.append("".join(buf))
            if seps is not None:
                seps.append("|" if text.startswith("|&", i) else text[i:i + 2])   # |& pipes stderr too
            buf = []
            i += 2
            continue
        if ch == "|" and prev == ">" and i != esc_end:
            buf.append(ch)                   # `>|` is a clobber redirection, not a pipe (`\>|` is a pipe)
        elif ch == "&" and ((prev in ("<", ">") and i != esc_end) or text.startswith("&>", i)):
            buf.append(ch)
        else:
            parts.append("".join(buf))       # ; | newline, or a lone `&`: the next command
            if seps is not None:
                seps.append(";" if ch == "&" else ch)
            if amps is not None and ch == "&":
                amps.append(len(parts) - 1)
            buf = []
        i += 1
    parts.append("".join(buf))
    if seps is not None:
        seps.append("")
    return parts, open_quote


class _NetArgv(list):
    """The argv of one command, carrying the NAME=VALUE assignments written
    before it (`npm_config_registry=… npm i x`, `GH_HOST=… gh …`): they can
    change where the program downloads from (R3B10, R3B11). Also what its
    wrappers do to the environment it inherits (R3F5): `env -i` or `env -`
    clears it (`env_clear`), `env -u NAME` drops NAME (`env_unset`), and sudo
    or doas without -E may reset it (`env_maybe`: the sudoers policy decides)."""
    env: dict = {}
    env_clear = False
    env_unset: frozenset = frozenset()
    env_maybe = False


def _net_argv(tokens: list[str], env: dict, scope: "dict | None" = None) -> list[str]:
    if not env and not (scope and (scope["clear"] or scope["unset"] or scope["maybe"])):
        return tokens
    out = _NetArgv(tokens)
    out.env = env
    if scope:
        out.env_clear, out.env_unset, out.env_maybe = scope["clear"], frozenset(scope["unset"]), scope["maybe"]
    return out


def _net_inherit(tokens: list[str], outer: list[str]) -> list[str]:
    """`tokens`, run by the command `outer` (`VAR=x bash -c '…'`, `env -i sh -c
    '…'`): it inherits outer's assignments and environment changes (R3F5)."""
    o_env = getattr(outer, "env", {})
    o_clear, o_unset, o_maybe = (getattr(outer, "env_clear", False), getattr(outer, "env_unset", frozenset()),
                                 getattr(outer, "env_maybe", False))
    if not (o_env or o_clear or o_unset or o_maybe):
        return tokens
    out = _NetArgv(tokens)
    out.env = {**o_env, **getattr(tokens, "env", {})}
    out.env_clear = o_clear or getattr(tokens, "env_clear", False)
    out.env_unset = o_unset | getattr(tokens, "env_unset", frozenset())
    out.env_maybe = o_maybe or getattr(tokens, "env_maybe", False)
    return out


def _net_strip_prefixes(tokens: list[str]) -> tuple[list[str], bool]:
    """The command a segment runs, past assignments, control-flow words and
    wrappers, and whether it came through `xargs` (its arguments may then
    arrive on stdin, out of sight). Names are compared lower-cased (R11), a
    wrapper by its base name (`/usr/bin/env` is env, R3C1). The assignments
    skipped ride on the result (_NetArgv.env)."""
    i, via_xargs, via_exec = 0, False, False
    env: dict[str, str] = {}
    scope: dict = {"clear": False, "unset": set(), "maybe": False}
    while i < len(tokens):
        t = tokens[i]
        low = t.lower()
        if _NET_ASSIGN.match(t):
            k, _, v = t.partition("=")
            env[k] = v
            i += 1
            continue
        if low in _NET_CONTROL_WORDS:
            i += 1
            continue
        if "/" in low:
            low = _net_base(low)
        if low in _NET_PREFIXES:
            takes = _NET_PREFIX_VALUE_FLAGS.get(low, set())
            via_xargs = via_xargs or low == "xargs"
            i += 1
            keep_env = False
            while i < len(tokens) and tokens[i].startswith("-") and len(tokens[i]) > 1:
                a = tokens[i]
                if low == "env":
                    gone = (tokens[i + 1] if a in ("-u", "--unset") and i + 1 < len(tokens)
                            else a[8:] if a.startswith("--unset=")
                            else a[2:] if a.startswith("-u") and not a.startswith("--") else None)
                    if a in ("-i", "--ignore-environment") or (
                            not a.startswith("--") and gone is None and "i" in a and set(a[1:]) <= set("iv0")):
                        env.clear()              # `env -i`: nothing inherited, nothing assigned before
                        scope["clear"] = True
                    elif gone:
                        env.pop(gone, None)
                        scope["unset"].add(gone)
                elif low in ("sudo", "doas") and (a in ("-E", "--preserve-env")
                                                  or a.startswith("--preserve-env=")):
                    keep_env = True
                if low == "flock" and a in ("-c", "--command"):
                    break
                if low == "env" and (a in ("-S", "--split-string") or a.startswith(("-S", "--split-string="))):
                    # `env -S 'curl … | sh'`: env splits the string into the command (R3B7).
                    if a in ("-S", "--split-string"):
                        text, rest = (tokens[i + 1] if i + 1 < len(tokens) else ""), tokens[i + 2:]
                    else:
                        text, rest = a.split("=", 1)[1] if a.startswith("--") else a[2:], tokens[i + 1:]
                    return _net_argv(["sh", "-c", " ".join([text] + rest)], env, scope), via_xargs
                if low == "watch" and a in ("-x", "--exec"):
                    via_exec = True
                    i += 1
                    break
                i += 2 if a in takes else 1
            if low == "env" and i < len(tokens) and tokens[i] == "-":
                env.clear()                      # `env - CMD` is `env -i CMD`
                scope["clear"] = True
                i += 1
            if low in ("sudo", "doas") and not keep_env:
                scope["maybe"] = True            # env_reset: what reaches CMD is the policy's call
            if low in ("timeout", "flock") and i < len(tokens):
                i += 1                       # timeout's DURATION, flock's FILE
            if low == "flock" and i < len(tokens) and tokens[i] in ("-c", "--command"):
                return _net_argv(["sh", "-c"] + tokens[i + 1:], env, scope), via_xargs    # `flock F -c CMD` runs CMD with sh
            if low == "watch" and i < len(tokens) and not via_exec:
                # watch runs its arguments, joined, with `sh -c` (R3B7).
                return _net_argv(["sh", "-c", " ".join(tokens[i:])], env, scope), via_xargs
            continue
        break
    return _net_argv(tokens[i:], env, scope), via_xargs


# `{name}>f` (bash 4.1+) allocates a file descriptor into $name: a redirection.
_NET_FD_VAR = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}\Z")
# Redirection operators, longest first. `>|` reaches here only from _net_split,
# which keeps the `|` of a clobber with its `>`.
_NET_REDIRECT_OPS = ("&>>", "&>", "<<<", "<<", "<>", "<&", "<", ">>", ">&", ">|", ">")
_ANSI_C_ESCAPES = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
                   "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_ANSI_C_STOP = re.compile(r"[\\']")
_ANSI_C_HEX = re.compile(r"[0-9A-Fa-f]+")
_ANSI_C_OCT = re.compile(r"[0-7]+")


def _ansi_c(text: str, i: int) -> tuple[str | None, int]:
    """Decode the ANSI-C quoted word $'…' that starts at text[i] (the `$`):
    (its value, the index after the closing quote), or (None, -1) when it is
    not closed. Backslash escapes as bash reads them, including \\'. Bash
    cuts the value at the first NUL (`$'cu\\x00x'rl` is `curl`), and the
    lexer's private-use markers are replaced, so a decoded value can never
    forge one."""
    out: list[str] = []
    j, n = i + 2, len(text)
    while True:
        m = _ANSI_C_STOP.search(text, j)
        if m is None:
            return None, -1
        out.append(text[j:m.start()])
        j = m.start()
        if text[j] == "'":
            value = "".join(out)
            if "\0" in value:
                value = value[:value.index("\0")]
            if not value.isascii() and _LEX_PRIVATE.search(value):
                value = _LEX_PRIVATE.sub("\ufffd", value)
            return value, j + 1
        if j + 1 >= n:
            return None, -1
        e = text[j + 1]
        if e in _ANSI_C_ESCAPES:
            out.append(_ANSI_C_ESCAPES[e])
            j += 2
        elif e in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[e]
            h = _ANSI_C_HEX.match(text, j + 2, min(n, j + 2 + width))
            if h:
                cp = int(h.group(0), 16)
                out.append(chr(cp) if cp <= 0x10FFFF else "\ufffd")
                j = h.end()
            else:
                out.append("\\" + e)
                j += 2
        elif e in "01234567":
            o = _ANSI_C_OCT.match(text, j + 1, min(n, j + 4))
            out.append(chr(int(o.group(0), 8) & 0xFF))
            j = o.end()
        elif e == "c" and j + 2 < n:
            out.append(chr(ord(text[j + 2]) & 0x1F))
            j += 3
        else:
            out.append("\\" + e)
            j += 2


def _net_tokens(segment: str, operators: bool = False,
                redirs: "list[tuple[str, str]] | None" = None) -> list[str]:
    """Like _shell_tokens, but a backslash escapes: `\\"` is a quote character,
    not a quote; $'…' is decoded (ANSI-C quoting, where \\' is a quote
    character); a `#` that starts a word comments out the rest of its line.
    Kept here so command_head() keeps its behaviour.

    With `operators`, an unquoted `(` or `)` separates words, and an unquoted redirection (`>`, `2>&1`, `&>f`, `< f`,
    `<<< w`, `>| f`, attached or not) is dropped with its target, and a word
    is cut where an unquoted `<` or `>` starts one: `https://a.io>/tmp/x`
    is the URL `https://a.io`. A redirection is never a package or a host.
    `redirs`, when given, receives (operator, target) for each one dropped."""
    if not _NET_TOKENS_SLOW.search(segment):  # no quote, escape or operator: plain words
        return segment.split()
    out, buf, quote, started, i = [], [], "", False, 0
    discard = False                          # the next word is a redirection target
    op = ""
    n = len(segment)

    def flush() -> None:
        if discard:
            if redirs is not None:
                redirs.append((op, "".join(buf)))
        else:
            out.append("".join(buf))

    while i < n:
        if not quote:                        # copy a run of plain characters at once
            m = _NET_TOKENS_STOP.search(segment, i)
            j = m.start() if m else n
            if j > i:
                buf.append(segment[i:j])
                started = True
                i = j
                if i >= n:
                    break
        elif quote == "'":
            e = segment.find("'", i)
            if e < 0:
                buf.append(segment[i:])
                break
            buf.append(segment[i:e])
            quote = ""
            i = e + 1
            continue
        ch = segment[i]
        if ch == "\\" and quote != "'" and i + 1 < n:
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
        elif ch == "$" and segment.startswith("$'", i):
            value, end = _ansi_c(segment, i)
            if value is None:                # not closed: the rest is the word
                buf.append(segment[i + 2:])
                started = True
                break
            buf.append(value)
            started = True
            i = end
            continue
        elif ch in "\"'":
            quote, started = ch, True
        elif ch == "#" and not buf and not started and (i == 0 or segment[i - 1] in _NET_WORD_BREAK):
            k = segment.find("\n", i)        # a comment: nothing after it on its line is a word
            i = n if k < 0 else k
            continue
        elif ch.isspace():
            if buf or started:
                flush()
                discard = False
                buf, started = [], False
        elif operators and ch in "()":
            if buf or started:
                flush()
                discard = False
            buf, started = [], False
        elif operators and (ch in "<>" or segment.startswith("&>", i)):
            nop = next(o for o in _NET_REDIRECT_OPS if segment.startswith(o, i))
            word = "".join(buf)
            if (buf or started) and not word.isdigit() and not _NET_FD_VAR.match(word):
                flush()                      # `a.io>f`: the word ends here; `2>f`, `{fd}>f`: the fd
            buf, started, discard, op = [], False, True, nop
            i += len(nop)
            continue
        else:
            buf.append(ch)
            started = True
        i += 1
    if buf or started:
        flush()
    return out


# --- the shared shell lexer ----------------------------------------------------
#
# One pass over a command, as bash reads it (R9): '…' is literal; "…" and the
# body of a heredoc whose word is unquoted expand $(…), `…` and ${…}; $'…' is
# ANSI-C quoted; a `#` that starts a word outside quotes is a comment; `\`
# before a newline joins lines; a heredoc opener counts only outside quotes,
# comments and $((…)). It yields the command as plain shell code (comments and
# heredoc bodies cut out, $'…' turned into '…') in which every substitution is
# a placeholder word holding `$`, and the substitution bodies and heredoc
# bodies beside it. Nesting is a stack, never recursion, so any depth costs one
# pass; only a backtick body holding \` or \$ is read again, as bash does, at
# most NET_NEST_MAX levels deep and charged to the budget. Arithmetic and
# [[ … ]] text is kept out of the code (only its substitutions stay). The
# audit (audit_command) and the network inventory both read commands through
# it (R12).

_LEX_HD = "\ue000"                           # brackets a heredoc marker in lexed code
_LEX_PH = "\ue001"                           # brackets a substitution placeholder
_LEX_SUB = re.compile("\\$\ue001(\\d+)\ue001")
_LEX_HEREDOC = re.compile("\ue000(\\d+)\ue000")
_LEX_PRIVATE = re.compile("[\ue000\ue001]")
_LEX_STOP = {
    "code": re.compile(r"[\\'\"`$#<>()\n]|case|esac|\[\["),
    "dq": re.compile(r"[\\\"`$]"),
    "hd": re.compile(r"[\\`$]"),
    "arith": re.compile(r"[\\'\"`$()]"),
    "barith": re.compile(r"[\\'\"`$\[\]]"),     # legacy $[ … ] arithmetic
    "brace": re.compile(r"[\\'\"`${}]"),
    "test": re.compile(r"[\\'\"`$\]]"),     # [[ … ]]
}
_LEX_CLASS = {"top": "code", "cmd": "code", "proc": "code", "tick": "code",
              "dq": "dq", "hd": "hd", "arith": "arith", "barith": "barith",
              "brace": "brace", "test": "test"}
# Words after which the next word is in command position, where bash reads a
# reserved word such as `case` or `[[` (R3A2-1); `esac` may also follow `in`.
_LEX_CMD_WORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "time", "{", "!"})
_LEX_ESAC_WORDS = _LEX_CMD_WORDS | {"in"}
# A comment inside `…` ends at the closing backtick (an escaped one does not count) or the newline.
_LEX_TICK_COMMENT = re.compile(r"\\.|[`\n]", re.S)
NET_NEST_MAX = 8                             # re-read levels: bash -c, eval, here-strings, heredoc code
NET_TREE_MAX = 200                           # substitutions inside substitutions in one text
NET_LEX_BUDGET = 2 * MAX_SCAN_HARD           # characters lexed per command, every level together


class _LexUnit:
    """One piece of shell code: the command text (`buf`, joined into `code`)
    and the global ids of the substitutions directly inside it."""
    __slots__ = ("buf", "children", "code")

    def __init__(self) -> None:
        self.buf: list[str] = []
        self.children: list[int] = []
        self.code = ""


class _LexCtx:
    """State shared by every level of one command: all substitution bodies
    (`subs`, their kinds and whether a shell runs their output), all heredocs
    ([body or None when unterminated, word quoted, word, `<<-`]), the heredoc
    body spans of the outermost text, the character budget, how many backtick
    bodies deep the lexer is reading again, and whether a limit was hit (R10)."""
    __slots__ = ("subs", "kinds", "feeds", "heredocs", "spans", "budget", "limit", "lines", "depth", "top")

    def __init__(self) -> None:
        self.subs: list[_LexUnit] = []
        self.kinds: list[str] = []
        self.feeds: list[bool] = []
        self.heredocs: list[list] = []
        self.spans: list[tuple[int, int]] = []
        self.budget = NET_LEX_BUDGET
        self.limit = False
        self.lines: list[str] = []
        self.depth = 0
        # The top level's scope: (for each segment, (part, "direct" | "eval" |
        # "nested") or (None, …) when the part is not known; the parts; the
        # operator after each; the parts a lone `&` ends). Set by _net_unit_segments.
        self.top: tuple = ([], [], [], [])


def _lex_prepare(text: str) -> str:
    """\\r\\n is \\n (R9); the private-use characters the lexer marks with are
    replaced, so transcript text can never forge a marker."""
    if "\r" in text:
        text = text.replace("\r\n", "\n")
    if not text.isascii() and _LEX_PRIVATE.search(text):
        text = _LEX_PRIVATE.sub("\ufffd", text)
    return text


def _shell_lex(text: str, ctx: _LexCtx, mode: str = "top", spans: bool = False) -> _LexUnit:
    """Lex `text` (see the section comment). mode "hd" reads a heredoc body:
    only substitutions count. With `spans`, the raw spans of heredoc bodies
    (with their terminator lines) are recorded in ctx.spans."""
    top = _LexUnit()
    first_sub = len(ctx.subs)
    # A frame: [kind, unit, paren depth, open `case`s, start, extra, pending
    # heredocs at its start]. `extra` is, for a backtick frame, whether its body
    # held \` or \$ (it is then read again, as bash does); for an arithmetic or
    # [[ ]] frame, the unit its placeholder goes to.
    stack: list[list] = [[mode, top, 0, 0, 0, None, 0]]
    pending: list[int] = []
    indexes: dict[tuple[bool, bool], dict[str, list[tuple[int, int]]]] = {}   # built on first use
    seen: dict[tuple[bool, bool, str], int] = {}
    sinks: set[int] = set()                      # ids of the units that hold arithmetic or [[ ]] text
    last_close = -1
    esc_end = -1                                 # the index just after the last escaped character
    cont = "\\\n" in text
    i, n = 0, len(text)

    def push(kind: str, unit: _LexUnit, start: int, extra: object = None) -> None:
        stack.append([kind, unit, 0, 0, start, extra, len(pending)])

    def seq(k: int, s: str) -> int:
        """The index after `s` read at text[k], skipping line continuations
        (bash joins them before it reads an operator: `<\\ newline <EOF`), or -1."""
        if not cont:
            return k + len(s) if text.startswith(s, k) else -1
        for c in s:
            while text.startswith("\\\n", k):
                k += 2
            if k >= n or text[k] != c:
                return -1
            k += 1
        return k

    def before(k: int) -> int:
        """k moved back over the line continuations just before it."""
        start = stack[-1][4]
        while cont and k - 2 >= start and text[k - 1] == "\n" and text[k - 2] == "\\" and esc_end != k - 1:
            k -= 2
        return k

    def word_start(k: int) -> bool:
        # An escaped blank or operator (`a\ #b`) is part of the word, not a break.
        k = before(k)
        return k == stack[-1][4] or (k != last_close and k != esc_end and text[k - 1] in _NET_WORD_BREAK)

    def cmd_pos(k: int, words: frozenset = _LEX_CMD_WORDS) -> bool:
        """Whether the word at k is in command position, where bash reads a
        reserved word (`case`, `esac`, `[[`): after a separator, `(`, the frame
        start, or a reserved word that a command follows. `echo case` is not."""
        start = stack[-1][4]
        j = before(k) - 1
        while j >= start and text[j] in " \t":
            j = before(j) - 1
        if j < start:
            return True
        c = text[j]
        if c in ";&|(\n":
            return esc_end != j + 1
        if c == ")":
            return bool(stack[-1][3]) and esc_end != j + 1 and last_close != j + 1
        w = j
        while w > start and j - w < 5 and text[w - 1] not in _NET_WORD_BREAK:
            w -= 1
        return (text[w:j + 1] in words and esc_end != j + 1
                and (w == start or text[w - 1] in _NET_WORD_BREAK))

    def open_child(kind: str, unit: _LexUnit, start: int) -> None:
        g = len(ctx.subs)
        child = _LexUnit()
        ctx.subs.append(child)
        ctx.kinds.append(kind)
        ctx.feeds.append(False)
        unit.children.append(g)
        unit.buf.append(f"${_LEX_PH}{g}{_LEX_PH}")
        push(kind, child, start, False)

    def open_sink(kind: str, unit: _LexUnit, start: int) -> None:
        # Arithmetic and [[ ]] text is not commands: it goes to a unit of its
        # own, and only its substitutions reach the code (R3A2-15). Nested in
        # another such text, it shares that unit (extra None), so no
        # substitution id is ever moved twice: linear at any depth.
        if id(unit) in sinks:
            push(kind, unit, start, None)
            return
        sink = _LexUnit()
        sinks.add(id(sink))
        push(kind, sink, start, unit)

    def close_sink(fr: list, tail: str) -> None:
        sink, parent = fr[1], fr[5]
        if parent is None:
            return                           # shared with the enclosing arithmetic: nothing to move
        if sink.children:
            parent.buf.append(" ".join(f"${_LEX_PH}{g}{_LEX_PH}" for g in sink.children) + " ")
            parent.children.extend(sink.children)
        parent.buf.append(tail)

    def reread(unit: _LexUnit) -> None:
        # `…` with \` or \$ inside: bash unescapes the body and parses it again.
        body = "".join(unit.buf)
        if ctx.depth >= NET_NEST_MAX or len(body) > ctx.budget:
            ctx.limit = True
            return
        ctx.budget -= len(body)
        ctx.depth += 1
        try:
            inner = _shell_lex(body, ctx)
        finally:
            ctx.depth -= 1
        unit.buf = [inner.code]
        unit.children.extend(inner.children)

    def terminators(logical: bool, dash: bool) -> dict[str, list[tuple[int, int]]]:
        """Terminator line -> [(start, end)] of the lines that read as it: the
        whole line, as bash compares it (no blank stripped); with `dash`
        (`<<-`) leading tabs removed; with `logical` (an unquoted word)
        backslash-newline continuations joined first (`EO\\ newline F` is `EOF`)."""
        key = (logical, dash)
        idx = indexes.get(key)
        if idx is not None:
            return idx
        idx = indexes[key] = {}
        start = first = 0
        parts: list[str] = []
        for line in text.split("\n"):
            end = start + len(line)
            if logical and line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2:
                parts.append(line[:-1])
                start = end + 1
                continue
            if parts:
                parts.append(line)
                line = "".join(parts)
                parts = []
            if dash:
                line = line.lstrip("\t")
            if line:
                idx.setdefault(line, []).append((first, end))
            start = first = end + 1
        return idx

    def read_heredocs(pos: int, base: int) -> int:
        # The heredocs opened on this line in this frame (or in substitutions
        # on it that have closed): bash reads their bodies after the newline
        # that ends the line, not at a newline inside a $( … ) on it.
        for h in pending[base:]:
            _body, quoted, word, dash = ctx.heredocs[h]
            key = (not quoted, dash)
            found = terminators(*key).get(word, ())
            k = seen.get((*key, word), 0)
            while k < len(found) and found[k][0] < pos:     # pos only grows: linear
                k += 1
            seen[(*key, word)] = k
            if k == len(found):
                continue                     # no terminator: its lines stay commands
            s, e = found[k]
            e = n if e >= n else e + 1
            ctx.heredocs[h][0] = text[pos:max(pos, s - 1)]
            if spans:
                ctx.spans.append((pos, e))
            pos = e
        del pending[base:]
        return pos

    def heredoc_open(unit: _LexUnit, after: int) -> int:
        j, dash = after, False
        d = seq(j, "-")
        if d >= 0:
            j, dash = d, True
        while j < n and (text[j] in " \t" or (cont and text.startswith("\\\n", j))):
            j += 2 if text[j] == "\\" else 1
        if j < n and text[j] == _LEX_HD:     # a marker from an earlier pass (a backtick body read again)
            e = text.find(_LEX_HD, j + 1)
            if e > 0:
                unit.buf.append("<<" + text[j:e + 1] + " ")
                return e + 1
        word: list[str] = []
        quoted = False
        while j < n:
            c = text[j]
            if c in _NET_WORD_BREAK:
                break
            if c in "'\"":
                e = text.find(c, j + 1)
                if e < 0:
                    word = []
                    break
                word.append(text[j + 1:e])
                quoted, j = True, e + 1
            elif c == "\\" and j + 1 < n:
                if text[j + 1] == "\n":
                    j += 2                   # a continuation: `<<E\ newline OF` is the unquoted EOF
                    continue
                word.append(text[j + 1])
                quoted, j = True, j + 2
            else:
                word.append(c)
                j += 1
        delim = "".join(word)
        if not delim:
            unit.buf.append("<<")
            return after
        h = len(ctx.heredocs)
        ctx.heredocs.append([None, quoted, delim, dash])
        pending.append(h)
        unit.buf.append(f"<<{_LEX_HD}{h}{_LEX_HD} ")
        return j

    while i < n:
        fr = stack[-1]
        kind, unit = fr[0], fr[1]
        buf = unit.buf
        cls = _LEX_CLASS[kind]
        m = _LEX_STOP[cls].search(text, i)
        if m is None:
            buf.append(text[i:])
            break
        j = m.start()
        if j > i:
            buf.append(text[i:j])
            i = j
        ch = text[i]
        if ch == "\\":
            nxt = text[i + 1:i + 2]
            if nxt == "\n":
                i += 2                       # a continuation: the line goes on
                continue
            if kind == "tick" and nxt in ("`", "$", "\\"):
                buf.append(nxt)              # inside `…`, \` \$ \\ lose their backslash
                if nxt != "\\":
                    fr[5] = True             # and the body is read again when it closes
            else:
                buf.append(text[i:i + 2])
            i += 2
            esc_end = i
            continue
        if ch == "`":
            if kind == "tick":
                stack.pop()
                last_close = i + 1
                if fr[5]:
                    reread(unit)
            else:
                open_child("tick", unit, i + 1)
            i += 1
            continue
        if ch == "$":
            k = seq(i, "$((")
            if k >= 0:
                buf.append("$((")
                open_sink("arith", unit, k)
                i = k
                continue
            k = seq(i, "$[")
            if k >= 0:
                # Legacy arithmetic, like $(( )): `<<` in it is a shift, never
                # a heredoc (`$[1<<EOF]` would otherwise hide the next lines).
                buf.append("$[")
                open_sink("barith", unit, k)
                i = k
                continue
            k = seq(i, "$(")
            if k >= 0:
                open_child("cmd", unit, k)
                i = k
                continue
            k = seq(i, "${")
            if k >= 0:
                buf.append("${")
                push("brace", unit, k)
                i = k
                continue
            k = seq(i, "$'") if cls in ("code", "brace", "test") else -1
            if k >= 0:
                value, end = _ansi_c(text, k - 2)
                if value is None:
                    buf.append(text[i:])     # not closed: an open quote, as bash would see it
                    break
                buf.append("'" + value.replace("'", "'\\''") + "'")
                i = end
                continue
            k = seq(i, '$"') if cls in ("code", "test") else -1
            if k >= 0:
                buf.append('"')
                push("dq", unit, k)
                i = k
                continue
            buf.append("$")
            i += 1
            continue
        if ch == '"':
            buf.append('"')
            if kind == "dq":
                stack.pop()
            else:
                push("dq", unit, i + 1)
            i += 1
            continue
        if ch == "'":
            e = text.find("'", i + 1)
            if e < 0:
                buf.append(text[i:])         # not closed: an open quote
                break
            buf.append(text[i:e + 1])
            i = e + 1
            continue
        if kind == "brace":
            if ch == "{":
                fr[2] += 1
            elif fr[2]:
                fr[2] -= 1
            else:
                stack.pop()
            buf.append(ch)
            i += 1
            continue
        if kind == "barith":
            if ch == "[":
                fr[2] += 1
            elif fr[2]:
                fr[2] -= 1
            else:
                stack.pop()
                close_sink(fr, "]")
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if kind == "arith":
            if ch == "(":
                fr[2] += 1
            elif fr[2]:
                fr[2] -= 1
            else:
                stack.pop()
                k = seq(i, "))")
                if k >= 0:
                    close_sink(fr, "))")
                    i = k
                    continue
                # `((a); b)`: a subshell after all; the outer ( is open, and the text is code
                parent = fr[5] or unit
                if fr[5] is not None:
                    parent.buf.extend(buf)
                    parent.children.extend(unit.children)
                    sinks.discard(id(unit))
                stack[-1][2] += 1
                parent.buf.append(ch)
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if kind == "test":                   # ch is "]": the end of `[[ … ]]` is a word `]]`
            k = seq(i, "]]")
            b = before(i)
            if k >= 0 and (k >= n or text[k] in _NET_WORD_BREAK) and b != esc_end and text[b - 1] in " \t\n":
                stack.pop()
                close_sink(fr, " ]]")
                i = k
            else:
                buf.append("]")
                i += 1
            continue
        # code: top, $( ), <( ), >( ), ` `
        if ch == "#":
            if not word_start(i):
                buf.append("#")
                i += 1
            elif kind == "tick":
                # bash finds the closing backtick before it parses the body,
                # so a comment in `…` ends there (R3A2-4).
                c2 = _LEX_TICK_COMMENT.search(text, i)
                while c2 is not None and c2.group()[0] == "\\":
                    c2 = _LEX_TICK_COMMENT.search(text, c2.end())
                i = n if c2 is None else c2.start()
            else:
                e = text.find("\n", i)
                i = n if e < 0 else e
            continue
        if ch == "\n":
            buf.append("\n")
            i += 1
            if len(pending) > fr[6]:
                i = read_heredocs(i, fr[6])
            continue
        if ch == "<":
            k = seq(i, "<<<")
            if k >= 0:
                buf.append("<<<")
                i = k
                continue
            k = seq(i, "<<")
            if k >= 0:
                i = heredoc_open(unit, k)
                continue
            k = seq(i, "<(")
            if k >= 0:
                open_child("proc", unit, k)
                i = k
                continue
            buf.append("<")
            i += 1
            continue
        if ch == ">":
            k = seq(i, ">(")
            if k >= 0:
                open_child("proc", unit, k)
                i = k
            else:
                buf.append(">")
                i += 1
            continue
        if ch == "(":
            k = seq(i, "((")
            if k >= 0 and word_start(i):
                buf.append("((")
                open_sink("arith", unit, k)
                i = k
            else:
                fr[2] += 1
                buf.append("(")
                i += 1
            continue
        if ch == ")":
            if fr[2]:
                fr[2] -= 1
                buf.append(")")
            elif kind in ("cmd", "proc") and not fr[3]:
                stack.pop()
                last_close = i + 1
            else:
                buf.append(")")              # a `case` pattern, or a stray `)`
            i += 1
            continue
        if ch == "[":
            # `[[ … ]]` in command position is a test: nothing in it runs but
            # its substitutions (`[[ $v =~ (a|npm i x) ]]` installs nothing).
            if word_start(i) and (i + 2 >= n or text[i + 2] in " \t\n") and cmd_pos(i):
                buf.append("[[")
                open_sink("test", unit, i + 2)
            else:
                buf.append("[[")
            i += 2
            continue
        # `case` / `esac`: a `)` inside $( case … esac ) is a pattern, not the
        # end. Reserved only in command position: `$(echo case)` closes (R3A2-1).
        word = text[i:i + 4]
        if word_start(i) and (i + 4 >= n or text[i + 4] in _NET_WORD_BREAK):
            if word == "case":
                if cmd_pos(i):
                    fr[3] += 1
            elif fr[3] and cmd_pos(i, _LEX_ESAC_WORDS):
                fr[3] -= 1
        buf.append(word)
        i += 4
    for fr in stack:                         # unterminated arithmetic or [[: its text stays code
        if fr[0] in ("arith", "barith", "test") and fr[5] is not None:
            fr[5].buf.extend(fr[1].buf)
            fr[5].children.extend(fr[1].children)
    for unit in [top] + ctx.subs[first_sub:]:
        if unit.buf:                         # a unit a nested read already joined keeps its code
            unit.code = "".join(unit.buf)
            unit.buf = []
    return top


def _without_heredocs(cmd: str) -> str:
    """Drop heredoc bodies before looking for a program.

    A heredoc carries data -- a JSON payload, a commit message, a file being
    written. Splitting the command on newlines turned each of those lines into
    its own candidate segment, so a bare path inside a document became "the
    program" on 121 real commands. The `cat <<EOF` line itself is kept; only
    the body between it and its terminator is removed. Openers are found by
    the shared lexer, so a `<<` in quotes, a comment or $((…)) opens nothing.
    """
    if "<<" not in cmd:
        return cmd
    text = _lex_prepare(cmd[:MAX_SCAN_HARD])
    ctx = _LexCtx()
    _shell_lex(text, ctx, spans=True)
    if not ctx.spans:
        return text
    out, at = [], 0
    for s, e in ctx.spans:
        out.append(text[at:s])
        at = e
    out.append(text[at:])
    return "".join(out)


_NET_FUNC_DEF = re.compile(r"^\s*(?:function\s+[^\s(){}]+(?:\s*\(\s*\))?|[A-Za-z_][\w.:-]*\s*\(\s*\))")
# `case WORD in` at the start of a segment, and an arm's pattern `x)` / `(x)`.
_NET_CASE_HEAD = re.compile(r"\s*case\s+\S+\s+in(?:\s+|$)")
# A pattern word may quote or escape a blank (`*" "*)`, `'a b')`, `a\ b)`);
# alternatives are joined by `|`. Each alternative of a word starts with a
# different character, so the match is linear.
_NET_CASE_WORD = r"""(?:[^()\s'"\\|]|'[^']*'|"(?:[^"\\]|\\.)*"|\\.)+"""
_NET_CASE_PATTERN = re.compile(r"\s*\(?\s*" + _NET_CASE_WORD + r"(?:\s*\|\s*" + _NET_CASE_WORD + r")*\s*\)",
                               re.S)
# `coproc NAME { …; }` / `coproc NAME ( … )`: NAME names the coprocess, it is not the program.
_NET_COPROC_NAME = re.compile(r"(\s*coproc\s+)[A-Za-z_][A-Za-z0-9_]*(?=\s*[({])")
# Brace expansion (`cu{r,}l`, `https://{a,b}.io`, `h{1..3}`): at most this many
# words from one word; past it the word is unresolved, never guessed.
NET_BRACE_MAX = 16
_NET_BRACE_SEQ = re.compile(r"(-?\d{1,6}|[A-Za-z])\.\.(-?\d{1,6}|[A-Za-z])(?:\.\.(-?\d{1,6}))?")
_NET_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_NET_STDIN_FILES = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})
_NET_SHELL_VALUE_OPTS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})


def _net_display(text: str) -> str:
    """Lexed text fit to show: a substitution placeholder reads `$(…)`, a
    heredoc marker reads `EOF`."""
    if _LEX_PH in text:
        text = _LEX_SUB.sub("$(…)", text)
    if _LEX_HD in text:
        text = _LEX_HEREDOC.sub("EOF", text)
    return text


def _net_shell_operand(prog: str, args: list[str], via_xargs: bool) -> tuple[str, str | None]:
    """How a shell (or source / .) gets its code: ("stdin", None) when it reads
    it from stdin (`bash`, `sh -s -- a`, `bash /dev/stdin`, `source /dev/stdin`,
    `xargs bash -c`), ("script", operand) when it runs a file, ("c", None) for
    a -c string, else ("", None)."""
    if prog in ("source", "."):
        if not args:
            return "", None
        return ("stdin", None) if args[0] in _NET_STDIN_FILES else ("script", args[0])
    if prog not in _NET_SHELLS:
        return "", None
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("--", "-"):
            k += a == "--"
            break
        if a[:1] in ("-", "+") and len(a) > 1:
            if _net_shell_c(a):
                return ("stdin", None) if via_xargs and k == len(args) - 1 else ("c", None)
            if a in _NET_SHELL_VALUE_OPTS:
                k += 2
                continue
            if a[0] == "-" and not a.startswith("--") and "s" in a:
                return "stdin", None         # -s: commands from stdin, the rest are arguments
            k += 1
            continue
        break
    rest = args[k:]
    if not rest or rest[0] in _NET_STDIN_FILES:
        return "stdin", None
    return "script", rest[0]


def _net_segments(cmd: str, depth: int = 0, ctx: "_LexCtx | None" = None
                  ) -> tuple[list[tuple[list[str], bool, bool, str]], int]:
    """Token lists for every simple command in `cmd`, nested ones included
    ($(...), <(...), backticks, bash -lc "...", eval "...", heredocs and
    here-strings fed to a shell, substitutions in an unquoted heredoc), each
    with whether it ran under xargs, whether its output is run by a shell,
    and its text; and how many segments could not be tokenised because a
    quote was left open or a limit (NET_NEST_MAX, NET_TREE_MAX, NET_LEX_BUDGET)
    was reached. A limit also sets ctx.limit, which the caller reports (R10)."""
    if ctx is None:
        ctx = _LexCtx()
        cmd = _lex_prepare(cmd)
    if len(cmd) > ctx.budget:
        ctx.limit = True
        return [], 1
    ctx.budget -= len(cmd)
    unit = _shell_lex(cmd, ctx)
    return _net_unit_segments(unit, depth, 0, ctx)


def _net_brace_expand(word: str) -> list[str] | None:
    """bash brace expansion of one unquoted word, left to right: `cu{r,}l` is
    curl cul, `h{1..3}` is h1 h2 h3. None when it would make more than
    NET_BRACE_MAX words (or the word is too long to read). Each step is one
    linear pass over a word of at most 512 characters."""
    out = [word]
    for _ in range(NET_BRACE_MAX + 1):
        changed, nxt = False, []
        for w in out:
            alts = _net_brace_once(w)
            if alts is None:
                return None
            changed = changed or alts != [w]
            nxt += alts
            if len(nxt) > NET_BRACE_MAX:
                return None
        out = nxt
        if not changed:
            return out
    return None


def _net_brace_once(w: str) -> list[str] | None:
    """The words of the first expandable `{…}` group in w ([w] when none),
    or None when there are too many or w is too long."""
    if len(w) > 512:
        return None
    stack: list[int] = []
    comma: dict[int, bool] = {}
    pairs: list[tuple[int, int]] = []
    for k, c in enumerate(w):
        if c == "{":
            stack.append(-1 if k and w[k - 1] == "$" else k)    # ${…} is a parameter, not a group
            comma[stack[-1]] = False
        elif c == "," and stack:
            comma[stack[-1]] = True
        elif c == "}" and stack:
            p = stack.pop()
            if p >= 0:
                pairs.append((p, k))
    for p, e in sorted(pairs):
        if comma[p]:
            alts, depth, at = [], 0, p + 1
            for k in range(p + 1, e):
                c = w[k]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                elif c == "," and not depth:
                    alts.append(w[at:k])
                    at = k + 1
            alts.append(w[at:e])
        else:
            m = _NET_BRACE_SEQ.fullmatch(w, p + 1, e)
            if not m:
                continue
            a, b, step = m.group(1), m.group(2), abs(int(m.group(3) or 1)) or 1
            if a.isalpha() != b.isalpha():
                continue
            lo, hi = (ord(a), ord(b)) if a.isalpha() else (int(a), int(b))
            if abs(hi - lo) // step + 1 > NET_BRACE_MAX:
                return None
            vals = range(lo, hi + (1 if hi >= lo else -1), step if hi >= lo else -step)
            width = max(len(a), len(b)) if not a.isalpha() and (a.lstrip("-")[:1] == "0" or
                                                              b.lstrip("-")[:1] == "0") else 0
            alts = [chr(v) if a.isalpha() else str(v).zfill(width) for v in vals]
        return [w[:p] + x + w[e + 1:] for x in alts]
    return [w]


_NET_BRACE_STOP = " \t\n;&|()<>"


def _net_braces(toks: list[str], q: str) -> tuple[list[str], bool]:
    """Brace-expand the program word and every URL of one command, when the
    word stands unquoted in the code (`'cu{r,}l'` is literal): (the tokens,
    whether a word was past NET_BRACE_MAX)."""
    st, _ = _net_strip_prefixes(toks)
    prog = len(toks) - len(st) if st else -1
    out: list[str] = []
    over = False
    for k, t in enumerate(toks):
        if "{" in t and (k == prog or "://" in t) and _net_unquoted(t, q):
            got = _net_brace_expand(t)
            if got is None:
                over = True
                out.append(t)
            else:
                out += [g for g in got if g]     # `{npm,}` is npm: an empty word is dropped
        else:
            out.append(t)
    return out, over


def _net_unquoted(word: str, q: str) -> bool:
    """Whether `word` stands as written, as a whole word, in the code q (the
    first few places it occurs), so no quote or escape touched it."""
    at = 0
    for _ in range(8):
        k = q.find(word, at)
        if k < 0:
            return False
        e = k + len(word)
        if (k == 0 or q[k - 1] in _NET_BRACE_STOP) and (e == len(q) or q[e] in _NET_BRACE_STOP):
            return True
        at = k + 1
    return False


_NET_UNIT_SLOW = re.compile(r"[\n;&|<>()'\"\\$`#\ue000\ue001]|case|function|" + _NET_BRACE_HINT)


def _net_unit_segments(unit: _LexUnit, depth: int, nest: int, ctx: _LexCtx
                       ) -> tuple[list[tuple[list[str], bool, bool, str]], int]:
    """_net_segments over one lexed unit: its own commands, the heredocs and
    strings they feed to a shell (re-read at depth + 1), and its substitution
    bodies (already lexed: no re-read). Each unit also adds its commands, as
    dequoted lines, to ctx.lines for the audit."""
    code = unit.code
    if not unit.children and not _NET_UNIT_SLOW.search(code):
        # Plain words, one command (most substitution bodies): nothing to split.
        tokens = code.split()
        if not tokens:
            return [], 0
        st, via = _net_strip_prefixes(tokens)
        first = _net_base(st[0]).lower() if st else ""
        if st and first not in ("eval", "su", "find") and first not in _NET_SHELLS:
            ctx.lines.append((" ".join(tokens), code.strip()))
            if depth == 0 and nest == 0:
                ctx.top = ([(0, "direct")], [code], [""], [])
            return [(st, via, False, code)], 0
        if not st:
            ctx.lines.append((" ".join(tokens), code.strip()))
            return [], 0
    unparsed = 0
    seps: list[str] = []
    amps: list[int] = []
    parts, open_quote = _net_split(code, seps, amps)
    if open_quote:
        parts = parts[:-1]
        unparsed += 1
    top = depth == 0 and nest == 0
    in_case = 0
    raw_tokens: list[list[str]] = []
    stripped: list[tuple[list[str], bool, list[tuple[str, str]]]] = []
    for p in parts:
        q = p
        if in_case or "case" in q:
            m = _NET_CASE_HEAD.match(q)
            if m:
                in_case += 1
                q = q[m.end():]
            if in_case:
                m = _NET_CASE_PATTERN.match(q)
                q = " " + q[m.end():] if m else q
        if "(" in q or "function" in q:
            q = _NET_FUNC_DEF.sub(" ", q, count=1)
        if "coproc" in q:
            m = _NET_COPROC_NAME.match(q)
            q = m.group(1) + q[m.end():] if m else q
        redirs: list[tuple[str, str]] = []
        toks = _net_tokens(q, operators=True, redirs=redirs)
        if "{" in q and toks:
            toks, over = _net_braces(toks, q)
            if over:
                unparsed += 1                # too many words to read: unresolved, not clean (R10)
                ctx.limit = True
        if in_case and "esac" in toks:
            in_case = max(0, in_case - toks.count("esac"))
        raw_tokens.append(toks)
        st, via = _net_strip_prefixes(toks)
        stripped.append((st, via, redirs))
    # The audit's view: each logical line, dequoted, joined back with its operators.
    # (dequoted, as written), the second for evidence.
    line: list[str] = []
    shown: list[str] = []
    for n, toks in enumerate(raw_tokens):
        line.append(" ".join(toks))
        shown.append(parts[n].strip())
        if seps[n] in ("\n", "") or n == len(raw_tokens) - 1:
            text = _net_display(" ".join(x for x in line if x))
            if text:
                ctx.lines.append((text, _net_display(" ".join(x for x in shown if x))))
            line, shown = [], []
        else:
            line.append(seps[n])
            shown.append(seps[n])
    # `curl … | sh`, `| sudo bash`, `| busybox sh`, `| tee f | sh`: a shell at
    # any later stage of the same pipeline, on the dequoted names. Worked
    # backwards once, so a long pipeline stays linear.
    downstream = [False] * (len(stripped) + 1)
    for n in range(len(stripped) - 2, -1, -1):
        if seps[n] == "|":
            nxt = stripped[n + 1][0]
            downstream[n] = downstream[n + 1] or (
                bool(nxt) and _net_base(nxt[0]).lower() in _NET_SHELLS and not _net_shell_c_index(nxt))
    own: list[tuple[list[str], bool, bool, str]] = []
    code_docs: list[int] = []
    data_docs: list[int] = []
    # At the top level only: for each of `own`, the part it came from and how
    # (R3F5): "direct" (the part's own command), "eval" (run by eval, in this
    # shell) or "nested" (a child shell: bash -c, su -c, trap, find -exec).
    own_scope: list[tuple[int, str]] = []
    doc_part: dict[int, int] = {}
    doc_env: dict[int, list[str]] = {}

    def nested(text: str, outer: "list[str] | None" = None, how: str = "nested") -> None:
        nonlocal unparsed
        if depth >= NET_NEST_MAX:
            unparsed += 1                    # nested deeper than we read: say so
            ctx.limit = True
            return
        inner, bad = _net_segments(text, depth + 1, ctx)
        if outer is not None:                # `VAR=x bash -c '…'`: the child inherits VAR
            inner = [(_net_inherit(t, outer), x, f, r) for t, x, f, r in inner]
        own.extend(inner)
        if top:
            own_scope.extend((n, how) for _ in inner)
        unparsed += bad

    for n, (tokens, via_xargs, redirs) in enumerate(stripped):
        part = parts[n]
        marks = [int(h) for h in _LEX_HEREDOC.findall(part)
                 if int(h) < len(ctx.heredocs)] if _LEX_HD in part else []
        if top:
            for h in marks:
                doc_part[h] = n
        if downstream[n] and _LEX_PH in part:
            for g in _LEX_SUB.findall(part):     # `echo "$(curl …)" | sh`
                if int(g) < len(ctx.feeds):
                    ctx.feeds[int(g)] = True
        if not tokens:
            data_docs += marks
            continue
        # `eval eval … CMD` is `eval CMD`: one level, however many words.
        evals = 0
        outer = tokens
        while tokens and _net_base(tokens[0]).lower() == "eval":
            tokens, evals = tokens[1:], evals + 1
        if evals:
            if tokens:
                nested(" ".join(tokens), outer, "eval")
            data_docs += marks
            continue
        head = _LEX_SUB.fullmatch(tokens[0])
        if head and int(head.group(1)) < len(ctx.feeds):
            ctx.feeds[int(head.group(1))] = True     # `$(curl …)` as a command: its output runs
        prog = _net_base(tokens[0]).lower()
        if prog == "su":
            k = next((k for k in range(1, len(tokens) - 1) if tokens[k] in ("-c", "--command")), 0)
            if k:
                nested(tokens[k + 1])
                data_docs += marks
                continue
        if prog == "find":
            k = 1
            while k < len(tokens):
                if tokens[k] in _NET_FIND_EXEC:
                    e = next((e for e in range(k + 1, len(tokens)) if tokens[e] in (";", "+")), len(tokens))
                    sub, x = _net_strip_prefixes(tokens[k + 1:e])
                    if sub:
                        own.append((sub, x, False, _net_display(part)))
                        if top:
                            own_scope.append((n, "nested"))
                    k = e
                k += 1
        mode, operand = _net_shell_operand(prog, tokens[1:], via_xargs)
        if mode == "script" and operand is not None:
            sub = _LEX_SUB.fullmatch(operand)
            if sub and int(sub.group(1)) < len(ctx.kinds) and ctx.kinds[int(sub.group(1))] == "proc":
                ctx.feeds[int(sub.group(1))] = True  # `bash <(curl …)`, `source <(curl …)`
        if mode == "stdin":
            for op, target in redirs:
                sub = _LEX_SUB.fullmatch(target) if op == "<" else None
                if sub and int(sub.group(1)) < len(ctx.feeds):
                    ctx.feeds[int(sub.group(1))] = True  # `bash < <(curl …)`
        (code_docs if mode == "stdin" or downstream[n] else data_docs).extend(marks)
        if mode == "stdin":
            for h in marks:
                doc_env[h] = tokens          # `VAR=x bash <<EOF`: the body inherits VAR
        if mode == "stdin" or downstream[n]:
            for op, target in redirs:
                if op == "<<<" and target:
                    # `bash <<< "…"`, `cat <<< "…" | sh`: the word is the script
                    nested(target, tokens if mode == "stdin" else None)
        if prog == "trap":
            # `trap 'CMD' SIG…`: bash runs CMD when the signal comes. One
            # operand, `-`, `-p` or `-l` resets or lists: no command.
            args = tokens[2:] if tokens[1:2] == ["--"] else tokens[1:]
            if len(args) >= 2 and not args[0].startswith("-"):
                nested(args[0])
        flag = _net_shell_c_index(tokens) if prog in _NET_SHELLS else 0
        if flag:
            nested(tokens[flag + 1], tokens)
            continue
        own.append((tokens, via_xargs, downstream[n], _net_display(part)))
        if top:
            own_scope.append((n, "direct"))
    pre: list[tuple[list[str], bool, bool, str]] = []
    pre_scope: list[tuple[int | None, str]] = []
    for h in code_docs:                      # `bash <<EOF … EOF`, `cat <<EOF | sh`: the body is code
        body = ctx.heredocs[h][0]
        if body is None:
            continue                         # unterminated: its lines were read as commands
        if depth >= NET_NEST_MAX:
            unparsed += 1
            ctx.limit = True
            continue
        inner, bad = _net_segments(body, depth + 1, ctx)
        if h in doc_env:
            inner = [(_net_inherit(t, doc_env[h]), x, f, r) for t, x, f, r in inner]
        pre += inner
        if top:
            pre_scope += [(doc_part.get(h), "nested")] * len(inner)
        unparsed += bad
    kids = list(unit.children)
    for h in data_docs:                      # an unquoted data heredoc still runs its $(…) and `…`
        body, quoted = ctx.heredocs[h][0], ctx.heredocs[h][1]
        if body is None or quoted or ("$" not in body and "`" not in body):
            continue
        if len(body) > ctx.budget:
            unparsed += 1
            ctx.limit = True
            continue
        ctx.budget -= len(body)
        kids += _shell_lex(body, ctx, mode="hd").children
    sub_part: dict[int, int] = {}
    if top and kids:
        for k, p in enumerate(parts):
            if _LEX_PH in p:
                for g in _LEX_SUB.findall(p):
                    sub_part.setdefault(int(g), k)
    for g in kids:
        if nest >= NET_TREE_MAX:
            unparsed += 1
            ctx.limit = True
            continue
        inner, bad = _net_unit_segments(ctx.subs[g], depth, nest + 1, ctx)
        # `sh -c "$(curl …)"`, `bash <(curl …)`, `eval "$(curl …)"`: what the body prints is run.
        pre += [(t, x, True, r) for t, x, _, r in inner] if ctx.feeds[g] else inner
        if top:
            pre_scope += [(sub_part.get(g), "nested")] * len(inner)
        unparsed += bad
    if top:
        ctx.top = (pre_scope + own_scope, parts, seps, amps)
    return pre + own, unparsed


# The last command walked, for the audit and the inventory, which both read
# every command (R12): one lexing pass serves both.
_WALK_CACHE: list = [None, None]


def _shell_walk(cmd: str) -> tuple[list[tuple[list[str], bool, bool, str]], int, bool, list[str], tuple]:
    """(segments, unparsed, limit reached, the audit's dequoted lines, the top
    level's scope: see _LexCtx.top) for one command already cut to MAX_SCAN_HARD."""
    if _WALK_CACHE[0] is not None and _WALK_CACHE[0] == cmd:
        return _WALK_CACHE[1]
    ctx = _LexCtx()
    segments, unparsed = _net_segments(_lex_prepare(cmd), 0, ctx)
    result = (segments, unparsed, ctx.limit, ctx.lines, ctx.top)
    _WALK_CACHE[0], _WALK_CACHE[1] = cmd, result
    return result


# Every option that takes a value, from `curl --help all` (8.x, plus the newer
# --ech, --ip-tos, --knownhosts, --sigalgs, --ssl-sessions, --upload-flags,
# --vlan-priority) and GNU `wget --help` (1.21). A value option missing here
# leaks its argument as a positional, and `name.tld` reads as a host.
_CURL_VALUE = frozenset(
    "-o --output -H --header -d --data --data-raw --data-binary --data-urlencode -X --request "
    "-u --user -A --user-agent -e --referer -b --cookie -c --cookie-jar -F --form -T --upload-file "
    "-w --write-out -m --max-time --connect-timeout -x --proxy --retry -r --range --cacert --cert "
    "--key -K --config --resolve --url -E -D --dump-header --trace --trace-ascii --stderr --json "
    "--limit-rate --max-filesize --interface --netrc-file --capath --unix-socket --proto "
    "--proto-redir --variable -Y --speed-limit -y --speed-time "
    "--abstract-unix-socket --alt-svc --aws-sigv4 --cert-type --ciphers --connect-to -C --continue-at "
    "--create-file-mode --crlfile --curves --data-ascii --delegation --dns-interface --dns-ipv4-addr "
    "--dns-ipv6-addr --dns-servers --doh-url --ech --egd-file --engine --etag-compare --etag-save "
    "--expect100-timeout --form-string --ftp-account --ftp-alternative-to-user --ftp-method -P "
    "--ftp-port --ftp-ssl-ccc-mode --happy-eyeballs-timeout-ms --haproxy-clientip -h --help "
    "--hostpubmd5 --hostpubsha256 --hsts --ip-tos --ipfs-gateway --keepalive-time --key-type "
    "--knownhosts --krb --libcurl --local-port --login-options --mail-auth --mail-from --mail-rcpt "
    "--max-redirs --noproxy --oauth2-bearer --output-dir --parallel-max --pass --pinnedpubkey "
    "--preproxy --proto-default --proxy-cacert --proxy-capath --proxy-cert --proxy-cert-type "
    "--proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass "
    "--proxy-pinnedpubkey --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype "
    "--proxy-tlspassword --proxy-tlsuser -U --proxy-user --proxy1.0 --pubkey -Q --quote "
    "--random-file --rate --request-target --retry-delay --retry-max-time --sasl-authzid "
    "--service-name --sigalgs --socks4 --socks4a --socks5 --socks5-gssapi-service --socks5-hostname "
    "--ssl-sessions -t --telnet-option --tftp-blksize -z --time-cond --tls-max --tls13-ciphers "
    "--tlsauthtype --tlspassword --tlsuser --trace-config --upload-flags --url-query "
    "--vlan-priority".split())
_WGET_VALUE = frozenset("-O --output-document -P --directory-prefix -o --output-file -U --user-agent "
                        "--header -t --tries -T --timeout -e --execute -i --input-file "
                        "-a --append-output --config "
                        "-B --base --rejected-log --report-speed --input-metalink --metalink-index "
                        "--preferred-location --retry-on-http-error --dns-timeout --connect-timeout "
                        "--read-timeout -w --wait --waitretry -Q --quota --bind-address "
                        "--bind-dns-address --dns-servers --limit-rate --user --password "
                        "--use-askpass --prefer-family --progress --local-encoding --remote-encoding "
                        "--restrict-file-names --compression --start-pos --backups --ftp-user "
                        "--ftp-password --http-user --http-password --proxy-user --proxy-password "
                        "--max-redirect --referer --save-cookies --load-cookies --post-data "
                        "--post-file --method --body-data --body-file --default-page --hsts-file "
                        "--secure-protocol --certificate --certificate-type --private-key "
                        "--private-key-type --ca-certificate --ca-directory --crl-file "
                        "--pinnedpubkey --random-file --egd-file --ciphers --warc-file "
                        "--warc-header --warc-max-size --warc-dedup --warc-tempdir --cut-dirs "
                        "-l --level -A --accept -R --reject --accept-regex --reject-regex "
                        "--regex-type -D --domains --exclude-domains --follow-tags --ignore-tags "
                        "-I --include-directories -X --exclude-directories".split())
_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree"})
# `git clone -h` (2.47): every option that takes a value as the next word.
_GIT_CLONE_VALUE = frozenset("--depth -b --branch -o --origin --reference --filter -c --config "
                             "-j --jobs --template --separate-git-dir --shallow-since --shallow-exclude "
                             "--reference-if-able --server-option --bundle-uri -u --upload-pack "
                             "--revision --ref-format".split())
_GIT_SUBMODULE_ADD_VALUE = frozenset({"-b", "--branch", "--name", "--reference", "--depth"})
_GIT_LS_REMOTE_VALUE = frozenset({"--upload-pack", "-o", "--server-option", "--sort"})
_GH_DOWNLOAD_VALUE = frozenset({"-R", "--repo", "-p", "--pattern", "-D", "--dir", "-O", "--output",
                                "-A", "--archive"})
# Options of npm, pnpm, yarn and bun that take a value, before or after the
# subcommand. `-w`/`--workspace` take one only for npm: for pnpm `-w` is
# --workspace-root, a flag (R3B5), so they are in _NPM_PROG_VALUE.
_NPM_VALUE = frozenset("--registry --prefix --tag --cache -C --dir --filter -F "
                       "--omit --include --install-strategy --before --userconfig --globalconfig "
                       "--loglevel --cwd --location --otp --fetch-retries --fetch-timeout "
                       "--network-concurrency --network-timeout --modules-folder --cache-folder "
                       "--global-folder --link-folder --mutex --use-yarnrc --proxy --https-proxy "
                       "--save-prefix --workspace-concurrency --reporter --store-dir --virtual-store-dir "
                       "--lockfile-dir --config-dir --cache-dir --global-dir --backend".split())
_NPM_PROG_VALUE = {"npm": _NPM_VALUE | {"-w", "--workspace"}}
# Every subcommand of npm, pnpm, yarn and bun that is not an install: when the
# first word is none of these and not an install, a value option this table
# lacks has eaten the subcommand's place, and the install is read from the
# first install word after it (R3B6).
_NPM_COMMANDS = frozenset("run run-script test t start stop restart exec x ci ls list ll la view v info show "
                          "publish pack link ln uninstall remove rm r un unlink update up upgrade outdated "
                          "audit config c set get version init create cache why explain dedupe ddp prune "
                          "rebuild rb login logout adduser whoami owner dist-tag search s find help doctor "
                          "fund diff query pkg root bin prefix edit explore completion shrinkwrap star "
                          "unstar stars team token access hook org profile deprecate unpublish sbom dlx "
                          "workspace workspaces global store env import patch patch-commit setup node "
                          "licenses recursive outdated bunx pm build".split())
_NPM_INSTALL = {"npm": {"i", "install", "add"}, "pnpm": {"add", "install", "i"},
                "yarn": {"add", "install"}, "bun": {"add", "install", "i"}}
_NPX_VALUE = frozenset({"-p", "--package", "--registry", "-c", "--call", "-w", "--workspace"})
# pip's general options (`pip --help`) and `pip install --help`, plus uv's
# `--index`/`--default-index`, which `uv pip install` and `uv add` take.
_PIP_VALUE = frozenset("-r --requirement -c --constraint -i --index-url --extra-index-url -t --target "
                       "--prefix --root -e --editable -f --find-links --python -p --platform "
                       "--proxy --retries --timeout --log --log-file --cache-dir --cert --client-cert "
                       "--exists-action --trusted-host --src --progress-bar --keyring-provider "
                       "--upgrade-strategy --global-option --config-settings -C --no-binary --only-binary "
                       "--implementation --python-version --abi --report --root-user-action --use-feature "
                       "--use-deprecated --resume-retries --group --index --default-index".split())
_PIP_COMMANDS = frozenset("download uninstall freeze inspect list show check config search cache index "
                          "wheel hash completion debug help lock".split())
# `uv --help`: global options that take a value, before the subcommand.
_UV_GLOBAL_VALUE = frozenset("--directory --project --cache-dir --config-file --color -p --python "
                             "--python-preference --allow-insecure-host".split())
_UVX_VALUE = frozenset({"--from", "--with", "-w", "--with-requirements", "--with-editable", "-p", "--python",
                        "--index-url", "-i", "--index", "--default-index", "--extra-index-url",
                        "--python-preference", "--directory", "--project", "--cache-dir", "--config-file",
                        "--color"})
_CARGO_VALUE = frozenset({"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path",
                          "--registry", "--index", "-F", "--features", "--root",
                          "--color", "--config", "-Z", "--manifest-path", "--target-dir", "--target",
                          "-j", "--jobs", "--profile", "--bin", "--example", "--message-format",
                          "--lockfile-path"})
_GO_VALUE = frozenset({"-C", "-modfile", "-tags", "-ldflags", "-o"})
# `docker run|create --help` (and podman's extras): every option that takes a value.
_DOCKER_VALUE = frozenset("-v --volume -e --env -p --publish --name -w --workdir --network --entrypoint "
                          "-u --user --platform --env-file -l --label --mount -h --hostname --add-host "
                          "--cpus -m --memory --restart --pull --log-driver --gpus "
                          "-a --attach --annotation --blkio-weight --blkio-weight-device --cap-add "
                          "--cap-drop --cgroup-parent --cgroupns --cidfile --cpu-period --cpu-quota "
                          "--cpu-rt-period --cpu-rt-runtime -c --cpu-shares --cpuset-cpus --cpuset-mems "
                          "--device --device-cgroup-rule --device-read-bps --device-read-iops "
                          "--device-write-bps --device-write-iops --dns --dns-option --dns-opt "
                          "--dns-search --domainname --expose --group-add --health-cmd "
                          "--health-interval --health-retries --health-start-period "
                          "--health-start-interval --health-timeout --ip --ip6 --ipc --isolation "
                          "--kernel-memory --label-file --link --link-local-ip --log-opt --mac-address "
                          "--memory-reservation --memory-swap --memory-swappiness --net --network-alias "
                          "--net-alias --oom-score-adj --pid --pids-limit --runtime --security-opt "
                          "--shm-size --stop-signal --stop-timeout --storage-opt --sysctl --tmpfs "
                          "--ulimit --userns --uts --volume-driver --volumes-from --detach-keys "
                          "--pod --arch --os --variant --authfile --creds --cert-dir --secret --uidmap "
                          "--gidmap --tz --umask --unsetenv --cgroups --pidfile --timeout --retry "
                          "--retry-delay --decryption-key --personality --init-path --seccomp-policy "
                          "--sdnotify --requires --preserve-fds --hosts-file --subuidname --subgidname "
                          "--chrootdirs --conmon-pidfile --env-merge --group-entry --passwd-entry "
                          "--rdt-class --pod-id-file --image-volume "
                          "--pids-limit --variant --cpu-rt-period --label-file --health-on-failure "
                          "--health-log-destination --health-max-log-count --health-max-log-size "
                          "--health-startup-cmd --health-startup-interval --health-startup-retries "
                          "--health-startup-success --health-startup-timeout --uts --userns".split())
# `docker pull`: -a is --all-tags there, which takes nothing.
_DOCKER_PULL_VALUE = frozenset("--platform --arch --os --variant --authfile --creds --cert-dir "
                               "--decryption-key --retry --retry-delay".split())
# Global options, before the subcommand: `docker --context x run …`, `docker -H h pull …`.
_DOCKER_GLOBAL_VALUE = frozenset("-c --context -H --host --config -l --log-level --tlscacert --tlscert "
                                 "--tlskey --connection --url --identity --root --runroot "
                                 "--storage-driver --storage-opt --cgroup-manager --events-backend "
                                 "--hooks-dir --imagestore --module --network-cmd-path "
                                 "--network-config-dir --runtime --tmpdir --volumepath --ssh".split())
_NET_PEP508_URL = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*@\s*(\S+://\S*)$")
_PIP_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^,;\s]*)")


# curl and wget read a positional with no scheme as http: `curl evil.example/x`.
# An optional `user@` first: `u@evil.example/x` is fetched from evil.example.
_NET_BARE_HOST = re.compile(r"^(?:[^@/\s]+@)?(?:(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\.?|localhost)"
                            r"(?::\d+)?(?:[/?#]|$)")
# An address with no scheme (R3B2): a numeric IPv4 in any inet_aton form, or a
# bracketed IPv6. A single number counts only with a port or path after it
# (`101058054/x`), so a stray count is not read as a host.
_NET_BARE_IP = re.compile(r"^(?:[^@/\s]+@)?(\[[0-9A-Fa-f:.]+\]|[0-9][0-9A-Fa-fxX]*(?:\.[0-9A-Fa-fxX]+){0,3}\.?)"
                          r"(:\d*)?([/?#]|$)")


def _net_bare_ip(a: str) -> bool:
    m = _NET_BARE_IP.match(a)
    if not m:
        return False
    host = m.group(1)
    if not host.startswith("[") and "." not in host and not (m.group(2) or m.group(3)):
        return False
    return _host_canon(host) is not None


def _net_is_url_arg(a: str) -> bool:
    return "://" in a or "$" in a or "`" in a or bool(_NET_BARE_HOST.match(a)) or _net_bare_ip(a)


# Brace expansion (`{a,b}`, `{1..3}`, `{a..c}`) and curl's URL globs (`[a-z]`,
# `[1-9:2]`): a word that names several hosts or packages is read as each one
# (R3B3). Bounded: past NET_EXPAND_MAX words, or NET_EXPAND_MAX * 4 steps, the
# word is not expanded and the item is reported unresolved (R10), as is a group
# in a word longer than NET_EXPAND_CHARS.
NET_EXPAND_MAX = 64
NET_EXPAND_CHARS = 4096                      # a longer word is not expanded: unresolved if it would be
_NET_SEQ = re.compile(r"(-?\d{1,9})\.\.(-?\d{1,9})(?:\.\.(-?\d{1,9}))?|([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d{1,9}))?")
_NET_CURL_RANGE = re.compile(r"(?:(\d{1,9})-(\d{1,9})|([a-z])-([a-z])|([A-Z])-([A-Z]))(?::(\d{1,9}))?")


def _net_seq(body: str, curl_range: bool = False) -> "list[str] | None | bool":
    """The words of a sequence `1..5`, `a..e`, `01..10..3` (or, for curl, a
    range `1-5`, `a-e`, `1-9:2`); None when body is not one; False when it
    names more than NET_EXPAND_MAX words."""
    m = (_NET_CURL_RANGE if curl_range else _NET_SEQ).fullmatch(body)
    if not m:
        return None
    g = m.groups()
    step = abs(int(g[-1])) if g[-1] else 1
    step = step or 1
    if g[0] is not None:
        lo, hi = int(g[0]), int(g[1])
        width = max(len(g[0]), len(g[1])) if (g[0].lstrip("-")[:1] == "0" and len(g[0].lstrip("-")) > 1) \
            or (g[1].lstrip("-")[:1] == "0" and len(g[1].lstrip("-")) > 1) else 0
        if abs(hi - lo) // step + 1 > NET_EXPAND_MAX:
            return False
        rng = range(lo, hi + 1, step) if hi >= lo else range(lo, hi - 1, -step)
        return [str(n).zfill(width) for n in rng]
    a, b = (g[2], g[3]) if g[2] is not None else (g[4], g[5]) if curl_range else (g[3], g[4])
    lo, hi = ord(a), ord(b)
    if abs(hi - lo) // step + 1 > NET_EXPAND_MAX:
        return False
    rng = range(lo, hi + 1, step) if hi >= lo else range(lo, hi - 1, -step)
    return [chr(n) for n in rng]


def _net_group(word: str, curl: bool) -> "tuple[int, int, list[str]] | None | bool":
    """The first group in word that expands, as (start, end, alternatives);
    None when there is none; False when it names too many words. One pass
    over the word (matching braces found with a stack)."""
    stack: list[int] = []
    close: dict[int, int] = {}
    commas: dict[int, list[int]] = {}
    for j, ch in enumerate(word):
        if ch == "{" and not (j and word[j - 1] == "$"):
            stack.append(j)
        elif ch == "}" and stack:
            close[stack.pop()] = j
        elif ch == "," and stack:
            commas.setdefault(stack[-1], []).append(j)
    cands = sorted(close)
    if curl:
        k = 0
        while True:
            k = word.find("[", k)
            if k < 0:
                break
            e = word.find("]", k)
            if e < 0:
                break
            close[k] = e
            cands.append(k)
            k = e
        cands.sort()
    for i in cands:
        j = close[i]
        if word[i] == "[":
            alts = _net_seq(word[i + 1:j], curl_range=True)
            if alts is False:
                return False
            if alts:
                return i, j + 1, alts
            continue
        if i in commas:
            cuts = [i] + commas[i] + [j]
            return i, j + 1, [word[a + 1:b] for a, b in zip(cuts, cuts[1:])]
        alts = _net_seq(word[i + 1:j])
        if alts is False:
            return False
        if alts:
            return i, j + 1, alts
    return None


def _net_expand(word: str, curl: bool = False) -> list[str] | None:
    """The words bash brace expansion (and, with curl, curl's URL globbing)
    makes of `word`, in order; [word] when nothing expands; None when the
    result would pass NET_EXPAND_MAX words."""
    if "{" not in word and not (curl and "[" in word):
        return [word]
    if len(word) > NET_EXPAND_CHARS:
        return [word] if _net_group(word, curl) is None else None
    done: list[str] = []
    todo = [word]
    steps = 0
    while todo:
        w = todo.pop(0)
        steps += 1
        if steps > 4 * NET_EXPAND_MAX:
            return None
        g = _net_group(w, curl)
        if g is False:
            return None
        if g is None:
            done.append(w)
            continue
        a, b, alts = g
        if len(done) + len(todo) + len(alts) > NET_EXPAND_MAX:
            return None
        todo = [w[:a] + x + w[b:] for x in alts] + todo
    return done


def _net_expand_items(items: list[dict]) -> list[dict]:
    """Each item whose url or package holds a brace group, once per word it
    expands to (R3B3). A word past the cap leaves the item unresolved."""
    out: list[dict] = []
    for item in items:
        group = [item]
        for key in ("url", "package"):
            nxt: list[dict] = []
            for it in group:
                v = it.get(key)
                words = _net_expand(v) if isinstance(v, str) and "{" in v else [v]
                if words is None:
                    it = dict(it, dynamic=True, _unresolved="unreadable")
                    nxt.append(it)
                    continue
                if words == [v]:
                    nxt.append(it)
                    continue
                for w in words:
                    c = dict(it)
                    c[key] = w
                    if key == "url" and (it.get("host") is None or it.get("host") == url_host(v)):
                        host, unresolved = _url_host_parts(w)
                        c["host"] = host
                        c.pop("_unresolved", None)
                        if unresolved:
                            c["dynamic"], c["_unresolved"] = True, "host-unresolved"
                    nxt.append(c)
            group = nxt
        out += group
    return out


def _net_fetch_item(program: str, url: str, dest: str | None) -> dict:
    """A curl or wget item; a URL with no scheme is the http one it fetches."""
    if "://" not in url and not re.match(r"[^/?#]*[$`]", url):    # a literal host
        url = "http://" + url
    return _net_url_item("fetch", program, url, dest=dest)


def _net_curl(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _CURL_VALUE)
    # Every --url counts: curl fetches each (R3B8).
    urls = [u for u in pos if _net_is_url_arg(u)] + _net_opt_values(args, frozenset({"--url"}), _CURL_VALUE)
    dest = opts.get("-o") or opts.get("--output") or (
        "(remote name)" if "-O" in opts or "--remote-name" in opts else None)
    if not urls and ("-K" in opts or "--config" in opts):
        return [_net_item("fetch", "curl", dynamic=True)]    # the URLs are in the config file
    globs = "-g" not in opts and "--globoff" not in opts
    out: list[dict] = []
    for u in urls:
        words = _net_expand(u, curl=globs)
        if words is None:                    # more URLs than are read: unresolved (R10)
            out.append(dict(_net_fetch_item("curl", u, dest), host=None, dynamic=True, _unresolved="unreadable"))
            continue
        out += [_net_fetch_item("curl", w, dest) for w in words]
    return out


def _net_wget(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _WGET_VALUE)
    dest = (opts.get("-O") or opts.get("--output-document") or opts.get("-P")
            or opts.get("--directory-prefix"))
    out = [_net_fetch_item("wget", u, dest) for u in pos if _net_is_url_arg(u)]
    listed = opts.get("-i") if "-i" in opts else opts.get("--input-file")
    if listed is not None:                   # `-i FILE`: the URLs are in the file, as with xargs
        if "://" in listed:                  # `-i URL` fetches the list itself first
            out.append(_net_fetch_item("wget", listed, None))
        out.append(_net_item("fetch", "wget", dynamic=True))
    return out


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


def _net_git_repo_index(pos: list[str]) -> int:
    """Which positional of `git clone` (or `submodule add`) is the repository:
    the first URL or scp remote, else the first (R3B9). A value option missing
    from the table then cannot make its value the repository."""
    return next((k for k, p in enumerate(pos) if _NET_URL.match(p) or _NET_SCP.match(p)), 0)


_GIT_CONFIG_VALUE = frozenset({"-f", "--file", "--blob", "--type", "--default", "--comment", "--value"})
_GIT_REMOTE_URL_KEY = re.compile(r"(?i:remote)\.(.+)\.(?i:url)")


def _net_git_remotes(args: list[str], remotes: dict[str, str]) -> None:
    """Track, in order, the URL each remote name stands for in this session:
    `git remote add|set-url NAME URL`, `git config remote.NAME.url URL`, and
    the `origin` a `git clone URL` makes."""
    sub, rest = _net_git_sub(args)
    if sub == "clone":
        pos, opts = _net_positionals(rest, _GIT_CLONE_VALUE)
        name = opts.get("-o") or opts.get("--origin") or "origin"
        if pos and (len(remotes) < NET_REMOTES_CAP or name in remotes):
            remotes[name] = pos[_net_git_repo_index(pos)]
    elif sub == "config":
        pos, _ = _net_positionals(rest, _GIT_CONFIG_VALUE)
        if pos[:1] in (["set"], ["add"]):    # `git config set KEY VALUE` (git 2.46)
            pos = pos[1:]
        m = _GIT_REMOTE_URL_KEY.fullmatch(pos[0]) if len(pos) >= 2 else None
        if m and (len(remotes) < NET_REMOTES_CAP or m.group(1) in remotes):
            remotes[m.group(1)] = pos[1]
    elif sub == "remote" and rest[:1] in (["add"], ["set-url"]):
        # -t BRANCH and -m MASTER take a value; -f, --tags, --no-tags, --mirror=… do not.
        pos, _ = _net_positionals(rest[1:], _GIT_REMOTE_ADD_VALUE)
        if len(pos) >= 2 and (len(remotes) < NET_REMOTES_CAP or pos[0] in remotes):
            remotes[pos[0]] = pos[1]


def _net_git_remote_name(args: list[str]) -> str | None:
    """The remote a fetch, pull or dry-run push names (`origin` when none is
    given), or None for any other command or when a URL is given directly."""
    sub, rest = _net_git_sub(args)
    if sub not in ("fetch", "pull", "push", "ls-remote"):
        return None
    pos, _ = _net_positionals(rest, _GIT_LS_REMOTE_VALUE if sub == "ls-remote"
                              else frozenset({"--depth", "-j", "--jobs"}))
    if not pos:
        return "origin"
    return None if _NET_URL.match(pos[0]) or url_host(pos[0]) else pos[0]


def _net_git_config(args: list[str], env: dict | None = None) -> list[tuple[str, str]]:
    """(key, value) of the configuration a git command line sets for itself:
    `git -c K=V`, `git clone -c|--config K=V`, and GIT_CONFIG_COUNT /
    GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n or GIT_CONFIG_PARAMETERS assigned
    before it. These can rewrite the URL (url.*.insteadOf) or proxy it (R3B11)."""
    vals: list[str] = []
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-c" and i + 1 < len(args):
            vals.append(args[i + 1])
        i += 2 if args[i] in _GIT_GLOBAL_VALUE else 1
    if i < len(args) and args[i] == "clone":
        vals += _net_opt_values(args[i + 1:], frozenset({"-c", "--config"}), _GIT_CLONE_VALUE)
    out = [(k, v) for k, _, v in (x.partition("=") for x in vals)]
    env = env or {}
    count = env.get("GIT_CONFIG_COUNT", "")
    if count.isdigit():
        for n in range(min(int(count), 64)):
            k = env.get(f"GIT_CONFIG_KEY_{n}")
            if k:
                out.append((k, env.get(f"GIT_CONFIG_VALUE_{n}", "")))
    out += re.findall(r"'([^']*)'='([^']*)'", env.get("GIT_CONFIG_PARAMETERS", ""))
    # `git config --global url.X.insteadOf Y` earlier in the same command (R3F7).
    out += re.findall(r"'([^']*)'='([^']*)'", env.get(_NET_GIT_WRITTEN, ""))
    return out


def _net_git_rewrite(items: list[dict], config: list[tuple[str, str]]) -> list[dict]:
    """Apply `url.<base>.insteadOf=<prefix>`: the longest prefix wins, as in git,
    so the item names the host git really contacts (R3B11)."""
    rules = [(v, k[4:-len(".insteadof")]) for k, v in config
             if k.lower().startswith("url.") and k.lower().endswith(".insteadof") and v]
    if not rules:
        return items
    out = []
    for it in items:
        url = it.get("url")
        best = max((r for r in rules if isinstance(url, str) and url.startswith(r[0])),
                   key=lambda r: len(r[0]), default=None)
        if best is None:
            out.append(it)
            continue
        new = _net_url_item(it["kind"], it["program"], best[1] + url[len(best[0]):], dest=it.get("dest"))
        out.append(new)
    return out


def _net_git(args: list[str], env: dict | None = None) -> list[dict]:
    items = _net_git_items(args)
    return _net_git_rewrite(items, _net_git_config(args, env)) if items else items


def _net_git_items(args: list[str]) -> list[dict]:
    sub, rest = _net_git_sub(args)
    if not sub:
        return []
    if sub == "clone":
        pos, _ = _net_positionals(rest, _GIT_CLONE_VALUE)
        if not pos:
            return []
        k = _net_git_repo_index(pos)
        return [_net_url_item("clone", "git", pos[k], dest=pos[k + 1] if len(pos) > k + 1 else None)]
    if sub == "submodule" and rest[:1] == ["add"]:     # clones the repository (R3B9)
        pos, _ = _net_positionals(rest[1:], _GIT_SUBMODULE_ADD_VALUE)
        if not pos:
            return []
        k = _net_git_repo_index(pos)
        return [_net_url_item("clone", "git", pos[k], dest=pos[k + 1] if len(pos) > k + 1 else None)]
    if sub == "ls-remote":                   # contacts the remote
        pos, _ = _net_positionals(rest, _GIT_LS_REMOTE_VALUE)
        if pos and (_NET_URL.match(pos[0]) or _NET_SCP.match(pos[0])):
            return [_net_url_item("clone", "git", pos[0])]
        return [_net_item("clone", "git")]
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


def _net_gh_url(repo: str, host: str) -> str:
    """The URL gh fetches for a repository argument: a URL or scp remote as
    written; `HOST/OWNER/REPO` (GitHub Enterprise) on HOST; `OWNER/REPO` on
    GH_HOST or github.com (R3B10)."""
    if "://" in repo or _NET_SCP.match(repo):
        return repo
    parts = repo.split("/")
    if len(parts) >= 3 and "." in parts[0]:
        return f"https://{repo}"
    return f"https://{host}/{repo}"


def _net_gh(args: list[str], env: dict | None = None) -> list[dict]:
    host = (env or {}).get("GH_HOST") or "github.com"
    if args[:2] == ["repo", "clone"] and len(args) > 2:
        return [_net_url_item("clone", "gh", _net_gh_url(args[2], host))]
    if args[:2] == ["release", "download"]:
        _, opts = _net_positionals(args[2:], _GH_DOWNLOAD_VALUE)
        dest = opts.get("-D") or opts.get("--dir") or opts.get("-O") or opts.get("--output")
        repo = opts.get("-R") or opts.get("--repo")
        if repo:
            return [_net_url_item("fetch", "gh", _net_gh_url(repo, host), dest=dest)]
        if host != "github.com":
            return [dict(_net_url_item("fetch", "gh", f"https://{host}/"), url=None, dest=dest)]
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
    if not spec.startswith("@") and "/" in spec and "@" not in spec and ":" not in spec:
        # `npm i owner/repo[#ref]` installs from github.com/owner/repo (R3B10).
        repo = spec.split("#", 1)[0]
        return _net_item("install", program, ecosystem="npm", host="github.com", package=spec,
                         url=f"https://github.com/{repo}", exec=exec_)
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


def _net_npm_create(prog: str, sub: str, spec: str, registry: str | None) -> dict | None:
    """`npm init x`, `npm create x`, `yarn|pnpm|bun create x`: downloads and runs
    the initializer `create-x` (`@s` -> `@s/create`, `@s/x` -> `@s/create-x`)."""
    if spec.startswith(("-", ".", "/", "~")) or ":" in spec:
        return None
    at = spec.find("@", 1)
    name, version = (spec, None) if at < 0 else (spec[:at], spec[at + 1:] or None)
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        name = f"{scope}/create-{rest}" if rest else f"{scope}/create"
    elif name.startswith("create-"):
        pass
    else:
        name = "create-" + name
    return _net_registry_item(f"{prog} {sub}", "npm", name, version, registry, exec_=True)


def _net_npm(prog: str, args: list[str], env_registry: str | None = None) -> list[dict]:
    pos, opts = _net_positionals(args, _NPM_PROG_VALUE.get(prog, _NPM_VALUE))
    if pos and pos[0] not in _NPM_INSTALL[prog] and pos[0] not in _NPM_COMMANDS:
        # An unknown first word: a value option we do not know ate the
        # subcommand's place. Read from the first install word (R3B6).
        k = next((k for k in range(1, len(pos)) if pos[k] in _NPM_INSTALL[prog]), 0)
        pos = pos[k:] if k else pos
    registry = opts.get("--registry") or env_registry
    lockfile = ((prog == "npm" and pos[:1] == ["ci"])
                or (prog == "pnpm" and pos[:1] == ["install"] and "--frozen-lockfile" in opts)
                or (prog == "yarn" and pos[:1] in ([], ["install"]) and "--immutable" in opts))
    if lockfile:
        return [_net_lockfile(prog, "npm", registry)]
    if pos[:1] in (["create"], ["init"]) and len(pos) > 1:
        item = _net_npm_create(prog, pos[0], pos[1], registry)
        return [item] if item else []
    if prog == "yarn" and pos[:2] == ["global", "add"]:
        pos = pos[1:]
    if prog == "yarn" and not pos:
        pos = ["install"]
    if not pos or pos[0] not in _NPM_INSTALL[prog]:
        return []
    if len(pos) == 1:
        return [_net_registry_item(prog, "npm", None, None, registry)]
    found = (_net_npm_package(prog, s, registry) for s in pos[1:])
    return [i for i in found if i]


def _net_npx(prog: str, args: list[str], env_registry: str | None = None) -> list[dict]:
    label = prog
    if prog in ("pnpm", "yarn", "npm"):      # pnpm dlx, yarn dlx, npm exec, npm x
        label, args = f"{prog} {args[0]}", args[1:]
    pos, opts = _net_positionals(args, _NPX_VALUE)
    # Every -p/--package is installed (R3B8); with none, the command names the package.
    specs = _net_opt_values(args, frozenset({"-p", "--package"}), _NPX_VALUE) or pos[:1]
    registry = opts.get("--registry") or env_registry
    found = (_net_npm_package(label, spec, registry, exec_=True) for spec in specs if spec)
    return [i for i in found if i]


def _net_pip_package(program: str, spec: str, registry: str | None, exec_: bool = False) -> dict | None:
    if spec == "@" or spec.startswith((".", "/", "~")):
        return None
    direct = _NET_PEP508_URL.match(spec)
    if direct:                               # PEP 508 `name @ url`: the name is the package
        url = direct.group(2)
        url = url.split("+", 1)[1] if re.match(r"^[a-z]+\+[a-z]", url) else url
        return _net_url_item("install", program, url, ecosystem="pypi", package=direct.group(1),
                             exec=exec_)
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


def _net_opt_values(args: list[str], names: frozenset, takes_value: frozenset) -> list[str]:
    """Every value given to one of `names` (`-r a -r b`, `--opt=v`, `-rFILE`),
    in order; options are read as `_net_positionals` reads them."""
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a.startswith("--") and "=" in a:
            if a.split("=", 1)[0] in names:
                out.append(a.split("=", 1)[1])
        elif a in takes_value and i + 1 < len(args):
            if a in names:
                out.append(args[i + 1])
            i += 1
        elif not a.startswith("--") and len(a) > 2 and a[:2] in names:
            out.append(a[2:])                # `-rreq.txt`
        i += 1
    return out


_PIP_REQ_OPTS = frozenset({"-r", "--requirement"})
_PIP_URL_OPTS = frozenset({"-c", "--constraint", "--extra-index-url", "-f", "--find-links"})
_PIP_EDITABLE = frozenset({"-e", "--editable"})


def _net_pip(prog: str, args: list[str], env_index: str | None = None,
             env_extra: tuple = ()) -> list[dict]:
    pos, opts = _net_positionals(args, _PIP_VALUE)
    if pos and pos[0] != "install" and pos[0] not in _PIP_COMMANDS and "install" in pos:
        pos = pos[pos.index("install"):]     # a value option we do not know ate its place (R3B6)
    if not pos or pos[0] != "install":
        return []
    registry = opts.get("-i") or opts.get("--index-url") or opts.get("--default-index") or env_index
    out: list[dict] = []
    reqs = _net_opt_values(args, _PIP_REQ_OPTS, _PIP_VALUE)
    if reqs:
        item = _net_registry_item(prog, "pypi", None, None, registry)
        item["source"] = reqs[-1]
        out.append(item)
    # A requirements or constraints file, an extra index or a find-links page
    # given as a URL is fetched from that host (`--extra-index-url` is the
    # dependency-confusion vector).
    for url in _net_opt_values(args, _PIP_REQ_OPTS | _PIP_URL_OPTS | {"--index"}, _PIP_VALUE) + list(env_extra):
        if "=" in url and "://" in url.split("=", 1)[1]:
            url = url.split("=", 1)[1]       # uv's `--index name=URL`
        if "://" in url:
            out.append(_net_url_item("fetch", prog, url))
    for spec in _net_opt_values(args, _PIP_EDITABLE, _PIP_VALUE) + pos[1:]:
        words = _net_expand(spec) if "{" in spec else [spec]   # `pip install {evil,ok}==1` (R3B3)
        if words is None:
            out.append(_net_item("install", prog, ecosystem="pypi", package=spec, dynamic=True,
                                 _unresolved="unreadable"))
            continue
        for w in words:
            item = _net_pip_package(prog, w, registry)
            if item:
                out.append(item)
    return out


_UV_INDEX_OPTS = frozenset({"-i", "--index-url", "--default-index", "--index", "--extra-index-url",
                            "-f", "--find-links"})


def _net_uv(args: list[str], env: dict | None = None) -> list[dict]:
    # Global options before the subcommand (`uv --directory app pip install …`,
    # R3B6); an index given there still applies, so it is carried along.
    i, carry = 0, []
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a in _UV_INDEX_OPTS and i + 1 < len(args):
            carry += args[i:i + 2]
            i += 2
        elif a.split("=", 1)[0] in _UV_INDEX_OPTS:
            carry.append(a)
            i += 1
        else:
            i += 2 if a in _UV_GLOBAL_VALUE else 1
    args = args[i:]
    env = env or {}
    index = env.get("UV_INDEX_URL") or env.get("UV_DEFAULT_INDEX")
    extra = tuple(u for k in ("UV_EXTRA_INDEX_URL", "UV_INDEX") for u in (env.get(k) or "").split())
    if args[:2] == ["pip", "install"]:
        return _net_pip("uv pip", args[1:] + carry, index, extra)
    if args[:2] == ["tool", "install"]:
        return _net_pip("uv tool", args[1:] + carry, index, extra)
    if args[:2] == ["tool", "run"]:
        return _net_uvx("uv tool run", args[2:] + carry, index)
    if args[:1] == ["run"]:                  # `uv run --with x==1 script.py`: each --with
        withs = [v for k, v in zip(args, args[1:]) if k == "--with"] \
            + [a.split("=", 1)[1] for a in args if a.startswith("--with=")]
        found = (_net_pip_package("uv run", w, None, exec_=True) for w in withs)
        return [i for i in found if i]
    if args[:1] == ["add"]:
        return _net_pip("uv", ["install"] + args[1:] + carry, index, extra)
    if args[:1] == ["sync"]:
        return [_net_lockfile("uv", "pypi")]
    return []


def _net_uvx(prog: str, args: list[str], env_index: str | None = None) -> list[dict]:
    exec_ = True
    if prog == "pipx":
        if not args or args[0] not in ("run", "install"):
            return []
        exec_, args = args[0] == "run", args[1:]
    pos, opts = _net_positionals(args, _UVX_VALUE)
    spec = opts.get("--from") or (pos[0] if pos else None)
    registry = opts.get("-i") or opts.get("--index-url") or opts.get("--default-index") or env_index
    out: list[dict] = []
    item = _net_pip_package(prog, spec, registry, exec_=exec_) if spec else None
    if item:
        out.append(item)
    # Every --with is installed too (R3B8); a requirements file given as a URL is fetched.
    for w in _net_opt_values(args, frozenset({"--with", "-w"}), _UVX_VALUE):
        for one in (x.strip() for x in w.split(",")):
            item = _net_pip_package(prog, one, registry, exec_=exec_) if one else None
            if item:
                out.append(item)
    for r in _net_opt_values(args, frozenset({"--with-requirements"}), _UVX_VALUE):
        if "://" in r:
            out.append(_net_url_item("fetch", prog, r))
    return out


def _net_brew(args: list[str]) -> list[dict]:
    pos, _ = _net_positionals(args)
    if not pos or pos[0] not in ("install", "reinstall", "tap"):
        return []
    if pos[0] == "tap" and len(pos) > 2:     # `brew tap NAME URL` clones URL (R3B10)
        return [_net_url_item("clone", "brew", pos[2])]
    if pos[0] == "tap":                      # clones github.com/<owner>/homebrew-<repo>
        return [_net_item("clone", "brew", host="github.com", host_inferred=True,
                          url=f"https://github.com/{owner}/homebrew-{repo}")
                for owner, _, repo in (t.partition("/") for t in pos[1:]) if repo]
    return [_net_registry_item("brew", "brew", f, None, None) for f in pos[1:]]


def _net_cargo(args: list[str]) -> list[dict]:
    if args[:1] and args[0].startswith("+"):
        args = args[1:]                      # `cargo +nightly install …`: a toolchain
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
    if not pos or pos[0] not in ("install", "get", "run"):
        return []
    if pos[0] == "run":                      # `go run mod/cmd@v1`: downloads the module; later words are its args
        pos = pos[:2] if len(pos) > 1 and "@" in pos[1] else []
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
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in _DOCKER_GLOBAL_VALUE else 1
    args = args[i:]
    if args[:2] in (["image", "pull"], ["container", "run"], ["container", "create"]):
        args = args[1:]
    if not args or args[0] not in ("pull", "run", "create"):
        return []
    pos, _ = _net_positionals(args[1:], _DOCKER_PULL_VALUE if args[0] == "pull" else _DOCKER_VALUE)
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


_NET_PIP_PROG = re.compile(r"pip(?:\d+(?:\.\d+)?)?")   # pip, pip3, pip3.12


def _net_extract(tokens: list[str], env: dict | None = None) -> list[dict]:
    """The downloads one command makes. `env` holds the NAME=VALUE assignments
    in effect (written before it, or exported earlier in the same command):
    a registry or GH_HOST is applied as the option would be, a proxy marks
    the transfer redirected (R3B10, R3B11)."""
    # Lower-cased: `Docker`, `NPM`, `CURL` run the real tool on macOS (ruling R11).
    prog, args = _net_base(tokens[0]).lower(), tokens[1:]
    if re.fullmatch(r"python(?:\d(?:\.\d+)?)?", prog) and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    own = getattr(tokens, "env", {})
    env = {**env, **own} if env else own
    items = _net_extract_prog(prog, args, env)
    return _net_transport(prog, args, env, items) if items else items


def _net_npm_env_registry(prog: str, env: dict) -> str | None:
    """The registry npm, pnpm, yarn or bun reads from the environment
    (npm_config_* names are case-insensitive)."""
    if not env:
        return None
    for k in ("YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY") if prog == "yarn" else ():
        if env.get(k):
            return env[k]
    if prog in ("bun", "bunx") and env.get("BUN_CONFIG_REGISTRY"):
        return env["BUN_CONFIG_REGISTRY"]
    return next((v for k, v in env.items() if k.lower() == "npm_config_registry" and v), None)


def _net_extract_prog(prog: str, args: list[str], env: dict) -> list[dict]:
    if prog == "curl":
        return _net_curl(args)
    if prog == "wget":
        return _net_wget(args)
    if prog == "git":
        return _net_git(args, env)
    if prog == "gh":
        return _net_gh(args, env)
    if prog in ("npx", "bunx") or (prog in ("pnpm", "yarn") and args[:1] == ["dlx"]) \
            or (prog == "npm" and args[:1] in (["exec"], ["x"])):
        return _net_npx(prog, args, _net_npm_env_registry(prog, env))
    if prog in _NPM_INSTALL:
        return _net_npm(prog, args, _net_npm_env_registry(prog, env))
    if _NET_PIP_PROG.fullmatch(prog):
        return _net_pip(prog, args, env.get("PIP_INDEX_URL"),
                        tuple(u for k in ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS")
                              for u in (env.get(k) or "").split()))
    if prog == "uv":
        return _net_uv(args, env)
    if prog in ("uvx", "pipx"):
        return _net_uvx(prog, args, env.get("UV_INDEX_URL") or env.get("UV_DEFAULT_INDEX") if prog == "uvx"
                        else env.get("PIP_INDEX_URL"))
    if prog == "brew":
        return _net_brew(args)
    if prog == "cargo":
        return _net_cargo(args)
    if prog == "go":
        return _net_go(args)
    if prog in ("docker", "podman"):
        return _net_docker(prog, args)
    return []


# Options that send a transfer through another host: a proxy, or another
# address for the host the URL names (R3B11).
_CURL_PROXY_OPTS = frozenset({"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5",
                              "--socks5-hostname", "--doh-url"})
_CURL_CONNECT_TO = re.compile(r"(\[[^\]]*\]|[^:]*):([^:]*):(\[[^\]]*\]|[^:]*):(.*)")
_CURL_RESOLVE = re.compile(r"[+]?(\[[^\]]*\]|[^:]*):([^:]*):(.+)")
_BREW_MIRROR_ENV = ("HOMEBREW_BOTTLE_DOMAIN", "HOMEBREW_ARTIFACT_DOMAIN", "HOMEBREW_API_DOMAIN",
                    "HOMEBREW_BREW_GIT_REMOTE", "HOMEBREW_CORE_GIT_REMOTE")
_GOPROXY_DEFAULT = frozenset({"", "direct", "off", "https://proxy.golang.org"})


def _net_transport(prog: str, args: list[str], env: dict, items: list[dict]) -> list[dict]:
    """Mark items whose transfer the same command redirects (a proxy option or
    variable, curl --connect-to/--resolve/--doh-url, git http.proxy, GOPROXY, a
    Homebrew mirror) as dynamic and unresolved: never trusted, and unresolved
    under --ioc (R3B11). Each redirect target that names a host is added as an
    item of its own, so a listed host still matches."""
    if prog in ("docker", "podman"):
        return items                         # the daemon pulls, with its own settings
    common: list[str | None] = []            # None: redirected to a target not known
    if prog == "curl":
        common += _net_opt_values(args, _CURL_PROXY_OPTS, _CURL_VALUE)
        for v in _net_opt_values(args, frozenset({"--connect-to"}), _CURL_VALUE):
            m = _CURL_CONNECT_TO.fullmatch(v)
            if not m:
                common.append(None)
            elif m.group(3):
                common.append(m.group(3) + (":" + m.group(4) if m.group(4) else ""))
        for v in _net_opt_values(args, frozenset({"--resolve"}), _CURL_VALUE):
            m = _CURL_RESOLVE.fullmatch(v)
            common += [a.strip() for a in m.group(3).split(",") if a.strip()] if m else [None]
    elif prog == "git":
        for k, v in _net_git_config(args, env):
            low = k.lower()
            if low in ("http.proxy", "https.proxy") or (low.startswith("http.") and low.endswith(".proxy")):
                common.append(v or None)
        if env.get("GIT_PROXY_COMMAND"):
            common.append(None)
    elif prog in _NPM_INSTALL or prog in ("npx", "bunx"):
        common += _net_opt_values(args, frozenset({"--proxy", "--https-proxy"}), _NPM_VALUE)
        common += [v for k, v in env.items() if k.lower() in ("npm_config_proxy", "npm_config_https_proxy",
                                                              "yarn_proxy", "yarn_https_proxy") and v]
    elif _NET_PIP_PROG.fullmatch(prog) or prog in ("uv", "uvx", "pipx"):
        common += _net_opt_values(args, frozenset({"--proxy"}), _PIP_VALUE)
        common += [env["PIP_PROXY"]] if env.get("PIP_PROXY") else []
    elif prog == "go":
        common += [p for p in re.split(r"[,|]", env.get("GOPROXY", "")) if p.strip().rstrip("/") not in _GOPROXY_DEFAULT]
    elif prog == "brew":
        common += [env[k] for k in _BREW_MIRROR_ENV if env.get(k)]
    elif prog == "cargo" and env.get("CARGO_HTTP_PROXY"):
        common.append(env["CARGO_HTTP_PROXY"])
    if not common and not any(k.lower().endswith("_proxy") and not k.lower().startswith("no_") for k in env):
        return items
    targets: list[str] = []
    for it in items:
        ts = list(common)
        url = it.get("url") or ""
        scheme = url.split("://", 1)[0].lower() if "://" in url else ("" if url else "https")
        if scheme:                           # an scp remote goes over ssh: no HTTP proxy
            ts += [env[n] for n in ("all_proxy", "ALL_PROXY", f"{scheme}_proxy", f"{scheme.upper()}_PROXY")
                   if env.get(n)]
        if ts:
            it["dynamic"], it["_unresolved"] = True, "redirected"
            targets += [t for t in ts if t]
    program = items[0]["program"]
    for t in dict.fromkeys(targets):
        out = _net_url_item("fetch", program, t if "://" in t else "http://" + t)
        if out["host"] or out["dynamic"]:
            items.append(out)
    return items


# xargs reads the arguments of these from stdin: (kind, ecosystem) of the
# dynamic item an install through xargs stands for (P2B13).
_NET_XARGS_INSTALL = {"npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm", "npx": "npm", "bunx": "npm",
                      "pip": "pypi", "pip3": "pypi", "uv": "pypi", "uvx": "pypi", "pipx": "pypi",
                      "docker": "oci", "podman": "oci", "cargo": "crates", "go": "go", "brew": "brew"}
_NET_XARGS_SUBS = frozenset({"i", "install", "add", "pull", "run", "get", "exec", "x", "dlx", "create"})
_NET_ITEM_TEXT = ("url", "package", "version", "host", "dest", "source", "alias")


# --------------------------------------------------------------------------
# What earlier parts of the same command do to a later one's environment and
# configuration (R3F5, R3F7), as bash scopes it. `export NAME=VALUE`, `unset
# NAME`, `export -n NAME`, and a config write (`git config [--global]
# url.X.insteadOf Y`, `http.proxy`; `npm|pnpm config set registry|proxy`,
# `yarn config set …`; `pip config set *.index-url|proxy`) reach the commands
# after them in the same shell. They do not leave a child: a pipeline element,
# a command run in the background, `( … )`, `$( … )`, `bash -c`, a heredoc fed
# to a shell. A later command gets them for certain only when the effect is a
# top-level command of the plain part of the line (no `( )`, `{ }`, function,
# if/while/for/case before it), run unconditionally (after `;`, a newline or
# `&`) or followed by `&&` alone up to that command. Anywhere else the scope
# cannot be told, and a later download that would come out differently with
# and without the effect is reported both ways, unresolved: never trusted, and
# network-ioc-unresolved under --ioc. A config file written with a redirect or
# tee (.npmrc, .yarnrc, pip.conf, .gitconfig) cannot be read, so a later
# download by that tool is unresolved. A config written by an earlier, separate
# tool call is out of scope; command_rule_matches flags every config write
# (network-config) so it is seen.
# --------------------------------------------------------------------------

_NET_GIT_WRITTEN = " git-config"             # not a variable name: cannot be assigned
_NET_TAINT = " written"                      # families whose config file was written unread
_NET_ENV_NAME = re.compile(r"(?i)npm_config_|yarn_|bun_config_|pip_|uv_|git_config|homebrew_"
                           r"|(?:git_proxy_command|gh_host|goproxy|cargo_http_proxy|[a-z0-9_]*_proxy"
                           r"| git-config)\Z")
NET_SCOPE_EFFECTS_MAX = 256                  # effects per command read; past it every download is unresolved
_NET_SCOPE_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"|\$'(?:[^'\\]|\\.)*'|\\.|\$\{[^}]*\}")
_NET_SCOPE_RESERVED = frozenset({"if", "then", "elif", "else", "fi", "while", "until", "for", "do", "done",
                                 "case", "esac", "select", "function", "coproc", "[[", "]]", "((", "{", "}"})
_NET_CONFIG_FILE = re.compile(r"(?i)(?:\.npmrc|\.yarnrc(?:\.yml)?|pip\.conf|pip\.ini|\.gitconfig"
                              r"|\.config/git/config)['\"]?\Z")
_NET_CONFIG_FILE_WRITE = re.compile(r"(?i)>>?\|?\s*['\"]?([^\s'\";|&<>]{0,512})")
_NET_CONFIG_FAMILY = {".npmrc": "npm", ".yarnrc": "npm", ".yarnrc.yml": "npm", "pip.conf": "pip",
                      "pip.ini": "pip", ".gitconfig": "git", "config": "git"}
_NET_FAMILY_PROGS = {"npm": frozenset({"npm", "pnpm", "yarn", "bun", "npx", "bunx"}),
                     "pip": frozenset({"pip", "pipx", "uv", "uvx"}), "git": frozenset({"git"})}
_NET_HINT_CONFIG = re.compile(r"(?i)export|unset|declare|typeset|config|\bset\b|npmrc|yarnrc|pip\.(?:conf|ini)"
                              r"|gitconfig|git/config")


def _net_scope_plain(parts: list[str]) -> list[bool]:
    """For each top-level part, whether it and every part before it are plain:
    no `(` `)`, no `{` `}` word, no reserved word in command position. Only
    there is a top-level command known to run in the shell itself, in order."""
    out: list[bool] = []
    plain = True
    for p in parts:
        if plain:
            q = _NET_SCOPE_QUOTED.sub(" ", p) if any(c in p for c in "'\"\\$") else p
            words = q.split()
            if "(" in q or ")" in q or any(w in _NET_SCOPE_RESERVED for w in words[:1]) \
                    or "{" in words or "}" in words:
                plain = False
        out.append(plain)
    return out


def _net_family(prog: str) -> str:
    if _NET_PIP_PROG.fullmatch(prog) or prog in _NET_FAMILY_PROGS["pip"]:
        return "pip"
    return next((f for f, progs in _NET_FAMILY_PROGS.items() if prog in progs), "")


def _net_config_effects(tokens: list[str], raw: str = "") -> "tuple[list[tuple], bool] | None":
    """What one command writes to the network configuration of later ones:
    (effects, whether it writes the user's own config, which every later
    command reads), or None when it writes none. An effect is ("append", name,
    text), ("set", name, value) or ("taint", family): a file written that
    cannot be read."""
    prog, args = _net_base(tokens[0]).lower(), list(tokens[1:])
    if re.fullmatch(r"python(?:\d(?:\.\d+)?)?", prog) and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    if prog == "tee" or (raw and ">" in raw):
        targets = [a for a in args if not a.startswith("-")] if prog == "tee" else []
        targets += [m.group(1) for m in _NET_CONFIG_FILE_WRITE.finditer(raw)] if raw and ">" in raw else []
        fams = {_NET_CONFIG_FAMILY.get(t.rstrip("'\"").rsplit("/", 1)[-1].lower(), "") for t in targets
                if _NET_CONFIG_FILE.search(t)}
        if fams - {""}:
            return [("taint", f) for f in sorted(fams - {""})], True
    if prog == "git":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in _GIT_GLOBAL_VALUE else 1
        if i >= len(args) or args[i] != "config":
            return None
        rest = args[i + 1:]
        if rest[:1] == ["set"]:
            rest = rest[1:]
        user, pos, j = False, [], 0
        while j < len(rest):
            a = rest[j]
            if a in ("--global", "--system"):
                user = True
            elif a in ("--unset", "--unset-all", "--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l",
                       "--list", "-e", "--edit", "--remove-section", "--rename-section", "unset", "get",
                       "list", "edit"):
                return None
            elif a in ("-f", "--file", "--blob", "--type", "--default", "--comment", "--value"):
                j += 1
            elif not a.startswith("-"):
                pos.append(a)
            j += 1
        if len(pos) < 2:
            return None
        key, value = pos[0], pos[1]
        low = key.lower()
        if low.startswith("url.") and low.endswith(".insteadof") or low in ("http.proxy", "https.proxy") \
                or (low.startswith("http.") and low.endswith(".proxy")):
            return [("append", _NET_GIT_WRITTEN, f"'{key}'='{value}'")], user
        if low.startswith("url.") and low.endswith(".pushinsteadof"):
            return [], user
        return None
    if prog in ("npm", "pnpm", "yarn"):
        words = [a for a in args if not a.startswith("-")]
        if words[:2] == ["config", "set"]:
            kv = words[2:]
        elif prog in ("npm", "pnpm") and words[:1] == ["set"]:
            kv = words[1:]
        else:
            return None
        if not kv:
            return None
        key, value = kv[0].split("=", 1) if "=" in kv[0] else (kv[0], kv[1] if len(kv) > 1 else "")
        low = key.lower().replace("_", "-")
        names = ({"registry": "YARN_REGISTRY", "npmregistryserver": "YARN_NPM_REGISTRY_SERVER",
                  "proxy": "yarn_proxy", "httpproxy": "yarn_proxy", "https-proxy": "yarn_https_proxy",
                  "httpsproxy": "yarn_https_proxy"} if prog == "yarn" else
                 {"registry": "npm_config_registry", "proxy": "npm_config_proxy",
                  "https-proxy": "npm_config_https_proxy"})
        if low in names:
            return [("set", names[low], value)], True
        if low.endswith(":registry") or "registry" in low or "proxy" in low:
            return [], True
        return None
    if _NET_PIP_PROG.fullmatch(prog):
        words = [a for a in args if not a.startswith("-")]
        if words[:2] != ["config", "set"] or len(words) < 4:
            return None
        key, value = words[2].lower(), words[3]
        field = key.rsplit(".", 1)[-1]
        names = {"index-url": "PIP_INDEX_URL", "extra-index-url": "PIP_EXTRA_INDEX_URL", "proxy": "PIP_PROXY"}
        if field in names:
            return [("set", names[field], value)], True
        if field in ("trusted-host", "find-links"):
            return [], True
        return None
    return None


def _net_env_effects(tokens: list[str]) -> "list[tuple] | None":
    """`export NAME=VALUE` / `declare -x NAME=VALUE` (set), `export -n NAME`
    and `unset NAME` (unset), for the names a download reads; None when the
    command is none of these."""
    head = tokens[0]
    if head not in ("export", "unset", "declare", "typeset"):
        return None
    out: list[tuple] = []
    opts = "".join(t[1:] for t in tokens[1:] if t.startswith("-") and not _NET_ASSIGN.match(t))
    if head in ("declare", "typeset") and "x" not in opts:
        return out                           # not exported: no child sees it
    if head == "unset" and "f" in opts:
        return out
    drop = head == "unset" or (head == "export" and "n" in opts)
    for t in tokens[1:]:
        if t.startswith("-"):
            continue
        name, eq, value = t.partition("=")
        if not _NET_ENV_NAME.match(name):
            continue
        if drop:
            out.append(("unset", name))
        elif eq:
            out.append(("set", name, value))
    return out


def _net_apply(env: dict, ops: "list[tuple]") -> None:
    for op in ops:
        if op[0] == "set":
            env[op[1]] = op[2]
        elif op[0] == "unset":
            env.pop(op[1], None)
        elif op[0] == "append":
            env[op[1]] = env.get(op[1], "") + op[2]
        elif op[0] == "taint":
            env[_NET_TAINT] = env.get(_NET_TAINT, "") + " " + op[1]


def _net_signature(items: list[dict]) -> list[tuple]:
    return [(i.get("kind"), i.get("host"), i.get("url"), i.get("package"), i.get("version"),
             i.get("_unresolved")) for i in items]


def network_items_from_command(cmd: str, piped_to_shell: list[str] | None = None,
                               remotes: dict[str, str] | None = None,
                               limits: list[str] | None = None) -> tuple[list[dict], int]:
    """Every download the command shows, and how many segments could not be read.

    `piped_to_shell`, when given, receives the raw text of each curl or wget
    segment whose output a shell runs: remote code execution, seen on the
    dequoted command (`cu''rl … | s''h`) that the audit regexes miss.

    `remotes`, when given, is one session's git remote names and the URLs they
    were added with; it is read to resolve `git pull NAME` and updated by
    `git remote add` and `git clone`, so a remote added in one command and
    pulled in the next keeps its host. Pass a fresh dict per session, never shared.

    `limits`, when given, receives a reason when part of the command was not
    read because of a cap or nesting limit (past 1 MiB, NET_NEST_MAX,
    NET_TREE_MAX, NET_LEX_BUDGET): the caller reports it under --ioc (R10)."""
    # Read up to the hard cap like the audit does, so padding before an install
    # does not hide it. Every pass below is linear; past the cap, one segment
    # is counted unparsed so the coverage line does not claim the whole command.
    cmd = cmd or ""
    text = cmd[:MAX_SCAN_HARD]
    beyond = 1 if len(cmd) > MAX_SCAN_HARD else 0
    if beyond and limits is not None:
        limits.append("past 1 MiB")
    if not _NET_MAY_DOWNLOAD.search(text):
        return [], beyond
    segments, unparsed, limit, _lines, top = _shell_walk(text)
    if limit and limits is not None:
        limits.append("nested or long past what is read")
    unparsed += beyond
    found: list[dict] = []
    scope = _NetScope(segments, top) if _NET_HINT_CONFIG.search(text) else None
    for idx, (tokens, via_xargs, into_shell, raw) in enumerate(segments):
        if tokens[0] in ("export", "unset", "declare", "typeset"):
            continue
        got = scope.extract(idx, tokens) if scope is not None else [dict(i) for i in _net_extract(tokens, {})]
        if any("{" in (i.get("url") or "") or "{" in (i.get("package") or "") for i in got):
            got = _net_expand_items(got)
        prog = _net_base(tokens[0]).lower()
        for item in got:
            # A substitution's output is not in the transcript: built at run time.
            url = item.get("url")
            if isinstance(url, str) and _LEX_PH in url and not item.get("host"):
                # `curl https://o.io/$(date)`: the host is literal; only a
                # substitution in the authority hides it.
                a, b = url_host(_LEX_SUB.sub("a", url)), url_host(_LEX_SUB.sub("b", url))
                if a and a == b:
                    item["host"] = a
            for k in _NET_ITEM_TEXT:
                v = item.get(k)
                if isinstance(v, str) and _LEX_PH in v:
                    item[k] = _net_display(v)
                    item["dynamic"] = True
            if "$" in (item.get("package") or ""):
                item["dynamic"] = True
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
        elif (via_xargs or any(_LEX_PH in t for t in tokens[1:])) and prog.lower() in _NET_XARGS_INSTALL and (
                (got and all(i["kind"] == "install" and not i["package"] for i in got))
                or (not got and _NET_XARGS_SUBS.intersection(t.lower() for t in tokens[1:3]))):
            # `xargs npm i`, `xargs pip install`, `pip install $(cat reqs)`: the
            # packages come at run time, not from a lockfile.
            got = [_net_item("install", prog, ecosystem=_NET_XARGS_INSTALL[prog.lower()], dynamic=True)]
        if into_shell and piped_to_shell is not None and prog in ("curl", "wget") and got:
            piped_to_shell.append(raw)
        found += got
    return found, unparsed


def network_config_write(cmd: str) -> str:
    """The text of the first segment of `cmd` that writes download
    configuration (see the section comment above _NET_GIT_WRITTEN), or ""."""
    text = (cmd or "")[:MAX_SCAN_HARD]
    if not _NET_HINT_CONFIG.search(text) or not _NET_MAY_DOWNLOAD.search(text):
        return ""
    for tokens, _x, _f, raw in _shell_walk(text)[0]:
        if _net_config_effects(tokens, raw) is not None:
            return raw
    return ""


class _NetScope:
    """The environment and configuration effects of one command's segments
    (see the section comment above _NET_GIT_WRITTEN), and the downloads of a
    segment read under them."""

    def __init__(self, segments: list, top: tuple) -> None:
        info, parts, seps, amps = top
        if len(info) != len(segments):       # cannot place the segments: every effect is uncertain
            info = [(None, "eval")] * len(segments)
        self.info = info
        self.effects: list[tuple] = []       # (index, part, mode, ops, chain end)
        self.overflow = False
        plain = _net_scope_plain(parts)
        amp = set(amps)
        chain_end = list(range(len(parts)))
        for k in range(len(parts) - 2, -1, -1):
            if seps[k] == "&&":
                chain_end[k] = chain_end[k + 1]
        for idx, (tokens, _x, _f, raw) in enumerate(segments):
            ops = _net_env_effects(tokens)
            user, written = True, False
            if ops is None:
                got = _net_config_effects(tokens, raw)
                if got is None:
                    continue
                (ops, user), written = got, True
            if not ops:
                continue
            m, how = info[idx]
            # A config write is a file: it outlasts the shell that made it, so
            # where it ran decides only whether it ran, and before what.
            if how == "nested" and not written:
                mode = "nested"              # a child shell's export: reaches nothing outside it
            elif how != "direct" or m is None or not user:
                mode = "maybe"
            elif seps[m] == "|" or (m and seps[m - 1] == "|") or m in amp:
                if not written:
                    continue                 # a pipeline element or a background job: a subshell
                mode = "maybe"               # run alongside what follows it
            elif not plain[m] or (m and seps[m - 1] == "||"):
                mode = "maybe"
            elif m and seps[m - 1] == "&&":
                mode = "chain"
            else:
                mode = "certain"
            self.effects.append((idx, m, mode, ops, chain_end[m] if m is not None else 0))
        if len(self.effects) > NET_SCOPE_EFFECTS_MAX:
            self.overflow = True             # past what is read: unresolved, not clean (R10)

    def _envs(self, idx: int) -> "tuple[dict, list[tuple]]":
        n, how = self.info[idx]
        cert: dict = {}
        maybe: list[tuple] = []
        for e_idx, m, mode, ops, end in self.effects:
            if e_idx == idx:
                continue
            if mode == "nested":
                if how != "direct":
                    maybe += ops
                continue
            if n is None or m is None:
                maybe += ops
            elif mode == "maybe":
                if n >= m:
                    maybe += ops
            elif n > m:
                if mode == "certain" or n <= end:
                    _net_apply(cert, ops)
                else:
                    maybe += ops
        return cert, maybe

    def extract(self, idx: int, tokens: list[str]) -> list[dict]:
        if not self.effects:
            return [dict(i) for i in _net_extract(tokens, {})]
        if self.overflow:
            got = [dict(i) for i in _net_extract(tokens, {})]
            for i in got:
                i["dynamic"] = True
                i["_unresolved"] = i.get("_unresolved") or "redirected"
            return got
        cert, maybe = self._envs(idx)
        alts: list[dict] = []
        if maybe:
            b = dict(cert)
            _net_apply(b, [op for op in maybe if op[0] != "unset"])
            c = dict(cert)
            _net_apply(c, [op for op in maybe if op[0] == "unset"])
            alts = [b, c]
        prog = _net_base(tokens[0]).lower()
        fam = _net_family(prog)
        taint = bool(fam) and (("taint", fam) in maybe or fam in cert.get(_NET_TAINT, "").split())
        if getattr(tokens, "env_clear", False):
            cert, alts = {}, []
        else:
            gone = getattr(tokens, "env_unset", frozenset())
            if gone:
                cert = {k: v for k, v in cert.items() if k not in gone}
                alts = [{k: v for k, v in a.items() if k not in gone} for a in alts]
            if getattr(tokens, "env_maybe", False) and cert:
                alts.append({})
        got = [dict(i) for i in _net_extract(tokens, cert)]
        sig = _net_signature(got)
        extra: list[dict] = []
        differ = taint
        for env in alts:
            if env == cert:
                continue
            other = [dict(i) for i in _net_extract(tokens, env)]
            if _net_signature(other) != sig:
                differ = True
                seen = set(sig + _net_signature(extra))
                extra += [i for i in other if _net_signature([i])[0] not in seen]
        if differ:
            for i in got + extra:
                i["dynamic"] = True
                i["_unresolved"] = i.get("_unresolved") or "redirected"
        return got + extra


_NET_TOOL_WORDS = ("fetch", "browse", "download", "http")


def network_items_from_tool(name: str, tool_input: dict) -> list[dict]:
    """A non-shell tool call that reaches the network. A search keeps no query:
    the query is the user's words, not a destination."""
    n = (name or "").lower()
    if n in ("bash", "shell_command"):
        return []
    if n in ("websearch", "web_search", "google_web_search"):
        return [_net_item("search", name)]
    if n in ("webfetch", "web_fetch") or any(w in n for w in _NET_TOOL_WORDS):
        inp = tool_input if isinstance(tool_input, dict) else {}
        url = next((inp[k] for k in ("url", "uri", "href") if isinstance(inp.get(k), str)), None)
        if not url and n == "web_fetch":
            # Gemini CLI's web_fetch takes a prompt with the URLs written into it.
            urls, _beyond = urls_in_text(inp.get("prompt"))
            if urls:
                return [_net_url_item("fetch", name, u) for u in urls]
        return [_net_url_item("fetch", name, url) if url else _net_item("fetch", name)]
    return []


_FILE_WRITE_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit", "create",
                               "edit_file", "str_replace_editor", "str_replace_based_edit_tool",
                               "write_file", "replace"})    # Gemini CLI and Qwen Code
_WRITE_REDIRECT = re.compile(r">>?(.*)$", re.S)


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


def _glob_class_body(body: str) -> str:
    """The inside of a [...] class made safe for re: set operators (`--`, `&&`,
    `||`, `~~`) would raise a FutureWarning, so those characters are escaped."""
    out, prev = [], ""
    for c in body:
        if c in "\\][^&|~" or (c == "-" and prev == "-"):
            out.append("\\" + c)
        else:
            out.append(c)
        prev = c
    return "".join(out)


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
            out.append("[" + ("^" if neg else "") + _glob_class_body(body[1:] if neg else body) + "]")
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
        # An image from an explicit registry (`ghcr.io/org/img`): the repository path.
        if item.get("ecosystem") == "oci" and "/" in pkg and not item.get("host_inferred") \
           and pkg.split("/", 1)[0].split(":", 1)[0] == (item.get("host") or ""):
            path = "/" + pkg.split("/", 1)[1]
    if any(seg in (".", "..") or "%2e" in seg.lower() for seg in path.split("/")) \
            or "$" in path or "`" in path:       # a variable may hold `../`
        return None
    return path.lower()


_NET_PCT_UNRESERVED = re.compile(r"%(2[dD]|3[0-9]|[46][1-9a-fA-F]|[57][0-9aA]|5[fF]|7[eE])")
_NET_SLASHES = re.compile(r"/{2,}")


def _ioc_path(path: str) -> str:
    """A path as a server reads it, for IOC matching only (R3B13): percent-encoded
    unreserved characters decoded (`%65` is `e`; `%2e` already made the path
    unknown) and repeated slashes merged."""
    if "%" in path:
        path = _NET_PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), path).lower()
    return _NET_SLASHES.sub("/", path) if "//" in path else path


def _host_path_match(host: str, path: str, item: dict, exact: bool = False, ioc: bool = False) -> bool:
    """Whether an item's host and path fall under host[/path]: the host equal,
    or (unless exact) a suffix on a label boundary; the path a prefix on a
    segment boundary. An item with no known host, or a path that cannot be
    known, never matches a path. With ioc, the path is compared as a server
    reads it (_ioc_path): looser, so only for matching a block list, never trust."""
    ih = (item.get("host") or "").removesuffix(".")
    if not ih or (ih != host and (exact or not ih.endswith("." + host))):
        return False
    if not path:
        return True
    ip = _net_item_path(item)
    if ip is not None and ioc:
        ip = _ioc_path(ip)
    return ip is not None and (ip == path or ip.startswith(path + "/"))


def network_trusted(item: dict, trust: list[tuple[str, str]]) -> bool:
    """Host suffix on a label boundary; path prefix on a segment boundary.
    An item with no known host is never trusted, and neither is one whose
    host could not be normalised or whose transport the command redirected
    (a proxy, `--connect-to`, `--resolve`): the bytes come from elsewhere."""
    if item.get("_unresolved"):
        return False
    return any(_host_path_match(h, p, item) for h, p in trust)


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
        latest = max(group, key=lambda i: (_net_utc_key(i["ts"]), i["project"]))
        where = "a URL built from a variable" if host == "?" else host
        fleet.flags.append({
            "id": fid, "severity": "med", "categories": ["network-unasked"],
            "program": program, "project": latest["project"], "when": latest["ts"],
            "evidence": f"{len(group)} unasked download(s) via {program} from {where}"[:240],
            "had_secret": False, "suppressed": suppressed,
            "suppressed_reason": fleet.suppressions.get(fid, ""),
        })


def network_filter(fleet: "Fleet", host: str | None = None, package: str | None = None,
                   session: str | None = None, unasked: bool = False) -> None:
    """Keep only the items every given filter matches, before --network-strict
    and --ioc run, so totals, hosts, packages, findings and matches are all of
    the filtered set. host: a suffix on a label boundary, as trust matches
    (host/path also works). package: the exact name, compared as the IOC
    matcher compares it (npm exactly, pypi by PEP 503). session: a prefix."""
    trust = parse_trust([host], "--host") if host else []

    def keep(i: dict) -> bool:
        if trust and not network_trusted(i, trust):
            return False
        if package is not None:
            eco = i.get("ecosystem") or ""
            if not i.get("package") or _ioc_norm_name(eco, i["package"]) != _ioc_norm_name(eco, package):
                return False
        if session is not None and not (i.get("session") or "").startswith(session):
            return False
        return not unasked or i.get("approval") == "unasked"

    fleet.network = [i for i in fleet.network if keep(i)]
    fleet._net_by_call = {}              # positions are stale; every outcome is already applied


NETWORK_ITEM_KEYS = ("kind", "program", "host", "host_inferred", "url", "dest", "source",
                     "ecosystem", "package", "version", "pinned", "exec", "dynamic", "alias",
                     "failed", "approval", "trusted", "agent", "project", "session", "call_id", "ts", "ioc", "reputation",
                     "mode", "why", "prompt", "transcript", "rewound")

# why and prompt: what the assistant said before a call, and what the person
# last asked. Both are kept short, redacted and cleaned when they are read.
NET_CONTEXT_MAX = 160
NET_COMMAND_MAX = 200                # the text view's command line, after redaction
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
# Text that wraps harness output or instructions, not the person's own words.
_NOT_A_PROMPT = ("<command-name>", "<command-message>", "<command-args>", "<local-command-",
                 "<system-reminder>", "<user-prompt-submit-hook>", "<bash-stdout>", "<bash-stderr>",
                 "<environment_context>", "<user_instructions>", "Caveat: The messages below",
                 "[Request interrupted")


def _net_context(text: str | None, last_sentence: bool = False) -> str | None:
    """One line of at most NET_CONTEXT_MAX characters, cut on a word boundary:
    the last sentence of `text`, or its start. Control characters go before
    redaction (one inside a token would hide it from the patterns) and again
    after; whitespace, newlines included, collapses to single spaces."""
    if not text:
        return None
    t = " ".join(clean(text).split())
    if last_sentence:
        t = _SENTENCE_END.split(t)[-1]
    end = t.find(" ", 4 * NET_CONTEXT_MAX)  # bounded work; never cuts inside a token
    if end > 0:
        t = t[:end]
    t = " ".join(redact(clean(t)).split())
    return clip(t, NET_CONTEXT_MAX) or None


def _prompt_source(content: object) -> str | None:
    """The person's own words in a user message, raw, or None when it holds
    none: a tool result, an image, a slash-command or local-command wrapper,
    a system reminder or an agent's injected context."""
    if isinstance(content, str):
        texts = [content]
    elif isinstance(content, list):
        texts = [b["text"] for b in content if isinstance(b, dict)
                 and b.get("type") in ("text", "input_text") and isinstance(b.get("text"), str)]
    else:
        return None
    kept = [t for t in texts if t.strip() and not t.lstrip().startswith(_NOT_A_PROMPT)]
    return " ".join(kept) or None


def _net_public(i: dict, raw: bool = False, prompts: bool = False) -> dict:
    """An item as --json shows it: NETWORK_ITEM_KEYS, with url, dest and
    source redacted unless raw. prompt is null unless --with-prompts; why and
    prompt were redacted when read, so --no-redact does not reveal them."""
    out = {k: i.get(k) for k in NETWORK_ITEM_KEYS}
    if not raw:
        for k in ("url", "dest", "source", "package", "version", "alias"):
            if out[k]:
                out[k] = redact(out[k])
    if not prompts:
        out["prompt"] = None
    if out["transcript"]:
        out["transcript"] = dict(out["transcript"])
    return out


def _net_order_key(i: dict) -> tuple:
    """Every field that can differ, so no two distinct items tie. Time first,
    as a UTC instant: items keep their transcript's offset."""
    return (_net_utc_key(i["ts"]),) + tuple(str(i[k] or "") for k in (
        "ts", "agent", "project", "program", "host", "url", "package", "version", "kind",
        "dest", "source", "session", "approval"))


def _net_utc_date(ts: str) -> str:
    """YYYY-MM-DD of an ISO timestamp in UTC; its own date when it has no
    offset or does not parse (ts comes from parse_ts, so that is rare)."""
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return ts[:10]
    if dt.tzinfo is None:
        return ts[:10]
    try:
        return dt.astimezone(timezone.utc).date().isoformat()
    except OverflowError:                    # 9999-12-31T23:00-05:00 has no UTC date
        return ts[:10]


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
        if i["ts"] and (h["first_seen"] is None or _net_utc_key(i["ts"]) < _net_utc_key(h["first_seen"])):
            h["first_seen"] = i["ts"]
        h["trusted"] = h["trusted"] or i["trusted"]

    packages: dict[tuple[str, str], dict] = {}
    for i in items:
        if not i["package"]:
            continue
        p = packages.setdefault((i["ecosystem"] or "", i["package"]), {
            "ecosystem": i["ecosystem"], "name": i["package"], "versions": set(),
            "pinned": True, "exec": False, "count": 0, "unasked": 0})
        p["count"] += 1
        p["unasked"] += 1 if i["approval"] == "unasked" else 0
        if i["version"]:
            p["versions"].add(i["version"])
        p["pinned"] = p["pinned"] and i["pinned"]
        p["exec"] = p["exec"] or i["exec"]

    # The chart series. A date is the UTC date of the item's timestamp (ts
    # keeps the transcript's offset, so ts[:10] alone would be a local date);
    # an item with no timestamp is counted in by_day_undated, never guessed at.
    days: dict[str, dict] = {}
    projects: dict[str, dict] = {}
    for i in items:
        un = 1 if i["approval"] == "unasked" else 0
        if i["ts"]:
            key = _net_utc_date(i["ts"])
            d = days.setdefault(key, {"date": key, "items": 0, "unasked": 0})
            d["items"] += 1
            d["unasked"] += un
        pr = projects.setdefault(i["project"] or "", {"project": i["project"] or "",
                                                       "items": 0, "unasked": 0})
        pr["items"] += 1
        pr["unasked"] += un

    order = sorted(items, key=_net_order_key, reverse=True)
    return {
        "totals": {"items": len(items), "asked": approval["asked"], "unasked": approval["unasked"],
                   "unknown": approval["unknown"],
                   "failed": sum(1 for i in items if i["failed"] is True),
                   "unparsed_segments": fleet.network_unparsed},
        "by_kind": {k: kinds.get(k, 0) for k in ("install", "clone", "fetch", "search")},
        "by_day": [days[k] for k in sorted(days)],
        "by_day_undated": sum(1 for i in items if not i["ts"]),
        "by_project": sorted(projects.values(), key=lambda p: (-p["items"], p["project"])),
        "hosts": sorted(hosts.values(), key=lambda h: (-h["count"], h["host"])),
        "packages": [{**p, "name": p["name"] if raw else redact(p["name"]),
                      "versions": sorted(p["versions"] if raw else {redact(v) for v in p["versions"]})}
                     for _, p in sorted(packages.items(), key=lambda kv: (-kv[1]["count"], kv[0]))],
        "items": [_net_public(i, raw, fleet.with_prompts) for i in order[:NETWORK_ITEMS_CAP]],
        "items_truncated": len(items) > NETWORK_ITEMS_CAP,
        "strict": fleet.network_strict,
        "trust": list(fleet.network_trust),
        "trust_sources": [{"source": t["source"], "path": t.get("path"),
                           "sha256": t.get("sha256"), "entries": list(t["entries"])}
                          for t in fleet.network_trust_sources],
        "reputation": reputation_json(fleet),
        "ioc": ioc_json(fleet, raw),
    }


def reputation_json(fleet: "Fleet") -> dict:
    """network.reputation. Always an object; enabled false without --reputation."""
    data = fleet.reputation
    out = {"enabled": data is not None, "lists_status": None, "provider_lists": {}, "lists_age_hours": None,
           "stale": False, "vt_results": 0, "vt_status": None, "totals": dict(fleet.reputation_totals), "candidates": [],
           "advisory": {"text": None, "url": None}, "network_last_used": {"at": None, "provider": None}}
    if data is None:
        return out
    now = datetime.now(timezone.utc)
    out["lists_status"] = data.status
    out["provider_lists"] = {k: v["fetched_at"].isoformat(timespec="seconds")
                             for k, v in sorted(data.state.items())}
    if data.oldest:
        out["lists_age_hours"] = max(0, int((now - data.oldest).total_seconds() // 3600))
        out["stale"] = now - data.oldest > timedelta(days=REPUTATION_STALE_DAYS)
    out["vt_results"] = len(data.vt)
    out["vt_status"] = "corrupt" if data.vt_error else ("ok" if data.vt_present else "absent")
    out["candidates"] = sorted(({"prefix_b64": base64.b64encode(p).decode(), "expressions": n}
                                for p, n in fleet.reputation_candidates.items()),
                               key=lambda c: c["prefix_b64"])
    if data.lists:
        out["advisory"] = {"text": GSB_ADVISORY, "url": GSB_ADVISORY_URL}
    if data.last_network:
        out["network_last_used"] = {"at": data.last_network.get("at"),
                                    "provider": data.last_network.get("provider")}
    return out


def network_reconciles(n: dict) -> list[str]:
    """Why the network object's numbers do not add up; empty means they do.
    Takes the dict network_json returns, so the check sees what --json shows."""
    bad: list[str] = []
    t, kinds, items = n["totals"], n["by_kind"], n["items"]
    by_approval = t["asked"] + t["unasked"] + t["unknown"]
    if t["items"] != by_approval:
        bad.append(f"totals.items {t['items']} != asked + unasked + unknown {by_approval}")
    if t["items"] != sum(kinds.values()):
        bad.append(f"totals.items {t['items']} != sum of by_kind {sum(kinds.values())}")
    if t["failed"] > t["items"]:
        bad.append(f"totals.failed {t['failed']} > totals.items {t['items']}")
    hosted = sum(h["count"] for h in n["hosts"])
    if n["items_truncated"] or len(items) < t["items"]:
        if hosted > t["items"]:                    # the cap hides items; only a bound is checkable
            bad.append(f"hosts counts {hosted} > totals.items {t['items']}")
    elif hosted != sum(1 for i in items if i["host"]):
        bad.append(f"hosts counts {hosted} != items with a host "
                   f"{sum(1 for i in items if i['host'])}")
    for i in items:
        if i["approval"] not in ("asked", "unasked", "unknown"):
            bad.append(f"item approval {i['approval']!r} is not asked, unasked or unknown")
            break
    for i in items:
        if i["kind"] not in ("install", "clone", "fetch", "search"):
            bad.append(f"item kind {i['kind']!r} is not install, clone, fetch or search")
            break
    # The chart series, where present (a payload from before 0.3.0 has none).
    if "by_day" in n:
        dated = sum(d["items"] for d in n["by_day"])
        if dated + n["by_day_undated"] != t["items"]:
            bad.append(f"by_day items {dated} + undated {n['by_day_undated']} "
                       f"!= totals.items {t['items']}")
        if sum(d["unasked"] for d in n["by_day"]) > t["unasked"]:
            bad.append("by_day unasked exceeds totals.unasked")
        if any(d["unasked"] > d["items"] for d in n["by_day"]):
            bad.append("a by_day entry has more unasked than items")
    if "by_project" in n:
        for key, total in (("items", t["items"]), ("unasked", t["unasked"])):
            got = sum(p[key] for p in n["by_project"])
            if got != total:
                bad.append(f"by_project {key} {got} != totals.{key} {total}")
    if n["items_truncated"] != (len(items) < t["items"]):
        bad.append(f"items_truncated {n['items_truncated']} but {len(items)} of "
                   f"{t['items']} items are listed")
    return bad


# --------------------------------------------------------------------------
# --ioc: known-bad packages and hosts, matched offline
#
# A list someone else published (a malware feed, an incident write-up) is
# compared against the network inventory: did an agent install X@bad, or
# contact evil.example, and did anyone approve it? Nothing is fetched, and the
# list is read only when named on the command line.
#
# The list is untrusted input. Every regex below is anchored, with bounded
# repeats; none is built from file content. Versions are ordered with SemVer
# 2.0.0 section 11 (npm, crates, go) and PEP 440 (pypi), both written out here
# because the standard library has neither.
# --------------------------------------------------------------------------

IOC_VERSION_MAX = 128
_IOC_UNDECIDABLE = "undecidable"     # a clause that can never decide: an OSV range it cannot order
_IOC_ANY_VERSION = frozenset({"*", ">=0", ">=0.0.0"})
_IOC_OPS = ("===", "==", ">=", "<=", "=", ">", "<")      # longest first
_IOC_VERSION_CHARS = re.compile(r"[A-Za-z0-9.\-+_!:]{1,128}")
_IOC_WORD = re.compile(r"[A-Za-z]+")
# PEP 440 Appendix B, VERSION_PATTERN, anchored by fullmatch. The surrounding
# whitespace it allows is not: a version reaches output, and a list has no reason to pad one.
_IOC_PEP440 = re.compile(r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?
        (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?
        (?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
    """, re.VERBOSE | re.IGNORECASE | re.ASCII)
_IOC_PEP440_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_IOC_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IOC_OCI_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


IOC_QUOTE_MAX = 80


def _ioc_q(text: str) -> str:
    """Quote a token from the list for an error message, clipped: the message
    names what to fix without copying a megabyte of the file into a CI log."""
    return '"' + (text if len(text) <= IOC_QUOTE_MAX else text[:IOC_QUOTE_MAX - 1] + "\u2026") + '"'


class _IocError(ValueError):
    """A problem in one IOC entry: what is wrong, and how to write it.
    The caller adds the file and line."""

    def __init__(self, what: str, how: str = "") -> None:
        super().__init__(what + (f" — {how}" if how else ""))
        self.what, self.how = what, how


def _ioc_semver_number(p: str) -> bool:
    """A SemVer numeric identifier: ASCII digits, no leading zero."""
    return p.isascii() and p.isdigit() and (p == "0" or p[0] != "0")


def _ioc_semver_ident(p: str) -> bool:
    """A SemVer identifier: non-empty, [0-9A-Za-z-] only."""
    return bool(p) and p.isascii() and (p.replace("-", "").isalnum() or set(p) == {"-"})


def _ioc_semver_key(v: str) -> tuple | None:
    """SemVer 2.0.0 precedence (section 11) as a sortable tuple, or None.

    (major, minor, patch, pre): pre is (1,) for a release, else (0, ids) with
    each id (0, int) when numeric and (1, str) otherwise. A pre-release sorts
    below its release, numeric ids below alphanumeric, and a longer id list
    above an equal prefix. A leading v and build metadata (+incompatible) are
    ignored. Go pseudo-versions are ordinary pre-releases.

    Scanned by hand, not by regex: the SemVer grammar's pre-release
    alternation backtracks quadratically on a long run of digits."""
    if not v or len(v) > IOC_VERSION_MAX:
        return None
    if v[0] == "v":
        v = v[1:]
    v, plus, build = v.partition("+")
    if plus and not all(_ioc_semver_ident(b) for b in build.split(".")):
        return None
    core, dash, pre = v.partition("-")
    parts = core.split(".")
    if len(parts) != 3 or not all(_ioc_semver_number(p) for p in parts):
        return None
    if not dash:
        return (int(parts[0]), int(parts[1]), int(parts[2]), (1,))
    ids = []
    for p in pre.split("."):
        if not _ioc_semver_ident(p):
            return None
        if p.isdigit():
            if not _ioc_semver_number(p):
                return None
            ids.append((0, int(p)))
        else:
            ids.append((1, p))
    return (int(parts[0]), int(parts[1]), int(parts[2]), (0, tuple(ids)))


def _ioc_pep440_key(v: str) -> tuple | None:
    """PEP 440 ordering as a sortable tuple, or None.

    (epoch, release, pre, post, dev), following `packaging`: trailing zeros
    of the release are dropped (1.0 == 1.0.0); a dev release with no pre or
    post sorts before every pre-release; a missing post sorts below post0; a
    missing dev sorts above any dev. Each slot is (0,) for "below everything",
    (2,) for "above everything", or (1, value). The local part is ignored."""
    if not v or len(v) > IOC_VERSION_MAX:
        return None
    m = _IOC_PEP440.fullmatch(v)
    if not m:
        return None
    release = [int(p) for p in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    has_pre, has_post, has_dev = m.group("pre_l"), m.group("post"), m.group("dev_l")
    if has_pre:
        pre = (1, _IOC_PEP440_PRE[has_pre.lower()], int(m.group("pre_n") or 0))
    elif has_dev and not has_post:
        pre = (0,)
    else:
        pre = (2,)
    post = (1, int(m.group("post_n1") or m.group("post_n2") or 0)) if has_post else (0,)
    dev = (1, int(m.group("dev_n") or 0)) if has_dev else (2,)
    return (int(m.group("epoch") or 0), tuple(release), pre, post, dev)


def _ioc_version_key(eco: str, v: str) -> tuple | None:
    return _ioc_pep440_key(v) if eco == "pypi" else _ioc_semver_key(v)


def _ioc_bad_version(eco: str, v: str) -> _IocError:
    """The error for a comparator version that does not parse, naming the fix."""
    if eco == "oci":
        return _IocError(f'{_ioc_q(v)} is not an image tag or sha256 digest', "write =TAG or =sha256:<64 hex>")
    if _IOC_WORD.fullmatch(v):
        return _IocError(f'{_ioc_q(v)} is not a version', "an IOC names versions; latest moves")
    if eco == "pypi":
        return _IocError(f'{_ioc_q(v)} is not a PEP 440 version for pypi', "write 1.2.3, or ===TEXT for an exact string")
    parts = v.lstrip("v").split(".")
    if 1 <= len(parts) < 3 and all(p.isdigit() for p in parts):
        full = ".".join(parts + ["0"] * (3 - len(parts)))
        return _IocError(f'{_ioc_q(v)} is not a full version for {eco}', f"write {full}")
    return _IocError(f'{_ioc_q(v)} is not a SemVer version for {eco}', "write MAJOR.MINOR.PATCH")


def _ioc_comparator(eco: str, text: str) -> tuple:
    """One comparator as (op, key, raw). op is =, ===, >=, <=, > or <."""
    op = next((o for o in _IOC_OPS if text.startswith(o)), "")
    v = text[len(op):]
    op = "=" if op in ("", "==") else op
    if not v:
        raise _IocError(f'{_ioc_q(text)} has no version', "write =1.2.3")
    if v[0] in "^~":
        raise _IocError(f'{_ioc_q(text)} is a range', "^ and ~ ranges are not accepted; write >=X,<Y")
    if len(v) > IOC_VERSION_MAX:
        raise _IocError(f"a version is over {IOC_VERSION_MAX} characters")
    if any(p in ("x", "X", "*") for p in v.split(".")):
        raise _IocError(f'{_ioc_q(text)} is a wildcard', "wildcards are not accepted; write >=1.0.0,<2.0.0")
    if not _IOC_VERSION_CHARS.fullmatch(v):
        raise _ioc_bad_version(eco, v)
    if eco == "oci":
        if op != "=":
            raise _IocError(f'{_ioc_q(text)}: an image has no version order', "write =TAG or =sha256:<digest>, joined by ||")
        if v == "latest":
            raise _IocError('"latest" is not an image version', "an IOC names versions; latest moves")
        if not (_IOC_OCI_DIGEST.fullmatch(v) or (_IOC_OCI_TAG.fullmatch(v) and not v.startswith("sha256:"))):
            raise _ioc_bad_version(eco, v)
        return ("=", v, v)
    if op == "===":
        if eco != "pypi":
            raise _IocError(f'{_ioc_q(text)}: === is PEP 440 only', "write =1.2.3")
        return ("===", None, v)
    key = _ioc_version_key(eco, v)
    if key is None:
        raise _ioc_bad_version(eco, v)
    return (op, key, v)


def _ioc_parse_spec(eco: str, text: str | None) -> tuple | None:
    """A version spec, parsed once: None for any version, else a tuple of
    clauses (OR), each a tuple of comparators (AND)."""
    if text is None or text in _IOC_ANY_VERSION:
        return None
    if text.count("||") >= IOC_CLAUSES_MAX:
        raise _IocError(f"over {IOC_CLAUSES_MAX:,} alternatives", "split the entry over several lines")
    clauses = []
    for clause_text in text.split("||"):
        if not clause_text:
            raise _IocError(f'{_ioc_q(text)} has an empty clause', "write A||B, with a version on each side of ||")
        comps = []
        for comp in clause_text.split(","):
            if not comp:
                raise _IocError(f'{_ioc_q(text)} has an empty comparator', "write >=1.0.0,<2.0.0")
            if comp == "*":
                raise _IocError(f'{_ioc_q(text)} is a wildcard', "wildcards are not accepted; write >=1.0.0,<2.0.0")
            comps.append(_ioc_comparator(eco, comp))
        if sum(1 for op, _, _ in comps if op in ("=", "===")) > 1:
            raise _IocError(f'{_ioc_q(text)} puts two versions in one clause',
                            "a comma means AND; use || between alternative versions")
        clauses.append(tuple(comps))
    return tuple(clauses)


def _ioc_spec_text(spec: tuple | None) -> str | None:
    """The canonical text of a spec, for output: =4.1.1||=4.1.2, >=1.0.0,<2.0.0."""
    if spec is None:
        return None
    return "||".join(_IOC_UNDECIDABLE if c == _IOC_UNDECIDABLE else ",".join(op + raw for op, _, raw in c)
                     for c in spec)


def _ioc_compare(op: str, entry_key, version_key) -> bool:
    if op == "=":
        return version_key == entry_key
    if op == ">=":
        return version_key >= entry_key
    if op == "<=":
        return version_key <= entry_key
    if op == ">":
        return version_key > entry_key
    return version_key < entry_key


def _ioc_oci_digest(v: str) -> bool:
    return v.startswith("sha256:")


def _ioc_spec_contains(eco: str, spec: tuple | None, version: str) -> bool | None:
    """Whether a resolved item version is inside a spec. None when it cannot
    be decided: an OSV range that does not order, a version that does not
    parse, or an image digest compared with a tag."""
    if spec is None:
        return True
    raw = version[3:] if eco == "pypi" and version.startswith("===") else version
    key = None if eco == "oci" else _ioc_version_key(eco, raw)
    undecided = False
    for clause in spec:
        if clause == _IOC_UNDECIDABLE:
            undecided = True
            continue
        result: bool | None = True
        for op, ekey, eraw in clause:
            if eco == "oci":
                r = (raw == eraw) if _ioc_oci_digest(raw) == _ioc_oci_digest(eraw) else None
            elif op == "===":
                r = raw == eraw
            elif ekey is None:                  # an OSV versions[] string that does not parse
                r = raw.removeprefix("v") == eraw.removeprefix("v")
            elif key is None:
                r = None
            else:
                r = _ioc_compare(op, ekey, key)
            if r is False:
                result = False
                break
            if r is None:
                result = None
        if result is True:
            return True
        if result is None:
            undecided = True
    return None if undecided else False


IOC_FILE_MAX = 1 << 30                # 1 GiB, the most any --ioc file may be
IOC_WHOLE_JSON_MAX = 64 << 20         # a line file, an OSV array, or a document parsed whole
IOC_LINE_MAX = 1 << 20                # one line of either format
IOC_ENTRIES_MAX = 1_000_000           # across every file
IOC_NAME_MAX = 214                    # npm's limit, applied to every ecosystem
IOC_LINES_MAX = 4_000_000             # lines per file, blank and comment lines included
IOC_CLAUSES_MAX = 10_000              # alternatives (|| or versions[]) in one entry
IOC_EVENTS_MAX = 10_000               # events in one OSV range
IOC_JSON_DEPTH = 64                   # nesting in one OSV document or JSONL record; real ones use 5

_IOC_ECOSYSTEMS = {"npm": "npm", "pypi": "pypi", "pip": "pypi",
                   "crates": "crates", "crates.io": "crates", "cargo": "crates", "rust": "crates",
                   "go": "go", "golang": "go", "oci": "oci", "docker": "oci", "container": "oci",
                   "brew": "brew", "homebrew": "brew"}
IOC_CHECKABLE = ("npm", "pypi", "crates", "go", "oci", "brew")
# Accepted so one list can serve several tools, but this inventory never sees them.
_IOC_NOT_CHECKABLE = ("rubygems", "nuget", "maven", "packagist", "composer", "pub", "hex", "erlang",
                      "swift", "swifturl", "actions", "github-actions", "vscode", "open-vsx", "git")
_IOC_ECO_WORD = re.compile(r"[A-Za-z0-9.-]{1,64}")
_IOC_NAME = {
    "npm": re.compile(r"(?:@[a-z0-9~][a-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*"),
    "pypi": re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"),
    "crates": re.compile(r"[a-z0-9][a-z0-9-]{0,63}"),
    "go": re.compile(r"[A-Za-z0-9.~_+-]+(?:/[A-Za-z0-9.~_+-]+)*"),
    "oci": re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"),
    "brew": re.compile(r"[a-z0-9][a-z0-9@+._-]*(?:/[a-z0-9][a-z0-9@+._-]*){0,2}"),
}
_IOC_ATTR_VALUE = {"id": re.compile(r"[A-Za-z0-9._:-]{1,64}"),
                   "label": re.compile(r"[A-Za-z0-9._-]{1,48}")}
_IOC_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_IOC_WS = re.compile(r"[ \t]+")
_IOC_LINE_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
# A host entry with no path naming one of these would match every download from it.
_IOC_BROAD_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org",
                              "pypi.org", "files.pythonhosted.org", "crates.io", "proxy.golang.org",
                              "registry-1.docker.io", "ghcr.io"})


class IocEntry(NamedTuple):
    kind: str                 # "package" | "host"
    eco: str | None           # npm pypi crates go oci brew; None for a host
    name: str | None          # normalised by _ioc_norm_name
    spec: tuple | None        # None: any version; else clauses (OR) of comparators (AND)
    spec_text: str | None     # canonical: "=4.1.1||=4.1.2", ">=1.0.0,<2.0.0"
    host: str | None
    path: str                 # "" or "/a/b"
    exact_host: bool
    ref: str | None
    label: str | None
    frm: date | None          # shown, not applied (N2a)
    until: date | None
    source: int               # index into IocSet.sources, the --ioc order
    line: int | None


class IocSet:
    """Every loaded entry, indexed for lookup by package key and by host."""

    def __init__(self) -> None:
        self.packages: dict[tuple[str, str], list[IocEntry]] = {}
        self.host_suffix: dict[str, list[IocEntry]] = {}
        self.host_exact: dict[str, list[IocEntry]] = {}
        self.sources: list[dict] = []
        self.mtimes: list[float] = []
        self.has_window = False
        self.total = 0
        self.bytes_read = 0            # across every file, for the 1 GiB cap

    def add(self, e: IocEntry) -> None:
        self.total += 1
        if self.total > IOC_ENTRIES_MAX:
            raise _IocError("over 1,000,000 entries; split by ecosystem")
        if e.frm or e.until:
            self.has_window = True
        if e.kind == "package":
            self.packages.setdefault((e.eco, e.name), []).append(e)
        else:
            (self.host_exact if e.exact_host else self.host_suffix).setdefault(e.host, []).append(e)
        self.sources[e.source]["entries"][e.kind] += 1


def _ioc_norm_name(eco: str, name: str) -> str:
    """The one name normaliser, for IOC entries and inventory items alike.
    npm and go compare exactly; pypi by PEP 503; images as _oci_name does."""
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "crates":
        return name.lower().replace("_", "-")
    if eco == "oci":
        return _oci_name(name)[0]
    if eco == "brew":
        return name.lower()
    return name


def _ioc_valid_name(eco: str, name: str) -> bool:
    if not name or len(name) > IOC_NAME_MAX or not _IOC_NAME[eco].fullmatch(name):
        return False
    if eco == "go":
        parts = name.split("/")
        return "." in parts[0] and not any(p in (".", "..") for p in parts)
    return True


def _ioc_attrs(tokens: list[str]) -> dict:
    """id=, label=, from= and until=, validated. Stops at a comment."""
    attrs: dict[str, str] = {}
    for t in tokens:
        if t.startswith("#"):
            break
        key, eq, value = t.partition("=")
        if not eq:
            raise _IocError(f'{_ioc_q(t)} is not key=value', "a spec holds no spaces; write >=1.0.0,<2.0.0")
        if "#" in t:
            raise _IocError(f'{_ioc_q(t)} holds a #', "a comment starts with # after a space")
        key = key.lower()
        if key not in ("id", "label", "from", "until"):
            raise _IocError(f'unknown attribute {_ioc_q(key)}', "use id=, label=, from= or until=")
        if key in attrs:
            raise _IocError(f'"{key}=" is repeated', "give each attribute once")
        attrs[key] = value
    out: dict = {"ref": None, "label": None, "frm": None, "until": None}
    for key, pattern in _IOC_ATTR_VALUE.items():
        if key in attrs:
            if not pattern.fullmatch(attrs[key]):
                raise _IocError(f'{_ioc_q(key + "=" + attrs[key])} is not a valid {key}',
                                "letters, digits and . _ - (and : in an id)")
            out["ref" if key == "id" else key] = attrs[key]
    for key in ("from", "until"):
        if key in attrs:
            try:
                if not _IOC_DATE.fullmatch(attrs[key]):
                    raise ValueError
                out["frm" if key == "from" else key] = date.fromisoformat(attrs[key])
            except ValueError:
                raise _IocError(f'{_ioc_q(key + "=" + attrs[key])} is not a date', "write YYYY-MM-DD") from None
    if out["frm"] and out["until"] and out["until"] < out["frm"]:
        raise _IocError("until= is before from=", "swap them")
    return out


_IOC_NO_ATTRS = {"ref": None, "label": None, "frm": None, "until": None}


def _ioc_host_entry(body: str, attrs: dict, src: int, n: int | None, label: str) -> IocEntry:
    exact = body.startswith("=")
    text = body[1:] if exact else body
    host, slash, path = text.lower().partition("/")
    host = host.removesuffix(".")
    m = _TRUST_ENTRY.fullmatch(host + (slash + path if slash else ""))
    if "://" in text or "*" in text or not m:
        raise _IocError(f'{_ioc_q("host:" + body)} is not a host or host/path',
                        "no scheme, port, wildcard or IPv6; write host:evil.example or host:github.com/evil-org")
    path = (m.group(2) or "").rstrip("/")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise _IocError(f'{_ioc_q("host:" + body)} has a . or .. segment', "write the path as the server sees it")
    if not path and m.group(1) in _IOC_BROAD_HOSTS:
        print(f"actualis: --ioc {label} line {n}: host:{m.group(1)} matches every download from "
              f"{m.group(1)}; add a path", file=sys.stderr)
    return IocEntry("host", None, None, None, None, m.group(1), path, exact,
                    attrs["ref"], attrs["label"], attrs["frm"], attrs["until"], src, n)


def _ioc_line(text: str, ioc: IocSet, src: int, n: int, label: str) -> None:
    """One line of the actualis-ioc format."""
    if " " in text or "\t" in text:
        tokens = [t for t in _IOC_WS.split(text) if t]
    else:
        tokens = [text] if text else []
    if not tokens or tokens[0].startswith("#"):
        return
    if _IOC_LINE_CONTROL.search(text):
        raise _IocError("the line holds a control character", "remove it")
    entry = tokens[0]
    attrs = _ioc_attrs(tokens[1:]) if len(tokens) > 1 else _IOC_NO_ATTRS
    if "#" in entry:
        raise _IocError(f'{_ioc_q(entry)} holds a #', "a comment starts with # after a space")
    word, colon, body = entry.partition(":")
    if word.lower() == "host" and colon:
        ioc.add(_ioc_host_entry(body, attrs, src, n, label))
        return
    if not colon or not body:
        raise _IocError(f'{_ioc_q(entry)} is not ecosystem:name or host:name',
                        "write npm:name@=1.2.3 or host:evil.example")
    eco = _IOC_ECOSYSTEMS.get(word) or (_IOC_ECOSYSTEMS.get(word.lower()) if _IOC_ECO_WORD.fullmatch(word)
                                        else None)
    if eco is None:
        if word.lower() in _IOC_NOT_CHECKABLE:
            nc = ioc.sources[src]["not_checkable"]
            nc[word.lower()] = nc.get(word.lower(), 0) + 1
            return
        raise _IocError(f'unknown ecosystem {_ioc_q(word)}',
                        f"known: {' '.join(IOC_CHECKABLE)} (and not-checkable: {' '.join(_IOC_NOT_CHECKABLE)})")
    at = (-1 if eco == "brew" else body.rfind("@") if eco == "oci"
          else body.find("@", 1) if eco == "npm" else body.find("@"))
    name, spec_text = (body, None) if at < 0 else (body[:at], body[at + 1:])
    if spec_text == "":
        raise _IocError(f'{_ioc_q(entry)} ends in @', "write name@=1.2.3, or the name alone for any version")
    norm = _ioc_norm_name(eco, name) if len(name) <= IOC_NAME_MAX else ""
    if not _ioc_valid_name(eco, norm):
        raise _IocError(f'{_ioc_q(name)} is not a valid {eco} name')
    spec = _ioc_parse_spec(eco, spec_text) if spec_text is not None else None
    ioc.add(IocEntry._make(("package", eco, norm, spec, _ioc_spec_text(spec) if spec else None, None, "",
                            False, attrs["ref"], attrs["label"], attrs["frm"], attrs["until"], src, n)))


def _ioc_lines(data: bytes, start: int = 1):
    """(line number, bytes) for each line, CR LF or LF, with a leading BOM removed."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for n, raw in enumerate(data.split(b"\n"), start):
        yield n, raw[:-1] if raw.endswith(b"\r") else raw


def _ioc_decode(raw: bytes, n: int) -> str:
    if len(raw) > IOC_LINE_MAX:
        raise _IocError("the line is over 1 MiB")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _IocError("not UTF-8", "save the file as UTF-8") from None


def parse_ioc_lines(lines, ioc: IocSet, src: int, label: str) -> None:
    """The actualis-ioc line format, version 1, from (line, bytes) pairs. The
    first error stops the load."""
    for n, raw in lines:
        try:
            if len(raw) > IOC_LINE_MAX:
                raise _IocError("the line is over 1 MiB")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise _IocError("not UTF-8", "save the file as UTF-8") from None
            _ioc_line(text, ioc, src, n, label)
        except _IocError as exc:
            raise ValueError(f"--ioc {label} line {n}: {exc}") from None


def _ioc_first_byte(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.lstrip(b" \t\r\n")[:1]


def _ioc_source(path: Path) -> dict:
    return {"path": str(path.resolve()), "sha256": "", "format": "lines",
            "entries": {"package": 0, "host": 0}, "not_checkable": {},
            "skipped": 0, "first_skipped_line": None, "withdrawn": 0,
            "ranges_git": 0, "ranges_with_limit": 0, "skipped_ranges": 0}


_IOC_OSV_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi", "crates.io": "crates", "Go": "go"}
_IOC_OSV_EVENTS = ("introduced", "fixed", "last_affected", "limit")
_IOC_BOM = b"\xef\xbb\xbf"


def _ioc_skip(source: dict, line: int | None) -> None:
    source["skipped"] += 1
    if source["first_skipped_line"] is None and line is not None:
        source["first_skipped_line"] = line


def _ioc_osv_range(eco: str, kind: str, events: object, source: dict) -> list | str:
    """One OSV SEMVER or ECOSYSTEM range as clauses, or _IOC_UNDECIDABLE when
    it cannot be used: an event version that does not order, a malformed or
    unknown event, or more than IOC_EVENTS_MAX events. Those last are counted
    in skipped_ranges. A range is never just dropped: a dropped range would
    leave the versions inside it clean.

    Events are sorted by version; introduced opens an interval, fixed closes
    it below and last_affected at, the earliest close winning. limit is
    ignored, which leaves the interval open above: over-matching is the safe
    direction. An empty clause, (), means any version."""
    if not isinstance(events, list) or len(events) > IOC_EVENTS_MAX:
        source["skipped_ranges"] += 1
        return _IOC_UNDECIDABLE
    parsed = []
    for ev in events:
        if not isinstance(ev, dict) or len(ev) != 1:
            source["skipped_ranges"] += 1
            return _IOC_UNDECIDABLE
        [(k, v)] = ev.items()
        if k not in _IOC_OSV_EVENTS or not isinstance(v, str):
            source["skipped_ranges"] += 1
            return _IOC_UNDECIDABLE
        parsed.append((k, v))
    if any(k == "limit" for k, _ in parsed):
        source["ranges_with_limit"] += 1
    check = _ioc_semver_key if kind == "SEMVER" or eco != "pypi" else _ioc_pep440_key
    keyed = []
    for k, v in parsed:
        if k == "limit":
            continue
        if k == "introduced" and v == "0":
            keyed.append(((0,), 0, k, v, None))
            continue
        key = _ioc_version_key(eco, v) if check(v) is not None else None
        if key is None:
            source["skipped_ranges"] += 1
            return _IOC_UNDECIDABLE
        keyed.append(((1, key), 0 if k == "introduced" else 1, k, v, key))
    keyed.sort(key=lambda t: t[:2])
    clauses: list = []
    low, is_open = None, False
    for _, _, k, v, key in keyed:
        if k == "introduced":
            if not is_open:
                is_open, low = True, (None if key is None else (">=", key, v))
        elif is_open:
            high = ("<" if k == "fixed" else "<=", key, v)
            clauses.append((low, high) if low else (high,))
            is_open = False
    if is_open:
        clauses.append((low,) if low else ())
    if not clauses:                          # no introduced: the schema requires one
        source["skipped_ranges"] += 1
        return _IOC_UNDECIDABLE
    return clauses


def parse_ioc_osv(records, ioc: IocSet, src: int, label: str) -> None:
    """OSV records, as (line or None, record) pairs. Malformed records and
    affected[] elements are counted and skipped, never fatal; an ecosystem
    this inventory cannot see is counted as not checkable. references[] never
    become host entries."""
    source = ioc.sources[src]
    nc = source["not_checkable"]
    for line, rec in records:
        if not isinstance(rec, dict):
            _ioc_skip(source, line)
            continue
        if rec.get("withdrawn") is not None:
            source["withdrawn"] += 1
            continue
        rid = rec.get("id")
        ref = rid if isinstance(rid, str) and _IOC_ATTR_VALUE["id"].fullmatch(rid) else None
        affected = rec.get("affected")
        if not isinstance(affected, list) or not affected:
            _ioc_skip(source, line)
            continue
        for aff in affected:
            pkg = aff.get("package") if isinstance(aff, dict) else None
            name = pkg.get("name") if isinstance(pkg, dict) else None
            eco_text = pkg.get("ecosystem") if isinstance(pkg, dict) else None
            if not (isinstance(name, str) and name and isinstance(eco_text, str) and eco_text):
                _ioc_skip(source, line)
                continue
            eco = _IOC_OSV_ECOSYSTEMS.get(eco_text)
            if eco is None:
                key = re.sub(r"[^a-z0-9.-]", "-", eco_text.lower().split(":", 1)[0])[:32] or "-"
                nc[key] = nc.get(key, 0) + 1
                continue
            norm = _ioc_norm_name(eco, name) if len(name) <= IOC_NAME_MAX else ""
            if not _ioc_valid_name(eco, norm):
                _ioc_skip(source, line)
                continue
            clauses: list = []
            usable = any_version = False
            versions = aff.get("versions")
            for v in versions if isinstance(versions, list) else ():
                # versions[] is the authority's own strings: kept even when they do not
                # parse, compared as text then. A string that could not be printed is dropped.
                if isinstance(v, str) and _IOC_VERSION_CHARS.fullmatch(v):
                    k = _ioc_version_key(eco, v)
                    clauses.append((("=", k, v if k is not None else v.removeprefix("v")),))
                    usable = True
            ranges = aff.get("ranges")
            for r in ranges if isinstance(ranges, list) else ():
                kind = r.get("type") if isinstance(r, dict) else None
                if kind == "GIT":
                    source["ranges_git"] += 1
                    continue
                usable = True
                if kind not in ("SEMVER", "ECOSYSTEM"):
                    source["skipped_ranges"] += 1
                    clauses.append(_IOC_UNDECIDABLE)
                    continue
                out = _ioc_osv_range(eco, kind, r.get("events"), source)
                if out == _IOC_UNDECIDABLE:
                    clauses.append(_IOC_UNDECIDABLE)
                    continue
                for c in out:
                    if c == ():
                        any_version = True
                    else:
                        clauses.append(c)
            if len(clauses) > IOC_CLAUSES_MAX:       # too many to compare: every version is undecidable
                source["skipped_ranges"] += 1
                clauses = [_IOC_UNDECIDABLE]
            spec = None if any_version or not usable else tuple(dict.fromkeys(clauses))
            try:
                ioc.add(IocEntry("package", eco, norm, spec, _ioc_spec_text(spec), None, "", False,
                                 ref, None, None, None, src, line))
            except _IocError as exc:
                raise ValueError(f"--ioc {label}" + (f" line {line}" if line else "") + f": {exc}") from None


def _ioc_jsonl(lines, label: str):
    """(line, record) for each non-blank JSONL line."""
    for n, raw in lines:
        if not raw.strip():
            continue
        try:
            _ioc_json_depth(raw)
            yield n, json.loads(_ioc_decode(raw, n))
        except _IocError as exc:
            raise ValueError(f"--ioc {label} line {n}: {exc}") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"--ioc {label} line {n}: invalid JSON ({exc.msg}) — one OSV record per line") from None
        except RecursionError:
            raise ValueError(f"--ioc {label} line {n}: JSON nested too deeply") from None


_IOC_JSON_SPECIAL = re.compile(rb'["\[\]{}]')


def _ioc_json_depth(data: bytes) -> None:
    """Refuse JSON nested deeper than IOC_JSON_DEPTH before json parses it.

    A hand-written scan, linear in the input: it jumps from one quote or
    bracket to the next, and over each string to its closing quote, so a
    bracket inside a string does not count. (A regex for JSON strings
    backtracks quadratically on a run of escaped quotes.)"""
    if data.count(b"[") + data.count(b"{") <= IOC_JSON_DEPTH:
        return
    depth = pos = 0
    find = _IOC_JSON_SPECIAL.search
    while True:
        m = find(data, pos)
        if m is None:
            return
        c, pos = data[m.start()], m.end()
        if c == 34:                                  # " : skip the string
            while True:
                q = data.find(b'"', pos)
                if q < 0:
                    return                           # unclosed: json refuses it
                k = q
                while k > pos and data[k - 1] == 92:     # count the backslashes before it
                    k -= 1
                pos = q + 1
                if (q - k) % 2 == 0:
                    break
        elif c in (91, 123):
            depth += 1
            if depth > IOC_JSON_DEPTH:
                raise _IocError(f"JSON nested over {IOC_JSON_DEPTH} levels", "an OSV record is a few levels deep")
        else:
            depth -= 1


def _ioc_size(n: int) -> str:
    if n % (1 << 30) == 0:
        return f"{n >> 30} GiB"
    if n % (1 << 20) == 0:
        return f"{n >> 20} MiB"
    return f"{n:,} bytes"


def _ioc_count_bytes(ioc: IocSet, n: int, label: str) -> None:
    ioc.bytes_read += n
    if ioc.bytes_read > IOC_FILE_MAX:
        raise ValueError(f"--ioc {label}: over {_ioc_size(IOC_FILE_MAX)} across all --ioc files")


_IOC_CHUNK = 1 << 20


def _ioc_stream(fh, digest, label: str, ioc: IocSet, limit: int, hint: str):
    """(line, bytes) from an open file, hashing every byte as it is read.
    Reads are 1 MiB chunks; the unfinished tail of a line is carried and
    refused once it passes IOC_LINE_MAX, so no line is ever buffered whole,
    and the byte and line caps hold while reading."""
    n = total = 0
    rest, head = b"", True
    while True:
        chunk = fh.read(_IOC_CHUNK)
        if chunk:
            total += len(chunk)
            digest.update(chunk)
            if total > limit:
                raise ValueError(f"--ioc {label}: over {_ioc_size(limit)} — {hint}")
            _ioc_count_bytes(ioc, len(chunk), label)
            if head:
                chunk, head = chunk.removeprefix(_IOC_BOM), False
        parts = (rest + chunk).split(b"\n") if chunk else ([rest] if rest else [])
        rest = parts.pop() if chunk else b""
        if len(rest) > IOC_LINE_MAX:
            raise ValueError(f"--ioc {label} line {n + len(parts) + 1}: the line is over 1 MiB")
        if n + len(parts) > IOC_LINES_MAX:
            raise ValueError(f"--ioc {label}: over {IOC_LINES_MAX:,} lines — split the file")
        for raw in parts:
            n += 1
            yield n, raw[:-1] if raw.endswith(b"\r") else raw
        if not chunk:
            return


def _ioc_peek(fh) -> bytes:
    """The first byte that is not a BOM or whitespace, then rewind."""
    first, head, seen = b"", True, 0
    while not first and seen <= IOC_WHOLE_JSON_MAX:
        chunk = fh.read(1 << 16)
        seen += len(chunk)
        if not chunk:
            break
        if head:
            chunk, head = chunk.removeprefix(_IOC_BOM), False
        first = chunk.lstrip(b" \t\r\n")[:1]
    fh.seek(0)
    return first


def _ioc_osv_document(data: bytes, first: bytes, label: str):
    """Records from an OSV file read whole: an object, an array, or JSONL
    when an object is followed by "Extra data"."""
    body = data.removeprefix(_IOC_BOM)
    try:
        _ioc_json_depth(body)
    except _IocError as exc:
        raise ValueError(f"--ioc {label}: {exc}") from None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"--ioc {label} byte offset {exc.start + len(data) - len(body)}: not UTF-8") from None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        if first == b"{" and exc.msg == "Extra data":
            return _ioc_jsonl(_ioc_lines(data), label), "osv-jsonl"
        offset = len(text[:exc.pos].encode("utf-8")) + len(data) - len(body)
        raise ValueError(f"--ioc {label} byte offset {offset}: invalid JSON ({exc.msg})") from None
    except RecursionError:
        raise ValueError(f"--ioc {label}: JSON nested too deeply") from None
    return ((None, r) for r in (doc if isinstance(doc, list) else [doc])), "osv-json"


def _ioc_load_file(path: Path, ioc: IocSet, src: int, label: str) -> None:
    """One file: detect the format from its first byte, parse, hash every
    byte. Only a whole OSV document is read whole, and only up to
    IOC_WHOLE_JSON_MAX; everything else is read a bounded line at a time."""
    source = ioc.sources[src]
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        st = os.fstat(fh.fileno())
        if st.st_size > IOC_FILE_MAX:
            raise ValueError(f"--ioc {label}: over {_ioc_size(IOC_FILE_MAX)}")
        first = _ioc_peek(fh)
        if first == b"[" and st.st_size > IOC_WHOLE_JSON_MAX:
            raise ValueError(f"--ioc {label}: an OSV array over {_ioc_size(IOC_WHOLE_JSON_MAX)} — "
                             "convert to JSONL: jq -c '.[]' f > f.jsonl")
        if first == b"{" and st.st_size > IOC_WHOLE_JSON_MAX:
            source["format"] = "osv-jsonl"
            lines = _ioc_stream(fh, digest, label, ioc, IOC_FILE_MAX, "split the file")
            parse_ioc_osv(_ioc_jsonl(lines, label), ioc, src, label)
        elif first in (b"{", b"["):
            data = fh.read(IOC_WHOLE_JSON_MAX + 1)
            if len(data) > IOC_WHOLE_JSON_MAX:     # grew since stat, or not a regular file
                raise ValueError(f"--ioc {label}: over {_ioc_size(IOC_WHOLE_JSON_MAX)} — "
                                 "convert to JSONL: jq -c '.[]' f > f.jsonl")
            digest.update(data)
            _ioc_count_bytes(ioc, len(data), label)
            records, source["format"] = _ioc_osv_document(data, first, label)
            parse_ioc_osv(records, ioc, src, label)
        else:
            lines = _ioc_stream(fh, digest, label, ioc, IOC_WHOLE_JSON_MAX, "split the file")
            parse_ioc_lines(lines, ioc, src, label)
    source["sha256"] = digest.hexdigest()
    ioc.mtimes.append(st.st_mtime)


def load_ioc(paths: list[str]) -> IocSet:
    """Every --ioc file, in order. Any problem is a ValueError naming the file,
    and the line where there is one. Never called unless --ioc was given."""
    ioc = IocSet()
    for src, given in enumerate(paths):
        label = clean(given)
        path = Path(given)
        ioc.sources.append(_ioc_source(path))
        try:
            _ioc_load_file(path, ioc, src, label)
        except OSError as exc:
            raise ValueError(f"--ioc {label}: cannot read: {clean(exc.strerror or str(exc))}") from None
        except _IocError as exc:                 # an entry past the cap
            raise ValueError(f"--ioc {label}: {clean(str(exc))}") from None
        except ValueError as exc:
            # Messages quote the offending text so it can be fixed. It comes
            # from an untrusted file, so it is cleaned before it reaches stderr.
            raise ValueError(clean(str(exc)).replace("\n", " ")) from None
    checkable = sum(s["entries"]["package"] + s["entries"]["host"] for s in ioc.sources)
    if checkable == 0:
        nc: Counter = Counter()
        for s in ioc.sources:
            nc.update(s["not_checkable"])
        detail = ", ".join(f"{k} {v}" for k, v in sorted(nc.items(), key=lambda kv: (-kv[1], kv[0])))
        raise ValueError(f"--ioc: none of the {sum(nc.values())} entries can be checked"
                         + (f" (not checkable: {detail})" if detail else ""))
    return ioc


_IOC_RANK = {"match": 2, "unresolved": 1}
_IOC_HOST_LABELS = 127
_IOC_DOWNGRADE = ("npm", "pypi", "crates")      # a registry the entry may not describe
# Hosts that serve the public registry itself (an alias, a mirror run by the
# registry, or yarn's default): a match from one of these is the public package,
# not a private registry's namesake (R3B12). Anything else downgrades.
_IOC_PUBLIC_REGISTRIES = {
    "npm": frozenset({"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"}),
    "pypi": frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"}),
    "crates": frozenset({"crates.io", "index.crates.io", "static.crates.io"}),
}


def _ioc_zero_totals() -> dict:
    return {"match": 0, "unresolved": 0, "refused": 0, "suppressed": 0, "clean_name_matches": 0,
            "undecidable": 0, "items_checked": 0, "items_not_checkable": {"lockfile": 0, "no_host": 0, "other": 0}}


def _ioc_resolved(item: dict) -> list[tuple[str, str]]:
    """(normalised name, version) to compare, the version "" when the item
    does not name exactly one release. An npm alias (`x@npm:evil@1.0.0`)
    carries the target as `package` (B1); the alias name is a second pair,
    unresolved, since the version belongs to the target."""
    eco, ver = item["ecosystem"], item.get("version") or ""
    name = _ioc_norm_name(eco, item["package"])
    if eco == "npm":
        v = ver[1:] if ver[:1] in ("=", "v") else ver
        pairs = [(name, v if _ioc_semver_key(v) else "")]
        if item.get("alias"):
            pairs.append((item["alias"], ""))
        return pairs
    if eco == "pypi":                        # `uvx x@latest` names a tag, not a release
        exact = item.get("pinned") or ver.startswith("===") or _ioc_pep440_key(ver)
        return [(name, ver if exact else "")]
    if eco == "crates":
        v = ver.removeprefix("=")
        return [(name, v if item.get("pinned") and _ioc_semver_key(v) else "")]
    if eco == "go":
        return [(name, ver if ver.startswith("v") and _ioc_semver_key(ver) else "")]
    if eco == "oci":
        ok = _IOC_OCI_DIGEST.fullmatch(ver) or (ver and ver != "latest" and not ver.startswith("sha256:"))
        return [(name, ver if ok else "")]
    return [(name, "")]                                # brew records no version


_IOC_TARBALL_VERSION = re.compile(r"-v?[0-9]+\.[0-9]+\.[0-9]+")


def _ioc_url_name(item: dict) -> str | None:
    """The npm package a git or tarball URL install most likely is: the name
    before /-/ in a registry tarball URL, else the last path segment without
    .git, .tgz and a -1.2.3 suffix. A guess, so a hit on it is only ever
    unresolved (name-from-url), never a match and never clean."""
    if item.get("ecosystem") != "npm" or not item.get("url"):
        return None
    path = url_path(item["url"]).replace("%40", "@").replace("%2f", "/").replace("%2F", "/")
    if "/-/" in path:
        name = path.split("/-/", 1)[0].strip("/")
    else:
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if len(name) > 2 * IOC_NAME_MAX:
            return None
        name = name.removesuffix(".git")
        for ext in (".tgz", ".tar.gz"):
            if name.endswith(ext):
                name = name[:-len(ext)]
                m = _IOC_TARBALL_VERSION.search(name)
                name = name[:m.start()] if m else name
    return name if _ioc_valid_name("npm", name) else None


def _ioc_host_entries(ioc: IocSet, host: str) -> list[IocEntry]:
    """Host entries that could match: exact on the host, suffix on each label
    boundary. A host of more labels than DNS allows is refused rather than
    partly checked, so the caller fails closed."""
    if not ioc.host_suffix and not ioc.host_exact:
        return []
    labels = host.split(".")
    if len(labels) > _IOC_HOST_LABELS:
        raise _IocError(f"a host of over {_IOC_HOST_LABELS} labels")
    found = list(ioc.host_exact.get(host, ()))
    for i in range(len(labels)):
        found += ioc.host_suffix.get(".".join(labels[i:]), ())
    return found


# Every item field matching reads, and nothing else: apply_ioc hands
# match_ioc a view of exactly these, and memoises on them, so a field added
# to matching without being added here cannot be read (and the memo cannot
# confuse two items that differ in it).
IOC_ITEM_FIELDS = ("kind", "program", "ecosystem", "package", "version", "pinned", "alias",
                   "host", "host_inferred", "url")


def _ioc_go_prefixes(path: str) -> list[str]:
    """The /-boundary prefixes of a Go package path, longest first: the
    modules it could belong to (`evil.example/m/cmd/x` is in `evil.example/m`).
    Only prefixes an entry could name: a dot in the first element, at most
    IOC_NAME_MAX characters."""
    if "." not in path.split("/", 1)[0]:
        return []
    out, cut = [], path.rfind("/", 0, IOC_NAME_MAX + 1)
    while cut > 0:
        out.append(path[:cut])
        cut = path.rfind("/", 0, cut)
    return [p for p in out if "/" in p or "." in p]


def _ioc_host_checkable(item: dict) -> bool:
    """A host the command named, or one the session itself supplied as a URL
    (a resolved git remote, a brew tap's repository). A registry default
    (`npm i x` and registry.npmjs.org) has no URL and is never matched."""
    return bool(item.get("host")) and (not item.get("host_inferred") or bool(item.get("url")))


def match_ioc(item: dict, ioc: IocSet) -> tuple | None:
    """(verdict, reason, entries, flag key, undecided) for one item, or None.

    The verdict is the strongest over every entry: match, then unresolved;
    "clean" when names matched and every version fell outside. entries are
    all the entries at that strength, by (source, line). The trust list is
    never consulted."""
    hits: list[tuple[str, str, IocEntry, str]] = []
    clean_hit = False
    eco = item.get("ecosystem")
    if item["kind"] == "install" and eco in IOC_CHECKABLE and item.get("package"):
        for name, version in _ioc_resolved(item):
            # A Go install names a package; lists name the module it is in.
            names = [(name, False)] + [(m, True) for m in (_ioc_go_prefixes(name) if eco == "go" else ())]
            for listed, prefix in names:
                for e in ioc.packages.get((eco, listed), ()):
                    if e.spec is None:
                        verdict, reason = "match", "any-version"
                    elif not version:
                        verdict, reason = "unresolved", "version-unresolved"
                    else:
                        try:
                            inside = _ioc_spec_contains(eco, e.spec, version)
                        except Exception:        # noqa: BLE001 -- fail closed: undecidable, never clean
                            inside = None
                        if inside is False:
                            clean_hit = True
                            continue
                        verdict, reason = (("match", "version-in-spec") if inside
                                           else ("unresolved", "module-prefix" if prefix else "undecidable"))
                    if verdict == "match" and eco in _IOC_DOWNGRADE and not item.get("host_inferred") \
                       and item.get("host") not in _IOC_PUBLIC_REGISTRIES[eco]:
                        verdict, reason = "unresolved", "private-registry"
                    hits.append((verdict, reason, e, f"{eco}:{listed}@{redact(version) if version else '?'}"))
    url_name = _ioc_url_name(item) if item["kind"] == "install" else None
    for e in ioc.packages.get(("npm", url_name), ()) if url_name else ():
        hits.append(("unresolved", "name-from-url", e, f"npm:{url_name}@?"))
    host = (item.get("host") or "").removesuffix(".")
    if _ioc_host_checkable(item):
        for e in _ioc_host_entries(ioc, host):
            if _host_path_match(e.host, e.path, item, e.exact_host, ioc=True):
                hits.append(("match", "host", e, f"host:{'=' if e.exact_host else ''}{e.host}{e.path}"))
    if not hits:
        return ("clean", None, [], None, False) if clean_hit else None
    best = max(_IOC_RANK[h[0]] for h in hits)
    top = sorted((h for h in hits if _IOC_RANK[h[0]] == best),
                 key=lambda h: (h[2].source, h[2].line or 0))
    undecided = any(h[1] in ("undecidable", "module-prefix") for h in hits)
    return top[0][0], top[0][1], [h[2] for h in top], top[0][3], undecided


def _ioc_failed_closed(item: dict) -> tuple:
    """What an item becomes when checking it raised: unresolved, reason
    "error", against a placeholder entry, so it is listed, flagged medium
    and counted, never clean."""
    entry = IocEntry("error", item.get("ecosystem"), None, None, None, None, "", False,
                     None, None, None, None, -1, None)
    return "unresolved", "error", [entry], f"error:{item.get('ecosystem') or item.get('program') or '?'}", True


def _ioc_coverage(item: dict) -> str:
    """items_checked, or which items_not_checkable bucket an item is in."""
    # A package built at run time (`npm i "$(…)"`, `xargs npm i`) was not checked.
    dynamic = bool(item.get("dynamic"))
    if item.get("_unresolved"):
        return "other"                       # a host not normalised, or redirected transport
    if (item["kind"] == "install" and item["ecosystem"] in IOC_CHECKABLE and item["package"]
            and not (dynamic and "$" in item["package"])) or _ioc_host_checkable(item):
        return "checked"
    if item["kind"] == "install" and not item["package"] and not dynamic:
        return "lockfile"
    return "no_host" if not item["host"] else "other"


def apply_ioc(fleet: "Fleet", ioc: IocSet | None) -> None:
    """Match every inventory item, refused ones included, and turn each
    (verdict, key) group of the rest into one flag: match is high
    (network-ioc), unresolved is medium (network-ioc-unresolved). Refused
    rows are listed and never flagged. Run once, after apply_network_policy."""
    fleet.ioc = ioc
    fleet.ioc_rows = []
    fleet.ioc_totals = totals = _ioc_zero_totals()
    for item in fleet.network:
        item["ioc"] = None
    if ioc is None:
        return
    groups: dict[tuple[str, str], list[dict]] = {}
    memo: dict[tuple, tuple | None] = {}
    # A command read only in part (a cap or nesting limit, R10) cannot be
    # cleared: it is listed, and flagged unresolved.
    for item in getattr(fleet, "network_unreadable", ()):
        if not item.get("_listed"):
            item["_listed"] = True
            fleet.network.append(item)
    for item in fleet.network:
        refused = bool(item.get("_refused"))
        if not refused:
            bucket = _ioc_coverage(item)
            if bucket == "checked":
                totals["items_checked"] += 1
            else:
                totals["items_not_checkable"][bucket] += 1
        # Items that agree on every field matching reads get the same answer, so
        # forty installs of one package cost one lookup, however long the list.
        view = {k: item.get(k) for k in IOC_ITEM_FIELDS}
        unresolved = item.get("_unresolved")
        memo_key = tuple(view.values()) + (unresolved,)
        if item.get("_unreadable"):
            entry = IocEntry("error", None, None, None, None, None, "", False,
                             None, None, None, None, -1, None)
            memo_key = ("_unreadable",)
            memo[memo_key] = ("unresolved", "unreadable", [entry], "unreadable", False)
        if memo_key not in memo:
            try:
                memo[memo_key] = match_ioc(view, ioc)
            except Exception:                    # noqa: BLE001 -- fail closed, never clean
                memo[memo_key] = _ioc_failed_closed(view)
            if unresolved and (memo[memo_key] is None or memo[memo_key][0] != "match"):
                # Its host could not be normalised, or the command sent the transfer
                # somewhere else: it cannot be cleared (R15, R3B11).
                entry = IocEntry("error", item.get("ecosystem"), None, None, None, None, "", False,
                                 None, None, None, None, -1, None)
                memo[memo_key] = ("unresolved", unresolved, [entry],
                                  f"{unresolved}:{item.get('program') or '?'}@{item.get('host') or '?'}", False)
        found = memo[memo_key]
        if found is None:
            continue
        verdict, reason, matched, key, undecided = found
        totals["undecidable"] += 1 if undecided and not refused else 0
        if verdict == "clean":
            totals["clean_name_matches"] += 0 if refused else 1
            continue
        row = {"verdict": verdict, "reason": reason, "refused": refused, "entries": matched,
               "item": item, "key": key, "flag_id": None, "suppressed": False}
        fleet.ioc_rows.append(row)
        if refused:
            totals["refused"] += 1
            continue
        item["ioc"] = verdict
        totals[verdict] += 1
        groups.setdefault((verdict, key), []).append(row)
    for (verdict, key), rows in sorted(groups.items()):
        severity, category = ("high", "network-ioc") if verdict == "match" else ("med", "network-ioc-unresolved")
        fid = flag_id(severity, [category], key)
        suppressed = fid in fleet.suppressions
        if suppressed:
            fleet.suppressed_flags += 1
            totals["suppressed"] += 1
        first = min(rows, key=lambda r: (r["entries"][0].source, r["entries"][0].line or 0))
        entry = first["entries"][0]
        items = [r["item"] for r in rows]
        latest = max(items, key=lambda i: (_net_utc_key(i["ts"]), i["project"]))
        program = latest["program"]
        why = {"private-registry": f"installed from {latest['host']}; the entry describes the public registry",
               "undecidable": "the version cannot be ordered against the entry",
               "module-prefix": "the package is inside the listed module; the version cannot be ordered against it",
               "name-from-url": "the name is read from the URL",
               "error": "the item could not be checked; treated as unresolved",
               "unreadable": "part of the command was nested or long past what is read; "
                             "treated as unresolved",
               "host-unresolved": "the host is written in a form that cannot be normalised; "
                                  "treated as unresolved",
               "redirected": "the command sends the transfer through a proxy or another address; "
                             "treated as unresolved"}.get(first["reason"])
        evidence = (f"{len(items)} {'download' if key.startswith(('host:', 'host-unresolved:', 'redirected:')) else 'install'}(s) of {key} "
                    f"via {program} ({latest['approval']})"
                    + (f" — ran it ({program})" if any(i["exec"] for i in items) else "")
                    + (" (call failed)" if any(i["failed"] is True for i in items) else "")
                    + f"; {entry.ref or entry.label or 'listed'}"
                    + (f"; {why}" if why else ""))
        fleet.flags.append({
            "id": fid, "severity": severity, "categories": [category],
            "program": key, "project": latest["project"], "when": latest["ts"],
            "evidence": redact(clean(evidence))[:240],
            "had_secret": False, "suppressed": suppressed,
            "suppressed_reason": fleet.suppressions.get(fid, ""),
        })
        for r in rows:
            r["flag_id"], r["suppressed"] = fid, suppressed


IOC_ROWS_SHOWN = 50
IOC_REFS_CAP = 20
_IOC_REASON_TEXT = {"version-unresolved": "version not resolved", "undecidable": "undecidable",
                    "module-prefix": "in a listed module",
                    "private-registry": "private registry", "name-from-url": "name from URL",
                    "error": "could not check", "unreadable": "not fully read",
                    "host-unresolved": "host not normalised", "redirected": "transport redirected"}


def _ioc_entry_json(e: IocEntry) -> dict:
    return {"kind": e.kind, "ecosystem": e.eco, "name": e.name, "spec": e.spec_text,
            "host": e.host, "path": e.path or None, "exact_host": e.exact_host,
            "ref": e.ref, "label": e.label,
            "from": e.frm.isoformat() if e.frm else None,
            "until": e.until.isoformat() if e.until else None,
            "source": e.source, "line": e.line}


def _ioc_utc(ts: datetime | None) -> datetime | None:
    return ts.replace(tzinfo=timezone.utc) if ts is not None and ts.tzinfo is None else ts


def _ioc_ordered_rows(fleet: "Fleet") -> list[dict]:
    """Rows in a total order, so the bytes are deterministic: not refused
    first, then match before unresolved, then newest, then the item, then
    (source, line) of the first entry."""
    rows = sorted(fleet.ioc_rows, key=lambda r: (r["entries"][0].source, r["entries"][0].line or 0))
    rows.sort(key=lambda r: _net_order_key(r["item"]), reverse=True)
    rows.sort(key=lambda r: (r["refused"], -_IOC_RANK[r["verdict"]]))
    return rows


def ioc_json(fleet: "Fleet", raw: bool = False) -> dict:
    """network.ioc. Always an object: without --ioc it is enabled false with
    zero totals, so every path keeps one type."""
    t = fleet.ioc_totals
    totals = {**t, "items_not_checkable": dict(t["items_not_checkable"])}
    ioc = fleet.ioc
    if ioc is None:
        return {"enabled": False, "sources": [], "totals": totals, "matches": [], "matches_truncated": False}
    start, end = _ioc_utc(fleet.first_ts), _ioc_utc(fleet.last_ts)
    sources = []
    for s, mtime in zip(ioc.sources, ioc.mtimes):
        modified = datetime.fromtimestamp(mtime, timezone.utc)
        sources.append({**s, "entries": dict(s["entries"]), "not_checkable": dict(sorted(s["not_checkable"].items())),
                        "mtime_in_window": bool(start and end and start <= modified <= end)})
    rows = _ioc_ordered_rows(fleet)
    matches = []
    for r in rows[:NETWORK_ITEMS_CAP]:
        matches.append({
            "verdict": r["verdict"], "reason": r["reason"], "refused": r["refused"],
            "suppressed": r["suppressed"], "flag_id": r["flag_id"],
            "refs": sorted({e.ref for e in r["entries"] if e.ref})[:IOC_REFS_CAP],
            "labels": sorted({e.label for e in r["entries"] if e.label})[:IOC_REFS_CAP],
            "entry": _ioc_entry_json(r["entries"][0]),
            "item": _net_public(r["item"], raw, fleet.with_prompts),
        })
    return {"enabled": True, "sources": sources, "totals": totals, "matches": matches,
            "matches_truncated": len(rows) > NETWORK_ITEMS_CAP}


# ---------------------------------------------------------------------------
# Host reputation (offline). actualis only READS the cache that the companion
# command actualis-reputation writes (docs/reputation.md); nothing here can
# open a socket, and --self-check keeps proving it.

def reputation_dir() -> Path:
    """Where actualis-reputation keeps its cache. Never created here."""
    env = os.environ.get("ACTUALIS_REPUTATION_DIR")
    if env:
        return Path(env).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "actualis" / "reputation"
    base = os.environ.get("XDG_CACHE_HOME")
    if not base:
        try:
            base = str(Path.home() / ".cache")
        except RuntimeError:                 # no home directory at all
            raise OSError("no home directory; set ACTUALIS_REPUTATION_DIR") from None
    return Path(base) / "actualis" / "reputation"


NET_MARK = "\u2295\U0001F310"       # circled plus, globe: on every line that reports network use, nowhere else
# (escapes, not literals: the source stays readable as cp1252, which Windows tools default to)
REPUTATION_LISTS = ("mw-4b", "se-4b", "uws-4b", "uwsa-4b", "pha-4b")
REPUTATION_THREAT = {"mw-4b": "MALWARE", "se-4b": "SOCIAL_ENGINEERING", "uws-4b": "UNWANTED_SOFTWARE",
                     "uwsa-4b": "UNWANTED_SOFTWARE", "pha-4b": "POTENTIALLY_HARMFUL_APPLICATION"}
REPUTATION_THREAT_TEXT = {"MALWARE": "malware", "SOCIAL_ENGINEERING": "phishing (social engineering)",
                          "UNWANTED_SOFTWARE": "unwanted software",
                          "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful application"}
REPUTATION_CONFIRM_TTL = 30 * 60         # Google: warn only on a full-hash answer under 30 minutes old
REPUTATION_STALE_DAYS = 7
GSB_ADVISORY = "Advisory provided by Google"
GSB_ADVISORY_URL = "https://developers.google.com/safe-browsing/v4/advisory"
SB_HOST_SUFFIXES = 5                     # the exact host, then hosts from the last five labels
SB_PATH_PREFIXES = 4                     # "/" and up to three directories below it
_SB_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def reputation_skip(host: str) -> bool:
    """Hosts never looked up and never sent anywhere: loopback, private,
    link-local, IPv6 literals, single-label names and the local-only
    suffixes. They are never on a public list, and naming them to a provider
    would say which internal systems the agents touch."""
    h = (host or "").lower().rstrip(".")
    if not h or h.startswith("[") or "." not in h:
        return True
    if h.endswith((".internal", ".home.arpa", ".lan", ".localdomain", ".corp", ".home", ".intranet",
                   ".private", ".test", ".invalid")):
        return True
    if _local_host(h):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        a, b, c = int(parts[0]), int(parts[1]), int(parts[2])
        return (a == 0 or (a == 100 and 64 <= b <= 127) or a >= 224
                or (a == 192 and b == 0 and c in (0, 2)) or (a == 198 and b in (18, 19))
                or (a == 198 and b == 51 and c == 100) or (a == 203 and b == 0 and c == 113))
    return False


def _sb_path_canon(path: str) -> str:
    """Safe Browsing's path canonicalisation, minus the query (never hashed):
    percent-decode until stable, resolve . and .., collapse //, re-escape
    bytes <= 0x20, >= 0x7f, '#' and '%'."""
    path = path.split("#", 1)[0].split("?", 1)[0] or "/"
    raw = path.encode("utf-8", "surrogatepass")
    for _ in range(8):                   # %2541 -> %41 -> A; bounded
        nxt = _NET_PCT.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
        if nxt == raw:
            break
        raw = nxt
    segs: list[bytes] = []
    for seg in raw.split(b"/"):
        if seg in (b"", b"."):
            continue
        if seg == b"..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    out = b"/" + b"/".join(segs)
    if raw.endswith(b"/") and segs:
        out += b"/"
    return "".join(chr(b) if 0x20 < b < 0x7f and b not in (0x23, 0x25) else f"%{b:02X}" for b in out)


def sb_expressions(host: str, path: str = "") -> list[str]:
    """The host-suffix / path-prefix expressions Safe Browsing hashes for one
    canonical host (and, when the inventory recorded one, a URL path)."""
    host = host.lower().rstrip(".")
    while ".." in host:
        host = host.replace("..", ".")
    hosts = [host]
    if not _SB_IPV4.fullmatch(host):
        tail = host.split(".")[-5:]
        for k in range(len(tail) - 1):        # never the bare TLD
            cand = ".".join(tail[k:])
            if cand not in hosts:
                hosts.append(cand)
    hosts = hosts[:SB_HOST_SUFFIXES]
    paths = ["/"]
    if path and path != "/":
        exact = _sb_path_canon(path)
        dirs = exact.split("/")[1:-1]
        paths = [exact] if exact != "/" else []
        prefix = "/"
        for d in [""] + dirs[:SB_PATH_PREFIXES - 1]:
            prefix = prefix + d + "/" if d else prefix
            if prefix not in paths:
                paths.append(prefix)
    return [h + p for h in hosts for p in paths]


def sb_hash(expr: str) -> bytes:
    return hashlib.sha256(expr.encode("utf-8")).digest()


REPUTATION_FILE_MAX = 64 << 20           # a prefix list, or any cache file, past this is refused
REPUTATION_LOG_TAIL = 64 << 10
_REPUTATION_FILE_NAME = re.compile(r"[a-z0-9-]+\.[0-9a-f]{16}\.prefixes")


class ReputationData:
    """What the reputation cache holds, read once per run. status is "ok",
    "absent" (never updated) or "corrupt" (a list failed its check: treated as
    no lists, so a gate cannot pass on tampered data)."""

    def __init__(self, directory: "Path | None" = None) -> None:
        self.directory = directory
        self.status = "absent"
        self.error: str | None = None
        self.lists: dict[str, bytes] = {}
        self.state: dict[str, dict] = {}
        self.oldest: datetime | None = None
        self.confirmations: dict[bytes, dict] = {}
        self.confirmations_error: str | None = None
        self.vt: dict[str, dict] = {}
        self.vt_threshold = 2
        self.vt_error: str | None = None
        self.vt_present = False
        self.last_network: dict | None = None


def _parse_utc(text: object) -> "datetime | None":
    if not isinstance(text, str):
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _read_cache_file(path: Path, limit: int = REPUTATION_FILE_MAX) -> "bytes | None":
    """A cache file's bytes; None if absent. OSError for a symlink, a
    non-regular file or one over `limit`."""
    if os.path.islink(path):
        raise OSError(f"{path.name} is a symlink; refusing it")
    try:
        fh = _open_regular(path, binary=True)
    except FileNotFoundError:
        return None
    with fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{path.name} is over {limit >> 20} MiB")
    return data


def _b64_bytes(text: object, size: int | None = None) -> "bytes | None":
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return None
    return raw if size is None or len(raw) == size else None


def _load_confirmations(path: Path) -> dict:
    raw = _read_cache_file(path)
    if raw is None:
        return {}
    doc = json.loads(raw)
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("entries"), list):
        raise ValueError("confirmations.json: not schema 1")
    out: dict[bytes, dict] = {}
    for e in doc["entries"]:
        if not isinstance(e, dict):
            continue
        p = _b64_bytes(e.get("prefix"), 4)
        at, until = _parse_utc(e.get("confirmed_at")), _parse_utc(e.get("cache_until"))
        if p is None or at is None or until is None or not isinstance(e.get("full_hashes"), list):
            continue
        hashes = []
        for fh in e["full_hashes"]:
            h = _b64_bytes(fh.get("hash"), 32) if isinstance(fh, dict) else None
            types = fh.get("threat_types") if isinstance(fh, dict) else None
            if h is None or not isinstance(types, list) or not all(isinstance(t, str) for t in types):
                continue
            hashes.append({"hash": h, "threat_types": sorted(set(types)), "canary": fh.get("canary") is True})
        out[p] = {"full_hashes": hashes, "confirmed_at": at, "cache_until": until}
    return out


def _load_vt(path: Path, data: "ReputationData") -> None:
    raw = _read_cache_file(path)
    if raw is None:
        return
    data.vt_present = True
    doc = json.loads(raw)
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("results"), list):
        raise ValueError("vt/results.json: not schema 1")
    t = doc.get("vt_threshold")
    data.vt_threshold = t if isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= 100 else 2
    for r in doc["results"]:
        if not isinstance(r, dict) or not isinstance(r.get("host"), str):
            continue
        at = _parse_utc(r.get("checked_at"))
        stats = r.get("stats") if isinstance(r.get("stats"), dict) else {}
        clean_stats = {k: v for k, v in stats.items()
                       if k in ("malicious", "suspicious", "harmless", "undetected", "timeout")
                       and isinstance(v, int) and not isinstance(v, bool) and v >= 0}
        if at is None or r.get("status") not in ("found", "unknown"):
            continue
        data.vt[r["host"].lower()] = {"stats": clean_stats, "status": r["status"], "checked_at": at}


def reputation_last_network(directory: "Path | None" = None) -> "dict | None":
    """The newest valid line of network-log.jsonl, or None. Never raises."""
    try:
        path = (directory or reputation_dir()) / "network-log.jsonl"
        raw = _read_cache_file(path)
    except OSError:
        return None
    if not raw:
        return None
    for line in reversed(raw[-REPUTATION_LOG_TAIL:].decode("utf-8", "replace").splitlines()):
        ok, rec = _json_line(line)
        if ok and isinstance(rec, dict) and _parse_utc(rec.get("at")) and isinstance(rec.get("provider"), str):
            return {"at": rec["at"], "provider": rec["provider"]}
    return None


REPUTATION_FLAG_CATEGORIES = ("reputation-listed", "reputation-candidate", "reputation-suspicious",
                              "reputation-stale")
_REPUTATION_RANK = {"listed": 5, "candidate": 4, "suspicious": 3, "not-listed": 2, "unknown": 1, "none": 0}


def _reputation_zero_totals() -> dict:
    return {k: 0 for k in ("checked", "skipped", "none", "candidate", "listed", "not_listed",
                           "suspicious", "unknown")}


def _prefix_in(blob: bytes, p: bytes) -> bool:
    """Binary search over a sorted run of 4-byte records."""
    lo, hi = 0, len(blob) // 4
    while lo < hi:
        mid = (lo + hi) // 2
        v = blob[mid * 4:mid * 4 + 4]
        if v < p:
            lo = mid + 1
        elif v > p:
            hi = mid
        else:
            return True
    return False


def _confirmation_fresh(c: dict, now: datetime) -> bool:
    at = c["confirmed_at"]
    if at > now + timedelta(minutes=1):      # dated in the future: a bad clock or a tampered file
        return False
    return now < min(at + timedelta(seconds=REPUTATION_CONFIRM_TTL), c["cache_until"])


def gsb_verdict(host: str, path: str, data: "ReputationData", now: datetime) -> dict:
    out = {"state": "none", "threat_types": [], "checked_at": None, "candidates": {}}
    hashes = [sb_hash(e) for e in sb_expressions(host, path)]
    hits: dict[bytes, int] = {}
    for h in hashes:
        if any(_prefix_in(blob, h[:4]) for blob in data.lists.values()):
            hits[h[:4]] = hits.get(h[:4], 0) + 1
    if not hits:
        return out
    full = set(hashes)
    types: set[str] = set()
    all_fresh = True
    for p, n in hits.items():
        c = data.confirmations.get(p)
        if c is None or not _confirmation_fresh(c, now):
            all_fresh = False
            out["candidates"][p] = n
            continue
        out["checked_at"] = max(filter(None, (out["checked_at"], c["confirmed_at"])))
        for fh in c["full_hashes"]:
            if fh["hash"] in full:
                types.update(fh["threat_types"])
    if types:
        out["state"], out["threat_types"] = "listed", sorted(types)
    elif all_fresh:
        out["state"] = "not-listed"
    else:
        out["state"] = "candidate"
    return out


def vt_verdict(host: str, data: "ReputationData", now: datetime) -> "dict | None":
    r = data.vt.get(host)
    if r is None or now - r["checked_at"] > timedelta(days=REPUTATION_STALE_DAYS):
        return None
    m, s = r["stats"].get("malicious", 0), r["stats"].get("suspicious", 0)
    if r["status"] == "unknown":
        state = "unknown"
    elif m >= data.vt_threshold:
        state = "listed"
    elif m or s:
        state = "suspicious"
    else:
        state = "not-listed"
    return {"state": state, "malicious": m, "suspicious": s, "threshold": data.vt_threshold,
            "checked_at": r["checked_at"]}


def _utc_hm(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def apply_reputation(fleet: "Fleet", data: "ReputationData | None", now: "datetime | None" = None) -> None:
    """Check every non-refused item with a host against the local cache. One
    flag per (category, provider:host); a stale list is one flag. Run once,
    after apply_ioc. Never opens a socket."""
    fleet.reputation = data
    fleet.reputation_totals = totals = _reputation_zero_totals()
    fleet.reputation_candidates = {}
    for item in fleet.network:
        item["reputation"] = None
    if data is None:
        return
    now = now or datetime.now(timezone.utc)
    memo: dict[tuple, tuple] = {}
    groups: dict[tuple[str, str], dict] = {}
    for item in fleet.network:
        host = item.get("host")
        if item.get("_refused") or not host:
            continue
        if reputation_skip(host):
            item["reputation"] = {"state": "skipped", "provider": None, "threat_types": [],
                                  "checked_at": None, "advisory": None}
            totals["skipped"] += 1
            continue
        path = url_path(item["url"]) if item.get("url") else ""
        key = (host, path)
        if key not in memo:
            g = gsb_verdict(host, path, data, now) if data.lists else None
            memo[key] = (g, vt_verdict(host, data, now))
        g, v = memo[key]
        totals["checked"] += 1
        if g:
            for p, n in g["candidates"].items():
                fleet.reputation_candidates[p] = max(fleet.reputation_candidates.get(p, 0), n)
        best = None                              # (rank, provider, verdict)
        if g:
            best = (_REPUTATION_RANK[g["state"]], "google-safe-browsing", g)
        if v and (best is None or _REPUTATION_RANK[v["state"]] > best[0]):
            best = (_REPUTATION_RANK[v["state"]], "virustotal", v)
        state = best[2]["state"] if best else "none"
        provider = best[1] if best and state != "none" else None
        google = provider == "google-safe-browsing"
        checked = best[2]["checked_at"] if best else None
        item["reputation"] = {"state": state, "provider": provider,
                              "threat_types": list(best[2].get("threat_types", [])) if best else [],
                              "checked_at": checked.isoformat(timespec="seconds") if checked else None,
                              "advisory": GSB_ADVISORY if google and state in ("listed", "candidate") else None}
        totals[state.replace("-", "_")] += 1
        if state in ("listed", "candidate", "suspicious"):
            category = {"listed": "reputation-listed", "candidate": "reputation-candidate",
                        "suspicious": "reputation-suspicious"}[state]
            gk = (category, f"{'gsb' if google else 'vt'}:{host}")
            grp = groups.setdefault(gk, {"items": [], "verdict": best[2], "google": google, "host": host,
                                         "types": set()})
            grp["items"].append(item)
            grp["types"].update(best[2].get("threat_types", ()))
    for (category, key), grp in sorted(groups.items()):
        items, v, host = grp["items"], grp["verdict"], grp["host"]
        latest = max(items, key=lambda i: (_net_utc_key(i["ts"]), i["project"]))
        n = f"{len(items)} download(s) via {latest['program']}"
        if category == "reputation-listed" and grp["google"]:
            what = " or ".join(REPUTATION_THREAT_TEXT.get(t, t.lower()) for t in sorted(grp["types"]))
            evidence = (f"{host} is currently listed by Google Safe Browsing as suspected {what} "
                        f"(checked {_utc_hm(v['checked_at'])}); {n}")
        elif category == "reputation-listed":
            evidence = (f"{host} flagged malicious by {v['malicious']} VirusTotal engines "
                        f"(checked {_utc_hm(v['checked_at'])}); {n}")
        elif category == "reputation-candidate":
            evidence = (f"possible match for {host} in Google Safe Browsing lists, not confirmed; "
                        f"run `actualis-reputation confirm`; {n}")
        else:
            evidence = (f"{host}: {v['malicious']} malicious and {v['suspicious']} suspicious VirusTotal "
                        f"engines, below the threshold of {v['threshold']} (checked {_utc_hm(v['checked_at'])}); {n}")
        advisory = category in ("reputation-listed", "reputation-candidate") and grp["google"]
        _reputation_flag(fleet, "high" if category == "reputation-listed" else "med", category, key,
                         latest, evidence, ". " + GSB_ADVISORY if advisory else "")
    if data.oldest and now - data.oldest > timedelta(days=REPUTATION_STALE_DAYS):
        days = (now - data.oldest).days
        _reputation_flag(fleet, "med", "reputation-stale", "gsb-lists", None,
                         f"Google Safe Browsing lists are {days} days old and can miss new threats; "
                         f"run `actualis-reputation update`")


def _reputation_flag(fleet: "Fleet", severity: str, category: str, key: str, latest: "dict | None",
                     evidence: str, suffix: str = "") -> None:
    """suffix (the Google advisory) is appended after the body is clipped, so
    a long host cannot cut it off."""
    fid = flag_id(severity, [category], key)
    suppressed = fid in fleet.suppressions
    if suppressed:
        fleet.suppressed_flags += 1
    fleet.flags.append({
        "id": fid, "severity": severity, "categories": [category], "program": key,
        "project": latest["project"] if latest else "", "when": latest["ts"] if latest else None,
        "evidence": redact(clean(evidence))[:240 - len(suffix)] + suffix, "had_secret": False,
        "suppressed": suppressed, "suppressed_reason": fleet.suppressions.get(fid, ""),
    })


def load_reputation(directory: "Path | None" = None) -> ReputationData:
    """Read the cache, read-only. A bad list makes the whole set corrupt; bad
    confirmations or VirusTotal files are ignored with a note (ignoring them
    can only leave a host a candidate, never clear it)."""
    root = directory or reputation_dir()
    data = ReputationData(root)
    data.last_network = reputation_last_network(root)
    try:                                     # first: VirusTotal results count even with no Safe Browsing lists
        _load_vt(root / "vt" / "results.json", data)
    except (OSError, ValueError, RecursionError, TypeError, AttributeError) as exc:
        data.vt, data.vt_error = {}, str(exc) or "nested too deeply"
    gsb = root / "gsb"
    try:
        raw = _read_cache_file(gsb / "state.json")
        if raw is None:
            return data
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("lists"), list):
            raise ValueError("state.json is not schema 1")
        by_name = {e["name"]: e for e in doc["lists"] if isinstance(e, dict) and isinstance(e.get("name"), str)}
        for name in REPUTATION_LISTS:
            e = by_name.get(name)
            if e is None:
                raise ValueError(f"state.json has no {name} list")
            fname, sha, count = e.get("file"), e.get("sha256"), e.get("prefix_count")
            fetched = _parse_utc(e.get("fetched_at"))
            if not (isinstance(fname, str) and _REPUTATION_FILE_NAME.fullmatch(fname)
                    and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)
                    and isinstance(count, int) and not isinstance(count, bool) and fetched):
                raise ValueError(f"state.json: the {name} entry is malformed")
            blob = _read_cache_file(gsb / fname)
            if blob is None:
                raise ValueError(f"{name}: {fname} is missing")
            if len(blob) != 4 * count or hashlib.sha256(blob).hexdigest() != sha:
                raise ValueError(f"{name}: checksum does not match")
            if any(blob[i:i + 4] > blob[i + 4:i + 8] for i in range(0, len(blob) - 4, 4)):
                raise ValueError(f"{name}: prefixes are not sorted")
            if fetched > datetime.now(timezone.utc) + timedelta(days=1):
                raise ValueError(f"{name}: fetched_at is in the future")
            data.lists[name] = blob
            data.state[name] = {"fetched_at": fetched, "next_update_at": _parse_utc(e.get("next_update_at")),
                                "prefix_count": count, "version": e.get("version")}
            data.oldest = fetched if data.oldest is None else min(data.oldest, fetched)
    except (OSError, ValueError, RecursionError, TypeError, AttributeError) as exc:   # JSONDecodeError is a ValueError
        data.status, data.error, data.lists, data.state = "corrupt", str(exc), {}, {}
        return data
    data.status = "ok"
    try:
        data.confirmations = _load_confirmations(gsb / "confirmations.json")
    except (OSError, ValueError, RecursionError, TypeError, AttributeError) as exc:
        data.confirmations_error = str(exc) or "nested too deeply"
    return data


def render_reputation(fleet: "Fleet", c: "C") -> None:
    """The reputation block of the NETWORK section. A match is not network
    use, so no NET_MARK here."""
    data = fleet.reputation
    if data is None:
        return
    t = fleet.reputation_totals
    if data.status != "ok" and not data.vt:
        print(f"  {c.yellow}reputation: no usable Safe Browsing lists ({data.status}); "
              f"run actualis-reputation update{c.off}")
        return
    if data.oldest:
        age_h = int((datetime.now(timezone.utc) - data.oldest).total_seconds() // 3600)
        age = f"{age_h} h old" if age_h < 48 else f"{age_h // 24} days old"
        head = f"reputation: Google Safe Browsing lists from {_utc_hm(data.oldest)}, {age}"
    else:
        head = "reputation: VirusTotal results only"
    sus = f" \u00b7 {t['suspicious']} suspicious" if t["suspicious"] else ""
    print(f"  {head} \u00b7 {t['listed']} listed \u00b7 {t['candidate']} candidate{sus}"
          f" \u00b7 {t['checked']} checked \u00b7 {t['skipped']} private skipped")
    shown = 0
    for f in fleet.flags:
        if not set(f["categories"]) & set(REPUTATION_FLAG_CATEGORIES) or shown >= IOC_ROWS_SHOWN:
            continue
        high = f["severity"] == "high"
        color, mark = (c.red, "\u25b2") if high else (c.yellow, "?")
        print(f"    {color}{mark}{c.off} {clip(f['evidence'], NET_VIEW_WIDTH - 6)}")
        shown += 1
    if data.lists and (t["listed"] or t["candidate"]):
        print(f"  {c.dim}{GSB_ADVISORY}: {GSB_ADVISORY_URL}. Lists can be wrong both ways; "
              f"see docs/reputation.md{c.off}")


def render_ioc(fleet: "Fleet", c: "C", raw: bool = False) -> None:
    """The IOC block of NETWORK. Nothing without --ioc. Every printed field
    is cleaned; item fields come from the redacted public view."""
    if fleet.ioc is None:
        return
    j = ioc_json(fleet, raw)
    t = j["totals"]
    pad = " " * 13
    listed = sum(s["entries"]["package"] + s["entries"]["host"] for s in j["sources"])
    rows = j["matches"]
    if not rows:
        print(f"  {'IOC':<11}{c.green}no match{c.off} in {num(t['items_checked'])} checkable downloads "
              f"({num(listed)} entries)")
    else:
        parts = [f"{c.red}{num(t['match'])} match{c.off}", f"{c.yellow}{num(t['unresolved'])} unresolved{c.off}"]
        parts += [f"{num(t[k])} {k}" for k in ("refused", "suppressed") if t[k]]
        print(f"  {'IOC':<11}" + " · ".join(parts))
    for s in j["sources"]:
        print(f"{pad}{clip(clean(Path(s['path']).name), 32)}  sha256 {s['sha256'][:12]}  {s['format']}  "
              f"{num(s['entries']['package'])} package · {num(s['entries']['host'])} host"
              + (f"  {c.yellow}modified during the window{c.off}" if s["mtime_in_window"] else ""))
        extra = []
        if s["not_checkable"]:
            extra.append("not checkable: " + " · ".join(f"{clean(k)} {num(v)}" for k, v in sorted(
                s["not_checkable"].items(), key=lambda kv: (-kv[1], kv[0]))))
        if s["skipped"]:
            extra.append(f"skipped {num(s['skipped'])} malformed"
                         + (f" (first at line {s['first_skipped_line']})" if s["first_skipped_line"] else ""))
        if s["withdrawn"]:
            extra.append(f"withdrawn {num(s['withdrawn'])}")
        if s["skipped_ranges"]:
            extra.append(f"{num(s['skipped_ranges'])} unusable range(s), read as undecidable")
        if extra:
            print(f"{pad}{c.dim}{' · '.join(extra)}{c.off}")
    if rows:
        nc = [f"{k.replace('_', ' ')} {num(v)}" for k, v in t["items_not_checkable"].items() if v]
        seen = t["items_checked"] + sum(t["items_not_checkable"].values())
        print(f"{pad}{c.dim}checked {num(t['items_checked'])} of {num(seen)} downloads"
              + (" · not checkable: " + " · ".join(nc) if nc else "")
              + (f" · undecidable {num(t['undecidable'])}" if t["undecidable"] else "") + c.off)
    if fleet.ioc.has_window:
        print(f"{pad}{c.dim}from/until are shown, not yet applied{c.off}")
    for r in rows[:IOC_ROWS_SHOWN]:
        i, e = r["item"], r["entry"]
        if e["kind"] == "host":
            what = f"host {e['host']}{e['path'] or ''} ({i['program']})"
        else:
            name = i["package"] or e["name"] or i["host"] or "?"
            eco = i["ecosystem"] or i["program"]
            what = (f"{eco} {name} ({i['version'] or 'no version'})" if r["verdict"] == "unresolved"
                    else f"{eco} {name}@{i['version']}" if i["version"] else f"{eco} {name}")
        if r["refused"]:
            tail = "never ran"
        elif r["suppressed"]:
            tail = "suppressed"
        elif r["verdict"] == "match":
            tail = (r["refs"] or r["labels"] or ["listed"])[0]
        else:
            tail = _IOC_REASON_TEXT.get(r["reason"], r["reason"])
        label = "REFUSED" if r["refused"] else r["verdict"].upper()
        color = c.dim if r["refused"] else c.red if r["verdict"] == "match" else c.yellow
        print(f"  {color}{label:<11}{c.off}{clip(clean(what), 34):<34} {c.dim}{clip(clean(i['project']), 10):<10} "
              f"{(i['ts'] or '')[:10]:<10} {('—' if r['refused'] else i['approval']):<8}{c.off} {clean(tail)}")
    more = len(fleet.ioc_rows) - min(len(rows), IOC_ROWS_SHOWN)
    if more > 0:
        print(f"  {'':<11}{c.dim}+{num(more)} more (--json for all){c.off}")
    print(f"  {c.dim}No match is not \"not affected\": this covers the transcripts still on this machine in the{c.off}")
    print(f"  {c.dim}window, and lockfile installs, scripts and postinstall hooks are not visible. "
          f"See --explain ioc.{c.off}")


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


def load_suppressions(rejected: list[str] | None = None) -> dict[str, str]:
    """fingerprint -> reason. Malformed lines are skipped, never fatal. An id
    is read case-insensitively and may be followed by a tab; a line whose id
    is not one this tool emits matches nothing, so it is not loaded, and
    `rejected`, when given, receives it (for --suppressions to show)."""
    out: dict[str, str] = {}
    for path in suppression_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = clean(line).strip()       # clean() first: a tab becomes a space
            if not line or line.startswith("#"):
                continue
            fp, _, reason = line.partition(" ")
            fp = fp[:64].lower()
            if not fp:
                continue
            if not _FINGERPRINT.fullmatch(fp):
                if rejected is not None:
                    rejected.append(line[:120])
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
    # One entry is one line: a newline in the reason wrote a second, silent
    # suppression (`--reason $'ok\n620e24b6 x'`). Refuse every control and
    # line-breaking character rather than guess what was meant.
    bad = next((ch for ch in reason
                if ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F or ch in "\u2028\u2029"), None)
    if bad is not None:
        raise ValueError(f"--reason must be one line of text: it contains {bad!r}. "
                         f"Newlines and control characters are refused.")
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
        (Path(os.environ.get("GEMINI_CLI_HOME") or "~").expanduser() / ".gemini" / "tmp",
         "Gemini CLI", "GEMINI_CLI_HOME"),
        ((Path(os.environ.get("QWEN_RUNTIME_DIR") or os.environ.get("QWEN_HOME") or "~/.qwen")
          .expanduser() / "projects"),
         "Qwen Code", "QWEN_RUNTIME_DIR" if os.environ.get("QWEN_RUNTIME_DIR") else "QWEN_HOME"),
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
        "  GEMINI_CLI_HOME=/path/holding/.gemini actualis",
        "  QWEN_HOME=/path/to/.qwen actualis      (or QWEN_RUNTIME_DIR)",
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
        found = [f for f in root.rglob("*.json") if f.parent.name == "chats"]
        for f in list(root.rglob("*.jsonl")) + found:
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


_TS_MIN = datetime.min.replace(tzinfo=timezone.utc)


def parse_ts(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):     # transcripts are untrusted: any JSON type
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        # Always aware UTC: a naive stamp is read as UTC, an offset is converted.
        # Mixing naive and aware crashed every comparison, and a -05:00 record
        # was bucketed under its local date while the buckets are UTC dates.
        return (dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None
                else dt.astimezone(timezone.utc))
    except (ValueError, OverflowError):      # 9999-12-31T23:00-05:00 has no UTC time
        return None


# The largest count _tokens() accepts. A quadrillion tokens is ~10^6 times any
# real session; past it a value is hostile or corrupt, and a 400-digit integer
# (valid JSON) raised OverflowError at the first `/ 1e6` and stopped every mode.
MAX_TOKEN_VALUE = 10 ** 15


def _tokens(v) -> int:
    """A token count (or duration) from an untrusted transcript: a finite,
    non-negative number no larger than MAX_TOKEN_VALUE, else 0. A string, null,
    bool, negative or absurd count must not crash the run or move the spend."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return 0
    if v != v or v < 0 or v > MAX_TOKEN_VALUE:     # NaN, negative, inf, absurd
        return 0
    return int(v)


def _absurd_count(v) -> bool:
    """A number too large to be a real count: _tokens() reads it as 0, and the
    Fleet counts its line as unparsable so the skip is never silent."""
    return (not isinstance(v, bool) and isinstance(v, (int, float))
            and v == v and v > MAX_TOKEN_VALUE)


def _str_or(v, default):
    """v when it is a non-empty string, else default: an untrusted field of
    the wrong type is absent."""
    return v if isinstance(v, str) and v else default


_S_IFMT, _S_IFREG = 0o170000, 0o100000


def _open_regular(path: Path, binary: bool = False):
    """Open a transcript-side file for reading, only if it is a regular file.

    Every file an agent can write (transcripts, .project_root, projects.json,
    session logs) is opened through here. A FIFO opened with a plain open()
    blocks until a writer appears, so one `mkfifo` under ~/.gemini or
    ~/.claude would hang every run, --fail-on in CI included; a device such as
    /dev/zero behind a symlink would never end. O_NONBLOCK makes the open of a
    FIFO return at once, and fstat on the descriptor (not the path, which could
    be swapped in between) rejects anything that is not a regular file. Raises
    OSError, which every caller already treats as an unreadable file.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        if os.fstat(fd).st_mode & _S_IFMT != _S_IFREG:
            raise OSError(f"not a regular file: {path}")
    except BaseException:
        os.close(fd)
        raise
    if binary:
        return os.fdopen(fd, "rb")
    return os.fdopen(fd, "r", encoding="utf-8", errors="replace")


def _json_line(text: str) -> "tuple[bool, object]":
    """Decode one transcript line (or embedded JSON string): (ok, value).

    The one place transcript JSON is decoded. ok is False when the text is
    unreadable: malformed, or nested deeper than the decoder can go, which
    raises RecursionError rather than ValueError. Callers count it and move on;
    one hostile line must never stop the run. A blank line is (True, None).
    """
    if not text or text.isspace():
        return True, None
    try:
        return True, json.loads(text)
    except (ValueError, RecursionError):
        return False, None


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
    total_in = _tokens(usage.get("input_tokens"))
    cached = _tokens(usage.get("cached_input_tokens"))
    out = _tokens(usage.get("output_tokens"))
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
HUMAN_REFUSALS = frozenset({"user-rejected", "copilot:denied-interactively-by-user",
                            "gemini:user-denied", "qwen:user-denied"})


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
    total_in = _tokens(usage.get("inputTokens"))
    rd = _tokens(usage.get("cacheReadTokens"))
    wr = _tokens(usage.get("cacheWriteTokens"))
    out = _tokens(usage.get("outputTokens"))
    fresh = max(total_in - rd - wr, 0)
    read_mult = OPENAI_CACHED_MULT if r.provider == "openai" else r.cache_read
    return (fresh / 1e6 * r.input
            + rd / 1e6 * r.input * read_mult
            + wr / 1e6 * r.input * CACHE_WRITE_ASSUMED_MULT
            + out / 1e6 * r.output)


# --------------------------------------------------------------------------
# Gemini CLI and Qwen Code
#
# Formats read from source, not from anyone's transcripts:
#   Gemini CLI  google-gemini/gemini-cli @204db94 (v0.63.0 stable, 0.64 preview),
#               packages/core/src/services/chatRecordingService.ts and
#               chatRecordingTypes.ts; config/storage.ts and projectRegistry.ts
#               for where files live.
#   Qwen Code   QwenLM/qwen-code @6212189 (0.25.1),
#               packages/core/src/services/chatRecordingService.ts.
# Qwen forked Gemini CLI but replaced chat recording with a Claude-Code-like
# tree of records, so the two have separate readers.
# --------------------------------------------------------------------------

def _existing_dirs(candidates: list[Path]) -> list[Path]:
    """The candidates that are directories, each once (by resolved path)."""
    out: list[Path] = []
    for p in candidates:
        try:
            if p.is_dir() and p.resolve() not in {q.resolve() for q in out}:
                out.append(p)
        except OSError:
            continue
    return out


def gemini_roots() -> list[Path]:
    """Gemini CLI's per-project directories live under <home>/.gemini/tmp.

    $GEMINI_CLI_HOME replaces the home directory itself (paths.ts homedir()),
    so it names the directory that holds .gemini, not .gemini. A macOS
    Seatbelt sandbox run (SANDBOX=sandbox-exec) writes under
    <home>/.cache/.gemini instead (storage.ts), so both are read."""
    env = os.environ.get("GEMINI_CLI_HOME")
    home = Path(env).expanduser() if env else Path.home()
    return _existing_dirs([home / ".gemini" / "tmp", home / ".cache" / ".gemini" / "tmp"])


def qwen_roots() -> list[Path]:
    """Qwen Code writes <runtime>/projects/<cwd slug>/chats/<session>.jsonl.

    The runtime directory is $QWEN_RUNTIME_DIR when set, else the global
    directory: $QWEN_HOME (which names the .qwen directory itself), else
    ~/.qwen. When the runtime directory was moved, the global one is read too,
    so sessions written before the move are not lost."""
    env = os.environ.get("QWEN_HOME")
    base = Path(env).expanduser() if env else Path.home() / ".qwen"
    runtime = os.environ.get("QWEN_RUNTIME_DIR")
    cands = ([Path(runtime).expanduser() / "projects"] if runtime else []) + [base / "projects"]
    return _existing_dirs(cands)


def _agent_root(root: Path, agent: str) -> Path:
    """What --root names for Gemini or Qwen: the vendor directory (~/.gemini,
    ~/.qwen) or the directory of project directories (tmp, projects)."""
    sub = root / ("tmp" if agent == "gemini" else "projects")
    return sub if sub.is_dir() else root


def _project_dirs(root: Path) -> list[Path]:
    """Per-project directories under a Gemini tmp or Qwen projects root. A
    root that is itself one project (it holds chats/) is that project."""
    if (root / "chats").is_dir():
        return [root]
    try:
        return sorted(d for d in root.iterdir() if d.is_dir())
    except OSError as exc:
        print(f"actualis: cannot read {root}: {exc.strerror or exc}", file=sys.stderr)
        return []


def gemini_session_files(project_dir: Path) -> list[Path]:
    """chats/*.jsonl (v0.39+), chats/*.json (the legacy single object), and
    chats/<parent session>/*.jsonl (subagents). A rewrite leaves backups named
    *.jsonl.unreadable-<ms> and *.jsonl.tmp-<pid>; their suffix excludes them."""
    chats = project_dir / "chats"
    out: list[Path] = []
    try:
        entries = sorted(chats.iterdir())
    except OSError:
        return out
    for e in entries:
        try:
            if e.is_dir():
                out.extend(sorted(g for g in e.iterdir() if g.suffix == ".jsonl" and g.is_file()))
            elif e.suffix in (".jsonl", ".json") and e.is_file():
                out.append(e)
        except OSError:
            continue
    return out


def qwen_session_files(project_dir: Path) -> list[Path]:
    try:
        return sorted(f for f in (project_dir / "chats").glob("*.jsonl") if f.is_file())
    except OSError:
        return []


_ROOT_MARKER_MAX = 4096
# A legacy (<= v0.38) Gemini session is one JSON document, decoded whole (about
# ten times its size in memory). Past this it is counted unparsable, not read.
GEMINI_JSON_MAX = 64 << 20


def gemini_registry(root: Path) -> dict[str, str]:
    """slug -> project path, inverted from <runtime>/projects.json
    ({"projects": {"<abs path>": "<slug>"}}). Wrong types are absent."""
    try:
        with _open_regular(root.parent / "projects.json") as fh:
            text = fh.read(1 << 22)
    except OSError:
        return {}
    ok, doc = _json_line(text)
    projects = doc.get("projects") if ok and isinstance(doc, dict) else None
    if not isinstance(projects, dict):
        return {}
    return {slug: path for path, slug in projects.items()
            if isinstance(path, str) and path and isinstance(slug, str) and slug}


def gemini_project_root(project_dir: Path, registry: dict[str, str]) -> str:
    """The real project path: tmp/<slug>/.project_root (plain text), else the
    projects.json registry, else "" (the caller falls back to the slug)."""
    try:
        with _open_regular(project_dir / ".project_root") as fh:
            text = fh.read(_ROOT_MARKER_MAX + 1).strip()
    except OSError:
        text = ""
    if text and len(text) <= _ROOT_MARKER_MAX and "\n" not in text and "\x00" not in text:
        return text
    return registry.get(project_dir.name, "")


def gemini_command_project(project: str, real: str, args) -> str:
    """Where one run_shell_command ran: its dir_path (`directory` before
    dir_path existed) when that is an absolute path outside the project root,
    or when no root was recovered; else the session's project."""
    wd = args.get("dir_path", args.get("directory")) if isinstance(args, dict) else None
    if not isinstance(wd, str) or not wd.startswith("/"):
        return project
    if real and (wd == real or wd.startswith(real.rstrip("/") + "/")):
        return project
    return path_project(wd)


def path_project(path: str) -> str:
    """A filesystem path as a project name, the way Codex cwds are shown."""
    return pretty_project(path.replace("\\", "/").lstrip("/").replace("/", "-"))


def read_gemini_session(path: Path) -> dict | None:
    """One Gemini CLI session file, reconstructed for an audit.

    Mirrors the reader in chatRecordingService.ts, with one deliberate
    difference: messages a `$rewindTo` drops are kept and marked rewound,
    because their tool calls ran. Returns
      meta        merged session metadata (initial record, then every $set)
      messages    [(record, line, rewound)], one per message id (its last
                  version), in file order; line is None for a legacy .json
      unparsable  lines that would not decode
      unsupported records of a kind not read: $patch (0.64 preview) and any
                  other unknown shape, skipped and counted
    None when the file cannot be opened.
    """
    try:
        fh = _open_regular(path)
    except OSError:
        return None
    meta: dict = {}
    live: dict[str, tuple[dict, int | None]] = {}    # insertion order, as a JS Map
    dead: list[tuple[str, dict, int | None]] = []
    bad = odd = anon = 0

    def put(m: dict, line: int | None) -> None:
        nonlocal anon
        mid = m.get("id")
        if not isinstance(mid, str) or not mid:
            anon += 1
            mid = f"\x00{anon}"          # no id to key on: kept, never merged
        live[mid] = (m, line)            # an existing id keeps its place

    with fh:
        try:
            if path.suffix == ".json":
                text = ""
                if os.fstat(fh.fileno()).st_size <= GEMINI_JSON_MAX:
                    text = fh.read(GEMINI_JSON_MAX + 1)    # characters: grown since fstat
                ok, doc = (False, None) if not text or len(text) > GEMINI_JSON_MAX \
                    else _json_line(text)
                if not ok:
                    bad += 1
                elif isinstance(doc, dict):
                    for k, v in doc.items():
                        if k == "messages" and isinstance(v, list):
                            for m in v:
                                if isinstance(m, dict):
                                    put(m, None)
                        elif k != "messages":
                            meta[k] = v
                elif doc is not None:
                    odd += 1
            else:
                for n, line in enumerate(fh, 1):
                    ok, rec = _json_line(line)
                    if not ok:
                        bad += 1
                        continue
                    if rec is None:
                        continue
                    if not isinstance(rec, dict):
                        odd += 1
                        continue
                    to = rec.get("$rewindTo")
                    if isinstance(to, str):
                        # That message and everything after it leave the view.
                        if to in live:
                            while live:
                                mid, (m, ln) = live.popitem()
                                dead.append((mid, m, ln))
                                if mid == to:
                                    break
                        continue
                    if "$patch" in rec:
                        odd += 1
                        continue
                    if isinstance(rec.get("id"), str) and rec["id"]:
                        put(rec, n)
                        continue
                    upd = rec.get("$set")
                    if isinstance(upd, dict):
                        for k, v in upd.items():
                            if k == "messages":
                                # A full-history checkpoint (<= v0.63). Messages it
                                # leaves out were compressed, not undone: kept.
                                if isinstance(v, list):
                                    for m in v:
                                        if isinstance(m, dict):
                                            put(m, n)
                            else:
                                meta[k] = v
                        continue
                    if isinstance(rec.get("sessionId"), str) and isinstance(rec.get("projectHash"), str):
                        meta.update(rec)
                        continue
                    odd += 1
        except OSError:
            pass
    chosen: dict[str, tuple[dict, int | None, bool]] = {}
    for mid, m, ln in dead:
        chosen[mid] = (m, ln, True)
    for mid, (m, ln) in live.items():
        chosen[mid] = (m, ln, False)      # re-recorded after the rewind: live again
    msgs = sorted(chosen.values(), key=lambda t: (t[1] is None, t[1] or 0))
    return {"meta": meta, "messages": msgs, "unparsable": bad, "unsupported": odd}


def _parts_text(content) -> str | None:
    """The text of a Gemini PartListUnion: a string, a Part, or Part[]."""
    if isinstance(content, str):
        return content if content.strip() else None
    if isinstance(content, dict):
        content = [content]
    if not isinstance(content, list):
        return None
    texts = [p["text"] for p in content
             if isinstance(p, dict) and isinstance(p.get("text"), str) and not p.get("thought")]
    said = " ".join(t for t in texts if t.strip())
    return said or None


def _response_error(result) -> str:
    """The error text of a tool result: Part[] of functionResponse, whose
    response holds {"error": "..."} when the call failed or was refused."""
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        return ""
    for p in result:
        fr = p.get("functionResponse") if isinstance(p, dict) else None
        resp = fr.get("response") if isinstance(fr, dict) else None
        err = resp.get("error") if isinstance(resp, dict) else None
        if isinstance(err, str) and err:
            return err
    return ""


# The exact texts Gemini CLI writes (scheduler/state-manager.ts, policy.ts),
# matched as prefixes so tool output that merely quotes them is not a refusal.
GEMINI_USER_DENIED = ("[Operation Cancelled] Reason: User denied execution.",
                      "User denied execution.")
GEMINI_POLICY_DENIED = "Tool execution denied by policy."


def tool_refusal(status: str, error: str) -> str | None:
    """"user-denied" (a person said no at the prompt), "policy-denied" (a
    policy rule blocked it), or None. Gemini records no approval, so this is
    all that is known about who allowed a call."""
    err = error.lstrip()[:200]
    if status == "cancelled" and err.startswith(GEMINI_USER_DENIED):
        return "user-denied"
    if status == "error" and err.startswith(GEMINI_POLICY_DENIED):
        return "policy-denied"
    return None


# Qwen ApprovalMode values (config/approval-mode.ts) as permission-mode keys.
# auto-edit approves edits only, so it maps to Claude's acceptEdits reading,
# not to "auto": a shell command still asks.
_QWEN_MODES = {"default": "default", "plan": "plan", "auto-edit": "accept-edits",
               "autoedit": "accept-edits", "auto": "auto", "yolo": "yolo"}


def qwen_mode(raw) -> str | None:
    """A Qwen approval mode as a permission-mode key (`qwen:<mode>`), or None."""
    v = clean(raw)[:40] if isinstance(raw, str) else ""
    if not v:
        return None
    key = _QWEN_MODES.get(v.lower().replace("_", "-"), v)
    return f"qwen:{key}"


# A URL inside free text (web_fetch takes a prompt, not a url). One bounded
# character class after a fixed prefix: linear at any length.
_TEXT_URL = re.compile(r"https?://[^\s\"'<>`\\(){}\[\]|^]{1,2048}", re.I)


def urls_in_text(text: str) -> tuple[list[str], int]:
    """Every distinct http(s) URL in text up to MAX_SCAN_HARD, and 1 when the
    text runs past that cap (counted unparsed, never silently dropped)."""
    if not isinstance(text, str):
        return [], 0
    urls = [m.group(0).rstrip(".,;:!?*") for m in _TEXT_URL.finditer(text[:MAX_SCAN_HARD])]
    return list(dict.fromkeys(u for u in urls if len(u) > 8)), int(len(text) > MAX_SCAN_HARD)


class Fleet:
    def __init__(self, network_only: bool = False) -> None:
        # --network with nothing that reads findings: the shell-audit rules,
        # the unreadable count, the audit-config tripwire and the secret
        # ranking are skipped, since nothing they produce is shown. The
        # network inventory, strict findings and --ioc matches are the same.
        self.network_only = network_only
        # --with-prompts: network.items[].prompt in --json. The text view shows it.
        self.with_prompts = False
        # Per transcript file, for network items: the person's last real
        # message (raw), the text blocks of the assistant message being read,
        # and where in the file the current record is.
        self._prompt: str | None = None
        self._why_id: object = None
        self._why_prior: list[str] = []
        self._src_root = ""
        self._src_file = ""
        self._src_line: int | None = None
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
        # Cache-read tokens at the full input rate, and what they were billed at.
        # Their ratio is the project's effective read multiplier (it differs by
        # model), which the cache-efficiency finding needs to price a miss.
        self.cache_read_list: dict[str, float] = defaultdict(float)
        self.cache_read_paid: dict[str, float] = defaultdict(float)
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
        # The same two counts over every command, dated or not. bash_total -
        # bash_moded is the commands whose approval is unknown (Gemini CLI
        # records no mode at all), which every supervision figure must name
        # rather than silently leave out of its denominator.
        self.bash_moded = 0
        self.bash_unsupervised = 0
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
        self.network_unreadable: list[dict] = []   # commands not read past a limit; listed under --ioc
        self.network_trust: list[str] = []
        self.network_trust_sources: list[dict] = []
        self.network_strict = False
        # --ioc: the loaded list (None without the flag), one row per matched
        # item (refused ones included), and the counts network.ioc reports.
        self.ioc: IocSet | None = None
        self.ioc_rows: list[dict] = []
        self.ioc_totals: dict = _ioc_zero_totals()
        self.reputation: "ReputationData | None" = None
        self.reputation_totals: dict = _reputation_zero_totals()
        self.reputation_candidates: dict[bytes, int] = {}
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
        # Resumed and forked sessions copy history into a new file, so one
        # tool call can sit in several transcripts. Keyed (agent, call id).
        self.seen_tool_calls: set[tuple[str, str]] = set()
        # The same, for the records that move permission modes and refusals;
        # _file_keys numbers each key's occurrences within the current file.
        self.seen_records: set[tuple] = set()
        self._file_keys: Counter = Counter()
        self.duplicate_tool_calls_skipped = 0
        # Transcript lines (and Codex `arguments` strings) that would not
        # decode: malformed, or nested past the decoder's limit. Skipped, and
        # counted so a skip is never silent.
        self.unparsable_lines = 0
        # (root, file, line) of each line already counted for an absurd number.
        self._absurd_lines: set[tuple] = set()
        # Gemini CLI records of a kind this version does not read ($patch from
        # 0.64 preview, any other unknown shape): skipped, and counted.
        self.unsupported_records = 0
        # Gemini tool calls a $rewindTo took out of the conversation. They ran,
        # so they are audited and inventoried like any other, and counted here.
        self.rewound_tool_calls = 0
        # model -> tokens, for models with no published rate (tier UNPRICED):
        # shown, never priced.
        self.unpriced_tokens: Counter = Counter()
        # Codex session id -> [largest total, project, model, token_count
        # points], while scan_codex runs; None outside it. See scan_codex.
        self._codex_sessions: dict[str, list] | None = None
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        # The filters this run was given (--days, --project, --agent), so
        # --diff can tell two reports over different populations apart.
        self.scope: dict = {"days": None, "project": "", "agent": "all"}
        self.roots: list[Path] = []
        self.files_scanned = 0
        self.bytes_scanned = 0

    # -- ingest ------------------------------------------------------------

    def _tok(self, v) -> int:
        """_tokens(), counting an absurd value's line as unparsable (once per
        line: one record can carry several such fields)."""
        if _absurd_count(v):
            key = (self._src_root, self._src_file, self._src_line)
            if key not in self._absurd_lines:
                self._absurd_lines.add(key)
                self.unparsable_lines += 1
        return _tokens(v)

    def add_usage(self, project: str, model: str, usage: dict, ts: datetime | None,
                  branch: str | None = None) -> None:
        # Sanitise at the boundary of the data structure rather than at one call
        # site, so no future caller can bypass it.
        if model == "<synthetic>" and not any(_tokens(v) for v in usage.values()
                                              if not isinstance(v, dict)):
            # Claude Code's own zero-usage records (an interrupted turn, an
            # API error): no model ran, so no message and no unpriced model.
            return
        project = clean(project)[:120] or "unknown"
        model = clean(model)[:48] or "unknown"
        branch = (clean(branch)[:120] or None) if branch else None
        cc = usage.get("cache_creation")
        cc = cc if isinstance(cc, dict) else {}
        w1h = self._tok(cc.get("ephemeral_1h_input_tokens"))
        w5m = self._tok(cc.get("ephemeral_5m_input_tokens"))
        assumed = 0
        if not w1h and not w5m:
            # Older transcript with no TTL split. Priced at the 1h rate and
            # counted separately so the assumption is visible in the report.
            assumed = self._tok(usage.get("cache_creation_input_tokens"))

        inp = self._tok(usage.get("input_tokens"))
        out = self._tok(usage.get("output_tokens"))
        rd = self._tok(usage.get("cache_read_input_tokens"))

        in_rate, out_rate, _provider, known, src = rates_for(model, ts)
        rate = rate_at(model, ts)
        # Each row's own threshold: Haiku 5.5 at 100,000, Gemini Pro at 200,000.
        if rate.long_prompt and inp + rd + w1h + w5m + assumed > rate.long_prompt_tokens:
            rate = rate.long_prompt     # the whole message, not just the excess
            in_rate, out_rate = rate.input, rate.output
        read_mult = rate.cache_read
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
            + rd / 1e6 * in_rate * read_mult
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
            + rd / 1e6 * in_rate * read_mult)
        self.cache_read_list[project] += rd / 1e6 * in_rate
        self.cache_read_paid[project] += rd / 1e6 * in_rate * read_mult
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
                          ts: datetime | None,
                          days: "list[tuple[datetime | None, dict]] | None" = None) -> None:
        """Record one Codex session from its FINAL cumulative usage.

        `total_token_usage` is cumulative across the session and `token_count`
        events repeat, so summing either over-counts badly. The last total is
        the session total, exactly. `days`, when given, is each token_count's
        increment over the one before it, with its time: each day's share of
        the cost is booked to that day, not all of it to the last one.
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
        cached = self._tok(usage.get("cached_input_tokens"))
        self.tokens["input"] += max(self._tok(usage.get("input_tokens")) - cached, 0)
        self.tokens["cache_read"] += cached
        self.tokens["output"] += self._tok(usage.get("output_tokens"))
        if days:
            booked, last_day = 0.0, None
            for dts, inc in days:
                if dts is None:
                    continue
                last_day = dts.date().isoformat()
                share = codex_session_cost(inc, model)
                self.cost_by_day[last_day] += share
                booked += share
                if self.first_ts is None or dts < self.first_ts:
                    self.first_ts = dts
                if self.last_ts is None or dts > self.last_ts:
                    self.last_ts = dts
            if last_day is not None and abs(cost - booked) > 1e-9:
                # A step whose cached share outgrew its input is clamped, so the
                # shares can miss the session price: by_day still sums to cost.
                self.cost_by_day[last_day] += cost - booked
        elif ts:
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
        rd = self._tok(usage.get("cacheReadTokens"))
        wr = self._tok(usage.get("cacheWriteTokens"))
        self.tokens["input"] += max(self._tok(usage.get("inputTokens")) - rd - wr, 0)
        self.tokens["cache_read"] += rd
        self.tokens["cache_w_assumed"] += wr
        self.tokens["output"] += self._tok(usage.get("outputTokens"))

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
        # A resumed or forked session copies its history into a new rollout
        # under the same session id, cumulative totals included. Each session
        # id is priced once, from the token_count totals of all its files.
        self._codex_sessions = {}
        for root in roots:
            for f in sorted(root.rglob("rollout-*.jsonl")):
                self._scan_codex_file(f, since, project_filter, root)
        sessions, self._codex_sessions = self._codex_sessions, None
        for _total, project, model, points in sessions.values():
            self._book_codex(project, model, points, since)

    def _book_codex(self, project: str, model: str,
                    points: "list[tuple[int, datetime | None, dict]]",
                    since: datetime | None) -> None:
        """Price one Codex session from its cumulative token_count totals.

        Totals are cumulative, so what a window used is the final total minus
        the last total stamped before it, and each step's increment belongs to
        the day of the token_count that reported it. Pricing the whole final
        total under --days booked months of history to today.
        """
        keys = ("input_tokens", "cached_input_tokens", "output_tokens")
        uniq = {(t, ts, tuple(u[k] for k in keys)) for t, ts, u in points}
        # Cumulative, so ordering by total is ordering in time.
        ordered = sorted(uniq, key=lambda p: (p[0], p[1] is not None, p[1] or _TS_MIN, p[2]))
        prev = dict.fromkeys(keys, 0)
        window = dict.fromkeys(keys, 0)
        days: list[tuple[datetime | None, dict]] = []
        last: datetime | None = None
        for _t, ts, vals in ordered:
            cur = dict(zip(keys, vals))
            inc = {k: max(cur[k] - prev[k], 0) for k in keys}
            prev = {k: max(cur[k], prev[k]) for k in keys}
            if since and ts and ts < since:
                continue                    # before the window: only moves the base
            for k in keys:
                window[k] += inc[k]
            days.append((ts, inc))
            if ts and (last is None or ts > last):
                last = ts
        if days:
            self.add_codex_session(project, model, window, last, days)

    def _scan_codex_file(self, path: Path, since: datetime | None,
                         project_filter: str | None, root: Path | None = None) -> None:
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
        # (cumulative total, ts, usage) per token_count, values already read
        # through _tok: an absurd count is 0 here and counted once.
        points: list[tuple[int, datetime | None, dict]] = []
        # (command, ts, mode, why, prompt, line, call id)
        pending: list[tuple[str, datetime | None, str | None, str | None, str | None, int,
                            str | None]] = []
        # why: the latest assistant message or reasoning summary text, until the
        # next call's output or user message. prompt: the latest user message.
        why: str | None = None
        prompt: str | None = None
        # (ts, mode key): counted after the project filter and per turn against
        # --days, as commands are, so a filtered-out file moves no mode.
        modes: list[tuple[datetime | None, str]] = []
        self._start_file(path, root)

        try:
            with _open_regular(path) as fh:
                for n, line in enumerate(fh, 1):
                    ok, rec = _json_line(line)
                    if not ok:
                        self.unparsable_lines += 1
                        continue
                    if not isinstance(rec, dict):
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    payload = rec.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    kind = rec.get("type")
                    ptype = payload.get("type")

                    if kind == "event_msg" and ptype == "user_message":
                        said = _prompt_source(payload.get("message"))
                        if said:
                            prompt, why = said, None
                    elif kind == "response_item" and ptype == "message":
                        blocks = payload.get("content")
                        if payload.get("role") == "user":
                            said = _prompt_source(blocks)
                            if said:
                                prompt, why = said, None
                        elif payload.get("role") == "assistant" and isinstance(blocks, list):
                            said = " ".join(b["text"] for b in blocks if isinstance(b, dict)
                                            and b.get("type") == "output_text"
                                            and isinstance(b.get("text"), str))
                            why = said or why
                    elif kind == "response_item" and ptype == "reasoning":
                        summary = payload.get("summary")
                        if isinstance(summary, list):
                            said = " ".join(b["text"] for b in summary if isinstance(b, dict)
                                            and isinstance(b.get("text"), str))
                            why = said or why
                    elif kind == "response_item" and ptype == "function_call_output":
                        why = None

                    if kind == "session_meta":
                        cwd = _str_or(payload.get("cwd"), cwd)
                        session = _str_or(payload.get("id"), session)
                    elif kind == "turn_context":
                        cwd = _str_or(payload.get("cwd"), cwd)
                        # Harness-written, but a tampered file reaches the terminal
                        # through these as surely as through a command: clean them.
                        model = clean(payload.get("model"))[:48] or model
                        pol = payload.get("approval_policy")
                        # Newer Codex writes {"granular": {...flags}}: keep the kind.
                        if isinstance(pol, dict) and len(pol) == 1:
                            pol = next(iter(pol))
                        pol = clean(pol)[:48]
                        if pol:
                            policy = f"codex:{pol}"
                            modes.append((ts, policy))
                        sb = payload.get("sandbox_policy")
                        sbt = clean(sb.get("type"))[:48] if isinstance(sb, dict) else ""
                        if sbt:
                            modes.append((ts, f"sandbox:{sbt}"))
                    elif kind == "event_msg" and payload.get("type") == "token_count":
                        info = payload.get("info")
                        tot = info.get("total_token_usage") if isinstance(info, dict) else None
                        if isinstance(tot, dict):
                            self._src_line = n
                            u = {k: self._tok(tot.get(k)) for k in
                                 ("input_tokens", "cached_input_tokens", "output_tokens",
                                  "total_tokens")}
                            points.append((u["total_tokens"], ts, u))
                    elif payload.get("type") == "function_call" and \
                            payload.get("name") == "shell_command":
                        raw_args = payload.get("arguments")
                        ok, args = _json_line(raw_args) if isinstance(raw_args, str) else (True, {})
                        if not ok:
                            self.unparsable_lines += 1
                            continue
                        if not isinstance(args, dict):
                            continue
                        cmd = args.get("command")
                        if isinstance(cmd, str) and cmd:
                            pending.append((cmd, ts, policy, why, prompt, n,
                                            _str_or(payload.get("call_id"), None)))
                            cwd = _str_or(args.get("workdir"), cwd)
        except OSError:
            return

        project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "unknown"
        if project_filter and project_filter.lower() not in project.lower():
            return

        for ts, key in modes:
            if not (since and ts and ts < since):
                # A resumed rollout copies the session's turn contexts.
                if session and self._seen_copy(("codex-mode", session, ts, key)):
                    continue
                self.permission_modes[key] += 1

        for cmd, ts, mode, why, prompt, n, call_id in pending:
            # Per command, as the Claude and Copilot paths filter per record:
            # a session still active in the window can hold commands from
            # months before it, and those are outside --days.
            if since and ts and ts < since:
                continue
            # Normalise Codex's shell_command onto the same "Bash" tool name the
            # Claude Code path uses, so the audit is one cross-agent view.
            self._src_line = n
            self.add_tool(project, "Bash", {"command": cmd}, ts, mode,
                          session=session, call_id=call_id, agent="codex", why=why,
                          prompt=prompt, where=self._where())

        if points:
            model = model or "unknown"
            top = max(p[0] for p in points)
            pend = self._codex_sessions
            if session and pend is not None:
                seen = pend.get(session)
                if seen is None:
                    pend[session] = [top, project, model, list(points)]
                else:
                    seen[3].extend(points)
                    if top > seen[0]:       # named after the file that got furthest
                        seen[0], seen[1], seen[2] = top, project, model
            else:
                self._book_codex(project, model, points, since)

    def scan_copilot(self, roots: list[Path], since: datetime | None,
                     project_filter: str | None) -> None:
        for root in roots:
            for f in sorted(root.glob("*/events.jsonl")):
                self._scan_copilot_file(f, since, project_filter, root)

    def _scan_copilot_file(self, path: Path, since: datetime | None,
                           project_filter: str | None, root: Path | None = None) -> None:
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
        # (id, tool, command, ts, args, why, prompt, line)
        calls: list[tuple[str, str, str, datetime | None, dict, str | None, str | None, int]] = []
        why: str | None = None          # the latest assistant.message text, until a tool completes
        prompt: str | None = None       # the latest user.message
        self._start_file(path, root if root is not None else path.parent.parent)
        prompted: set[str] = set()
        prompted_any: set[str] = set()
        refusals: list[tuple[str, str, datetime | None]] = []     # (kind, id, ts)
        subagents: list[tuple[dict, datetime | None]] = []
        try:
            with _open_regular(path) as fh:
                for n, line in enumerate(fh, 1):
                    ok, rec = _json_line(line)
                    if not ok:
                        self.unparsable_lines += 1
                        continue
                    if not isinstance(rec, dict):
                        continue
                    data = rec.get("data")
                    if not isinstance(data, dict):
                        continue
                    kind = rec.get("type")
                    ts = parse_ts(rec.get("timestamp"))
                    if kind == "user.message":
                        said = _prompt_source(data.get("content"))
                        if said:
                            prompt, why = said, None
                    elif kind == "assistant.message":
                        said = data.get("content")
                        why = said if isinstance(said, str) and said.strip() else why
                    elif kind == "tool.execution_complete":
                        why = None
                    if kind in ("session.start", "session.context_changed"):
                        ctx = data.get("context") if kind == "session.start" else data
                        if isinstance(ctx, dict):
                            cwd, branch = _copilot_context(ctx, cwd, branch)
                    elif kind == "tool.execution_start":
                        name = _str_or(data.get("toolName"), "?")
                        args = data.get("arguments")
                        cmd = args.get("command") if isinstance(args, dict) else None
                        cmd = cmd if name == "bash" and isinstance(cmd, str) else ""
                        calls.append((_str_or(data.get("toolCallId"), ""), name, cmd, ts,
                                      args if isinstance(args, dict) else {}, why, prompt, n))
                    elif kind == "permission.requested":
                        req = data.get("permissionRequest")
                        req_id = _str_or(req.get("toolCallId"), "") if isinstance(req, dict) else ""
                        if req_id:
                            prompted_any.add(req_id)
                            if req.get("kind") == "shell":
                                prompted.add(req_id)
                    elif kind == "permission.completed":
                        result = data.get("result")
                        rk = _str_or(result.get("kind"), "") if isinstance(result, dict) else ""
                        if rk and rk not in COPILOT_APPROVED:
                            refusals.append((f"copilot:{clean(rk)[:40]}",
                                             _str_or(data.get("toolCallId"), ""), ts))
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
        for call_id, name, cmd, ts, targs, why, prompt, n in calls:
            if not in_window(ts):
                continue
            active = True
            self._src_line = n
            detail = {"why": why, "prompt": prompt, "where": self._where()}
            if cmd:
                mode = "copilot:prompted" if call_id in prompted else "copilot:auto"
                if not (call_id and ("copilot", call_id) in self.seen_tool_calls):
                    self.permission_modes[mode] += 1
                # Normalised onto "Bash", as Codex is, so the audit is one view.
                self.add_tool(project, "Bash", {"command": cmd}, ts, mode,
                              session=sid, call_id=call_id, agent="copilot", **detail)
                if call_id:
                    joined[call_id] = ("Bash", cmd[:MAX_SCAN_LINE])
            else:
                # The arguments go to the network inventory only; add_tool
                # counts nothing else for a non-Bash tool.
                net_mode = "copilot:prompted" if call_id in prompted_any else "copilot:auto"
                self.add_tool(project, name, targs, ts, net_mode,
                              session=sid, call_id=call_id, agent="copilot", **detail)
                if call_id:
                    joined[call_id] = (name, "")
        for kind, call_id, ts in refusals:
            if in_window(ts):
                active = True
                if call_id and self._seen_copy(("copilot-refusal", call_id, kind)):
                    continue                # the same call, refused, in a copied session
                self._network_outcome(f"copilot:{call_id}", refused=True)
                self.denials[kind] += 1
                self.denials_by_project[project] += 1
                self._record_refusal(kind, project, ts, joined.get(call_id))
        for data, ts in subagents:
            if in_window(ts):
                # Copilot gives a token total with no input/output split, so no
                # usage is passed and no cost floor is recorded.
                self.add_subagent({"resolvedModel": copilot_model(_str_or(data.get("model"), "")),
                                   "status": "completed",
                                   "totalDurationMs": self._tok(data.get("durationMs")),
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

    def add_model_usage(self, agent: str, project: str, model: str, inp: int, out: int,
                        cached: int, thoughts: int, tool: int, ts: datetime | None,
                        branch: str | None = None) -> None:
        """One Gemini-API-shaped response (Gemini CLI tokens, Qwen usageMetadata).

        input already INCLUDES cached (promptTokenCount is the whole prompt);
        thoughts are billed at the output rate; tool-use prompt tokens count
        as input. A Pro model's whole message moves to the long-prompt rate when
        its prompt exceeds the row's threshold. A model with no published rate
        adds its tokens and no cost: it is never priced at a ceiling.
        """
        project = clean(project)[:120] or "unknown"
        model = clean(model)[:48] or "unknown"
        branch = (clean(branch)[:120] or None) if branch else None
        cached = min(cached, inp)
        fresh = inp - cached + tool
        outp = out + thoughts
        r = rate_at(model, ts)
        if r.tier == DEFAULT:
            r = unpriced_rate(model)
        tier = r.tier
        if r.long_prompt and inp > r.long_prompt_tokens:
            r = r.long_prompt
        read_mult = OPENAI_CACHED_MULT if r.provider == "openai" else r.cache_read
        cost = (fresh / 1e6 * r.input + cached / 1e6 * r.input * read_mult
                + outp / 1e6 * r.output)
        known = tier in (VENDOR, VENDOR_DOC, AGGREGATOR)
        if not known:
            self.unknown_models[model] += 1
            self.cost_unknown += cost
        elif tier == AGGREGATOR:
            self.aggregator_models[model] += 1
        if tier == UNPRICED:
            self.unpriced_tokens[model] += fresh + cached + outp
        self.cost_by_tier[tier] += cost
        self.models_by_tier[tier].add(model)

        self.messages += 1
        self.agents_seen.add(agent)
        self.cost_by_agent[agent] += cost
        self.units_by_agent[agent] += 1
        self.msgs_by_model[model] += 1
        self.cost_by_model[model] += cost
        self.cost_by_project[project] += cost
        self.tokens["input"] += fresh
        self.tokens["cache_read"] += cached
        self.tokens["output"] += outp
        pt = self.tokens_by_project[project]
        pt["input"] += fresh; pt["output"] += outp; pt["cache_read"] += cached
        self.msgs_by_project[project] += 1
        self.cache_actual[project] += fresh / 1e6 * r.input + cached / 1e6 * r.input * read_mult
        self.cache_read_list[project] += cached / 1e6 * r.input
        self.cache_read_paid[project] += cached / 1e6 * r.input * read_mult
        self.cache_uncached[project] += (fresh + cached) / 1e6 * r.input

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

    def _vendor_call(self, agent: str, project: str, name: str, args: dict,
                     ts: datetime | None, mode: str | None, session: str | None,
                     call_id: str | None, status: str, error: str, why: str | None,
                     prompt: str | None, rewound: bool = False) -> None:
        """One Gemini or Qwen tool call: audited and inventoried as every
        agent's are, then its outcome applied. run_shell_command is read as the
        shared "Bash" tool. A refusal counts as a denial; a refused call still
        counts as attempted, as Copilot's and Claude Code's do."""
        dup = bool(call_id) and (agent, call_id) in self.seen_tool_calls
        cmd = args.get("command") if name == "run_shell_command" else None
        before = len(self.network)
        if name == "run_shell_command":
            self.add_tool(project, "Bash", {"command": cmd} if isinstance(cmd, str) else {},
                          ts, mode, session=session, call_id=call_id, agent=agent,
                          why=why, prompt=prompt, where=self._where())
        else:
            self.add_tool(project, name, args, ts, mode, session=session, call_id=call_id,
                          agent=agent, why=why, prompt=prompt, where=self._where())
        if dup:
            return
        items = self.network[before:]
        refusal = tool_refusal(status, error)
        for item in items:
            item["rewound"] = rewound
            if refusal:
                item["_refused"] = True
            elif status == "success":
                item["failed"] = False
            elif status == "error":
                item["failed"] = True
        if call_id:
            self._net_by_call.pop(f"{agent}:{call_id}", None)    # outcome applied here
        if rewound:
            self.rewound_tool_calls += 1
        if refusal:
            kind = f"{agent}:{refusal}"
            self.denials[kind] += 1
            self.denials_by_project[clean(project)[:120] or "unknown"] += 1
            shown = "Bash" if name == "run_shell_command" else name
            self._record_refusal(kind, clean(project)[:120] or "unknown", ts,
                                 (shown, cmd[:MAX_SCAN_LINE] if isinstance(cmd, str) else ""))

    def scan_gemini(self, roots: list[Path], since: datetime | None,
                    project_filter: str | None) -> None:
        for root in roots:
            registry = gemini_registry(root)
            for d in _project_dirs(root):
                real = gemini_project_root(d, registry)
                project = path_project(real) if real else pretty_project(d.name)
                if project_filter and project_filter.lower() not in project.lower():
                    continue
                for f in gemini_session_files(d):
                    self._scan_gemini_file(f, project, real, since, root)

    def _scan_gemini_file(self, path: Path, project: str, real: str,
                          since: datetime | None, root: Path) -> None:
        try:
            st = path.stat()
        except OSError:
            return
        if since is not None and st.st_mtime < (since.timestamp() - 3600):
            return
        self.bytes_scanned += st.st_size
        self.files_scanned += 1
        self._start_file(path, root)
        sess = read_gemini_session(path)
        if sess is None:
            return
        self.unparsable_lines += sess["unparsable"]
        self.unsupported_records += sess["unsupported"]
        meta = sess["meta"]
        sid = _str_or(meta.get("sessionId"), path.stem)
        prompt: str | None = None
        active = False

        def in_window(t: datetime | None) -> bool:
            return not (since and t and t < since)

        for msg, line, rewound in sess["messages"]:
            self._src_line = line
            kind = msg.get("type")
            ts = parse_ts(msg.get("timestamp"))
            if kind == "user":
                prompt = _parts_text(msg.get("content")) or prompt
                continue
            if kind != "gemini":
                continue
            why = _parts_text(msg.get("content"))
            tok = msg.get("tokens")
            mid = msg.get("id")
            if isinstance(tok, dict) and in_window(ts):
                key = f"gemini:{mid}" if isinstance(mid, str) and mid else None
                if key and key in self.seen_message_ids:
                    self.duplicate_usage_records += 1
                else:
                    if key:
                        self.seen_message_ids.add(key)
                    self.add_model_usage("gemini", project, _str_or(msg.get("model"), "unknown"),
                                         self._tok(tok.get("input")), self._tok(tok.get("output")),
                                         self._tok(tok.get("cached")), self._tok(tok.get("thoughts")),
                                         self._tok(tok.get("tool")), ts)
                    active = True
            calls = msg.get("toolCalls")
            for tc in calls if isinstance(calls, list) else ():
                if not isinstance(tc, dict):
                    continue
                cts = parse_ts(tc.get("timestamp")) or ts
                if not in_window(cts):
                    continue
                active = True
                args = tc.get("args")
                args = args if isinstance(args, dict) else {}
                name = _str_or(tc.get("name"), "?")
                where = gemini_command_project(project, real, args) \
                    if name == "run_shell_command" else project
                self._vendor_call("gemini", where, name, args, cts, None, sid,
                                  _str_or(tc.get("id"), None), _str_or(tc.get("status"), ""),
                                  _response_error(tc.get("result")), why, prompt, rewound)
        if active:
            self.agents_seen.add("gemini")

    def scan_qwen(self, roots: list[Path], since: datetime | None,
                  project_filter: str | None) -> None:
        for root in roots:
            for d in _project_dirs(root):
                for f in qwen_session_files(d):
                    self._scan_qwen_file(f, d.name, since, project_filter, root)

    def _scan_qwen_file(self, path: Path, slug: str, since: datetime | None,
                        project_filter: str | None, root: Path) -> None:
        """One Qwen Code session: records carry their own cwd, the approval mode
        is written per user turn and on every change, tool calls are Gemini
        functionCall parts and results are tool_result records."""
        try:
            st = path.stat()
        except OSError:
            return
        if since is not None and st.st_mtime < (since.timestamp() - 3600):
            return
        self.bytes_scanned += st.st_size
        self.files_scanned += 1
        self._start_file(path, root)
        mode: str | None = None
        cwd = branch = ""
        prompt = why = None
        active = False
        # call id -> (project, name, command, ts): a result joins its call.
        calls: dict[str, tuple[str, str, str, datetime | None, list]] = {}
        try:
            with _open_regular(path) as fh:
                for n, line in enumerate(fh, 1):
                    ok, rec = _json_line(line)
                    if not ok:
                        self.unparsable_lines += 1
                        continue
                    if not isinstance(rec, dict):
                        continue
                    self._src_line = n
                    cwd = _str_or(rec.get("cwd"), cwd)
                    branch = _str_or(rec.get("gitBranch"), branch)
                    project = path_project(cwd) if cwd else pretty_project(slug)
                    ts = parse_ts(rec.get("timestamp"))
                    kind = rec.get("type")
                    msg = rec.get("message")
                    parts = msg.get("parts") if isinstance(msg, dict) else None
                    parts = parts if isinstance(parts, list) else []
                    new_mode = None
                    if kind == "user":
                        ctx = rec.get("executionContext")
                        new_mode = qwen_mode(ctx.get("approvalMode")) if isinstance(ctx, dict) else None
                        said = _parts_text(parts)
                        if said and not any(isinstance(p, dict) and "functionResponse" in p for p in parts):
                            prompt, why = said, None
                    elif kind == "system" and rec.get("subtype") == "session_approval_mode":
                        pay = rec.get("systemPayload")
                        new_mode = qwen_mode(pay.get("mode")) if isinstance(pay, dict) else None
                    if new_mode:
                        mode = new_mode         # in force for the calls that follow
                    if project_filter and project_filter.lower() not in project.lower():
                        continue
                    if since and ts and ts < since:
                        continue
                    if new_mode and not self._record_seen(rec):
                        self.permission_modes[new_mode] += 1
                    if kind == "assistant":
                        said = _parts_text(parts)
                        why = said or why
                        usage = rec.get("usageMetadata")
                        if isinstance(usage, dict):
                            uid = rec.get("uuid")
                            key = f"qwen:{uid}" if isinstance(uid, str) and uid else None
                            if key and key in self.seen_message_ids:
                                self.duplicate_usage_records += 1
                            else:
                                if key:
                                    self.seen_message_ids.add(key)
                                self.add_model_usage(
                                    "qwen", project, _str_or(rec.get("model"), "unknown"),
                                    self._tok(usage.get("promptTokenCount")),
                                    self._tok(usage.get("candidatesTokenCount")),
                                    self._tok(usage.get("cachedContentTokenCount")),
                                    self._tok(usage.get("thoughtsTokenCount")),
                                    self._tok(usage.get("toolUsePromptTokenCount")), ts, branch)
                                active = True
                        for p in parts:
                            fc = p.get("functionCall") if isinstance(p, dict) else None
                            if not isinstance(fc, dict):
                                continue
                            active = True
                            name = _str_or(fc.get("name"), "?")
                            args = fc.get("args")
                            args = args if isinstance(args, dict) else {}
                            cid = _str_or(fc.get("id"), None)
                            before = len(self.network)
                            dup = bool(cid) and ("qwen", cid) in self.seen_tool_calls
                            self._vendor_call("qwen", project, name, args, ts, mode,
                                              rec.get("sessionId") if isinstance(rec.get("sessionId"), str)
                                              else path.stem, cid, "", "", why, prompt)
                            if cid and not dup:
                                cmd = args.get("command") if name == "run_shell_command" else None
                                calls[cid] = (project, name, cmd if isinstance(cmd, str) else "",
                                              ts, list(range(before, len(self.network))))
                    elif kind == "tool_result":
                        why = None
                        self._qwen_result(rec, parts, calls)
        except OSError:
            return
        if active:
            self.agents_seen.add("qwen")

    def _qwen_result(self, rec: dict, parts: list, calls: dict) -> None:
        """Apply one tool_result to the call it answers (by call id)."""
        tcr = rec.get("toolCallResult")
        tcr = tcr if isinstance(tcr, dict) else {}
        cid = _str_or(tcr.get("callId"), "")
        status = _str_or(tcr.get("status"), "")
        err = tcr.get("error")
        if isinstance(err, dict):
            err = err.get("message")
        err = err if isinstance(err, str) else ""
        for p in parts:
            fr = p.get("functionResponse") if isinstance(p, dict) else None
            if isinstance(fr, dict):
                cid = cid or _str_or(fr.get("id"), "")
                err = err or _response_error([p])
        hit = calls.pop(cid, None) if cid else None
        if hit is None:
            return
        project, name, cmd, ts, idx = hit
        refusal = tool_refusal(status, err)
        for i in idx:
            if i >= len(self.network):
                continue
            if refusal:
                self.network[i]["_refused"] = True
            elif status == "success":
                self.network[i]["failed"] = False
            elif status == "error":
                self.network[i]["failed"] = True
        if refusal:
            kind = f"qwen:{refusal}"
            self.denials[kind] += 1
            self.denials_by_project[clean(project)[:120] or "unknown"] += 1
            self._record_refusal(kind, clean(project)[:120] or "unknown", ts,
                                 ("Bash" if name == "run_shell_command" else name, cmd[:MAX_SCAN_LINE]))

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
                    tid = b.get("tool_use_id")
                    hit = calls.get(tid) if isinstance(tid, str) and tid else None
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
            head = display_head(cmd)
            if head:
                self.refusal_program[kind][head] += 1

    def add_subagent(self, result: dict, ts: datetime | None) -> None:
        """One completed subagent run.

        `totalTokens` is NOT the run total. It equals the sum of the final
        message's usage in 873 of 873 observed cases and scales only ~2x from a
        4-tool run to a 45-tool run, which is context growth, not summation. The
        cumulative spend of a subagent's turns is not present in the parent
        transcript, so what is recorded here is an explicit FLOOR.
        """
        self.sub_calls += 1
        model = result.get("resolvedModel")
        model = (clean(model)[:48] if isinstance(model, str) else "") or "unknown"
        self.sub_by_model[model] += 1
        status = result.get("status")
        self.sub_status[(clean(status)[:48] if isinstance(status, str) else "") or "?"] += 1
        self.sub_ms += self._tok(result.get("totalDurationMs"))

        stats = result.get("toolStats")
        stats = stats if isinstance(stats, dict) else {}
        for k in ("bashCount", "readCount", "editFileCount", "searchCount", "otherToolCount"):
            self.sub_tools[k] += self._tok(stats.get(k))
        self.sub_lines["added"] += self._tok(stats.get("linesAdded"))
        self.sub_lines["removed"] += self._tok(stats.get("linesRemoved"))

        u = result.get("usage")
        if isinstance(u, dict):
            base = model.replace("[1m]", "")
            in_rate, out_rate, _prov, _known, _src = rates_for(base, ts)
            read_mult = rate_for(base).cache_read
            cc = u.get("cache_creation")
            cc = cc if isinstance(cc, dict) else {}
            self.sub_cost_floor += (
                self._tok(u.get("input_tokens")) / 1e6 * in_rate
                + self._tok(u.get("output_tokens")) / 1e6 * out_rate
                + self._tok(cc.get("ephemeral_1h_input_tokens")) / 1e6 * in_rate * CACHE_WRITE_1H_MULT
                + self._tok(cc.get("ephemeral_5m_input_tokens")) / 1e6 * in_rate * CACHE_WRITE_5M_MULT
                + self._tok(u.get("cache_read_input_tokens")) / 1e6 * in_rate * read_mult)

    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                 mode: str | None = None, *, session: str | None = None,
                 call_id: str | None = None, agent: str | None = None,
                 why: str | None = None, prompt: str | None = None,
                 where: dict | None = None) -> None:
        if not isinstance(tool_input, dict):
            tool_input = {}
        if "command" in tool_input and not isinstance(tool_input["command"], str):
            # A list or object here is not a command line: read it as absent.
            tool_input = {k: v for k, v in tool_input.items() if k != "command"}
        if call_id:
            who = agent or ("codex" if (mode or "").startswith("codex:")
                            else "copilot" if (mode or "").startswith("copilot:") else "claude")
            key = (who, str(call_id))
            if key in self.seen_tool_calls:
                self.duplicate_tool_calls_skipped += 1      # counted once, in the file read first
                return
            self.seen_tool_calls.add(key)
        project = clean(project)[:120] or "unknown"
        name = clean(name)[:48] or "?"
        self.tools[name] += 1
        self._net_remote_exec = ""
        self._add_network(project, name, tool_input or {}, ts, mode, session, call_id, agent,
                          (why, prompt, where))
        if not self.network_only:
            self._audit_config_write(project, name, tool_input or {}, ts)
        if name != "Bash":
            return
        cmd = (tool_input or {}).get("command") or ""
        if not cmd:
            return
        self.bash_total += 1
        self.bash_by_project[project] += 1
        if mode:
            self.bash_moded += 1
            if is_ungated_mode(mode):
                self.bash_unsupervised += 1
        if self.network_only:
            return
        self.bash_categories[command_category(cmd)] += 1
        if ts:
            day = ts.date().isoformat()
            self.bash_by_day[day] += 1
            if mode:
                self.bash_moded_by_day[day] += 1
                if is_ungated_mode(mode):
                    self.unsupervised_by_day[day] += 1
        head = display_head(cmd)
        if head:
            self.bash_first_token[head] += 1

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

        matches = command_rule_matches(cmd, windows, self._net_remote_exec)
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
            # Stored whole (up to one scan line): redacted first, cut to 240 on the way
            # out, so a token is never cut short of the length its pattern needs.
            "evidence": evidence[:MAX_SCAN_LINE],
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
            base = max(i, 0)
            chunk = text[base:base + MAX_SCAN_LINE]
            for sev, rx in rules:
                m = rx.search(chunk)
                if m:
                    return [(sev, "remote-exec", _redacted_excerpt(text, base + m.start(), base + m.end()))]
        # The dequoted `cu''rl … | s''h` shape needs no pass here: _add_network
        # already read the whole command up to MAX_SCAN_HARD (_net_remote_exec).
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
                self._scan_file(f, project, since, d.parent)
        if progress:
            print("\r" + " " * 72 + "\r", end="", file=sys.stderr, flush=True)

    def _start_file(self, path: Path, root: Path | None) -> None:
        """Reset the per-file state network items read: mode, prompt, the
        assistant text being collected, and the file's path under its root."""
        self._mode = None
        self._prompt = None
        self._why_id, self._why_prior = None, []
        self._file_keys = Counter()
        root = root if root is not None else path.parent
        self._src_root = str(root)
        try:
            self._src_file = path.relative_to(root).as_posix()
        except ValueError:
            self._src_file = path.name
        self._src_line = None

    def _where(self) -> dict:
        return {"root": self._src_root, "file": self._src_file, "line": self._src_line}

    def _scan_file(self, path: Path, project: str, since: datetime | None,
                   root: Path | None = None) -> None:
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
        self._start_file(path, root)
        calls: dict[str, tuple[str, str]] = {}
        try:
            with _open_regular(path) as fh:
                for n, line in enumerate(fh, 1):
                    # Cheap prefilter: skip lines that cannot contribute to any
                    # counter. Must include the permission fields, which live on
                    # records that carry neither usage nor tool_use.
                    counts = not ('"usage"' not in line and '"tool_use"' not in line
                                  and '"permissionMode"' not in line
                                  and '"toolDenialKind"' not in line)
                    # A user message with no tool result may be the prompt a
                    # network item shows; it moves no counter.
                    said = not counts and ('"type":"user"' in line or '"type": "user"' in line) \
                        and '"tool_result"' not in line
                    # A line admitted only for its error result feeds the
                    # network inventory alone, so no existing counter moves.
                    if not counts and not said and '"is_error":true' not in line \
                            and '"is_error": true' not in line:
                        continue
                    ok, rec = _json_line(line)
                    if not ok:
                        self.unparsable_lines += 1
                        continue
                    if not isinstance(rec, dict):
                        continue
                    self._src_line = n

                    if counts:
                        self._ingest_claude(rec, project, since, calls)
                    else:
                        self._claude_context(rec)
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
                        evidence = (redact(clean(w)).replace("\n", " ") if n == 0 else
                                    f"a {len(cmd):,}-character command writes an audit config "
                                    "file past its first 32 KB")
                        program = display_head(cmd) or "Bash"
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
        mode = clean(rec.get("permissionMode"))[:48]
        if mode:
            # Stays in force for the tool calls that follow it, even when this
            # record is itself older than the window.
            self._mode = str(mode)
        whys = self._claude_context(rec)        # likewise: a prompt outlives the window
        if since and ts and ts < since:
            return
        self._network_results(rec)

        denial = clean(rec.get("toolDenialKind"))[:48]
        if (mode or denial) and self._record_seen(rec):
            # A resumed or forked session copies its history into a new file:
            # the copy's mode and refusal records were counted from the first.
            mode = denial = ""
        if mode:
            self.permission_modes[mode] += 1
        if denial:
            self.denials[denial] += 1
            self.denials_by_project[project] += 1
            self.add_refusal(denial, rec, project, ts, calls)
        eff = rec.get("effort")
        if isinstance(eff, str) and eff:
            self.effort_mix[eff] += 1

        msg = rec.get("message")
        if not isinstance(msg, dict):
            return

        usage = msg.get("usage")
        if isinstance(usage, dict):
            # One billable message, however many records carry it.
            mid = msg.get("id")
            if not isinstance(mid, str):    # a list or object here is unhashable
                mid = None
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
            for k, block in enumerate(content):
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    inp = block.get("input")
                    inp = inp if isinstance(inp, dict) else {}
                    self.add_tool(project, block.get("name") or "?",
                                  inp, ts, self._mode,
                                  session=rec.get("sessionId"), call_id=block.get("id"),
                                  agent="claude", why=whys.get(k), prompt=self._prompt,
                                  where=self._where())
                    bid, cmd = block.get("id"), inp.get("command")
                    if bid and isinstance(bid, str):
                        calls[bid] = (block.get("name") or "?",
                                      cmd[:MAX_SCAN_LINE] if isinstance(cmd, str) else "")

    def _record_seen(self, rec: dict) -> bool:
        """Whether this Claude Code (or Qwen) record was already counted from
        another file. Keyed on what a copy keeps: uuid, session, timestamp,
        type and the mode or refusal it carries. A record with neither a uuid
        nor a timestamp is never taken for a repeat."""
        uid, raw_ts, sid = rec.get("uuid"), rec.get("timestamp"), rec.get("sessionId")
        uid = uid if isinstance(uid, str) else ""
        raw_ts = raw_ts if isinstance(raw_ts, str) else ""
        if not uid and not raw_ts:
            return False
        msg = rec.get("message")
        blocks = msg.get("content") if isinstance(msg, dict) else None
        tids = tuple(b["tool_use_id"] for b in (blocks if isinstance(blocks, list) else ())
                     if isinstance(b, dict) and isinstance(b.get("tool_use_id"), str))
        return self._seen_copy(("rec", uid, sid if isinstance(sid, str) else "", raw_ts,
                                str(rec.get("type")), str(rec.get("permissionMode")),
                                str(rec.get("toolDenialKind")), tids))

    def _seen_copy(self, key: tuple) -> bool:
        """Whether `key` was already counted from an earlier file. Each key is
        numbered by its occurrence in this file, so two identical records in
        one file both count, while a copied file's records match the
        original's, one for one."""
        n = self._file_keys[key]
        self._file_keys[key] = n + 1
        full = key + (n,)
        if full in self.seen_records:
            return True
        self.seen_records.add(full)
        return False

    def _claude_context(self, rec: dict) -> dict[int, str]:
        """Note a real user prompt, and collect an assistant message's text.

        Claude Code writes one record per content block, all under the same
        message id, so the text before a tool_use may sit in earlier records.
        Returns, for each tool_use block in this record, the raw text that came
        before it in its message. A meta, compact-summary or sidechain user
        record is never the person's prompt."""
        msg = rec.get("message")
        if not isinstance(msg, dict):
            return {}
        content = msg.get("content")
        kind = rec.get("type")
        if kind == "user":
            if not (rec.get("isMeta") or rec.get("isCompactSummary") or rec.get("isSidechain")):
                said = _prompt_source(content)
                if said:
                    self._prompt = said
            return {}
        if kind != "assistant" or not isinstance(content, list):
            return {}
        mid = msg.get("id")
        if not mid or mid != self._why_id:
            self._why_id, self._why_prior = mid, []
        whys: dict[int, str] = {}
        for k, b in enumerate(content):
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text" and isinstance(b.get("text"), str):
                if b["text"] not in self._why_prior:     # a re-emitted record adds nothing
                    self._why_prior.append(b["text"])
            elif b.get("type") == "tool_use" and self._why_prior:
                whys[k] = " ".join(self._why_prior)
        return whys

    def _add_network(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                     mode: str | None, session: str | None, call_id: str | None,
                     agent: str | None, context: tuple = (None, None, None)) -> None:
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
            limits: list[str] = []
            try:
                found, unparsed = network_items_from_command(cmd, piped, remotes, limits)
            except Exception:                   # noqa: BLE001 -- one bad command must not end the scan
                found, unparsed, piped = [], 1, []
            self.network_unparsed += unparsed
            self._net_remote_exec = piped[0].strip() if piped else ""
            if limits:
                # Part of the command was not read (R10): listed and flagged
                # unresolved under --ioc (apply_ioc), never silently clean.
                found = found + [_net_item("fetch", NET_UNREADABLE_PROGRAM, dynamic=True,
                                           source=limits[0], _unreadable=True)]
        else:
            found = network_items_from_tool(name, tool_input)
            if name.lower() == "web_fetch" and not tool_input.get("url"):
                self.network_unparsed += urls_in_text(tool_input.get("prompt"))[1]
        if not found:
            return
        if not agent:
            agent = ("codex" if (mode or "").startswith("codex:")
                     else "copilot" if (mode or "").startswith("copilot:") else "claude")
        # Worked out only for a call that reached the network: redaction is the cost.
        why_raw, prompt_raw, where = context
        why, prompt = _net_context(why_raw, last_sentence=True), _net_context(prompt_raw)
        # What the text view prints as `command`: cleaned and on one line here,
        # redacted when printed (unless --no-redact), never in --json.
        if name == "Bash":
            command = " ".join(clean(tool_input.get("command") or "").split())
        else:
            target = tool_input.get("url")
            command = clean(f"{name} {target}" if isinstance(target, str) else name)
            command = " ".join(command.split())
        cut = command.find(" ", 4 * NET_COMMAND_MAX)
        command = command[:cut] if cut > 0 else command[:MAX_SCAN_LINE]
        where = ({"root": clean(str(where.get("root") or "")),
                  "file": clean(str(where.get("file") or "")).replace("\n", " "),
                  "line": where.get("line") if isinstance(where.get("line"), int) else None}
                 if isinstance(where, dict) else None)
        for item in found:
            for k, v in item.items():           # transcript text must not reach a terminal
                if isinstance(v, str):
                    item[k] = clean(v).replace("\n", " ")
            item.update(approval=network_approval(mode), agent=agent, project=project,
                        session=clean(str(session))[:80] if session else None,
                        call_id=clean(str(call_id))[:120] if call_id else None,
                        ts=ts.isoformat() if ts else None,
                        failed=False if agent == "claude" else None, trusted=False, ioc=None,
                        rewound=False,
                        mode=clean(str(mode))[:48] or None if mode else None,
                        why=why, prompt=prompt, transcript=dict(where) if where else None,
                        _command=command)
            if item.get("_unreadable"):
                self.network_unreadable.append(item)
                continue
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
            with _open_regular(path) as fh:
                records = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError, RecursionError):
            return
        if not isinstance(records, list):
            return
        self._start_file(path, path.parent)     # one JSON array: no line numbers
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
    __slots__ = ("id", "severity", "title", "evidence", "action", "impact", "project")

    def __init__(self, fid, severity, title, evidence, action, impact=None, project=""):
        self.id, self.severity, self.title = fid, severity, title
        self.evidence, self.action, self.impact = evidence, action, impact
        # The project a per-project finding (AF002, AF006) is about, else "".
        # Several rows share one id, so --diff keys on (id, project).
        self.project = project


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
                listed = fleet.cache_read_list.get(proj, 0)
                mult = (fleet.cache_read_paid[proj] / listed if listed
                        else CACHE_READ_MULT)
                waste = max(fleet.cache_uncached.get(proj, 0) * (med - r) / 100
                            * (1 - mult), 0.0)
                out.append(Finding(
                    "AF002", "high", "Cache efficiency below your own median",
                    f"{proj} reads {r:.0f}% of tokens from cache; your median project "
                    f"is {med:.0f}%. Something in that project changes the prompt "
                    f"prefix on most requests.",
                    "Look for a timestamp, a random id, or unsorted JSON early in the "
                    "context. Stable content must come first.",
                    f"~{money(waste)} of avoidable spend at current volume", project=proj))

    # --- AF003 unsupervised execution --------------------------------------
    auto = ungated_modes(fleet.permission_modes)
    modes = recorded_turns(fleet.permission_modes)
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
                    "in that project describing its conventions is the cheapest fix.",
                    project=proj))

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
    problem = _baseline_problem(data)
    if problem:
        raise ValueError(f"{path} is not a well-formed baseline: {problem}. "
                         "Regenerate it with actualis --json.")
    return data


def _baseline_problem(data: dict) -> str:
    """The first field --diff reads that has the wrong type, or "".

    A baseline is a file the user hands us, often a CI artifact, so it is
    checked like any other input rather than trusted to be our own output.
    """
    def obj(key, v):
        return "" if v is None or isinstance(v, dict) else f"{key} is not an object"

    def rows(key, v, strs, lists):
        if v is None:
            return ""
        if not isinstance(v, list):
            return f"{key} is not an array"
        for i, r in enumerate(v):
            if not isinstance(r, dict):
                return f"{key}[{i}] is not an object"
            for k in strs:
                if k in r and r[k] is not None and not isinstance(r[k], str):
                    return f"{key}[{i}].{k} is not a string"
            for k in lists:
                if k in r and r[k] is not None and not (
                        isinstance(r[k], list) and all(isinstance(x, str) for x in r[k])):
                    return f"{key}[{i}].{k} is not an array of strings"
        return ""

    bash = data.get("bash")
    scanned = data.get("scanned")
    checks = [
        obj("window", data.get("window")),
        obj("bash", bash),
        obj("scope", data.get("scope")),
        obj("scanned", scanned),
        rows("secrets", data.get("secrets"), ("id", "priority"), ("types", "projects")),
        rows("coach", data.get("coach"), ("id", "severity", "title", "project", "evidence"), ()),
        rows("bash.flags", bash.get("flags") if isinstance(bash, dict) else None,
             ("id", "severity", "program"), ("categories",)),
    ]
    for key in ("cost_usd", "messages"):
        v = data.get(key)
        if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float))):
            checks.append(f"{key} is not a number")
    if isinstance(scanned, dict):
        r = scanned.get("roots")
        if r is not None and not (isinstance(r, list) and all(isinstance(x, str) for x in r)):
            checks.append("scanned.roots is not an array of strings")
    return next((c for c in checks if c), "")


def _finding_key(r: dict) -> str:
    """AF002 and AF006 repeat once per project under one id, so a finding is
    (id, project). A baseline from before `project` existed names the project
    only at the start of the evidence ("<project> reads ...")."""
    fid = str(r["id"])
    proj = r.get("project")
    if not isinstance(proj, str):
        proj = ""
        ev = r.get("evidence")
        if fid in ("AF002", "AF006") and isinstance(ev, str):
            for verb in (" reads ", " rejects "):
                if verb in ev:
                    proj = ev.split(verb, 1)[0]
                    break
    return f"{fid}\x00{proj}" if proj else fid


def _findings_by_key(rows: object) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict) and r.get("id"):
                out[_finding_key(r)] = r
    return out


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
        ("findings", _findings_by_key(old.get("coach")), _findings_by_key(new.get("coach")),
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
    ow = old.get("window") if isinstance(old.get("window"), dict) else {}
    nw = new.get("window") if isinstance(new.get("window"), dict) else {}
    out["windows"] = (ow.get("from"), ow.get("to"), nw.get("from"), nw.get("to"))
    out["digests"] = (old.get("report_sha256"), new.get("report_sha256"))
    out["scope"] = _scope_differences(old, new)
    return out


def _scope_differences(old: dict, new: dict) -> list[tuple[str, object, object]]:
    """(flag, baseline value, this run's value) for each filter that differs.

    Two reports over different populations diff as a wall of "new" and
    "gone": a --project api baseline against a full run lists every other
    project's credentials as new. Compared only where both sides record it.
    """
    out: list[tuple[str, object, object]] = []
    os_, ns = old.get("scope"), new.get("scope")
    if isinstance(os_, dict) and isinstance(ns, dict):
        for key, flag in (("days", "--days"), ("project", "--project"), ("agent", "--agent")):
            if os_.get(key) != ns.get(key):
                out.append((flag, os_.get(key), ns.get(key)))
    oc, nc = old.get("scanned"), new.get("scanned")
    if isinstance(oc, dict) and isinstance(nc, dict):
        orr, nr = oc.get("roots"), nc.get("roots")
        if isinstance(orr, list) and isinstance(nr, list) and \
                sorted(map(str, orr)) != sorted(map(str, nr)):
            out.append(("roots", ", ".join(map(str, orr)), ", ".join(map(str, nr))))
    return out


def _txt(v: object) -> str:
    """A value from a baseline file, safe to print: any type, no escapes."""
    return clean(v if isinstance(v, str) else "" if v is None else str(v))


def _txt_list(v: object) -> str:
    return ", ".join(_txt(x) for x in v) if isinstance(v, list) else ""


def _label(row: dict, family: str) -> str:
    if family == "secrets":
        types = _txt_list(row.get("types")) or "unknown type"
        where = _txt_list(row.get("projects"))
        return f"{types}" + (f"  in {where}" if where else "")
    if family == "findings":
        title = _txt(row.get("title"))
        proj = row.get("project")
        return title + (f"  ({_txt(proj)})" if isinstance(proj, str) and proj else "")
    prog = _txt(row.get("program")) or "?"
    cats = _txt_list(row.get("categories"))
    return f"{prog}" + (f"  ({cats})" if cats else "")


def render_diff(d: dict, c: C) -> None:
    rule(c, "DIFF")
    of, ot, nf, nt = (_txt(v) for v in d["windows"])
    print(f"  baseline   {of or '?'} → {ot or '?'}")
    print(f"  this run   {nf or '?'} → {nt or '?'}")
    scope = d.get("scope") or []
    if scope:
        print(f"\n  {c.yellow}▲ The two reports have a different scope{c.off}, so rows "
              f"below may differ because a different population was read, not "
              f"because anything changed:")
        for flag, ov, nv in scope:
            print(f"    {flag:<10} baseline {_txt(ov) or '(none)'}  "
                  f"this run {_txt(nv) or '(none)'}")
    od, nd = d["digests"]
    od = od if isinstance(od, str) else None
    nd = nd if isinstance(nd, str) else None
    if od and nd and od == nd:
        print(f"\n  {c.ok}Identical report.{c.off} {c.dim}Same digest ({_txt(od[:16])}), "
              f"so nothing below changed.{c.off}\n")
        return

    changed = False
    for family, blk in d["families"].items():
        noun = blk["noun"]
        rows = []
        sk = blk["sev_key"]
        for r in blk["appeared"]:
            sev = _txt(r.get(sk, ""))
            rows.append((_rank(sev), "new", sev, _label(r, family), ""))
        for r in blk["resolved"]:
            sev = _txt(r.get(sk, ""))
            rows.append((_rank(sev), "gone", sev, _label(r, family), ""))
        for ro, rn in blk["worse"]:
            sev = _txt(rn.get(sk, ""))
            rows.append((_rank(sev), "worse", sev, _label(rn, family),
                         f"was {_txt(ro.get(sk, ''))}"))
        for ro, rn in blk["better"]:
            sev = _txt(rn.get(sk, ""))
            rows.append((_rank(sev), "better", sev, _label(rn, family),
                         f"was {_txt(ro.get(sk, ''))}"))
        for ro, rn in blk["moved"]:
            delta = rn["count"] - ro.get("count", 0)
            sev = _txt(rn.get(sk, ""))
            rows.append((_rank(sev), "count", sev, _label(rn, family),
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
        if d["totals"] and all(ov == nv for ov, nv in d["totals"].values()):
            # The digest ignores the clock (pricing.age_days, pricing.stale,
            # AF013), so this is a baseline from a build that hashed them in.
            print(f"\n  {c.dim}No credential, finding or command-kind changed, and "
                  f"cost and message counts are equal. The digests differ because "
                  f"the baseline was written by a version that hashed the "
                  f"clock-dependent fields; digests from 0.2.2 and earlier are not "
                  f"comparable.{c.off}")
        else:
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

    # A sighting with no usable timestamp still counts (the report counts it),
    # but it cannot place a window: the window spans the dated ones, and the
    # undated sightings join it as themselves. Other undated commands are not
    # placed in it, since nothing says when they ran.
    dated = [e for e in sightings if e.ts is not None]
    first = dated[0].ts if dated else None
    last = dated[-1].ts if dated else None
    window = [e for e in events
              if e.ts is not None and first is not None and first <= e.ts <= last]
    window += [e for e in sightings if e.ts is None]

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
            head = display_head(e.cmd)       # cleaned: model-written text
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
            "first_seen": first.isoformat() if first else "",
            "last_seen": last.isoformat() if last else "",
            "days": round((last - first).total_seconds() / 86400, 2) if dated else 0.0,
            "sightings": len(sightings),
            "undated_sightings": len(sightings) - len(dated),
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
    print(f"  first seen   {w['first_seen'][:19].replace('T', ' ') or 'undated'}")
    print(f"  last seen    {w['last_seen'][:19].replace('T', ' ') or 'undated'}")
    undated = w.get("undated_sightings", 0)
    print(f"  exposed for  {c.bold}{w['days']} days{c.off} across {w['sightings']} appearances"
          + (f"  {c.dim}({undated} undated: no usable timestamp){c.off}" if undated else ""))

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
        # `cur and`: a first word longer than the width starts the first
        # line, rather than leaving an empty line above it.
        if cur and len(cur) + len(w) + 1 > width:
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
                 copilot: list[Path] | None = None, gemini: list[Path] | None = None,
                 qwen: list[Path] | None = None) -> list[Path]:
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
    # Gemini's legacy .json sessions are rewritten whole, never appended: not watched.
    for r in gemini or []:
        out.extend(f for d in _project_dirs(r) for f in gemini_session_files(d)
                   if f.suffix == ".jsonl")
    for r in qwen or []:
        out.extend(f for d in _project_dirs(r) for f in qwen_session_files(d))
    return out


WATCH_RESCAN_SECS = 30.0     # how often --watch re-walks the transcript directories


def command_rule_matches(cmd: str, windows: list[str] | None = None,
                         net_remote_exec: str | None = None) -> list[tuple[str, str, str]]:
    """[(severity, category, line)] the report raises for one shell command:
    the audit rules, the remote-exec rules past the scan cut of an oversized
    command, and the remote execution only the network tokenizer reads
    (`cu''rl … | s''h`, `| busybox sh`, `| /bin/bash`, `bash <(curl …)`).
    The report and --watch both use it, so they agree (R3C8).
    `net_remote_exec`, when the caller already read the command's network
    items, is the fetch a shell runs ("" for none); None reads it here."""
    matches = audit_command(cmd)
    if len(cmd) > MAX_SCAN_TOTAL and not any(cat == "remote-exec" for _, cat, _ in matches):
        matches += Fleet._oversized_remote_exec(cmd, windows if windows is not None else scan_windows(cmd))
    if net_remote_exec is None:
        piped: list[str] = []
        try:
            network_items_from_command(cmd, piped)
        except Exception:                    # noqa: BLE001 -- as _add_network: never end the caller
            piped = []
        net_remote_exec = piped[0].strip() if piped else ""
    # `cu''rl … | s''h` and `curl … | busybox sh` evade the
    # remote-exec regex on the raw text; the network tokenizer reads them
    # dequoted. One flag per command: added only when the rule did not fire.
    if net_remote_exec and not any(cat == "remote-exec" for _, cat, _ in matches):
        # The line holding the fetch that the shell runs, not just any pipe.
        frag = net_remote_exec
        line = next((ln for ln in cmd.split("\n") if frag in ln), None) \
            or next((ln for ln in cmd.split("\n") if "|" in ln), cmd)
        matches.append(("high", "remote-exec", clean(line[:MAX_SCAN_LINE].strip())))
    # A write to git, npm, yarn or pip download configuration redirects every
    # later download, including ones in later tool calls this scan cannot tie
    # to it (R3F7): a medium finding, so the redirect is seen.
    try:
        written = network_config_write(cmd)
    except Exception:                        # noqa: BLE001 -- as above: never end the caller
        written = ""
    if written:
        matches.append(("med", "network-config", clean(written[:MAX_SCAN_LINE].strip())))
    return matches


def watch(roots: list[Path], codex: list[Path], interval: float, c: C,
          quiet: bool, raw: bool, copilot: list[Path] | None = None,
          gemini: list[Path] | None = None, qwen: list[Path] | None = None) -> int:
    import time

    # Python block-buffers stdout when it is not a terminal. For a watcher that
    # means an alert can sit unwritten in a 4KB buffer for hours, which defeats
    # the entire point of running it in the background.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    offsets: dict[Path, int] = {}
    files = _jsonl_files(roots, codex, copilot, gemini, qwen)
    last_walk = time.monotonic()
    for f in files:
        try:
            offsets[f] = f.stat().st_size      # start at EOF: history is not news
        except OSError:
            pass

    seen_secrets: set[str] = set()
    cmds = flagged = crit = 0
    started = datetime.now(timezone.utc)
    # A Codex rollout lives under sessions/YYYY/MM/DD, so its directory names
    # a day, not a project: the project comes from the rollout's own cwd.
    rollout_cwd: dict[Path, str] = {}

    def rollout_head_cwd(f: Path) -> str:
        # session_meta is a rollout's first line, written before watch began.
        try:
            with _open_regular(f) as fh:
                rec = _json_line(fh.readline(1 << 20))[1]
        except OSError:
            return ""
        payload = rec.get("payload") if isinstance(rec, dict) else None
        if isinstance(rec, dict) and rec.get("type") in ("session_meta", "turn_context") \
                and isinstance(payload, dict):
            return _str_or(payload.get("cwd"), "")
        return ""

    # Likewise a Copilot session: its directory is the session id, and the
    # project comes from the cwd in session.start / session.context_changed.
    copilot_cwd: dict[Path, str] = {}

    def copilot_ctx(rec: object, cwd: str) -> str:
        if not isinstance(rec, dict) or not isinstance(rec.get("data"), dict):
            return cwd
        kind = rec.get("type")
        if kind not in ("session.start", "session.context_changed"):
            return cwd
        ctx = rec["data"].get("context") if kind == "session.start" else rec["data"]
        return _copilot_context(ctx, cwd, "")[0] if isinstance(ctx, dict) else cwd

    def copilot_head_cwd(f: Path) -> str:
        # session.start is the first line, written before watch began.
        try:
            with _open_regular(f) as fh:
                return copilot_ctx(_json_line(fh.readline(1 << 20))[1], "")
        except OSError:
            return ""

    srcs = ", ".join(str(r) for r in (roots + codex + (copilot or []) + (gemini or [])
                                      + (qwen or [])))
    # Gemini re-appends a whole message each time it changes, so a call id
    # already alerted on is not alerted on again.
    seen_calls: set[tuple[str, str]] = set()
    gem_projects: dict[Path, str] = {}

    def vendor_of(f: Path) -> str:
        for name, group in (("gemini", gemini or []), ("qwen", qwen or [])):
            for r in group:
                try:
                    if f.is_relative_to(r):
                        return name
                except (ValueError, OSError):
                    continue
        return ""

    def gemini_project(f: Path) -> str:
        d = f.parent.parent if f.parent.name == "chats" else f.parent.parent.parent
        if d not in gem_projects:
            real = gemini_project_root(d, {})
            gem_projects[d] = path_project(real) if real else pretty_project(d.name)
        return gem_projects[d]
    print(f"{c.bold}actualis watch{c.off} {c.dim}· {len(offsets)} files · every "
          f"{interval:g}s · ctrl-c to stop{c.off}")
    print(f"{c.dim}watching {srcs}{c.off}")
    print(f"{c.dim}Starting from now. Existing history is not replayed.{c.off}\n")

    try:
        while True:
            # Walking every transcript directory is the expensive part, so it
            # happens every WATCH_RESCAN_SECS; in between only known files are
            # stat'ed. Offsets of files that have gone are dropped.
            if time.monotonic() - last_walk >= WATCH_RESCAN_SECS:
                files = _jsonl_files(roots, codex, copilot, gemini, qwen)
                last_walk = time.monotonic()
                live = set(files)
                for gone in [k for k in offsets if k not in live]:
                    del offsets[gone]
                    rollout_cwd.pop(gone, None)
                    copilot_cwd.pop(gone, None)
            for f in files:
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
                    with _open_regular(f, binary=True) as fh:
                        fh.seek(start)
                        chunk = fh.read()
                except OSError:
                    continue
                # Only complete lines are consumed. A record caught mid-write
                # stays unread until its newline arrives, instead of being
                # split across two polls and failing to parse both times.
                end = chunk.rfind(b"\n")
                if end < 0:
                    continue
                offsets[f] = start + end + 1

                rollout = f.name.startswith("rollout-")
                if rollout and f not in rollout_cwd:
                    rollout_cwd[f] = rollout_head_cwd(f) if start else ""
                vendor = vendor_of(f) if (gemini or qwen) else ""
                is_copilot = f.name == "events.jsonl" and not vendor
                if is_copilot and f not in copilot_cwd:
                    copilot_cwd[f] = copilot_head_cwd(f) if start else ""
                project = ("copilot" if f.name == "events.jsonl"
                           else gemini_project(f) if vendor == "gemini"
                           else pretty_project(f.parent.name))
                for raw_line in chunk[:end].split(b"\n"):
                    line = raw_line.decode("utf-8", "replace")
                    context = (rollout and ('"session_meta"' in line or '"turn_context"' in line)) \
                        or (is_copilot and ('"session.start"' in line
                                            or '"session.context_changed"' in line))
                    if ('"tool_use"' not in line and '"function_call"' not in line
                            and '"tool.execution_start"' not in line and not context
                            and '"toolCalls"' not in line and '"functionCall"' not in line):
                        continue
                    rec = _json_line(line)[1]
                    if not isinstance(rec, dict):
                        continue
                    if rollout:
                        payload = rec.get("payload")
                        if rec.get("type") in ("session_meta", "turn_context") \
                                and isinstance(payload, dict):
                            rollout_cwd[f] = _str_or(payload.get("cwd"), rollout_cwd[f])
                        cwd = rollout_cwd[f]
                        project = (pretty_project(cwd.lstrip("/").replace("/", "-"))
                                   if cwd else "codex")
                    if is_copilot:
                        cwd = copilot_cwd[f] = copilot_ctx(rec, copilot_cwd[f])
                        project = (pretty_project(cwd.lstrip("/").replace("/", "-"))
                                   if cwd else "copilot")
                    if vendor == "qwen":
                        cwd = _str_or(rec.get("cwd"), "")
                        project = path_project(cwd) if cwd else pretty_project(f.parent.parent.name)
                    try:
                        if vendor:
                            commands = []
                            for cid, cmd in _vendor_shell_calls(rec, vendor):
                                if cid and (vendor, cid) in seen_calls:
                                    continue
                                if cid:
                                    seen_calls.add((vendor, cid))
                                commands.append(cmd)
                        else:
                            commands = _commands_in(rec)
                    except OSError:
                        raise
                    except Exception:
                        # The watcher runs unattended: one odd record must not
                        # switch it off.
                        continue
                    for command in commands:
                        cmds += 1
                        for pri, kind, fp in classify_secrets(command):
                            if fp in seen_secrets or pri == "low":
                                continue
                            seen_secrets.add(fp)
                            crit += 1
                            msg = f"{kind} in {_one_line(project)}"
                            # flush: under a service manager stdout is a file,
                            # so it is block-buffered. Without this an alert can
                            # sit unwritten for hours -- which is the whole
                            # point of the feature, lost to an 8KB buffer.
                            print(f"\r{c.red}▲ SECRET{c.off}  {msg}  {c.dim}{fp}{c.off}"
                                  + " " * 20, flush=True)
                            notify("actualis: credential exposed", msg)
                        hits = command_rule_matches(command)   # what the report flags (R3C8)
                        high = [h for h in hits if h[0] == "high"]
                        if high:
                            flagged += 1
                            cats = ",".join(sorted({h[1] for h in high}))
                            line_txt = _one_line(high[0][2] if raw else redact(high[0][2]))
                            print(f"\r{c.yellow}▲ {cats}{c.off}  {line_txt[:88]}"
                                  f"  {c.dim}{_one_line(project)[:28]}{c.off}" + " " * 10,
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
        # Computed here: Ctrl-C can land before the first pass has finished.
        mins = (datetime.now(timezone.utc) - started).total_seconds() / 60
        if sys.stdout.isatty():
            print(f"\r{' ' * 72}\r", end="")
        print(f"{c.bold}stopped{c.off} after {mins:.1f}m · {cmds} commands · "
              f"{flagged} flagged · {crit} distinct secrets")
        return 0


def _vendor_shell_calls(rec: dict, vendor: str | None = None) -> list[tuple[str, str]]:
    """(call id or "", command) for each run_shell_command in one Gemini CLI
    message (toolCalls) or Qwen Code record (functionCall parts of an
    assistant record, as the report's Qwen reader reads them). `vendor` names
    the format the record came from: "gemini" reads only toolCalls, "qwen"
    only the parts, so one agent's file is never read as the other's. None
    (a record of unknown origin) reads both."""
    out: list[tuple[str, str]] = []
    calls = rec.get("toolCalls") if vendor != "qwen" else None
    found = [(tc, tc.get("args")) for tc in (calls if isinstance(calls, list) else ())
             if isinstance(tc, dict)]
    msg = rec.get("message") if vendor != "gemini" else None
    if vendor == "qwen" and rec.get("type") != "assistant":
        msg = None
    parts = msg.get("parts") if isinstance(msg, dict) else None
    for p in parts if isinstance(parts, list) else ():
        fc = p.get("functionCall") if isinstance(p, dict) else None
        if isinstance(fc, dict):
            found.append((fc, fc.get("args")))
    for call, args in found:
        cmd = args.get("command") if isinstance(args, dict) else None
        if call.get("name") == "run_shell_command" and isinstance(cmd, str) and cmd:
            out.append((_str_or(call.get("id"), ""), cmd))
    return out


def _commands_in(rec: dict) -> list[str]:
    """Every shell command in one transcript record, across every agent format."""
    out: list[str] = [cmd for _cid, cmd in _vendor_shell_calls(rec)]
    msg = rec.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), list):
        for b in msg["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Bash":
                inp = b.get("input")
                cmd = inp.get("command") if isinstance(inp, dict) else None
                if isinstance(cmd, str) and cmd:
                    out.append(cmd)
    payload = rec.get("payload")
    if isinstance(payload, dict) and payload.get("name") == "shell_command":
        # Untrusted types (R1), as the main scanner treats them: a non-string
        # `arguments`, a non-object decode or a non-string command is absent.
        raw_args = payload.get("arguments")
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else {}
        except (ValueError, RecursionError):
            args = {}
        cmd = args.get("command") if isinstance(args, dict) else None
        if isinstance(cmd, str) and cmd:
            out.append(cmd)
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
# Five agents are supported, unevenly, and until now nothing said how. Someone
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

# Gemini CLI and Qwen Code, per capability above: (gemini, qwen, the field it
# rests on). Kept beside the original table rather than widening its rows, so
# every reader of the five-column shape is unchanged.
VENDOR_CAPABILITIES_MORE = {
    "Cost and token usage": (YES, YES, "Gemini: message tokens (input includes cached; "
                             "thoughts billed as output). Qwen: usageMetadata. A model with "
                             "no published rate shows tokens and no cost"),
    "Per-message dedup":    (YES, YES, "Gemini: message id, last re-appended version wins; "
                             "Qwen: record uuid"),
    "Shell command text":   (YES, YES, "toolCalls / functionCall run_shell_command"),
    "Project attribution":  (YES, YES, "Gemini: tmp/<slug>/.project_root or projects.json, "
                             "else the slug; Qwen: cwd on every record"),
    "Git branch":           (NO, YES, "Gemini sessions carry no branch; Qwen: gitBranch"),
    "Tool refusals":        (PARTIAL, PARTIAL, "Gemini: status cancelled with 'User denied "
                             "execution.' or error 'Tool execution denied by policy.'; "
                             "Qwen: the same texts in tool_result, not confirmed"),
    "Permission mode":      (NO, YES, "Gemini writes no approval and no mode change, so every "
                             "Gemini call's approval is unknown; Qwen: executionContext."
                             "approvalMode per turn and session_approval_mode changes"),
    "Sandbox policy":       (NO, NO, "neither transcript records a sandbox"),
    "Subagent activity":    (YES, PARTIAL, "Gemini: chats/<parent>/<subagent>.jsonl, a full "
                             "transcript; Qwen: sidechain records in the session file"),
    "Subagent cost":        (YES, PARTIAL, "Gemini subagent transcripts carry their own "
                             "tokens and are priced like any session"),
    "Cache TTL split":      (NO, NO, "Gemini usage has one cached count"),
    "Reasoning effort":     (NO, NO, "thought tokens are counted, no effort level is written"),
}

_VENDOR_COLUMN = {"claude": 1, "codex": 2, "copilot": 3, "gemini": 5, "qwen": 6}


def vendor_gaps(vendor: str) -> list[tuple[str, str]]:
    """Capabilities this vendor does not fully provide, with the reason."""
    idx = _VENDOR_COLUMN[vendor]       # an unknown vendor is a KeyError, not Codex's gaps
    if idx > 4:
        return [(cap, VENDOR_CAPABILITIES_MORE[cap][2]) for cap, *_ in VENDOR_CAPABILITIES
                if VENDOR_CAPABILITIES_MORE[cap][idx - 5] != YES]
    return [(row[0], row[4]) for row in VENDOR_CAPABILITIES if row[idx] != YES]


# Every id coach() can emit; --why rejects anything else as a usage error.
# Defined before EXPLAIN, whose coach text quotes the range from it.
COACH_FINDING_IDS = tuple(f"AF{n:03d}" for n in range(1, 14))


EXPLAIN: dict[str, dict[str, object]] = {
    "sources": {
        "measures": "Which files every number is derived from.",
        "formula": [
            "Claude Code  ~/.claude/projects/**/*.jsonl  (plus $CLAUDE_CONFIG_DIR)",
            "Codex        $CODEX_HOME/sessions/**/rollout-*.jsonl",
            "Copilot CLI  $COPILOT_HOME/session-state/*/events.jsonl  (default ~/.copilot)",
            "Gemini CLI   $GEMINI_CLI_HOME/.gemini/tmp/<project>/chats/  (default ~/.gemini;",
            "             also ~/.cache/.gemini, where a macOS sandbox run writes)",
            "Qwen Code    $QWEN_RUNTIME_DIR or $QWEN_HOME /projects/<project>/chats/*.jsonl",
            "             (default ~/.qwen)",
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
            "  cache read   x rate x the model's read multiplier",
            "",
            "The cache-read multiplier is per model: 0.10 by default, 0.05 for Opus 5.5",
            "and Sonnet 5.5, 0.025 for Fable 5.1 and Mythos 5.1. Haiku 5.5 reprices a",
            "whole message at $0.50 / $2.50 when its prompt (input + cache read +",
            "cache write) exceeds 100,000 tokens, and $0.10 / $0.50 otherwise.",
            "Fast mode, batch pricing and data-residency uplifts are not modelled.",
            "",
            "OpenAI differs: input_tokens INCLUDES cached, so the cached portion is",
            "billed at 0.10x and only the remainder at full rate.",
            "",
            "Gemini CLI and Qwen Code likewise: the prompt INCLUDES cached tokens,",
            "and thinking tokens are billed at the output rate. Gemini Pro models",
            "reprice a whole message above 200,000 prompt tokens, and dated Google",
            "price changes apply by the message's UTC date. A model with no",
            "published rate (gemini-3.5-flash, every Qwen model) adds tokens and no",
            "cost: see --explain gemini.",
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
            "Claude and OpenAI models with no published rate are priced at the top",
            "of the known range for their provider; that estimated share is",
            "reported separately (cost_usd_from_unpriced_models) so you can",
            "subtract it. Gemini, Gemma and Qwen ids with no published rate are",
            "the exception: tier 'unpriced', $0 and their tokens listed",
            "(unpriced_model_tokens), never estimated.",
        ],
        "verify": ("actualis --json | jq '.cost_usd, .duplicate_usage_records_skipped, "
                   ".cost_usd_from_unpriced_models, .unpriced_model_tokens'"),
    },
    "vendors": {
        "measures": "What each agent's transcript actually contains, and what it does not.",
        "formula": [
            "capability                claude   codex    copilot  gemini   qwen",
        ] + [f"  {cap:<24}{c:<9}{x:<9}{p:<9}{VENDOR_CAPABILITIES_MORE[cap][0]:<9}"
             f"{VENDOR_CAPABILITIES_MORE[cap][1]}"
             for cap, c, x, p, _why in VENDOR_CAPABILITIES] + [
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
    "gemini": {
        "measures": "How a Gemini CLI session is read, and what it cannot show.",
        "formula": [
            "Source    $GEMINI_CLI_HOME/.gemini/tmp/<project>/chats/ (GEMINI_CLI_HOME",
            "          replaces the home dir; default ~/.gemini), and ~/.cache/.gemini",
            "          where a macOS sandbox run writes. session-*.jsonl, the legacy",
            "          session-*.json, and chats/<parent session>/*.jsonl subagents",
            "Messages  the last line of each message id wins (Gemini re-appends a",
            "          message whenever it changes). $set merges metadata. $rewindTo",
            "          removes a message and all after it from the conversation; their",
            "          tool calls ran, so they are kept and counted as rewound. $patch",
            "          (0.64 preview) and unknown records are skipped and counted",
            "Project   tmp/<slug>/.project_root, else projects.json, else the slug; a",
            "          command whose dir_path is an absolute path outside the root is",
            "          attributed to that path",
            "Cost      per message: (input - cached + tool) x input rate",
            "          + cached x cached rate + (output + thoughts) x output rate.",
            "          Pro models above 200,000 prompt tokens: the long-prompt rate",
            "Approval  unknown for every call: not recorded",
            "Refusal   status cancelled + 'User denied execution.' (a person), or",
            "          status error + 'Tool execution denied by policy.' (a policy)",
        ],
        "assumes": [
            "Gemini CLI does not write whether a person approved a call, or the",
            "approval mode (YOLO, auto-edit) it ran in. Even an auto-approved call",
            "is recorded like one a person allowed, so this is not guessed.",
            "Models Google's price list does not name (gemini-3-pro-preview,",
            "gemini-3.5-flash) show tokens and no cost. A free-tier session cannot",
            "be told apart, so Gemini cost is API-equivalent.",
            "logs.json, checkpoints and shell_history are not read: they hold the",
            "person's own prompts and ! commands, not what the agent ran.",
            "--watch reads JSONL sessions only; a legacy .json session is rewritten",
            "whole, never appended.",
        ],
        "verify": "actualis --agent gemini --json | jq '.by_agent, .rewound_tool_calls, "
                  ".unsupported_records, .unpriced_model_tokens'",
    },
    "qwen": {
        "measures": "How a Qwen Code session is read, and what it cannot show.",
        "formula": [
            "Source    $QWEN_RUNTIME_DIR/projects/<cwd slug>/chats/<session>.jsonl, and",
            "          $QWEN_HOME/projects (QWEN_HOME is the .qwen directory; default",
            "          ~/.qwen)",
            "Project   the cwd written on every record; the branch from gitBranch",
            "Commands  functionCall parts named run_shell_command",
            "Cost      usageMetadata per assistant record, once per record uuid:",
            "          promptTokenCount includes cachedContentTokenCount; thoughts",
            "          are billed at the output rate",
            "Mode      executionContext.approvalMode per user turn, and",
            "          session_approval_mode records on every change: yolo and auto",
            "          are unasked; default, plan and auto-edit are unknown",
            "Refusal   a tool_result with the same denial texts as Gemini CLI",
        ],
        "assumes": [
            "auto-edit approves edits only, so a shell command in it still asks: it",
            "is not counted as unsupervised. Whether a person approved one call is",
            "not recorded.",
            "Qwen publishes no USD price this tool can cite, so Qwen models show",
            "tokens and no cost. A model with a published price (a Gemini, Claude",
            "or OpenAI id run through Qwen Code) is priced at that rate.",
            "The refusal texts are Gemini CLI's, inherited by the fork; Qwen's own",
            "were not confirmed.",
        ],
        "verify": "actualis --agent qwen --json | jq '.by_agent, .permission_modes'",
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
        "measures": "Downloads and fetches the agents made (actualis --network), and whether a person approved each.",
        "formula": [
            "The inventory is a tripwire, not a guarantee. It reads only what the",
            "transcript shows. Shell commands are read as bash reads them, by the",
            "same lexer the shell audit uses: split on && || ; | & and newlines",
            "outside quotes and # comments, on the dequoted text ($'...' decoded), so",
            "cu''rl and \"cu\"rl read as curl.",
            "Also read, as commands of their own:",
            "  command substitution $(...) and backticks, and process substitution",
            "  <(...), at any depth (200 levels), also inside an unquoted heredoc;",
            "  the string after a shell's -c, including combined flags (bash -lc,",
            "  sh -xc), su -c, find -exec, the arguments of eval, and a heredoc or",
            "  here-string fed to a shell, to 8 levels;",
            "  the action of trap 'CMD' SIGNAL;",
            "  the bodies of if/while/until/for loops, case arms, { } and ( ) groups,",
            "  and a leading !.",
            "Brace expansion is applied to the program word and to URLs (cu{r,}l is",
            "curl, https://{a,b}.io is two URLs), up to 16 words. Arithmetic and",
            "[[ ... ]] text is not read as commands; their substitutions are.",
            "Skipped to reach the command: sudo env time nice nohup command exec",
            "timeout stdbuf doas busybox xargs coproc setsid caffeinate arch flock",
            "watch, and VAR=value. Under xargs the",
            "arguments may arrive on stdin, so a bare `xargs curl` is recorded as a",
            "fetch with a variable host.",
            "Recognised programs: curl wget git gh npm pnpm yarn bun npx bunx pip",
            "pip3 uv uvx pipx brew cargo go docker podman.",
            "Counted as unreadable (totals.unparsed_segments), not skipped silently:",
            "a segment with a quote left open, a brace expansion past 16 words, and",
            "nesting past the levels above",
            "(under --ioc, such a command is also an unresolved item).",
            "A git remote is resolved to the URL it was added or cloned with earlier",
            "in the same session; a remote name that resolves to nothing has no host",
            "and is listed, not flagged.",
            "Tool calls: WebFetch,",
            "WebSearch, web_fetch, web_search, google_web_search, and any tool named",
            "like fetch/browse/download/http. Gemini's web_fetch takes a prompt, not",
            "a url: every http(s) URL written in the prompt is an item.",
            "",
            "approval  asked    Copilot asked the person before the call",
            "          unasked  the call ran in auto or bypass mode, Codex 'never', or a",
            "                   Copilot standing rule",
            "          unknown  default mode: an allowlist rule may have approved it",
            "                   without asking; the transcript does not say. Every",
            "                   Gemini CLI call: Gemini records no approval at all",
            "Qwen Code: yolo and auto are unasked; default, plan and auto-edit unknown.",
            "A Gemini or Qwen call a person declined or a policy blocked is a refusal",
            "and leaves the inventory. A Gemini call a later rewind removed from the",
            "conversation still ran: it stays, with rewound: true.",
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
            "",
            "--ioc FILE matches this inventory against a known-bad list: see",
            "actualis --explain ioc.",
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
            "",
            "Each item carries detail, all redacted and cleaned when read:",
            "  mode        the permission-mode key approval was judged from",
            "  why         the assistant's own words before the call, last sentence,",
            "              at most 160 characters",
            "  prompt      the person's last real message before the turn, at most",
            "              160 characters. The text view shows it; --json emits it",
            "              only with --with-prompts, otherwise null",
            "  transcript  root, file (relative to root) and 1-based line of the",
            "              record that made the call",
            "What each agent provides:",
            "  Claude Code  why: text blocks of the same assistant message before the",
            "               tool_use. prompt: the last user message that is not a tool",
            "               result, meta record, slash-command or local-command",
            "               wrapper, or system reminder.",
            "  Codex        why: the latest assistant message or reasoning summary",
            "               before the call, cleared by a call's output. prompt: the",
            "               latest user_message, not injected environment context.",
            "               No call_id is recorded for Codex.",
            "  Copilot      why: the latest assistant.message text, cleared when a",
            "               tool completes. prompt: the latest user.message.",
            "  Gemini CLI   why: the text of the message holding the call. prompt:",
            "               the latest user message.",
            "  Qwen Code    why: the latest assistant text, cleared by a tool result.",
            "               prompt: the latest user message.",
            "A field the records do not give is null.",
            "",
            "To see the exact transcript record behind an item:",
            "  actualis --network --json | jq -r '.items[0].transcript'",
            "  sed -n '<line>p' <root>/<file>",
            "or by call id:",
            "  actualis --network --json | jq -r '.items[0] | .session, .call_id'",
            "  grep -l '<call_id>' ~/.claude/projects/*/*.jsonl",
            "call_id is the tool call's id in the transcript (null when none). The",
            "text view's trace line prints the call_id, then the same path and line.",
            "",
            "The text view's charts, and the --network --json path each one draws:",
            "  approval bar   .totals (unasked solid, unknown medium, asked light)",
            "  per day        .by_day, one cell per UTC date from first to last (or",
            "                 per run of days, said on the row), empty dates blank;",
            "                 .by_day_undated counts items with no time",
            "  unasked        .by_day[].unasked, on the per-day row's scale",
            "  kind           .by_kind",
            "  TOP HOSTS      .hosts, ranked by unasked, then count; local and",
            "                 private hosts are counted on the 'plus' line",
            "  TOP PACKAGES   .packages (count, unasked, versions, pinned, exec)",
            "  BY PROJECT     .by_project, shown with two or more projects",
            "  BY SESSION     .items grouped by .session; counts are of every item",
            "A bar's solid part is the unasked share; its length is the count",
            "against the largest row in the same chart. Any count above zero gets",
            "at least one cell. The series reconcile with .totals; the report says",
            "so in red when they do not.",
            "  actualis --network --json | jq '.by_day, .by_project'",
            "--html writes the same report as one self-contained page",
            "(actualis-network.html, never overwritten, readable by you only). It",
            "loads nothing from the network and embeds the --network --json object,",
            "with its sha256, so every number on it can be checked against --json.",
        ],
        "verify": "actualis --json | jq '.network.totals, .network.hosts[:5]'",
    },
    "ioc": {
        "measures": "Which downloads match a known-bad list you supply with --ioc.",
        "formula": [
            "Each download in the network inventory is compared with every entry",
            "in the --ioc files: package entries by ecosystem and name, then by",
            "version; host entries by host suffix on a label boundary and path",
            "prefix on a segment boundary. A host is matched when the command named",
            "it or the session supplied it as a URL (a git remote added earlier, a",
            "brew tap's repository), never the default registry a bare install",
            "implies. A Go package also matches the module it is in:",
            "go install evil.example/m/cmd/x@v1 is checked against evil.example/m.",
            "",
            "verdict  match       an any-version entry, a version inside the",
            "                     entry's spec, or a host entry. High finding,",
            "                     category network-ioc.",
            "         unresolved  the name is listed but the version cannot be",
            "                     decided: none or a range was installed",
            "                     (version-unresolved), the versions do not order",
            "                     (undecidable), a private registry served it",
            "                     (private-registry), the name was read from a git",
            "                     or tarball URL (name-from-url), a Go package inside",
            "                     a listed module could not be ordered",
            "                     (module-prefix), or checking failed",
            "                     (error); also a host that cannot be normalised",
            "                     (host-unresolved) or a transfer the command sends",
            "                     through a proxy or another address (redirected).",
            "                     Medium finding, network-ioc-unresolved.",
            "A listed name whose version is outside every spec is clean, and only",
            "counted (clean_name_matches).",
            "",
            "Names: npm and Go exactly; pypi by PEP 503; crates lowercased with _",
            "as -; images with docker.io/library/ spelled out or not. Versions:",
            "SemVer 2.0.0 for npm, crates and go, PEP 440 for pypi; an image by tag",
            "or digest, never by order. One finding per (verdict, key), where the",
            "key is eco:name@version or host:host/path.",
            "",
            "Refused calls are listed (refused) and never flagged or gated. The",
            "trust list never exempts a match. Findings are suppressible, and",
            "suppressed ones stay counted. --fail-on high fails on a match; any",
            "also fails on unresolved.",
        ],
        "assumes": [
            "No match is not \"not affected\". Lockfile installs (npm ci,",
            "pip install -r), scripts and postinstall hooks are out of sight, and",
            "only the transcripts still on this machine in the window are read.",
            "The coverage line says how many downloads could be checked.",
            "from= and until= are shown and not yet applied.",
            "brew records no version, so brew entries match any version.",
            "A Go module's host is its origin (github.com/x), not the proxy used.",
            "The list is read only when named; nothing is fetched. If it sits",
            "where the agent could write, the agent could have edited it: the",
            "report records each file's sha256, and mtime_in_window says whether",
            "it changed while the agent worked. Fetch it after the agent step.",
            "Use malware lists, not vulnerability databases.",
        ],
        "verify": "actualis --ioc f --json | jq '.network.ioc.totals'",
    },
    "reputation": {
        "measures": "Which hosts in the network inventory are on a reputation list (--reputation), offline.",
        "formula": [
            "Each public host is hashed into Safe Browsing expressions and its 4-byte",
            "prefixes are looked up in the lists on disk. actualis never uses the",
            "network; actualis-reputation (a separate command) downloads the lists.",
            "",
            "state  none        no prefix in any list",
            "       candidate   a prefix matched; not confirmed. Medium finding.",
            "       listed      a confirmation under 30 minutes old (and inside",
            "                   Google's cache time) returned the host's full hash, or",
            "                   VirusTotal malicious >= --vt-threshold. High finding.",
            "       not-listed  a fresh check found nothing",
            "       suspicious  VirusTotal: 1 <= malicious < threshold, or suspicious >= 1",
            "       unknown     VirusTotal has never seen the host",
            "       skipped     a private or local host, never looked up or sent",
            "",
            "Lists older than 7 days raise reputation-stale. With --fail-on, absent or",
            "corrupt lists, or a corrupt VirusTotal file, exit 2 before scanning.",
            "The cache is in $ACTUALIS_REPUTATION_DIR; else %LOCALAPPDATA%\\actualis\\reputation",
            "on Windows; else $XDG_CACHE_HOME/actualis/reputation; else",
            "~/.cache/actualis/reputation.",
        ],
        "assumes": [
            "A listing is about now, not about when the agent reached the host.",
            "Lists can be wrong both ways: no result is not proof of safety.",
            "A Google result carries \"Advisory provided by Google\"; both providers",
            "are for non-commercial use. See docs/reputation.md.",
        ],
        "verify": "actualis --network --reputation --json | jq '.reputation.totals'",
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
            f"Each finding {COACH_FINDING_IDS[0]}-{COACH_FINDING_IDS[-1]} has a documented "
            "threshold. Comparisons are",
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
    # AF002 and AF006 fire once per project under one id: explain every one,
    # or fixing the first and re-running looks like whack-a-mole.
    if len(found) > 1:
        names = [" ".join(str(f.project or "?").split())[:66] for f in found]
        print(f"  {c.bold}Firing for {len(found)} projects:{c.off} {', '.join(names)}")
        print(f"  {c.dim}Narrow to one with --project.{c.off}\n")
    for i, f in enumerate(found):
        if len(found) > 1:
            print(f"  {c.bold}── {names[i]}{c.off}\n")
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
        if i < len(found) - 1:
            print()
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
    ("Qwen Code", "qwen"),
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
        # Built from EXPLAIN so a new topic is advertised the day it ships.
        "description": "How a number is computed, what it assumes, and how to verify it "
                       "independently. Topics: " + ", ".join(sorted(EXPLAIN)) + ".",
        "inputSchema": {"type": "object", "properties": {
            "topic": {"type": "string", "enum": sorted(EXPLAIN)}}, "required": ["topic"]},
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
MCP_MAX_LINE = 1_000_000     # bytes; a longer JSON-RPC line is refused unparsed


def clamp_days(v: object) -> int | None:
    """Client-supplied window, bounded. bool is an int in Python and must not pass."""
    if isinstance(v, float) and v.is_integer():    # 7.0 is a natural thing to send
        v = int(v)
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return min(max(v, 1), MCP_MAX_DAYS)


class _MCPCache:
    """A scan takes ~80s over a large fleet, so hold it — but only a few, LRU."""

    def __init__(self, scope: dict | None = None) -> None:
        self._store: OrderedDict[tuple, Fleet] = OrderedDict()
        # The --root, --agent, --days and --project the server was started
        # with (R14). A client may narrow them, never widen them.
        self.scope = scope or {}

    def _narrow(self, days: int | None, project: str | None) -> tuple:
        cli_days = self.scope.get("days")
        if cli_days:
            days = min(days, cli_days) if days else cli_days
        cli_project = self.scope.get("project")
        if cli_project:
            want, have = (project or "").lower(), cli_project.lower()
            if not project or have in want:
                project = project or cli_project      # the client's is the narrower one
            elif want in have:
                project = cli_project
            else:
                raise _MCPClientError(
                    f"this server was started with --project {clean(cli_project)[:100]}; "
                    f"ask for a project whose name contains it, or for none")
        return days, project

    def _scan(self, f: Fleet, since: datetime | None, project: str | None) -> None:
        """The same roots and parsers main() would read for this scope."""
        agent = self.scope.get("agent") or "all"
        root = self.scope.get("root")
        if root:
            root = Path(root).expanduser()
            if agent == "codex":
                f.roots.append(root)
                f.scan_codex([root], since, project)
            elif agent == "copilot":
                f.roots.append(root)
                f.scan_copilot([root], since, project)
            elif agent in ("gemini", "qwen"):
                vroot = _agent_root(root, agent)
                f.roots.append(vroot)
                (f.scan_gemini if agent == "gemini" else f.scan_qwen)([vroot], since, project)
            else:
                f.scan([root], since, project, progress=False)
            return
        roots = transcript_roots() if agent in ("all", "claude") else []
        if roots:
            f.scan(roots, since, project, progress=False)
        for name, find, scan in (("codex", codex_roots, f.scan_codex),
                                 ("copilot", copilot_roots, f.scan_copilot),
                                 ("gemini", gemini_roots, f.scan_gemini),
                                 ("qwen", qwen_roots, f.scan_qwen)):
            found = find() if agent in ("all", name) else []
            if found:
                f.roots.extend(found)
                scan(found, since, project)

    def fleet(self, days: int | None = None, project: str | None = None) -> Fleet:
        days, project = self._narrow(days, project)
        key = (days, project)
        if key in self._store:
            self._store.move_to_end(key)
        else:
            f = Fleet()
            # The same cutoff as the CLI's --days, so the two never disagree.
            since = window_start(days) if days else None
            self._scan(f, since, project)
            self._store[key] = f
            while len(self._store) > MCP_CACHE_MAX:
                self._store.popitem(last=False)
        return self._store[key]


class _MCPClientError(ValueError):
    """A bad request from the client. Only this is echoed back (-32602): its
    message names what the client sent. Any other ValueError comes from inside
    a scan, may quote paths or data, and gets the redacted -32603 reply."""


_MCP_TOOL_BY_NAME = {t["name"]: t for t in MCP_TOOLS}


def _mcp_call(name: str, args: dict, cache: _MCPCache) -> dict:
    if not isinstance(args, dict):
        raise _MCPClientError("arguments must be an object")

    # Tools that need no scan answer before one is started: a scan takes
    # minutes over a large fleet, and an unknown name must not cost one.
    if name == "explain":
        topic = str(args.get("topic", "")).lower()
        e = EXPLAIN.get(topic)
        if not e:
            return {"topics": sorted(EXPLAIN), "error": f"unknown topic: {topic[:100]}"}
        return {"topic": topic, "measures": e["measures"], "formula": e["formula"],
                "assumes": e["assumes"], "verify_independently": e["verify"]}

    if name == "verify_agents":
        rows = verify_agents()
        return {"agents": rows,
                "note": "a valid signature proves origin and integrity, not safety; "
                        "unsigned is normal for npm and script installs"}

    tool = _MCP_TOOL_BY_NAME.get(name) if isinstance(name, str) else None
    if tool is None:
        raise _MCPClientError(f"unknown tool: {str(name)[:100]}")
    # Only the arguments a tool declares reach the cache key. Otherwise a
    # client varying an ignored `project` forced a fresh full scan per call.
    declared = tool["inputSchema"].get("properties", {})
    project = args.get("project") if "project" in declared else None
    days = clamp_days(args.get("days")) if "days" in declared else None
    if "days" in declared and args.get("days") is not None and days is None:
        # "7" or 7.5 used to mean all time without a word.
        raise _MCPClientError("days must be a whole number of days, e.g. 7")
    f = cache.fleet(days,
                    project[:MCP_MAX_PROJECT] if isinstance(project, str) else None)

    if name == "fleet_summary":
        ctx = Counter()
        for t in f.tokens_by_project.values():
            ctx.update(t)
        modes = recorded_turns(f.permission_modes)
        unsup = ungated_modes(f.permission_modes)
        top = sorted(f.cost_by_project.items(), key=lambda kv: -kv[1])[:8]
        return {
            "window": {"from": f.first_ts.isoformat() if f.first_ts else None,
                       "to": f.last_ts.isoformat() if f.last_ts else None,
                       "active_days": f.active_days},
            "messages": f.messages,
            "cost_usd_list_price": round(f.total_cost, 2),
            # Estimated spend (family or ceiling price), as in --json. Models
            # with no price at all (tier unpriced) add no cost: they are listed
            # with their tokens in unpriced_model_tokens instead.
            "cost_usd_from_unpriced_models": round(f.cost_unknown, 2),
            "unpriced_model_tokens": dict(f.unpriced_tokens),
            "duplicate_usage_records_skipped": f.duplicate_usage_records,
            "cost_note": "provider list prices; a subscription bills a flat fee, so read "
                         "this as consumption rather than a bill. "
                         "cost_usd_from_unpriced_models is the estimated part (models "
                         "priced by family or provider ceiling); models with no "
                         "published rate at all are in unpriced_model_tokens and "
                         "add no cost",
            "cache_hit_rate_pct": round(cache_hit_rate(ctx), 1),
            "cache_saved_usd": round(sum(f.cache_uncached.values())
                                     - sum(f.cache_actual.values()), 2),
            "by_agent": {k: round(v, 2) for k, v in f.cost_by_agent.items()},
            "top_projects": [{"project": p, "cost_usd": round(c, 2)} for p, c in top],
            "shell_commands": f.bash_total,
            "unsupervised_pct": round(unsup / modes * 100, 1) if modes else None,
            "unsupervised_basis": "turns with a recorded permission mode",
            "moded_commands": f.bash_moded,
            "unmoded_commands": max(f.bash_total - f.bash_moded, 0),
        }

    if name == "ticket_cost":
        want = args.get("ticket")
        if isinstance(want, bool) or not isinstance(want, (str, int, type(None))):
            raise _MCPClientError("ticket must be a string, e.g. '#412' or 'PROJ-456'")
        if isinstance(want, int):
            want = str(want)                 # 412 is a natural thing for a model to send
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
        lim = args.get("limit")
        # bool is an int; a negative limit sliced off the last ticket instead.
        lim = (min(max(lim, 1), 200) if isinstance(lim, int) and not isinstance(lim, bool)
               else 15)
        med = _median(list(f.cost_by_ticket.values())) if f.cost_by_ticket else 0
        return {"ticket_count": len(rows), "median_ticket_usd": round(med, 2),
                "unattributed_usd": round(f.cost_by_branch.get("trunk", 0)
                                          + f.cost_by_branch.get("detached HEAD", 0), 2),
                "tickets": [{"ticket": t, "cost_usd": round(c, 2),
                             "branches": len(f.branches_by_ticket[t])} for t, c in rows[:lim]]}

    if name == "exposed_secrets":
        want = args.get("priority", "all")
        rank = {"critical": 0, "high": 1, "low": 2}
        # An unknown priority ("medium") used to return every row unfiltered.
        if not isinstance(want, str) or (want not in rank and want != "all"):
            raise _MCPClientError("priority must be one of critical, high, low, all")
        rows = sorted(f.secrets.items(), key=lambda kv: (rank.get(kv[1]["priority"], 9),
                                                         -kv[1]["uses"]))
        if want in rank:
            rows = [r for r in rows if r[1]["priority"] == want]
        return {
            "distinct_secrets": len(rows),
            # As the report counts it: a credential the user suppressed as not
            # a credential is not worth rotating.
            "worth_rotating": sum(1 for _, e in rows
                                  if e["priority"] != "low" and not e.get("suppressed")),
            "suppressed": sum(1 for _, e in rows if e.get("suppressed")),
            "note": "a fingerprint is sha256[:8] of the value, or for a password, of "
                    "where it appeared; values are never stored or returned. A "
                    "suppressed row was marked as not a credential on this machine",
            "secrets": [{"priority": e["priority"], "types": sorted(e["kinds"]),
                         "fingerprint": fp, "uses": e["uses"],
                         "first_seen": e["first"] or "", "last_seen": e["last"] or "",
                         "projects": sorted(e["projects"]),
                         "distinct_values": e.get("distinct_values", 1),
                         "suppressed": bool(e.get("suppressed")),
                         "suppressed_reason": e.get("suppressed_reason", "")}
                        for fp, e in rows[:50]],
        }

    if name == "coach_findings":
        return {"findings": [{"id": x.id, "severity": x.severity, "title": x.title,
                              "evidence": x.evidence, "action": x.action,
                              "impact": x.impact, "project": x.project}
                             for x in coach(f)]}

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

    raise _MCPClientError(f"unknown tool: {name}")


def _mcp_lines(stream):
    """Lines from stdin, at most MCP_MAX_LINE long. An overlong line is
    drained and yielded as None, so it is refused without ever being held."""
    while True:
        raw = stream.readline(MCP_MAX_LINE + 1)
        if not raw:
            return
        nl = b"\n" if isinstance(raw, bytes) else "\n"
        if len(raw) > MCP_MAX_LINE and not raw.endswith(nl):
            while True:
                more = stream.readline(MCP_MAX_LINE)
                if not more or more.endswith(nl):
                    break
            yield None
            continue
        yield raw


def mcp_serve(scope: dict | None = None) -> int:
    """JSON-RPC over stdio. Nothing but protocol may be written to stdout.

    No line may stop the server: a parse failure answers -32700, anything that
    is not a request object (a batch included) answers -32600, and the loop
    carries on with the next line. `scope` holds the --root, --agent, --days
    and --project it was started with; every answer stays inside them."""
    cache = _MCPCache(scope)
    out = sys.stdout

    def send(obj: dict) -> None:
        out.write(json.dumps(obj) + "\n")
        out.flush()

    def error(rid, code: int, message: str) -> None:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

    # Bytes, decoded leniently: a strict text stdin raised UnicodeDecodeError
    # out of the iterator on one bad byte, outside every handler.
    stdin = getattr(sys.stdin, "buffer", None) or sys.stdin
    for raw in _mcp_lines(stdin):
        if raw is None:
            error(None, -32700, f"parse error: line longer than {MCP_MAX_LINE} bytes")
            continue
        line = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw).strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except (ValueError, RecursionError):    # RecursionError: deeply nested input
            error(None, -32700, "parse error")
            continue
        if not isinstance(req, dict):
            error(None, -32600, "invalid request: batches are not supported"
                  if isinstance(req, list) else "invalid request")
            continue
        method, rid = req.get("method"), req.get("id")
        # NaN and infinity parse, but a reply echoing them is not valid JSON.
        if rid is not None and (isinstance(rid, bool) or not isinstance(rid, (str, int, float))
                                or (isinstance(rid, float)
                                    and (rid != rid or rid in (float("inf"), float("-inf"))))):
            error(None, -32600, "invalid request: id must be a string or number")
            continue
        if not isinstance(method, str):
            error(rid, -32600, "invalid request: method must be a string")
            continue

        # Notifications carry no id and get no reply.
        if rid is None and method.startswith("notifications/"):
            continue

        try:
            if method == "initialize":
                params = req.get("params")
                asked = params.get("protocolVersion") if isinstance(params, dict) else None
                result = {
                    "protocolVersion": asked if asked in MCP_PROTOCOL_VERSIONS
                                       else MCP_PROTOCOL_VERSIONS[0],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "actualis", "version": __version__},
                }
            elif method in ("tools/list", "server/discover"):
                result = {"tools": MCP_TOOLS, "ttlMs": 3_600_000, "cacheScope": "session"}
            elif method == "tools/call":
                params = req.get("params")
                if not isinstance(params, dict):
                    raise _MCPClientError("params must be an object")
                arguments = params.get("arguments")
                payload = _mcp_call(params.get("name"),
                                    {} if arguments is None else arguments, cache)
                result = {"content": [{"type": "text",
                                       "text": json.dumps(payload, indent=2)}],
                          "structuredContent": payload,
                          "isError": False}
            elif method == "ping":
                result = {}
            else:
                if rid is not None:
                    send({"jsonrpc": "2.0", "id": rid,
                          "error": {"code": -32601,
                                    "message": f"method not found: {method[:100]}"}})
                continue
        except _MCPClientError as exc:
            # Deliberate, client-facing: the message names what the caller sent.
            # Any other ValueError falls through to the redacted branch below.
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
    "█": "#",      # bar chart: the unasked share
    "░": ".",      # bar chart: the rest
    "▒": ":",      # approval bar: unknown
    # Sparkline levels, lowest to highest (written as escapes: see _BLOCKS).
    "\u2581": "_", "\u2582": ".", "\u2583": ":", "\u2584": "-",
    "\u2585": "=", "\u2586": "+", "\u2587": "*",
    "\u2295": "[+", "\U0001F310": "net]",     # NET_MARK -> [+net]
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
        if stream is None:
            continue
        if _stream_handles_glyphs(stream):
            # The codec carries every glyph, but a lone surrogate from a
            # transcript is unencodable in any codec: escape it, never raise.
            # (surrogateescape, the default under a C or UTF-8-mode locale,
            # covers only U+DC80-DCFF, so it raises on the rest.)
            if getattr(stream, "errors", "strict") in ("strict", "surrogateescape"):
                try:
                    stream.reconfigure(errors="backslashreplace")
                except (AttributeError, OSError, ValueError):
                    pass
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


def _local_host(host: str) -> bool:
    """Loopback, private (RFC 1918), link-local, *.local and *.localhost hosts:
    not third parties. IPv4 is parsed by hand."""
    h = (host or "").lower().strip("[]").rstrip(".")
    if h in ("localhost", "::1", "0.0.0.0") or h.endswith((".localhost", ".local")):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        a, b = int(parts[0]), int(parts[1])
        return (a in (10, 127) or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or (a == 169 and b == 254))
    return False


NET_VIEW_WIDTH = 100


def _net_wrap(text: str, width: int, breaks: str = " ") -> list[str]:
    """Lines of at most `width`, broken after a character in `breaks` where one
    falls in the last third of the line, else hard. Concatenating the lines
    (with a space when a break was a space) gives the text back."""
    out: list[str] = []
    while len(text) > width:
        cut = max(text.rfind(b, width * 2 // 3, width) for b in breaks)
        if cut < 0:
            out.append(text[:width])
            text = text[width:]
        elif text[cut] == " ":
            out.append(text[:cut])
            text = text[cut + 1:]
        else:
            out.append(text[:cut + 1])
            text = text[cut + 1:]
    return out + [text] if text or not out else out


def _net_when(ts: str | None) -> str:
    return ts[:16].replace("T", " ") if ts else "time unknown"


def _net_what(r: dict) -> str:
    """The program and what it fetched, as one short phrase (fields as printed)."""
    if r["package"]:
        what = r["package"] + (f"@{r['version']}" if r["version"] else "")
    else:
        what = r["url"] or r["dest"] or ""
    return f"{r['program']} {what}".rstrip()


def _net_command(i: dict, raw: bool) -> str:
    cmd = i.get("_command") or ""
    return clip(cmd if raw else redact(cmd), NET_COMMAND_MAX)


def _net_path(t: dict | None) -> str:
    """root/file:line, with the home directory written as ~, or "-"."""
    if not t or not t.get("file"):
        return "-"
    path = str(Path(t["root"]) / t["file"]) if t.get("root") else t["file"]
    home = str(Path.home())
    if home not in ("", "/") and path.startswith(home + os.sep):
        path = "~" + path[len(home):]
    return path + (f":{t['line']}" if t.get("line") else "")


def _net_host_clip(host: str, width: int) -> str:
    """A host cut from the left: the right end is what says who owns it, so
    objects.githubusercontent.com.evil.ru shortens to ...usercontent.com.evil.ru,
    never to objects.githubuserconte..."""
    return host if len(host) <= width else "\u2026" + host[-(width - 1):]


NET_SPARK_MAX = 36          # cells in a sparkline; wider windows share a cell
NET_PER_SESSION = 5         # items listed under each session
NET_SESSIONS = 5            # sessions listed in the default view


def _net_bar(part: int, whole: int, scale: int, width: int) -> str:
    """`whole` drawn against `scale` (the largest whole in the chart) in
    `width` cells, the first `part` of it solid. Anything above zero gets at
    least one cell, so a small count is never drawn as nothing."""
    if scale <= 0 or whole <= 0:
        return " " * width
    w = min(width, max(1, round(whole / scale * width)))
    p = min(w, max(1, round(part / scale * width))) if part else 0
    if part < whole and p == w and w > 1:   # something not unasked is always visible
        p = w - 1
    return ("\u2588" * p + "\u2591" * (w - p)).ljust(width)


def _net_shares(values: list[int], width: int) -> list[int]:
    """`width` cells shared among `values` by largest remainder, so they add
    up to `width`; a value above zero always gets a cell, taken from the
    largest share. The terminal approval bar and the HTML charts both use it,
    so the two cannot disagree on proportions."""
    total = sum(values)
    if not total or width <= 0:
        return [0] * len(values)
    exact = [v * width / total for v in values]
    cells = [int(e) for e in exact]
    for k in sorted(range(len(values)), key=lambda k: -(exact[k] - cells[k]))[:width - sum(cells)]:
        cells[k] += 1
    for k in range(len(values)):
        if values[k] and not cells[k]:
            cells[k] = 1
            cells[max(range(len(values)), key=lambda j: cells[j])] -= 1
    return cells


def _net_approval_bar(t: dict, width: int, c: "C | None" = None) -> str:
    """unasked (solid), unknown (medium), asked (light), in that order, the
    cells shared out by _net_shares so they always add up to `width`."""
    parts = [(t["unasked"], "\u2588"), (t["unknown"], "\u2592"), (t["asked"], "\u2591")]
    if not sum(v for v, _ in parts):
        return " " * width
    cells = _net_shares([v for v, _ in parts], width)
    colours = (c.yellow, c.dim, "") if c else ("", "", "")
    off = c.off if c else ""
    return "".join(f"{col}{g * n}{off}" if n and col else g * n
                   for (_, g), n, col in zip(parts, cells, colours))


def _net_buckets(by_day: list[dict], width: int) -> tuple[list[int], list[int], int]:
    """by_day as at most `width` cells from its first date to its last: items
    and unasked per cell, and the days in each cell. Empty days count as zero.
    Computed from the offsets, never by walking the calendar, so a stray date
    in 9999 costs nothing."""
    first = datetime.strptime(by_day[0]["date"], "%Y-%m-%d").date()
    last = datetime.strptime(by_day[-1]["date"], "%Y-%m-%d").date()
    span = (last - first).days + 1
    step = -(-span // width)
    totals, unasked = [0] * -(-span // step), [0] * -(-span // step)
    for d in by_day:
        k = (datetime.strptime(d["date"], "%Y-%m-%d").date() - first).days // step
        totals[k] += d["items"]
        unasked[k] += d["unasked"]
    return totals, unasked, step


def _net_spark(values: list[int], vmax: int) -> str:
    """One cell per value: blank for zero, else one of eight levels of vmax."""
    return "".join(" " if not v else _BLOCKS[min(7, max(0, -(-v * 8 // vmax) - 1))]
                   for v in values)


def _net_tail(parts: list[str], room: int) -> str:
    """As many whole " \u00b7 "-joined parts as fit in `room`; never a part cut short."""
    out = ""
    for p in parts:
        nxt = p if not out else out + " \u00b7 " + p
        if len(nxt) > room:
            break
        out = nxt
    return out


def _render_network_strip(n: dict, c: "C") -> None:
    """The chart strip; a failure here prints one line and never takes the
    report down (the numbers it would draw are still in --json)."""
    try:
        _render_network_strip_inner(n, c)
    except Exception as exc:                  # noqa: BLE001
        print(f"  {c.dim}charts unavailable ({type(exc).__name__}); "
              f"actualis --network --json has the numbers{c.off}")


def _render_network_strip_inner(n: dict, c: "C") -> None:
    """Approval share, downloads per day with the unasked under it on the
    same scale, and the mix of kinds. Every number printed is in --json
    (totals, by_day, by_kind); see --explain network."""
    t = n["totals"]
    label = lambda s: f"  {s:<10}"               # noqa: E731
    print(label("approval") + _net_approval_bar(t, 32, c)
          + f"   unasked {num(t['unasked'])} \u00b7 unknown {num(t['unknown'])}"
          f" \u00b7 asked {num(t['asked'])}")
    by_day = n["by_day"]
    undated = [f"{num(n['by_day_undated'])} undated"] if n["by_day_undated"] else []
    if not by_day:
        print(label("per day") + f"{c.dim}{_net_tail(['no timestamps'] + undated, 88)}{c.off}")
    elif len(by_day) == 1:
        print(label("per day") + _net_tail([f"all on {by_day[0]['date']}"] + undated, 88))
    else:
        totals, unasked, step = _net_buckets(by_day, NET_SPARK_MAX)
        vmax = max(totals)
        peak = max(by_day, key=lambda d: (d["items"], d["date"]))
        width = len(totals)
        tail = _net_tail([f"{by_day[0]['date']} \u2192 {by_day[-1]['date']}",
                          f"peak {num(peak['items'])} on {peak['date']}"] + undated,
                         NET_VIEW_WIDTH - 12 - width - 3)
        print(label("per day") + _net_spark(totals, vmax).ljust(width) + "   " + tail)
        note = "same scale" + ("" if step == 1 else f", {num(step)} days a cell")
        print(label("unasked") + f"{c.yellow}{_net_spark(unasked, vmax).ljust(width)}{c.off}"
              f"   {c.dim}{note}{c.off}")
    kinds = sorted(((k, v) for k, v in n["by_kind"].items() if v), key=lambda kv: (-kv[1], kv[0]))
    if kinds:
        top_k = kinds[0][1]
        parts = [f"{k} {num(v)} {_net_bar(v, v, top_k, 6).rstrip()}" for k, v in kinds]
        print(clip(label("kind") + "  ".join(parts), NET_VIEW_WIDTH))


def _net_rank_row(lead: str, part: int, whole: int, scale: int, tail: str, c: "C") -> str:
    """A ranking row: `lead` (already padded), a 20-cell bar, `part / whole`
    right-aligned, and a dim `tail` in what room is left. Counts too wide for
    their column take cells from the bar, so the row stays in 100 columns."""
    ratio = f"{num(part)} / {num(whole)}"
    bar_w = max(0, 20 - max(0, len(ratio) - 13))
    row = f"{lead} {_net_bar(part, whole, scale, bar_w)}  {ratio:>13}"
    room = NET_VIEW_WIDTH - len(row) - 2
    if tail and room > 0:
        row += f"  {c.dim}{clip(tail, room)}{c.off}"
    return row


def _render_network_sessions(fleet: "Fleet", n: dict, c: "C", top: int, raw: bool) -> None:
    """The unasked downloads (else the unknown ones) grouped by session, so a
    burst reads as one task: newest session first, each in the order it ran."""
    t = n["totals"]
    want = "unasked" if t["unasked"] else "unknown" if t["unknown"] else None
    if not want:
        return
    groups: dict[str, list[dict]] = {}
    size: Counter = Counter()
    for i in fleet.network_items:
        size[i["session"] or ""] += 1
        if i["approval"] == want:
            groups.setdefault(i["session"] or "", []).append(i)
    for g in groups.values():
        g.sort(key=_net_order_key)
    order = sorted(groups, key=lambda s: (max(_net_utc_key(i["ts"]) for i in groups[s]), s), reverse=True)
    shown = order[:min(max(top, 0), NET_SESSIONS)]
    print(f"  {want.upper()}, BY SESSION   {c.dim}newest first{c.off}")
    for sid in shown:
        rows = [_net_public(i, raw) for i in groups[sid]]
        one_day = len({(r["ts"] or "")[:10] for r in rows[:NET_PER_SESSION]}) == 1
        many = size[sid]
        counts = f"{num(many)} download{'' if many == 1 else 's'}, "
        flagged = f"{num(len(rows))} {want}"
        proj_w = max(8, min(28, NET_VIEW_WIDTH - 34 - len(counts) - len(flagged)))
        print(f"    {_net_when(rows[0]['ts']):<16}  {clip(rows[0]['project'], proj_w):<{proj_w}}  "
              f"{(sid[:8] or '(none)'):<8}  {counts}{c.yellow}{flagged}{c.off}")
        for r in rows[:NET_PER_SESSION]:
            ts = r["ts"] or ""
            when = ts[11:16] if one_day else ts[5:16].replace("T", " ")
            room = NET_VIEW_WIDTH - 6 - 11 - 2 - 2 - 24
            what = _net_what(r)                  # cut, not clip: clip drops the URL at its space
            what = what if len(what) <= room else what[:room - 1] + "\u2026"
            print(f"      {when or '--:--':<11}  {what:<{room}}  "
                  f"{c.dim}{_net_host_clip(r['host'] or '-', 24)}{c.off}")
            if r["why"]:
                print(f"        {c.dim}why: {clip(r['why'], NET_VIEW_WIDTH - 13)}{c.off}")
        if len(rows) > NET_PER_SESSION:
            print(f"      {c.dim}\u2026 {num(len(rows) - NET_PER_SESSION)} more{c.off}")
        if sid:
            print(f"      {c.dim}\u2192 actualis --network --session {sid[:8]}{c.off}")
    if len(order) > len(shown):
        print(f"    {c.dim}\u2026 {num(len(order) - len(shown))} more sessions{c.off}")


def _render_network_items(fleet: "Fleet", c: "C", top: int, raw: bool,
                          filters: list[str]) -> None:
    """Every item the filters kept, newest first, one block each."""
    order = sorted(fleet.network_items, key=_net_order_key, reverse=True)
    limit = max(top, 0) * 5
    print(f"  {c.dim}showing {num(min(limit, len(order)))} of {num(len(order))}, newest first{c.off}")
    pad = " " * 13
    width = NET_VIEW_WIDTH - len(pad)
    per_session = Counter(i["session"] or "" for i in order)
    last_session = None
    for i in order[:limit]:
        r = _net_public(i, raw, prompts=True)
        if (r["session"] or "") != last_session:
            last_session = r["session"] or ""
            k = per_session[last_session]
            print()
            print(f"  session {(last_session[:8] or '(none)')} \u00b7 "
                  f"{clip(r['project'], 48)} \u00b7 {num(k)} download{'' if k == 1 else 's'}")
        kind = r["kind"] + ((", pinned" if r["pinned"] else ", unpinned") if r["kind"] == "install" else "")
        print()
        head = f"  {r['host'] or '(no host)'}  \u00b7  {_net_what(r)}"
        tail = f"  ({kind})"
        print(clip(head, NET_VIEW_WIDTH - len(tail)) + tail)
        lead = f"{_net_when(r['ts'])}  \u00b7  {r['agent']} \u00b7 project "
        sess = f" \u00b7 session {(r['session'] or '-')[:8]}"
        fields = [("when", lead + clip(r["project"], max(width - len(lead) - len(sess), 8)) + sess, True)]
        asked = f"{r['approval']} ({r['mode'] or 'mode not recorded'})"
        asked += (" \u00b7 failed" if r["failed"] else "") + (" \u00b7 trusted" if r["trusted"] else "") \
            + (f" \u00b7 ioc {r['ioc']}" if r["ioc"] else "")
        fields.append(("asked", asked, True))
        fields.append(("command", _net_command(i, raw), False))
        if r["why"]:
            fields.append(("why", r["why"], False))
        if r["prompt"]:
            fields.append(("prompt", r["prompt"], False))
        for label, value, one_line in fields:
            lines = [clip(value, width)] if one_line else _net_wrap(value, width)
            print(f"    {label:<9}{lines[0]}")
            for more in lines[1:]:
                print(pad + more)
        trace = f"{r['call_id'] or '-'} \u00b7 {_net_path(r['transcript'])}"
        if len(trace) <= width:
            print(f"    {'trace':<9}{trace}")
        else:                                # the path whole, broken after a /, never cut
            print(f"    {'trace':<9}{clip(r['call_id'] or '-', width)}")
            for part in _net_wrap(_net_path(r["transcript"]), width, "/"):
                print(pad + part)
    if len(order) > limit:
        print()
        print(f"  {c.dim}\u2026 {num(len(order) - limit)} more, narrow with --days or --session{c.off}")


def render_network(fleet: Fleet, c: C, top: int, raw: bool = False,
                   filters: list[str] | None = None) -> None:
    """NETWORK: what came in, and from where; unasked first. Every printed
    field comes from network_json or _net_public, redacted unless raw, or
    from _net_command, which redacts too. `filters`, when given, names the
    --network filters in force and switches to one block per item."""
    n = network_json(fleet, raw)
    t = n["totals"]
    rule(c, "NETWORK")
    try:                                   # a self-check on the numbers; never a crash
        problems = network_reconciles(n)
    except Exception as exc:               # noqa: BLE001
        problems = [f"check failed: {type(exc).__name__}"]
    if problems:
        print(f"  {c.red}\u25b2 network totals do not reconcile: {'; '.join(problems)[:200]}. "
              f"Do not trust these numbers.{c.off}")
    if not t["items"]:
        print(f"  {c.dim}no downloads seen{c.off}")
        render_ioc(fleet, c, raw)              # an empty inventory is still an answer to --ioc
        render_reputation(fleet, c)
        return
    share = f" ({t['unasked'] * 100 // t['items']}%)" if t["unasked"] else ""
    print(f"  {num(t['items'])} download{'' if t['items'] == 1 else 's'} · {c.yellow}{num(t['unasked'])} unasked{share}{c.off}"
          f" · {num(t['unknown'])} unknown"
          + (f" · {num(t['failed'])} failed" if t["failed"] else ""))
    if t["unknown"]:
        print(f"  {c.dim}unknown = no record of who approved it (an allowlist rule in default "
              f"mode, or an agent with none){c.off}")
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
    render_ioc(fleet, c, raw)
    render_reputation(fleet, c)
    items = fleet.network_items
    if filters:
        joined = " \u00b7 ".join(filters)
        # Clip the text, not the escape-wrapped string: slicing that dropped the
        # trailing reset and left the rest of the report dim.
        print(f"  {c.dim}{clip('FILTER   ' + joined, NET_VIEW_WIDTH - 2)}{c.off}")
    _render_network_strip(n, c)
    if filters:
        _render_network_items(fleet, c, top, raw, filters)
        return

    eco = Counter(i["ecosystem"] for i in items if i["kind"] == "install" and i["ecosystem"])
    unpinned = sum(1 for p in n["packages"] if not p["pinned"])
    if eco:
        parts = " \u00b7 ".join(f"{k} {num(v)}" for k, v in sorted(eco.items(), key=lambda kv: (-kv[1], kv[0])))
        print(f"  {'INSTALLED':<10}{parts}"
              + (f"   {c.dim}{num(unpinned)} unpinned package(s){c.off}" if unpinned else ""))
    clones = Counter(i["host"] or "(remote name)" for i in items if i["kind"] == "clone")
    if clones:
        parts = " \u00b7 ".join(f"{h} {num(v)}" for h, v in sorted(clones.items(), key=lambda kv: (-kv[1], kv[0]))[:top])
        print(clip(f"  {'CLONED':<10}{num(sum(clones.values()))}   {parts}", NET_VIEW_WIDTH))
    rows_max = min(10, max(top, 0))

    # Real remote hosts are ranked; host-less and local ones are counted on
    # one line, since a row reading `?  git` says nothing a reader can act on.
    hosts = sorted((h for h in n["hosts"] if not _local_host(h["host"])),
                   key=lambda h: (-h["unasked"], -h["count"], h["host"]))[:rows_max]
    n_nohost = sum(1 for i in items if not i["host"])
    n_local = sum(h["count"] for h in n["hosts"] if _local_host(h["host"]))
    if hosts or n_nohost or n_local:
        print()
        print(f"  TOP HOSTS{' ' * 48}{c.dim}unasked / all{c.off}")
        scale = max((h["count"] for h in hosts), default=0)
        for h in hosts:
            seen = "trusted" if h["trusted"] else f"first {(h['first_seen'] or '?')[:10]}"
            print(_net_rank_row(f"    {_net_host_clip(h['host'], 32):<32}", h["unasked"], h["count"],
                                scale, seen, c))
        extra = ([f"{num(n_nohost)} with no host (git remote names, $VAR URLs)"] if n_nohost else []) \
            + ([f"{num(n_local)} local or private"] if n_local else [])
        if extra:
            joined = " \u00b7 ".join(extra)
            print(f"    {c.dim}plus {joined}{c.off}")

    pkgs = n["packages"][:rows_max]
    if pkgs:
        print()
        print(f"  TOP PACKAGES{' ' * 45}{c.dim}unasked / all{c.off}")
        scale = max(p["count"] for p in pkgs)
        for p in pkgs:
            flags = ", ".join(p["versions"][:2]) or "no version"
            flags += ("" if p["pinned"] else " \u00b7 unpinned") + (" \u00b7 exec" if p["exec"] else "")
            print(_net_rank_row(f"    {(p['ecosystem'] or '-'):<6} {clip(p['name'], 25):<25}",
                                p["unasked"], p["count"], scale, flags, c))

    if len(n["by_project"]) >= 2:
        print()
        print(f"  BY PROJECT{' ' * 47}{c.dim}unasked / all{c.off}")
        projects = n["by_project"][:rows_max]
        scale = max(p["items"] for p in projects)
        for p in projects:
            print(_net_rank_row(f"    {clip(p['project'] or '-', 32):<32}", p["unasked"], p["items"],
                                scale, "", c))
        if len(n["by_project"]) > len(projects):
            print(f"    {c.dim}\u2026 {num(len(n['by_project']) - len(projects))} more{c.off}")

    print()
    _render_network_sessions(fleet, n, c, top, raw)


# --------------------------------------------------------------------------
# --network --html: the network view as one self-contained page. Pure: the
# page is a function of network_json and the flags, so the same input gives
# the same bytes. Everything from a transcript goes through _h().

NET_HTML_NAME = "actualis-network"
NET_HTML_DAY_CELLS = 120        # bars in the per-day chart; wider spans share a bar
NET_HTML_RANK_ROWS = 15

_NET_HTML_SCRIPT = (
    "document.querySelectorAll('th').forEach(function(th){th.addEventListener('click',function(){"
    "var tb=th.closest('table').tBodies[0],k=+th.dataset.k,d=th.dataset.d==='1'?-1:1;"
    "th.dataset.d=d===1?'1':'0';var rows=Array.prototype.slice.call(tb.rows);"
    "rows.sort(function(a,b){var x=a.cells[k].textContent,y=b.cells[k].textContent,"
    "nx=parseFloat(x.replace(/,/g,'')),ny=parseFloat(y.replace(/,/g,''));"
    "return(!isNaN(nx)&&!isNaN(ny)&&/^[\\d,.]+$/.test(x)&&/^[\\d,.]+$/.test(y)?nx-ny:x.localeCompare(y))*d;});"
    "rows.forEach(function(r){tb.appendChild(r);});});});"
    "document.querySelectorAll('input.flt').forEach(function(i){i.hidden=false;"
    "i.addEventListener('input',function(){var q=i.value.toLowerCase();"
    "Array.prototype.forEach.call(document.getElementById(i.dataset.t).tBodies[0].rows,"
    "function(r){r.hidden=!!q&&r.textContent.toLowerCase().indexOf(q)<0;});});});")

_NET_HTML_STYLE = (
    ":root{--bg:#fbfaf7;--fg:#1d1c1a;--mut:#6b6862;--line:#e3e0d8;--un:#c99700;--uk:#a8a49b;"
    "--as:#e8e5de;--card:#fff;--bad:#b42318}"
    "@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mut:#9d9a93;"
    "--line:#2c2b28;--un:#e6b422;--uk:#6e6b65;--as:#3a3935;--card:#1c1c1a;--bad:#ff6b5b}}"
    "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);"
    "font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}"
    "main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0}"
    "h2{font-size:16px;margin:32px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}"
    "h3{font-size:14px;margin:16px 0 6px;color:var(--mut)}.meta,.note{color:var(--mut);font-size:13px}"
    ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:16px}"
    ".tile{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px}"
    ".tile b{display:block;font-size:22px;font-variant-numeric:tabular-nums}"
    ".tile span{color:var(--mut);font-size:12px}svg{width:100%;height:auto;display:block}"
    ".b-unasked{fill:var(--un)}.b-unknown{fill:var(--uk)}.b-asked{fill:var(--as)}"
    ".b-other{fill:var(--uk);opacity:.45}.ax{font-size:11px;fill:var(--mut)}.axis{stroke:var(--line)}"
    ".lg{display:inline-block;width:10px;height:10px;margin:0 4px 0 12px;border-radius:2px}"
    ".lg.b-unasked{background:var(--un)}.lg.b-unknown{background:var(--uk)}"
    ".lg.b-asked{background:var(--as)}.lg.b-other{background:var(--uk);opacity:.45}"
    ".cols{display:grid;grid-template-columns:1fr 1fr;gap:24px}"
    "@media(max-width:720px){.cols{grid-template-columns:1fr}}"
    ".rk{display:grid;grid-template-columns:minmax(0,40%) 1fr auto;gap:8px;align-items:center;"
    "font-size:13px;margin:3px 0}.rk svg{height:10px}.rl{overflow-wrap:anywhere}"
    ".rn{font-variant-numeric:tabular-nums;color:var(--mut)}"
    ".tw{overflow-x:auto;border:1px solid var(--line);border-radius:6px}"
    "table{border-collapse:collapse;width:100%;font-size:13px}"
    "th,td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}"
    "th{cursor:pointer;background:var(--card);white-space:nowrap}td.n{text-align:right;"
    "font-variant-numeric:tabular-nums}td{max-width:340px;overflow-wrap:anywhere}"
    ".flt{margin:6px 0;padding:4px 8px;border:1px solid var(--line);border-radius:4px;"
    "background:var(--card);color:var(--fg)}code,pre{font:12px ui-monospace,Menlo,monospace}"
    "code{word-break:break-all}.bad{color:var(--bad);font-weight:600}"
    "pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;"
    "background:var(--card);padding:8px;border:1px solid var(--line)}")


def _h(s: object) -> str:
    """Any value as HTML text or attribute: cleaned, then escaped."""
    if s is None:
        return ""
    return _html.escape(clean(s) if isinstance(s, str) else str(s), quote=True)


def _net_html_when(ts: str | None) -> str:
    """An item timestamp as YYYY-MM-DD HH:MM in UTC."""
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, OverflowError):
        return ts[:16]


def _net_utc_key(ts: str | None) -> str:
    """A timestamp as a sortable UTC string: items keep the transcript's own
    offset, so raw strings from two zones do not compare in time order."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).isoformat() if dt.tzinfo is not None else ts
    except (ValueError, OverflowError):
        return ts


def _net_html_ioc(j: dict) -> str:
    """The IOC block when --ioc was given, as render_ioc prints it: totals,
    each list with its sha256, and every match. Empty without --ioc."""
    if not j["enabled"]:
        return ""
    t = j["totals"]
    out = [f'<h2>IOC</h2><p><span class="{"bad" if t["match"] else ""}">{t["match"]:,} match</span>'
           f' &middot; {t["unresolved"]:,} unresolved'
           + "".join(f" &middot; {t[k]:,} {k}" for k in ("refused", "suppressed") if t[k])
           + f' &middot; {t["items_checked"]:,} checkable downloads checked</p>']
    out.append(_html_table("t-ioc-lists", ["list", "sha256", "format", "package entries", "host entries",
                                           "modified during the window"], [
        [_h(Path(src["path"]).name), _h(src["sha256"]), _h(src["format"]), src["entries"]["package"],
         src["entries"]["host"], "yes" if src["mtime_in_window"] else "no"] for src in j["sources"]]))
    if j["matches"]:
        rows = []
        for r in j["matches"]:
            i = r["item"]
            if r["refused"]:
                state = "never ran"
            elif r["suppressed"]:
                state = "suppressed"
            elif r["verdict"] == "match":
                state = ""
            else:
                state = _IOC_REASON_TEXT.get(r["reason"], r["reason"] or "")
            rows.append([_h("REFUSED" if r["refused"] else r["verdict"].upper()), _h(_net_what(i)),
                         _h(", ".join(r["refs"]) or "-"), _h(", ".join(r["labels"]) or "-"),
                         _h(i["project"] or "-"), _h(_net_html_when(i["ts"])), _h(i["approval"]),
                         _h(state)])
        out.append(_html_table("t-ioc", ["verdict", "what", "refs", "labels", "project", "when (UTC)",
                                         "approval", "note"], rows))
        if j["matches_truncated"]:
            out.append('<p class="note">More matches than listed; --network --json --ioc has them all.</p>')
    out.append('<p class="note">No match is not "not affected": this covers the transcripts still on '
               "this machine in the window, and lockfile installs, scripts and postinstall hooks are "
               "not visible. See actualis --explain ioc.</p>")
    return "".join(out)


def _net_html_blob(n: dict) -> str:
    """The JSON as embedded: sorted, compact, ASCII, and with < > & escaped so
    no value can close the script element. Still valid JSON for the same object."""
    s = json.dumps(n, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _svg_day_bars(by_day: list[dict], undated: int) -> str:
    if not by_day:
        return '<p class="note">No dated downloads.</p>'
    totals, unasked, step = _net_buckets(by_day, NET_HTML_DAY_CELLS)
    first = datetime.strptime(by_day[0]["date"], "%Y-%m-%d").date()
    last = datetime.strptime(by_day[-1]["date"], "%Y-%m-%d").date()
    vmax = max(totals) or 1
    w, h, pad = 1000, 160, 4
    bw = (w - 2 * pad) / len(totals)
    out = [f'<svg viewBox="0 0 {w} {h + 24}" role="img" aria-label="Downloads per day">']
    for k, (items, un) in enumerate(zip(totals, unasked)):
        if not items:
            continue
        start = first + timedelta(days=k * step)
        end = last if (last - start).days < step - 1 else start + timedelta(days=step - 1)
        when = start.isoformat() if start == end else f"{start.isoformat()} to {end.isoformat()}"
        x, hi, hu = pad + k * bw, h * items / vmax, h * un / vmax
        out.append(f'<g><title>{when}: {items:,} downloads, {un:,} unasked</title>'
                   f'<rect class="b-other" x="{x:.1f}" y="{h - hi:.1f}" width="{bw * 0.8:.1f}" '
                   f'height="{hi - hu:.1f}"/><rect class="b-unasked" x="{x:.1f}" y="{h - hu:.1f}" '
                   f'width="{bw * 0.8:.1f}" height="{hu:.1f}"/></g>')
    out.append(f'<line class="axis" x1="{pad}" y1="{h}" x2="{w - pad}" y2="{h}"/>'
               f'<text class="ax" x="{pad}" y="{h + 18}">{first.isoformat()}</text>'
               f'<text class="ax" x="{w - pad}" y="{h + 18}" text-anchor="end">{last.isoformat()}</text>'
               "</svg>")
    out.append('<p class="note"><span class="lg b-unasked"></span>unasked'
               '<span class="lg b-other"></span>unknown or asked'
               + (f" &middot; one bar is {step} days" if step > 1 else "") + "</p>")
    if undated:
        out.append(f'<p class="note">{undated:,} downloads have no date and are not in this chart.</p>')
    return "".join(out)


def _svg_approval_bar(t: dict) -> str:
    parts = [("unasked", t["unasked"], "b-unasked"), ("unknown", t["unknown"], "b-unknown"),
             ("asked", t["asked"], "b-asked")]
    total = sum(v for _, v, _ in parts) or 1
    cells = _net_shares([v for _, v, _ in parts], 1000)
    out, x = ['<svg viewBox="0 0 1000 34" role="img" aria-label="Approval">'], 0
    for (name, v, cls), wd in zip(parts, cells):
        if wd:
            out.append(f'<rect class="{cls}" x="{x}" y="0" width="{wd}" height="34">'
                       f'<title>{name}: {v:,} ({v * 100 // total}%)</title></rect>')
        x += wd
    out.append("</svg><p class=\"note\">")
    out.append("".join(f'<span class="lg {cls}"></span>{name} {v:,}' for name, v, cls in parts))
    return "".join(out) + "</p>"


def _svg_rank_bars(title: str, rows: list[tuple[str, int, int]]) -> str:
    """Rows of (label, unasked, total), drawn as total with unasked over it."""
    if not rows:
        return ""
    vmax = max(whole for _, _, whole in rows) or 1
    out = [f"<h3>{title}</h3><div class=\"ranks\">"]
    for label, part, whole in rows:
        out.append(f'<div class="rk"><span class="rl">{_h(label)}</span>'
                   f'<svg viewBox="0 0 100 10" preserveAspectRatio="none" role="img" '
                   f'aria-label="{_h(label)}"><title>{_h(label)}: {part:,} unasked of {whole:,}</title>'
                   f'<rect class="b-other" width="{100 * whole / vmax:.2f}" height="10"/>'
                   f'<rect class="b-unasked" width="{100 * part / vmax:.2f}" height="10"/></svg>'
                   f'<span class="rn">{part:,} / {whole:,}</span></div>')
    return "".join(out) + "</div>"


def _html_table(tid: str, cols: list[str], rows: list[list]) -> str:
    """A table whose int cells are right-aligned and comma-grouped. The filter
    box is hidden until the script shows it, so with scripts off it is absent."""
    head = "".join(f'<th data-k="{k}">{_h(c)}</th>' for k, c in enumerate(cols))
    body = []
    for r in rows:
        cells = "".join(f'<td class="n">{v:,}</td>' if isinstance(v, int) and not isinstance(v, bool)
                        else f"<td>{v}</td>" for v in r)
        body.append(f"<tr>{cells}</tr>")
    return (f'<input class="flt" data-t="{tid}" placeholder="filter" aria-label="filter" hidden>'
            f'<div class="tw"><table id="{tid}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def _net_html_reputation(n: dict, flags: "list[dict] | None") -> str:
    r = n.get("reputation") or {}
    if not r.get("enabled"):
        return ""
    rows = "".join(f"<li>{_h(f['evidence'])}</li>" for f in (flags or [])
                   if set(f["categories"]) & set(REPUTATION_FLAG_CATEGORIES))
    adv = r["advisory"]
    foot = (f'<p class="dim"><a href="{_h(adv["url"])}">{_h(adv["text"])}</a>. Lists can be wrong both ways.</p>'
            if adv["text"] else "")
    t = r["totals"]
    return (f'<section id="reputation"><h2>Reputation</h2><p>{t["listed"]} listed &middot; '
            f'{t["candidate"]} candidate &middot; {t["checked"]} checked &middot; '
            f'{t["skipped"]} private skipped</p><ul>{rows}</ul>{foot}</section>')


def render_network_html(n: dict, *, filters: list[str], version: str, with_prompts: bool,
                        flags: "list[dict] | None" = None) -> str:
    """The --network --html page. Every number on it is read from `n`, the
    object --network --json prints, which is also embedded verbatim."""
    t = n["totals"]
    items = n["items"]
    truncated = len(items) < t["items"]
    blob = _net_html_blob(n)
    digest = hashlib.sha256(blob.encode("ascii")).hexdigest()
    sh = base64.b64encode(hashlib.sha256(_NET_HTML_SCRIPT.encode("ascii")).digest()).decode()
    csp = (f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{sh}'; "
           "img-src data:; base-uri 'none'; form-action 'none'")
    window = (f"{n['by_day'][0]['date']} to {n['by_day'][-1]['date']} UTC"
              if n["by_day"] else "no dated downloads")
    sessions: dict = {}
    for i in items:
        s = sessions.setdefault(i["session"] or "-", {"start": i["ts"] or "", "project": i["project"],
                                                      "n": 0, "u": 0})
        if i["ts"] and (not s["start"] or _net_utc_key(i["ts"]) < _net_utc_key(s["start"])):
            s["start"] = i["ts"]
        s["n"] += 1
        s["u"] += i["approval"] == "unasked"
    listed = " in listed items" if truncated else ""
    pct = t["unasked"] * 100 // t["items"] if t["items"] else 0

    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
           f"<title>actualis network report</title><style>{_NET_HTML_STYLE}</style></head>"
           "<body><main><h1>actualis network report</h1>"
           f'<p class="meta">actualis {_h(version)} &middot; {_h(window)} &middot; filters: '
           f'{_h(", ".join(filters)) if filters else "none"}</p>'
           '<p class="meta"><b>unasked</b>: ran in a mode that never stops to ask. '
           "<b>unknown</b>: the mode could have asked; the transcript does not say. "
           "<b>asked</b>: a person approved it.</p>"]
    try:                                   # a self-check on the numbers; never a crash
        problems = network_reconciles(n)
    except Exception as exc:               # noqa: BLE001
        problems = [f"check failed: {type(exc).__name__}"]
    if problems:
        out.append(f'<p class="bad">Network totals do not reconcile: {_h("; ".join(problems)[:200])}. '
                   "Do not trust these numbers.</p>")
    out.append(_net_html_ioc(n["ioc"]))
    out.append(_net_html_reputation(n, flags))
    if not t["items"]:
        out.append("<p>No downloads were recorded"
                   + (" for these filters" if filters else "") + ".</p>")
    else:
        tiles = [(t["items"], "downloads"), (t["unasked"], f"unasked ({pct}%)"),
                 (t["unknown"], "unknown"), (t["asked"], "asked"), (t["failed"], "failed"),
                 (len(n["hosts"]), "hosts"), (len(n["packages"]), "packages"),
                 (len(sessions), "sessions" + listed), (len(n["by_project"]), "projects")]
        out.append('<div class="tiles">' + "".join(
            f'<div class="tile"><b>{v:,}</b><span>{_h(label)}</span></div>' for v, label in tiles)
            + "</div>")
        out.append("<h2>Downloads per day</h2>" + _svg_day_bars(n["by_day"], n["by_day_undated"]))
        out.append("<h2>Approval</h2>" + _svg_approval_bar(t))
        hosts = [(h["host"], h["unasked"], h["count"]) for h in n["hosts"][:NET_HTML_RANK_ROWS]]
        pkgs = [(f"{p['ecosystem']} {p['name']}", p["unasked"], p["count"])
                for p in n["packages"][:NET_HTML_RANK_ROWS]]
        out.append('<div class="cols"><div>' + _svg_rank_bars("Top hosts (unasked / total)", hosts)
                   + "</div><div>" + _svg_rank_bars("Top packages (unasked / total)", pkgs)
                   + "</div></div>")
        if len(n["by_project"]) > 1:
            out.append(_svg_rank_bars("By project (unasked / total)", [
                (p["project"] or "-", p["unasked"], p["items"])
                for p in n["by_project"][:NET_HTML_RANK_ROWS]]))
        out.append("<h2>Hosts</h2>" + _html_table("t-hosts", ["host", "downloads", "unasked",
                                                             "first seen (UTC)", "trusted"], [
            [_h(h["host"]), h["count"], h["unasked"], _h(_net_html_when(h["first_seen"])),
             "yes" if h["trusted"] else "no"] for h in n["hosts"]]))
        out.append("<h2>Packages</h2>" + _html_table("t-packages", ["ecosystem", "name", "versions",
                                                                   "pinned", "downloads", "unasked"], [
            [_h(p["ecosystem"]), _h(p["name"]), _h(", ".join(p["versions"])) or "-",
             "yes" if p["pinned"] else "no", p["count"], p["unasked"]] for p in n["packages"]]))
        out.append("<h2>Projects</h2>" + _html_table("t-projects", ["project", "downloads", "unasked"], [
            [_h(p["project"] or "-"), p["items"], p["unasked"]] for p in n["by_project"]]))
        out.append(f"<h2>Sessions{listed}</h2>" + _html_table(
            "t-sessions", ["start (UTC)", "project", "session", "downloads", "unasked"], [
                [_h(_net_html_when(s["start"])), _h(s["project"] or "-"), _h(sid[:8]), s["n"], s["u"]]
                for sid, s in sorted(sessions.items(), key=lambda kv: (_net_utc_key(kv[1]["start"]), kv[0]),
                                     reverse=True)]))
        cols = ["when (UTC)", "host", "what", "approval", "mode", "agent", "project", "session",
                "why", "trace", "ioc"] + (["prompt"] if with_prompts else [])
        rows = []
        for i in items:
            row = [_h(_net_html_when(i["ts"])), _h(i["host"] or "-"), _h(_net_what(i)),
                   _h(i["approval"]) + (" &middot; failed" if i["failed"] else ""), _h(i["mode"] or "-"), _h(i["agent"] or "-"),
                   _h(i["project"] or "-"), _h((i["session"] or "-")[:8]), _h(i["why"] or ""),
                   f"{_h(i['call_id'] or '-')} &middot; {_h(_net_path(i['transcript']))}",
                   f'<span class="bad">{_h(i["ioc"])}</span>' if i["ioc"] else ""]
            if with_prompts:
                row.append(_h(i["prompt"] or ""))
            rows.append(row)
        out.append("<h2>Every download</h2>" + _html_table("t-items", cols, rows))
        if truncated:
            out.append(f'<p class="note">{t["items"] - len(items):,} more not listed; '
                       "narrow with --days or --session.</p>")
    check = ("actualis --network --json SAME-FLAGS | python3 -c 'import json,re,sys; "
             "p=open(sys.argv[1]).read(); print(json.loads(re.search(r\"actualis-network\\\">"
             "(.*?)</script>\", p, re.S).group(1)) == json.load(sys.stdin))' REPORT.html")
    out.append("<h2>Data</h2>"
               '<p class="meta">Every number above is read from the object '
               "<code>actualis --network --json</code> prints for the same flags, embedded below. "
               f"sha256 of the embedded text: <code>{digest}</code></p>"
               f'<p class="meta">Check it (prints True):</p><pre>{_h(check)}</pre>'
               '<p class="meta">The object is in this page\'s source, in '
               '<code>&lt;script id="actualis-network"&gt;</code>.</p>'
               f'<script type="application/json" id="actualis-network">{blob}</script>'
               f"<script>{_NET_HTML_SCRIPT}</script></main></body></html>\n")
    return "".join(out)


def network_html_path(out_dir: Path) -> Path:
    """The first actualis-network[-N].html that does not exist yet."""
    k = 1
    while True:
        p = out_dir / (f"{NET_HTML_NAME}.html" if k == 1 else f"{NET_HTML_NAME}-{k}.html")
        if not os.path.lexists(p):          # a dangling symlink is taken too
            return p
        k += 1


def write_network_html(page: str, out_dir: Path) -> Path:
    """Write the page, never over an existing file: O_EXCL makes that hold
    even under a race, and a lost race takes the next name. 0600 because the
    page holds commands and URLs from the user's transcripts."""
    data = page.encode("utf-8", "replace")     # a lone surrogate must not abort the write
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(100):                     # a lost race takes the next name; bounded
        path = network_html_path(out_dir)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        break
    else:
        raise FileExistsError(f"no free {NET_HTML_NAME}-N.html name after 100 tries")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


# Characters that start a new line in a terminal or a Markdown job summary.
# clean() keeps newlines on purpose (a command is multi-line), so a model id, branch,
# cwd or session id holding one printed whole fake lines -- a forged "no
# high-severity findings", or a ``` that closed the action's code fence.
_LINE_BREAKS = re.compile("[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")


def _one_line(text: str) -> str:
    """text with every line break made visible: a newline or carriage return
    as the two characters backslash-n or backslash-r, any other separator as a
    space. For display only: --json keeps
    the raw value, which JSON escapes anyway."""
    if not isinstance(text, str) or not _LINE_BREAKS.search(text):
        return text
    return _LINE_BREAKS.sub(lambda m: {"\n": "\\n", "\r": "\\r"}.get(m.group(), " "), text)


def _display_safe(v):
    """v with _one_line applied to every string in it, keys included; the
    container types (Counter, defaultdict, namedtuple, set) are kept."""
    if isinstance(v, str):
        return _one_line(v)
    if isinstance(v, dict):
        out = v.copy()
        out.clear()
        for k, x in v.items():
            out[_display_safe(k)] = _display_safe(x)
        return out
    if isinstance(v, list):
        return [_display_safe(x) for x in v]
    if isinstance(v, tuple):
        items = [_display_safe(x) for x in v]
        return type(v)(*items) if hasattr(v, "_fields") else tuple(items)
    if isinstance(v, (set, frozenset)):
        return type(v)(_display_safe(x) for x in v)
    return v


def _display_view(fleet: "Fleet") -> "Fleet":
    """The fleet as the terminal and Markdown views show it (R13): every
    transcript string one line. Counts are unchanged; the digest is still taken
    from the fleet itself, so it matches --json."""
    cls = type(fleet)
    view = cls.__new__(cls)
    view.__dict__.update({k: _display_safe(v) for k, v in fleet.__dict__.items()})
    view._display_of = fleet
    return view


def render(fleet: Fleet, c: C, bash_only: bool, top: int, raw: bool = False,
           network_only: bool = False, network_filters: list[str] | None = None) -> None:
    if network_only:
        # --network: the NETWORK section and the redaction note, nothing else.
        render_network(fleet, c, top, raw, network_filters)
        print()
        print(f"{c.dim}  Ask how this was read:  actualis --explain network")
        if not raw:
            print(f"  Credentials are redacted; --no-redact disables that.{c.off}")
        else:
            print(f"  {c.red}--no-redact is on: this output may contain live secrets.{c.off}")
        print()
        return
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
        if fleet.network_items:
            n_un = sum(1 for i in fleet.network_items if i["approval"] == "unasked")
            n_all = len(fleet.network_items)
            print(f"  network       {num(n_all)} download{'' if n_all == 1 else 's'}"
                  f" · {num(n_un)} unasked → actualis --network")
        # Printed so a screenshot of this report can be checked against the
        # --json payload it came from. Same fleet, same digest.
        # raw: under --no-redact the --json payload is unredacted, so its digest is too.
        print(f"  {c.dim}digest        "
              f"{report_digest(_to_json_body(getattr(fleet, '_display_of', fleet), raw)):.16}"
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
            print(f"  {c.dim}estimated     {money(fleet.cost_unknown)} of the total "
                  f"is estimated: models with no published rate, priced by family or "
                  f"provider ceiling{c.off}")
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
                         ("cache_read", "cache read      per model")):
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
                unit = "messages" if a in ("claude-code", "gemini", "qwen") else "sessions"
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
    unmoded = max(fleet.bash_total - fleet.bash_moded, 0)
    if unmoded and not fleet.network_only:
        print(f"  {c.dim}no mode       {num(unmoded)} of {num(fleet.bash_total)} shell commands "
              f"had no recorded permission mode; who approved them is unknown{c.off}")
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

    no_rate = fleet.models_by_tier.get(UNPRICED, set())
    ceiling = [m for m in fleet.unknown_models if m not in no_rate]
    if ceiling:
        print(f"\n  {c.yellow}▲{c.off} models priced by inference (a family sibling or the "
              f"provider ceiling), not a published rate: {', '.join(ceiling)}")
    if no_rate:
        print(f"\n  {c.yellow}▲{c.off} no published rate, so tokens shown and cost NOT counted: "
              + ", ".join(f"{m} ({num(fleet.unpriced_tokens[m])} tokens)"
                          if fleet.unpriced_tokens.get(m) else m for m in sorted(no_rate)))
    if fleet.rewound_tool_calls:
        print(f"\n  {c.dim}{num(fleet.rewound_tool_calls)} Gemini tool calls were later rewound out "
              f"of their conversation. They ran, so they are audited and counted.{c.off}")
    if fleet.unsupported_records:
        print(f"\n  {c.yellow}▲{c.off} {num(fleet.unsupported_records)} transcript records of a "
              f"kind this version does not read were skipped (e.g. Gemini $patch).")

    if fleet.aggregator_models:
        print(f"\n  {c.yellow}▲{c.off} priced from a third party, not the vendor's own "
              f"list: {', '.join(fleet.aggregator_models)}")
        print(f"    {c.dim}The rate is probably right; nobody authoritative has "
              f"published it.{c.off}")

    print()
    print(f"{c.dim}  Ask how any of this was computed:  actualis --explain")
    print(f"  Ask why a finding fired:            actualis --why AF004{c.off}")
    print()
    print(f"{c.dim}  Costs are provider list prices (Anthropic, OpenAI, Google; oldest rates")
    print(f"  verified {PRICING_VERIFIED}). On a Pro/Max subscription your actual outlay")
    print(f"  is the flat fee; read this as consumption.")
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

    modes = recorded_turns(fleet.permission_modes)
    unsup = ungated_modes(fleet.permission_modes)
    unsup_pct = (unsup / modes * 100) if modes else 0

    sub_bash = fleet.sub_tools.get("bashCount", 0)
    blind = (sub_bash / (fleet.bash_total + sub_bash) * 100) if (fleet.bash_total + sub_bash) else 0

    tools_total = sum(fleet.tools.values())
    bash_pct = (fleet.bash_total / tools_total * 100) if tools_total else 0

    # Suppressed credentials stay in the distinct total but leave the
    # actionable counts, as in the report, the gate and the tray.
    live = fleet.actionable_secrets
    crit = sum(1 for e in live.values() if e["priority"] == "critical")
    rotate = sum(1 for e in live.values() if e["priority"] != "low")
    n_suppressed = len(fleet.secrets) - len(live)

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
    unmoded = max(fleet.bash_total - fleet.bash_moded, 0)
    if modes and not unmoded:
        print(f"  {b}{unsup_pct:.0f}%{o} of turns ran unsupervised")
    elif modes:
        print(f"  {b}{unsup_pct:.0f}%{o} of turns with a recorded permission mode ran unsupervised")
    if unmoded:
        # Named, never silently dropped from the denominator above.
        print(f"  {b}{num(unmoded)}{o} of {num(fleet.bash_total)} shell commands had no "
              f"recorded permission mode {d}(who approved them is unknown){o}")
    if sub_bash:
        print(f"  {b}{blind:.0f}%{o} of shell activity happened inside subagents, "
              f"where the commands are not recorded")
    if fleet.secrets:
        print(f"  {b}{num(len(fleet.secrets))}{o} distinct credentials found in command "
              f"history   {d}{num(crit)} critical, {num(rotate)} worth rotating"
              + (f", {num(n_suppressed)} suppressed" if n_suppressed else "")
              + f"{o}")

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
    print(f"  Costs are provider list prices (Anthropic, OpenAI, Google); a")
    print(f"  subscription bills a flat fee, so read this as consumption.{o}\n")


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
        moded = fleet.bash_moded
        unsup = fleet.bash_unsupervised
        unmoded = max(commands - moded, 0)      # approval unknown: no mode recorded
        if moded and not unmoded:
            m["hero"] = f"{unsup / moded * 100:.0f}%"
            m["caption"] = "of my agents' shell commands ran with nobody approving them"
            m["share"] = (f"{m['hero']} of my coding agents' shell commands ran "
                          f"unsupervised in the last {n} days. {CARD_INSTALL}")
        elif moded:
            # Some commands (every Gemini CLI one) have no recorded mode. The
            # share is of the commands that do, and says so: leaving the rest
            # out of the denominator silently would overstate it.
            m["hero"] = f"{unsup / moded * 100:.0f}%"
            m["caption"] = f"of {num(moded)} commands with a recorded mode ran unapproved"
            m["share"] = (f"{m['hero']} of the {num(moded)} shell commands my coding agents "
                          f"ran with a recorded permission mode ran unsupervised in the last "
                          f"{n} days; {num(unmoded)} more had no recorded mode. {CARD_INSTALL}")
        else:
            m["hero"] = "—"
            m["caption"] = "no permission mode was recorded for these commands"
            m["share"] = (f"My coding agents ran {num(commands)} shell commands in "
                          f"the last {n} days. {CARD_INSTALL}")
        m.update(header="SUPERVISION", hero_label="unsupervised",
                 stats=[(num(commands), "commands"), (refused, "refused"), (agents, "agents")]
                 + ([(num(unmoded), "no mode")] if unmoded and moded else []),
                 # "gated", not "you": a mode that can stop for approval does not
                 # mean a person approved (an allowlist rule may have).
                 bars=[("auto", float(unsup), num(unsup)),
                       ("gated", float(moded - unsup), num(moded - unsup))]
                 + ([("no mode", float(unmoded), num(unmoded))] if unmoded else [])
                 + [("refused", float(fleet.refusals), refused)],
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


def _compact_bar_text(value: float, text: str, width: int) -> str:
    """A bar's value text that fits `width` characters without changing the
    number it shows: as written when it fits, else a compact unit ($12.3M,
    123M) from the bar's numeric value, else nothing. Never a slice of the
    digits, which reads as a different figure."""
    if len(text) <= width:
        return text
    pre = "$" if text.startswith("$") else ""
    v = value if isinstance(value, (int, float)) and value == value else -1.0
    for div, unit in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")):
        if v >= div:
            for digits in (1, 0):
                out = f"{pre}{v / div:.{digits}f}{unit}"
                if len(out) <= width:
                    return out
            break
    return ""


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
                            P["fg"], _compact_bar_text(value, text, 10)))
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
        # lexists: a dangling symlink is taken too, as for network_html_path
        if not os.path.lexists(svg) and not os.path.lexists(png):
            return svg, png
        n += 1


def write_card(m: dict, style: str, out_dir: Path) -> tuple:
    """Write one card. Mode "x" makes never-overwrite hold even under a race."""
    ops = layout_hero(m) if style == "hero" else layout_terminal(m)
    svg_data, png_data = svg_text(ops), png_bytes(ops)   # render before opening anything
    for _ in range(100):                     # a lost race takes the next name; bounded
        svg, png = card_paths(out_dir)
        try:
            fh = svg.open("x", encoding="utf-8", newline="\n")
        except FileExistsError:
            continue
        with fh:
            fh.write(svg_data)
        try:
            with png.open("xb") as fh:
                fh.write(png_data)
        except FileExistsError:
            # The PNG name was taken after card_paths looked: give back the SVG
            # and take the next stem, so the pair keeps one name.
            try:
                svg.unlink()
            except OSError:
                pass
            continue
        except BaseException:
            try:
                svg.unlink()
            except OSError:
                pass
            raise
        return svg, png
    raise FileExistsError("no free actualis-card-N name after 100 tries")


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
    "scope.days": "int|null",
    "scope.project": "str",
    "scope.agent": "str",
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
    "duplicate_tool_calls_skipped": "int",
    "unparsable_lines": "int",
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
    "bash.flagged.high": "int",
    "bash.flagged.medium": "int",
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
    "coach[].project": "str",
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
    "unsupervised_pct": "float|null",
    "moded_commands": "int",
    "unmoded_commands": "int",
    "denials.*": "int",
    "suppressed_flags": "int",
    "vendors.capabilities": "array",
    "vendors.capabilities[].capability": "str",
    "vendors.capabilities[].claude": "str",
    "vendors.capabilities[].codex": "str",
    "vendors.capabilities[].copilot": "str",
    "vendors.capabilities[].gemini": "str",
    "vendors.capabilities[].qwen": "str",
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
    "network.by_day": "array",
    "network.by_day[].date": "str",
    "network.by_day[].items": "int",
    "network.by_day[].unasked": "int",
    "network.by_day_undated": "int",
    "network.by_project": "array",
    "network.by_project[].project": "str",
    "network.by_project[].items": "int",
    "network.by_project[].unasked": "int",
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
    "network.packages[].unasked": "int",
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
    "network.items[].call_id": "str|null",
    "network.items[].ts": "str|null",
    "network.items[].mode": "str|null",
    "network.items[].why": "str|null",
    "network.items[].prompt": "str|null",
    "network.items[].transcript": "object|null",
    "network.items[].transcript.root": "str",
    "network.items[].transcript.file": "str",
    "network.items[].transcript.line": "int|null",
    "network.items[].rewound": "bool",
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
    "network.items[].ioc": "str|null",
    "network.items[].reputation": "object|null",
    "network.items[].reputation.state": "str",
    "network.items[].reputation.provider": "str|null",
    "network.items[].reputation.threat_types": "array",
    "network.items[].reputation.threat_types[]": "str",
    "network.items[].reputation.checked_at": "str|null",
    "network.items[].reputation.advisory": "str|null",
    "network.reputation.enabled": "bool",
    "network.reputation.lists_status": "str|null",
    "network.reputation.provider_lists.*": "str",
    "network.reputation.lists_age_hours": "int|null",
    "network.reputation.stale": "bool",
    "network.reputation.vt_results": "int",
    "network.reputation.vt_status": "str|null",
    "network.reputation.totals.checked": "int",
    "network.reputation.totals.skipped": "int",
    "network.reputation.totals.none": "int",
    "network.reputation.totals.candidate": "int",
    "network.reputation.totals.listed": "int",
    "network.reputation.totals.not_listed": "int",
    "network.reputation.totals.suspicious": "int",
    "network.reputation.totals.unknown": "int",
    "network.reputation.candidates": "array",
    "network.reputation.candidates[].prefix_b64": "str",
    "network.reputation.candidates[].expressions": "int",
    "network.reputation.advisory.text": "str|null",
    "network.reputation.advisory.url": "str|null",
    "network.reputation.network_last_used.at": "str|null",
    "network.reputation.network_last_used.provider": "str|null",
    "network.ioc.enabled": "bool",
    "network.ioc.sources": "array",
    "network.ioc.sources[].path": "str",
    "network.ioc.sources[].sha256": "str",
    "network.ioc.sources[].format": "str",
    "network.ioc.sources[].entries.package": "int",
    "network.ioc.sources[].entries.host": "int",
    "network.ioc.sources[].not_checkable.*": "int",
    "network.ioc.sources[].skipped": "int",
    "network.ioc.sources[].first_skipped_line": "int|null",
    "network.ioc.sources[].withdrawn": "int",
    "network.ioc.sources[].ranges_git": "int",
    "network.ioc.sources[].ranges_with_limit": "int",
    "network.ioc.sources[].skipped_ranges": "int",
    "network.ioc.sources[].mtime_in_window": "bool",
    "network.ioc.totals.match": "int",
    "network.ioc.totals.unresolved": "int",
    "network.ioc.totals.refused": "int",
    "network.ioc.totals.suppressed": "int",
    "network.ioc.totals.clean_name_matches": "int",
    "network.ioc.totals.undecidable": "int",
    "network.ioc.totals.items_checked": "int",
    "network.ioc.totals.items_not_checkable.lockfile": "int",
    "network.ioc.totals.items_not_checkable.no_host": "int",
    "network.ioc.totals.items_not_checkable.other": "int",
    "network.ioc.matches": "array",
    "network.ioc.matches[].verdict": "str",
    "network.ioc.matches[].reason": "str",
    "network.ioc.matches[].refused": "bool",
    "network.ioc.matches[].suppressed": "bool",
    "network.ioc.matches[].flag_id": "str|null",
    "network.ioc.matches[].refs": "array",
    "network.ioc.matches[].refs[]": "str",
    "network.ioc.matches[].labels": "array",
    "network.ioc.matches[].labels[]": "str",
    "network.ioc.matches[].entry.kind": "str",
    "network.ioc.matches[].entry.ecosystem": "str|null",
    "network.ioc.matches[].entry.name": "str|null",
    "network.ioc.matches[].entry.spec": "str|null",
    "network.ioc.matches[].entry.host": "str|null",
    "network.ioc.matches[].entry.path": "str|null",
    "network.ioc.matches[].entry.exact_host": "bool",
    "network.ioc.matches[].entry.ref": "str|null",
    "network.ioc.matches[].entry.label": "str|null",
    "network.ioc.matches[].entry.from": "str|null",
    "network.ioc.matches[].entry.until": "str|null",
    "network.ioc.matches[].entry.source": "int",
    "network.ioc.matches[].entry.line": "int|null",
    "network.ioc.matches_truncated": "bool",
    "unknown_models.*": "int",
    "aggregator_priced_models.*": "int",
    "unpriced_model_tokens.*": "int",
    "rewound_tool_calls": "int",
    "unsupported_records": "int",
}

# A matched item is shown exactly as network.items shows it.
JSON_SCHEMA.update({f"network.ioc.matches[].item.{k}": JSON_SCHEMA[f"network.items[].{k}"]
                    for k in NETWORK_ITEM_KEYS})
JSON_SCHEMA.update({f"network.ioc.matches[].item.transcript.{k}": JSON_SCHEMA[f"network.items[].transcript.{k}"]
                    for k in ("root", "file", "line")})
JSON_SCHEMA.update({f"network.ioc.matches[].item.reputation.{k}": JSON_SCHEMA[f"network.items[].reputation.{k}"]
                    for k in ("state", "provider", "threat_types", "threat_types[]", "checked_at", "advisory")})


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
    """sha256 of the report, excluding the digest and the fields that move with the clock.

    Self-referential by construction otherwise: the hash cannot cover a field
    whose value is the hash. The same goes for pricing.age_days, pricing.stale
    and finding AF013, which change as days pass over unchanged transcripts. The
    digest then answers "did the evidence change", not "what day is it".
    REPORT_DIGEST_EXCLUDES and REPORT_DIGEST_CLOCK_FINDINGS name all of it in one
    place so the emitter and any verifier cannot disagree.
    """
    def keep(node: dict, prefix: str) -> dict:
        out = {}
        for k, v in node.items():
            path = prefix + k
            if path in REPORT_DIGEST_EXCLUDES:
                continue
            out[k] = keep(v, path + ".") if isinstance(v, dict) else v
        return out
    body = keep(payload, "")
    if isinstance(body.get("coach"), list):
        body["coach"] = [f for f in body["coach"]
                         if not (isinstance(f, dict)
                                 and f.get("id") in REPORT_DIGEST_CLOCK_FINDINGS)]
    # surrogatepass: identical bytes for any encodable text, so docs/json.md's
    # recipe still verifies; a lone surrogate that slipped past clean() can no
    # longer crash the report (R3).
    return hashlib.sha256(canonical_json(body).encode("utf-8", "surrogatepass")).hexdigest()


# Dotted paths into the payload (a top-level key is a path of one part).
REPORT_DIGEST_EXCLUDES = frozenset({"report_sha256", "pricing.age_days", "pricing.stale"})
# Coach findings whose presence depends on today's date, not on the transcripts.
REPORT_DIGEST_CLOCK_FINDINGS = frozenset({"AF013"})

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
#   4    --self-check: a check failed
#   130  interrupted
#
# Findings are 3, not 1 and not 2. 1 already meant "could not run" before
# --fail-on existed. 2 is argparse's exit for a bad invocation, and a pipeline
# that cannot tell "a credential is exposed" from "you mistyped a flag" will
# eventually be told to ignore both.
# --------------------------------------------------------------------------

EXIT_OK = 0
EXIT_CANNOT_RUN = 1
EXIT_USAGE = 2        # argparse's, and --reputation --fail-on with no usable lists
EXIT_FINDINGS = 3
EXIT_SELF_CHECK_FAILED = 4   # --self-check: a privacy claim did not hold

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

    # Right after credentials, so a known-bad install is the first thing a
    # failing pipeline prints. Split out of the generic flag counts below.
    ioc_hit = [f for f in fleet.actionable_flags if "network-ioc" in f["categories"]]
    ioc_unresolved = [f for f in fleet.actionable_flags if "network-ioc-unresolved" in f["categories"]]
    if want_high and ioc_hit:
        out.append(f"{len(ioc_hit)} known-bad download group(s) (IOC)")
    if want_any and ioc_unresolved:
        out.append(f"{len(ioc_unresolved)} unresolved IOC match group(s)")
    rep = set(REPUTATION_FLAG_CATEGORIES)
    rep_listed = [f for f in fleet.actionable_flags if "reputation-listed" in f["categories"]]
    rep_med = [f for f in fleet.actionable_flags if rep & set(f["categories"]) - {"reputation-listed"}]
    if want_high and rep_listed:
        out.append(f"{len(rep_listed)} host(s) currently on a reputation list")
    if want_any and rep_med:
        out.append(f"{len(rep_med)} unconfirmed or suspicious reputation result(s), or stale lists")

    for finding in coach(fleet):
        # A finding that depends on today's date, not on the transcripts, must
        # not turn a gate red on a fixed day with nothing changed (AF013).
        if finding.id in REPORT_DIGEST_CLOCK_FINDINGS:
            continue
        if finding.severity == "critical" or (want_high and finding.severity == "high") \
           or (want_any and finding.severity == "info"):
            out.append(f"{finding.id} {finding.title}")

    if want_high:
        fl = [f for f in fleet.actionable_flags if f["severity"] == "high" and "network-ioc" not in f["categories"]
              and not rep & set(f["categories"])]
        if fl:
            out.append(f"{len(fl)} high-severity shell command(s) flagged")
    if want_any:
        fl = [f for f in fleet.actionable_flags if f["severity"] == "med"]
        net = [f for f in fl if "network-unasked" in f["categories"]]
        fl = [f for f in fl if not ({"network-unasked", "network-ioc-unresolved"} | rep) & set(f["categories"])]
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
        "scope": dict(fleet.scope),
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
        "cost_note": "Claude and OpenAI models with no published rate are priced at "
                     "the top of the known range for their provider, so that share "
                     "(cost_usd_from_unpriced_models) is an upper bound among current "
                     "models rather than a measurement. Gemini, Gemma and Qwen ids "
                     "with no published rate are tier unpriced: $0, never estimated, "
                     "listed in unpriced_model_tokens",
        "duplicate_usage_records_skipped": fleet.duplicate_usage_records,
        "duplicate_tool_calls_skipped": fleet.duplicate_tool_calls_skipped,
        "unparsable_lines": fleet.unparsable_lines,
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
             "first_seen": min(fleet.dates_by_ticket[t]) if fleet.dates_by_ticket.get(t) else "",
             "last_seen": max(fleet.dates_by_ticket[t]) if fleet.dates_by_ticket.get(t) else ""}
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
            # The counts the report prints as "flagged N high  M medium":
            # one per command, suppressed ones left out. flag_counts counts
            # per category and includes suppressed flags, so it cannot stand in.
            "flagged": {
                "high": sum(1 for f in fleet.actionable_flags if f["severity"] == "high"),
                "medium": sum(1 for f in fleet.actionable_flags if f["severity"] == "med"),
            },
            "flags": [{**f, "evidence": (f["evidence"] if raw else redact(f["evidence"]))[:240]}
                      for f in fleet.flags],
        },
        "coach": [{"id": f.id, "severity": f.severity, "title": f.title,
                   "evidence": f.evidence, "action": f.action, "impact": f.impact,
                   "project": f.project}
                  for f in coach(fleet)],
        "secret_exposures": fleet.secret_exposures,
        "suppressed_secrets": fleet.suppressed_secrets,
        "suppression_note": "suppressed findings are still counted and still "
                            "listed here; they are held back from the actionable "
                            "list, not hidden. A scan with many suppressions "
                            "should look different from a clean one.",
        "secrets": [
            {"priority": e["priority"], "types": sorted(e["kinds"]), "id": fp,
             "uses": e["uses"], "first_seen": e["first"] or "", "last_seen": e["last"] or "",
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
        # The share --share prints as "N% of turns ran unsupervised", computed
        # once here so readers (the tray) need not re-derive it from
        # permission_modes and drift (a Codex `sandbox:` key is not a turn).
        "unsupervised_pct": (ungated_modes(fleet.permission_modes)
                             / recorded_turns(fleet.permission_modes) * 100)
                            if recorded_turns(fleet.permission_modes) else None,
        # unsupervised_pct covers only what has a recorded mode. These say how
        # many shell commands that is, and how many have none (approval
        # unknown: every Gemini CLI command), so no reader has to assume.
        "moded_commands": fleet.bash_moded,
        "unmoded_commands": max(fleet.bash_total - fleet.bash_moded, 0),
        "denials": dict(fleet.denials),
        "suppressed_flags": fleet.suppressed_flags,
        "vendors": {
            "capabilities": [
                {"capability": cap, "claude": c, "codex": x, "copilot": p,
                 "gemini": VENDOR_CAPABILITIES_MORE[cap][0], "qwen": VENDOR_CAPABILITIES_MORE[cap][1],
                 "depends_on": f"{why}. {VENDOR_CAPABILITIES_MORE[cap][2]}"}
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
        "unpriced_model_tokens": dict(fleet.unpriced_tokens.most_common()),
        "rewound_tool_calls": fleet.rewound_tool_calls,
        "unsupported_records": fleet.unsupported_records,
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
    # Run as `python3 actualis.py` from a checkout: THIS file and THIS
    # interpreter, before PATH gets a chance to name some other install.
    here = Path(__file__).resolve()
    if argv0:
        try:
            if argv0.resolve() == here:
                return [sys.executable, str(here)]
        except OSError:
            pass
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


def _unit_safe(text: str, what: str) -> str:
    """Refuse a control character: a newline in a path ends a unit directive
    and starts another one, and no unit format can carry it safely."""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError(f"cannot write a unit: the {what} contains a control "
                         f"character: {text!r}")
    return text


def _systemd_quote(arg: str) -> str:
    """One ExecStart= argument, per systemd's own rules.

    `%` is a specifier and `$` an environment reference, so both are doubled
    everywhere; an argument with whitespace, a quote or a backslash is wrapped
    in double quotes with `\\` and `\"` escaped.
    """
    out = arg.replace("%", "%%").replace("$", "$$")
    if not arg or any(ch.isspace() or ch in "\"'\\;" for ch in arg):
        out = '"' + out.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return out


def service_unit(kind: str, interval: float = 4.0, quiet: bool = False) -> str:
    """Raises ValueError for a path no unit format can carry safely."""
    # `--interval 4.0` is valid but reads like a mistake in a unit file.
    secs = f"{interval:g}"
    argv = _actualis_command() + ["--watch", "--interval", secs]
    if quiet:
        argv.append("--quiet")
    for a in argv:
        _unit_safe(a, "command")
    log = Path(SERVICE_LOG).expanduser()
    _unit_safe(str(log), "log path")

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
        cmd = " ".join(_systemd_quote(a) for a in argv)
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
    #
    # newsyslog splits its lines on whitespace and has no quoting, and the
    # owner field is user:group, so anything else is refused, not mangled.
    user = os.environ.get("USER", "root")
    for value, what in ((str(log), "log path"), (user, "user name")):
        if any(ch.isspace() for ch in value) or (what == "user name" and ":" in value):
            raise ValueError(f"cannot write a newsyslog line: the {what} {value!r} contains "
                             f"whitespace{' or a colon' if what == 'user name' else ''}, "
                             "which newsyslog.conf cannot carry.")
        _unit_safe(value, what)
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
{log}  {user}:staff  644  5  1024  *  NC
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
        with _open_regular(path, binary=True) as fh:
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


def self_check(c: C, days: int | None = 7, root: str | None = None,
               agent: str = "all") -> int:
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

    # Routed as main() routes them: --agent says how --root is read, and which
    # vendors' default directories are read without it. Every root parsed by
    # the Claude reader made a Codex corpus "reconcile" with nothing parsed.
    if root:
        r = Path(root).expanduser()
        slot = {"codex": 1, "copilot": 2, "gemini": 3, "qwen": 4}.get(agent, 0)
        if slot >= 3:
            r = _agent_root(r, agent)
        by_agent = tuple([r] if i == slot else [] for i in range(5))
    else:
        by_agent = (transcript_roots() if agent in ("all", "claude") else [],
                    codex_roots() if agent in ("all", "codex") else [],
                    copilot_roots() if agent in ("all", "copilot") else [],
                    gemini_roots() if agent in ("all", "gemini") else [],
                    qwen_roots() if agent in ("all", "qwen") else [])
    roots = [r for group in by_agent for r in group]
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
    try:
        last = reputation_last_network()
        log_path = reputation_dir() / "network-log.jsonl"
    except OSError:
        last, log_path = None, None
    names = {"gsb": "Google Safe Browsing", "vt": "VirusTotal"}
    result(True, f"{NET_MARK} network: actualis never uses it",
           (f"actualis-reputation last used it for {names.get(last['provider'], last['provider'])} "
            f"at {last['at']}, read from {log_path}." if last else
            "actualis-reputation has never used it on this machine (no network-log.jsonl)."))

    # 2. Sample the transcripts, hash them, scan, hash again. The checks below
    #    need a corpus; the ones above and below them do not, and skipping the
    #    whole run when there is nothing to read would hide the ones that are
    #    always meaningful.
    sample: list[Path] = []
    for root in roots:
        # Gemini's legacy sessions are single .json objects under chats/.
        legacy = (f for f in root.rglob("*.json") if f.parent.name == "chats") \
            if root in by_agent[3] else ()
        for f in [*root.rglob("*.jsonl"), *legacy]:
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
        _self_check_corpus(roots, sample, result, c, days, skipped, by_agent)

    # 3. Where this build is allowed to write, named explicitly.
    writable = [str(p) for p in suppression_paths()]
    result(True, "the only write paths in this build",
           "Suppressions, and only when you pass --suppress: "
           + "; ".join(writable)
           + ". A card, and only when you pass --card: actualis-card[-N].svg and "
           "actualis-card[-N].png in the current directory, or in --out. A network "
           "report, and only when you pass --network --html: actualis-network[-N].html "
           "in the current directory, or in --out. None is ever overwritten.")

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
    return EXIT_OK if ok else EXIT_SELF_CHECK_FAILED


def _self_check_corpus(roots: list[Path], sample: list[Path], result, c: C,
                       days: int | None, skipped=None, by_agent=None) -> None:
    """The checks that need something to read.

    Split out so that the checks which do NOT need a corpus -- the import scan,
    the write path, this build's own digest -- are never skipped along with
    them. A machine with no transcripts can still verify most of the claims.
    """
    before = {f: _digest_file(f) for f in sample}
    tree_before = _tree_state(roots)

    fleet = Fleet()
    since = window_start(days, datetime.now(timezone.utc)) if days else None
    claude_r, codex_r, copilot_r, gemini_r, qwen_r = (
        by_agent if by_agent is not None else (roots, [], [], [], []))
    fleet.scan(claude_r, since, None, progress=False)
    if codex_r:
        fleet.scan_codex(codex_r, since, None)
    if copilot_r:
        fleet.scan_copilot(copilot_r, since, None)
    if gemini_r:
        fleet.scan_gemini(gemini_r, since, None)
    if qwen_r:
        fleet.scan_qwen(qwen_r, since, None)

    if fleet.files_scanned == 0 and skipped is not None:
        # Totals over nothing reconcile trivially; a pass here would claim a
        # check that never ran.
        skipped("network totals reconcile",
                "No session file was parsed in the format --agent names "
                f"({len(sample)} file{'' if len(sample) == 1 else 's'} found by name), so "
                "there were no totals to compare. Pass --agent codex, copilot, gemini or qwen "
                "for those directories.")
    else:
        problems = network_reconciles(network_json(fleet))
        result(not problems, "network totals reconcile",
               "Items equal asked + unasked + unknown and the sum of kinds, hosts add up, "
               "and every approval and kind is a known one."
               if not problems else "; ".join(problems))

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
    return "auto" in k or "bypass" in k or "yolo" in k or key == "codex:never"


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


def recorded_turns(modes: "Counter") -> int:
    """Turns with a recorded permission mode: the denominator for ungated_modes.

    Codex writes a sandbox policy beside the approval policy on every
    turn_context, and both land in permission_modes. Counting the `sandbox:`
    entries as turns counted every Codex turn twice, so a fleet running 100%
    `never` scored 50% ungated.
    """
    return sum(v for k, v in modes.items() if not k.startswith("sandbox:"))


def _aisvs_9_2_1(fleet: "Fleet") -> tuple[str, str]:
    modes = fleet.permission_modes
    total = recorded_turns(modes)
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
    # Commands, not category matches, and only actionable ones: a suppressed
    # flag is a recorded decision, as in 9.5.4.
    high = sum(1 for f in fleet.actionable_flags
               if f.get("severity") == "high" and "network-ioc" not in f.get("categories", ()))
    if not fleet.bash_total:
        return UNKNOWN, "no shell activity recorded."
    if high:
        return FAILING, (f"{high:,} command{'' if high == 1 else 's'} matched high-severity shapes "
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
    "window.undated_sightings": "int",
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


def _claude_files(root: Path) -> list[Path]:
    """The files Fleet.scan reads, in its order: <root>/<project>/*.jsonl."""
    try:
        dirs = sorted(d for d in root.iterdir() if d.is_dir())
    except OSError:
        return []
    return [f for d in dirs for f in sorted(d.glob("*.jsonl"))]


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _replay_attr(v) -> str:
    """A session id or branch fit to show and to key on: a string, cleaned
    and cut, or "" (an untrusted field of the wrong type is absent)."""
    return clean(v)[:120] if isinstance(v, str) else ""


def _replay_project_ok(project: str, project_filter: str | None) -> bool:
    """--project, matched as the report matches it: a case-insensitive
    substring of the report's own project name."""
    return not project_filter or project_filter.lower() in project.lower()


def _replay_untimed_ok(ts: datetime | None, since: datetime | None) -> bool:
    """Whether a record belongs in the replay. An untimed record is kept, as
    the report counts it: dropping it made a fingerprint taken from the
    report's own table "not appear"."""
    return ts is None or not (since and ts < since)


def _claude_events(roots: list[Path], since: datetime | None,
                   project_filter: str | None = None) -> list[ReplayEvent]:
    # The same files and the same tool-call dedup as the report: a resumed or
    # forked session copies its history, and counting the copy twice would
    # overstate the exposure the report itself counted once.
    out: list[ReplayEvent] = []
    seen: set[str] = set()
    for root in roots:
        for f in _claude_files(root):
            project = pretty_project(f.parent.name)
            if not _replay_project_ok(project, project_filter):
                continue
            try:
                fh = _open_regular(f)
            except OSError:
                continue
            with fh:
                for line in fh:
                    if '"Bash"' not in line:
                        continue          # cheap prefilter; most records are not
                    rec = _json_line(line)[1]      # unreadable: skipped, as by the report
                    if not isinstance(rec, dict):
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    if not _replay_untimed_ok(ts, since):
                        continue
                    msg = rec.get("message")
                    content = msg.get("content") if isinstance(msg, dict) else None
                    ids = [b["id"] for b in (content if isinstance(content, list) else [])
                           if isinstance(b, dict) and b.get("type") == "tool_use"
                           and isinstance(b.get("id"), str) and b["id"]]
                    if ids and all(i in seen for i in ids):
                        continue
                    seen.update(ids)
                    session = _replay_attr(rec.get("sessionId")) or _replay_attr(rec.get("session_id"))
                    branch = _replay_attr(rec.get("gitBranch"))
                    for cmd in _commands_in(rec):
                        if cmd:
                            out.append(ReplayEvent(ts, cmd, session, project, branch,
                                                   "claude", str(root)))
    return out


def _codex_events(roots: list[Path], since: datetime | None,
                  project_filter: str | None = None) -> list[ReplayEvent]:
    """Codex records no git branch, so those stay empty rather than invented.

    Read as the report reads it: the session is session_meta's id (the file
    name only when there is none), a call id already seen in another file
    (a resumed rollout copies its history) is counted once, and the project is
    the report's name for the rollout's last cwd.
    """
    out: list[ReplayEvent] = []
    seen: set[str] = set()
    for root in roots:
        for f in sorted(root.rglob("rollout-*.jsonl")):
            cwd = ""
            session = _replay_attr(f.stem)
            found: list[tuple[datetime | None, str]] = []
            try:
                fh = _open_regular(f)
            except OSError:
                continue
            with fh:
                for line in fh:
                    if "shell_command" not in line and "session_meta" not in line \
                            and "turn_context" not in line:
                        continue
                    rec = _json_line(line)[1]      # unreadable: skipped, as by the report
                    if not isinstance(rec, dict):
                        continue
                    payload = rec.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    if rec.get("type") in ("session_meta", "turn_context"):
                        cwd = _str_or(payload.get("cwd"), cwd)
                        if rec.get("type") == "session_meta":
                            session = _replay_attr(payload.get("id")) or session
                        continue
                    if payload.get("type") != "function_call" or \
                            payload.get("name") != "shell_command":
                        continue
                    raw_args = payload.get("arguments")
                    ok, args = _json_line(raw_args) if isinstance(raw_args, str) else (True, {})
                    if ok and isinstance(args, dict):
                        cwd = _str_or(args.get("workdir"), cwd)     # as the report does
                    ts = parse_ts(rec.get("timestamp"))
                    if not _replay_untimed_ok(ts, since):
                        continue
                    call_id = _str_or(payload.get("call_id"), None)
                    if call_id is not None:
                        if call_id in seen:
                            continue
                        seen.add(call_id)
                    found.extend((ts, cmd) for cmd in _commands_in(rec))
            project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "unknown"
            if _replay_project_ok(project, project_filter):
                out.extend(ReplayEvent(ts, cmd, session, project, "", "codex", str(root))
                           for ts, cmd in found)
    return out


def _copilot_events(roots: list[Path], since: datetime | None,
                    project_filter: str | None = None) -> list[ReplayEvent]:
    """Copilot records the branch, so unlike Codex it is carried through. The
    project is the report's name for the session's last cwd."""
    out: list[ReplayEvent] = []
    for root in roots:
        for f in sorted(root.glob("*/events.jsonl")):
            cwd = branch = ""
            found: list[tuple[datetime | None, str, str]] = []
            try:
                fh = _open_regular(f)
            except OSError:
                continue
            with fh:
                for line in fh:
                    if "tool.execution_start" not in line and "session.start" not in line \
                            and "session.context_changed" not in line:
                        continue
                    rec = _json_line(line)[1]      # unreadable: skipped, as by the report
                    if not isinstance(rec, dict) or not isinstance(rec.get("data"), dict):
                        continue
                    kind = rec.get("type")
                    if kind in ("session.start", "session.context_changed"):
                        ctx = rec["data"].get("context") if kind == "session.start" else rec["data"]
                        if isinstance(ctx, dict):
                            cwd, branch = _copilot_context(ctx, cwd, branch)
                        continue
                    ts = parse_ts(rec.get("timestamp"))
                    if not _replay_untimed_ok(ts, since):
                        continue
                    found.extend((ts, cmd, branch) for cmd in _commands_in(rec))
            project = pretty_project(cwd.lstrip("/").replace("/", "-")) if cwd else "copilot"
            if _replay_project_ok(project, project_filter):
                out.extend(ReplayEvent(ts, cmd, _replay_attr(f.parent.name), project,
                                       _replay_attr(b), "copilot", str(root))
                           for ts, cmd, b in found)
    return out


def _gemini_events(roots: list[Path], since: datetime | None,
                   project_filter: str | None = None) -> list[ReplayEvent]:
    """Gemini CLI records no branch. Read with the report's reader, so a
    re-appended message is one message and a rewound call is still a call."""
    out: list[ReplayEvent] = []
    seen: set[str] = set()
    for root in roots:
        registry = gemini_registry(root)
        for d in _project_dirs(root):
            real = gemini_project_root(d, registry)
            project = path_project(real) if real else pretty_project(d.name)
            if not _replay_project_ok(project, project_filter):
                continue
            for f in gemini_session_files(d):
                sess = read_gemini_session(f)
                if sess is None:
                    continue
                sid = _replay_attr(sess["meta"].get("sessionId")) or _replay_attr(f.stem)
                for msg, _line, _rewound in sess["messages"]:
                    if msg.get("type") != "gemini":
                        continue
                    mts = parse_ts(msg.get("timestamp"))
                    calls = msg.get("toolCalls")
                    for tc in calls if isinstance(calls, list) else ():
                        if not isinstance(tc, dict):
                            continue
                        ts = parse_ts(tc.get("timestamp")) or mts
                        if not _replay_untimed_ok(ts, since):
                            continue
                        hits = _vendor_shell_calls({"toolCalls": [tc]}, "gemini")
                        if not hits:
                            continue
                        cid = hits[0][0]
                        if cid:
                            if cid in seen:
                                continue
                            seen.add(cid)
                        args = tc.get("args")
                        out.append(ReplayEvent(ts, hits[0][1], sid,
                                               gemini_command_project(project, real, args),
                                               "", "gemini", str(root)))
    return out


def _qwen_events(roots: list[Path], since: datetime | None,
                 project_filter: str | None = None) -> list[ReplayEvent]:
    """Qwen Code records cwd and branch on every record."""
    out: list[ReplayEvent] = []
    seen: set[str] = set()
    for root in roots:
        for d in _project_dirs(root):
            for f in qwen_session_files(d):
                try:
                    fh = _open_regular(f)
                except OSError:
                    continue
                with fh:
                    for line in fh:
                        if "functionCall" not in line:
                            continue
                        rec = _json_line(line)[1]
                        if not isinstance(rec, dict):
                            continue
                        ts = parse_ts(rec.get("timestamp"))
                        if not _replay_untimed_ok(ts, since):
                            continue
                        cwd = _str_or(rec.get("cwd"), "")
                        project = path_project(cwd) if cwd else pretty_project(d.name)
                        if not _replay_project_ok(project, project_filter):
                            continue
                        for cid, cmd in _vendor_shell_calls(rec, "qwen"):
                            if cid:
                                if cid in seen:
                                    continue
                                seen.add(cid)
                            out.append(ReplayEvent(
                                ts, cmd, _replay_attr(rec.get("sessionId")) or _replay_attr(f.stem),
                                project, _replay_attr(rec.get("gitBranch")), "qwen", str(root)))
    return out


def replay_events(since: datetime | None = None,
                  root: str | None = None, agent: str = "all",
                  project: str | None = None) -> list[ReplayEvent]:
    """Every recorded command in the report's scope, oldest first.

    Scoped as the report is: --agent picks the vendors (a --root is read with
    that one parser; with no --agent, with every parser, as before) and
    --project keeps the projects whose report name contains it."""
    readers = (("claude", _claude_events, transcript_roots),
               ("codex", _codex_events, codex_roots),
               ("copilot", _copilot_events, copilot_roots),
               ("gemini", _gemini_events, gemini_roots),
               ("qwen", _qwen_events, qwen_roots))
    events: list[ReplayEvent] = []
    if root:
        base = Path(root).expanduser()
        for name, read, _roots in readers:
            if agent in ("all", name):
                events += read([_agent_root(base, name) if name in ("gemini", "qwen")
                                else base], since, project)
    else:
        for name, read, roots in readers:
            if agent in ("all", name):
                events += read(roots(), since, project)
    # Undated events (kept, see _replay_untimed_ok) sort after every dated one.
    events.sort(key=lambda e: (e.ts is None, e.ts or _EPOCH))
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
    "--ioc": "file",
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
    # --card/--explain take an optional value; --ioc/--network-trust repeat.
    actions = build_parser()._actions
    optional = {o for a in actions if a.nargs == "?" for o in a.option_strings}
    repeat = {o for a in actions if isinstance(a, argparse._AppendAction)
              for o in a.option_strings}
    header = (f"# actualis {shell} completion, generated by "
              f"`actualis --completions {shell}` (v{__version__}).\n"
              "# Regenerate after upgrading; do not edit by hand.\n")

    if shell == "bash":
        cases = []
        for opt, values, hint in spec:
            if values and opt in optional:
                # The value may be left out: a flag typed next is completed
                # as a flag, not offered the value list.
                cases.append(f'        {opt}) if [[ "$cur" != -* ]]; then COMPREPLY=($(compgen -W "'
                             f'{" ".join(values)}" -- "$cur")); return; fi;;')
            elif values:
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
            if values and opt in optional:
                arg = f"=::value:({' '.join(values)})"
            elif values:
                arg = f"=:value:({' '.join(values)})"
            elif hint == "dir":
                arg = "=:directory:_files -/"
            elif hint == "file":
                arg = "=:file:_files"
            elif hint == "none":
                arg = "=:value:"
            star = "*" if opt in repeat else ""
            lines.append(f"    '{star}{opt}{arg}{desc}' \\")
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

MIN_INTERVAL = 0.5
MAX_INTERVAL = 3600.0
MAX_DAYS = 36500        # a century; far larger overflows the date arithmetic


def _interval_arg(text: str) -> float:
    """--interval: a finite number of seconds from 0.5 to 3600.

    The single source of the bounds: --watch used to clamp silently to these
    while this accepted up to a day. NaN and infinity crash time.sleep(), and
    --service would bake them into a unit that restarts forever.
    """
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if v != v or not MIN_INTERVAL <= v <= MAX_INTERVAL:
        raise argparse.ArgumentTypeError(
            f"must be at least {MIN_INTERVAL:g} and at most {MAX_INTERVAL:g} seconds, "
            f"got {text!r}")
    return v


def _days_arg(text: str) -> int:
    """--days: a whole number of days, 1 to MAX_DAYS (0 used to mean all time)."""
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not 1 <= v <= MAX_DAYS:
        raise argparse.ArgumentTypeError(f"must be from 1 to {MAX_DAYS}, got {text!r}")
    return v


def _top_arg(text: str) -> int:
    """--top: a whole number, 1 or more. A negative slice dropped the last rows."""
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if v < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {text!r}")
    return v


AGENT_CHOICES = ["all", "claude", "codex", "copilot", "gemini", "qwen"]


def build_parser() -> argparse.ArgumentParser:
    """The parser, built separately so completions can be generated FROM it.

    A completion script that hardcodes its own copy of the flag list is wrong
    the moment a flag is added, and nothing fails to tell you.
    """
    ap = argparse.ArgumentParser(
        prog="actualis",
        description="What actually ran. Local, read-only, honest about limits.",
    )
    ap.add_argument("--days", type=_days_arg, metavar="N",
                    help=f"only the last N days (1 to {MAX_DAYS})")
    ap.add_argument("--project", metavar="SUBSTR", help="only projects matching SUBSTR")
    ap.add_argument("--diff", metavar="OLD.json",
                    help="compare against a saved --json report")
    # default None, so a --top given to a view that never lists projects is
    # refused rather than dropped; main() fills in 12 after that check.
    ap.add_argument("--top", type=_top_arg, default=None, metavar="N",
                    help="text report: projects to list, 1 or more (default 12)")
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
                    help="--card or --html: directory to write into (default: current directory)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--watch", action="store_true",
                    help="live monitor: alert on new secrets and risky commands")
    ap.add_argument("--interval", type=_interval_arg, default=None, metavar="SEC",
                    help=f"--watch poll interval, {MIN_INTERVAL:g} to {MAX_INTERVAL:g} (default 4)")
    ap.add_argument("--quiet", action="store_true",
                    help="--watch: notify on secrets only, not every flagged command")
    ap.add_argument("--agent", choices=AGENT_CHOICES, default="all",
                    help="which agents to include (default: all)")
    ap.add_argument("--no-redact", action="store_true",
                    help="do NOT redact credentials from output (unsafe to share)")
    ap.add_argument("--fail-on", metavar="LEVEL", choices=FAIL_ON_LEVELS,
                    help="exit 3 if any unsuppressed finding is at or above "
                         f"LEVEL ({', '.join(FAIL_ON_LEVELS)}); 2 is a usage error. "
                         "For gating a pipeline. Still changes nothing and blocks nothing.")
    net = ap.add_argument_group("Network")
    net.add_argument("--network", action="store_true",
                     help="print only the NETWORK section (with --ioc, the IOC block too). "
                          "--network --json emits only the network object, without schema_version")
    net.add_argument("--network-trust", metavar="HOST[/PATH],...", action="append",
                     help="trusted download sources for --network-strict; also read from "
                          "./.actualis-network-trust")
    net.add_argument("--ioc", metavar="FILE", action="append",
                     help="known-bad packages and hosts to match the network inventory against: the "
                          "actualis-ioc line format or OSV JSON/JSONL. Repeatable. Never read unless named.")
    net.add_argument("--reputation", action="store_true",
                     help="match the network inventory against the local host-reputation cache that "
                          "actualis-reputation writes (Google Safe Browsing lists, VirusTotal results). "
                          "Offline: actualis never uses the network")
    net.add_argument("--network-strict", action="store_true",
                     help="make every unasked download from an untrusted source a medium finding")
    net.add_argument("--host", metavar="HOST",
                     help="--network: only downloads from HOST or a subdomain of it")
    net.add_argument("--package", metavar="NAME",
                     help="--network: only installs of this exact package (npm exactly, pypi by PEP 503)")
    net.add_argument("--session", metavar="ID",
                     help="--network: only sessions whose id starts with ID")
    net.add_argument("--unasked", action="store_true",
                     help="--network: only downloads that ran without asking")
    net.add_argument("--html", action="store_true",
                     help="--network: write the report as one self-contained HTML page "
                          "(actualis-network.html, never overwritten; see --out)")
    net.add_argument("--with-prompts", action="store_true",
                     help="--json or --html: include network.items[].prompt, the person's last message "
                          "before each download (redacted, 160 characters). Null otherwise")
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


def network_filtered(args) -> bool:
    """Whether any --network filter was given."""
    return bool(network_filter_names(args))


def network_filter_names(args) -> list[str]:
    """The --network filters in force, as the filtered view names them."""
    if not args.network:
        return []
    return ([f"host {clean(args.host)}"] if args.host else []) \
        + ([f"package {clean(args.package)}"] if args.package is not None else []) \
        + ([f"session {clean(args.session)}"] if args.session is not None else []) \
        + (["unasked only"] if args.unasked else [])


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    # Before ANY output: every mode below prints, and on a stream whose codec
    # cannot carry the report's glyphs, printing raises rather than degrades.
    make_output_printable(args.json)

    # Checked before anything runs, so a refused --suppress writes nothing.
    # --fail-on is never silently ignored: these modes return before the gate.
    if args.fail_on:
        for flag, on in (("--diff", args.diff), ("--why", args.why),
                         ("--replay", args.replay), ("--watch", args.watch),
                         ("--mcp", args.mcp), ("--explain", args.explain is not None),
                         ("--agents", args.agents), ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--self-check", args.self_check), ("--service", args.service),
                         ("--completions", args.completions)):
            if on:
                ap.error(f"--fail-on cannot be combined with {flag}: "
                         f"{flag} does not evaluate the gate.")
    # Nor is --json: these modes print text, or would print something else.
    if args.json:
        for flag, on in (("--share", args.share), ("--coach", args.coach),
                         ("--aisvs", args.aisvs), ("--bash", args.bash),
                         ("--why", args.why), ("--explain", args.explain is not None),
                         ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--self-check", args.self_check), ("--service", args.service),
                         ("--completions", args.completions), ("--watch", args.watch),
                         ("--mcp", args.mcp)):
            if on:
                ap.error(f"--json cannot be combined with {flag}: {flag} has no JSON form.")
    views = [flag for flag, on in (("--share", args.share), ("--coach", args.coach),
                                   ("--aisvs", args.aisvs), ("--bash", args.bash)) if on]
    if len(views) > 1:
        ap.error(f"{views[0]} cannot be combined with {views[1]}: each is a different view.")
    if args.ci_log:
        # The log is the whole input: these would be accepted and then ignored.
        # It is a Claude Code log, so --agent claude agrees with it.
        for flag, on in (("--root", args.root),
                         ("--agent", args.agent not in ("all", "claude")),
                         ("--project", args.project is not None),
                         ("--replay", args.replay)):
            if on:
                ap.error(f"--ci-log cannot be combined with {flag}: "
                         f"the execution log is the only input.")
        # Only the scanning modes read it; these would read something else.
        for flag, on in (("--watch", args.watch), ("--mcp", args.mcp),
                         ("--explain", args.explain is not None), ("--agents", args.agents),
                         ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--self-check", args.self_check), ("--service", args.service),
                         ("--completions", args.completions)):
            if on:
                ap.error(f"--ci-log cannot be combined with {flag}: "
                         f"{flag} never reads the execution log.")

    if args.card and args.json:
        ap.error("--card writes files; it cannot also emit --json.")
    # --ioc is never silently ignored: a mode it cannot reach is an error.
    if args.network:
        for flag, on in (("--share", args.share), ("--card", args.card), ("--bash", args.bash),
                         ("--diff", args.diff), ("--replay", args.replay),
                         ("--watch", args.watch), ("--mcp", args.mcp),
                         ("--coach", args.coach), ("--aisvs", args.aisvs)):
            if on:
                ap.error(f"--network cannot be combined with {flag}.")
    for name, given in (("--ioc", bool(args.ioc)), ("--reputation", args.reputation)):
        if not given:
            continue
        # These return before the list is loaded.
        for flag, on in (("--replay", args.replay), ("--agents", args.agents),
                         ("--why", args.why), ("--explain", args.explain is not None),
                         ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--self-check", args.self_check), ("--service", args.service),
                         ("--completions", args.completions)):
            if on:
                ap.error(f"{name} cannot be combined with {flag}: {flag} never reads it.")
        # These views never show the matches; only the gate reads them.
        for flag, on in (("--coach", args.coach), ("--aisvs", args.aisvs),
                         ("--share", args.share)):
            if on and not args.fail_on:
                shown = "IOC matches" if name == "--ioc" else "reputation results"
                ap.error(f"{name} cannot be combined with {flag} without --fail-on: "
                         f"{flag} never shows {shown}. Use --network {name}, or "
                         f"add --fail-on to gate on them.")
    for flag, on in (("--host", args.host), ("--package", args.package),
                     ("--session", args.session), ("--unasked", args.unasked)):
        if on is not None and on is not False and not args.network:
            ap.error(f"{flag} requires --network: it narrows the network view.")
    if args.host:
        try:
            parse_trust([args.host], "--host")
        except ValueError as exc:
            ap.error(str(exc))
    if args.html and not args.network:
        ap.error("--html requires --network: it writes the network report.")
    if args.html and args.json:
        ap.error("--html writes a file; it cannot also emit --json.")
    if args.html:
        for flag, on in (("--why", args.why), ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--explain", args.explain is not None), ("--agents", args.agents),
                         ("--completions", args.completions), ("--service", args.service),
                         ("--self-check", args.self_check)):
            if on:
                ap.error(f"--html writes a file; it cannot be combined with {flag}.")
    if args.network:
        # After the --html check, which names these with its own message.
        for flag, on in (("--why", args.why), ("--agents", args.agents),
                         ("--explain", args.explain is not None),
                         ("--suppress", args.suppress),
                         ("--suppressions", args.suppressions),
                         ("--self-check", args.self_check), ("--service", args.service),
                         ("--completions", args.completions)):
            if on:
                ap.error(f"--network cannot be combined with {flag}.")
    for flag, on in (("--agents", args.agents), ("--replay", args.replay),
                     ("--watch", args.watch), ("--mcp", args.mcp)):
        if args.with_prompts and on:
            ap.error(f"--with-prompts cannot be combined with {flag}: "
                     f"{flag} has no prompt field.")
    if args.with_prompts and not (args.json or args.html):
        ap.error("--with-prompts applies only to --json or --html; "
                 "the text view already shows prompts.")
    if args.ioc and args.card:
        ap.error("--ioc does not apply to --card; the card never shows downloads.")
    if args.ioc and (args.watch or args.mcp):
        ap.error("--ioc is not supported with --watch or --mcp yet.")
    if args.reputation and args.card:
        ap.error("--reputation does not apply to --card; the card never shows downloads.")
    if args.reputation and (args.watch or args.mcp):
        ap.error("--reputation is not supported with --watch or --mcp yet.")
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
    # One primary mode per run: main() runs the first it meets and would drop
    # the rest without a word (a --suppress write, a --why, a whole view).
    modes = [flag for flag, on in (
        ("--diff", args.diff), ("--why", args.why), ("--replay", args.replay),
        ("--watch", args.watch), ("--mcp", args.mcp),
        ("--explain", args.explain is not None), ("--agents", args.agents),
        ("--suppress", args.suppress), ("--suppressions", args.suppressions),
        ("--self-check", args.self_check), ("--service", args.service),
        ("--completions", args.completions), ("--card", args.card),
        ("--share", args.share), ("--coach", args.coach), ("--aisvs", args.aisvs),
        ("--bash", args.bash)) if on]
    if len(modes) > 1:
        ap.error(f"{modes[0]} cannot be combined with {modes[1]}: each is a different mode.")
    if args.service:
        # The unit runs `actualis --watch` with only --interval and --quiet.
        for flag, on in (("--root", args.root), ("--agent", args.agent != "all"),
                         ("--no-redact", args.no_redact)):
            if on:
                ap.error(f"--service cannot be combined with {flag}: the unit it "
                         f"prints watches the default roots and passes only "
                         f"--interval and --quiet.")
    # Scope and option flags are never silently dropped either (R4, R14): a
    # mode that would ignore one refuses it, naming both. Checked before the
    # modes that return early, so a refused --suppress writes nothing.
    mode = modes[0] if modes else None
    if args.reason is not None and not args.suppress:
        ap.error("--reason applies only to --suppress: it records why a suppression is correct.")
    for flag, on in (("--quiet", args.quiet), ("--interval", args.interval is not None)):
        if not on or args.watch or args.service in ("launchd", "systemd"):
            continue
        if args.service:
            ap.error(f"--service {args.service} cannot be combined with {flag}: "
                     f"the {args.service} rule rotates the log and runs no watcher.")
        ap.error(f"{flag} applies only to --watch, or to the --service launchd or "
                 f"systemd unit that runs it.")
    if args.top is not None:
        # Only the text report (and --bash, --network, which print its
        # sections) lists top-N rows.
        off = mode if mode not in (None, "--bash") else \
            "--json" if args.json else "--html" if args.html else None
        if off:
            ap.error(f"--top cannot be combined with {off}: only the text report "
                     f"lists top projects.")
    else:
        args.top = 12
    if args.interval is None:
        args.interval = 4.0
    # mode -> the scope flags it honours. Modes not listed (the scanning
    # report, --json, --network, --bash, --diff) honour all of them.
    no_text = ("--root", "--agent", "--days", "--project")    # no credential text printed
    honours = {
        "--explain": (), "--agents": (), "--completions": (), "--suppress": (),
        "--suppressions": (), "--service": (),
        "--watch": ("--root", "--agent", "--no-redact"),
        "--self-check": ("--root", "--agent", "--days"),
        "--replay": no_text, "--mcp": no_text, "--why": no_text, "--card": no_text,
        "--share": no_text, "--coach": no_text, "--aisvs": no_text,
    }
    if mode in honours:
        for flag, on in (("--root", args.root is not None), ("--agent", args.agent != "all"),
                         ("--days", args.days is not None),
                         ("--project", args.project is not None),
                         ("--no-redact", args.no_redact)):
            if on and flag not in honours[mode]:
                why = ("it prints no credential text" if flag == "--no-redact"
                       else "it does not read that scope")
                ap.error(f"{mode} cannot be combined with {flag}: {why}.")
    # The P2D3 rule for --ioc, applied to its siblings: these views never show
    # network findings, and these modes never compute them.
    for flag, on in (("--network-strict", args.network_strict),
                     ("--network-trust", bool(args.network_trust))):
        if not on:
            continue
        if mode in ("--replay", "--agents", "--why", "--explain", "--suppress",
                    "--suppressions", "--self-check", "--service", "--completions",
                    "--watch", "--mcp", "--card"):
            ap.error(f"{flag} cannot be combined with {mode}: {mode} never reads it.")
        if mode in ("--coach", "--aisvs", "--share") and not args.fail_on:
            ap.error(f"{flag} cannot be combined with {mode} without --fail-on: "
                     f"{mode} never shows network findings. Use --network, or "
                     f"add --fail-on to gate on them.")
    if args.mcp and args.root and not Path(args.root).expanduser().is_dir():
        ap.error(f"--mcp --root: {clean(args.root)} is not a directory.")
    # Before the modes that return early (--service, --self-check,
    # --completions), so none of them drops these silently.
    if not args.card and args.style != "hero":
        ap.error("--style applies only to --card.")
    if args.out and not (args.card or args.html):
        ap.error("--out applies only to --card or --html.")
    if args.explain and args.explain.lower() not in EXPLAIN:
        ap.error(f"--explain takes a topic ({', '.join(sorted(EXPLAIN))}); "
                 f"got {args.explain!r}. Run --explain alone for the list.")
    if args.card:
        card_dir = Path(args.out).expanduser() if args.out else Path.cwd()
        if not card_dir.is_dir():
            print(f"actualis: {card_dir} is not a directory.\n"
                  "  --out takes the directory the card is written into.", file=sys.stderr)
            return EXIT_CANNOT_RUN
    if args.html:
        html_dir = Path(args.out).expanduser() if args.out else Path.cwd()
        if not html_dir.is_dir():
            print(f"actualis: {html_dir} is not a directory.\n"
                  "  --out takes the directory the report is written into.", file=sys.stderr)
            return EXIT_CANNOT_RUN
    if args.service:
        # Unit to stdout, instructions to stderr: `> file` must yield a file
        # that works, and still tell the user what to do with it.
        try:
            unit = service_unit(args.service, args.interval, args.quiet)
        except ValueError as exc:
            print(f"actualis: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        print(unit, end="")
        print(service_install_notes(args.service), file=sys.stderr)
        return EXIT_OK

    if args.self_check:
        return self_check(C(use_color()), args.days, args.root, args.agent or "all")

    if args.completions:
        print(completion_script(args.completions), end="")
        return EXIT_OK

    if args.replay:
        if not _FINGERPRINT.fullmatch(args.replay):
            ap.error(f"--replay takes a credential fingerprint: eight hex "
                     f"characters, as printed in the report. Got {args.replay!r}.")

    if args.why and args.why.upper() not in COACH_FINDING_IDS:
        ap.error(f"--why takes a finding id ({COACH_FINDING_IDS[0]}-{COACH_FINDING_IDS[-1]}); "
                 f"got {args.why!r}. All findings: docs/findings.md")
    if args.diff and args.json:
        ap.error("--diff renders a comparison; it cannot also emit --json. "
                 "Save this run with --json, then diff the two files.")
    baseline = None
    if args.diff:
        # Before the scan: a bad baseline is a bad argument, and finding that
        # out after reading every transcript wastes the whole run.
        try:
            baseline = load_report(Path(args.diff).expanduser())
        except ValueError as exc:
            ap.error(f"--diff: {clean(str(exc))}")

    since = None
    if args.days:
        since = window_start(args.days)

    if args.suppressions:
        c = C(use_color())
        rule(c, "SUPPRESSIONS")
        for path in suppression_paths():
            mark = "" if path.exists() else f"  {c.dim}(none){c.off}"
            print(f"  {c.dim}{path}{c.off}{mark}")
        rejected: list[str] = []
        current = load_suppressions(rejected)
        print()
        for line in rejected:
            print(f"  {c.yellow}▲{c.off} ignored, not an id from this tool: {line}")
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
            ap.error(str(exc))
        print(f"  suppressed {args.suppress} in {path}")
        if not args.reason:
            print(f"  {c.yellow}▲{c.off} no --reason given. In six months nobody "
                  f"will know why this is here.")
        print(f"  {c.dim}It stays counted; it leaves the actionable list. "
              f"Remove the line to undo.{c.off}")
        return 0

    if args.mcp:
        return mcp_serve({"root": args.root, "agent": args.agent, "days": args.days,
                          "project": args.project})

    if args.explain is not None:
        return render_explain(args.explain.lower() or None, C(use_color()))

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
            slot = {"codex": 1, "copilot": 2, "gemini": 3, "qwen": 4}.get(args.agent, 0)
            if slot >= 3:
                root = _agent_root(root, args.agent)
            w_roots, w_codex, w_copilot, w_gemini, w_qwen = (
                [root] if i == slot else [] for i in range(5))
        else:
            w_roots = transcript_roots() if args.agent in ("all", "claude") else []
            w_codex = codex_roots() if args.agent in ("all", "codex") else []
            w_copilot = copilot_roots() if args.agent in ("all", "copilot") else []
            w_gemini = gemini_roots() if args.agent in ("all", "gemini") else []
            w_qwen = qwen_roots() if args.agent in ("all", "qwen") else []
        return watch(w_roots, w_codex, args.interval,
                     C(use_color()), args.quiet, args.no_redact, w_copilot, w_gemini, w_qwen)

    if args.replay:
        since_r = window_start(args.days, datetime.now(timezone.utc)) if args.days else None
        if not args.json and sys.stderr.isatty():
            print("  reading transcripts...", end="", file=sys.stderr, flush=True)
        events = replay_events(since_r, args.root, args.agent or "all", args.project)
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
            render_replay(_display_safe(inc), C(use_color()))
        return EXIT_OK

    # Loaded here, after every mode that never scans: a malformed trust file
    # or IOC list must not break --explain, --agents, --suppressions and the
    # rest. The IOC list is read only from --ioc; there is no default path.
    try:
        network_trust, trust_sources = load_network_trust_sources(args.network_trust)
        ioc = load_ioc(args.ioc) if args.ioc else None
        reputation = load_reputation() if args.reputation else None
    except (ValueError, OSError) as exc:
        ap.error(str(exc))
    if reputation is not None and reputation.status != "ok":
        where = reputation.directory
        if reputation.status == "absent":
            msg = (f"actualis: --reputation: no Google Safe Browsing lists in {where}. Run "
                   f"`actualis-reputation update` first (it uses the network; actualis never does).")
        else:
            msg = (f"actualis: --reputation: the lists in {where} failed their check "
                   f"({clean(reputation.error or '')}). "
                   f"Run `actualis-reputation update` to download them again.")
        print(msg, file=sys.stderr)
        if args.fail_on:
            return EXIT_USAGE
    if reputation is not None and reputation.vt_error:
        print(f"actualis: --reputation: vt/results.json in {reputation.directory} is unreadable "
              f"({clean(reputation.vt_error)}); VirusTotal verdicts are ignored. Run "
              f"`actualis-reputation virustotal` to rebuild it.", file=sys.stderr)
        if args.fail_on:
            return EXIT_USAGE
    if reputation is not None and reputation.confirmations_error:
        print(f"actualis: --reputation: gsb/confirmations.json in {reputation.directory} is unreadable "
              f"({clean(reputation.confirmations_error)}); matches stay candidates. Run "
              f"`actualis-reputation confirm`.", file=sys.stderr)

    # --network shows only the inventory; --fail-on reads findings (--why
    # with --network is refused above).
    fleet = Fleet(network_only=bool(args.network and not args.fail_on))
    fleet.scope = {"days": args.days or None, "project": clean(args.project or ""),
                   "agent": clean(args.agent or "all")}
    fleet.with_prompts = args.with_prompts
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
        elif args.agent in ("gemini", "qwen"):
            vroot = _agent_root(root, args.agent)
            fleet.roots.append(vroot)
            (fleet.scan_gemini if args.agent == "gemini" else fleet.scan_qwen)(
                [vroot], since, args.project)
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
        if args.agent in ("all", "gemini"):
            groots = gemini_roots()
            if groots:
                fleet.roots.extend(groots)
                fleet.scan_gemini(groots, since, args.project)
            elif args.agent == "gemini":
                sys.exit(no_transcripts_message())
        if args.agent in ("all", "qwen"):
            qroots = qwen_roots()
            if qroots:
                fleet.roots.extend(qroots)
                fleet.scan_qwen(qroots, since, args.project)
            elif args.agent == "qwen":
                sys.exit(no_transcripts_message())

    if fleet.messages == 0 and fleet.bash_total == 0:
        print(dead_end_message(fleet, args), file=sys.stderr)
        return EXIT_CANNOT_RUN

    if network_filtered(args):
        network_filter(fleet, args.host, args.package, args.session, args.unasked)
    apply_network_policy(fleet, network_trust, args.network_strict, trust_sources)
    apply_ioc(fleet, ioc)
    apply_reputation(fleet, reputation)

    if baseline is not None:
        render_diff(_display_safe(diff_reports(baseline, to_json(fleet, raw=args.no_redact))),
                    C(use_color()))
        return EXIT_OK

    # What the terminal (and the --ci-log job summary) shows: one line per
    # transcript string (R13). --json, --html and the gate read the fleet.
    view = _display_view(fleet) if not (args.json or args.html or args.card) else fleet

    if args.why:
        return render_why(args.why, view, C(use_color()))

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

    # The verdict is decided before any output (R5): a reader that closes
    # stdout early must not turn a failing gate into a pass. _cli() reads it.
    _PENDING_GATE[:] = [(args.fail_on, failing_findings(fleet, args.fail_on),
                         _suppressed_count(fleet))] if args.fail_on else []

    if args.html:
        page = render_network_html(network_json(fleet, raw=args.no_redact),
                                   filters=network_filter_names(args), version=__version__,
                                   with_prompts=args.with_prompts, flags=fleet.flags)
        try:
            path = write_network_html(page, html_dir)
        except OSError as exc:
            print(f"actualis: cannot write the report to {html_dir}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_CANNOT_RUN
        print(path)
        if args.no_redact:
            print("actualis: --no-redact is on: this report may contain live secrets.",
                  file=sys.stderr)
    elif args.json:
        json.dump(network_json(fleet, raw=args.no_redact) if args.network
                  else to_json(fleet, raw=args.no_redact), sys.stdout, indent=2)
        print()
        if args.no_redact:
            print("actualis: --no-redact is on: this output may contain live secrets.",
                  file=sys.stderr)
    elif args.share:
        render_share(view, C(use_color()))
    elif args.aisvs:
        render_aisvs(aisvs_findings(view), C(use_color()))
    elif args.coach:
        render_coach(coach(view), C(use_color()))
    else:
        render(view, C(use_color()), bash_only=args.bash, top=args.top, raw=args.no_redact,
               network_only=args.network, network_filters=network_filter_names(args))

    if _PENDING_GATE:
        return _gate_verdict()
    return EXIT_OK


# (level, reasons, suppressed count) for the run in progress, set by main()
# before it writes the report, so a closed stdout still gets the gate's code.
_PENDING_GATE: list = []


def _suppressed_count(fleet: Fleet) -> int:
    """Suppressed credentials AND suppressed flags: both leave the gate."""
    return (len(fleet.secrets) - len(fleet.actionable_secrets)
            + len(fleet.flags) - len(fleet.actionable_flags))


def _gate_verdict() -> int:
    """Print the pending --fail-on verdict to stderr and return its exit code.

    The code is decided first and returned whatever happens to stderr: a reader
    that closes stderr mid-verdict (`2>&1 | head -1`) must not turn a failing
    gate into a pass (R5), and the verdict leaves the pending list only once it
    has been reported, or reporting it has failed."""
    if not _PENDING_GATE:
        return EXIT_OK
    level, reasons, suppressed = _PENDING_GATE[-1]
    code = EXIT_FINDINGS if reasons else EXIT_OK
    # stderr, so `--json` on stdout stays byte-identical and a pipeline can
    # capture the report and the verdict separately.
    try:
        if reasons:
            print(f"actualis: FAIL at --fail-on {level}", file=sys.stderr)
            for r in reasons:
                print(f"  - {_one_line(r)}", file=sys.stderr)
            print(f"  {suppressed} suppressed finding(s) were not counted.", file=sys.stderr)
        else:
            print(f"actualis: PASS at --fail-on {level}", file=sys.stderr)
        sys.stderr.flush()
    except (OSError, ValueError):            # BrokenPipeError is an OSError
        _silence_stderr()
    finally:
        _PENDING_GATE[:] = []
    return code


def _reader_gone(exc: BaseException) -> bool:
    """True when `exc` is a write to a std stream whose reader has gone.

    POSIX reports that as EPIPE (BrokenPipeError). Windows reports a write or
    flush to a pipe with no reader as EINVAL (errno 22) instead: only there,
    and only for an error that names no file (a bad path is EINVAL on Windows
    too, and carries its filename), is it treated the same way.
    """
    if isinstance(exc, BrokenPipeError):
        return True
    return (sys.platform == "win32" and isinstance(exc, OSError)
            and exc.errno == 22 and exc.filename is None)


def _silence_fd(stream) -> None:
    """Point a stream's descriptor at the null device once its reader has gone.

    Otherwise the interpreter's own flush at exit fails again and replaces the
    exit code with 120, a code the docs do not list.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass


def _silence_stdout() -> None:
    """Point stdout at the null device once its reader has gone."""
    _silence_fd(sys.stdout)


def _silence_stderr() -> None:
    """Point stderr at the null device once its reader has gone."""
    _silence_fd(sys.stderr)


def _cli(argv: list[str] | None = None) -> int:
    """main() with the process-level handling: Ctrl-C and a closed stdout or stderr."""
    code = None
    _PENDING_GATE[:] = []
    try:
        code = main(argv)
        sys.stdout.flush()
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        if not _reader_gone(exc):
            raise
        # `actualis | head` is not an error, but it must not turn a failing
        # gate into exit 0 either: the verdict was decided before the output.
        # Only the stream whose reader has gone is silenced, so a closed
        # stderr does not throw away a report still buffered for stdout.
        for stream, silence in ((sys.stdout, _silence_stdout), (sys.stderr, _silence_stderr)):
            try:
                stream.flush()
            except (OSError, ValueError):
                silence()
        if code is None:
            code = _gate_verdict()
    try:
        sys.stderr.flush()
    except (OSError, ValueError):
        _silence_stderr()
    return code


if __name__ == "__main__":
    sys.exit(_cli())
