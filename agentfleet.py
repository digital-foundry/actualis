#!/usr/bin/env python3
"""
agentfleet - what your coding agents cost, and what they actually did.

Reads Claude Code's local session transcripts and produces a fleet-wide report:
spend by model and project, tool activity, and a deterministic audit of every
shell command your agents ran.

No network. No telemetry. No dependencies. Reads only files already on your disk.

Usage:
    python3 agentfleet.py                 # full report, all time
    python3 agentfleet.py --days 30       # last 30 days
    python3 agentfleet.py --bash          # shell audit only
    python3 agentfleet.py --json          # machine-readable
    python3 agentfleet.py --project foo   # filter to matching projects
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

__version__ = "0.1.0"

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

# Two providers, two cache conventions. Getting this backwards overcharges:
#
#   anthropic  input_tokens EXCLUDES cached. cache_read is a separate bucket at
#              0.10x, cache writes cost 1.25x (5m TTL) or 2.00x (1h TTL).
#   openai     input_tokens INCLUDES cached_input_tokens. Cached portion bills at
#              0.10x, the rest at full rate. There is no cache-write premium, and
#              reasoning_output_tokens is a subset of output_tokens, not an addition.
PRICING = {
    # model id            (input $/Mtok, output $/Mtok, provider)
    "claude-fable-5":     (10.0, 50.0, "anthropic"),
    "claude-mythos-5":    (10.0, 50.0, "anthropic"),
    "claude-opus-5":      (5.0, 25.0, "anthropic"),
    "claude-opus-4-8":    (5.0, 25.0, "anthropic"),
    "claude-opus-4-7":    (5.0, 25.0, "anthropic"),
    "claude-opus-4-6":    (5.0, 25.0, "anthropic"),
    "claude-sonnet-5":    (3.0, 15.0, "anthropic"),
    "claude-sonnet-4-6":  (3.0, 15.0, "anthropic"),
    "claude-haiku-4-5":   (1.0, 5.0, "anthropic"),
    # OpenAI rates via pricepertoken.com, 2026-08-22. Third-party aggregator,
    # not OpenAI's own page: verify before trusting a number that matters.
    "gpt-5.2-codex":      (1.75, 14.0, "openai"),
}

OPENAI_CACHED_MULT = 0.10

# Claude Sonnet 5 introductory pricing, through 2026-08-31.
SONNET5_INTRO_UNTIL = datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc)
SONNET5_INTRO = (2.0, 10.0, "anthropic")

DEFAULT_RATES = (5.0, 25.0, "anthropic")  # unknown model: assume Opus-tier, and say so


def rates_for(model: str, when: datetime | None) -> tuple[float, float, str, bool]:
    """Return (input_rate, output_rate, provider, is_known) at a point in time."""
    if model == "claude-sonnet-5" and when is not None and when <= SONNET5_INTRO_UNTIL:
        return (*SONNET5_INTRO, True)
    if model in PRICING:
        return (*PRICING[model], True)
    if model.startswith(("gpt-", "o1", "o3", "o4")):
        return (1.75, 14.0, "openai", False)
    return (*DEFAULT_RATES, False)


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
    ("high", "remote-exec",      r"\b(curl|wget)\b[^|;\n]*\|\s*(sudo\s+)?(ba|z|k)?sh\b"),
    # An interpreter with an inline-script flag (-c/-e/-m) treats stdin as DATA,
    # so `curl … | python3 -c '…'` is parsing a response, not running downloaded
    # code. Only the bare interpreter form executes what was fetched.
    ("high", "remote-exec",      r"\b(curl|wget)\b[^|;\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b"
                                 r"(?!\s+-(?:c|e|m|p)\b)"),
    ("med",  "remote-exec",      r"\bnpx\s+(-y\s+)?https?://"),
    ("med",  "remote-exec",      r"\bpip\s+install\b[^|;\n]*\bhttps?://"),

    # --- credential and secret access ---
    ("high", "credentials",      r"(cat|less|more|head|tail|strings|cp|scp|base64)\b[^|;\n]*"
                                 r"(\.env(\.[a-z]+)?|id_[rd]sa|\.pem|\.p12|credentials|\.netrc|\.npmrc|\.pypirc)\b"),
    ("high", "credentials",      r"\bsecurity\s+find-(generic|internet)-password\b"),
    ("med",  "credentials",      r"\b(printenv|env)\b\s*(\||$)"),
    ("med",  "credentials",      r"\b(AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN)\s*="),
    ("high", "credentials",      r"\bgh\s+auth\s+token\b"),

    # --- data egress ---
    # Case-sensitive on the flags: curl -D (dump headers) is not curl -d (send body).
    # Skipped entirely when the command only talks to loopback.
    ("high", "egress",           r"(?!.*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))"
                                 r"\bcurl\b[^|;\n]*\s(?-i:-d|--data|--data-raw|--data-binary|-F|--form|-T|--upload-file)\b"),
    ("med",  "egress",           r"\b(scp|rsync)\b[^|;\n]*\s[^\s]+@[^\s]+:"),

    # --- git danger ---
    ("high", "git",              r"\bgit\s+push\b[^|;\n]*\s(--force|-f)\b"),
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
    ("high", "publish",          r"\baws\s+s3\s+(rm|sync)\b[^|;\n]*--delete\b"),

    # --- database ---
    ("high", "database",         r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b"),
    ("high", "database",         r"\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)"),
    ("med",  "database",         r"\b(psql|mysql|mongosh)\b[^|;\n]*-c\b"),

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


def audit_command(cmd: str) -> list[tuple[str, str, str]]:
    """Return [(severity, category, matching_line)] for every rule that fires.

    Agent commands are frequently multi-line scripts. Reporting the first line
    of a 40-line heredoc tells you nothing, so each match carries the line that
    actually triggered it.
    """
    lines = cmd.splitlines() or [cmd]
    out: list[tuple[str, str, str]] = []
    for sev, cat, rx in COMPILED_RULES:
        for ln in lines:
            if rx.search(ln):
                out.append((sev, cat, ln.strip()))
                break
        else:
            # Some rules span lines (e.g. a pipeline broken across newlines).
            if rx.search(cmd):
                out.append((sev, cat, cmd.strip().splitlines()[0]))
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
]

_SECRET_PATTERNS = [
    # KEY=value / KEY: value for anything that smells like a secret
    re.compile(
        r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY"
        r"|PRIVATE_KEY|CREDENTIAL|AUTH|BEARER|SESSION|COOKIE)[A-Z0-9_]*)"
        r"(\s*[=:]\s*)(['\"]?)"
        r"(?!(?:Bearer|Basic|Digest|Token|None|null|true|false)\b)"
        r"([^\s'\";|&]{6,})"
    ),
    # bare tokens by known prefix
    re.compile(r"\b(" + "|".join(re.escape(p) for p in _TOKEN_PREFIXES) + r")([A-Za-z0-9_\-]{8,})"),
    # Authorization headers
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)([^\s'\"]{8,})"),
    # postgres://user:pass@host and friends
    re.compile(r"([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s@/]{3,})(@)"),
]


_MASKED = "<redacted"


_SHELL_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def _mask(s: str) -> str:
    if _MASKED in s:          # already redacted; re-masking would corrupt the length
        return s
    if _SHELL_REF.match(s):   # "$VERCEL_TOKEN" is a reference; the secret is elsewhere
        return s
    if len(s) <= 8:
        return "<redacted>"
    return f"{s[:4]}…<redacted:{len(s)}>"


def redact(text: str) -> str:
    """Remove credential material from a command string. Idempotent."""
    if not text:
        return text
    out = text
    # Order matters: the Authorization header rule must run before the generic
    # KEY=value rule, or "AUTH" in "Authorization:" makes it eat the scheme word.
    out = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    out = _SECRET_PATTERNS[3].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}{m.group(3)}", out)
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask(m.group(4))}", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    return out


def contains_secret(text: str) -> bool:
    return redact(text) != text


# Words that are never the command being run.
_HEADER_KEYWORDS = {"for", "while", "until", "if", "case", "select", "function", "elif"}
_BODY_KEYWORDS = {"do", "then", "else", "fi", "done", "esac", "in", "{", "(", "!"}
_PREFIX_WORDS = {"sudo", "env", "exec", "time", "nohup", "command", "builtin", "nice", "xargs"}
_TAKES_PATH_ARG = {"cd", "pushd", "popd"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


# --------------------------------------------------------------------------
# Ticket attribution
#
# Cost per project answers "where did the money go" at a granularity nobody
# budgets in. Branch names almost always carry the issue number, so the same
# data answers "what did issue #1283 cost", which is the unit engineering and
# finance already think in.
#
# One ticket often spans several branches (feat/1283-p5-…, feat/1283-p6-…), so
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
    re.compile(r"^[a-z]+/(\d{1,6})\b", re.I),            # feat/1283-slug
    re.compile(r"^(\d{2,6})-"),                           # 1283-slug
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
    ("critical", "Anthropic key",    re.compile(r"\bsk-ant-[a-z0-9-]*([A-Za-z0-9_\-]{16,})")),
    ("critical", "OpenAI key",       re.compile(r"\bsk-(?!ant)[A-Za-z0-9]{2,}-([A-Za-z0-9_\-]{16,})")),
    ("critical", "JWT / service key", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.([A-Za-z0-9_\-]{20,})")),
    ("high",     "GitHub PAT",       re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)([A-Za-z0-9_]{16,})")),
    ("high",     "Google API key",   re.compile(r"\bAIza([A-Za-z0-9_\-]{16,})")),
    ("high",     "Slack token",      re.compile(r"\bxox[baprs]-([A-Za-z0-9\-]{16,})")),
    ("high",     "Vercel token",     re.compile(r"\bvcp_([A-Za-z0-9]{16,})")),
    ("high",     "GitLab PAT",       re.compile(r"\bglpat-([A-Za-z0-9_\-]{16,})")),
    ("high",     "DigitalOcean",     re.compile(r"\bdop_v1_([a-f0-9]{32,})")),
    ("high",     "HuggingFace",      re.compile(r"\bhf_([A-Za-z0-9]{16,})")),
]

# Connection strings. Loopback is dev credential churn, not an incident.
_URL_CRED = re.compile(r"([a-z][a-z0-9+.\-]*)://([^\s:/@]+):([^\s@/]{6,})@([^\s/:\"']+)")
_LOCAL_HOST = re.compile(r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$", re.I)

# Secret-shaped assignments, minus the field names that merely *sound* like one.
_NAMED_SECRET = re.compile(
    r"\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)"
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
            f"{scheme} password ({'local' if local else 'remote'})", pw)

    for m in _NAMED_SECRET.finditer(cmd):
        name, value = m.group(1), m.group(2)
        if _NOT_SECRET_NAMES.match(name):
            continue
        add(_priority_for_name(name), name.upper(), value)

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
    for segment in re.split(r"&&|\|\||;|\||\n", cmd.strip()):
        tokens = segment.split()
        if not tokens:
            continue
        if tokens[0] in _HEADER_KEYWORDS:
            continue  # loop/conditional header: the body is a later segment
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if _ASSIGNMENT.match(tok):
                continue                      # environment assignment
            if tok in _BODY_KEYWORDS or tok in _PREFIX_WORDS:
                continue                      # `do tool …`, `sudo tool …`
            if tok == "\\":
                continue                      # line continuation, not a program
            if tok in _TAKES_PATH_ARG:
                skip_next = True              # `cd /some/path && real-cmd`
                continue
            return tok
    first = cmd.strip().split()
    return first[0] if first else None


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
    return s or slug


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
    in_rate, out_rate, provider, _known = rates_for(model, None)
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
        self.secret_exposures = 0
        self.secret_projects: Counter = Counter()
        # (priority, type, fingerprint) -> {uses, first, last, projects}
        self.secrets: dict[str, dict] = {}   # sha256[:8] -> record
        self.unknown_models: Counter = Counter()
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.roots: list[Path] = []
        self.files_scanned = 0
        self.bytes_scanned = 0

    # -- ingest ------------------------------------------------------------

    def add_usage(self, project: str, model: str, usage: dict, ts: datetime | None,
                  branch: str | None = None) -> None:
        cc = usage.get("cache_creation") or {}
        w1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
        w5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        if not w1h and not w5m:
            # older transcripts only carry the flat total; assume 5m TTL
            w5m = usage.get("cache_creation_input_tokens", 0) or 0

        inp = usage.get("input_tokens", 0) or 0
        out = usage.get("output_tokens", 0) or 0
        rd = usage.get("cache_read_input_tokens", 0) or 0

        in_rate, out_rate, _provider, known = rates_for(model, ts)
        if not known:
            self.unknown_models[model] += 1

        cost = (
            inp / 1e6 * in_rate
            + out / 1e6 * out_rate
            + w1h / 1e6 * in_rate * CACHE_WRITE_1H_MULT
            + w5m / 1e6 * in_rate * CACHE_WRITE_5M_MULT
            + rd / 1e6 * in_rate * CACHE_READ_MULT
        )

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
        self.tokens["cache_read"] += rd
        pt = self.tokens_by_project[project]
        pt["input"] += inp; pt["output"] += out
        pt["cache_w"] += w1h + w5m; pt["cache_read"] += rd
        self.msgs_by_project[project] += 1

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
        _, _, _, known = rates_for(model, None)
        if not known:
            self.unknown_models[model] += 1

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
            self.bytes_scanned += path.stat().st_size
        except OSError:
            return
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

    def add_subagent(self, result: dict, ts: datetime | None) -> None:
        """One completed subagent run.

        `totalTokens` is NOT the run total. It equals the sum of the final
        message's usage in 873 of 873 observed cases and scales only ~2x from a
        4-tool run to a 45-tool run, which is context growth, not summation. The
        cumulative spend of a subagent's turns is not present in the parent
        transcript, so what is recorded here is an explicit FLOOR.
        """
        self.sub_calls += 1
        model = result.get("resolvedModel") or "unknown"
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
            in_rate, out_rate, _prov, _known = rates_for(base, ts)
            cc = u.get("cache_creation") or {}
            self.sub_cost_floor += (
                (u.get("input_tokens", 0) or 0) / 1e6 * in_rate
                + (u.get("output_tokens", 0) or 0) / 1e6 * out_rate
                + (cc.get("ephemeral_1h_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_WRITE_1H_MULT
                + (cc.get("ephemeral_5m_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_WRITE_5M_MULT
                + (u.get("cache_read_input_tokens", 0) or 0) / 1e6 * in_rate * CACHE_READ_MULT)

    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None) -> None:
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
            self.bash_first_token[head[:40]] += 1

        if contains_secret(cmd):
            self.secret_exposures += 1
            self.secret_projects[project] += 1

        _rank = {"critical": 0, "high": 1, "low": 2}
        for priority, kind, fp in classify_secrets(cmd):
            e = self.secrets.setdefault(fp, {
                "priority": priority, "kinds": set(), "uses": 0,
                "first": None, "last": None, "projects": set()})
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
        self.flags.append({
            "severity": worst[0],
            "categories": sorted({c for _, c, _ in matches}),
            "project": project,
            "when": ts.isoformat() if ts else None,
            "evidence": evidence[:240],
            "had_secret": contains_secret(cmd),
        })

    # -- scan --------------------------------------------------------------

    def scan(self, roots: list[Path], since: datetime | None, project_filter: str | None,
             progress: bool) -> None:
        if not roots:
            return
        self.roots.extend(roots)
        dirs = sorted(d for r in roots for d in r.iterdir() if d.is_dir())
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
            size = path.stat().st_size
        except OSError:
            return
        self.files_scanned += 1
        self.bytes_scanned += size
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
                    eff = rec.get("effort")
                    if eff:
                        self.effort_mix[str(eff)] += 1

                    msg = rec.get("message")
                    if not isinstance(msg, dict):
                        continue

                    usage = msg.get("usage")
                    if isinstance(usage, dict):
                        self.add_usage(project, msg.get("model") or "unknown", usage, ts,
                                       rec.get("gitBranch"))

                    tur = rec.get("toolUseResult")
                    if isinstance(tur, dict) and tur.get("toolStats") is not None:
                        self.add_subagent(tur, ts)

                    content = msg.get("content")
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_use":
                                self.add_tool(project, block.get("name") or "?",
                                              block.get("input") or {}, ts)
        except OSError:
            return

    # -- derived -----------------------------------------------------------

    @property
    def total_cost(self) -> float:
        return sum(self.cost_by_model.values())

    @property
    def span_days(self) -> float:
        if not (self.first_ts and self.last_ts):
            return 0.0
        return max((self.last_ts - self.first_ts).total_seconds() / 86400.0, 1.0)

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
        tot = sum(t.values())
        if tot > 1_000_000 and fleet.cost_by_project.get(proj, 0) >= MIN_PROJECT_COST:
            ratios[proj] = t["cache_read"] / tot * 100
    if len(ratios) >= 3:
        med = _median(list(ratios.values()))
        for proj, r in sorted(ratios.items(), key=lambda kv: kv[1]):
            if r < med - 15 and r < 90:
                waste = fleet.cost_by_project.get(proj, 0) * ((med - r) / 100) * 0.5
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
                "AF011", "high", "A fifth of shell activity is invisible to the audit",
                f"{num(sub_bash)} shell commands ran inside {num(fleet.sub_calls)} "
                f"subagent runs, {blind:.0f}% of all shell activity. Their command text "
                f"is never written to the parent transcript.",
                "Subagents inherit the parent's permissions but not its visibility. If "
                "the audit matters to you, prefer doing shell work in the main loop, or "
                "treat these runs as unreviewed."))

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
            script = (f"display notification {json.dumps(message)} "
                      f"with title {json.dumps(title)}")
            subprocess.run(["osascript", "-e", script], timeout=5,
                           capture_output=True, check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["notify-send", title, message], timeout=5,
                           capture_output=True, check=False)
        elif sys.platform == "win32":
            ps = (f"[Windows.UI.Notifications.ToastNotificationManager, "
                  f"Windows.UI.Notifications, ContentType=WindowsRuntime] > $null; "
                  f"Write-Output {json.dumps(title + ': ' + message)}")
            subprocess.run(["powershell", "-NoProfile", "-Command", ps], timeout=5,
                           capture_output=True, check=False)
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
    print(f"{c.bold}agentfleet watch{c.off} {c.dim}· {len(offsets)} files · every "
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
                            notify("agentfleet: credential exposed", msg)
                        hits = audit_command(command)
                        high = [h for h in hits if h[0] == "high"]
                        if high:
                            flagged += 1
                            cats = ",".join(sorted({h[1] for h in high}))
                            line_txt = high[0][2] if raw else redact(high[0][2])
                            print(f"\r{c.yellow}▲ {cats}{c.off}  {line_txt[:88]}"
                                  f"  {c.dim}{project[:28]}{c.off}" + " " * 10)
                            if not quiet:
                                notify(f"agentfleet: {cats}", line_txt[:120])

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
        tok = sum(fleet.tokens.values())
        print(f"  tokens        {num(tok)}")
        print(f"  {c.bold}cost{c.off}          {c.bold}{money(fleet.total_cost)}{c.off} "
              f"{c.dim}notional, at API list price{c.off}")
        if active >= 2:
            per_day = fleet.total_cost / active
            print(f"  {c.dim}per active day {money(per_day)}"
                  f"   ·  per week {money(per_day * 7)}"
                  f"   ·  {active} active days of {span:.0f}{c.off}")

        rule(c, "TOKENS")
        for k, label in (("input", "input"), ("output", "output"),
                         ("cache_w_1h", "cache write 1h  ×2.00"),
                         ("cache_w_5m", "cache write 5m  ×1.25"),
                         ("cache_read", "cache read      ×0.10")):
            v = fleet.tokens.get(k, 0)
            pct = (v / tok * 100) if tok else 0
            print(f"  {label:<22} {num(v):>16}  {c.dim}{pct:5.1f}%{c.off}")

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
        actionable = sum(1 for _, e in rows if e["priority"] != "low")

        print(f"\n  {c.red}▲ {num(distinct)} distinct secrets{c.off} exposed across "
              f"{num(fleet.secret_exposures)} commands "
              f"{c.dim}({num(actionable)} worth rotating){c.off}")
        print(f"\n  {'':<9} {'type':<26} {'uses':>6}  {'first':<11} {'last':<11} id")
        for fp, e in rows[:24]:
            pri = e["priority"]
            col = c.red if pri == "critical" else (c.yellow if pri == "high" else c.dim)
            mark = "ROTATE" if pri == "critical" else ("rotate" if pri == "high" else "dev")
            kind = ", ".join(sorted(e["kinds"]))
            print(f"    {col}{mark:<7}{c.off} {kind[:26]:<26} {num(e['uses']):>6}  "
                  f"{(e['first'] or '?'):<11} {(e['last'] or '?'):<11} {c.dim}{fp}{c.off}")
        if len(rows) > 24:
            print(f"    {c.dim}… {len(rows) - 24} more{c.off}")
        print(f"\n    {c.dim}id is sha256[:8] of the secret; the value is never stored or")
        print(f"    printed. Same secret reused 200 times counts once. Rotate in the order")
        print(f"    shown, then purge the transcripts that carry them.{c.off}")

    highs = [f for f in fleet.flags if f["severity"] == "high"]
    meds = [f for f in fleet.flags if f["severity"] == "med"]

    print(f"\n  {c.dim}flagged{c.off}   "
          f"{c.red}{len(highs)} high{c.off}   {c.yellow}{len(meds)} medium{c.off}   "
          f"{c.dim}of {num(fleet.bash_total)} commands{c.off}")

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

    print()
    print(f"{c.dim}  Costs are Anthropic API list prices (verified 2026-08-22). On a Pro/Max")
    print(f"  subscription your actual outlay is the flat fee; read this as consumption.")
    print(f"  Flags mean 'worth looking at', not 'wrong'. Nothing left this machine.")
    if not raw:
        print(f"  Credentials are redacted; --no-redact disables that.{c.off}")
    else:
        print(f"  {c.red}--no-redact is on: this output may contain live secrets.{c.off}")
    print()


def to_json(fleet: Fleet, raw: bool = False) -> dict:
    return {
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
        "cost_usd": round(fleet.total_cost, 4),
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
        "secrets": [
            {"priority": e["priority"], "types": sorted(e["kinds"]), "id": fp,
             "uses": e["uses"], "first_seen": e["first"], "last_seen": e["last"],
             "projects": sorted(e["projects"])}
            for fp, e in sorted(
                fleet.secrets.items(),
                key=lambda kv: ({"critical": 0, "high": 1, "low": 2}.get(kv[1]["priority"], 9),
                                -kv[1]["uses"]))
        ],
        "secret_projects": dict(fleet.secret_projects),
        "redacted": not raw,
        "permission_modes": dict(fleet.permission_modes),
        "denials": dict(fleet.denials),
        "unknown_models": dict(fleet.unknown_models),
    }


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentfleet",
        description="What your coding agents cost, and what they actually did.",
    )
    ap.add_argument("--days", type=int, metavar="N", help="only the last N days")
    ap.add_argument("--project", metavar="SUBSTR", help="only projects matching SUBSTR")
    ap.add_argument("--top", type=int, default=12, metavar="N", help="projects to list (default 12)")
    ap.add_argument("--bash", action="store_true", help="shell audit only")
    ap.add_argument("--coach", action="store_true", help="coaching findings only")
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
    ap.add_argument("--root", metavar="DIR", help="transcript directory")
    ap.add_argument("--version", action="version", version=f"agentfleet {__version__}")
    args = ap.parse_args(argv)

    since = None
    if args.days:
        since = datetime.now(timezone.utc) - timedelta(days=args.days)

    if args.watch:
        if args.root:
            w_roots, w_codex = [Path(args.root).expanduser()], []
        else:
            w_roots = transcript_roots() if args.agent in ("all", "claude") else []
            w_codex = codex_roots() if args.agent in ("all", "codex") else []
        return watch(w_roots, w_codex, max(args.interval, 0.5),
                     C(use_color()), args.quiet, args.no_redact)

    fleet = Fleet()
    progress = not args.json and sys.stderr.isatty()

    if args.root:
        fleet.scan([Path(args.root).expanduser()], since, args.project, progress=progress)
    else:
        if args.agent in ("all", "claude"):
            roots = transcript_roots()
            if roots:
                fleet.scan(roots, since, args.project, progress=progress)
            elif args.agent == "claude":
                sys.exit("agentfleet: no Claude Code transcripts found.")
        if args.agent in ("all", "codex"):
            croots = codex_roots()
            if croots:
                fleet.roots.extend(croots)
                fleet.scan_codex(croots, since, args.project)
            elif args.agent == "codex":
                sys.exit("agentfleet: no Codex sessions found under $CODEX_HOME/sessions.")

    if fleet.messages == 0 and fleet.bash_total == 0:
        print("agentfleet: no matching activity found.", file=sys.stderr)
        return 1

    if args.json:
        json.dump(to_json(fleet, raw=args.no_redact), sys.stdout, indent=2)
        print()
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
