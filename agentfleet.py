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

PRICING = {
    # model id            (input $/Mtok, output $/Mtok)
    "claude-fable-5":     (10.0, 50.0),
    "claude-mythos-5":    (10.0, 50.0),
    "claude-opus-5":      (5.0, 25.0),
    "claude-opus-4-8":    (5.0, 25.0),
    "claude-opus-4-7":    (5.0, 25.0),
    "claude-opus-4-6":    (5.0, 25.0),
    "claude-sonnet-5":    (3.0, 15.0),
    "claude-sonnet-4-6":  (3.0, 15.0),
    "claude-haiku-4-5":   (1.0, 5.0),
}

# Claude Sonnet 5 introductory pricing, through 2026-08-31.
SONNET5_INTRO_UNTIL = datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc)
SONNET5_INTRO = (2.0, 10.0)

DEFAULT_RATES = (5.0, 25.0)  # unknown model: assume Opus-tier, and say so


def rates_for(model: str, when: datetime | None) -> tuple[float, float, bool]:
    """Return (input_rate, output_rate, is_known) for a model at a point in time."""
    if model == "claude-sonnet-5" and when is not None and when <= SONNET5_INTRO_UNTIL:
        return (*SONNET5_INTRO, True)
    if model in PRICING:
        return (*PRICING[model], True)
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


def command_head(cmd: str) -> str | None:
    """The program actually being run.

    Agent commands are rarely a bare invocation. They arrive as
    `VAR=x cd path && for f in *.py; do tool $f; done`, and naively taking the
    first token reports `VAR=x` or `for`, which tells you nothing about what ran.
    """
    for segment in re.split(r"&&|\|\||;|\|", cmd.strip()):
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


class Fleet:
    def __init__(self) -> None:
        self.messages = 0
        self.cost_by_model: dict[str, float] = defaultdict(float)
        self.msgs_by_model: Counter = Counter()
        self.cost_by_project: dict[str, float] = defaultdict(float)
        self.cost_by_day: dict[str, float] = defaultdict(float)
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
        self.unknown_models: Counter = Counter()
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.roots: list[Path] = []
        self.files_scanned = 0
        self.bytes_scanned = 0

    # -- ingest ------------------------------------------------------------

    def add_usage(self, project: str, model: str, usage: dict, ts: datetime | None) -> None:
        cc = usage.get("cache_creation") or {}
        w1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
        w5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        if not w1h and not w5m:
            # older transcripts only carry the flat total; assume 5m TTL
            w5m = usage.get("cache_creation_input_tokens", 0) or 0

        inp = usage.get("input_tokens", 0) or 0
        out = usage.get("output_tokens", 0) or 0
        rd = usage.get("cache_read_input_tokens", 0) or 0

        in_rate, out_rate, known = rates_for(model, ts)
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
        self.msgs_by_model[model] += 1
        self.cost_by_model[model] += cost
        self.cost_by_project[project] += cost
        self.tokens["input"] += inp
        self.tokens["output"] += out
        self.tokens["cache_w_1h"] += w1h
        self.tokens["cache_w_5m"] += w5m
        self.tokens["cache_read"] += rd

        if ts:
            self.cost_by_day[ts.date().isoformat()] += cost
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None) -> None:
        self.tools[name] += 1
        if name != "Bash":
            return
        cmd = (tool_input or {}).get("command") or ""
        if not cmd:
            return
        self.bash_total += 1
        head = command_head(cmd)
        if head:
            self.bash_first_token[head[:40]] += 1

        if contains_secret(cmd):
            self.secret_exposures += 1
            self.secret_projects[project] += 1

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
            sys.exit("agentfleet: no Claude Code transcripts found.\n"
                     "Looked in ~/.claude/projects and $CLAUDE_CONFIG_DIR/projects.\n"
                     "Pass --root DIR if yours lives elsewhere.")
        self.roots = roots
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

                    msg = rec.get("message")
                    if not isinstance(msg, dict):
                        continue

                    usage = msg.get("usage")
                    if isinstance(usage, dict):
                        self.add_usage(project, msg.get("model") or "unknown", usage, ts)

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
    weeks = span / 7.0 if span else 0

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
        if weeks >= 1:
            print(f"  {c.dim}per week      {money(fleet.total_cost / weeks)}"
                  f"   ·  annualized {money(fleet.total_cost / weeks * 52)}{c.off}")

        rule(c, "TOKENS")
        for k, label in (("input", "input"), ("output", "output"),
                         ("cache_w_1h", "cache write 1h  ×2.00"),
                         ("cache_w_5m", "cache write 5m  ×1.25"),
                         ("cache_read", "cache read      ×0.10")):
            v = fleet.tokens.get(k, 0)
            pct = (v / tok * 100) if tok else 0
            print(f"  {label:<22} {num(v):>16}  {c.dim}{pct:5.1f}%{c.off}")

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

    if fleet.permission_modes:
        modes = "  ".join(f"{k}={num(v)}" for k, v in fleet.permission_modes.most_common(5))
        print(f"  permission    {modes}")
    if fleet.denials:
        den = "  ".join(f"{k}={num(v)}" for k, v in fleet.denials.most_common(5))
        print(f"  denied        {den}")

    print(f"\n  {c.dim}most-run commands{c.off}")
    for cmd, n in fleet.bash_first_token.most_common(12):
        print(f"    {num(n):>7}  {cmd[:40]}")

    if fleet.secret_exposures:
        print(f"\n  {c.red}▲ {num(fleet.secret_exposures)} commands contained credential "
              f"material{c.off}")
        for p, n in fleet.secret_projects.most_common(5):
            print(f"      {num(n):>7}  {p[:56]}")
        print(f"    {c.dim}Those secrets are sitting in plaintext in your transcripts under")
        print(f"    ~/.claude/projects. Rotate anything live. Output here is redacted.{c.off}")

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
        },
        "scanned": {"files": fleet.files_scanned, "bytes": fleet.bytes_scanned,
                    "roots": [str(r) for r in fleet.roots]},
        "messages": fleet.messages,
        "cost_usd": round(fleet.total_cost, 4),
        "tokens": dict(fleet.tokens),
        "by_model": {k: round(v, 4) for k, v in
                     sorted(fleet.cost_by_model.items(), key=lambda kv: -kv[1])},
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
        "secret_exposures": fleet.secret_exposures,
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
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-redact", action="store_true",
                    help="do NOT redact credentials from output (unsafe to share)")
    ap.add_argument("--root", metavar="DIR", help="transcript directory")
    ap.add_argument("--version", action="version", version=f"agentfleet {__version__}")
    args = ap.parse_args(argv)

    since = None
    if args.days:
        since = datetime.now(timezone.utc) - timedelta(days=args.days)

    roots = [Path(args.root).expanduser()] if args.root else transcript_roots()

    fleet = Fleet()
    fleet.scan(roots, since, args.project, progress=not args.json and sys.stderr.isatty())

    if fleet.messages == 0 and fleet.bash_total == 0:
        print("agentfleet: no matching activity found.", file=sys.stderr)
        return 1

    if args.json:
        json.dump(to_json(fleet, raw=args.no_redact), sys.stdout, indent=2)
        print()
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
