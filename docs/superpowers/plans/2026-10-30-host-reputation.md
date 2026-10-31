# Host Reputation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tell the user when a host their coding agents reached is on Google Safe Browsing (checked offline against downloaded lists) or flagged by VirusTotal (optional, online), and let that fail a `--fail-on` gate, while `actualis` itself still never uses the network.

**Architecture:** `actualis.py` gains an offline section: Safe Browsing expressions and SHA-256 prefixes, a read-only loader for the reputation cache, a matcher that sets `item["reputation"]` and raises flags, and the `--reputation` flag, JSON fields, text and HTML output. Its import list does not change. A new single-file companion, `actualis_reputation.py` (console script `actualis-reputation`), is the only code that opens a socket. It writes the cache (`update`, `confirm`, `virustotal`), discloses, asks consent, shows a live indicator, writes a receipt and a network-use log, and imports `actualis` for shared paths and host rules. Data flows one way: the companion writes the cache, `actualis` reads it.

**Tech Stack:** Python 3.9+ standard library only (`urllib.request`, `ssl` in the companion; `hashlib`, `json`, `base64` in actualis). `unittest`. Go (tray badge). Mermaid in docs.

**Spec:** `docs/superpowers/specs/2026-10-30-host-reputation-design.md` (approved 2026-10-30). Executors read the spec and this plan.

## Global Constraints

- `actualis.py` imports stay exactly: `__future__, argparse, base64, collections, datetime, hashlib, html, json, os, pathlib, re, shutil, struct, subprocess, sys, time, typing, zlib` (`tests/test_ioc.py::test_imports_are_unchanged`). It never imports `actualis_reputation`.
- `JSON_SCHEMA` is additive only; `schema_version` stays 1. Every new emitted path is declared in `JSON_SCHEMA` in the same commit.
- Without `--reputation`, `actualis` behaves exactly as 0.4.0 (output bytes included, apart from the new always-present JSON keys).
- Severity strings in flags are `"high"` and `"med"` (not "medium"). Categories: `reputation-listed` (high), `reputation-candidate` (med), `reputation-suspicious` (med), `reputation-stale` (med).
- A Google result always carries `"Advisory provided by Google"` with the link `https://developers.google.com/safe-browsing/v4/advisory`; a VirusTotal result never does. Wording is hedged: "is currently listed … as suspected …".
- A local prefix hit alone is never "listed". Listed needs a confirmation less than 30 minutes old (`REPUTATION_CONFIRM_TTL = 1800`) and within its `cache_until`. Lists older than 7 days (`REPUTATION_STALE_DAYS = 7`) raise `reputation-stale`.
- Lists: `mw-4b`, `se-4b`, `uws-4b`, `uwsa-4b`, `pha-4b`. Hosts: `safebrowsing.googleapis.com`, `www.virustotal.com`. Nothing else is ever contacted.
- Cache: `$ACTUALIS_REPUTATION_DIR`, else `%LOCALAPPDATA%\actualis\reputation` on Windows, else `${XDG_CACHE_HOME:-~/.cache}/actualis/reputation`. Directories 0700, files 0600, atomic writes, never through a symlink.
- Keys: `ACTUALIS_GSB_KEY`, `ACTUALIS_VT_KEY`, or `--key-command CMD` (run without a shell). Never an argument value; never printed, logged, cached or put in a receipt.
- The mark is `⊕🌐` (`NET_MARK = "⊕\U0001F310"`); ASCII fallback `[+net]`. It appears only on lines that report network use.
- Companion exit codes: 0 done, 1 runtime error (network, quota, bad response), 2 usage error (no key, refused combination, no consent without a terminal). `actualis` keeps its codes (3 = findings).
- Tests are hermetic: synthetic hosts only (`*.example`), a temp HOME and cache dir, and no socket to anything but loopback. Never read real transcripts. Never commit a real key.
- Every commit message ends with `Refs #67` (Task 0) and the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Run the whole suite with `python3 -m unittest discover -s tests` before every commit that touches `actualis.py`.

## Decisions this plan makes beyond the spec

Each was ruled to keep the spec's intent with less risk; the docs task records the user-visible ones.

1. **Safe Browsing key goes in the `X-Goog-Api-Key` header**, not the query string, so it never sits in a URL (proxy logs, exception text). The scrubber still runs everywhere.
2. **Prefix files are named by checksum** (`gsb/<list>.<sha256[:16]>.prefixes`), and `state.json` is written last as the commit point. A crash mid-update leaves the old, consistent set. Spec §4 named them `<list>.prefixes`.
3. **No query-string expressions.** Path expressions drop `?…` and `#…`, so nothing derived from a query string is hashed or sent.
4. **Consent is asked on every terminal run**, not only the first per provider. Stricter than spec §6.3; needs no stored consent state.
5. **Companion tests use a fake provider server over plain HTTP** on 127.0.0.1, injected through `Http(endpoints=…, scheme="http")`. The CLI and environment cannot set either. One extra test, run only when `openssl` is on PATH, proves certificate verification refuses an untrusted certificate. This avoids committing a private key, which gitleaks would flag.
6. **VirusTotal "suspicious"** covers `1 <= malicious < threshold` or `suspicious >= 1`. Under spec §5.2 a single engine's "malicious" would otherwise be silent.
7. **VirusTotal results older than 7 days are ignored**, and the threshold is stored in `vt/results.json` (written from `--vt-threshold`), so `actualis` needs no new flag.
8. **`network.items[].reputation.state` adds `skipped`** (private or local host) **and `suspicious`** to the spec's four values. `advisory` is null for non-Google results, not absent, which keeps the schema stable.
9. **`--dry-run` reads no key**, so `--key-command` is not run.
10. **A `state.json` missing any of the five lists counts as corrupt.**
11. **`network-log.jsonl` gets a line only when at least one request was attempted.**
12. **The tray badge reads `in-flight.json`** (`{pid, provider, started_at}`). The companion writes it while a networked command runs and removes it in `finally`.
13. **`argparse` has `allow_abbrev=False`** (so `--key` cannot abbreviate `--key-command` and run a pasted key as a command). An "unrecognized arguments" error never echoes the arguments, because one may be a key.
14. **`--reputation --fail-on` with absent or corrupt lists exits 2 before scanning**, with the one-line message from spec §5.2.
15. **The work is tracked by a public issue in `digital-foundry/actualis`.** The spec already lives in this public repo, and CLAUDE.md requires an issue in the repo being changed. The issue text describes the shipped feature only, no roadmap.

## Review Focus

The five inputs or failure modes most likely to bite a user that no feature test naturally exercises. Each has a pinned test in the owning task, listed in brackets.

1. **A key typed as an argument** (`--key AIza…`, or `--key-command` given a key): it must not run as a command, and the value must not be echoed in the argparse error. [Task 5, `test_key_like_argument_is_not_echoed_or_run`]
2. **A tampered or half-written cache** (checksum mismatch, a symlinked file, a `state.json` naming a missing file, a future-dated confirmation): it must never clear a host. It reads as corrupt (exit 2 under `--fail-on`) or falls back to candidate. [Task 2, `test_corrupt_*`; Task 3, `test_future_confirmation_is_not_fresh`]
3. **The key leaking through an error path** (connection refused, HTTP 403 body echoing the request, a `--key-command` that fails, Ctrl-C mid-request): the key appears in no stdout, stderr, receipt, log or exception text. [Task 6, `test_key_never_appears_anywhere`]
4. **CI without a terminal and without `--yes`**: exit 2, zero requests, a clear message. [Task 5, `test_no_terminal_no_yes_sends_nothing`]
5. **Private hosts** (`10.x`, `192.168.x`, `*.local`, `*.internal`, a single-label `intranet`, `localhost`): never hashed into candidates, never sent to VirusTotal, counted as skipped. [Task 1, `test_private_hosts_are_skipped`; Task 8, `test_private_hosts_never_sent`]

---

## File Structure

| File | Responsibility |
|---|---|
| `actualis.py` (modify) | New section "Host reputation (offline)" after `ioc_json` (around line 7530): constants, `reputation_skip`, `sb_expressions`, `reputation_dir`, `ReputationData`, `load_reputation`, `reputation_last_network`, `gsb_verdict`, `vt_verdict`, `apply_reputation`, `reputation_json`, `render_reputation`. Plus small edits in `NETWORK_ITEM_KEYS`, `Fleet.__init__`, `network_json`, `failing_findings`, `JSON_SCHEMA`, `_GLYPH_FALLBACK`, `render_network`, `render_network_html`, `self_check`, `build_parser`, `main`. |
| `actualis_reputation.py` (create) | The companion: CLI, keys and scrubber, cache writer, disclosure and consent, `NetSession` (indicator, receipt, log, tray marker), `Http`, `rice_decode`, `update`, `confirm`, `virustotal`, `status`, `forget`. |
| `tests/_reputation.py` (create) | Synthetic cache writer and fake provider server, shared by the reputation tests. |
| `tests/_fixtures.py` (modify) | Isolates `XDG_CACHE_HOME`, `ACTUALIS_REPUTATION_DIR` and `LOCALAPPDATA`; blocks sockets to anything but loopback. |
| `tests/test_reputation_match.py` (create) | actualis side: expressions, loader, matcher, flags, gate (Tasks 1 to 3). |
| `tests/test_reputation_cli.py` (create) | actualis side: `--reputation` CLI, JSON, text, HTML, self-check (Task 4). |
| `tests/test_reputation_companion.py` (create) | Companion core, `update`, `confirm`, `virustotal` (Tasks 5 to 8). |
| `pyproject.toml`, `.github/workflows/test.yml`, `tools/brew-formula.py`, `tools/security/run.sh` (modify) | Packaging, the companion's own import allowlist, the Homebrew formula, bandit over both files. |
| `tray-go/main.go`, `tray-go/netuse_unix.go`, `tray-go/netuse_windows.go`, `tray-go/netuse_test.go`, `tray-go/icons/gen_icons.py`, `tray-go/icons/network-{dark,light}.png` | Tray badge while the companion uses the network. |
| `README.md`, `docs/reputation.md` (create), `docs/json.md`, `docs/findings.md`, `docs/img/reputation-badge.svg` (create), `CHANGELOG.md` | Docs, diagrams, attribution, the reworded "no network" claim. |

---

### Task 0: Issue, worktree, hermetic test isolation

**Files:**
- Modify: `tests/_fixtures.py` (the `AGENT_VARS` tuple near line 24 and the `audit` hook near line 88)
- Test: `tests/test_reputation_match.py` (create; first test only)

**Interfaces:**
- Produces: issue number `N` (used in branch, commits, PR); worktree `../actualis-wt/N-host-reputation`; a test process in which `XDG_CACHE_HOME`, `ACTUALIS_REPUTATION_DIR`, `LOCALAPPDATA` point inside the temp home, and any `socket.connect`/`socket.getaddrinfo` to a non-loopback host raises `PermissionError`.

- [ ] **Step 1: Create the issue** (search first: `gh issue list -R digital-foundry/actualis --search "reputation" --state all`)

```bash
gh issue create -R digital-foundry/actualis --title "Optional host reputation: Safe Browsing (offline lists) and VirusTotal" --label enhancement --body "$(cat <<'EOF'
What: an optional `actualis-reputation` companion command that downloads Google Safe Browsing threat lists (and, if asked, queries VirusTotal), plus `actualis --reputation`, which checks the network inventory against those local files offline.

Why: tell users when a host their coding agents reached is currently on a reputation list, and let `--fail-on` gate on it, without actualis itself ever using the network.

Done when: spec docs/superpowers/specs/2026-10-30-host-reputation-design.md is implemented, tests pass on all CI platforms, README and docs/reputation.md document setup, and a manual run with a real key succeeds.
EOF
)"
```

If the `enhancement` label does not exist, drop `--label`. Record the number as `N`.

- [ ] **Step 2: Create the worktree from the spec branch, rename the branch, return the main checkout to main**

```bash
cd /Users/aaron/Documents/github/digital_foundry/actualis
git switch main && git pull --ff-only
git worktree add ../actualis-wt/N-host-reputation -b N-host-reputation feat/host-reputation
git branch -D feat/host-reputation      # its two commits (spec, plan) now live on N-host-reputation
cd ../actualis-wt/N-host-reputation
```

All later tasks run in this worktree.

- [ ] **Step 3: Write the failing isolation test** in `tests/test_reputation_match.py`

```python
"""Host reputation, actualis side: expressions, the cache loader, the matcher,
flags and the gate. Every host is invented; the cache is written by
tests/_reputation.py into the temp home."""
from __future__ import annotations

import os
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_X import af  # noqa: E402


class TestIsolation(unittest.TestCase):
    def test_cache_dirs_are_inside_the_temp_home(self):
        for var in ("XDG_CACHE_HOME", "ACTUALIS_REPUTATION_DIR", "LOCALAPPDATA"):
            self.assertTrue(os.environ[var].startswith(_fixtures.TEMP_HOME), var)
        self.assertTrue(str(af.reputation_dir()).startswith(_fixtures.TEMP_HOME))

    def test_no_socket_leaves_the_machine(self):
        with self.assertRaises(PermissionError):
            socket.getaddrinfo("safebrowsing.googleapis.com", 443)
        with self.assertRaises(PermissionError):
            socket.create_connection(("192.0.2.1", 443), timeout=1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run it to verify it fails**

Run: `python3 -m unittest tests.test_reputation_match -v`
Expected: FAIL. `KeyError: 'XDG_CACHE_HOME'` or `AttributeError: … no attribute 'reputation_dir'`, and the socket test does not raise.

- [ ] **Step 5: Extend `_fixtures.py`**

Add the three variables to `AGENT_VARS`, which sets each one inside the temp home:

```python
AGENT_VARS = ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME",
              "QWEN_HOME", "QWEN_RUNTIME_DIR", "XDG_CONFIG_HOME",
              "XDG_CACHE_HOME", "ACTUALIS_REPUTATION_DIR", "LOCALAPPDATA")
```

Read how `_isolate_process` assigns `AGENT_VARS` and follow it exactly. If it maps each name to a directory under `TEMP_HOME`, these three join that mapping. `ACTUALIS_REPUTATION_DIR` should be `TEMP_HOME/.cache/actualis/reputation`.

Then, inside `audit(event, args)`, before the existing `open`/`listdir` filter, add:

```python
        if event == "socket.getaddrinfo" and args:
            if str(args[0]).lower() not in _LOOPBACK:
                raise PermissionError(f"test isolation: DNS lookup of {args[0]}")
            return
        if event == "socket.connect" and len(args) > 1:
            addr = args[1]
            host = addr[0] if isinstance(addr, tuple) and addr else addr
            if isinstance(host, str) and host.lower() not in _LOOPBACK:
                raise PermissionError(f"test isolation: connect to {host}")
            return
```

At module level:

```python
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0"})
```

The Go and `subprocess` tests are separate processes and unaffected. A test that runs `actualis.py` in a subprocess imports no socket module.

`reputation_dir()` does not exist yet. Add the minimal version now, so the first test can pass; Task 2 adds its tests. Put it in a new section after `ioc_json` in `actualis.py`:

```python
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
```

- [ ] **Step 6: Run the test, then the full suite**

Run: `python3 -m unittest tests.test_reputation_match -v && python3 -m unittest discover -s tests`
Expected: PASS, and no existing test fails. If an existing test does a real DNS lookup, it was already non-hermetic: report it rather than weakening the guard.

- [ ] **Step 7: Commit**

```bash
git add tests/_fixtures.py tests/test_reputation_match.py actualis.py
git commit -m "Tests: isolate the reputation cache and block non-loopback sockets

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: Safe Browsing expressions and private-host skipping (actualis.py)

**Files:**
- Modify: `actualis.py` (the reputation section from Task 0)
- Test: `tests/test_reputation_match.py`

**Interfaces:**
- Consumes: `_host_canon(host) -> str | None` (line ~2660), `_local_host(host) -> bool` (line ~13106), `_NET_PCT` (bytes regex `%XX`).
- Produces:
  - `NET_MARK: str = "⊕\U0001F310"`
  - `REPUTATION_LISTS: tuple[str, ...]`, `REPUTATION_THREAT: dict[str, str]`, `REPUTATION_CONFIRM_TTL = 1800`, `REPUTATION_STALE_DAYS = 7`, `GSB_ADVISORY: str`, `GSB_ADVISORY_URL: str`
  - `reputation_skip(host: str) -> bool`
  - `sb_expressions(host: str, path: str = "") -> list[str]` (host already canonical, as inventory items carry it)
  - `sb_hash(expr: str) -> bytes` (32-byte SHA-256)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_reputation_match.py`)

```python
import hashlib  # noqa: E402  (add to the imports at the top instead)


class TestExpressions(unittest.TestCase):
    def test_google_rice_example_hashes(self):
        # The three expressions of Google's Local Database worked example.
        self.assertEqual(af.sb_hash("a.example.com/")[:4].hex(), "291bc542")
        self.assertEqual(af.sb_hash("b.example.com/")[:4].hex(), "1d32c508")
        self.assertEqual(af.sb_hash("y.example.com/")[:4].hex(), "f7a502e5")

    def test_host_suffixes_last_five_labels_never_tld(self):
        self.assertEqual(af.sb_expressions("a.b.c.d.e.f.g"),
                         ["a.b.c.d.e.f.g/", "c.d.e.f.g/", "d.e.f.g/", "e.f.g/", "f.g/"])
        self.assertEqual(af.sb_expressions("evil.example"), ["evil.example/"])
        self.assertEqual(af.sb_expressions("x.evil.example"), ["x.evil.example/", "evil.example/"])

    def test_ip_has_only_itself(self):
        self.assertEqual(af.sb_expressions("8.8.8.8"), ["8.8.8.8/"])

    def test_paths_exact_then_prefixes_no_query(self):
        self.assertEqual(af.sb_expressions("a.b.example", "/1/2.html?param=1#frag"),
                         ["a.b.example/1/2.html", "a.b.example/", "a.b.example/1/",
                          "b.example/1/2.html", "b.example/", "b.example/1/"])

    def test_path_prefixes_capped_at_four_from_root(self):
        exprs = af.sb_expressions("h.example", "/1/2/3/4/5/6.html")
        self.assertEqual(exprs, ["h.example/1/2/3/4/5/6.html", "h.example/", "h.example/1/",
                                 "h.example/1/2/", "h.example/1/2/3/"])

    def test_path_canonicalisation(self):
        self.assertEqual(af.sb_expressions("h.example", "/a/./b/../c//d")[0], "h.example/a/c/d")
        self.assertEqual(af.sb_expressions("h.example", "/%2541%2542")[0], "h.example/AB")
        self.assertEqual(af.sb_expressions("h.example", "/a b")[0], "h.example/a%20b")

    def test_private_hosts_are_skipped(self):
        for h in ("localhost", "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.1.1",
                  "printer.local", "app.localhost", "db.internal", "intranet", "[::1]", "[2001:db8::1]"):
            self.assertTrue(af.reputation_skip(h), h)
        for h in ("evil.example", "8.8.8.8", "registry.npmjs.org"):
            self.assertFalse(af.reputation_skip(h), h)

    def test_mark_falls_back_to_ascii(self):
        self.assertEqual(af.NET_MARK.translate(af._GLYPH_TABLE), "[+net]")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest tests.test_reputation_match.TestExpressions -v`
Expected: FAIL with `AttributeError: module 'actualis' has no attribute 'sb_hash'`.

- [ ] **Step 3: Implement** (in the reputation section, below `reputation_dir`)

```python
NET_MARK = "⊕\U0001F310"            # ⊕🌐: on every line that reports network use, nowhere else
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
    if h.endswith((".internal", ".home.arpa", ".lan")):
        return True
    return _local_host(h)


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
```

Add the fallback glyphs to the existing `_GLYPH_FALLBACK` dict (near line 13030), before `_GLYPH_TABLE` is built:

```python
    "⊕": "[+", "\U0001F310": "net]",     # NET_MARK -> [+net]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_reputation_match -v`
Expected: PASS. If `test_paths_exact_then_prefixes_no_query` fails on order, the expected order is per host: the exact path first, then `/`, then the deeper prefixes.

- [ ] **Step 5: Full suite and commit**

```bash
python3 -m unittest discover -s tests
git add actualis.py tests/test_reputation_match.py
git commit -m "Reputation: Safe Browsing expressions and private-host skipping

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Read-only cache loader (actualis.py) and the test cache writer

**Files:**
- Create: `tests/_reputation.py`
- Modify: `actualis.py` (reputation section)
- Test: `tests/test_reputation_match.py`

**Interfaces:**
- Consumes: `reputation_dir()`, `REPUTATION_LISTS`, `_open_regular(path, binary=True)`.
- Produces:
  - `class ReputationData` with attributes `status: str` (`"absent" | "corrupt" | "ok"`), `error: str | None`, `directory: Path | None`, `lists: dict[str, bytes]` (sorted 4-byte records), `state: dict[str, dict]` (per list: `fetched_at`, `next_update_at`, `prefix_count`, `version`), `oldest: datetime | None`, `confirmations: dict[bytes, dict]` (prefix -> `{"full_hashes": [{"hash": bytes, "threat_types": [str], "canary": bool}], "confirmed_at": datetime, "cache_until": datetime}`), `confirmations_error: str | None`, `vt: dict[str, dict]` (host -> `{"stats": dict, "status": "found"|"unknown", "checked_at": datetime}`), `vt_threshold: int`, `vt_error: str | None`, `last_network: dict | None` (`{"at": str, "provider": str}`)
  - `load_reputation(directory: Path | None = None) -> ReputationData` (never raises for bad files; raises `OSError` only when no directory can be resolved)
  - `reputation_last_network(directory: Path | None = None) -> dict | None`
  - `_parse_utc(text) -> datetime | None`
  - test helper `tests/_reputation.py`: `prefix(expr) -> bytes`, `full(expr) -> bytes`, `iso(dt) -> str`, `write_cache(root, lists=None, *, fetched_at=None, confirmations=(), vt=None, vt_threshold=2, log=()) -> Path`, `confirmation(prefix_expr, *, listed=(), threat="MALWARE", at=None, cache_s=300, canary=False) -> dict`

- [ ] **Step 1: Create `tests/_reputation.py`**

```python
"""Synthetic host-reputation caches and a fake provider server, for the tests.

Every host is invented (*.example). The cache layout is the one the companion
writes (docs/reputation.md): gsb/state.json names one checksum-named prefix
file per list, gsb/confirmations.json, vt/results.json, network-log.jsonl.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

LISTS = ("mw-4b", "se-4b", "uws-4b", "uwsa-4b", "pha-4b")


def full(expr: str) -> bytes:
    return hashlib.sha256(expr.encode()).digest()


def prefix(expr: str) -> bytes:
    return full(expr)[:4]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def write_cache(root: Path, lists: dict | None = None, *, fetched_at: datetime | None = None,
                confirmations=(), vt: list | None = None, vt_threshold: int = 2, log=()) -> Path:
    """lists: {list name: [4-byte prefixes]}; every list in LISTS is written."""
    gsb = root / "gsb"
    gsb.mkdir(parents=True, exist_ok=True)
    fetched_at = fetched_at or datetime.now(timezone.utc)
    entries = []
    for name in LISTS:
        blob = b"".join(sorted(set((lists or {}).get(name, []))))
        sha = hashlib.sha256(blob).hexdigest()
        fname = f"{name}.{sha[:16]}.prefixes"
        (gsb / fname).write_bytes(blob)
        entries.append({"name": name, "version": b64(name.encode()), "sha256": sha, "file": fname,
                        "fetched_at": iso(fetched_at),
                        "next_update_at": iso(fetched_at + timedelta(minutes=30)),
                        "prefix_count": len(blob) // 4})
    (gsb / "state.json").write_text(json.dumps({"schema": 1, "lists": entries}))
    if confirmations:
        (gsb / "confirmations.json").write_text(json.dumps({"schema": 1, "entries": list(confirmations)}))
    if vt is not None:
        (root / "vt").mkdir(exist_ok=True)
        (root / "vt" / "results.json").write_text(json.dumps(
            {"schema": 1, "vt_threshold": vt_threshold, "daily": {"date": "", "count": 0}, "results": vt}))
    if log:
        (root / "network-log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in log))
    return root


def confirmation(prefix_expr: str, *, listed=(), threat: str = "MALWARE", at: datetime | None = None,
                 cache_s: int = 300, canary: bool = False) -> dict:
    """A confirmations.json entry for the prefix of `prefix_expr`. `listed`:
    expressions whose full hashes the provider returned for it."""
    at = at or datetime.now(timezone.utc)
    return {"prefix": b64(prefix(prefix_expr)),
            "full_hashes": [{"hash": b64(full(e)), "threat_types": [] if canary else [threat],
                             "canary": canary} for e in listed],
            "confirmed_at": iso(at), "cache_until": iso(at + timedelta(seconds=cache_s))}


def vt_result(host: str, malicious: int = 0, suspicious: int = 0, *, status: str = "found",
              at: datetime | None = None) -> dict:
    return {"host": host, "status": status, "checked_at": iso(at or datetime.now(timezone.utc)),
            "stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 50,
                      "undetected": 20, "timeout": 0}}
```

- [ ] **Step 2: Write the failing loader tests** (append to `tests/test_reputation_match.py`)

```python
import json  # noqa: E402  (move to the top imports)
import tempfile  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import _reputation as R  # noqa: E402


class CacheCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=_fixtures.TEMP_HOME)
        self.root = Path(self._tmp.name) / "rep"

    def tearDown(self):
        self._tmp.cleanup()


class TestLoader(CacheCase):
    def test_absent(self):
        d = af.load_reputation(self.root)
        self.assertEqual((d.status, d.lists), ("absent", {}))

    def test_ok_reads_all_lists(self):
        R.write_cache(self.root, {"mw-4b": [R.prefix("evil.example/")]})
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "ok", d.error)
        self.assertEqual(set(d.lists), set(af.REPUTATION_LISTS))
        self.assertEqual(d.lists["mw-4b"], R.prefix("evil.example/"))
        self.assertIsNotNone(d.oldest)

    def test_corrupt_checksum(self):
        R.write_cache(self.root, {"mw-4b": [R.prefix("evil.example/")]})
        f = next((self.root / "gsb").glob("mw-4b.*.prefixes"))
        f.write_bytes(b"\x00\x00\x00\x01")
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("mw-4b", d.error)

    def test_corrupt_missing_list(self):
        R.write_cache(self.root)
        state = json.loads((self.root / "gsb" / "state.json").read_text())
        state["lists"] = state["lists"][1:]
        (self.root / "gsb" / "state.json").write_text(json.dumps(state))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    def test_corrupt_not_json_or_wrong_schema(self):
        R.write_cache(self.root)
        (self.root / "gsb" / "state.json").write_text("{nope")
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")
        (self.root / "gsb" / "state.json").write_text(json.dumps({"schema": 2, "lists": []}))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    def test_corrupt_file_name_escapes_the_directory(self):
        R.write_cache(self.root)
        state = json.loads((self.root / "gsb" / "state.json").read_text())
        state["lists"][0]["file"] = "../../etc/passwd"
        (self.root / "gsb" / "state.json").write_text(json.dumps(state))
        self.assertEqual(af.load_reputation(self.root).status, "corrupt")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_corrupt_symlinked_file(self):
        R.write_cache(self.root)
        f = next((self.root / "gsb").glob("se-4b.*.prefixes"))
        real = self.root / "elsewhere"
        real.write_bytes(f.read_bytes())
        f.unlink()
        f.symlink_to(real)
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "corrupt")
        self.assertIn("symlink", d.error)

    def test_bad_confirmations_are_ignored_not_fatal(self):
        R.write_cache(self.root)
        (self.root / "gsb" / "confirmations.json").write_text("[1,2")
        d = af.load_reputation(self.root)
        self.assertEqual((d.status, d.confirmations), ("ok", {}))
        self.assertIsNotNone(d.confirmations_error)

    def test_vt_and_threshold(self):
        R.write_cache(self.root, vt=[R.vt_result("evil.example", 5)], vt_threshold=3)
        d = af.load_reputation(self.root)
        self.assertEqual(d.vt_threshold, 3)
        self.assertEqual(d.vt["evil.example"]["stats"]["malicious"], 5)

    def test_last_network_reads_the_newest_valid_line(self):
        R.write_cache(self.root, log=[{"at": "2026-10-30T14:02:00+00:00", "provider": "gsb"},
                                      {"at": "2026-10-30T15:00:00+00:00", "provider": "vt"}])
        with open(self.root / "network-log.jsonl", "a") as fh:
            fh.write("{broken\n")
        self.assertEqual(af.reputation_last_network(self.root),
                         {"at": "2026-10-30T15:00:00+00:00", "provider": "vt"})
        self.assertIsNone(af.reputation_last_network(self.root / "nope"))
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_match.TestLoader -v`
Expected: FAIL with `AttributeError: … 'load_reputation'`.

- [ ] **Step 4: Implement the loader** (reputation section of `actualis.py`)

```python
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


def load_reputation(directory: "Path | None" = None) -> ReputationData:
    """Read the cache, read-only. A bad list makes the whole set corrupt; bad
    confirmations or VirusTotal files are ignored with a note (ignoring them
    can only leave a host a candidate, never clear it)."""
    root = directory or reputation_dir()
    data = ReputationData(root)
    data.last_network = reputation_last_network(root)
    try:                                     # first: VirusTotal results count even with no Safe Browsing lists
        _load_vt(root / "vt" / "results.json", data)
    except (OSError, ValueError) as exc:
        data.vt, data.vt_error = {}, str(exc)
    gsb = root / "gsb"
    try:
        raw = _read_cache_file(gsb / "state.json")
        if raw is None:
            return data
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("lists"), list):
            raise ValueError("state.json is not schema 1")
        by_name = {e.get("name"): e for e in doc["lists"] if isinstance(e, dict)}
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
            data.lists[name] = blob
            data.state[name] = {"fetched_at": fetched, "next_update_at": _parse_utc(e.get("next_update_at")),
                                "prefix_count": count, "version": e.get("version")}
            data.oldest = fetched if data.oldest is None else min(data.oldest, fetched)
    except (OSError, ValueError) as exc:     # json.JSONDecodeError is a ValueError
        data.status, data.error, data.lists, data.state = "corrupt", str(exc), {}, {}
        return data
    data.status = "ok"
    try:
        data.confirmations = _load_confirmations(gsb / "confirmations.json")
    except (OSError, ValueError) as exc:
        data.confirmations_error = str(exc)
    return data
```

If the list files are sorted ascending (the writer guarantees it), the matcher's binary search is valid. Add a sortedness check per list for safety:

```python
            if any(blob[i:i + 4] > blob[i + 4:i + 8] for i in range(0, len(blob) - 4, 4)):
                raise ValueError(f"{name}: prefixes are not sorted")
```

Place it right after the checksum check. The check is O(n), about 0.2 s for a million prefixes, which is acceptable once per run. If the timing test budget complains, check only when `count < 2_000_000`.

VirusTotal-only users (no Safe Browsing lists): `status` stays `"absent"`, but the VT file is still loaded, because `_load_vt` runs before the `state.json` read.

- [ ] **Step 5: Run tests**

Run: `python3 -m unittest tests.test_reputation_match -v`
Expected: PASS.

- [ ] **Step 6: Full suite and commit**

```bash
python3 -m unittest discover -s tests
git add actualis.py tests/_reputation.py tests/test_reputation_match.py
git commit -m "Reputation: read-only cache loader, fail closed on a bad list

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Matcher, flags and the gate (actualis.py)

**Files:**
- Modify: `actualis.py`: reputation section; `NETWORK_ITEM_KEYS` (line ~6093); `Fleet.__init__` (next to `self.ioc` at line ~8518); `failing_findings` (line ~15412)
- Test: `tests/test_reputation_match.py`

**Interfaces:**
- Consumes: `ReputationData`, `sb_expressions`, `sb_hash`, `reputation_skip`, `url_path(url) -> str`, `flag_id(severity, categories, program) -> str`, `redact`, `clean`, `_net_utc_key`.
- Produces:
  - `gsb_verdict(host: str, path: str, data: ReputationData, now: datetime) -> dict` with keys `state` (`"none"|"candidate"|"listed"|"not-listed"`), `threat_types: list[str]`, `checked_at: datetime | None`, `candidates: dict[bytes, int]` (unconfirmed prefix -> number of expressions with it)
  - `vt_verdict(host: str, data: ReputationData, now: datetime) -> dict | None` with keys `state` (`"listed"|"suspicious"|"not-listed"|"unknown"`), `malicious`, `suspicious`, `threshold`, `checked_at`
  - `apply_reputation(fleet: Fleet, data: ReputationData | None, now: datetime | None = None) -> None`. It sets `item["reputation"]` on every item (None when off) and fills `fleet.reputation`, `fleet.reputation_totals: dict[str, int]` (keys `checked, skipped, none, candidate, listed, not_listed, suspicious, unknown`) and `fleet.reputation_candidates: dict[bytes, int]`, then appends flags.
  - `REPUTATION_FLAG_CATEGORIES = ("reputation-listed", "reputation-candidate", "reputation-suspicious", "reputation-stale")`

- [ ] **Step 1: Write the failing tests**

```python
NOW = datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc)


def rep_fleet(*commands):
    f = af.Fleet()
    f.suppressions = {}
    ts = NOW - timedelta(days=1)
    for k, c in enumerate(commands):
        f.add_tool("proj", "Bash", {"command": c}, ts, "auto", call_id=f"t{k}")
    return f


class TestMatcher(CacheCase):
    def data(self, **kw):
        R.write_cache(self.root, fetched_at=kw.pop("fetched_at", NOW - timedelta(hours=3)), **kw)
        d = af.load_reputation(self.root)
        self.assertEqual(d.status, "ok", d.error)
        return d

    def test_none(self):
        v = af.gsb_verdict("fine.example", "", self.data(), NOW)
        self.assertEqual(v["state"], "none")

    def test_candidate_without_confirmation(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]})
        v = af.gsb_verdict("evil.example", "", d, NOW)
        self.assertEqual(v["state"], "candidate")
        self.assertEqual(v["candidates"], {R.prefix("evil.example/"): 1})

    def test_subdomain_matches_listed_parent(self):
        d = self.data(lists={"se-4b": [R.prefix("evil.example/")]})
        self.assertEqual(af.gsb_verdict("cdn.evil.example", "", d, NOW)["state"], "candidate")

    def test_listed_with_fresh_matching_full_hash(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                    at=NOW - timedelta(minutes=29))])
        v = af.gsb_verdict("evil.example", "", d, NOW)
        self.assertEqual((v["state"], v["threat_types"]), ("listed", ["MALWARE"]))

    def test_confirmation_31_minutes_old_is_candidate(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                    at=NOW - timedelta(minutes=31), cache_s=3600)])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "candidate")

    def test_past_cache_until_is_candidate(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                    at=NOW - timedelta(minutes=10), cache_s=60)])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "candidate")

    def test_future_confirmation_is_not_fresh(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                    at=NOW + timedelta(hours=2))])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "candidate")

    def test_not_listed_when_fresh_confirmation_has_no_matching_hash(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["other.example/"],
                                                    at=NOW - timedelta(minutes=5))])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "not-listed")

    def test_confirmation_without_local_prefix_creates_nothing(self):
        d = self.data(confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                    at=NOW - timedelta(minutes=5))])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "none")

    def test_canary_only_is_not_listed(self):
        d = self.data(lists={"mw-4b": [R.prefix("evil.example/")]},
                      confirmations=[R.confirmation("evil.example/", listed=["evil.example/"], canary=True,
                                                    at=NOW - timedelta(minutes=5))])
        self.assertEqual(af.gsb_verdict("evil.example", "", d, NOW)["state"], "not-listed")

    def test_vt_threshold_and_suspicious(self):
        d = self.data(vt=[R.vt_result("bad.example", 3), R.vt_result("meh.example", 1),
                          R.vt_result("sus.example", 0, 2), R.vt_result("new.example", status="unknown"),
                          R.vt_result("old.example", 9, at=NOW - timedelta(days=8))], vt_threshold=2)
        self.assertEqual(af.vt_verdict("bad.example", d, NOW)["state"], "listed")
        self.assertEqual(af.vt_verdict("meh.example", d, NOW)["state"], "suspicious")
        self.assertEqual(af.vt_verdict("sus.example", d, NOW)["state"], "suspicious")
        self.assertEqual(af.vt_verdict("new.example", d, NOW)["state"], "unknown")
        self.assertIsNone(af.vt_verdict("old.example", d, NOW))
        self.assertIsNone(af.vt_verdict("none.example", d, NOW))


class TestApply(CacheCase):
    def run_apply(self, fleet, **kw):
        R.write_cache(self.root, fetched_at=kw.pop("fetched_at", NOW - timedelta(hours=3)), **kw)
        af.apply_reputation(fleet, af.load_reputation(self.root), NOW)
        return fleet

    def cats(self, fleet):
        return sorted(c for f in fleet.flags for c in f["categories"] if c.startswith("reputation-"))

    def test_off_sets_none(self):
        f = rep_fleet("curl https://evil.example/x")
        af.apply_reputation(f, None, NOW)
        self.assertIsNone(f.network[0]["reputation"])
        self.assertEqual(self.cats(f), [])

    def test_listed_is_one_high_flag_per_host_with_advisory(self):
        f = self.run_apply(rep_fleet("curl https://evil.example/a", "curl https://evil.example/b"),
                           lists={"mw-4b": [R.prefix("evil.example/")]},
                           confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                         at=NOW - timedelta(minutes=5))])
        flags = [x for x in f.flags if "reputation-listed" in x["categories"]]
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["severity"], "high")
        self.assertIn("currently listed by Google Safe Browsing as suspected malware", flags[0]["evidence"])
        self.assertIn("Advisory provided by Google", flags[0]["evidence"])
        rep = f.network[0]["reputation"]
        self.assertEqual((rep["state"], rep["provider"], rep["advisory"]),
                         ("listed", "google-safe-browsing", "Advisory provided by Google"))
        self.assertEqual(f.reputation_totals["listed"], 2)

    def test_candidate_flag_and_candidates(self):
        f = self.run_apply(rep_fleet("curl https://evil.example/a"), lists={"se-4b": [R.prefix("evil.example/")]})
        self.assertEqual(self.cats(f), ["reputation-candidate"])
        self.assertEqual(f.reputation_candidates, {R.prefix("evil.example/"): 1})
        self.assertIn("actualis-reputation confirm", f.flags[-1]["evidence"])

    def test_private_hosts_are_skipped_and_counted(self):
        f = self.run_apply(rep_fleet("curl http://10.0.0.5/x", "curl http://printer.local/x"),
                           lists={"mw-4b": [R.prefix("10.0.0.5/")]})
        self.assertEqual(f.reputation_totals["skipped"], 2)
        self.assertEqual({i["reputation"]["state"] for i in f.network}, {"skipped"})
        self.assertEqual(f.reputation_candidates, {})

    def test_stale_lists_one_medium_flag(self):
        f = self.run_apply(rep_fleet("curl https://fine.example/"), fetched_at=NOW - timedelta(days=8))
        self.assertEqual(self.cats(f), ["reputation-stale"])

    def test_vt_listed_has_no_google_advisory(self):
        f = self.run_apply(rep_fleet("curl https://bad.example/"), vt=[R.vt_result("bad.example", 7)])
        flag = next(x for x in f.flags if "reputation-listed" in x["categories"])
        self.assertIn("flagged malicious by 7 VirusTotal engines", flag["evidence"])
        self.assertNotIn("Google", flag["evidence"])
        self.assertIsNone(f.network[0]["reputation"]["advisory"])

    def test_gate(self):
        f = self.run_apply(rep_fleet("curl https://evil.example/a", "curl https://odd.example/"),
                           lists={"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")]},
                           confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                         at=NOW - timedelta(minutes=5))])
        high = af.failing_findings(f, "high")
        self.assertTrue(any("currently on a reputation list" in r for r in high), high)
        self.assertFalse(any("unconfirmed" in r for r in high))
        self.assertTrue(any("unconfirmed or suspicious reputation" in r for r in af.failing_findings(f, "any")))
        self.assertFalse(any("high-severity shell command" in r for r in high))

    def test_refused_items_are_not_checked(self):
        f = rep_fleet("curl https://evil.example/a")
        f._network_outcome("claude:t0", refused=True)
        self.run_apply(f, lists={"mw-4b": [R.prefix("evil.example/")]})
        self.assertEqual(self.cats(f), [])
```

If `rep_fleet`'s `add_tool(..., call_id=...)` signature differs, copy the call shape from `TestJSONSchemaFreeze._populated` in `tests/test_actualis.py`, which uses `call_id="t-refused"` and `f._network_outcome("claude:t-refused", refused=True)`.

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_match.TestMatcher tests.test_reputation_match.TestApply -v`
Expected: FAIL with `AttributeError: … 'gsb_verdict'`.

- [ ] **Step 3: Implement**

In `NETWORK_ITEM_KEYS`, add `"reputation"` right after `"ioc"`. In `Fleet.__init__`, after the `self.ioc_totals` line:

```python
        self.reputation: "ReputationData | None" = None
        self.reputation_totals: dict = _reputation_zero_totals()
        self.reputation_candidates: dict[bytes, int] = {}
```

Reputation section:

```python
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
            grp = groups.setdefault(gk, {"items": [], "verdict": best[2], "google": google, "host": host})
            grp["items"].append(item)
    for (category, key), grp in sorted(groups.items()):
        items, v, host = grp["items"], grp["verdict"], grp["host"]
        latest = max(items, key=lambda i: (_net_utc_key(i["ts"]), i["project"]))
        n = f"{len(items)} download(s) via {latest['program']}"
        if category == "reputation-listed" and grp["google"]:
            what = " or ".join(REPUTATION_THREAT_TEXT.get(t, t.lower()) for t in v["threat_types"])
            evidence = (f"{host} is currently listed by Google Safe Browsing as suspected {what} "
                        f"(checked {_utc_hm(v['checked_at'])}); {n}. {GSB_ADVISORY}")
        elif category == "reputation-listed":
            evidence = (f"{host} flagged malicious by {v['malicious']} VirusTotal engines "
                        f"(checked {_utc_hm(v['checked_at'])}); {n}")
        elif category == "reputation-candidate":
            evidence = (f"possible match for {host} in Google Safe Browsing lists, not confirmed; "
                        f"run `actualis-reputation confirm`; {n}. {GSB_ADVISORY}")
        else:
            evidence = (f"{host}: {v['malicious']} malicious and {v['suspicious']} suspicious VirusTotal "
                        f"engines, below the threshold of {v['threshold']} (checked {_utc_hm(v['checked_at'])}); {n}")
        _reputation_flag(fleet, "high" if category == "reputation-listed" else "med", category, key,
                         latest, evidence)
    if data.oldest and now - data.oldest > timedelta(days=REPUTATION_STALE_DAYS):
        days = (now - data.oldest).days
        _reputation_flag(fleet, "med", "reputation-stale", "gsb-lists", None,
                         f"Google Safe Browsing lists are {days} days old and can miss new threats; "
                         f"run `actualis-reputation update`")


def _reputation_flag(fleet: "Fleet", severity: str, category: str, key: str, latest: "dict | None",
                     evidence: str) -> None:
    fid = flag_id(severity, [category], key)
    suppressed = fid in fleet.suppressions
    if suppressed:
        fleet.suppressed_flags += 1
    fleet.flags.append({
        "id": fid, "severity": severity, "categories": [category], "program": key,
        "project": latest["project"] if latest else "", "when": latest["ts"] if latest else None,
        "evidence": redact(clean(evidence))[:240], "had_secret": False, "suppressed": suppressed,
        "suppressed_reason": fleet.suppressions.get(fid, ""),
    })
```

If the stale flag's `"when": None` breaks a consumer of `fleet.flags` that expects a string, use `""`. Check how `bash.flags[].when` is declared in `JSON_SCHEMA` and follow it.

In `failing_findings`, after the IOC block:

```python
    rep = set(REPUTATION_FLAG_CATEGORIES)
    rep_listed = [f for f in fleet.actionable_flags if "reputation-listed" in f["categories"]]
    rep_med = [f for f in fleet.actionable_flags if rep & set(f["categories"]) - {"reputation-listed"}]
    if want_high and rep_listed:
        out.append(f"{len(rep_listed)} host(s) currently on a reputation list")
    if want_any and rep_med:
        out.append(f"{len(rep_med)} unconfirmed or suspicious reputation result(s), or stale lists")
```

Then exclude the reputation categories from the generic counts. In the `want_high` generic line, add `and not rep & set(f["categories"])`. In the `want_any` med filter, add the reputation categories to the excluded set:

```python
        fl = [f for f in fl if not ({"network-unasked", "network-ioc-unresolved"} | rep) & set(f["categories"])]
```

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_reputation_match -v`
Expected: PASS.

- [ ] **Step 5: Full suite and commit**

Run: `python3 -m unittest discover -s tests`. The schema freeze test will now fail: `network.items[].reputation` is emitted (as null) but not declared. Add one line to `JSON_SCHEMA`, next to `"network.items[].ioc"`, for this task only; Task 4 adds the rest:

```python
    "network.items[].reputation": "object|null",
```

```bash
git add actualis.py tests/test_reputation_match.py
git commit -m "Reputation: offline matcher, findings and --fail-on gate

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `--reputation` CLI, JSON, text, HTML and self-check (actualis.py)

**Files:**
- Modify: `actualis.py`: `build_parser` (Network group), `main` (the `--ioc` refusal blocks around line 17140, the load at line ~17455, after `apply_ioc` at line ~17552), `network_json`, `JSON_SCHEMA`, `render_network` (after both `render_ioc` calls), `render_network_html`, `self_check` (after check 1), the `EXIT_USAGE` comment, `tests/test_actualis.py::_populated`
- Test: `tests/test_reputation_cli.py` (create)

**Interfaces:**
- Consumes: everything from Tasks 1 to 3.
- Produces:
  - `reputation_json(fleet: Fleet) -> dict`, always an object, at `network.reputation`, with keys `enabled: bool`, `lists_status: str|null`, `provider_lists: {name: fetched_at str}`, `lists_age_hours: int|null`, `stale: bool`, `vt_results: int`, `totals: {checked, skipped, none, candidate, listed, not_listed, suspicious, unknown}`, `candidates: [{prefix_b64: str, expressions: int}]` (sorted by `prefix_b64`), `advisory: {text: str|null, url: str|null}`, `network_last_used: {at: str|null, provider: str|null}`
  - `render_reputation(fleet: Fleet, c: C) -> None`
  - The CLI: `actualis --network --reputation [--json|--html] [--fail-on L]`; `actualis --reputation --fail-on L` (full report). The companion's `confirm` reads `network.reputation.candidates[].prefix_b64`, and its `virustotal` reads `network.hosts[].host`, from either the `--network --json` object or the full `--json` payload's `network` key.

- [ ] **Step 1: Write the failing tests** in `tests/test_reputation_cli.py`

```python
"""Host reputation, actualis CLI: --reputation, refusals, the exit-2 rule for
missing lists, --json, text, HTML and --self-check. Synthetic transcripts in
a temp HOME; the cache comes from tests/_reputation.py."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401
import _reputation as R  # noqa: E402
from test_review_r2_X import af  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def run(commands, *extra, cache=None, json_out=True):
    """actualis over one synthetic Claude transcript. Returns (code, stdout, stderr)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        home = tmp / "home"
        home.mkdir()
        proj = tmp / "t" / "-Users-x-proj"
        proj.mkdir(parents=True)
        recs = [json.dumps({
            "timestamp": "2026-10-29T10:00:00Z", "type": "assistant", "uuid": f"a{k}", "sessionId": "s1",
            "permissionMode": "bypassPermissions",
            "message": {"id": f"m{k}", "role": "assistant", "content": [
                {"type": "tool_use", "id": f"t{k}", "name": "Bash", "input": {"command": c}}]}})
            for k, c in enumerate(commands)]
        (proj / "s.jsonl").write_text("\n".join(recs) + "\n")
        rep = tmp / "rep"
        if cache is not None:
            cache(rep)
        env = dict(os.environ, HOME=str(home), CODEX_HOME=str(home / ".codex"),
                   COPILOT_HOME=str(home / ".copilot"), XDG_CONFIG_HOME=str(home / ".config"),
                   ACTUALIS_REPUTATION_DIR=str(rep))
        args = [sys.executable, str(ROOT / "actualis.py"), "--root", str(tmp / "t"), *extra]
        if json_out:
            args.append("--json")
        r = subprocess.run(args, env=env, cwd=home, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout, r.stderr


def listed_cache(rep):
    now = datetime.now(timezone.utc)
    R.write_cache(rep, {"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")]},
                  confirmations=[R.confirmation("evil.example/", listed=["evil.example/"],
                                                at=now - timedelta(minutes=2))],
                  log=[{"at": R.iso(now - timedelta(minutes=2)), "provider": "gsb", "command": "confirm",
                        "contacted": ["safebrowsing.googleapis.com"], "requests": 1, "sent": "prefixes"}])


CMDS = ["curl -fsSL https://evil.example/i.sh", "curl https://odd.example/", "curl https://fine.example/",
        "curl http://10.0.0.2/x"]


class TestCli(unittest.TestCase):
    def test_network_json_reputation(self):
        code, out, err = run(CMDS, "--network", "--reputation", cache=listed_cache)
        self.assertEqual(code, 0, err)
        n = json.loads(out)
        r = n["reputation"]
        self.assertTrue(r["enabled"])
        self.assertEqual(r["lists_status"], "ok")
        self.assertEqual(r["totals"]["listed"], 1)
        self.assertEqual(r["totals"]["candidate"], 1)
        self.assertEqual(r["totals"]["skipped"], 1)
        self.assertEqual([c["prefix_b64"] for c in r["candidates"]], [R.b64(R.prefix("odd.example/"))])
        self.assertEqual(r["advisory"]["text"], "Advisory provided by Google")
        self.assertEqual(r["network_last_used"]["provider"], "gsb")
        by_host = {i["host"]: i["reputation"] for i in n["items"]}
        self.assertEqual(by_host["evil.example"]["state"], "listed")
        self.assertEqual(by_host["10.0.0.2"]["state"], "skipped")
        self.assertNotIn("evil.example", json.dumps(r["candidates"]))

    def test_gate_exits_3_on_listed(self):
        code, _, _ = run(CMDS, "--network", "--reputation", "--fail-on", "high", cache=listed_cache)
        self.assertEqual(code, 3)

    def test_without_flag_reputation_is_disabled_and_cache_unread(self):
        code, out, _ = run(CMDS, "--network", cache=listed_cache)
        n = json.loads(out)
        self.assertEqual(code, 0)
        self.assertFalse(n["reputation"]["enabled"])
        self.assertTrue(all(i["reputation"] is None for i in n["items"]))

    def test_missing_lists_with_fail_on_exits_2_before_scanning(self):
        code, out, err = run(CMDS, "--network", "--reputation", "--fail-on", "high")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("actualis-reputation update", err)

    def test_missing_lists_without_fail_on_warns_and_runs(self):
        code, out, err = run(CMDS, "--network", "--reputation")
        self.assertEqual(code, 0)
        self.assertIn("actualis-reputation update", err)
        self.assertEqual(json.loads(out)["reputation"]["lists_status"], "absent")

    def test_corrupt_lists_exit_2_under_fail_on(self):
        def corrupt(rep):
            listed_cache(rep)
            next((rep / "gsb").glob("mw-4b.*")).write_bytes(b"\0\0\0\0")
        code, _, err = run(CMDS, "--network", "--reputation", "--fail-on", "any", cache=corrupt)
        self.assertEqual(code, 2)
        self.assertIn("failed their check", err)

    def test_refused_combinations(self):
        for extra in (["--card"], ["--watch"], ["--mcp"], ["--self-check"], ["--agents"],
                      ["--coach"], ["--share"], ["--explain"]):
            code, _, err = run(CMDS, "--reputation", *extra, json_out=False)
            self.assertEqual(code, 2, (extra, err))
            self.assertIn("--reputation", err)

    def test_text_view_shows_list_age_listed_host_and_advisory(self):
        code, out, err = run(CMDS, "--network", "--reputation", cache=listed_cache, json_out=False)
        self.assertEqual(code, 0, err)
        self.assertIn("reputation: Google Safe Browsing lists from", out)
        self.assertIn("evil.example", out)
        self.assertIn("Advisory provided by Google", out)
        self.assertNotIn("⊕", out)          # the mark is for network use, never for a match

    def test_html_carries_the_advisory(self):
        with tempfile.TemporaryDirectory() as out_dir:
            code, out, err = run(CMDS, "--network", "--reputation", "--html", "--out", out_dir,
                                 cache=listed_cache, json_out=False)
            self.assertEqual(code, 0, err)
            page = Path(out.strip()).read_text()
        self.assertIn("Advisory provided by Google", page)
        self.assertIn(af.GSB_ADVISORY_URL, page)


class TestSelfCheck(unittest.TestCase):
    def test_reports_network_use(self):
        with tempfile.TemporaryDirectory() as d:
            rep = Path(d) / "rep"
            listed_cache(rep)
            empty = Path(d) / "t"
            empty.mkdir()
            env = dict(os.environ, ACTUALIS_REPUTATION_DIR=str(rep))
            r = subprocess.run([sys.executable, str(ROOT / "actualis.py"), "--self-check", "--root", str(empty)],
                               env=env, capture_output=True, text=True, timeout=120)
        self.assertIn("actualis never uses it", r.stdout)
        self.assertIn("actualis-reputation last used it", r.stdout)
        self.assertIn("Google Safe Browsing", r.stdout)

    def test_never_imports_the_companion(self):
        src = (ROOT / "actualis.py").read_text(encoding="utf-8")
        self.assertNotIn("actualis_reputation", af.imports_in(src))


if __name__ == "__main__":
    unittest.main()
```

If `--self-check` with an empty root exits non-zero or prints a skip for the corpus, that is fine. The test checks only the network line.

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_cli -v`
Expected: FAIL. `unrecognized arguments: --reputation`.

- [ ] **Step 3: Implement the parser and main wiring**

In `build_parser`, Network group, after `--ioc`:

```python
    net.add_argument("--reputation", action="store_true",
                     help="match the network inventory against the local host-reputation cache that "
                          "actualis-reputation writes (Google Safe Browsing lists, VirusTotal results). "
                          "Offline: actualis never uses the network")
```

In `main`, extend the refusal rules so `--reputation` gets exactly the `--ioc` rules. In each loop that names `--ioc`, apply the same check to `args.reputation`, with the flag name in the message. The cleanest way is a loop over both:

```python
    for name, given in (("--ioc", bool(args.ioc)), ("--reputation", args.reputation)):
        if not given:
            continue
        for flag, on in (("--replay", args.replay), ("--agents", args.agents), ...same tuple as today...):
            if on:
                ap.error(f"{name} cannot be combined with {flag}: {flag} never reads it.")
        for flag, on in (("--coach", args.coach), ("--aisvs", args.aisvs), ("--share", args.share)):
            if on and not args.fail_on:
                ap.error(f"{name} cannot be combined with {flag} without --fail-on: "
                         f"{flag} never shows {'IOC matches' if name == '--ioc' else 'reputation results'}. "
                         f"Use --network {name}, or add --fail-on to gate on them.")
```

Keep every existing `--ioc` message byte-identical (existing tests assert them). Likewise duplicate the `--card`, `--watch`/`--mcp` single-line refusals for `--reputation`:

```python
    if args.reputation and args.card:
        ap.error("--reputation does not apply to --card; the card never shows downloads.")
    if args.reputation and (args.watch or args.mcp):
        ap.error("--reputation is not supported with --watch or --mcp yet.")
```

Change the comment on `EXIT_USAGE = 2` to `# argparse's, and --reputation --fail-on with no usable lists`.

At the load site (after `ioc = load_ioc(...)`, inside the same `try`):

```python
        reputation = load_reputation() if args.reputation else None
```

Right after that `try/except`, before `fleet = Fleet(...)`:

```python
    if reputation is not None and reputation.status != "ok":
        where = reputation.directory
        if reputation.status == "absent":
            msg = (f"actualis: --reputation: no Google Safe Browsing lists in {where}. Run "
                   f"`actualis-reputation update` first (it uses the network; actualis never does).")
        else:
            msg = (f"actualis: --reputation: the lists in {where} failed their check ({clean(reputation.error or '')}). "
                   f"Run `actualis-reputation update` to download them again.")
        print(msg, file=sys.stderr)
        if args.fail_on:
            return EXIT_USAGE
```

After `apply_ioc(fleet, ioc)`:

```python
    apply_reputation(fleet, reputation)
```

- [ ] **Step 4: Implement `reputation_json` and the schema**

```python
def reputation_json(fleet: "Fleet") -> dict:
    """network.reputation. Always an object; enabled false without --reputation."""
    data = fleet.reputation
    out = {"enabled": data is not None, "lists_status": None, "provider_lists": {}, "lists_age_hours": None,
           "stale": False, "vt_results": 0, "totals": dict(fleet.reputation_totals), "candidates": [],
           "advisory": {"text": None, "url": None}, "network_last_used": {"at": None, "provider": None}}
    if data is None:
        return out
    now = datetime.now(timezone.utc)
    out["lists_status"] = data.status
    out["provider_lists"] = {k: v["fetched_at"].isoformat(timespec="seconds") for k, v in sorted(data.state.items())}
    if data.oldest:
        out["lists_age_hours"] = max(0, int((now - data.oldest).total_seconds() // 3600))
        out["stale"] = now - data.oldest > timedelta(days=REPUTATION_STALE_DAYS)
    out["vt_results"] = len(data.vt)
    out["candidates"] = sorted(({"prefix_b64": base64.b64encode(p).decode(), "expressions": n}
                                for p, n in fleet.reputation_candidates.items()), key=lambda c: c["prefix_b64"])
    if data.lists:
        out["advisory"] = {"text": GSB_ADVISORY, "url": GSB_ADVISORY_URL}
    if data.last_network:
        out["network_last_used"] = dict(data.last_network)
    return out
```

In `network_json`'s return dict, after `"ioc"`, add `"reputation": reputation_json(fleet),`.

In `JSON_SCHEMA`, next to the `network.items[].ioc` line (the `reputation` line from Task 3 is already there):

```python
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
```

After the existing `JSON_SCHEMA.update(... network.ioc.matches[].item.transcript ...)` line, mirror the item's reputation keys:

```python
JSON_SCHEMA.update({f"network.ioc.matches[].item.reputation.{k}": JSON_SCHEMA[f"network.items[].reputation.{k}"]
                    for k in ("state", "provider", "threat_types", "threat_types[]", "checked_at", "advisory")})
```

In `tests/test_actualis.py::_populated`, so every fixed path is emitted as a string at least once, add this before `return f`:

```python
        # --reputation, from an in-memory cache: a listed host (a.io), a
        # candidate (x.io) and a recorded network use, so every str|null
        # path under network.reputation is a string at least once.
        rep = af.ReputationData()
        rep.status = "ok"
        a, x = af.sb_hash("a.io/"), af.sb_hash("x.io/")
        rep.lists = {name: b"" for name in af.REPUTATION_LISTS}
        rep.lists["mw-4b"] = b"".join(sorted([a[:4], x[:4]]))
        rep.state = {name: {"fetched_at": ts, "next_update_at": ts, "prefix_count": 0, "version": None}
                     for name in af.REPUTATION_LISTS}
        rep.oldest = ts
        rep.confirmations = {a[:4]: {"full_hashes": [{"hash": a, "threat_types": ["MALWARE"], "canary": False}],
                                     "confirmed_at": ts, "cache_until": ts + timedelta(days=36500)}}
        rep.last_network = {"at": ts.isoformat(), "provider": "gsb"}
        af.apply_reputation(f, rep, ts + timedelta(minutes=1))
```

Check that `timedelta` is imported in `tests/test_actualis.py`. The commands already in `_populated` are `curl https://a.io/x` and `curl -d @f https://x.io`, so a.io comes out listed and x.io a candidate.

- [ ] **Step 5: Text and HTML output**

```python
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
    sus = f" · {t['suspicious']} suspicious" if t["suspicious"] else ""
    print(f"  {head} · {t['listed']} listed · {t['candidate']} candidate{sus}"
          f" · {t['checked']} checked · {t['skipped']} private skipped")
    shown = 0
    for f in fleet.flags:
        if not set(f["categories"]) & set(REPUTATION_FLAG_CATEGORIES) or shown >= IOC_ROWS_SHOWN:
            continue
        high = f["severity"] == "high"
        color, mark = (c.red, "▲") if high else (c.yellow, "?")
        print(f"    {color}{mark}{c.off} {clip(f['evidence'], NET_VIEW_WIDTH - 6)}")
        shown += 1
    if data.lists and (t["listed"] or t["candidate"]):
        print(f"  {c.dim}{GSB_ADVISORY}: {GSB_ADVISORY_URL}. Lists can be wrong both ways; "
              f"see docs/reputation.md{c.off}")
```

No backslash appears inside an f-string expression, because that is a syntax error before Python 3.12 and the file must parse on 3.9.

Call `render_reputation(fleet, c)` right after **both** `render_ioc(fleet, c, raw)` calls in `render_network`.

In `render_network_html`, find where the IOC block is inserted (`_net_html_ioc(j)` or equivalent) and add a sibling:

```python
def _net_html_reputation(n: dict, flags: list[dict]) -> str:
    r = n.get("reputation") or {}
    if not r.get("enabled"):
        return ""
    rows = "".join(f"<li>{_h(f['evidence'])}</li>" for f in flags
                   if set(f["categories"]) & set(REPUTATION_FLAG_CATEGORIES))
    adv = r["advisory"]
    foot = (f'<p class="dim"><a href="{_h(adv["url"])}">{_h(adv["text"])}</a>. Lists can be wrong both ways.</p>'
            if adv["text"] else "")
    t = r["totals"]
    return (f'<section id="reputation"><h2>Reputation</h2><p>{t["listed"]} listed · {t["candidate"]} candidate · '
            f'{t["checked"]} checked · {t["skipped"]} private skipped</p><ul>{rows}</ul>{foot}</section>')
```

`render_network_html` receives only the network dict `n`, not the fleet. To pass the evidence lines, add a `flags: list[dict] | None = None` keyword argument to `render_network_html` and pass `fleet.flags` from `main`'s `--html` branch. The HTML page has a CSP: the link is a plain `<a>`, with no script and no external load, so the CSP is unaffected. Check that `_h` escapes attributes (it is used for text; confirm it escapes `"`).

- [ ] **Step 6: Self-check line**

In `self_check`, right after the "no networking module is imported by this build" result:

```python
    last = reputation_last_network()
    names = {"gsb": "Google Safe Browsing", "vt": "VirusTotal"}
    result(True, f"{NET_MARK} network: actualis never uses it",
           (f"actualis-reputation last used it {last['at']} ({names.get(last['provider'], last['provider'])}), "
            f"read from {reputation_dir() / 'network-log.jsonl'}." if last else
            "actualis-reputation has never used it on this machine (no network-log.jsonl)."))
```

`reputation_last_network()` never raises. If `reputation_dir()` itself raises `OSError` (no home), wrap the whole block in `try/except OSError` and print the "has never used it" branch.

- [ ] **Step 7: Run tests**

Run: `python3 -m unittest tests.test_reputation_cli tests.test_actualis -v 2>&1 | tail -30`, then `python3 -m unittest discover -s tests`
Expected: PASS. If golden-file tests under `tests/goldens` change because `network.reputation` appears in `--json` output, regenerate the goldens the way their test module documents. Inspect the diff: only the new keys may appear.

- [ ] **Step 8: Commit**

```bash
git add actualis.py tests/test_reputation_cli.py tests/test_actualis.py tests/goldens
git commit -m "Reputation: --reputation flag, JSON, text and HTML output, self-check line

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Companion core: CLI, keys, cache writer, consent, session, packaging

**Files:**
- Create: `actualis_reputation.py`
- Modify: `pyproject.toml`, `.github/workflows/test.yml`, `tools/brew-formula.py`, `tools/security/run.sh` (if it names `actualis.py` for bandit)
- Test: `tests/test_reputation_companion.py` (create)

**Interfaces:**
- Consumes: `actualis.reputation_dir`, `load_reputation`, `reputation_skip`, `_host_canon`, `redact`, `make_output_printable`, `NET_MARK`, `REPUTATION_LISTS`, `_open_regular`, `__version__`.
- Produces (used by Tasks 6 to 8):
  - `class UsageError(Exception)` (exit 2), `class NetError(Exception)` (exit 1)
  - `class Scrubber` with `add(secret: str) -> None`, `__call__(text) -> str`
  - `read_key(provider: str, key_command: str | None, scrub: Scrubber, env=os.environ) -> str` (`provider` in `"gsb"`, `"vt"`)
  - `ensure_dir(path: Path) -> None`, `write_atomic(path: Path, data: bytes) -> None`, `write_json(path: Path, obj) -> None`
  - `disclose(lines: list[tuple[str, str]], out) -> None`
  - `consent(question: str, *, yes: bool, dry_run: bool, stdin, out) -> bool`
  - `class NetSession` (context manager): `__init__(self, command: str, provider: str, scrub: Scrubber, *, receipt: str | None, out)`, `live(text: str)`, `live_done()`, `record(row: dict)`, `fail(reason: str)`, attribute `requests: list[dict]`
  - `read_report(path: str, stdin) -> dict` (the network object)
  - `build_parser() -> argparse.ArgumentParser`
  - `main(argv=None, *, http_factory=None, now=None, sleep=time.sleep, stdin=None, stdout=None, stderr=None) -> int`
  - `_cli() -> None` (console script)
  - Commands registered here: `status`, `forget`. Tasks 6 to 8 add `update`, `confirm`, `virustotal` to the `COMMANDS` dict.

- [ ] **Step 1: Write the failing tests** in `tests/test_reputation_companion.py`

```python
"""actualis-reputation, the only networked part of actualis. Every request in
these tests goes to a fake provider server on 127.0.0.1 (tests/_reputation.py),
injected through main(http_factory=...); _fixtures blocks any other socket.
Keys here are invented, never real."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401
import _reputation as R  # noqa: E402
from test_review_r2_X import af  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import actualis_reputation as ar  # noqa: E402

FAKE_KEY = "AIzaFAKE-test-key-0000000000000000000"


class TTY(io.StringIO):
    def isatty(self):
        return True


class CompanionCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=_fixtures.TEMP_HOME)
        self.tmp = Path(self._tmp.name)
        self.rep = self.tmp / "rep"
        self._env = mock_env = {"ACTUALIS_REPUTATION_DIR": str(self.rep)}
        self._old = {k: os.environ.get(k) for k in (*mock_env, "ACTUALIS_GSB_KEY", "ACTUALIS_VT_KEY")}
        os.environ.update(mock_env)
        os.environ.pop("ACTUALIS_GSB_KEY", None)
        os.environ.pop("ACTUALIS_VT_KEY", None)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def cli(self, *argv, stdin=None, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = ar.main(list(argv), stdin=stdin or io.StringIO(), stdout=out, stderr=err, **kw)
        return code, out.getvalue(), err.getvalue()


class TestCore(CompanionCase):
    def test_imports_are_stdlib_and_actualis(self):
        src = (ROOT / "actualis_reputation.py").read_text(encoding="utf-8")
        self.assertEqual(sorted(set(af.imports_in(src))),
                         ["__future__", "actualis", "argparse", "base64", "datetime", "hashlib", "json",
                          "math", "os", "pathlib", "secrets", "shlex", "ssl", "subprocess", "sys", "time",
                          "urllib"])

    def test_key_like_argument_is_not_echoed_or_run(self):
        code, out, err = self.cli("update", "--key", FAKE_KEY)
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, out + err)
        code, out, err = self.cli("update", FAKE_KEY)
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, out + err)

    def test_no_key_is_a_usage_error(self):
        code, _, err = self.cli("update", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("ACTUALIS_GSB_KEY", err)

    def test_key_command_runs_without_a_shell(self):
        scrub = ar.Scrubber()
        cmd = f'{sys.executable} -c "print(\'{FAKE_KEY}\')"'
        self.assertEqual(ar.read_key("gsb", cmd, scrub), FAKE_KEY)
        self.assertEqual(scrub(f"x{FAKE_KEY}y"), "x***y")
        with self.assertRaises(ar.UsageError) as cm:
            ar.read_key("gsb", f'{sys.executable} -c "import sys; print(\'{FAKE_KEY}\'); sys.exit(3)"', ar.Scrubber())
        self.assertNotIn(FAKE_KEY, str(cm.exception))
        with self.assertRaises(ar.UsageError):
            ar.read_key("gsb", "echo a; echo b", ar.Scrubber())     # "a;" is an argument to echo, one line out
        # `echo a; echo b` without a shell prints "a; echo b": a key with spaces is refused.

    def test_no_terminal_no_yes_sends_nothing(self):
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        server = R.FakeProvider()
        try:
            code, _, err = self.cli("update", http_factory=server.factory)
        finally:
            server.close()
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(server.requests, [])
        self.assertNotIn(FAKE_KEY, err)

    def test_terminal_no_answer_sends_nothing(self):
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        server = R.FakeProvider()
        try:
            code, _, err = self.cli("update", stdin=TTY("n\n"), http_factory=server.factory)
        finally:
            server.close()
        self.assertEqual(code, 0)
        self.assertEqual(server.requests, [])
        self.assertIn("nothing sent", err)

    def test_atomic_write_modes_and_symlink_refusal(self):
        target = self.rep / "gsb" / "state.json"
        ar.write_atomic(target, b"{}")
        self.assertEqual(target.read_bytes(), b"{}")
        if os.name != "nt":
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.rep / "gsb").stat().st_mode & 0o777, 0o700)
            link = self.rep / "gsb" / "confirmations.json"
            link.symlink_to(self.tmp / "elsewhere")
            with self.assertRaises(ar.NetError):
                ar.write_atomic(link, b"x")
            self.assertFalse((self.tmp / "elsewhere").exists())
        self.assertEqual([p.name for p in (self.rep / "gsb").iterdir() if p.name.startswith(".tmp")], [])

    def test_status_never_networks(self):
        R.write_cache(self.rep, {"mw-4b": [R.prefix("evil.example/")]},
                      log=[{"at": "2026-10-30T14:02:00+00:00", "provider": "gsb"}])
        code, out, _ = self.cli("status")
        self.assertEqual(code, 0)
        self.assertIn("mw-4b", out)
        self.assertIn("2026-10-30", out)

    def test_forget_requires_consent_and_deletes_only_cache_files(self):
        R.write_cache(self.rep)
        (self.rep / "keep-me.txt").write_text("not ours")
        code, _, _ = self.cli("forget")
        self.assertEqual(code, 2)
        self.assertTrue((self.rep / "gsb" / "state.json").exists())
        code, _, _ = self.cli("forget", "--yes")
        self.assertEqual(code, 0)
        self.assertFalse((self.rep / "gsb").exists())
        self.assertTrue((self.rep / "keep-me.txt").exists())

    def test_session_closing_line_receipt_and_log(self):
        receipt = self.tmp / "receipt.json"
        err = io.StringIO()
        scrub = ar.Scrubber()
        scrub.add(FAKE_KEY)
        with ar.NetSession("confirm", "gsb", scrub, receipt=str(receipt), out=err) as s:
            s.record({"method": "GET", "host": "safebrowsing.googleapis.com", "path": "/v5/hashes:search",
                      "sent": {"prefixes": 3, "decoys": 27}, "status": 200, "bytes": 10,
                      "note": f"key={FAKE_KEY}"})
            self.assertTrue((self.rep / "in-flight.json").exists())
        self.assertFalse((self.rep / "in-flight.json").exists())
        self.assertIn("network used: 1 request to safebrowsing.googleapis.com", err.getvalue())
        body = receipt.read_text()
        self.assertNotIn(FAKE_KEY, body)
        log = (self.rep / "network-log.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(log[-1])["provider"], "gsb")
        self.assertNotIn(FAKE_KEY, "".join(log))

    def test_session_prints_closing_line_on_ctrl_c(self):
        err = io.StringIO()
        with self.assertRaises(KeyboardInterrupt):
            with ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=err):
                raise KeyboardInterrupt
        self.assertIn("network used: nothing sent", err.getvalue())
        self.assertFalse((self.rep / "network-log.jsonl").exists())

    def test_console_script_entry_point_runs(self):
        r = subprocess.run([sys.executable, str(ROOT / "actualis_reputation.py"), "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn(af.__version__, r.stdout)
```

The `ar.read_key("gsb", "echo a; echo b", …)` assertion depends on `echo` existing. On Windows CI, `echo` is a shell builtin with no binary, so `subprocess` raises `FileNotFoundError`, and `read_key` turns that into `UsageError` too. The assertion holds on both.

- [ ] **Step 2: Add `FakeProvider` to `tests/_reputation.py`**

```python
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class FakeProvider:
    """A local stand-in for both providers. routes: {path: [(status, body bytes|dict)]},
    answered in order (the last one repeats). Records (method, path, query, headers)."""

    def __init__(self, routes: dict | None = None):
        self.routes = {k: list(v) for k, v in (routes or {}).items()}
        self.requests: list[dict] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                u = urlsplit(self.path)
                owner.requests.append({"path": u.path, "query": parse_qs(u.query),
                                       "headers": {k.lower(): v for k, v in self.headers.items()}})
                answers = owner.routes.get(u.path) or [(404, {"error": "no route"})]
                status, body = answers.pop(0) if len(answers) > 1 else answers[0]
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def factory(self, session):
        import actualis_reputation as ar
        netloc = f"127.0.0.1:{self.port}"
        # proxies={}: a developer's HTTPS_PROXY must not catch requests to the local fake.
        return ar.Http(session, endpoints={ar.GSB_HOST: netloc, ar.VT_HOST: netloc}, scheme="http", proxies={})

    def close(self):
        self.server.shutdown()
        self.server.server_close()
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_companion -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'actualis_reputation'`.

- [ ] **Step 4: Create `actualis_reputation.py`**

```python
#!/usr/bin/env python3
"""actualis-reputation: the only part of actualis that uses the network.

actualis itself never opens a socket (`actualis --self-check` proves it).
This companion downloads Google Safe Browsing threat lists, confirms local
matches with 4-byte hash prefixes, and (only when asked) looks hosts up on
VirusTotal. It writes the reputation cache that `actualis --reputation`
reads offline. Before any request it says what it will send, asks, shows a
live line while a request is in flight, and records what it did.

    actualis-reputation update      [--yes] [--dry-run] [--receipt FILE] [--key-command CMD]
    actualis-reputation confirm  NET.json   (same options)
    actualis-reputation virustotal NET.json [--vt-threshold N] (same options)
    actualis-reputation status
    actualis-reputation forget [--yes]

See docs/reputation.md. Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import actualis as af

__version__ = af.__version__
GSB_HOST = "safebrowsing.googleapis.com"
VT_HOST = "www.virustotal.com"
PROVIDERS = {"gsb": ("Google Safe Browsing", GSB_HOST, "ACTUALIS_GSB_KEY"),
             "vt": ("VirusTotal", VT_HOST, "ACTUALIS_VT_KEY")}
MARK = af.NET_MARK
LIST_RESPONSE_MAX = 64 << 20
SMALL_RESPONSE_MAX = 1 << 20
REPORT_MAX = 256 << 20
TIMEOUT = 30
EXIT_OK, EXIT_RUNTIME, EXIT_USAGE = 0, 1, 2
CACHE_FILES = ("gsb/state.json", "gsb/confirmations.json", "vt/results.json", "network-log.jsonl",
               "in-flight.json")


class UsageError(Exception):
    """Exit 2: nothing was sent."""


class NetError(Exception):
    """Exit 1: a request failed, a quota was hit, or a response was bad."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


class Scrubber:
    """Replaces every form of every secret it has seen with ***."""

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def add(self, secret: str) -> None:
        if secret:
            forms = {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)}
            self._secrets = sorted(set(self._secrets) | forms, key=len, reverse=True)

    def __call__(self, text: object) -> str:
        text = str(text)
        for s in self._secrets:
            text = text.replace(s, "***")
        return text


def read_key(provider: str, key_command: "str | None", scrub: Scrubber, env=os.environ) -> str:
    label, _host, var = PROVIDERS[provider]
    if key_command:
        try:
            argv = shlex.split(key_command)
        except ValueError as exc:
            raise UsageError(f"--key-command: {exc}") from None
        if not argv:
            raise UsageError("--key-command is empty")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=120)   # noqa: S603 (no shell)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UsageError(f"--key-command could not run ({type(exc).__name__})") from None
        key = r.stdout.strip()
        if r.returncode != 0:
            scrub.add(key)
            raise UsageError(f"--key-command exited {r.returncode}; its output is not shown") from None
    else:
        key = env.get(var, "").strip()
    if not key:
        raise UsageError(f"no {label} key: set ${var} or pass --key-command CMD (see docs/reputation.md)")
    scrub.add(key)
    if len(key) > 512 or not key.isprintable() or any(ch.isspace() for ch in key):
        raise UsageError(f"the {label} key holds spaces or control characters; check --key-command or ${var}")
    return key


def cache_root() -> Path:
    return af.reputation_dir()


def ensure_dir(path: Path) -> None:
    """Create `path` (0700) and refuse it if it, or the cache root, is a symlink."""
    root = cache_root()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in {root, path}:
        if os.path.islink(p):
            raise NetError(f"{p} is a symlink; refusing to write through it")
        if os.name != "nt":
            os.chmod(p, 0o700)


def write_atomic(path: Path, data: bytes) -> None:
    """Write to a temp file in the same directory, fsync, rename. 0600, never
    through a symlink."""
    ensure_dir(path.parent)
    if os.path.islink(path):
        raise NetError(f"{path.name} is a symlink; refusing to write through it")
    tmp = path.parent / f".tmp-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, obj) -> None:
    write_atomic(path, (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode())


def disclose(lines: "list[tuple[str, str]]", out) -> None:
    """The block printed before the first byte is sent (spec 6.2)."""
    out.write(f"{MARK} actualis-reputation uses the network.\n")
    for label, text in lines:
        for k, part in enumerate(text.split("\n")):
            out.write(f"  {label if k == 0 else '':<9} {part}\n")
    out.flush()


def consent(question: str, *, yes: bool, dry_run: bool, stdin, out) -> bool:
    if dry_run:
        return False
    if yes:
        return True
    if not (stdin is not None and stdin.isatty()):
        raise UsageError("nothing sent: there is no terminal to ask. Pass --yes to send, "
                         "or --dry-run to see exactly what would be sent.")
    out.write(f"{question} [y/N] ")
    out.flush()
    try:
        answer = stdin.readline()
    except (KeyboardInterrupt, EOFError):
        answer = ""
    return answer.strip().lower() in ("y", "yes")


class NetSession:
    """One run's network use: the live line, the closing summary (printed on
    success, failure and Ctrl-C), the receipt, the network-use log and the
    tray's in-flight marker."""

    def __init__(self, command: str, provider: str, scrub: Scrubber, *, receipt: "str | None", out) -> None:
        self.command, self.provider, self.scrub, self.receipt, self.out = command, provider, scrub, receipt, out
        self.requests: list[dict] = []
        self.failure: str | None = None
        self.started = _now()
        self._live = False

    def __enter__(self) -> "NetSession":
        try:
            write_json(cache_root() / "in-flight.json",
                       {"pid": os.getpid(), "provider": self.provider, "started_at": _iso(self.started)})
        except (OSError, NetError):
            pass                                  # the tray badge is a courtesy; never block on it
        return self

    def live(self, text: str) -> None:
        self.out.write(f"{MARK} {text}\n")
        self.out.flush()
        self._live = True

    def live_done(self) -> None:
        self._live = False

    def record(self, row: dict) -> None:
        self.requests.append(json.loads(self.scrub(json.dumps(row))))

    def fail(self, reason: str) -> None:
        self.failure = self.scrub(reason)

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            os.unlink(cache_root() / "in-flight.json")
        except OSError:
            pass
        if exc_type is KeyboardInterrupt and not self.failure:
            self.failure = "interrupted"
        hosts = sorted({r["host"] for r in self.requests})
        n = len(self.requests)
        if n:
            line = (f"{MARK} network used: {n} request{'' if n == 1 else 's'} to {', '.join(hosts)}, "
                    f"nothing else contacted")
        else:
            line = f"{MARK} network used: nothing sent"
        if self.failure:
            line += f" (stopped: {self.failure})"
        self.out.write(self.scrub(line) + "\n")
        self.out.flush()
        if self.receipt:
            try:
                Path(self.receipt).write_text(self.scrub(json.dumps(
                    {"command": self.command, "provider": self.provider, "started_at": _iso(self.started),
                     "finished_at": _iso(_now()), "requests": self.requests, "failure": self.failure},
                    indent=1)) + "\n")
            except OSError as e:
                self.out.write(f"actualis-reputation: cannot write the receipt: {e.strerror or e}\n")
        if n:
            sent = {"gsb": "prefixes" if self.command == "confirm" else "list-diff", "vt": "hostnames"}[self.provider]
            self._log({"at": _iso(self.started), "command": self.command, "provider": self.provider,
                       "contacted": hosts, "requests": n, "sent": sent})

    def _log(self, rec: dict) -> None:
        path = cache_root() / "network-log.jsonl"
        try:
            ensure_dir(path.parent)
            if os.path.islink(path):
                return
            if path.exists() and path.stat().st_size > (1 << 20):
                keep = path.read_text(errors="replace").splitlines()[-500:]
                write_atomic(path, ("\n".join(keep) + "\n").encode())
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except (OSError, NetError):
            pass


def read_report(path: str, stdin) -> dict:
    """The network object from `actualis --network --json` (or the full --json
    payload's network key)."""
    try:
        if path == "-":
            raw = (stdin or sys.stdin).read(REPORT_MAX + 1)
        else:
            with af._open_regular(Path(path)) as fh:
                raw = fh.read(REPORT_MAX + 1)
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    if len(raw) > REPORT_MAX:
        raise UsageError(f"{path} is over {REPORT_MAX >> 20} MiB")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise UsageError(f"{path} is not JSON; pass the output of actualis --network --json") from None
    net = doc.get("network", doc) if isinstance(doc, dict) else None
    if not isinstance(net, dict) or not isinstance(net.get("hosts"), list):
        raise UsageError(f"{path} is not actualis --network --json output")
    return net


def cmd_status(args, ctx) -> int:
    out = ctx["stdout"]
    data = af.load_reputation()
    out.write(f"cache: {data.directory}\n")
    out.write(f"Google Safe Browsing lists: {data.status}" + (f" ({data.error})" if data.error else "") + "\n")
    for name, st in sorted(data.state.items()):
        nxt = st["next_update_at"]
        out.write(f"  {name:<8} {st['prefix_count']:>9,} prefixes  fetched {_iso(st['fetched_at'])}"
                  + (f"  next refresh allowed {_iso(nxt)}" if nxt else "") + "\n")
    now = _now()
    fresh = sum(1 for c in data.confirmations.values() if af._confirmation_fresh(c, now))
    out.write(f"confirmations: {len(data.confirmations)} stored, {fresh} fresh (under 30 minutes)\n")
    out.write(f"VirusTotal results: {len(data.vt)}\n")
    last = data.last_network
    out.write(f"{MARK} network last used: " + (f"{last['at']} ({last['provider']})" if last else "never") + "\n")
    return EXIT_OK


def cmd_forget(args, ctx) -> int:
    root = cache_root()
    if os.path.islink(root):
        raise UsageError(f"{root} is a symlink; refusing to delete through it")
    if not root.exists():
        ctx["stdout"].write("nothing to forget\n")
        return EXIT_OK
    if not consent(f"Delete the reputation cache in {root}?", yes=args.yes, dry_run=False,
                   stdin=ctx["stdin"], out=ctx["stderr"]):
        ctx["stderr"].write("nothing deleted\n")
        return EXIT_OK
    removed = 0
    targets = [root / f for f in CACHE_FILES] + list((root / "gsb").glob("*.prefixes")) \
        + [p for d in (root, root / "gsb", root / "vt") if d.is_dir() for p in d.glob(".tmp-*")]
    for p in targets:
        try:
            if p.is_file() or p.is_symlink():
                p.unlink()
                removed += 1
        except OSError:
            pass
    for d in (root / "gsb", root / "vt", root):
        try:
            d.rmdir()
        except OSError:
            pass                                   # not empty: something that is not ours stays
    ctx["stdout"].write(f"deleted {removed} file(s) from {root}\n")
    return EXIT_OK


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):                # never echo arguments: one may be a key
        if message.startswith("unrecognized arguments") or message.startswith("argument command"):
            message = message.split(":", 1)[0] + " (not repeated here, in case one is a key)"
        super().error(message)


def _threshold(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number from 1 to 100") from None
    if not 1 <= n <= 100:
        raise argparse.ArgumentTypeError("a whole number from 1 to 100")
    return n


def build_parser() -> argparse.ArgumentParser:
    ap = _Parser(prog="actualis-reputation", allow_abbrev=False,
                 description="The only part of actualis that uses the network. See docs/reputation.md.")
    ap.add_argument("--version", action="version", version=f"actualis-reputation {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def common(p):
        p.add_argument("--yes", action="store_true", help="send without asking (needed without a terminal)")
        p.add_argument("--dry-run", action="store_true", help="print exactly what would be sent; send nothing")
        p.add_argument("--receipt", metavar="FILE", help="write every request made (no key) to FILE as JSON")
        p.add_argument("--key-command", metavar="CMD",
                       help="run CMD (no shell) and use its output as the key, e.g. \"op read op://…\"")

    common(sub.add_parser("update", allow_abbrev=False, help="download Safe Browsing list updates"))
    cf = sub.add_parser("confirm", allow_abbrev=False, help="confirm local candidates with Google (prefixes only)")
    cf.add_argument("report", metavar="NET.json", help="actualis --network --reputation --json output, or -")
    common(cf)
    vt = sub.add_parser("virustotal", allow_abbrev=False, help="look hostnames up on VirusTotal (sends hostnames)")
    vt.add_argument("report", metavar="NET.json", help="actualis --network --json output, or -")
    vt.add_argument("--vt-threshold", type=_threshold, default=2, metavar="N",
                    help="engines flagging malicious for a high finding (default 2)")
    common(vt)
    sub.add_parser("status", allow_abbrev=False, help="lists, ages, last network use; never networks")
    fg = sub.add_parser("forget", allow_abbrev=False, help="delete the reputation cache")
    fg.add_argument("--yes", action="store_true", help="delete without asking")
    return ap


COMMANDS = {"status": cmd_status, "forget": cmd_forget}


def main(argv=None, *, http_factory=None, now=None, sleep=time.sleep, stdin=None, stdout=None,
         stderr=None) -> int:
    stdout, stderr, stdin = stdout or sys.stdout, stderr or sys.stderr, stdin or sys.stdin
    old_err = sys.stderr
    sys.stderr = stderr                           # argparse writes its errors here
    try:
        try:
            args = build_parser().parse_args(argv)
        except SystemExit as exc:
            return int(exc.code or 0)
    finally:
        sys.stderr = old_err
    scrub = Scrubber()
    ctx = {"stdin": stdin, "stdout": stdout, "stderr": stderr, "scrub": scrub, "sleep": sleep,
           "now": now or _now, "http_factory": http_factory or (lambda session: Http(session))}
    try:
        return COMMANDS[args.command](args, ctx)
    except UsageError as exc:
        stderr.write(f"actualis-reputation: {scrub(exc)}\n")
        return EXIT_USAGE
    except NetError as exc:
        stderr.write(f"actualis-reputation: {scrub(exc)}\n")
        return EXIT_RUNTIME
    except KeyboardInterrupt:
        stderr.write("actualis-reputation: interrupted\n")
        return 130
    except Exception as exc:                       # noqa: BLE001 -- never a traceback that could hold a key
        stderr.write(f"actualis-reputation: unexpected {type(exc).__name__}: {af.redact(scrub(exc))[:300]}\n")
        return EXIT_RUNTIME


def _cli() -> None:
    af.make_output_printable(False)
    sys.exit(main())


if __name__ == "__main__":
    _cli()
```

`Http` is defined in Task 6. Until then, add a minimal stub so `main` resolves the name. Task 6 replaces it:

```python
class Http:                                      # replaced in Task 6
    def __init__(self, session, **kw):
        raise NetError("no network client yet")
```

`math` is imported for Task 8's minute estimate. If a linter flags it unused before then, keep it; the import test pins it.

In the test helper, `R.FakeProvider.factory` returns an `ar.Http` with `endpoints` and `scheme`. Task 5's `test_no_terminal_no_yes_sends_nothing` never reaches the factory, because consent refuses first. For that, `update` must exist. Register a minimal `cmd_update` that reads the key, prints the disclosure and calls `consent`, then (until Task 6) returns `EXIT_OK` after `consent` is true:

```python
def cmd_update(args, ctx) -> int:                # completed in Task 6
    disclose([("Provider", "Google Safe Browsing v5, list download"),
              ("Sends", "nothing about your hosts: downloads list updates")], ctx["stderr"])
    if not args.dry_run:
        read_key("gsb", args.key_command, ctx["scrub"])
    if not consent("Download Safe Browsing list updates from Google?", yes=args.yes, dry_run=args.dry_run,
                   stdin=ctx["stdin"], out=ctx["stderr"]):
        ctx["stderr"].write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    return EXIT_OK


COMMANDS["update"] = cmd_update
```

`test_no_key_is_a_usage_error` expects exit 2 for `update --yes` with no key. With the order above (key read before consent), it holds.

- [ ] **Step 5: Packaging**

`pyproject.toml`:

```toml
[project.scripts]
actualis = "actualis:_cli"
actualis-reputation = "actualis_reputation:_cli"

[tool.hatch.build.targets.wheel]
include = ["actualis.py", "actualis_reputation.py"]
```

Add `"actualis_reputation.py"` to the sdist `include` list.

`.github/workflows/test.yml`: after the existing allowlist step, add a sibling step for the companion. Read the existing step's YAML structure and copy it with these differences:

```yaml
      - name: actualis-reputation imports only the standard library and actualis
        run: |
          uv run --python ${{ matrix.python }} python -c "
          import ast, sys
          # The only module allowed to use the network. Its own list, so the
          # core's list never has to grow.
          allowed = {'__future__','actualis','argparse','base64','datetime','hashlib','json','math',
                     'os','pathlib','secrets','shlex','ssl','subprocess','sys','time','urllib'}
          tree = ast.parse(open('actualis_reputation.py').read())
          found = set()
          for n in ast.walk(tree):
              if isinstance(n, ast.Import):
                  found |= {a.name.split('.')[0] for a in n.names}
              elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                  found.add(n.module.split('.')[0])
          extra = sorted(found - allowed)
          print('imports:', sorted(found))
          print('outside allowlist:', extra or 'none')
          sys.exit(1 if extra else 0)"
```

Also add one assertion step that the core never imports the companion:

```yaml
      - name: actualis never imports actualis-reputation
        run: "! grep -nE '^\\s*(import|from)\\s+actualis_reputation' actualis.py"
```

`shell: bash` is needed on the Windows matrix leg for `!`. Mirror how other steps set it.

`tools/brew-formula.py` `FORMULA`: install both files and write a second wrapper:

```ruby
  def install
    libexec.install "actualis.py", "actualis_reputation.py"
    (bin/"actualis").write <<~SH
      #!/bin/bash
      exec "#{{formula_opt_bin("python@3.13")}}/python3.13" "#{{libexec}}/actualis.py" "$@"
    SH
    (bin/"actualis-reputation").write <<~SH
      #!/bin/bash
      exec "#{{formula_opt_bin("python@3.13")}}/python3.13" "#{{libexec}}/actualis_reputation.py" "$@"
    SH
  end
```

Keep every existing line of the formula that this does not replace (read the whole `FORMULA` string first). Update the formula's `test do` block, if present, to also run `actualis-reputation --version`.

`tools/security/run.sh`: if bandit is pointed at `actualis.py` explicitly, add `actualis_reputation.py`. The companion's `subprocess.run` (no shell) and `urllib` uses will get bandit findings (B603, B310). Mark each with `# nosec Bxxx` and a reason on the same line, as `actualis.py` already does, if it does.

- [ ] **Step 6: Run tests**

Run: `python3 -m unittest tests.test_reputation_companion -v && python3 -m unittest discover -s tests`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add actualis_reputation.py tests/_reputation.py tests/test_reputation_companion.py pyproject.toml \
        .github/workflows/test.yml tools/brew-formula.py tools/security/run.sh
git commit -m "actualis-reputation: CLI, keys, scrubber, cache writer, consent, session record

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: HTTP client and `update` (Safe Browsing list download)

**Files:**
- Modify: `actualis_reputation.py` (replace the `Http` stub and `cmd_update`)
- Test: `tests/test_reputation_companion.py`

**Interfaces:**
- Consumes: Task 5 (`NetSession`, `Scrubber`, `read_key`, `disclose`, `consent`, `write_atomic`, `write_json`); `af.load_reputation`, `af.REPUTATION_LISTS`.
- Produces:
  - `class Http`: `__init__(self, session: NetSession, *, endpoints: dict | None = None, context: ssl.SSLContext | None = None, scheme: str = "https", proxies: dict | None = None)`, `get(self, host: str, path: str, *, query: list[tuple[str, str]] = (), headers: dict | None = None, limit: int = SMALL_RESPONSE_MAX, sent: dict, describe: str) -> tuple[int, bytes]`
  - `rice_decode(first_value: int, k: int, count: int, data: bytes) -> list[int]`
  - `apply_list_update(old: bytes, hl: dict) -> bytes`
  - `parse_duration(text: object) -> float` (seconds; `"3.5s"` -> 3.5; bad -> 0.0)
  - `_b64(text: object) -> bytes`
  - `cmd_update(args, ctx) -> int`

- [ ] **Step 1: Write the failing tests**

```python
def rice_lists(entries: dict) -> dict:
    """A hashLists:batchGet body with full (non-partial) lists, each list's
    prefixes Rice-encoded the way Google does, checksum included."""
    lists = []
    for name in R.LISTS:
        ps = sorted(set(entries.get(name, [])))
        lists.append(R.hash_list(name, ps))
    return {"hashLists": lists}


class TestRice(unittest.TestCase):
    def test_google_worked_example(self):
        vals = ar.rice_decode(489866504, 30, 2, bytes.fromhex("7400d2971bed497400"))
        self.assertEqual([v.to_bytes(4, "big").hex() for v in vals], ["1d32c508", "291bc542", "f7a502e5"])

    def test_round_trip_through_the_test_encoder(self):
        ps = sorted({R.prefix(f"h{i}.example/") for i in range(500)})
        hl = R.hash_list("mw-4b", ps)
        self.assertEqual(ar.apply_list_update(b"", hl), b"".join(ps))

    def test_rejects_truncated_and_out_of_range(self):
        with self.assertRaises(ValueError):
            ar.rice_decode(1, 30, 2, b"\x00")
        with self.assertRaises(ValueError):
            ar.rice_decode(0xFFFFFFF0, 3, 1, b"\xff\xff\x00")        # overflows 32 bits
        with self.assertRaises(ValueError):
            ar.apply_list_update(b"", {"additionsFourBytes": {"riceParameter": 2, "entriesCount": 1,
                                                                "firstValue": 1, "encodedData": "AA=="}})

    def test_partial_update_removes_then_adds(self):
        old = sorted({R.prefix(f"o{i}.example/") for i in range(5)})
        add = R.prefix("new.example/")
        new = sorted([p for i, p in enumerate(old) if i not in (1, 3)] + [add])
        hl = R.hash_list("mw-4b", [add], removals=[1, 3], partial=True, checksum_of=new)
        self.assertEqual(ar.apply_list_update(b"".join(old), hl), b"".join(new))

    def test_removal_index_past_end_is_rejected(self):
        hl = R.hash_list("mw-4b", [], removals=[9], partial=True, checksum_of=[])
        with self.assertRaises(ValueError):
            ar.apply_list_update(b"\x00\x00\x00\x01", hl)

    def test_durations(self):
        self.assertEqual(ar.parse_duration("3.5s"), 3.5)
        self.assertEqual(ar.parse_duration("1800s"), 1800.0)
        self.assertEqual(ar.parse_duration(None), 0.0)
        self.assertEqual(ar.parse_duration("-5s"), 0.0)
        self.assertEqual(ar.parse_duration("9" * 400 + "s"), 0.0)


class TestUpdate(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY

    def serve(self, *bodies):
        s = R.FakeProvider({"/v5/hashLists:batchGet": [(200, b) if isinstance(b, dict) else b for b in bodies]})
        self.addCleanup(s.close)
        return s

    def test_first_update_writes_lists_and_state(self):
        s = self.serve(rice_lists({"mw-4b": [R.prefix("evil.example/")]}))
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(s.requests), 1)
        q = s.requests[0]["query"]
        self.assertEqual(sorted(q["names"]), sorted(R.LISTS))
        self.assertNotIn("key", q)
        self.assertEqual(s.requests[0]["headers"]["x-goog-api-key"], FAKE_KEY)
        d = af.load_reputation(self.rep)
        self.assertEqual(d.status, "ok", d.error)
        self.assertEqual(d.lists["mw-4b"], R.prefix("evil.example/"))
        self.assertIn("network used: 1 request to safebrowsing.googleapis.com", err)

    def test_not_due_sends_nothing(self):
        s = self.serve(rice_lists({}))
        self.cli("update", "--yes", http_factory=s.factory)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0)
        self.assertEqual(len(s.requests), 1)
        self.assertIn("lists are current", err)

    def test_checksum_mismatch_falls_back_to_full_fetch(self):
        bad = rice_lists({"mw-4b": [R.prefix("evil.example/")]})
        bad["hashLists"][0]["sha256Checksum"] = R.b64(b"\x00" * 32)
        good = {"hashLists": [R.hash_list("mw-4b", [R.prefix("evil.example/")])]}   # only the retried list
        s = self.serve(bad, good)
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(s.requests), 2)
        self.assertNotIn("version", s.requests[1]["query"])

    def test_second_mismatch_writes_nothing(self):
        bad = rice_lists({"mw-4b": [R.prefix("evil.example/")]})
        bad["hashLists"][0]["sha256Checksum"] = R.b64(b"\x00" * 32)
        s = self.serve(bad, {"hashLists": [bad["hashLists"][0]]})
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual(af.load_reputation(self.rep).status, "absent")

    def test_403_is_a_runtime_error_with_no_key_in_output(self):
        s = self.serve((403, {"error": {"message": f"API key not valid: {FAKE_KEY}"}}))
        receipt = self.tmp / "r.json"
        code, out, err = self.cli("update", "--yes", "--receipt", str(receipt), http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertIn("403", err)
        self.assertNotIn(FAKE_KEY, out + err + receipt.read_text())

    def test_dry_run_reads_no_key_and_sends_nothing(self):
        os.environ.pop("ACTUALIS_GSB_KEY")
        s = self.serve(rice_lists({}))
        code, _, err = self.cli("update", "--dry-run", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual(s.requests, [])
        self.assertIn("nothing sent", err)

    def test_redirect_is_not_followed(self):
        s = self.serve((302, b""))
        code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        self.assertEqual(code, 1)
        self.assertEqual(len(s.requests), 1)

    def test_oversized_response_is_refused(self):
        s = self.serve((200, b"x" * 2048))
        old = ar.LIST_RESPONSE_MAX
        ar.LIST_RESPONSE_MAX = 1024
        try:
            code, _, err = self.cli("update", "--yes", http_factory=s.factory)
        finally:
            ar.LIST_RESPONSE_MAX = old
        self.assertEqual(code, 1)
        self.assertIn("over", err)

    def test_key_never_appears_anywhere(self):
        s = self.serve((500, f"boom {FAKE_KEY}".encode()))
        receipt = self.tmp / "r.json"
        code, out, err = self.cli("update", "--yes", "--receipt", str(receipt), http_factory=s.factory)
        blob = out + err + receipt.read_text()
        for p in self.rep.rglob("*"):
            if p.is_file():
                blob += p.read_text(errors="replace")
        self.assertNotIn(FAKE_KEY, blob)

    def test_unknown_host_is_refused(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session, endpoints={ar.GSB_HOST: "127.0.0.1:9"}, scheme="http")
        with self.assertRaises(ar.NetError):
            http.get("evil.example", "/", sent={}, describe="x")

    def test_real_client_verifies_certificates(self):
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session)
        self.assertEqual(http.scheme, "https")
        self.assertEqual(http.context.verify_mode, __import__("ssl").CERT_REQUIRED)
        self.assertTrue(http.context.check_hostname)
        self.assertEqual(set(http.endpoints), {ar.GSB_HOST, ar.VT_HOST})


@unittest.skipUnless(__import__("shutil").which("openssl"), "needs openssl to mint a throwaway certificate")
class TestTlsRefusesUntrustedCert(CompanionCase):
    def test_self_signed_server_is_refused(self):
        import ssl
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        cert, key = self.tmp / "c.pem", self.tmp / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True, timeout=60)
        hits = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(cert), str(key))
        srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        session = ar.NetSession("update", "gsb", ar.Scrubber(), receipt=None, out=io.StringIO())
        http = ar.Http(session, endpoints={ar.GSB_HOST: f"127.0.0.1:{srv.server_address[1]}"})  # real https context
        with self.assertRaises(ar.NetError):
            http.get(ar.GSB_HOST, "/v5/hashLists:batchGet", sent={}, describe="x")
        self.assertEqual(hits, [])
```

Add the Rice encoder and `hash_list` builder to `tests/_reputation.py` (test side only):

```python
def rice_encode(values: list, k: int) -> tuple:
    """(first_value, rice_parameter, entries_count, encoded_data b64) for sorted uint32 values,
    as Google's Local Database page describes: unary quotient then k remainder bits, LSB first."""
    if not values:
        return None
    bits: list[int] = []
    for prev, cur in zip(values, values[1:]):
        d = cur - prev
        q, r = d >> k, d & ((1 << k) - 1)
        bits += [1] * q + [0]
        bits += [(r >> i) & 1 for i in range(k)]
    data = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        data[i >> 3] |= b << (i & 7)
    return values[0], k, len(values) - 1, b64(bytes(data))


def _rice_obj(values: list, k: int = 28) -> dict | None:
    enc = rice_encode(values, k)
    if enc is None:
        return None
    first, k, n, data = enc
    return {"firstValue": first, "riceParameter": k, "entriesCount": n, "encodedData": data}


def hash_list(name: str, prefixes: list, *, removals=(), partial=False, checksum_of=None,
              wait: str = "1800s") -> dict:
    hl = {"name": name, "version": b64(f"{name}-v2".encode()), "partialUpdate": partial,
          "minimumWaitDuration": wait}
    adds = _rice_obj(sorted(int.from_bytes(p, "big") for p in prefixes))
    if adds:
        hl["additionsFourBytes"] = adds
    rem = _rice_obj(sorted(removals), k=3)
    if rem:
        hl["compressedRemovals"] = rem
    final = sorted(checksum_of if checksum_of is not None else prefixes)
    hl["sha256Checksum"] = b64(hashlib.sha256(b"".join(final)).digest())
    return hl
```

`_rice_obj` with an empty list returns None (no field), matching the API's omission.

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_companion.TestRice tests.test_reputation_companion.TestUpdate -v`
Expected: FAIL with `AttributeError: … 'rice_decode'` / `NetError: no network client yet`.

- [ ] **Step 3: Implement `Http`** (replace the stub)

```python
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is returned as an error, never followed: a redirect could lead
    anywhere, and only the two provider hosts may be contacted."""

    def redirect_request(self, *args, **kwargs):
        return None


def _read_capped(resp, limit: int) -> bytes:
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise NetError(f"the response is over {limit >> 20 or 1} MiB; refusing it")
    return data


class Http:
    """HTTPS GETs to the two provider hosts and nothing else, with certificate
    verification, no redirects, a timeout and a size cap. Each request is
    shown while in flight and recorded for the receipt."""

    def __init__(self, session: NetSession, *, endpoints: "dict | None" = None,
                 context: "ssl.SSLContext | None" = None, scheme: str = "https",
                 proxies: "dict | None" = None) -> None:
        self.session = session
        self.endpoints = dict(endpoints or {GSB_HOST: GSB_HOST, VT_HOST: VT_HOST})
        self.context = context or ssl.create_default_context()
        self.scheme = scheme
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=self.context)]
        if proxies is not None:                  # None: honour HTTPS_PROXY and the system settings
            handlers.append(urllib.request.ProxyHandler(proxies))
        self.opener = urllib.request.build_opener(*handlers)

    def get(self, host: str, path: str, *, query=(), headers: "dict | None" = None,
            limit: int = SMALL_RESPONSE_MAX, sent: dict, describe: str) -> "tuple[int, bytes]":
        if host not in self.endpoints:
            raise NetError(f"refusing to contact {host}: only {', '.join(sorted(self.endpoints))}")
        url = f"{self.scheme}://{self.endpoints[host]}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(list(query))
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": f"actualis-reputation/{__version__}", "Accept": "application/json", **(headers or {})})
        status, body = 0, b""
        self.session.live(f"{describe} → {host}")
        try:
            try:
                with self.opener.open(req, timeout=TIMEOUT) as resp:      # nosec B310 (https, pinned hosts)
                    status = resp.status
                    body = _read_capped(resp, limit)
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = _read_capped(exc, SMALL_RESPONSE_MAX) if exc.fp else b""
            except (urllib.error.URLError, OSError, ValueError) as exc:
                reason = getattr(exc, "reason", exc)
                raise NetError(self.session.scrub(f"cannot reach {host}: {reason}")) from None
        finally:
            self.session.live_done()
            self.session.record({"method": "GET", "host": host, "path": path, "sent": sent,
                                 "status": status, "bytes": len(body), "at": _iso(_now())})
        return status, body
```

`ssl.SSLError` is a subclass of `OSError`, so certificate failures land in the `NetError` branch.

- [ ] **Step 4: Implement Rice decoding, list application and `cmd_update`** (replace the Task 5 version)

```python
GSB_BATCH_PATH = "/v5/hashLists:batchGet"


def _b64(text: object) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 text")
    pad = "=" * (-len(text) % 4)
    if "-" in text or "_" in text:
        return base64.urlsafe_b64decode(text + pad)
    return base64.b64decode(text + pad, validate=True)


def parse_duration(text: object) -> float:
    """A protobuf Duration ("3.5s") in seconds; 0.0 for anything else."""
    if not isinstance(text, str) or not text.endswith("s") or len(text) > 32:
        return 0.0
    try:
        v = float(text[:-1])
    except ValueError:
        return 0.0
    return v if math.isfinite(v) and v > 0 else 0.0


def rice_decode(first_value: int, k: int, count: int, data: bytes) -> "list[int]":
    """Golomb-Rice deltas as Google encodes them: per entry a unary quotient
    (1s ended by a 0) then k remainder bits, least significant bit first,
    bytes little-endian; each value is the previous plus (q << k | r)."""
    if not 0 <= first_value <= 0xFFFFFFFF:
        raise ValueError("first value is not a uint32")
    if count and not 3 <= k <= 30:
        raise ValueError(f"rice parameter {k} is outside 3..30")
    if count > len(data) * 8:
        raise ValueError("more entries than encoded bits")
    out, v, pos, nbits = [first_value], first_value, 0, len(data) * 8
    for _ in range(count):
        q = 0
        while True:
            if pos >= nbits:
                raise ValueError("encoded data ends early")
            bit = (data[pos >> 3] >> (pos & 7)) & 1
            pos += 1
            if not bit:
                break
            q += 1
            if q > 32:
                raise ValueError("quotient too long")
        if pos + k > nbits:
            raise ValueError("encoded data ends early")
        r = 0
        for i in range(k):
            r |= ((data[pos >> 3] >> (pos & 7)) & 1) << i
            pos += 1
        v += (q << k) | r
        if v > 0xFFFFFFFF:
            raise ValueError("value overflows 32 bits")
        out.append(v)
    return out


def _rice_field(obj: object) -> "list[int]":
    if obj is None:
        return []
    if not isinstance(obj, dict):
        raise ValueError("a Rice field is not an object")
    first = int(obj.get("firstValue") or 0)
    k = int(obj.get("riceParameter") or 0)
    n = int(obj.get("entriesCount") or 0)
    data = _b64(obj.get("encodedData") or "")
    if n < 0:
        raise ValueError("negative entry count")
    return rice_decode(first, k, n, data)


def apply_list_update(old: bytes, hl: dict) -> bytes:
    """The new sorted list after one HashList: a full list replaces `old`; a
    partial one removes by index, then adds. The caller checks the checksum."""
    for wide in ("additionsEightBytes", "additionsSixteenBytes", "additionsThirtyTwoBytes"):
        if wide in hl:
            raise ValueError(f"{wide}: only 4-byte lists are supported")
    partial = hl.get("partialUpdate") is True
    entries = [old[i:i + 4] for i in range(0, len(old), 4)] if partial else []
    if partial:
        removals = _rice_field(hl.get("compressedRemovals"))
        if removals:
            drop = set(removals)
            if max(drop) >= len(entries):
                raise ValueError("a removal index is past the end of the list")
            entries = [e for i, e in enumerate(entries) if i not in drop]
    entries += [v.to_bytes(4, "big") for v in _rice_field(hl.get("additionsFourBytes"))]
    entries.sort()
    return b"".join(entries)


def _verify(name: str, blob: bytes, hl: dict, old: bytes) -> bool:
    if "sha256Checksum" not in hl:
        # No checksum means no change was sent; the list must then be the old one.
        return blob == old
    return hashlib.sha256(blob).digest() == _b64(hl["sha256Checksum"])


def _batch(http: Http, key: str, names: "list[str]", versions: dict, describe: str) -> "list[dict]":
    query = [("names", n) for n in names] + [("version", versions[n]) for n in names if versions.get(n)]
    status, body = http.get(GSB_HOST, GSB_BATCH_PATH, query=query, headers={"X-Goog-Api-Key": key},
                            limit=LIST_RESPONSE_MAX, sent={"list_update": names}, describe=describe)
    _gsb_status(status, body)
    try:
        doc = json.loads(body)
        lists = doc["hashLists"]
        if not isinstance(lists, list) or len(lists) != len(names):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise NetError("Safe Browsing sent a response that is not a hash list") from None
    return lists


def _gsb_status(status: int, body: bytes) -> None:
    if status == 200:
        return
    hint = {400: "the request was refused", 401: "the key was rejected", 403: "the key was rejected or the "
            "Safe Browsing API is not enabled for its project", 429: "quota reached; try again later"}
    raise NetError(f"Safe Browsing answered HTTP {status}: {hint.get(status, 'server error')}")


def cmd_update(args, ctx) -> int:
    out, scrub, now = ctx["stderr"], ctx["scrub"], ctx["now"]()
    data = af.load_reputation()
    state = data.state if data.status == "ok" else {}
    due = [n for n in af.REPUTATION_LISTS
           if n not in state or not state[n]["next_update_at"] or state[n]["next_update_at"] <= now]
    if not due:
        nxt = min(s["next_update_at"] for s in state.values())
        out.write(f"lists are current (next refresh allowed at {_iso(nxt)}); no request sent\n")
        return EXIT_OK
    first = not state
    disclose([("Provider", "Google Safe Browsing v5, list download"),
              ("Sends", "nothing about your hosts: downloads list updates"
                        + (" (full lists on this first run)" if first else "")),
              ("Never", "commands, paths, query strings, credentials, transcript text"),
              ("Key", "(not read: --dry-run)" if args.dry_run else
               ("--key-command (not shown)" if args.key_command else "$ACTUALIS_GSB_KEY (set, not shown)"))], out)
    if args.dry_run:
        out.write(f"would request: GET https://{GSB_HOST}{GSB_BATCH_PATH} for {', '.join(due)}\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    key = read_key("gsb", args.key_command, scrub)
    if not consent("Download Safe Browsing list updates from Google?", yes=args.yes, dry_run=False,
                   stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    versions = {n: state[n]["version"] for n in due if n in state and state[n].get("version")}
    with NetSession("update", "gsb", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            new: dict[str, tuple[bytes, dict]] = {}
            lists = _batch(http, key, due, versions, f"downloading {len(due)} list update(s)")
            retry = []
            for name, hl in zip(due, lists):
                old = data.lists.get(name, b"")
                try:
                    blob = apply_list_update(old, hl)
                    ok = _verify(name, blob, hl, old)
                except ValueError:
                    ok = False
                if ok:
                    new[name] = (blob, hl)
                else:
                    retry.append(name)
            if retry:
                lists = _batch(http, key, retry, {}, f"checksum mismatch: downloading {len(retry)} full list(s)")
                for name, hl in zip(retry, lists):
                    try:
                        blob = apply_list_update(b"", {**hl, "partialUpdate": False})
                        ok = _verify(name, blob, hl, b"")
                    except ValueError:
                        ok = False
                    if not ok:
                        raise NetError(f"{name}: the full list failed its checksum; nothing was written")
                    new[name] = (blob, hl)
            _commit_lists(data, state, new, now)
        except NetError as exc:
            session.fail(str(exc))
            raise
    return EXIT_OK


def _commit_lists(data, state: dict, new: dict, now: datetime) -> None:
    """Write each changed list under a checksum name, then state.json last
    (the commit point), then remove list files nothing names."""
    gsb = cache_root() / "gsb"
    entries = []
    for name in af.REPUTATION_LISTS:
        if name in new:
            blob, hl = new[name]
            sha = hashlib.sha256(blob).hexdigest()
            fname = f"{name}.{sha[:16]}.prefixes"
            write_atomic(gsb / fname, blob)
            wait = parse_duration(hl.get("minimumWaitDuration"))
            entries.append({"name": name, "version": hl.get("version"), "sha256": sha, "file": fname,
                            "fetched_at": _iso(now), "next_update_at": _iso(now + timedelta(seconds=wait)),
                            "prefix_count": len(blob) // 4})
        else:
            st = state[name]
            blob = data.lists[name]
            sha = hashlib.sha256(blob).hexdigest()
            entries.append({"name": name, "version": st.get("version"), "sha256": sha,
                            "file": f"{name}.{sha[:16]}.prefixes", "fetched_at": _iso(st["fetched_at"]),
                            "next_update_at": _iso(st["next_update_at"]) if st["next_update_at"] else _iso(now),
                            "prefix_count": st["prefix_count"]})
    write_json(gsb / "state.json", {"schema": 1, "lists": entries})
    keep = {e["file"] for e in entries}
    for p in gsb.glob("*.prefixes"):
        if p.name not in keep:
            try:
                p.unlink()
            except OSError:
                pass


COMMANDS["update"] = cmd_update
```

Mind one subtle point about a `partialUpdate` with neither additions nor removals and no checksum ("no change"). `apply_list_update` returns `old` unchanged, and `_verify` accepts it.

- [ ] **Step 5: Run tests**

Run: `python3 -m unittest tests.test_reputation_companion -v && python3 -m unittest discover -s tests`
Expected: PASS. The TLS test is skipped where `openssl` is missing.

- [ ] **Step 6: Commit**

```bash
git add actualis_reputation.py tests/_reputation.py tests/test_reputation_companion.py
git commit -m "actualis-reputation update: Safe Browsing list download with Rice decoding and checksums

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: `confirm` (hash-prefix lookup with decoys)

**Files:**
- Modify: `actualis_reputation.py`
- Test: `tests/test_reputation_companion.py`

**Interfaces:**
- Consumes: `read_report`, `Http`, `NetSession`, `_b64`, `parse_duration`, `write_json`, `af._confirmation_fresh`.
- Produces: `make_decoys(real: set[bytes], total: int) -> list[bytes]`; `cmd_confirm(args, ctx) -> int`. It writes `gsb/confirmations.json` (`schema: 1`, `entries: [{prefix, full_hashes: [{hash, threat_types, canary}], confirmed_at, cache_until}]`), the format Task 2's loader reads.

- [ ] **Step 1: Write the failing tests**

```python
def net_json(path: Path, candidates=(), hosts=()) -> Path:
    path.write_text(json.dumps({"hosts": [{"host": h, "count": 1} for h in hosts],
                                "reputation": {"enabled": True, "candidates": [
                                    {"prefix_b64": R.b64(R.prefix(e)), "expressions": 1} for e in candidates],
                                    "totals": {"skipped": 2}}}))
    return path


class TestConfirm(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_GSB_KEY"] = FAKE_KEY
        R.write_cache(self.rep, {"mw-4b": [R.prefix("evil.example/"), R.prefix("odd.example/")]})

    def search(self, *full_hashes, cache="300s"):
        return {"fullHashes": [{"fullHash": R.b64(R.full(e)),
                                "fullHashDetails": [{"threatType": t, "attributes": attrs}]}
                               for e, t, attrs in full_hashes], "cacheDuration": cache}

    def test_sends_prefixes_and_decoys_never_hosts(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, self.search(("evil.example/", "MALWARE", [])))]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", ["evil.example/", "odd.example/"], hosts=["evil.example"])
        code, _, err = self.cli("confirm", str(nj), "--yes", http_factory=s.factory)
        self.assertEqual(code, 0, err)
        q = s.requests[0]["query"]["hashPrefixes"]
        self.assertEqual(len(q), 30)
        self.assertIn(R.b64(R.prefix("evil.example/")), q)
        self.assertNotIn("evil.example", json.dumps(s.requests))
        self.assertIn("run actualis again within 30 minutes", err)
        d = af.load_reputation(self.rep)
        now = datetime.now(timezone.utc)
        self.assertEqual(af.gsb_verdict("evil.example", "", d, now)["state"], "listed")
        self.assertEqual(af.gsb_verdict("odd.example", "", d, now)["state"], "not-listed")

    def test_decoy_hits_are_dropped(self):
        decoy_answer = {"fullHashes": [{"fullHash": R.b64(b"\x01\x02\x03\x04" + b"\0" * 28),
                                        "fullHashDetails": [{"threatType": "MALWARE"}]}], "cacheDuration": "300s"}
        s = R.FakeProvider({"/v5/hashes:search": [(200, decoy_answer)]})
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", ["evil.example/"])
        self.cli("confirm", str(nj), "--yes", http_factory=s.factory)
        conf = json.loads((self.rep / "gsb" / "confirmations.json").read_text())
        self.assertEqual([e["prefix"] for e in conf["entries"]], [R.b64(R.prefix("evil.example/"))])
        self.assertEqual(conf["entries"][0]["full_hashes"], [])

    def test_canary_is_stored_as_not_enforceable(self):
        s = R.FakeProvider({"/v5/hashes:search": [(200, self.search(("evil.example/", "MALWARE", ["CANARY"])))]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--yes", http_factory=s.factory)
        e = json.loads((self.rep / "gsb" / "confirmations.json").read_text())["entries"][0]
        self.assertEqual((e["full_hashes"][0]["threat_types"], e["full_hashes"][0]["canary"]), ([], True))

    def test_no_candidates_sends_nothing(self):
        s = R.FakeProvider()
        self.addCleanup(s.close)
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json")), "--yes", http_factory=s.factory)
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("no candidates", err)

    def test_report_without_reputation_is_a_usage_error(self):
        p = self.tmp / "n.json"
        p.write_text(json.dumps({"hosts": [], "reputation": {"enabled": False, "candidates": []}}))
        code, _, err = self.cli("confirm", str(p), "--yes")
        self.assertEqual(code, 2)
        self.assertIn("--reputation", err)

    def test_dry_run_lists_prefixes(self):
        code, _, err = self.cli("confirm", str(net_json(self.tmp / "n.json", ["evil.example/"])), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn(R.b64(R.prefix("evil.example/")), err)
        self.assertIn("29 random decoys", err)

    def test_many_candidates_are_chunked_under_1000(self):
        cands = [f"h{i}.example/" for i in range(1500)]
        s = R.FakeProvider({"/v5/hashes:search": [(200, {"cacheDuration": "300s"})]})
        self.addCleanup(s.close)
        self.cli("confirm", str(net_json(self.tmp / "n.json", cands)), "--yes", http_factory=s.factory)
        self.assertEqual(len(s.requests), 2)
        self.assertTrue(all(len(r["query"]["hashPrefixes"]) <= 1000 for r in s.requests))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_companion.TestConfirm -v`
Expected: FAIL with `invalid choice` / `KeyError: 'confirm'` (the command exists in the parser but not in `COMMANDS`).

- [ ] **Step 3: Implement**

```python
GSB_SEARCH_PATH = "/v5/hashes:search"
DECOY_TOTAL = 30
SEARCH_REAL_MAX = 970                            # + at least 30 decoys stays under Google's 1000


def make_decoys(real: "set[bytes]", total: int) -> "list[bytes]":
    out: set[bytes] = set()
    while len(out) < max(0, total - len(real)):
        d = secrets.token_bytes(4)
        if d not in real:
            out.add(d)
    return sorted(out)


def _candidates(net: dict) -> "list[bytes]":
    rep = net.get("reputation")
    if not isinstance(rep, dict) or not rep.get("enabled"):
        raise UsageError("this report has no reputation data; make it with actualis --network --reputation --json")
    out = set()
    for c in rep.get("candidates") or []:
        try:
            p = _b64(c.get("prefix_b64")) if isinstance(c, dict) else b""
        except ValueError:
            continue
        if len(p) == 4:
            out.add(p)
    return sorted(out)


def cmd_confirm(args, ctx) -> int:
    out, scrub = ctx["stderr"], ctx["scrub"]
    net = read_report(args.report, ctx["stdin"])
    real = _candidates(net)
    if not real:
        out.write(f"no candidates to confirm; {MARK} network used: nothing sent\n")
        return EXIT_OK
    chunks = [real[i:i + SEARCH_REAL_MAX] for i in range(0, len(real), SEARCH_REAL_MAX)]
    decoy_counts = [max(0, DECOY_TOTAL - len(c)) for c in chunks]
    skipped = (net.get("reputation") or {}).get("totals", {}).get("skipped", 0)
    disclose([("Provider", "Google Safe Browsing v5, hash-prefix lookup"),
              ("Sends", f"4-byte SHA-256 prefixes for {len(real)} candidate{'' if len(real) == 1 else 's'}, "
                        f"mixed with {sum(decoy_counts)} random decoys.\nGoogle never sees a host or URL."),
              ("Skips", f"{skipped} private or local hosts"),
              ("Never", "commands, paths, query strings, credentials, transcript text"),
              ("Key", "(not read: --dry-run)" if args.dry_run else
               ("--key-command (not shown)" if args.key_command else "$ACTUALIS_GSB_KEY (set, not shown)"))], out)
    if args.dry_run:
        for c, d in zip(chunks, decoy_counts):
            out.write(f"would send: {', '.join(base64.b64encode(p).decode() for p in c)} "
                      f"+ {d} random decoys\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    key = read_key("gsb", args.key_command, scrub)
    if not consent(f"Send {len(real)} lookup{'' if len(real) == 1 else 's'} to Google?", yes=args.yes,
                   dry_run=False, stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    now = ctx["now"]()
    entries: dict[str, dict] = {}
    with NetSession("confirm", "gsb", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            for chunk, nd in zip(chunks, decoy_counts):
                mine = set(chunk)
                sendable = chunk + make_decoys(mine, len(chunk) + nd)
                secrets.SystemRandom().shuffle(sendable)
                status, body = http.get(
                    GSB_HOST, GSB_SEARCH_PATH, headers={"X-Goog-Api-Key": key},
                    query=[("hashPrefixes", base64.b64encode(p).decode()) for p in sendable],
                    sent={"prefixes": len(chunk), "decoys": nd},
                    describe=f"sending {len(chunk)} lookup(s)")
                _gsb_status(status, body)
                try:
                    doc = json.loads(body or b"{}")
                    found = doc.get("fullHashes") or []
                    if not isinstance(found, list):
                        raise ValueError
                except (ValueError, AttributeError):
                    raise NetError("Safe Browsing sent a search response that is not JSON") from None
                until = now + timedelta(seconds=parse_duration(doc.get("cacheDuration")))
                by_prefix: dict[bytes, list] = {p: [] for p in chunk}
                for fh in found:
                    try:
                        h = _b64(fh.get("fullHash"))
                    except (ValueError, AttributeError):
                        continue
                    if len(h) != 32 or h[:4] not in mine:
                        continue                         # a decoy's answer, or junk: dropped
                    types, canary = set(), False
                    for det in fh.get("fullHashDetails") or []:
                        if not isinstance(det, dict) or not isinstance(det.get("threatType"), str):
                            continue
                        attrs = set(det.get("attributes") or [])
                        if "THREAT_ATTRIBUTE_UNSPECIFIED" in attrs:
                            continue
                        if "CANARY" in attrs:
                            canary = True
                            continue
                        types.add(det["threatType"])
                    by_prefix[h[:4]].append({"hash": base64.b64encode(h).decode(),
                                             "threat_types": sorted(types), "canary": canary})
                for p, hashes in by_prefix.items():
                    entries[base64.b64encode(p).decode()] = {
                        "prefix": base64.b64encode(p).decode(), "full_hashes": hashes,
                        "confirmed_at": _iso(now), "cache_until": _iso(until)}
        except NetError as exc:
            session.fail(str(exc))
            raise
        finally:
            if entries:
                _merge_confirmations(entries, now)
    listed = sum(1 for e in entries.values() if any(fh["threat_types"] for fh in e["full_hashes"]))
    out.write(f"{len(entries)} candidate(s) confirmed: {listed} listed. "
              f"Run actualis again within 30 minutes to see the result.\n")
    return EXIT_OK


def _merge_confirmations(new: dict, now: datetime) -> None:
    path = cache_root() / "gsb" / "confirmations.json"
    old = {}
    try:
        for p, e in af._load_confirmations(path).items():
            if now - e["confirmed_at"] < timedelta(hours=24):
                old[base64.b64encode(p).decode()] = {
                    "prefix": base64.b64encode(p).decode(),
                    "full_hashes": [{"hash": base64.b64encode(fh["hash"]).decode(),
                                     "threat_types": fh["threat_types"], "canary": fh["canary"]}
                                    for fh in e["full_hashes"]],
                    "confirmed_at": _iso(e["confirmed_at"]), "cache_until": _iso(e["cache_until"])}
    except (OSError, ValueError):
        old = {}
    old.update(new)
    write_json(path, {"schema": 1, "entries": [old[k] for k in sorted(old)]})


COMMANDS["confirm"] = cmd_confirm
```

Check `test_dry_run_lists_prefixes`: one candidate gives `DECOY_TOTAL - 1 = 29` decoys, matching "29 random decoys". The "Sends" line wording must contain `{n} random decoys`.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_reputation_companion -v && python3 -m unittest discover -s tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add actualis_reputation.py tests/test_reputation_companion.py
git commit -m "actualis-reputation confirm: prefix lookup with decoys, full-hash confirmations

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: `virustotal` (optional, online only)

**Files:**
- Modify: `actualis_reputation.py`
- Test: `tests/test_reputation_companion.py`

**Interfaces:**
- Consumes: `read_report`, `Http`, `NetSession`, `write_json`, `af.reputation_skip`, `af._host_canon`, `af.load_reputation` (for the existing `vt` results).
- Produces: `cmd_virustotal(args, ctx) -> int`. It writes `vt/results.json` (`schema: 1`, `vt_threshold`, `daily: {date, count}`, `results: [{host, stats, status, checked_at}]` sorted by host), the format Task 2's `_load_vt` reads. Constants `VT_PER_MINUTE = 4`, `VT_DAILY = 500`, `VT_RECHECK = timedelta(hours=24)`.

- [ ] **Step 1: Write the failing tests**

```python
def vt_body(m=0, s=0):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": m, "suspicious": s, "harmless": 60,
                                                             "undetected": 10, "timeout": 0}}}}


class TestVirusTotal(CompanionCase):
    def setUp(self):
        super().setUp()
        os.environ["ACTUALIS_VT_KEY"] = FAKE_KEY
        self.slept = []

    def run_vt(self, routes, hosts, *extra):
        s = R.FakeProvider(routes)
        self.addCleanup(s.close)
        nj = net_json(self.tmp / "n.json", hosts=hosts)
        code, out, err = self.cli("virustotal", str(nj), "--yes", *extra, http_factory=s.factory,
                                  sleep=self.slept.append)
        return code, err, s

    def test_found_unknown_and_threshold(self):
        code, err, s = self.run_vt({"/api/v3/domains/bad.example": [(200, vt_body(5))],
                                    "/api/v3/domains/new.example": [(404, {"error": {"code": "NotFoundError"}})]},
                                   ["bad.example", "new.example"], "--vt-threshold", "3")
        self.assertEqual(code, 0, err)
        self.assertEqual(s.requests[0]["headers"]["x-apikey"], FAKE_KEY)
        d = af.load_reputation(self.rep)
        self.assertEqual(d.vt_threshold, 3)
        self.assertEqual(d.vt["bad.example"]["stats"]["malicious"], 5)
        self.assertEqual(d.vt["new.example"]["status"], "unknown")

    def test_private_hosts_never_sent(self):
        code, err, s = self.run_vt({}, ["10.0.0.1", "printer.local", "intranet", "db.internal"])
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("no public hosts", err)

    def test_throttled_to_four_a_minute(self):
        hosts = [f"h{i}.example" for i in range(6)]
        self.run_vt({f"/api/v3/domains/{h}": [(200, vt_body())] for h in hosts}, hosts)
        self.assertEqual(self.slept, [15.0] * 5)

    def test_429_stops_and_keeps_what_was_checked(self):
        code, err, s = self.run_vt({"/api/v3/domains/a.example": [(200, vt_body())],
                                    "/api/v3/domains/b.example": [(429, {"error": {"code": "QuotaExceededError"}})]},
                                   ["a.example", "b.example", "c.example"])
        self.assertEqual(code, 1)
        self.assertIn("quota", err)
        self.assertEqual(len(s.requests), 2)
        self.assertIn("a.example", af.load_reputation(self.rep).vt)

    def test_recently_checked_hosts_are_skipped(self):
        R.write_cache(self.rep, vt=[R.vt_result("a.example", 0)])
        code, err, s = self.run_vt({"/api/v3/domains/b.example": [(200, vt_body())]}, ["a.example", "b.example"])
        self.assertEqual([r["path"] for r in s.requests], ["/api/v3/domains/b.example"])

    def test_dry_run_prints_hostnames_and_sends_nothing(self):
        s = R.FakeProvider()
        self.addCleanup(s.close)
        code, _, err = self.cli("virustotal", str(net_json(self.tmp / "n.json", hosts=["bad.example"])),
                                "--dry-run", http_factory=s.factory)
        self.assertEqual((code, s.requests), (0, []))
        self.assertIn("bad.example", err)
        self.assertIn("in plain text to VirusTotal", err)

    def test_ip_uses_the_ip_endpoint(self):
        code, err, s = self.run_vt({"/api/v3/ip_addresses/8.8.8.8": [(200, vt_body())]}, ["8.8.8.8"])
        self.assertEqual([r["path"] for r in s.requests], ["/api/v3/ip_addresses/8.8.8.8"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_companion.TestVirusTotal -v`
Expected: FAIL with `KeyError: 'virustotal'`.

- [ ] **Step 3: Implement**

```python
VT_PER_MINUTE = 4
VT_DAILY = 500
VT_RECHECK = timedelta(hours=24)


def _public_hosts(net: dict) -> "tuple[list[str], int]":
    hosts, skipped = set(), 0
    for h in net.get("hosts") or []:
        name = h.get("host") if isinstance(h, dict) else None
        if not isinstance(name, str):
            continue
        canon = af._host_canon(name)
        if canon is None or canon != name.lower() or af.reputation_skip(canon):
            skipped += 1
            continue
        hosts.add(canon)
    return sorted(hosts), skipped


def _vt_doc() -> dict:
    path = cache_root() / "vt" / "results.json"
    try:
        raw = af._read_cache_file(path)
        doc = json.loads(raw) if raw else None
    except (OSError, ValueError):
        doc = None
    if not isinstance(doc, dict) or doc.get("schema") != 1:
        doc = {"schema": 1, "vt_threshold": 2, "daily": {"date": "", "count": 0}, "results": []}
    return doc


def cmd_virustotal(args, ctx) -> int:
    out, scrub, now, sleep = ctx["stderr"], ctx["scrub"], ctx["now"](), ctx["sleep"]
    net = read_report(args.report, ctx["stdin"])
    hosts, skipped = _public_hosts(net)
    doc = _vt_doc()
    results = {r["host"]: r for r in doc["results"] if isinstance(r, dict) and isinstance(r.get("host"), str)}
    today = now.date().isoformat()
    used = doc["daily"].get("count", 0) if doc["daily"].get("date") == today else 0
    recent = {h for h, r in results.items()
              if (lambda at: at is not None and now - at < VT_RECHECK)(af._parse_utc(r.get("checked_at")))}
    todo = [h for h in hosts if h not in recent]
    plan = todo[:max(0, VT_DAILY - used)]
    if not plan:
        why = "no public hosts to look up" if not hosts else (
            "every host was checked in the last 24 hours" if not todo else "today's VirusTotal budget is used up")
        out.write(f"{why}; {MARK} network used: nothing sent\n")
        return EXIT_OK
    minutes = math.ceil(len(plan) / VT_PER_MINUTE)
    disclose([("Provider", "VirusTotal v3, domain and IP reports"),
              ("Sends", f"{len(plan)} hostname{'' if len(plan) == 1 else 's'} in plain text to VirusTotal, "
                        f"which may keep them.\nFree tier: about {minutes} minute{'' if minutes == 1 else 's'} "
                        f"at {VT_PER_MINUTE} a minute."),
              ("Skips", f"{skipped} private or local hosts, {len(hosts) - len(todo)} checked in the last 24 h"),
              ("Never", "URLs, paths, commands, credentials, transcript text"),
              ("Key", "(not read: --dry-run)" if args.dry_run else
               ("--key-command (not shown)" if args.key_command else "$ACTUALIS_VT_KEY (set, not shown)"))], out)
    if args.dry_run:
        for h in plan:
            out.write(f"would send: {h}\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    key = read_key("vt", args.key_command, scrub)
    if not consent(f"Send {len(plan)} hostname{'' if len(plan) == 1 else 's'} to VirusTotal?", yes=args.yes,
                   dry_run=False, stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    checked = 0
    with NetSession("virustotal", "vt", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            for i, host in enumerate(plan):
                if i:
                    sleep(60.0 / VT_PER_MINUTE)
                kind = "ip_addresses" if af._SB_IPV4.fullmatch(host) else "domains"
                status, body = http.get(VT_HOST, f"/api/v3/{kind}/{host}", headers={"x-apikey": key},
                                        sent={"hostnames": [host]}, describe=f"looking up {host}")
                used += 1
                if status == 429:
                    raise NetError(f"VirusTotal quota reached after {checked} of {len(plan)} hosts; "
                                   f"the rest can be checked later")
                if status in (401, 403):
                    raise NetError(f"VirusTotal answered HTTP {status}: the key was rejected")
                if status == 404:
                    results[host] = {"host": host, "status": "unknown", "stats": {}, "checked_at": _iso(now)}
                elif status == 200:
                    try:
                        stats = json.loads(body)["data"]["attributes"]["last_analysis_stats"]
                        stats = {k: int(stats.get(k, 0)) for k in
                                 ("malicious", "suspicious", "harmless", "undetected", "timeout")}
                    except (ValueError, KeyError, TypeError):
                        raise NetError(f"VirusTotal sent a report for {host} that is not readable") from None
                    results[host] = {"host": host, "status": "found", "stats": stats, "checked_at": _iso(now)}
                else:
                    raise NetError(f"VirusTotal answered HTTP {status} for {host}")
                checked += 1
        except NetError as exc:
            session.fail(str(exc))
            raise
        finally:
            write_json(cache_root() / "vt" / "results.json",
                       {"schema": 1, "vt_threshold": args.vt_threshold, "daily": {"date": today, "count": used},
                        "results": [results[h] for h in sorted(results)]})
    out.write(f"{checked} host(s) checked on VirusTotal. Run actualis --network --reputation to see the result.\n")
    return EXIT_OK


COMMANDS["virustotal"] = cmd_virustotal
```

Every test in this task runs with its own server and `sleep=self.slept.append`, so nothing really waits. `test_found_unknown_and_threshold` passes `--vt-threshold 3`, and that value is what `results.json` stores.

Note that `af.load_reputation` is asked for `vt` data when no Safe Browsing lists exist. Task 2 moved `_load_vt` above the `state.json` read, so `d.vt` is populated with `status == "absent"`. `test_found_unknown_and_threshold` relies on this.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_reputation_companion -v && python3 -m unittest discover -s tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add actualis_reputation.py tests/test_reputation_companion.py
git commit -m "actualis-reputation virustotal: throttled domain reports, daily budget, cached results

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Tray badge while the companion uses the network (Go)

**Files:**
- Modify: `tray-go/main.go` (`setIcon`, `iconFor`, the embeds block, `main()` where goroutines start)
- Modify: `tray-go/icons/gen_icons.py` (add the `network` state)
- Create: `tray-go/icons/network-dark.png`, `tray-go/icons/network-light.png` (generated)
- Create: `tray-go/netuse.go`, `tray-go/netuse_unix.go`, `tray-go/netuse_windows.go`, `tray-go/netuse_test.go`

**Interfaces:**
- Consumes: the companion's `in-flight.json` at the reputation cache root: `{"pid": int, "provider": "gsb"|"vt", "started_at": RFC 3339}`.
- Produces: `reputationDir() string`; `netInFlight(dir string, now time.Time) bool`; the tray shows the `network` icon while the companion runs and returns to the underlying state afterwards; tooltip `actualis-reputation is using the network`.

- [ ] **Step 1: Write the failing Go test** `tray-go/netuse_test.go`

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeInFlight(t *testing.T, dir string, pid int, at time.Time) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"pid": pid, "provider": "gsb", "started_at": at.UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, "in-flight.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNetInFlight(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if netInFlight(dir, now) {
		t.Fatal("no marker should mean no network use")
	}
	writeInFlight(t, dir, os.Getpid(), now.Add(-time.Minute))
	if !netInFlight(dir, now) {
		t.Fatal("a live process with a fresh marker is network use")
	}
	writeInFlight(t, dir, os.Getpid(), now.Add(-2*time.Hour))
	if netInFlight(dir, now) {
		t.Fatal("a marker older than an hour is stale")
	}
	os.WriteFile(filepath.Join(dir, "in-flight.json"), []byte("{bad"), 0o600)
	if netInFlight(dir, now) {
		t.Fatal("a malformed marker is ignored")
	}
}

func TestReputationDirFollowsActualis(t *testing.T) {
	t.Setenv("ACTUALIS_REPUTATION_DIR", "/x/rep")
	if got := reputationDir(); got != "/x/rep" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("ACTUALIS_REPUTATION_DIR", "")
	t.Setenv("XDG_CACHE_HOME", "/x/cache")
	if got := reputationDir(); got != filepath.Join("/x/cache", "actualis", "reputation") && os.Getenv("LOCALAPPDATA") == "" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd tray-go && go test ./... -run 'TestNetInFlight|TestReputationDir'`
Expected: FAIL. `undefined: netInFlight`.

- [ ] **Step 3: Implement**

`tray-go/netuse.go`:

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// reputationDir is where actualis-reputation keeps its cache; the same
// resolution as actualis.py's reputation_dir().
func reputationDir() string {
	if d := os.Getenv("ACTUALIS_REPUTATION_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "actualis", "reputation")
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "actualis", "reputation")
}

// netInFlight reports whether actualis-reputation is using the network now:
// its in-flight marker exists, is under an hour old, and names a live process.
func netInFlight(dir string, now time.Time) bool {
	b, err := os.ReadFile(filepath.Join(dir, "in-flight.json"))
	if err != nil || len(b) > 4096 {
		return false
	}
	var m struct {
		PID       int    `json:"pid"`
		StartedAt string `json:"started_at"`
	}
	if json.Unmarshal(b, &m) != nil || m.PID <= 0 {
		return false
	}
	at, err := time.Parse(time.RFC3339, m.StartedAt)
	if err != nil || now.Sub(at) > time.Hour || at.After(now.Add(time.Minute)) {
		return false
	}
	return processAlive(m.PID)
}

// netUse holds the badge: while active, setIcon shows "network" and
// remembers the state underneath, which comes back when the run ends.
var netUse struct {
	sync.Mutex
	active bool
	under  string
}

func watchNetworkUse() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		on := netInFlight(reputationDir(), time.Now())
		netUse.Lock()
		changed := on != netUse.active
		if changed && on {
			iconState.Lock()
			netUse.under = iconState.name
			iconState.Unlock()
		}
		netUse.active = on
		under := netUse.under
		netUse.Unlock()
		if !changed {
			continue
		}
		if on {
			setIcon("network")
			systray.SetTooltip("actualis-reputation is using the network")
		} else {
			setIcon(under)
			systray.SetTooltip("actualis")
		}
	}
}
```

`systray` is whatever package `main.go` imports under that name. Use the same import path, and check what tooltip text `main.go` sets normally. Restore that text instead of the literal `"actualis"` if it differs (grep `SetTooltip`).

`tray-go/netuse_unix.go`:

```go
//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
```

`tray-go/netuse_windows.go`:

```go
//go:build windows

package main

// Windows has no signal-0 probe; the marker's one-hour age limit bounds a
// stale badge after a crash.
func processAlive(pid int) bool { return pid > 0 }
```

In `setIcon`, at the top:

```go
	netUse.Lock()
	if netUse.active && state != "network" {
		netUse.under = state
		netUse.Unlock()
		return
	}
	netUse.Unlock()
```

A report refresh during a run then updates the remembered state without removing the badge.

Embeds and `iconFor`:

```go
//go:embed icons/network-dark.png
var iconNetDark []byte

//go:embed icons/network-light.png
var iconNetLight []byte
```

```go
	case "network":
		onDark, onLight = iconNetDark, iconNetLight
```

Start the goroutine wherever `watchAppearance` is started: `go watchNetworkUse()`.

`gen_icons.py`: add `"network"` to `STATES`. In `shapes_for(state, ink)`, add a branch that draws the idle A-mark plus a small amber badge in the lower-right corner: a ring (the globe) with one horizontal and one vertical arc, and a "+" to its upper left. Use the existing helpers `ring`, `seg` and `disc`. Size it like the MONITORING dots (radius about `0.17 * cap`), and keep the stroke at `STROKE * cap * 0.6`. Read `shapes_for` first and follow how MONITORING adds its dots. Then run `cd tray-go/icons && python3 gen_icons.py` and confirm `network-dark.png` and `network-light.png` exist and look right (open them with the Read tool).

- [ ] **Step 4: Run Go tests and build**

Run: `cd tray-go && go vet ./... && go test ./... && go build ./...`
Expected: PASS and builds.

- [ ] **Step 5: Commit**

```bash
git add tray-go/
git commit -m "Tray: network badge while actualis-reputation runs

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Documentation, badge, changelog

**Files:**
- Create: `docs/reputation.md`, `docs/img/reputation-badge.svg`
- Modify: `README.md` (line 15 "No account, no config file, no network", line ~516 "Nothing leaves your machine. No network calls", line ~808, plus a new section), `docs/json.md`, `docs/findings.md` (the Network findings table), `CHANGELOG.md`, `actualis.py` `EXPLAIN` (optional topic, see Step 4)
- Test: `tests/test_reputation_cli.py` (docs assertions)

**Interfaces:**
- Consumes: the final CLI, JSON and finding names from Tasks 3 to 8.
- Produces: user documentation. The README never describes a flag that does not exist.

- [ ] **Step 1: Write the failing docs test** (append to `tests/test_reputation_cli.py`)

```python
class TestDocs(unittest.TestCase):
    def test_reputation_doc(self):
        doc = (ROOT / "docs" / "reputation.md").read_text(encoding="utf-8")
        for needle in ("Advisory provided by Google", "non-commercial", "Web Risk", "false positive",
                       "false negative", "ACTUALIS_GSB_KEY", "ACTUALIS_VT_KEY", "--key-command",
                       "```mermaid", "sequenceDiagram", "stateDiagram-v2", "flowchart",
                       "actualis-reputation update", "actualis-reputation confirm",
                       "actualis-reputation virustotal", "30 minutes", "7 days", "[+net]", "--dry-run",
                       "--receipt", "Restrict the key"):
            self.assertIn(needle, doc, needle)

    def test_readme(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Optional: host reputation (uses the network)", readme)
        self.assertIn("actualis never uses the network. The optional `actualis-reputation` command does, "
                      "only when you run it, and tells you what it sends.", readme)
        self.assertIn("docs/reputation.md", readme)

    def test_findings_and_json_docs(self):
        findings = (ROOT / "docs" / "findings.md").read_text(encoding="utf-8")
        for cat in af.REPUTATION_FLAG_CATEGORIES:
            self.assertIn(f"`{cat}`", findings)
        jdoc = (ROOT / "docs" / "json.md").read_text(encoding="utf-8")
        self.assertIn("network.reputation", jdoc)
        self.assertIn("network.items[].reputation", jdoc)

    def test_changelog(self):
        self.assertIn("actualis-reputation", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reputation_cli.TestDocs -v`
Expected: FAIL. `FileNotFoundError: … docs/reputation.md`.

- [ ] **Step 3: Write `docs/reputation.md`**

Write it in plain, direct prose, matching `docs/ioc.md`'s voice. Read `docs/ioc.md` first. Required sections, in order:

1. **What it is**: two programs; actualis never uses the network; the companion does only when run. Show the `⊕🌐` mark and its `[+net]` fallback, plus the badge image (`![network badge](img/reputation-badge.svg)`).
2. **Set up Google Safe Browsing**: create a Google Cloud project; enable "Safe Browsing API"; Credentials, then Create credentials, then API key; **Restrict the key** to the Safe Browsing API (API restrictions); store it in a password manager. Run with `ACTUALIS_GSB_KEY` or `--key-command "op read op://Vault/Item/credential"`. Explain why `--key-command` is preferred (no shell history, never on the command line).
3. **Set up VirusTotal (optional)**: create an account, copy the API key from the profile, `ACTUALIS_VT_KEY`. Free tier: 4 a minute, 500 a day. It sends hostnames in plain text.
4. **Everyday use**: `actualis-reputation update` (daily or in CI), `actualis --network --reputation`, then `actualis --network --reputation --json > net.json && actualis-reputation confirm net.json && actualis --network --reputation --fail-on high` (within 30 minutes). Add a CI example (GitHub Actions step, with `--yes` and the key from a secret) and `status`/`forget`.
5. **What is sent and what is not**: a table per command (update: nothing about your hosts; confirm: 4-byte prefixes and decoys; virustotal: hostnames). Never: URLs, paths, query strings, commands, credentials, transcript text, the key in a URL. Private hosts are skipped (list the rules from `reputation_skip`).
6. **Seeing network use**: the disclosure block (copy spec §6.2), consent, `--dry-run`, `--receipt`, the live line and the closing line, `network-log.jsonl`, the `--self-check` line, the tray badge.
7. **How the verdicts work**: the table from spec §5.2 (with the `suspicious` ruling); the 30-minute rule and why (Google's terms); the 7-day staleness; "is currently listed" wording.
8. **Architecture**: the mermaid flowchart from spec §3.
9. **Sequences**: the four mermaid sequence diagrams from spec §7.
10. **State machines**: the three mermaid state diagrams from spec §8.
11. **Cache files**: the table from spec §4, with the checksum-named prefix files (ruling 2) and `in-flight.json`.
12. **Accuracy**: false positives and false negatives in plain words. Lists can be wrong both ways; a listing is about now, not about when the agent reached the host; no result is not proof of safety.
13. **Licensing and attribution**: Safe Browsing API is non-commercial only (commercial users: Google Web Risk); VirusTotal public API is non-commercial with its own terms (link https://docs.virustotal.com/reference/public-vs-premium-api). "Advisory provided by Google" with the link. Threat types link to https://developers.google.com/safe-browsing/reference/rest/v5/hashList#ThreatType (verify the URL resolves when writing).
14. **Troubleshooting**: HTTP 403 (API not enabled or key restricted to the wrong API), 429 (quota), "lists are current", corrupt lists (run `update` again), a proxy (`HTTPS_PROXY` is honoured), no terminal (`--yes`).

Copy the diagrams from the spec verbatim, then adjust two details: file names (ruling 2) and the `skipped`/`suspicious` states.

- [ ] **Step 4: README, json.md, findings.md, badge, changelog, explain**

README:
- Line 15: change "no network" so the sentence stays true. For example: "No account, no config file, no network: actualis never uses the network. The optional `actualis-reputation` command does, only when you run it, and tells you what it sends." The test asserts the second and third sentences verbatim, so keep them exact.
- Line ~516 ("Nothing leaves your machine…") and line ~808: add the same qualifier ("actualis itself…; see Optional: host reputation") without weakening the core claim.
- New section `## Optional: host reputation (uses the network)`, placed after the IOC section, with the badge image, a five-line explanation, the three commands, the disclosure block example, and a link to `docs/reputation.md`.

`docs/json.md`: document `network.items[].reputation` (every field and the state values `none, candidate, listed, not-listed, suspicious, unknown, skipped`) and `network.reputation` (every field), stating they are additive under `schema_version` 1.

`docs/findings.md`: add four rows to the Network findings table:

```markdown
| `reputation-listed` | high | `--reputation`: a host is currently listed by Google Safe Browsing (confirmed within 30 minutes) or flagged malicious by at least `--vt-threshold` VirusTotal engines | `high`, `any` |
| `reputation-candidate` | med | `--reputation`: a host's hash prefix is in the local Safe Browsing lists but not confirmed; run `actualis-reputation confirm` | `any` |
| `reputation-suspicious` | med | `--reputation`: VirusTotal engines flagged the host below the threshold, or as suspicious | `any` |
| `reputation-stale` | med | `--reputation`: the Safe Browsing lists are over 7 days old | `any` |
```

`docs/img/reputation-badge.svg`: a small (64×64 viewBox) SVG. The actualis "A" mark in carbon `#0B0C0E` (in the style of the tray: two legs and a short amber `#E08A24` dash), plus an amber circle badge in the lower-right holding a "+" and a simple globe (a circle with one meridian ellipse and one equator line). Plain paths, no fonts, no scripts, under 2 KB. Check it renders with the Read tool.

`CHANGELOG.md`: add an `## Unreleased` section at the top (the release task dates it as 0.5.0):

```markdown
## Unreleased

### Added
- `actualis-reputation`, an optional companion command and the only part of actualis that uses the network.
  `update` downloads Google Safe Browsing threat lists; `confirm` checks local matches with 4-byte hash
  prefixes mixed with decoys; `virustotal` looks hostnames up on VirusTotal (opt in; sends hostnames).
  Every run says what it will send, asks first (`--yes` in CI), shows ⊕🌐 while a request is in flight,
  and records what it did (`--receipt`, `network-log.jsonl`). Keys come from `ACTUALIS_GSB_KEY` /
  `ACTUALIS_VT_KEY` or `--key-command`, never an argument. See docs/reputation.md.
- `actualis --reputation`: matches the network inventory against the local reputation cache, offline.
  New findings `reputation-listed` (high), `reputation-candidate`, `reputation-suspicious`,
  `reputation-stale` (medium). `--reputation --fail-on` with no usable lists exits 2.
- `--json`: `network.items[].reputation` and `network.reputation` (additive; schema_version stays 1).
- `--self-check` reports when actualis-reputation last used the network.
- Tray: a network badge while actualis-reputation runs.
```

`EXPLAIN` in `actualis.py`: if `EXPLAIN` has a `network` topic, add a `reputation` topic in the same shape (three to six short paragraphs: offline matching, candidate vs listed, freshness, where the cache is, `jq '.network.reputation.totals'`). If tests require `EXPLAIN` keys to match a documented list, update that list. If this grows past 30 lines, skip it and note that in the report.

- [ ] **Step 5: Run tests**

Run: `python3 -m unittest discover -s tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/ CHANGELOG.md actualis.py tests/test_reputation_cli.py
git commit -m "Docs: host reputation setup, diagrams, attribution, findings and JSON fields

Refs #67

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Verification, security scan, manual acceptance with the real key

**Files:**
- No code unless a check fails. Fixes go in their own commits.

**Interfaces:**
- Consumes: the whole branch.
- Produces: a green suite, a clean `make security-remote`, and a recorded manual run.

- [ ] **Step 1: Full suite on this machine, both Python ends**

```bash
python3 -m unittest discover -s tests
uv run --python 3.9 python -m unittest discover -s tests
cd tray-go && go test ./... && cd ..
```

Expected: all PASS. A failure is fixed and committed before going on.

- [ ] **Step 2: Import allowlists, as CI runs them**

```bash
python3 -c "import actualis as a, pathlib; print(a.imports_in(pathlib.Path('actualis.py').read_text()))"
python3 -c "import actualis as a, pathlib; print(a.imports_in(pathlib.Path('actualis_reputation.py').read_text()))"
python3 actualis.py --self-check --root "$(mktemp -d)" | grep -E "networking module|network:"
```

Expected: the core list is unchanged, and the self-check passes "no networking module is imported by this build".

- [ ] **Step 3: Security scan on the build server**

Run: `make security-remote`
Expected: exit 0. Read `security-out/`. A bandit finding in `actualis_reputation.py` is either fixed or marked `# nosec` with a reason. A gitleaks or trufflehog hit on a test fixture means a fixture looks like a real key: change the fixture (`FAKE_KEY` is deliberately not key-shaped beyond `AIza`; if gitleaks flags it, drop the `AIza` prefix), never the allowlist.

- [ ] **Step 4: Build the wheel and check both entry points**

```bash
uv build
python3 -m venv /tmp/rep-venv && /tmp/rep-venv/bin/pip install dist/actualis-*.whl
/tmp/rep-venv/bin/actualis --version && /tmp/rep-venv/bin/actualis-reputation --version
/tmp/rep-venv/bin/actualis-reputation status
```

Use the session scratchpad instead of `/tmp`. Expected: both print the version, and `status` prints the cache path and "absent".

- [ ] **Step 5: Manual acceptance with the maintainer's real keys**

The key must never pass through the agent. The user runs these in the session with the `!` prefix, choosing the 1Password reference. The Private vault has no service account, so the desktop app will prompt them:

```
! actualis-reputation update --key-command "op read op://Private/<item>/credential"
! actualis-reputation status
! actualis --network --reputation --days 30
! actualis --network --reputation --json --days 30 > "$TMPDIR/net.json"
! actualis-reputation confirm "$TMPDIR/net.json" --dry-run
! actualis-reputation confirm "$TMPDIR/net.json" --key-command "op read op://Private/<item>/credential" --receipt "$TMPDIR/receipt.json"
! actualis --network --reputation --days 30 --fail-on high; echo "exit $?"
! actualis --self-check | grep network
```

Run them from the worktree with `python3 actualis.py …` and `python3 actualis_reputation.py …` if the wheel is not installed. Check and record in the PR description:
- `update` showed the disclosure, asked, printed the live line and "network used: 1 request…", and `status` shows five lists with plausible counts. **If the first real update fails its checksum twice, the checksum interpretation (sorted 4-byte prefixes, concatenated, SHA-256) or the byte order is wrong. Stop and investigate with a receipt; do not loosen the check.**
- The receipt has no key: `grep -c "AIza" "$TMPDIR/receipt.json"` prints 0.
- Optionally, VirusTotal: `! actualis-reputation virustotal "$TMPDIR/net.json" --dry-run`, then a real run on a small `--days 1` report.
- The tray shows the network badge during `update` (if the tray is running).

Aggregate-only checks of the real corpus are allowed (counts, exit codes). Do not paste transcript content or host lists into the PR.

- [ ] **Step 6: Hand off**

Use superpowers:finishing-a-development-branch. Push and open the PR only with the user's go-ahead. The PR body carries `Closes #67`, the rulings list from this plan, the manual-acceptance results, and the attribution line.

---

### Task 12: Release 0.5.0 (only after the PR is merged, with the user's go-ahead)

Not part of implementation. Listed so nothing is forgotten. Follow the established release flow:

1. Branch from main: bump `__version__` in `actualis.py` and `version` in `pyproject.toml` to `0.5.0`; rename `## Unreleased` to `## 0.5.0 (YYYY-MM-DD)`. PR, merge.
2. Tag `v0.5.0` on the merge commit and push the tag. `release.yml` publishes to PyPI via Trusted Publishing; confirm the run is green and `pip install actualis==0.5.0` works.
3. Homebrew tap: `python3 tools/brew-formula.py 0.5.0` (now with two wrappers); PR to `digital-foundry/homebrew-tap`; merge; `brew upgrade actualis && actualis-reputation --version`.
4. actualis-site: release page `/releases/0-5/` with the badge and the setup summary; PR; then `make deploy` from a synced checkout (retry once on "Not authorized").
5. Close or update actualis-pro #78 (superseded by this work).
6. Draft the community-voice LinkedIn post for the user to publish. Never post it.
