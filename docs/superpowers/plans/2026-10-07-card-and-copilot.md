# `--card` and Copilot CLI Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship v0.2.0: Actualis reads GitHub Copilot CLI sessions, and `actualis --card` writes a shareable 1200×630 SVG + PNG card that carries nothing identifying.

**Architecture:** Everything stays in the single file `actualis.py`. The Copilot reader is a third ingest path beside Claude Code and Codex, and it feeds the same `Fleet` counters. The card pipeline is `Fleet → card_model() → layout_hero()/layout_terminal() → [draw ops] → op_rects() → svg_text() / png_bytes()`. Both writers consume `op_rects()` and nothing else, so the SVG and the PNG match pixel for pixel. Only `card_model()` reads `Fleet`, so the leak test checks one place.

**Tech Stack:** Python 3.9+ standard library only (`zlib`, `struct`, `json`, `re`), `unittest`. The font is Spleen 2.2.0 8×16 (BSD-2-Clause), embedded as hex.

**Spec:** `docs/superpowers/specs/2026-10-07-card-and-copilot-design.md`. Read it before starting any task.

## Global Constraints

- Local, read-only, no network. `--self-check` must keep passing.
- Single file, no third-party dependencies, Python 3.9+, AGPL-3.0.
- Nothing identifying may reach shareable output. The existing `--share` leak test is the enforcement mechanism and is extended, not replaced.
- Credentials are never on the card, in any mode or style. There is no flag to add them.
- Canvas 1200×630, dark palette only: bg `#0d1117`, fg `#e6edf3`, muted `#8b949e`, rule `#30363d`, accent `#f0883e`.
- `--card` never overwrites. If either file exists, both get the next free suffix (`actualis-card-2.svg` / `actualis-card-2.png`).
- These two files are the only new writes. `--self-check` names the card output path as the second write path.
- Copilot `session.db` is **not** read. Only `events.jsonl`.
- Gemini CLI is out of scope.
- Python 3.9: no `match`, no `Path.write_text(newline=...)` (3.10+). Use `path.open("w", encoding="utf-8", newline="\n")`.
- Run the whole suite with `python3 -m unittest discover -s tests -q`. Run one file with `python3 -m unittest discover -s tests -p 'test_card.py' -v`. Add `-k <name>` to run one test.
- End every commit message with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Where this plan departs from the spec, and why

Each change below came from checking the spec against the code or against 17 real Copilot sessions while writing this plan.

1. **Supervision is per command, not per turn.** `render_share` divides by permission-mode *records* (turns), but the card's hero claims "% of shell commands". Task 1 records the mode in force at each shell command. A third counter, `bash_moded_by_day`, is the denominator, so a command whose mode was never recorded is neither supervised nor unsupervised.
2. **One definition of "unsupervised".** The spec says "the definition `render_share` uses", but `render_share` has a stale copy. The canonical one is `ungated_modes()`, which also counts `codex:never`. Task 1 extracts `is_ungated_mode()` from it. The card, `--share` and AISVS all use that one predicate.
3. **Copilot `inputTokens` already includes the cache tokens.** Measured on all 17 local sessions: `inputTokens ≈ cacheReadTokens + cacheWriteTokens + fresh`, and `reasoningTokens` is a subset of `outputTokens`. Fresh input is therefore `inputTokens − cacheReadTokens − cacheWriteTokens`. Copilot gives cache writes no TTL, so they are priced at `CACHE_WRITE_ASSUMED_MULT`, the same assumption a Claude record without a TTL split gets.
4. **Copilot writes Claude model ids with dots** (`claude-haiku-4.5`). The price table uses dashes. `copilot_model()` normalises them, or every Claude model under Copilot would be priced as a family guess.
5. **Project and branch come from `session.start.data.context` first.** Only 10 of 17 sessions have a `session.context_changed` event, and all 17 `session.start` events carry `context.gitRoot`, `cwd` and `branch`.
6. **Premium requests are fractional** (`0.33`, `3.96`). The counter is a float.
7. **The card's model-name gate is an exact match on the price table** (`model in PRICING`), not a family match. A family match would let `ft:gpt-5-acme-internal` through. `gpt-5-mini` therefore shows as `custom`.
8. **Command categories need the subcommand.** `command_head("npm test")` returns `npm`, so `command_category()` reads the token after the program. It runs at ingest, and only the four category names are stored.
9. **Copilot fixtures are written at test time** (`tests/_fixtures.py`), not committed under `tests/fixtures/`. That keeps the credential canary out of the tree as a literal string.
10. **The PNG is RGB (colour type 2), not RGBA.** The card is opaque, so an alpha channel would only add bytes.
11. **`AGENT_COMMANDS` already lists `("GitHub Copilot CLI", "copilot")`**, so nothing needs adding there.
12. **The SVG has no `<text>` nodes.** Every glyph is drawn as integer-aligned path runs. Nothing in the SVG can be searched or copied as text.

## Review Focus

These five input classes are the ones most likely to hurt a real user, and no other task's tests cover them. Each line names the task that owns its test.

1. **A malformed Copilot session directory:** no `events.jsonl`, a truncated last line, `data` that is not an object, or a `toolCallId` missing. The scan skips what it cannot read and never crashes. A bash call with no id counts as `copilot:auto`. *(Task 2, `test_malformed_sessions_are_skipped_not_fatal`)*
2. **A hero value wider than its column** (`$12,345,678`). It scales down. Every op stays inside the canvas, and the left column stays clear of the rule at x=856. *(Task 7, `test_extreme_values_stay_inside_their_columns`)*
3. **A stray `actualis-card.png` with no `.svg` beside it.** Both files are written as `-2`. An `--out` path that is not a directory exits 1 and writes nothing. *(Task 8, `test_one_existing_file_bumps_both` and `test_out_must_be_a_directory`)*
4. **A long window (`--days 365`).** The terminal sparkline is bucketed to at most 40 cells, and every hero sparkline point stays inside its box. *(Task 7, `test_long_windows_are_bucketed`)*
5. **A character the font does not have.** It renders as `?`. It never raises `KeyError`. *(Task 6, `test_unknown_glyph_falls_back`)*

---

## File Structure

| File | Responsibility |
|---|---|
| `actualis.py` (modify) | Everything shipped: counters, Copilot reader, card model, font, draw ops, writers, layouts and CLI. Follows the single-file constraint. Each feature gets its own `# ----` banner section, matching the file's existing style. |
| `tests/test_card.py` (create) | Per-command supervision, categories, card model, draw ops and writers, layouts, CLI, goldens and the card leak test. |
| `tests/test_copilot.py` (create) | Copilot reader, cost, supervision, refusals, replay, wiring and the vendor matrix. |
| `tests/_fixtures.py` (create) | Synthetic Copilot sessions, plus an isolated `HOME` context manager. It is not a test module, because `discover` loads only `test*.py`. |
| `tests/test_actualis.py` (modify) | Update the two `VENDOR_CAPABILITIES` unpackings for the new 5-tuple. |
| `tests/goldens/` (create) | Six golden SVGs and one pixel sha256. |
| `tools/make-card-font.py` (create) | Reads Spleen's BDF and prints the `CARD_FONT` table. |
| `tools/make-card-images.py` (create) | Builds the demo fleet and renders all six cards. The goldens and the README images both come from it. |
| `tools/make-demo-fleet.py` (modify) | Optional second argument that writes two invented Copilot sessions. |
| `README.md`, `CHANGELOG.md`, `docs/json.md` (modify) | Flags, agents table, the card section and the 0.2.0 entry. |

Test module header, shared by `tests/test_card.py` and `tests/test_copilot.py`. It reuses an already-loaded module, so both files see the same `actualis`:

```python
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest
import zlib
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    _spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(_spec)
    sys.modules["actualis"] = af
    _spec.loader.exec_module(af)
```

---

### Task 1: Per-command supervision, command categories, one ungated predicate

**Files:**
- Modify: `actualis.py`. Imports (lines 25–36); `Fleet.__init__` (~1383–1476); `add_usage` (~1480); `add_codex_session` (~1563); `_scan_codex_file` (~1602–1679); `add_tool` (~1746); `_scan_file` (~1843); `_ingest_claude` (~1881–1902); `scan_execution_log` (~1939); `render_share` (~4321–4324); `ungated_modes` (~5290)
- Create: `tests/test_card.py`

**Interfaces:**
- Consumes: `command_head(cmd) -> str | None`, `ungated_modes(modes) -> int`
- Produces:
  - `is_ungated_mode(key: str) -> bool`
  - `command_category(cmd: str) -> str`, which returns one of `"git" | "test" | "install" | "other"`
  - `Fleet.bash_by_day: Counter` (ISO date → shell commands)
  - `Fleet.bash_moded_by_day: Counter` (ISO date → commands whose mode is known)
  - `Fleet.unsupervised_by_day: Counter` (ISO date → commands in an ungated mode)
  - `Fleet.bash_categories: Counter` (category → count)
  - `Fleet.agents_seen: set[str]` (`"claude-code"`, `"codex"`, `"copilot"`)
  - `Fleet.add_tool(project, name, tool_input, ts, mode: str | None = None)`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_card.py` with the module header from *File Structure*, then:

```python
def _claude_dir(td, records):
    p = Path(td) / "proj"
    p.mkdir()
    (p / "s.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n",
                               encoding="utf-8")
    return Path(td)


class TestPerCommandSupervision(unittest.TestCase):
    """The card says "% of shell commands". --share counted turns. A command is
    supervised or not by the mode in force when it ran."""

    TS = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)

    def test_one_definition_of_ungated(self):
        for k in ("auto", "bypassPermissions", "codex:never", "copilot:auto"):
            with self.subTest(k=k):
                self.assertTrue(af.is_ungated_mode(k))
        for k in ("default", "plan", "acceptEdits", "codex:on-request",
                  "copilot:prompted", "sandbox:workspace-write"):
            with self.subTest(k=k):
                self.assertFalse(af.is_ungated_mode(k))

    def test_a_command_inherits_the_mode_recorded_before_it(self):
        recs = [
            {"timestamp": "2026-09-01T12:00:00Z", "type": "user", "permissionMode": "default",
             "message": {"role": "user", "content": "x"}},
            {"timestamp": "2026-09-01T12:00:01Z", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}}]}},
            {"timestamp": "2026-09-01T12:00:02Z", "type": "user",
             "permissionMode": "bypassPermissions",
             "message": {"role": "user", "content": "y"}},
            {"timestamp": "2026-09-01T12:00:03Z", "message": {"content": [
                {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "ls"}}]}},
        ]
        f = af.Fleet()
        with tempfile.TemporaryDirectory() as td:
            f.scan([_claude_dir(td, recs)], None, None, progress=False)
        self.assertEqual(f.bash_by_day["2026-09-01"], 2)
        self.assertEqual(f.bash_moded_by_day["2026-09-01"], 2)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)

    def test_a_mode_set_before_the_window_still_applies(self):
        recs = [
            {"timestamp": "2026-08-01T00:00:00Z", "type": "user", "permissionMode": "auto",
             "message": {"role": "user", "content": "x"}},
            {"timestamp": "2026-09-01T12:00:00Z", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}}]}},
        ]
        f = af.Fleet()
        since = datetime(2026, 8, 15, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            f.scan([_claude_dir(td, recs)], since, None, progress=False)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)
        self.assertNotIn("auto", f.permission_modes, "the out-of-window turn is not counted")

    def test_a_command_with_no_recorded_mode_is_in_neither_bucket(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, self.TS)
        self.assertEqual(f.bash_by_day["2026-09-01"], 1)
        self.assertEqual(f.bash_moded_by_day["2026-09-01"], 0)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 0)

    def test_codex_commands_carry_the_turn_policy(self):
        lines = [
            {"timestamp": "2026-09-01T12:00:00Z", "type": "turn_context",
             "payload": {"cwd": "/x/proj", "model": "gpt-5.2-codex",
                         "approval_policy": "never"}},
            {"timestamp": "2026-09-01T12:00:01Z", "type": "response_item",
             "payload": {"type": "function_call", "name": "shell_command",
                         "arguments": json.dumps({"command": "ls"})}},
        ]
        f = af.Fleet()
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "rollout-1.jsonl").write_text(
                "\n".join(json.dumps(r) for r in lines) + "\n", encoding="utf-8")
            f.scan_codex([Path(td)], None, None)
        self.assertEqual(f.unsupervised_by_day["2026-09-01"], 1)

    def test_share_uses_the_same_definition(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, self.TS)
        f.permission_modes.update({"codex:never": 1, "default": 1})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        self.assertIn("50% of turns ran unsupervised", buf.getvalue())

    def test_agents_seen(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1}, self.TS)
        f.add_codex_session("p", "gpt-5.2-codex", {"output_tokens": 1}, self.TS)
        self.assertEqual(f.agents_seen, {"claude-code", "codex"})


class TestCommandCategory(unittest.TestCase):
    """Four words is the only shape of a command a card shows. A program name
    can identify (`./acme-deploy`); a fixed vocabulary cannot."""

    CASES = {
        "git status": "git", "cd app && git push": "git",
        "pytest -q": "test", "python -m pytest tests": "test",
        "python3 -m unittest discover": "test", "npm test -- --run": "test",
        "npm run test:unit": "test", "go test ./...": "test", "cargo test": "test",
        "make test": "test",
        "npm i left-pad": "install", "pip install requests": "install",
        "uv pip install x": "install", "uv add httpx": "install",
        "brew install gh": "install", "sudo apt-get install jq": "install",
        "npm run build": "other", "ls -la": "other", "pip list": "other",
        "./acme-deploy --prod": "other", "": "other",
    }

    def test_categories(self):
        for cmd, want in self.CASES.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(af.command_category(cmd), want)

    def test_counted_at_ingest(self):
        f = af.Fleet()
        for cmd in ("git status", "pytest", "ls"):
            f.add_tool("p", "Bash", {"command": cmd}, None)
        self.assertEqual(f.bash_categories, {"git": 1, "test": 1, "other": 1})
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -v`
Expected: errors with `AttributeError: module 'actualis' has no attribute 'is_ungated_mode'` (and `bash_by_day` and `command_category`).

- [ ] **Step 3: Implement**

Add `date` to the datetime import, and add `struct` and `zlib` now (Task 6 uses them):

```python
import struct
import sys
import zlib
from collections import Counter, OrderedDict, defaultdict
from typing import NamedTuple
from datetime import date, datetime, timedelta, timezone
```

Replace `ungated_modes` (keep its docstring) and add the predicate above it:

```python
def is_ungated_mode(key: str) -> bool:
    """One permission-mode key that does not stop for approval.

    The single definition. ungated_modes, --share and --card all read it, so
    the three cannot disagree about what "unsupervised" means again.
    """
    k = key.lower()
    return "auto" in k or "bypass" in k or key == "codex:never"


def ungated_modes(modes: "Counter") -> int:
    """<existing docstring unchanged>"""
    return sum(v for k, v in modes.items() if is_ungated_mode(k))
```

In `render_share`, replace the two `unsup = sum(...)` lines with:

```python
    unsup = ungated_modes(fleet.permission_modes)
```

Add `command_category` directly after `command_head` (~line 1090):

```python
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
```

In `Fleet.__init__`, after `self.bash_first_token`:

```python
        # Shell commands per UTC date, and how many ran in a mode that does not
        # stop for approval. bash_moded_by_day is the denominator: a command
        # whose mode was never recorded is neither supervised nor unsupervised,
        # and guessing either way would bias the card's headline number.
        self.bash_by_day: Counter = Counter()
        self.bash_moded_by_day: Counter = Counter()
        self.unsupervised_by_day: Counter = Counter()
        self.bash_categories: Counter = Counter()
        self.agents_seen: set[str] = set()
        # The permission mode in force, carried across records within one file.
        self._mode: str | None = None
```

In `add_usage`, after `self.messages += 1`: `self.agents_seen.add("claude-code")`.
In `add_codex_session`, after `self.messages += 1`: `self.agents_seen.add("codex")`.

Change `add_tool`'s signature and count right after `self.bash_by_project[project] += 1`:

```python
    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                 mode: str | None = None) -> None:
        ...
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
```

In `_scan_file`, put `self._mode = None` immediately before `calls: dict[...] = {}`. In `scan_execution_log`, do the same before its `calls` line.

In `_ingest_claude`, replace the opening down to the `denial` line with:

```python
        ts = parse_ts(rec.get("timestamp"))
        mode = rec.get("permissionMode")
        if mode:
            # Stays in force for the tool calls that follow it, even when this
            # record is itself older than the window.
            self._mode = str(mode)
        if since and ts and ts < since:
            return

        if mode:
            self.permission_modes[mode] += 1
```

In the `tool_use` branch of `_ingest_claude`, pass the mode:

```python
                    self.add_tool(project, block.get("name") or "?",
                                  block.get("input") or {}, ts, self._mode)
```

In `_scan_codex_file`: declare `policy: str | None = None` beside `cwd = model = None`. In the `turn_context` branch, set `policy = f"codex:{pol}"` inside `if pol:`. Change `pending` to hold triples, `pending.append((cmd, ts, policy))`. Change the final loop to:

```python
        for cmd, ts, mode in pending:
            # Normalise Codex's shell_command onto the same "Bash" tool name the
            # Claude Code path uses, so the audit is one cross-agent view.
            self.add_tool(project, "Bash", {"command": cmd}, ts, mode)
```

and change its annotation to `pending: list[tuple[str, datetime | None, str | None]] = []`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -v`, then `python3 -m unittest discover -s tests -q`
Expected: all pass, and the existing suite still passes.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_card.py
git commit -m "feat: supervision per shell command, and one definition of ungated"
```

---

### Task 2: Copilot CLI reader and wiring

**Files:**
- Modify: `actualis.py`. After `codex_session_cost` (~1381): roots, cost and model normalisation. `Fleet`: counters, `add_copilot_session`, `scan_copilot`, `_scan_copilot_file`, and the `_record_refusal` refactor of `add_refusal` (~1681). `no_transcripts_message` (~1207). `dead_end_message` (~1297). `_jsonl_files` / `watch` / `_commands_in` (~2748–2890). `EXPLAIN["sources"]` (~2945). `self_check` / `_self_check_corpus` (~5079–5215). `build_parser` `--agent` (~5748). `main` watch and scan branches (~5858–5937).
- Create: `tests/_fixtures.py`, `tests/test_copilot.py`

**Interfaces:**
- Consumes: `Fleet.add_tool(..., mode)` and `Fleet.agents_seen` (Task 1); `rate_for`, `rates_for`, `pretty_project`, `extract_ticket`, `branch_bucket`, `clean`
- Produces:
  - `copilot_roots() -> list[Path]` (`$COPILOT_HOME` or `~/.copilot`, then `/session-state`)
  - `copilot_model(raw: str) -> str`
  - `copilot_session_cost(usage: dict, model: str) -> float`
  - `COPILOT_APPROVED: frozenset[str]`
  - `Fleet.scan_copilot(roots, since, project_filter) -> None`
  - `Fleet.add_copilot_session(project, model, usage, ts, branch=None) -> None`
  - `Fleet._record_refusal(kind, project, ts, call: tuple[str, str] | None) -> None`
  - `Fleet.premium_requests_by_agent: dict[str, float]`, `Fleet.copilot_unpriced: int`
  - `watch(roots, codex, interval, c, quiet, raw, copilot=None)`, `_jsonl_files(roots, codex, copilot=None)`
  - Permission-mode keys `"copilot:auto"` / `"copilot:prompted"`, and refusal kinds `"copilot:<result.kind>"`

- [ ] **Step 1: Write the fixture helper**

Create `tests/_fixtures.py`:

```python
"""Synthetic Copilot CLI sessions and an isolated home, for the tests.

Every value is invented. The shapes follow Copilot CLI 1.0.70's events.jsonl,
checked against 17 real sessions; no real content was copied. Written at test
time rather than committed, so the credential canary is assembled at runtime
and never sits in the tree as a literal.
"""
import contextlib
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

CANARY = "sk_live_" + "abcdefghijklmnopqrst"
A = "aaaaaaaa-0000-4000-8000-000000000001"   # normal session, two models
B = "aaaaaaaa-0000-4000-8000-000000000002"   # no session.shutdown
C = "aaaaaaaa-0000-4000-8000-000000000003"   # a denied command
D = "aaaaaaaa-0000-4000-8000-000000000004"   # a credential in a command

USAGE_A = {
    "claude-haiku-4.5": {"inputTokens": 1_000_000, "outputTokens": 100_000,
                         "cacheReadTokens": 600_000, "cacheWriteTokens": 300_000,
                         "reasoningTokens": 20_000},
    "gpt-5-mini": {"inputTokens": 200_000, "outputTokens": 10_000,
                   "cacheReadTokens": 150_000, "cacheWriteTokens": 0,
                   "reasoningTokens": 5_000},
}
USAGE_D = {"claude-sonnet-4.5": {"inputTokens": 50_000, "outputTokens": 5_000,
                                 "cacheReadTokens": 0, "cacheWriteTokens": 0,
                                 "reasoningTokens": 0}}


def _start(sid, cwd, branch, ts):
    return ("session.start", {"sessionId": sid, "copilotVersion": "1.0.70",
                              "context": {"cwd": cwd, "gitRoot": cwd, "branch": branch}}, ts)


def _bash(call, cmd, ts):
    return ("tool.execution_start", {"toolCallId": call, "toolName": "bash",
                                     "arguments": {"command": cmd, "description": "x"}}, ts)


def _ask(call, req, ts):
    return ("permission.requested", {"requestId": req, "permissionRequest": {
        "kind": "shell", "toolCallId": call, "fullCommandText": "x"}}, ts)


def _done(call, req, kind, ts):
    return ("permission.completed", {"requestId": req, "toolCallId": call,
                                     "result": {"kind": kind}}, ts)


def _shutdown(metrics, premium, ts):
    return ("session.shutdown", {"shutdownType": "routine", "totalPremiumRequests": premium,
                                 "modelMetrics": {m: {"usage": u} for m, u in metrics.items()}},
            ts)


SESSIONS = {
    A: [_start(A, "/home/dev/orbital-ledger", "feature/ORB-412-ledger", "2026-09-02T10:00:00.000Z"),
        _bash("a1", "git status", "2026-09-02T10:01:00.000Z"),
        _ask("a2", "r1", "2026-09-02T10:02:00.000Z"),
        _done("a2", "r1", "approved", "2026-09-02T10:02:04.000Z"),
        _bash("a2", "npm test", "2026-09-02T10:02:05.000Z"),
        _bash("a3", "ls -la", "2026-09-02T10:03:00.000Z"),
        ("tool.execution_start", {"toolCallId": "a4", "toolName": "view",
                                  "arguments": {"path": "README.md"}}, "2026-09-02T10:04:00.000Z"),
        ("subagent.completed", {"toolCallId": "a5", "agentName": "explore",
                                "model": "claude-haiku-4.5", "totalTokens": 1200,
                                "totalToolCalls": 4, "durationMs": 5000},
         "2026-09-02T10:05:00.000Z"),
        _shutdown(USAGE_A, 0.33, "2026-09-02T11:00:00.000Z")],
    B: [_start(B, "/home/dev/atlas-gateway", "main", "2026-09-03T10:00:00.000Z"),
        _bash("b1", "make build", "2026-09-03T10:01:00.000Z")],
    C: [_start(C, "/home/dev/mesa-scheduler", "feature/MSA-9", "2026-09-04T10:00:00.000Z"),
        _ask("c1", "r1", "2026-09-04T10:01:00.000Z"),
        # Placeholder until a real denial is captured -- see the release checklist.
        _done("c1", "r1", "denied-by-user", "2026-09-04T10:01:05.000Z"),
        _bash("c1", "rm -rf ./dist", "2026-09-04T10:01:06.000Z"),
        _shutdown({}, 0, "2026-09-04T11:00:00.000Z")],
    D: [_start(D, "/home/dev/quarry-cli", "fix/QRY-9", "2026-09-05T10:00:00.000Z"),
        _bash("d1", f"export STRIPE_KEY={CANARY}", "2026-09-05T10:01:00.000Z"),
        _bash("d2", "make deploy", "2026-09-05T10:02:00.000Z"),
        _shutdown(USAGE_D, 1.0, "2026-09-05T11:00:00.000Z")],
}


def write_sessions(state: Path) -> Path:
    """Write the four sessions under `state` (a session-state directory)."""
    for sid, events in SESSIONS.items():
        d = state / sid
        d.mkdir(parents=True, exist_ok=True)
        with (d / "events.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for n, (kind, data, ts) in enumerate(events):
                fh.write(json.dumps({"type": kind, "data": data, "id": f"e{n}",
                                     "parentId": None, "timestamp": ts}) + "\n")
    return state


@contextlib.contextmanager
def isolated_home():
    """A temp HOME with no agent config in it, on POSIX and Windows alike."""
    with tempfile.TemporaryDirectory() as td:
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME")}
        env.update(HOME=td, USERPROFILE=td)
        with mock.patch.dict(os.environ, env, clear=True):
            yield Path(td)
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_copilot.py` with the module header, then:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402


def _fleet(state, since=None, project=None):
    f = af.Fleet()
    f.scan_copilot([state], since, project)
    return f


class TestCopilotCost(unittest.TestCase):
    """Copilot's inputTokens already include cache reads and writes, for every
    provider. Treating them as Anthropic-style additions double-bills."""

    def test_input_includes_cache_so_fresh_is_the_remainder(self):
        r = af.rate_for("claude-haiku-4-5")
        u = fx.USAGE_A["claude-haiku-4.5"]
        expected = (0.1 * r.input + 0.6 * r.input * af.CACHE_READ_MULT
                    + 0.3 * r.input * af.CACHE_WRITE_ASSUMED_MULT + 0.1 * r.output)
        self.assertAlmostEqual(af.copilot_session_cost(u, "claude-haiku-4-5"), expected, places=9)

    def test_reasoning_is_a_subset_not_an_addition(self):
        u = dict(fx.USAGE_A["gpt-5-mini"])
        a = af.copilot_session_cost(u, "gpt-5.2")
        u["reasoningTokens"] = 9_999_999
        self.assertEqual(a, af.copilot_session_cost(u, "gpt-5.2"))

    def test_dotted_claude_ids_get_the_published_rate(self):
        self.assertEqual(af.copilot_model("claude-haiku-4.5"), "claude-haiku-4-5")
        self.assertEqual(af.rate_for(af.copilot_model("claude-haiku-4.5")).tier, af.VENDOR)
        self.assertEqual(af.copilot_model("gpt-5.2"), "gpt-5.2")


class TestCopilotReader(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.state = fx.write_sessions(Path(self._td.name) / "session-state")

    def tearDown(self):
        self._td.cleanup()

    def test_cost_is_counted_once_per_model_per_session(self):
        f = _fleet(self.state)
        want = sum(af.copilot_session_cost(u, af.copilot_model(m))
                   for usage in (fx.USAGE_A, fx.USAGE_D) for m, u in usage.items())
        self.assertAlmostEqual(f.cost_by_agent["copilot"], want, places=9)
        self.assertEqual(f.units_by_agent["copilot"], 2)          # A and D
        self.assertEqual(f.msgs_by_model["claude-haiku-4-5"], 1)

    def test_a_session_with_no_shutdown_is_unpriced_not_zero(self):
        f = _fleet(self.state, project="atlas")
        self.assertEqual(f.copilot_unpriced, 1)
        self.assertNotIn("copilot", f.cost_by_agent)
        self.assertEqual(f.bash_total, 1, "its commands still count")

    def test_supervision(self):
        f = _fleet(self.state, project="orbital")
        self.assertEqual(f.permission_modes["copilot:auto"], 2)
        self.assertEqual(f.permission_modes["copilot:prompted"], 1)
        self.assertEqual(f.unsupervised_by_day["2026-09-02"], 2)
        self.assertEqual(f.bash_moded_by_day["2026-09-02"], 3)

    def test_the_refusal_is_recorded_and_joined(self):
        f = _fleet(self.state, project="mesa")
        self.assertEqual(f.denials["copilot:denied-by-user"], 1)
        self.assertEqual(f.refusals, 1)
        self.assertEqual(f.refusals_joined, 1)
        self.assertEqual(f.refusal_program["copilot:denied-by-user"]["rm"], 1)

    def test_approved_is_not_a_refusal(self):
        self.assertEqual(_fleet(self.state, project="orbital").refusals, 0)

    def test_credential_is_grouped_and_never_output(self):
        f = _fleet(self.state, project="quarry")
        self.assertEqual(len(f.secrets), 1)
        self.assertNotIn(fx.CANARY, json.dumps(af.to_json(f)))

    def test_project_branch_and_ticket_come_from_session_context(self):
        f = _fleet(self.state, project="orbital")
        self.assertIn("ORB-412", f.cost_by_ticket)
        self.assertTrue(any("orbital-ledger" in p for p in f.cost_by_project))

    def test_premium_requests_are_fractional_and_never_dollars(self):
        f = _fleet(self.state)
        self.assertAlmostEqual(f.premium_requests_by_agent["copilot"], 1.33, places=9)

    def test_subagent_is_counted(self):
        self.assertEqual(_fleet(self.state, project="orbital").sub_calls, 1)

    def test_window_excludes_an_older_shutdown(self):
        f = _fleet(self.state, since=datetime(2026, 9, 5, tzinfo=timezone.utc))
        self.assertEqual(f.units_by_agent["copilot"], 1)          # D only

    def test_malformed_sessions_are_skipped_not_fatal(self):
        (self.state / "no-events-here").mkdir()
        bad = self.state / "bbbbbbbb-0000-4000-8000-000000000009"
        bad.mkdir()
        (bad / "events.jsonl").write_text(
            '{"type":"session.start","data":"not an object"}\n'
            '{"type":"tool.execution_start","data":{"toolName":"bash",'
            '"arguments":{"command":"echo hi"}},"timestamp":"2026-09-06T10:00:00Z"}\n'
            '{"type":"tool.execution_start","data":{"toolName":"ba',   # truncated
            encoding="utf-8")
        f = _fleet(self.state, project="copilot")
        self.assertEqual(f.permission_modes["copilot:auto"], 1, "no toolCallId -> auto")


class TestCopilotWiring(unittest.TestCase):

    def test_roots_honour_copilot_home(self):
        with fx.isolated_home() as home:
            self.assertEqual(af.copilot_roots(), [])
            (home / ".copilot" / "session-state").mkdir(parents=True)
            self.assertEqual(af.copilot_roots(), [home / ".copilot" / "session-state"])
            other = home / "elsewhere"
            (other / "session-state").mkdir(parents=True)
            os.environ["COPILOT_HOME"] = str(other)
            self.assertEqual(af.copilot_roots(), [other / "session-state"])

    def test_agent_copilot_reads_only_copilot(self):
        with fx.isolated_home() as home:
            fx.write_sessions(home / ".copilot" / "session-state")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = af.main(["--agent", "copilot", "--json"])
        self.assertEqual(rc, af.EXIT_OK)
        want = sum(af.copilot_session_cost(u, af.copilot_model(m))
                   for usage in (fx.USAGE_A, fx.USAGE_D) for m, u in usage.items())
        self.assertAlmostEqual(json.loads(buf.getvalue())["cost_usd"], want, places=2)

    def test_no_transcripts_message_names_copilot(self):
        with fx.isolated_home():
            msg = af.no_transcripts_message()
        self.assertIn("Copilot CLI", msg)
        self.assertIn("COPILOT_HOME", msg)

    def test_agents_row_is_present(self):
        self.assertIn("copilot", [cmd for _, cmd in af.AGENT_COMMANDS])

    def test_watch_reads_copilot_commands(self):
        rec = {"type": "tool.execution_start",
               "data": {"toolName": "bash", "arguments": {"command": "ls"}}}
        self.assertEqual(af._commands_in(rec), ["ls"])
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            files = af._jsonl_files([], [], [state])
        self.assertEqual(len(files), 4)

    def test_self_check_reads_copilot_and_leaves_it_unchanged(self):
        with fx.isolated_home() as home:
            state = fx.write_sessions(home / ".copilot" / "session-state")
            before = {p: af._digest_file(p) for p in state.rglob("events.jsonl")}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = af.self_check(af.C(False), None, None)
            after = {p: af._digest_file(p) for p in state.rglob("events.jsonl")}
        self.assertEqual(rc, af.EXIT_OK)
        self.assertIn(str(state), buf.getvalue())
        self.assertEqual(before, after)
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_copilot.py' -v`
Expected: `AttributeError: ... no attribute 'copilot_session_cost'` (and others).

- [ ] **Step 4: Implement the reader**

After `codex_session_cost`:

```python
def copilot_roots() -> list[Path]:
    """Copilot CLI writes one directory per session under $COPILOT_HOME/session-state."""
    base = Path(os.environ.get("COPILOT_HOME", Path.home() / ".copilot")).expanduser()
    sess = base / "session-state"
    return [sess] if sess.is_dir() else []


# permission.completed result kinds that let the command run. Every other kind
# is a refusal -- a mapping taken from the schema, because no denial has been
# observed in a real session yet. --explain copilot says so.
COPILOT_APPROVED = frozenset({"approved", "approved-for-location"})


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
```

In `Fleet.__init__`, after `self.agents_seen`:

```python
        # Copilot bills in premium requests as well as tokens. Fractional
        # (0.33 per request on some models), and never converted to dollars:
        # the conversion depends on a plan this tool cannot see.
        self.premium_requests_by_agent: dict[str, float] = defaultdict(float)
        # Copilot sessions with activity but no session.shutdown record. Their
        # usage is unknowable, so they are counted rather than estimated.
        self.copilot_unpriced = 0
```

Add `add_copilot_session` after `add_codex_session`:

```python
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
```

Add the scanner after `_scan_codex_file`:

```python
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
        calls: list[tuple[str, str, str, datetime | None]] = []   # (id, tool, command, ts)
        prompted: set[str] = set()
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
                            cwd = ctx.get("gitRoot") or ctx.get("cwd") or cwd
                            branch = ctx.get("branch") or branch
                    elif kind == "tool.execution_start":
                        name = str(data.get("toolName") or "?")
                        args = data.get("arguments")
                        cmd = args.get("command") if isinstance(args, dict) else None
                        cmd = cmd if name == "bash" and isinstance(cmd, str) else ""
                        calls.append((str(data.get("toolCallId") or ""), name, cmd, ts))
                    elif kind == "permission.requested":
                        req = data.get("permissionRequest")
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
        for call_id, name, cmd, ts in calls:
            if not in_window(ts):
                continue
            active = True
            if cmd:
                mode = "copilot:prompted" if call_id in prompted else "copilot:auto"
                self.permission_modes[mode] += 1
                # Normalised onto "Bash", as Codex is, so the audit is one view.
                self.add_tool(project, "Bash", {"command": cmd}, ts, mode)
                if call_id:
                    joined[call_id] = ("Bash", cmd[:MAX_SCAN_LINE])
            else:
                self.add_tool(project, name, {}, ts)
                if call_id:
                    joined[call_id] = (name, "")
        for kind, call_id, ts in refusals:
            if in_window(ts):
                active = True
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
```

Refactor `add_refusal` so Copilot can share its accounting. Keep the docstring, and replace the body:

```python
    def add_refusal(self, kind: str, rec: dict, project: str,
                    ts: datetime | None, calls: dict[str, tuple[str, str]]) -> None:
        """<existing docstring unchanged>"""
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
            self.refusal_week[ts.strftime("%Y-W%V")][kind] += 1
        if not call:
            return
        name, cmd = call
        self.refusals_joined += 1
        self.refusal_tool[kind][clean(name)[:48] or "?"] += 1
        if name == "Bash" and cmd:
            head = command_head(cmd)
            if head:
                self.refusal_program[kind][clean(head)[:40]] += 1
```

- [ ] **Step 5: Wire it in**

`no_transcripts_message`: add a third entry to `checked`:

```python
        (Path(os.environ.get("COPILOT_HOME", "~/.copilot")).expanduser() / "session-state",
         "Copilot CLI", "COPILOT_HOME"),
```

and add the line `"  COPILOT_HOME=/path/to/copilot actualis",` after the `CODEX_HOME=` example.

`dead_end_message`: change `"Drop it to read both."` to `"Drop it to read every agent."`

`_jsonl_files` and `watch`:

```python
def _jsonl_files(roots: list[Path], codex: list[Path],
                 copilot: list[Path] | None = None) -> list[Path]:
    ...  # existing loops unchanged
    for r in copilot or []:
        try:
            out.extend(r.glob("*/events.jsonl"))
        except OSError:
            continue
    return out


def watch(roots: list[Path], codex: list[Path], interval: float, c: C,
          quiet: bool, raw: bool, copilot: list[Path] | None = None) -> int:
```

Inside `watch`: pass `copilot` to both `_jsonl_files(roots, codex, copilot)` calls. Build `srcs` from `roots + codex + (copilot or [])`. Widen the prefilter:

```python
                    if ('"tool_use"' not in line and '"function_call"' not in line
                            and '"tool.execution_start"' not in line):
                        continue
```

Name the project so a session UUID is never shown:

```python
                project = ("copilot" if f.name == "events.jsonl"
                           else pretty_project(f.parent.name))
```

`_commands_in`: append before `return out`:

```python
    data = rec.get("data")
    if rec.get("type") == "tool.execution_start" and isinstance(data, dict) \
            and data.get("toolName") == "bash":
        args = data.get("arguments")
        cmd = args.get("command") if isinstance(args, dict) else None
        if isinstance(cmd, str) and cmd:
            out.append(cmd)
```

Also update its docstring to "...across every agent format."

`EXPLAIN["sources"]["formula"]`: after the Codex line, add
`"Copilot CLI  $COPILOT_HOME/session-state/*/events.jsonl  (default ~/.copilot)",`

`self_check`: change the roots line to `else transcript_roots() + codex_roots() + copilot_roots())`. Right after it, add:

```python
    if roots:
        result(True, "the only directories this run reads",
               "; ".join(str(r) for r in roots))
```

`_self_check_corpus`: after `fleet.scan(roots, since, None, progress=False)`, add:

```python
    copilot = [r for r in roots if r in copilot_roots()]
    if copilot:
        fleet.scan_copilot(copilot, since, None)
```

`build_parser`: `--agent` choices become `["all", "claude", "codex", "copilot"]`.

`main`, watch branch:

```python
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
```

`main`, `--root` branch: insert before the `else:`:

```python
        elif args.agent == "copilot":
            fleet.roots.append(root)
            fleet.scan_copilot([root], since, args.project)
```

`main`, discovery branch: after the Codex block:

```python
        if args.agent in ("all", "copilot"):
            proots = copilot_roots()
            if proots:
                fleet.roots.extend(proots)
                fleet.scan_copilot(proots, since, args.project)
            elif args.agent == "copilot":
                sys.exit(no_transcripts_message())
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -p 'test_copilot.py' -v`, then `python3 -m unittest discover -s tests -q`
Expected: all pass. `TestRefusalJoin` and `TestWatch` in the old suite prove the refactors kept their behaviour.

- [ ] **Step 7: Run it against real sessions (manual, read-only)**

Run: `python3 actualis.py --agent copilot --days 120 | head -60`
Expected: a report with a `copilot` row in BY AGENT and no traceback. If `~/.copilot` is empty, the no-transcripts message names Copilot CLI.

- [ ] **Step 8: Commit**

```bash
git add actualis.py tests/_fixtures.py tests/test_copilot.py
git commit -m "feat: read GitHub Copilot CLI sessions"
```

---

### Task 3: Copilot in `--replay`

**Files:**
- Modify: `actualis.py`. Add `_copilot_events` after `_codex_events` (~5570), and update `replay_events` (~5572).
- Test: `tests/test_copilot.py`

**Interfaces:**
- Consumes: `_commands_in` (Copilot-aware since Task 2), `copilot_roots`, `ReplayEvent`
- Produces: `_copilot_events(roots: list[Path], since: datetime | None) -> list[ReplayEvent]`. Each event has vendor `"copilot"`, the session id taken from the directory name, and the branch carried through.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_copilot.py`:

```python
class TestCopilotReplay(unittest.TestCase):

    def test_replay_finds_the_in_session_commands(self):
        with fx.isolated_home() as home:
            state = fx.write_sessions(home / ".copilot" / "session-state")
            fleet = _fleet(state, project="quarry")
            fp = next(iter(fleet.secrets))
            inc = af.replay(fp, af.replay_events(None, None))
        self.assertTrue(inc)
        self.assertEqual(inc["exposure"]["vendors"], ["copilot"])
        self.assertEqual(inc["exposure"]["sessions"], [fx.D])
        self.assertIn("fix/QRY-9", inc["exposure"]["branches"])
        self.assertGreaterEqual(inc["blast_radius"]["same_session"]["commands"], 1)

    def test_replay_with_root(self):
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            events = af.replay_events(None, str(state))
        self.assertEqual({e.vendor for e in events}, {"copilot"})
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_copilot.py' -k Replay -v`
Expected: FAIL, because `inc` is `{}` (no Copilot events are read).

- [ ] **Step 3: Implement**

```python
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
                            cwd = ctx.get("gitRoot") or ctx.get("cwd") or cwd
                            branch = ctx.get("branch") or branch
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
```

In `replay_events`, change the docstring to "Every recorded command across every vendor, oldest first." With a root, use `+ _copilot_events(base, since)`. Without one, add `events += _copilot_events(copilot_roots(), since)`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_copilot.py
git commit -m "feat: --replay follows a credential through Copilot sessions"
```

---

### Task 4: Vendor matrix column, `--explain copilot`, docs

**Files:**
- Modify: `actualis.py`. `VENDOR_CAPABILITIES` and `vendor_gaps` (~2914–2941); `EXPLAIN["vendors"]` (~2992); a new `EXPLAIN["copilot"]`; the REFUSALS note in `render` (~4161); `JSON_SCHEMA` (~4518); the `to_json` vendors block (~4754).
- Modify: `tests/test_actualis.py` (`TestVendorCapabilities`, two unpackings), `README.md` ("Which agents" table and the Anthropic/OpenAI quirks list), `docs/json.md` (`by_agent` row, capability table)
- Test: `tests/test_copilot.py`

**Interfaces:**
- Consumes: `Fleet.denials` keys `copilot:*` (Task 2)
- Produces: `VENDOR_CAPABILITIES` rows as 5-tuples `(capability, claude, codex, copilot, depends_on)`; `vendor_gaps("copilot")`; the JSON key `vendors.capabilities[].copilot`; and `EXPLAIN["copilot"]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_copilot.py`:

```python
class TestCopilotCapabilities(unittest.TestCase):

    def test_copilot_column(self):
        gaps = dict(af.vendor_gaps("copilot"))
        self.assertNotIn("Git branch", gaps, "Copilot records the branch; Codex does not")
        self.assertIn("Sandbox policy", gaps)
        self.assertIn("Git branch", dict(af.vendor_gaps("codex")))

    def test_it_reaches_json(self):
        caps = af.to_json(af.Fleet())["vendors"]["capabilities"]
        self.assertTrue(all("copilot" in row for row in caps))

    def test_explain_copilot_states_the_unverified_mapping(self):
        e = af.EXPLAIN["copilot"]
        text = " ".join(e["formula"] + e["assumes"])
        self.assertIn("approved-for-location", text)
        self.assertIn("not been observed", text)
        self.assertIn("unpriced", text)

    def test_refusals_section_warns_about_copilot_kinds(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1},
                    datetime(2026, 9, 1, tzinfo=timezone.utc))
        f.denials["copilot:denied-by-user"] += 1
        f._record_refusal("copilot:denied-by-user", "p", None, ("Bash", "rm -rf x"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render(f, af.C(False), bash_only=False, top=5)
        self.assertIn("--explain copilot", buf.getvalue())
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_copilot.py' -k Capabilit -v`
Expected: FAIL / `KeyError: 'copilot'`.

- [ ] **Step 3: Implement**

Replace the banner comment's first lines with "Three agents are supported, unevenly...". Then replace the table and `vendor_gaps`:

```python
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
                                                        "result.kind is mapped from the schema, "
                                                        "not yet from an observed denial"),
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
```

`EXPLAIN["vendors"]["formula"]`:

```python
            "capability                claude   codex    copilot",
        ] + [f"  {cap:<24}{c:<9}{x:<9}{p}" for cap, c, x, p, _why in VENDOR_CAPABILITIES] + [
```

Add `EXPLAIN["copilot"]` after `"vendors"`:

```python
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
            "Refusal kinds are mapped from the event schema. A denial has not been",
            "observed in a real session yet, so one recorded some other way is missed.",
            "A command allow-listed in Copilot's config is never prompted, so it",
            "counts as auto -- unsupervised -- even though a person approved the rule.",
            "A session with no session.shutdown record is counted unpriced. No cost",
            "is estimated for it.",
            "session.db is not read; events.jsonl carries everything used here.",
        ],
        "verify": ("jq -c 'select(.type==\"session.shutdown\") | .data.modelMetrics' "
                   "~/.copilot/session-state/*/events.jsonl"),
    },
```

REFUSALS note in `render`. Replace the Codex-only block with:

```python
        if "codex" in fleet.cost_by_agent:
            print(f"  {c.yellow}▲{c.off} {c.dim}Codex writes no per-refusal record, so "
                  f"its sessions are absent here.{c.off}")
        if any(k.startswith("copilot:") for k in fleet.denials):
            print(f"  {c.yellow}▲{c.off} {c.dim}Copilot refusal kinds are mapped from its "
                  f"event schema, not observed data. See --explain copilot.{c.off}")
```

`JSON_SCHEMA`: add `"vendors.capabilities[].copilot": "str",` after the `codex` line.
`to_json`:

```python
                {"capability": cap, "claude": c, "codex": x, "copilot": p, "depends_on": why}
                for cap, c, x, p, why in VENDOR_CAPABILITIES
```

`tests/test_actualis.py` `TestVendorCapabilities`: change both `for cap, c, x, why in af.VENDOR_CAPABILITIES:` to `for cap, c, x, p, why in ...`. In the first test, add `self.assertIn(p, (af.YES, af.PARTIAL, af.NO))`. In the last test, change the condition to `c == af.NO and x == af.NO and p == af.NO` and the message to "a gap in all three...".

`README.md` "Which agents": add this row after Codex:
`| **GitHub Copilot CLI** | yes | `$COPILOT_HOME/session-state/*/events.jsonl` (default `~/.copilot`). Refusal kinds are mapped from the schema until a real denial is observed. |`
Add this bullet to the provider-quirks list:
`- **Copilot CLI** reports `inputTokens` *including* both cache reads and cache writes, for every provider, and writes one final per-model total at `session.shutdown`.`
Update the `--agent` row in "All options" to `` `--agent {all,claude,codex,copilot}` ``.

`docs/json.md`: change the `by_agent` row to `(`claude-code`, `codex`, `copilot`)`. Add a `Copilot CLI` column to the capability table at ~line 229, with values matching `VENDOR_CAPABILITIES`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass, including `TestJSONSchemaFreeze`, `TestDocumentation` and `TestVendorCapabilities`.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_actualis.py tests/test_copilot.py README.md docs/json.md
git commit -m "feat: Copilot column in the vendor matrix, and --explain copilot"
```

---

### Task 5: `card_model`

**Files:**
- Modify: `actualis.py`. Add a new banner section `# Card` immediately before `# The --json contract` (~4388).
- Test: `tests/test_card.py`

**Interfaces:**
- Consumes: Fleet counters from Tasks 1–2, plus `PRICING`, `num`, `cache_hit_rate`-free totals (`cache_uncached`, `cache_actual`), `active_days` and `total_cost`
- Produces:
  - `CARD_MODES = ("supervision", "cost", "volume")`, `CARD_STYLES = ("hero", "terminal")`, `CARD_INSTALL = "uv tool install actualis"`, `CARD_MIN_TREND_DAYS = 3`
  - `class CardError(Exception)`
  - `card_model_name(model: str) -> str`
  - `card_window(fleet, days: int | None, today: date | None = None) -> list[str]`
  - `card_model(fleet, mode: str, days: int | None = None, today: date | None = None) -> dict`, with these keys:
    - `mode: str`, `days: int`, `label: str`, `header: str`
    - `hero: str`, `hero_label: str`, `caption: str`
    - `stats: list[tuple[str, str]]` (value, label), 3 or 4 rows
    - `bars: list[tuple[str, float, str]]` (label, value, value text)
    - `series: list[float | None]`, `series_max: float`, `trend: bool`
    - `share: str`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_card.py`:

```python
D1 = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)


def _day(n):
    return D1.replace(day=n)


def _busy_fleet():
    """Five days of Claude activity: 4 commands a day, 3 of them in auto."""
    f = af.Fleet()
    for d in range(1, 6):
        f.add_usage("p", "claude-opus-5", {"output_tokens": 100_000,
                                           "cache_read_input_tokens": 1_000_000}, _day(d))
        for i in range(4):
            f.add_tool("p", "Bash", {"command": ["git status", "pytest", "npm i x", "ls"][i]},
                       _day(d), "auto" if i < 3 else "default")
    return f


class TestCardModel(unittest.TestCase):

    def test_supervision(self):
        m = af.card_model(_busy_fleet(), "supervision")
        self.assertEqual(m["hero"], "75%")
        self.assertEqual(m["days"], 5)
        self.assertEqual(m["label"], "ACTUALIS · LAST 5 DAYS")
        self.assertEqual([s[1] for s in m["stats"]], ["commands", "refused", "agents"])
        self.assertEqual(m["stats"][0][0], "20")
        self.assertEqual([b[0] for b in m["bars"]], ["auto", "you", "refused"])
        self.assertEqual(m["series"], [75.0] * 5)
        self.assertTrue(m["trend"])
        self.assertTrue(m["share"].startswith("75% of my coding agents' shell commands"))
        self.assertTrue(m["share"].endswith("uv tool install actualis"))

    def test_volume(self):
        m = af.card_model(_busy_fleet(), "volume")
        self.assertEqual(m["hero"], "20")
        self.assertEqual(dict((b[0], b[1]) for b in m["bars"]),
                         {"git": 5, "test": 5, "install": 5, "other": 5})
        self.assertEqual(m["stats"][0][1], "of tool calls")

    def test_cost(self):
        f = _busy_fleet()
        m = af.card_model(f, "cost")
        self.assertEqual(m["hero"], f"${f.total_cost:,.0f}")
        self.assertEqual(m["caption"], "at API list price, last 5 days")
        self.assertEqual([b[0] for b in m["bars"]], ["claude-opus-5"])
        self.assertEqual(len(m["stats"]), 3, "no premium row without Copilot")

    def test_no_shell_commands_refuses_supervision_and_volume(self):
        f = af.Fleet()
        f.add_usage("p", "claude-opus-5", {"output_tokens": 1}, D1)
        for mode in ("supervision", "volume"):
            with self.subTest(mode=mode):
                with self.assertRaises(af.CardError) as cm:
                    af.card_model(f, mode)
                self.assertEqual(str(cm.exception),
                                 "no shell commands in window — try --days or --card cost")
        af.card_model(f, "cost")   # still drawable

    def test_no_priced_usage_is_a_dash_never_zero(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, D1, "auto")
        m = af.card_model(f, "cost")
        self.assertEqual(m["hero"], "—")
        self.assertEqual(m["caption"], "no priced usage in window")

    def test_premium_row_only_with_copilot(self):
        f = _busy_fleet()
        f.premium_requests_by_agent["copilot"] += 3.96
        m = af.card_model(f, "cost")
        self.assertEqual(m["stats"][3], ("3.96", "premium requests"))
        self.assertNotIn("$", m["stats"][3][0])

    def test_fewer_than_three_active_days_has_no_trend(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, _day(1), "auto")
        f.add_tool("p", "Bash", {"command": "ls"}, _day(2), "auto")
        self.assertFalse(af.card_model(f, "volume")["trend"])

    def test_unknown_mode_everywhere_is_a_dash(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "ls"}, D1)
        m = af.card_model(f, "supervision")
        self.assertEqual(m["hero"], "—")

    def test_model_names_are_catalog_names_or_custom(self):
        self.assertEqual(af.card_model_name("claude-opus-5"), "claude-opus-5")
        for private in ("ft:leaktest-model", "ft:gpt-5.2-acme-internal", "gpt-5-mini"):
            with self.subTest(private=private):
                self.assertEqual(af.card_model_name(private), "custom")

    def test_custom_models_are_merged(self):
        f = af.Fleet()
        f.add_usage("p", "ft:one", {"output_tokens": 1_000_000}, D1)
        f.add_usage("p", "ft:two", {"output_tokens": 1_000_000}, D1)
        bars = af.card_model(f, "cost")["bars"]
        self.assertEqual([b[0] for b in bars], ["custom"])

    def test_window_with_days_ends_today(self):
        w = af.card_window(af.Fleet(), 3, date(2026, 9, 10))
        self.assertEqual(w, ["2026-09-08", "2026-09-09", "2026-09-10"])
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -k CardModel -v`
Expected: `AttributeError: ... no attribute 'card_model'`.

- [ ] **Step 3: Implement**

```python
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
        stats = [(_whole_money(total / fleet.active_days), "per active day"),
                 (_whole_money(saved), "cache saved"), (agents, "agents")]
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
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_card.py
git commit -m "feat: card_model, the only card code that reads the fleet"
```

---

### Task 6: Bitmap font, draw ops, PNG and SVG writers

**Files:**
- Create: `tools/make-card-font.py`
- Modify: `actualis.py`. Inside the `# Card` section, after `card_model`.
- Test: `tests/test_card.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (`struct` and `zlib` were imported in Task 1)
- Produces:
  - `CARD_W = 1200`, `CARD_H = 630`
  - `CARD_PALETTE = {"bg": "#0d1117", "fg": "#e6edf3", "muted": "#8b949e", "rule": "#30363d", "accent": "#f0883e"}`
  - `CARD_FONT: dict[str, str]` (char → 32 lowercase hex chars, 16 rows of 8 bits)
  - `class Text(NamedTuple): x: int; y: int; scale: int; colour: str; text: str`
  - `class Rect(NamedTuple): x: int; y: int; w: int; h: int; colour: str`
  - `class Polyline(NamedTuple): points: tuple; colour: str; width: int`
  - `op_rects(op) -> list[tuple[int, int, int, int]]`
  - `rasterize(ops) -> bytearray` (RGB, row-major, CARD_W×CARD_H)
  - `png_bytes(ops) -> bytes`
  - `svg_text(ops) -> str`

- [ ] **Step 1: Write the font extractor and generate the table**

Create `tools/make-card-font.py`:

```python
#!/usr/bin/env python3
"""Print the CARD_FONT table that actualis.py embeds, from Spleen's 8x16 BDF.

Spleen 2.2.0, BSD-2-Clause, (c) Frederic Cambus: https://github.com/fcambus/spleen

    curl -LO https://github.com/fcambus/spleen/releases/download/2.2.0/spleen-2.2.0.tar.gz
    shasum -a 256 spleen-2.2.0.tar.gz
    # ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
    tar xzf spleen-2.2.0.tar.gz
    python3 tools/make-card-font.py spleen-2.2.0/spleen-8x16.bdf

Paste the output over the CARD_FONT block in actualis.py. Only the glyphs a
card can draw are kept: printable ASCII plus the few symbols below.
"""
import sys

EXTRA = "·▁▂▃▄▅▆▇█░─—"
WANT = [chr(c) for c in range(32, 127)] + list(EXTRA)


def main(path: str) -> None:
    glyphs, enc, rows, in_bitmap = {}, -1, [], False
    with open(path, encoding="ascii") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("ENCODING "):
                enc, rows = int(line.split()[1]), []
            elif line.startswith("BBX ") and line.split()[1:] != ["8", "16", "0", "-4"]:
                sys.exit(f"glyph {enc}: unexpected {line}; this script assumes full 8x16 cells")
            elif line == "BITMAP":
                in_bitmap = True
            elif line == "ENDCHAR":
                in_bitmap = False
                if enc >= 0 and chr(enc) in WANT:
                    glyphs[chr(enc)] = "".join(r.lower() for r in rows)
            elif in_bitmap:
                rows.append(line)
    missing = [c for c in WANT if c not in glyphs]
    if missing:
        sys.exit(f"missing glyphs: {missing!r}")
    print("CARD_FONT: dict[str, str] = {")
    for ch in WANT:
        print(f"    {ch!r}: {glyphs[ch]!r},")
    print("}")


if __name__ == "__main__":
    main(sys.argv[1])
```

Run it in the scratchpad:

```bash
S=$(mktemp -d) && cd "$S" \
  && curl -sSLO https://github.com/fcambus/spleen/releases/download/2.2.0/spleen-2.2.0.tar.gz \
  && shasum -a 256 spleen-2.2.0.tar.gz \
  && tar xzf spleen-2.2.0.tar.gz && cd - \
  && python3 tools/make-card-font.py "$S/spleen-2.2.0/spleen-8x16.bdf" > "$S/font.py" \
  && wc -l "$S/font.py" && cat "$S/spleen-2.2.0/LICENSE"
```

Expected: the sha256 is `ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89`, and `font.py` has 109 lines (95 ASCII + 12 extra + 2). If the sha differs, stop and ask.

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_card.py`:

```python
W, H = 1200, 630


def _paint(rects_by_colour, bg="0d1117"):
    """An independent painter, for checking the writers against each other."""
    buf = bytearray(bytes.fromhex(bg) * (W * H))
    for colour, rects in rects_by_colour:
        px = bytes.fromhex(colour.lstrip("#"))
        for x, y, w, h in rects:
            x0, y0, x1, y1 = max(x, 0), max(y, 0), min(x + w, W), min(y + h, H)
            for yy in range(y0, y1):
                o = (yy * W + x0) * 3
                buf[o:o + (x1 - x0) * 3] = px * max(x1 - x0, 0)
    return buf


def _png_pixels(data):
    """Check every chunk's CRC and the IHDR, and return the unfiltered pixels."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, ihdr = 8, b"", None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        tag, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        assert crc == zlib.crc32(tag + body) & 0xFFFFFFFF, f"bad CRC on {tag!r}"
        if tag == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif tag == b"IDAT":
            idat += body
        pos += 12 + length
    assert ihdr == (W, H, 8, 2, 0, 0, 0), ihdr
    raw, stride, out = zlib.decompress(idat), W * 3, bytearray()
    for y in range(H):
        row = raw[y * (stride + 1):(y + 1) * (stride + 1)]
        assert row[0] == 0, "filter type 0 on every scanline"
        out += row[1:]
    return out


def _ops():
    return [af.Rect(0, 0, 10, 10, "#f0883e"),
            af.Text(20, 20, 2, "#e6edf3", "A%·█"),
            af.Polyline(((100, 100), (200, 150), (300, 120)), "#f0883e", 4),
            af.Rect(1190, 620, 50, 50, "#8b949e")]        # clipped at the corner


class TestCardWriters(unittest.TestCase):

    def test_font_covers_every_glyph_a_card_draws(self):
        for ch in [chr(c) for c in range(32, 127)] + list("·▁▂▃▄▅▆▇█░─—"):
            with self.subTest(ch=ch):
                self.assertRegex(af.CARD_FONT[ch], r"^[0-9a-f]{32}$")
        self.assertEqual(af.CARD_FONT["A"][4:6], "7c", "Spleen 'A', row 2")

    def test_unknown_glyph_falls_back(self):
        q = af.op_rects(af.Text(0, 0, 1, "#ffffff", "?"))
        self.assertEqual(af.op_rects(af.Text(0, 0, 1, "#ffffff", "漢")), q)

    def test_text_scales_by_integer_cells(self):
        one = af.op_rects(af.Text(0, 0, 1, "#ffffff", "A"))
        three = af.op_rects(af.Text(0, 0, 3, "#ffffff", "A"))
        self.assertEqual(three, [(x * 3, y * 3, w * 3, h * 3) for x, y, w, h in one])

    def test_png_is_valid_and_matches_the_rasterizer(self):
        ops = _ops()
        self.assertEqual(_png_pixels(af.png_bytes(ops)), af.rasterize(ops))

    def test_svg_and_png_agree_pixel_for_pixel(self):
        ops = _ops()
        svg = af.svg_text(ops)
        self.assertNotIn("<text", svg)
        painted = []
        for colour, d in re.findall(r'<path fill="(#[0-9a-f]{6})" d="([^"]*)"/>', svg):
            rects = [tuple(int(v) for v in r) for r in
                     re.findall(r"M(-?\d+) (-?\d+)h(\d+)v(\d+)h-\d+z", d)]
            painted.append((colour, rects))
        self.assertEqual(_paint(painted), af.rasterize(ops))

    def test_polyline_is_contiguous(self):
        rects = af.op_rects(af.Polyline(((0, 0), (40, 7)), "#ffffff", 1))
        xs = sorted({x + dx for x, y, w, h in rects for dx in range(w)})
        self.assertEqual(xs, list(range(41)))
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -k CardWriters -v`
Expected: `AttributeError: ... no attribute 'CARD_FONT'`.

- [ ] **Step 4: Implement**

Add after `card_model`. First a comment block that quotes Spleen's `LICENSE` **verbatim**, one `# ` per line, under the heading `# CARD_FONT glyphs are from Spleen 2.2.0 (8x16), redistributed under its license:`. Then paste the generated `CARD_FONT` table. Then:

```python
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
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass. `TestSelfCheck.test_this_build_imports_no_networking_module` still passes, because `struct` and `zlib` are not networking modules.

- [ ] **Step 6: Commit**

```bash
git add actualis.py tools/make-card-font.py tests/test_card.py
git commit -m "feat: stdlib PNG and SVG writers that agree pixel for pixel"
```

---

### Task 7: Hero and terminal layouts

**Files:**
- Modify: `actualis.py`. In the `# Card` section, after `svg_text`.
- Test: `tests/test_card.py`

**Interfaces:**
- Consumes: the `card_model()` dict (Task 5); `Text`, `Rect`, `Polyline`, `op_rects`, `CARD_PALETTE`, `CARD_W`, `CARD_H` (Task 6); `_wrap(text, width)` (existing, ~line 2697)
- Produces: `layout_hero(m: dict) -> list`, `layout_terminal(m: dict) -> list`, `HERO_RULE_X = 856`, `TERM_COLS = 48`

Hero geometry (pixels):

| Element | Position and size |
|---|---|
| Label | (64, 48), ×2, muted |
| Hero value | (64, 112). ×10 if it fits in 768 px, else ×8, else ×6. Accent. |
| Caption | (64, 296 + 52·line), ×3, fg, wrapped at 32 chars, at most 2 lines |
| Rule | Rect (856, 112, 2, 400) |
| Stats | Value at (888, 112 + 104·i), fg: ×4 up to 9 chars, ×3 up to 12. Label at y+68, ×2, muted, up to 16 chars. |
| Sparkline box | x 64..832, y 416..536, Polyline width 4, accent. Otherwise the text `not enough days for a trend` at (64, 456), ×2. |
| Footer | (64, 574), ×2, muted |

Terminal geometry: cell 24×48, origin (24, 24), 48 columns.

| Row | Content |
|---|---|
| 0 | `$` (accent) and `actualis --card <mode>` |
| 1 | `ACTUALIS · what actually ran` |
| 2 | header, then `─` to column 48 |
| 3–4 | hero ×6, then hero label ×3 on row 4 |
| 5–8 | bars: label (columns 0–10), 28 bar cells (12–39), value (41–47: ×3 up to 7 chars, ×2 up to 10) |
| next free row | `<N>d` and the block sparkline (at most 40 cells, from column 5) |
| 11 | footer, right-aligned |

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_card.py`:

```python
def _extent(op):
    """Bounding box of an op's pixels, or None when it draws nothing."""
    rects = af.op_rects(op)
    if not rects:
        return None
    return (min(r[0] for r in rects), min(r[1] for r in rects),
            max(r[0] + r[2] for r in rects), max(r[1] + r[3] for r in rects))


def _extreme_model():
    return {"mode": "cost", "days": 365, "label": "ACTUALIS · LAST 365 DAYS",
            "header": "COST", "hero": "$12,345,678", "hero_label": "at list price",
            "caption": "at API list price, last 365 days",
            "stats": [("$123,456", "per active day"), ("$9,999,999", "cache saved"),
                      ("3", "agents"), ("12,345.67", "premium requests")],
            "bars": [("claude-sonnet-4-5", 9e6, "$9,000,000"), ("custom", 1.0, "$1"),
                     ("gpt-5.2", 0.0, "$0")],
            "series": [float(i % 17) for i in range(365)], "series_max": 16.0,
            "trend": True, "share": "x"}


class TestCardLayouts(unittest.TestCase):

    def _all(self):
        models = [af.card_model(_busy_fleet(), mode) for mode in af.CARD_MODES]
        models.append(_extreme_model())
        for m in models:
            for name, layout in (("hero", af.layout_hero), ("terminal", af.layout_terminal)):
                yield name, m, layout(m)

    def test_every_op_is_inside_the_canvas(self):
        for name, m, ops in self._all():
            for op in ops:
                box = _extent(op)
                if box is None:
                    continue
                with self.subTest(style=name, mode=m["mode"], op=op):
                    x0, y0, x1, y1 = box
                    self.assertGreaterEqual(min(x0, y0), 0)
                    self.assertLessEqual(x1, 1200)
                    self.assertLessEqual(y1, 630)

    def test_extreme_values_stay_inside_their_columns(self):
        ops = af.layout_hero(_extreme_model())
        left = [op for op in ops if isinstance(op, af.Text) and op.x < af.HERO_RULE_X]
        for op in left:
            with self.subTest(op=op):
                self.assertLessEqual(op.x + len(op.text) * 8 * op.scale, af.HERO_RULE_X - 16)
        hero = next(op for op in ops if isinstance(op, af.Text) and op.text == "$12,345,678")
        self.assertLess(hero.scale, 10)

    def test_long_windows_are_bucketed(self):
        ops = af.layout_terminal(_extreme_model())
        spark = [op for op in ops if isinstance(op, af.Text)
                 and op.x == af.TERM_X + 5 * af.CELL_W and op.y > af.TERM_Y + 4 * af.CELL_H]
        self.assertEqual(len(spark), 1)
        self.assertLessEqual(len(spark[0].text), 40)
        line = next(op for op in af.layout_hero(_extreme_model()) if isinstance(op, af.Polyline))
        for x, y in line.points:
            self.assertTrue(64 <= x <= 832 and 416 <= y <= 536, (x, y))

    def test_no_trend_says_so(self):
        m = dict(_extreme_model(), trend=False)
        for layout in (af.layout_hero, af.layout_terminal):
            with self.subTest(layout=layout.__name__):
                texts = [op.text for op in layout(m) if isinstance(op, af.Text)]
                self.assertIn("not enough days for a trend", texts)

    def test_terminal_bars_are_28_cells(self):
        ops = af.layout_terminal(af.card_model(_busy_fleet(), "volume"))
        bar_rows = {}
        for op in ops:
            if isinstance(op, af.Text) and set(op.text) <= {"█", "░"}:
                bar_rows[op.y] = bar_rows.get(op.y, 0) + len(op.text)
        self.assertEqual(sorted(bar_rows.values()), [28, 28, 28, 28])

    def test_footer_on_both(self):
        for name, m, ops in self._all():
            with self.subTest(style=name):
                self.assertIn("uv tool install actualis",
                              [op.text for op in ops if isinstance(op, af.Text)])
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -k CardLayouts -v`
Expected: `AttributeError: ... no attribute 'layout_hero'`.

- [ ] **Step 3: Implement**

```python
HERO_RULE_X = 856
_HERO_LEFT, _HERO_WIDTH = 64, 768
_SPARK_BOX = (64, 416, 768, 120)          # x, y, w, h
TERM_X, TERM_Y, CELL_W, CELL_H, TERM_COLS = 24, 24, 24, 48, 48
_BLOCKS = "▁▂▃▄▅▆▇█"


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
            ops.append(at(12, row, P["accent"], "█" * filled))
        if filled < 28:
            ops.append(at(12 + filled, row, P["rule"], "░" * (28 - filled)))
        if len(text) <= 7:
            ops.append(at(41, row, P["fg"], text))
        else:   # x2 fits 10 characters in the same 7 cells; never cut a number
            ops.append(Text(TERM_X + 41 * CELL_W, TERM_Y + row * CELL_H + 16, 2,
                            P["fg"], text[:10]))
    spark_row = 5 + max(len(bars), 3)
    ops.append(at(0, spark_row, P["muted"], f"{m['days']}d"[:4]))
    if m["trend"]:
        ops.append(at(5, spark_row, P["accent"], _blocks(m["series"], m["series_max"], 40)))
    else:
        ops.append(at(5, spark_row, P["muted"], "not enough days for a trend"))
    ops.append(at(TERM_COLS - len(CARD_INSTALL), 11, P["muted"], CARD_INSTALL))
    return ops
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass.

- [ ] **Step 5: Look at the cards (manual)**

```bash
python3 - <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("actualis", "actualis.py"); af = importlib.util.module_from_spec(s); s.loader.exec_module(af)
sys.path.insert(0, "tests"); import test_card as t
for style, layout in (("hero", af.layout_hero), ("terminal", af.layout_terminal)):
    open(f"/tmp/card-{style}.png", "wb").write(af.png_bytes(layout(af.card_model(t._busy_fleet(), "supervision"))))
PY
open /tmp/card-hero.png /tmp/card-terminal.png
```

Expected: both read cleanly, with nothing overlapping. Fix any coordinate that looks wrong and re-run Step 4.

- [ ] **Step 6: Commit**

```bash
git add actualis.py tests/test_card.py
git commit -m "feat: hero and terminal card layouts"
```

---

### Task 8: `--card` on the command line, demo fleet, goldens

**Files:**
- Modify: `actualis.py`. Add `card_paths` and `write_card` in the `# Card` section. Update `build_parser`, `_VALUE_HINT`, `main` and the `self_check` write-path result.
- Modify: `tools/make-demo-fleet.py`, `README.md` ("All options" rows)
- Create: `tools/make-card-images.py`, `tests/goldens/` (6 SVGs, plus `card-hero-supervision.pixels.sha256`)
- Test: `tests/test_card.py`

**Interfaces:**
- Consumes: `card_model`, `CardError`, `layout_hero`, `layout_terminal`, `svg_text`, `png_bytes`, `rasterize`, `CARD_MODES`, `CARD_STYLES`
- Produces:
  - `card_paths(out_dir: Path) -> tuple[Path, Path]`
  - `write_card(m: dict, style: str, out_dir: Path) -> tuple[Path, Path]`
  - the flags `--card [MODE]`, `--style {hero,terminal}` and `--out DIR`
  - `tools/make-card-images.py`: `demo_fleet() -> (module, Fleet)` and `cards() -> (module, {(style, mode): ops})`
  - `tools/make-demo-fleet.py`: `main(dest, copilot_dest=None)`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_card.py`:

```python
GOLDENS = ROOT / "tests" / "goldens"
UPDATE = os.environ.get("ACTUALIS_UPDATE_GOLDENS") == "1"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures as fx  # noqa: E402


def _tool(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCardFiles(unittest.TestCase):

    def test_first_card_has_no_suffix(self):
        with tempfile.TemporaryDirectory() as td:
            svg, png = af.card_paths(Path(td))
        self.assertEqual((svg.name, png.name), ("actualis-card.svg", "actualis-card.png"))

    def test_one_existing_file_bumps_both(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "actualis-card.png").write_bytes(b"mine")
            svg, png = af.card_paths(Path(td))
            self.assertEqual((svg.name, png.name),
                             ("actualis-card-2.svg", "actualis-card-2.png"))
            self.assertEqual((Path(td) / "actualis-card.png").read_bytes(), b"mine")

    def test_write_card_never_overwrites(self):
        m = af.card_model(_busy_fleet(), "volume")
        with tempfile.TemporaryDirectory() as td:
            a = af.write_card(m, "hero", Path(td))
            b = af.write_card(m, "hero", Path(td))
            self.assertNotEqual(a, b)
            self.assertEqual(len(list(Path(td).iterdir())), 4)


class TestCardCli(unittest.TestCase):

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = af.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_card_writes_two_files_and_a_caption(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            fx.write_sessions(home / ".copilot" / "session-state")
            rc, stdout, _ = self._run(["--card", "--out", out])
            names = sorted(p.name for p in Path(out).iterdir())
        self.assertEqual(rc, af.EXIT_OK)
        self.assertEqual(names, ["actualis-card.png", "actualis-card.svg"])
        self.assertIn("uv tool install actualis", stdout)
        self.assertIn("actualis-card.svg", stdout)

    def test_terminal_style_and_mode(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            fx.write_sessions(home / ".copilot" / "session-state")
            rc, _, _ = self._run(["--card", "cost", "--style", "terminal", "--out", out])
        self.assertEqual(rc, af.EXIT_OK)

    def test_out_must_be_a_directory(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as td:
            fx.write_sessions(home / ".copilot" / "session-state")
            target = Path(td) / "file.txt"
            target.write_text("x")
            rc, _, err = self._run(["--card", "--out", str(target)])
            self.assertEqual(sorted(p.name for p in Path(td).iterdir()), ["file.txt"])
        self.assertEqual(rc, af.EXIT_CANNOT_RUN)
        self.assertIn("is not a directory", err)

    def test_no_commands_exits_nonzero_and_writes_nothing(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            p = home / ".claude" / "projects" / "proj"
            p.mkdir(parents=True)
            (p / "s.jsonl").write_text(json.dumps(
                {"timestamp": "2026-09-01T00:00:00Z",
                 "message": {"id": "m1", "model": "claude-opus-5",
                             "usage": {"output_tokens": 10}}}) + "\n")
            rc, _, err = self._run(["--card", "--out", out])
            self.assertEqual(list(Path(out).iterdir()), [])
        self.assertEqual(rc, af.EXIT_CANNOT_RUN)
        self.assertIn("no shell commands in window — try --days or --card cost", err)

    def test_card_and_json_conflict(self):
        with self.assertRaises(SystemExit):
            self._run(["--card", "--json"])

    def test_style_without_card_is_an_error(self):
        with self.assertRaises(SystemExit):
            self._run(["--style", "terminal"])

    def test_self_check_names_the_card_write_path(self):
        with fx.isolated_home():
            _, stdout, _ = self._run(["--self-check"])
        self.assertIn("actualis-card", stdout)
        self.assertIn("--card", stdout)


class TestCardGoldens(unittest.TestCase):
    """Cost goldens change when the price table does. Regenerate deliberately:
    ACTUALIS_UPDATE_GOLDENS=1 python3 -m unittest discover -s tests -p test_card.py"""

    @classmethod
    def setUpClass(cls):
        cls.mod, cls.cards = _tool("make_card_images", "make-card-images.py").cards()

    def test_svg_goldens(self):
        self.assertEqual(len(self.cards), 6)
        for (style, mode), ops in self.cards.items():
            with self.subTest(style=style, mode=mode):
                got = self.mod.svg_text(ops)
                path = GOLDENS / f"card-{style}-{mode}.svg"
                if UPDATE:
                    GOLDENS.mkdir(exist_ok=True)
                    with path.open("w", encoding="utf-8", newline="\n") as fh:
                        fh.write(got)
                self.assertEqual(path.read_text(encoding="utf-8").replace("\r\n", "\n"), got)

    def test_png_pixels_golden(self):
        digest = hashlib.sha256(bytes(self.mod.rasterize(self.cards[("hero", "supervision")]))).hexdigest()
        path = GOLDENS / "card-hero-supervision.pixels.sha256"
        if UPDATE:
            with path.open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(digest + "\n")
        self.assertEqual(path.read_text(encoding="utf-8").strip(), digest)
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -k "CardFiles or CardCli or CardGoldens" -v`
Expected: `AttributeError: ... no attribute 'card_paths'`, and `unrecognized arguments: --card`.

- [ ] **Step 3: Implement the writer and the CLI**

In the `# Card` section:

```python
def card_paths(out_dir: Path) -> tuple[Path, Path]:
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


def write_card(m: dict, style: str, out_dir: Path) -> tuple[Path, Path]:
    """Write one card. Mode "x" makes never-overwrite hold even under a race."""
    ops = layout_hero(m) if style == "hero" else layout_terminal(m)
    svg, png = card_paths(out_dir)
    with svg.open("x", encoding="utf-8", newline="\n") as fh:
        fh.write(svg_text(ops))
    with png.open("xb") as fh:
        fh.write(png_bytes(ops))
    return svg, png
```

`build_parser`, after `--share`:

```python
    ap.add_argument("--card", nargs="?", const="supervision", choices=CARD_MODES,
                    metavar="MODE",
                    help="write a shareable SVG and PNG card: supervision (default), "
                         "cost or volume. Nothing identifying is on it")
    ap.add_argument("--style", choices=CARD_STYLES, default="hero",
                    help="--card layout: hero (default) or terminal")
    ap.add_argument("--out", metavar="DIR",
                    help="--card: directory to write into (default: current directory)")
```

`_VALUE_HINT`: add `"--out": "dir",`.

`main`, beside the `--diff`/`--json` check:

```python
    if args.card and args.json:
        ap.error("--card writes files; it cannot also emit --json.")
    if not args.card and (args.style != "hero" or args.out):
        ap.error("--style and --out apply only to --card.")
```

`main`, right after `if args.why: return render_why(...)`:

```python
    if args.card:
        out_dir = Path(args.out).expanduser() if args.out else Path.cwd()
        if not out_dir.is_dir():
            print(f"actualis: {out_dir} is not a directory.\n"
                  "  --out takes the directory the card is written into.", file=sys.stderr)
            return EXIT_CANNOT_RUN
        try:
            model = card_model(fleet, args.card, args.days)
        except CardError as exc:
            print(f"actualis: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        svg, png = write_card(model, args.style, out_dir)
        print(f"  {svg}\n  {png}\n\n  {model['share']}")
        return EXIT_OK
```

`self_check`, the write-path result:

```python
    writable = [str(p) for p in suppression_paths()]
    result(True, "the only write paths in this build",
           "Suppressions, and only when you pass --suppress: " + "; ".join(writable)
           + ". A card, and only when you pass --card: actualis-card[-N].svg and "
           "actualis-card[-N].png in the current directory, or in --out. Neither "
           "is ever overwritten.")
```

`README.md` "All options": add these rows after `--share`:

```
| `--card [MODE]` | write a shareable 1200×630 SVG and PNG: `supervision` (default), `cost` or `volume`. Nothing identifying is on it, and it never overwrites |
| `--style STYLE` | `--card` layout: `hero` (default) or `terminal` |
| `--out DIR` | `--card`: the directory to write into (default: the current directory) |
```

- [ ] **Step 4: Add Copilot sessions to the demo fleet**

In `tools/make-demo-fleet.py`, update the docstring usage to
`python3 tools/make-demo-fleet.py /tmp/actualis-demo-fleet [/tmp/actualis-demo-copilot]`. Add the following after `RISKY`:

```python
COPILOT_MODELS = ("claude-sonnet-4.5", "gpt-5-mini")


def copilot_sessions(dest: str) -> None:
    """Two invented Copilot CLI sessions, in its events.jsonl shape.

    Written after the Claude fleet, so the random stream that fleet consumes is
    unchanged and its images stay byte-identical.
    """
    state = pathlib.Path(dest) / "session-state"
    for s in range(2):
        sid = f"00000000-0000-4000-8000-00000000000{s + 1}"
        day = BASE + timedelta(days=8 + s * 12)
        events = [("session.start", {"sessionId": sid, "copilotVersion": "1.0.70",
                   "context": {"cwd": "/home/dev/orbital-ledger",
                               "gitRoot": "/home/dev/orbital-ledger",
                               "branch": f"feature/ORB-{700 + s}"}}, day)]
        for i in range(20):
            ts, call = day + timedelta(minutes=3 * i), f"call-{s}-{i}"
            if random.random() < .1:
                events.append(("permission.requested", {"requestId": call,
                               "permissionRequest": {"kind": "shell", "toolCallId": call}}, ts))
                events.append(("permission.completed", {"requestId": call, "toolCallId": call,
                               "result": {"kind": "approved"}}, ts))
            events.append(("tool.execution_start", {"toolCallId": call, "toolName": "bash",
                           "arguments": {"command": random.choice(SAFE)}}, ts))
        events.append(("session.shutdown", {
            "shutdownType": "routine", "totalPremiumRequests": 1.65,
            "modelMetrics": {m: {"usage": {
                "inputTokens": 900_000, "cacheReadTokens": 780_000,
                "cacheWriteTokens": 60_000 if m.startswith("claude") else 0,
                "outputTokens": 14_000, "reasoningTokens": 3_000}} for m in COPILOT_MODELS}},
            day + timedelta(hours=2)))
        d = state / sid
        d.mkdir(parents=True, exist_ok=True)
        with (d / "events.jsonl").open("w") as fh:
            for n, (kind, data, ts) in enumerate(events):
                fh.write(json.dumps({"type": kind, "data": data, "id": f"e{n}",
                                     "parentId": None, "timestamp": ts.isoformat()}) + "\n")
```

Change `main(dest)` to `main(dest: str, copilot_dest: str | None = None)`. In 3.9, without the future import, write the annotation as `copilot_dest=None`. At the end of `main`, add `if copilot_dest: copilot_sessions(copilot_dest)`. Change the entry point to `main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)`.

Create `tools/make-card-images.py`:

```python
#!/usr/bin/env python3
"""Render every card from the invented demo fleet.

    python3 tools/make-card-images.py docs/img

The goldens in tests/goldens come from cards() here too, so the images in the
README and the cards the tests pin are the same cards.
"""
import contextlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def demo_fleet():
    af = _load("actualis", ROOT / "actualis.py")
    demo = _load("make_demo_fleet", ROOT / "tools" / "make-demo-fleet.py")
    with tempfile.TemporaryDirectory() as td:
        claude, copilot = Path(td) / "claude", Path(td) / "copilot"
        with contextlib.redirect_stdout(io.StringIO()):
            demo.main(str(claude), str(copilot))
        fleet = af.Fleet()
        fleet.scan([claude], None, None, progress=False)
        fleet.scan_copilot([copilot / "session-state"], None, None)
    return af, fleet


def cards():
    """(style, mode) -> draw ops, for all six cards."""
    af, fleet = demo_fleet()
    out = {}
    for mode in af.CARD_MODES:
        m = af.card_model(fleet, mode)
        out[("hero", mode)] = af.layout_hero(m)
        out[("terminal", mode)] = af.layout_terminal(m)
    return af, out


def main(dest: str) -> None:
    af, all_ops = cards()
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    for (style, mode), ops in all_ops.items():
        with (d / f"card-{style}-{mode}.svg").open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(af.svg_text(ops))
        (d / f"card-{style}-{mode}.png").write_bytes(af.png_bytes(ops))
    print(f"  {len(all_ops) * 2} files in {d}")


if __name__ == "__main__":
    main(sys.argv[1])
```

- [ ] **Step 5: Generate the goldens, then run the tests and confirm they pass**

```bash
ACTUALIS_UPDATE_GOLDENS=1 python3 -m unittest discover -s tests -p 'test_card.py' -k CardGoldens
python3 -m unittest discover -s tests -q
du -sh tests/goldens && ls tests/goldens
```

Expected: 7 files in `tests/goldens`, and the full suite passes **without** the env var. Open two of the SVGs in a browser and check they look like the PNGs from Task 7. Check that the demo sparkline shows a trend. Check that the cost card has a `premium requests` row, because the demo fleet has Copilot.

- [ ] **Step 6: Run it for real (manual)**

```bash
cd "$(mktemp -d)" && python3 ~/Documents/github/digital_foundry/actualis/actualis.py --card --days 30 \
  && python3 ~/Documents/github/digital_foundry/actualis/actualis.py --card cost --style terminal --days 30 \
  && ls && open actualis-card.png actualis-card-2.png
```

Expected: two pairs of files, the `-2` pair being the terminal cost card, and a caption line after each.

- [ ] **Step 7: Commit**

```bash
git add actualis.py README.md tools/make-demo-fleet.py tools/make-card-images.py tests/test_card.py tests/goldens
git commit -m "feat: actualis --card writes a shareable SVG and PNG"
```

---

### Task 9: The card leak test

**Files:**
- Test: `tests/test_card.py`

**Interfaces:**
- Consumes: everything above, through both `card_model` + writers and `main(["--card", ...])`
- Produces: nothing new. This task is the enforcement of the spec's privacy constraint.

- [ ] **Step 1: Write the tests**

These should pass at once, because Tasks 5–8 were built to make them pass. If one fails, the defect is in the shipped code. Fix the code, never the test.

```python
class TestCardLeaksNothing(unittest.TestCase):
    """The card is made to be posted. The only thing that matters about it is
    that nothing identifying can reach it -- in the model, the SVG, the PNG or
    the caption line printed beside them."""

    NEEDLES = ["ACME-CLASSIFIED-MERGER", "feat/9999-project-tigerclaw", "9999",
               "/Users/someone/private/repo", "internal-db.corp.example.com",
               "hunter2pass", "sk_live_leakcanary1234567", "ft:leaktest-model",
               "acme-deploy"]

    def _fleet(self):
        f = af.Fleet()
        ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for d in range(1, 6):
            t = ts.replace(day=d)
            f.add_usage("ACME-CLASSIFIED-MERGER", "ft:leaktest-model",
                        {"output_tokens": 1_000_000}, t, "feat/9999-project-tigerclaw")
            f.add_tool("ACME-CLASSIFIED-MERGER", "Bash",
                       {"command": "psql postgresql://u:hunter2pass@internal-db.corp.example.com/x "
                                   "&& export K=sk_live_leakcanary1234567 "
                                   "&& cat /Users/someone/private/repo/.env"}, t, "auto")
            f.add_tool("ACME-CLASSIFIED-MERGER", "Bash", {"command": "./acme-deploy --prod"},
                       t, "default")
        return f

    def _surfaces(self, f):
        for mode in af.CARD_MODES:
            m = af.card_model(f, mode)
            yield mode, "model", json.dumps(m, ensure_ascii=False)
            yield mode, "share", m["share"]
            for style, layout in (("hero", af.layout_hero), ("terminal", af.layout_terminal)):
                ops = layout(m)
                yield mode, f"{style}.ops", repr(ops)
                yield mode, f"{style}.svg", af.svg_text(ops)
                yield mode, f"{style}.png", bytes(_png_pixels(af.png_bytes(ops))).decode("latin-1")

    def test_no_identifying_string_reaches_any_surface(self):
        f = self._fleet()
        fps = list(f.secrets)
        self.assertTrue(fps, "the canary must have been detected for this test to mean anything")
        for mode, surface, text in self._surfaces(f):
            for needle in self.NEEDLES + fps:
                with self.subTest(mode=mode, surface=surface, needle=needle):
                    self.assertNotIn(needle, text)

    def test_private_model_is_shown_as_custom(self):
        m = af.card_model(self._fleet(), "cost")
        self.assertEqual([b[0] for b in m["bars"]], ["custom"])

    def test_end_to_end_through_main(self):
        with fx.isolated_home() as home, tempfile.TemporaryDirectory() as out:
            p = home / ".claude" / "projects" / "-Users-someone-private-ACME-CLASSIFIED-MERGER"
            p.mkdir(parents=True)
            recs = [{"timestamp": f"2026-09-0{d}T10:00:00Z", "permissionMode": "auto",
                     "gitBranch": "feat/9999-project-tigerclaw",
                     "message": {"id": f"m{d}", "model": "ft:leaktest-model",
                                 "usage": {"output_tokens": 1000},
                                 "content": [{"type": "tool_use", "id": f"t{d}", "name": "Bash",
                                              "input": {"command":
                                                        "export K=sk_live_leakcanary1234567"}}]}}
                    for d in range(1, 6)]
            (p / "s.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
            for mode in af.CARD_MODES:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(af.main(["--card", mode, "--out", out]), af.EXIT_OK)
                for needle in self.NEEDLES:
                    with self.subTest(mode=mode, needle=needle):
                        self.assertNotIn(needle, buf.getvalue().replace(out, ""))
            for written in Path(out).iterdir():
                body = written.read_bytes().decode("latin-1")
                for needle in self.NEEDLES:
                    with self.subTest(file=written.name, needle=needle):
                        self.assertNotIn(needle, body)

    def test_share_leak_test_still_holds_with_copilot_in_the_fleet(self):
        with tempfile.TemporaryDirectory() as td:
            state = fx.write_sessions(Path(td) / "session-state")
            f = af.Fleet()
            f.scan_copilot([state], None, None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            af.render_share(f, af.C(False))
        for needle in ("orbital-ledger", "ORB-412", fx.CANARY, fx.A, "quarry-cli"):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, buf.getvalue())
```

Note that the stdout check strips the temp `--out` path before searching. The printed file paths are the user's own `--out`, and they are not part of the posted card.

- [ ] **Step 2: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -p 'test_card.py' -k Leaks -v`, then `python3 -m unittest discover -s tests -q`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add tests/test_card.py
git commit -m "test: nothing identifying reaches a card, by any route"
```

---

### Task 10: README, images, CHANGELOG

**Files:**
- Modify: `README.md` (a new section after "Sharing a summary"), `CHANGELOG.md`
- Create: `docs/img/card-hero-supervision.png`, `docs/img/card-terminal-cost.png` (from `tools/make-card-images.py`)

- [ ] **Step 1: Render the README images**

```bash
D=$(mktemp -d) && python3 tools/make-card-images.py "$D" \
  && cp "$D/card-hero-supervision.png" "$D/card-terminal-cost.png" docs/img/ && ls -la docs/img
```

- [ ] **Step 2: Write the README section**

Insert after the `## Sharing a summary` section:

```markdown
## Post your card

`--share` prints a summary for people who read. `--card` draws one for people who scroll:

    actualis --card                    # supervision: what % of shell commands nobody approved
    actualis --card cost               # spend at API list price
    actualis --card volume --style terminal

<p align="center"><img src="docs/img/card-hero-supervision.png" width="600" alt="A hero card"> <img src="docs/img/card-terminal-cost.png" width="600" alt="A terminal card"></p>

Each run writes `actualis-card.svg` and `actualis-card.png` (1200×630, the size social
sites preview) to the current directory or `--out DIR`, and prints a caption you can
paste beside it. It never overwrites; a second card is `actualis-card-2.*`.

What is on it is counts, four command categories (`git`, `test`, `install`, `other`)
and model names from the public price table. Everything else is `custom`. No project,
branch, ticket, path, command, credential or fingerprint can reach it, and the test
suite checks the SVG, the PNG pixels and the caption for each of them. The SVG has
no text in it at all: every glyph is pixels.

<sub>Images above are from the invented demo fleet. Regenerate with
<code>tools/make-card-images.py</code>.</sub>
```

- [ ] **Step 3: Write the CHANGELOG entry**

Insert at the top, under `# Changelog`:

```markdown
## 0.2.0 — unreleased

Actualis now reads Copilot CLI. Post your card.

### Added

- **GitHub Copilot CLI sessions are read**, from
  `$COPILOT_HOME/session-state/*/events.jsonl` (default `~/.copilot`): shell
  commands into the same audit, cost per model per session, supervision per
  command, refusals, subagents and premium requests. `--agent copilot` reads it
  alone. Copilot reports `inputTokens` *including* cache reads and writes for
  every provider, and Claude model ids with dots; both are handled, and
  `--explain copilot` says how. Refusal kinds are mapped from the event schema
  because no real denial has been observed yet, and the report says so where a
  Copilot refusal appears.
- **`--card`** writes a 1200×630 SVG and PNG to post: `supervision`, `cost` or
  `volume`, in a `hero` or `terminal` style. Standard library only. The SVG and
  PNG are drawn from one list of pixel runs, so they cannot disagree. Nothing
  identifying can reach either, and the leak test now checks both, plus the
  printed caption.

### Changed

- **Supervision is counted per shell command**, using the permission mode in
  force when each command ran, rather than per turn. `--share` and the card now
  share the one definition of "unsupervised" the AISVS mapping already used,
  so `codex:never` counts there too.
- The vendor matrix (`--explain vendors`, `--json`) has a `copilot` column.
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python3 -m unittest discover -s tests -q`
Expected: all pass. `TestDocumentation.test_every_flag_is_documented` covers `--card`, `--style` and `--out`.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md docs/img/card-hero-supervision.png docs/img/card-terminal-cost.png
git commit -m "docs: the card, Copilot CLI support, and the 0.2.0 entry"
```

---

## Human steps before release (not tasks)

These come from the spec's release checklist. A code agent cannot do them.

- [ ] **Capture a real Copilot denial.** Start a Copilot CLI session in a scratch repository and ask it to run a shell command. Deny the prompt. Then run `jq -c 'select(.type=="permission.completed") | .data.result' ~/.copilot/session-state/*/events.jsonl | sort | uniq -c`. Put the real `result.kind` into `tests/_fixtures.py` session C, replacing `"denied-by-user"`. Change `--explain copilot`'s "not been observed" wording to say the kind was confirmed, and flip the vendor matrix caveat. If the denied command has **no** `tool.execution_start`, adjust session C to match and re-run the suite.
- [ ] Update the actualis.app announcement: the launch line, both card styles, and "Claude Code · Codex · Copilot CLI".
- [ ] Bump `__version__` and `pyproject.toml` to `0.2.0` through the normal release flow.

## Self-Review

1. **Spec coverage.** Every spec requirement maps to a task:
   - Copilot discovery and the `--agent` flag: Task 2
   - The mapping table, row by row: Task 2. Replay is Task 3.
   - Limits reported rather than guessed: Task 2 (unpriced) and Task 4 (explain and matrix)
   - `--card` command, data, rendering, both styles and the edge cases: Tasks 1 and 5–8
   - Card tests (goldens, PNG, SVG/PNG agreement, leak, edge cases, non-overwrite, self-check): Tasks 5–9
   - Copilot tests 1–4 and their assertions: Tasks 2 and 3
   - Release checklist: Task 10 and the human steps
2. **Placeholder scan.** Every code step contains code. The one deliberate placeholder is the fixture's `denied-by-user`, which the spec itself names as a placeholder, and it is tracked as a human step.
3. **Type consistency.** These names are used the same way in every task: `add_tool(..., mode)`, `is_ungated_mode`, `command_category`, `copilot_model`, `copilot_session_cost`, `_record_refusal(kind, project, ts, call)`, `card_model` dict keys (`hero`, `hero_label`, `caption`, `header`, `label`, `stats`, `bars`, `series`, `series_max`, `trend`, `share`, `days`, `mode`), `Text`/`Rect`/`Polyline` fields, `op_rects`, `rasterize`, `png_bytes`, `svg_text`, `layout_hero`, `layout_terminal`, `HERO_RULE_X`, `card_paths`, `write_card`, `cards()`.
4. **Review Focus.** All five items have tests in their owning tasks: Task 2 (malformed sessions), Task 7 (extreme values, long windows), Task 8 (one existing file, `--out` not a directory) and Task 6 (unknown glyph).
