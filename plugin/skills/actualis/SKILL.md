---
name: actualis
description: Audit coding-agent activity with the local actualis CLI. Use when the user asks what their coding agents did or cost, whether a credential or secret leaked into a command, whether a known-bad package version was installed (--ioc), which hosts or downloads agents contacted (--network), or whether actualis itself is trustworthy (--self-check).
---

# actualis

actualis reads agent transcripts on this machine, read-only and offline, and
reports cost, risky shell commands, exposed credentials, downloads and
findings (ids like `AF002`). Let the CLI read the transcripts; never open
transcript files (`~/.claude`, `~/.codex`, ...) yourself.

## Before anything

1. Run `command -v actualis`.
2. If it is missing, tell the user it is not installed and suggest
   `pipx install actualis` (or `uv tool install actualis`). Never install it
   unasked.

## Pick the command

| the user asks | run |
|---|---|
| what agents did, what it cost | `actualis --days 7 --json` (widen or narrow `--days N`) |
| one repo or ticket | add `--project SUBSTR` |
| one agent | add `--agent claude` (or `codex`, `copilot`, `gemini`, `qwen`) |
| did a credential leak, risky commands | `actualis --bash` or `actualis --coach` |
| one credential's blast radius | `actualis --replay ID` |
| what is finding AF0xx | `actualis --why AF0xx` |
| was a bad package version installed | `actualis --network --ioc FILE --json` (FILE is the user's known-bad list; see docs/ioc.md) |
| what hosts or downloads | `actualis --network`, narrow with `--host HOST`, `--package NAME`, `--unasked` |
| can I trust actualis | `actualis --self-check` |
| how is a number computed | `actualis --explain` |

Prefer `--json` when you need to parse; use the text report when summarising
for a human. `--json` is refused by some modes (`--bash`, `--coach`,
`--self-check`, `--why`, `--explain`); drop it there. Do not combine modes.
`--network --json` emits only the network object.

## Exit codes

`0` clean, `1` could not run (no transcripts, bad `--root`), `2` usage error
(bad flag combination), `3` findings at or above `--fail-on`, `4` a
`--self-check` check failed. Exit 3 is a verdict, not a crash.

## Reporting

- Lead with the answer, then list findings by id and severity
  (critical, high, med, info) with the project and when.
- Say what the numbers do not cover: "no match" for `--ioc` is not "not
  affected" (lockfile installs and postinstall hooks are out of sight).
- Never paste credential values. actualis redacts them by default; do not
  pass `--no-redact`, and do not reconstruct a value from fragments.
- Do not suppress findings (`--suppress`) unless the user asks.

## Network and reputation

actualis itself makes no network calls. The companion `actualis-reputation`
is the only part that does. You may SUGGEST it when the user wants host
reputation; never run it yourself.

## Verify

Everything is checkable: `actualis --self-check`, `actualis --explain`, and
`actualis --version`.
