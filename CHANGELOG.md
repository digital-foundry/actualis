# Changelog

## 0.1.2 — 2026-08-24

### Fixed

- **`command_head` reported redirects and flags as programs.** `most_run` was
  listing `-oE`, `-E` and `2>/dev/null` as if they were commands, in both the
  report and the MCP `shell_audit` tool. Two defects: skipping `cd` plus its
  path argument left a trailing redirect as the first surviving token, and an
  assignment whose value is a command substitution was skipped whole, walking
  the parser onto the next token — usually a flag. So `cd /tmp 2>/dev/null`
  reported `2>/dev/null`, and `TOK=$(grep -oE …)` reported `-oE` rather than
  `grep`, which is what actually runs.

  On a real corpus the correction redistributed the garbage into real programs
  rather than only removing it: in auto-mode denials `grep` went from 0 to 15,
  `cat` from 9 to 15, `gh` from 13 to 18.

### Added

- **`tools/denials.py`** — joins Claude Code's tool-refusal records to the exact
  commands they blocked, via `tool_use_id`. Read-only, no network, standard
  library only, and it prints program names rather than command text. Written
  for [an article](https://actualis.app/writing/what-your-agent-refuses/) and
  kept because the join turns out to be useful: a refused command is never sent
  to a provider, so this is a signal no API-layer tool can see.

## 0.1.1 — 2026-08-24

A three-pass audit — security, business logic, robustness — found eleven
defects in 0.1.0. All are fixed here, each with a regression test that fails
against 0.1.0.

### Fixed — cost was more than double

- **One message is now billed once, however many transcript records carry it.**
  Claude Code re-emits an assistant record while a response streams: same
  `message.id`, same usage block, a fresh record uuid each time. 0.1.0 billed
  every occurrence. On a live corpus of 145,116 usage records, **50.9% were
  repeats** and the reported total was **2.13× the real figure** — $46,997
  against $22,064. Deduplication is by message id, keeps the first occurrence,
  and also collapses messages replayed across resumed sessions. Across 71,311
  ids in that corpus, no id ever carried a differing usage payload, so which
  copy is kept does not matter.

  This affected every derived number: cost by project, day, ticket, model and
  branch, all token counters, cache hit rate, message counts, every coach
  finding, `--json`, `--share` and the MCP `fleet_summary` tool. **If you acted
  on a figure from 0.1.0, re-run it.** The report now prints how many repeats
  were collapsed, so the change is visible rather than silent.

  The Codex path already guarded its own version of this and had a test named
  `session_total_is_the_max_not_the_sum`. The Claude path had neither, which is
  why 107 passing tests missed it.

### Fixed — security

- **Notification text is no longer interpolated into a PowerShell command.**
  The Windows path built `Write-Output "…"` with an f-string. JSON escaping
  covers quotes and backslashes but not `$` or backtick, and PowerShell
  evaluates `$(…)` inside double quotes — while `--watch` fed transcript-derived
  command text straight in. That is code execution from content an agent wrote
  into its own transcript, which is the threat model this tool is built around.
  The text now travels through the environment and is referenced by name. The
  Go tray carried the same latent pattern, one call site away from being
  reachable, and is fixed the same way.
- **`clean()` now strips Unicode characters that reorder or hide text**, not
  only ASCII control characters. A right-to-left override visually reverses the
  tail of a command in most terminals and needs no escape sequence at all, so
  the previous defence stopped ANSI escapes while leaving the same attack
  available through U+202E, zero-width characters and bidi isolates.
- **Redaction no longer publishes a usable slice of a short secret.** A
  four-character prefix is a hint on a 40-character token and 40% of a
  10-character password. The prefix now appears only above 24 characters, and
  the exact length — a fingerprint that confirms a guess — is bucketed.
- **The MCP result cache is bounded** (LRU, 8 entries) and the client-supplied
  window is clamped. The key came from the caller, so an unbounded cache let a
  client retain unbounded memory and force unbounded rescans. `days` now
  rejects booleans and clamps negatives, which previously put the cutoff in the
  future and returned nothing.
- **MCP internal errors no longer echo exception text to the client.** That
  text routinely carries absolute filesystem paths, and an MCP reply is written
  into the agent's transcript — the artefact this tool exists to keep clean.
  Detail goes to stderr; the client gets the error class.

### Fixed — correctness

- **Unpriced models are reported as their own number.** Cost from models with
  no published rate is accumulated separately and shown in the report, `--json`
  and MCP, so the share that is an upper bound rather than a measurement can be
  subtracted. Previously the two fallbacks erred in opposite directions with no
  way to tell which applied.
- **An unrecognised Codex model is priced as OpenAI.** The cached-token
  discount was gated on the provider from the rate table, so an unknown model
  fell back to the Anthropic default and a Codex session was billed at
  Opus-tier rates with no cache discount.
- **`contains_secret()` no longer fires on length alone.** It was
  `redact(text) != text`, and `redact()` truncates, so every command longer
  than 32,768 characters reported as holding a secret.
- **A failure to run `codesign` is no longer reported as "unsigned".** A
  timeout or missing binary returned the same value as a genuine negative
  result, turning a transient failure into a positive claim about a signature.
- **An unreadable `--root` prints an error instead of a traceback.**
- **`--root` honours `--agent`**, so `--root X --agent codex` uses the Codex
  parser rather than silently parsing rollouts as Claude transcripts.
- **The tray no longer breaks on a path containing a space**, and no longer
  considers a bare relative `actualis.exe` — which resolved against the working
  directory, and is how a planted binary gets run.

## 0.1.0 — 2026-08-23

First public release.

### Reporting
- Cost, tokens and message counts across **Claude Code** and **Codex**, priced
  per model with correct cache multipliers (read 0.10×, 5m write 1.25×, 1h write
  2.00×). On real workloads ~98% of tokens are cache reads, so getting this
  wrong overstates spend roughly tenfold.
- **Cost per ticket** from branch names, grouping the several branches a ticket
  often spans. Work on trunk or detached `HEAD` is reported separately rather
  than guessed at.
- **Cache efficiency by project**, benchmarked against your own median, with the
  dollar value of what caching saved.
- **Subagent attribution**: runs, models, tool activity, lines changed and
  wall-clock. Cost is an explicit floor, excluded from the headline, because the
  parent transcript records only each run's final message.
- Rates derive from **active days**, not calendar span.

### Security
- **Shell audit** over every recorded command: nine deterministic categories, no
  model in the loop. Tuned to a 3.8% flag rate by deleting rules as much as
  adding them.
- **Secret classification**: distinct credentials by type and priority,
  deduplicated by `sha256[:8]`, ranked for rotation. Turns "310 flagged commands"
  into "37 secrets, 18 worth rotating".
- Reports what it **cannot** see: subagent shell commands are absent from the
  parent transcript, ~21% of shell activity on the author's fleet.
- **Redaction on by default** everywhere including `--json`.

### Coaching
- Eleven findings (`AF001`–`AF011`) with evidence, an action, and an impact
  estimate where one is computable. Benchmarked against your own history, so no
  telemetry is needed and it works with one user.

### Trust and explainability
- **Agent binary verification.** Before trusting a transcript, the code
  signature of the agent that produced it is checked against the expected
  publisher — Anthropic for Claude Code, OpenAI for Codex. A tampered or
  unsigned binary is reported as such rather than quietly accepted. Verified
  empirically by flipping one byte of a 325MB signed binary and confirming the
  check fails.
- **`--why`** expands any finding to the records behind it; **`--explain`**
  shows a metric's arithmetic, the rate applied, and what was excluded. No
  figure is presented that cannot be traced to its evidence.
- Unknown model rates are reported as unknown and excluded from totals rather
  than guessed, and the total says so when it is short.

### Tray
- Native menu bar app for **macOS, Linux and Windows**, reading the same local
  data as the CLI with no separate service.
- State is carried by form as well as colour, so the mark still reads without
  it. A newly-appearing critical credential raises one notification, once, per
  credential — the first scan establishes a baseline rather than dumping a
  month of history at launch.
- Report a bug, request a feature, or support development from the menu. A
  prefilled bug report carries the version and platform and nothing else: this
  tool reads credential exposures, and a convenient diagnostics attachment
  would be the worst bug it could ship.

### Interfaces
- **MCP server** over the 2026-07-28 stateless spec, exposing the same
  read-only data to an agent that the CLI shows a human.

### Modes
- `--watch` live alerting with native notifications, plus a macOS LaunchAgent.
- `--share` postable summary containing nothing identifying, verified by tests
  that plant identifying strings and assert none survive.
- `--coach`, `--bash`, `--json`, and filters `--days`, `--project`, `--agent`,
  `--top`, `--root`.

### Not supported, and why
- **Cursor and Windsurf.** Their local stores are empty shells; content is
  server-side. Verified on a machine with both installed.

### Licence
- AGPL-3.0-or-later. Section 13 closes the hosted-service gap that GPL-3.0
  leaves open.
