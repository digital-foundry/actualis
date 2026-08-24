# Changelog

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
