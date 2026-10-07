# `--card` and Copilot CLI support — design

Date: 2026-10-07
Status: approved 2026-10-07
Target release: v0.2.0

## Intent

**Goal (stated):** an announceable release on actualis.app that drives new
users and word of mouth.

**Baseline:** PyPI ~44 downloads/week (444/month, decaying from a late-August
spike), 2 GitHub stars, no issues requesting other agents.

**Success:** installs and posted cards after the v0.2.0 announcement.

**Launch line:** "Actualis now reads Copilot CLI. Post your card."

**Constraints (inherited, not negotiable):**

- Local, read-only, no network. `--self-check` must keep passing.
- Single file, no third-party dependencies, Python 3.9+, AGPL-3.0.
- Nothing identifying may reach shareable output. The existing `--share` leak
  test is the enforcement mechanism and is extended, not replaced.

**Out of scope:** Gemini CLI. The local 0.42.0 install writes only
`~/.gemini/tmp/<project>/logs.json` (user prompts; keys `message`,
`messageId`, `sessionId`, `timestamp`, `type`), with no tokens or tool calls.
Third-party docs describe a `chats/*.jsonl` format that could not be verified.
Revisit once a real session with that format is available.

## Build order

1. Copilot CLI reader (part 2). The card counts agents, so it lands first.
2. `--card` (part 1).

Each part is independently testable and could ship alone, but they are
announced together.

---

## Part 1 — `--card`

### Command

```
actualis --card [supervision|cost|volume] [--style hero|terminal]
         [--days N] [--agent ...] [--out PATH]
```

- Mode defaults to `supervision`. Style defaults to `hero`.
- Writes `actualis-card.svg` and `actualis-card.png` to the current
  directory, or to `--out` (a directory).
- Never overwrites. If either file exists, both get the next free suffix:
  `actualis-card-2.svg` / `actualis-card-2.png`.
- Prints both paths and one line of suggested caption text, e.g.
  `73% of my coding agents' shell commands ran unsupervised last month. uv tool install actualis`.
- These two files are the only new writes. `--self-check` lists the card
  output path as the second path the tool can write to, next to the
  suppressions file.

### Data

Inputs are the values `render_share` already derives from counts, plus two new
per-day counters on `Fleet`:

- `bash_by_day: dict[str, int]` — shell commands per ISO date.
- `unsupervised_by_day: dict[str, int]` — of those, how many ran without a
  human approval step.

"Unsupervised" uses the same definition `render_share` uses today (permission
mode containing `auto` or `bypass`), plus `copilot:auto` from part 2.

Credentials are never on the card, in any mode or style. There is no flag
to add them.

### Rendering architecture

```
Fleet ──► card_model(fleet, mode) ──► layout_<style>(model) ──► [DrawOp]
                                                                  │
                                              ┌───────────────────┴──────┐
                                              ▼                          ▼
                                        write_svg(ops)            write_png(ops)
```

- `card_model` returns a plain dict of the numbers and labels for the mode.
  This is the only place that reads `Fleet`, and it is what the leak test
  checks.
- `layout_hero` and `layout_terminal` turn the model into a list of drawing
  operations: `Text(x, y, scale, colour, str)`, `Rect(x, y, w, h, colour)`,
  `Polyline(points, colour, width)`.
- `write_svg` and `write_png` each take that list. Neither reads `Fleet`.
- PNG is stdlib only: RGBA buffer → per-scanline filter byte 0 →
  `zlib.compress` → `IHDR`/`IDAT`/`IEND` chunks with `struct` and
  `zlib.crc32`.
- Text: one embedded bitmap font (8×16 cells), drawn at integer scales.
  Glyphs: printable ASCII, `$ % · ▁▂▃▄▅▆▇█ ░`, plus `─`. Scales: ×2 labels,
  ×3 terminal body, ×4 stats, ×6 terminal hero, ×10 hero number. The SVG
  uses the same pixel grid as `<rect>` runs, so both outputs look the same.
- Polylines on the PNG use integer Bresenham lines at the stroke width. No
  anti-aliasing.
- Canvas 1200×630, dark palette only:
  bg `#0d1117`, fg `#e6edf3`, muted `#8b949e`, rule `#30363d`,
  accent `#f0883e`.

### Style: `hero` (layout A)

- Top-left label: `ACTUALIS · LAST N DAYS` (×2, muted).
- Left column: hero value (×10, accent), and a caption of up to 2 lines below
  it (×3).
- Right column, after a vertical rule: three stat rows of `value label`
  (×4 value, ×2 muted label).
- Bottom band: a sparkline over the window. Bottom-left footer:
  `uv tool install actualis` (×2, muted).

| mode | hero | caption | stats | sparkline |
|---|---|---|---|---|
| supervision | `NN%` | of my agents' shell commands ran with nobody approving them | commands · refused · agents | daily unsupervised % |
| cost | `$N,NNN` | at API list price, last N days | $/active day · cache saved · agents | `by_day` cost |
| volume | `NN,NNN` | shell commands my agents ran | % of tool calls · refused · agents | daily command count |

### Style: `terminal` (layout C)

A monospace grid at ×3 (40 columns × ~13 rows usable), hero line ×6.

```
$ actualis --card <mode>
ACTUALIS · what actually ran
<HEADER> ───────────────────────────────
<hero> <hero label>
<bar rows ×3>
30d <block sparkline>
                         uv tool install actualis
```

| mode | header | hero | bar rows |
|---|---|---|---|
| supervision | `SUPERVISION` | `NN%` unsupervised | `auto` / `you` / `refused` |
| cost | `COST` | `$N,NNN` | top 3 models by spend |
| volume | `SHELL` | `NN,NNN` commands | `git` / `test` / `install` / `other` |

- Bars are 28 cells of `█` and `░`, each followed by its count.
- **Model names:** a model is shown only if its family matches a priced entry
  in the built-in rate table. Anything else is shown as `custom`, so a
  fine-tune ID like `ft:acme-internal-…` never appears.
- **Command categories** come from a fixed classifier on `command_head`:
  `git`; `test` (pytest, jest, vitest, go test, cargo test, npm test, …);
  `install` (pip, uv, npm i, brew, apt, …); everything else is `other`. Raw
  command heads are never displayed.

### Edge cases

- **Fewer than 3 active days:** no sparkline. The text
  `not enough days for a trend` (muted) takes its place.
- **No shell commands:** supervision and volume modes exit non-zero with
  `no shell commands in window — try --days or --card cost`. No card is
  written.
- **No priced usage:** cost mode shows the hero `—` with the caption
  `no priced usage in window`, never `$0`.
- **Copilot premium requests:** a 4th line in the cost-mode stats column,
  `N premium requests`, shown only when Copilot sessions exist. It is never
  converted to dollars.

### Tests

- Golden SVGs: 2 styles × 3 modes = 6 files, from
  `tools/make-demo-fleet.py`.
- PNG: the signature, the `IHDR` size of 1200×630, CRC validity of every
  chunk, and the sha256 of the decompressed pixel buffer against a golden
  value.
- The SVG and PNG agree: rasterising the draw ops directly gives the same
  pixel buffer as `write_png`.
- Leak test, extended: seed a project name, branch, ticket id, path,
  command, credential and fingerprint, plus the model ID
  `ft:leaktest-model`. Assert none of them appears in `card_model` output,
  the SVG text, or the decompressed PNG bytes. Assert `custom` appears for
  the seeded model.
- The edge cases above, one test each.
- Non-overwrite: create `actualis-card.svg` in advance and assert `-2` is
  written.
- `--self-check` lists the card path.

---

## Part 2 — Copilot CLI reader

Shapes verified against 17 local Copilot CLI 1.0.70 sessions.

### Discovery

- `copilot_roots()`: `$COPILOT_HOME` if set, otherwise `~/.copilot`, then
  `session-state/*/events.jsonl`. Returns an empty list when the directory is
  missing, matching `codex_roots()`.
- `--agent` choices: `all | claude | codex | copilot`.
- `--watch` (`_jsonl_files`), `--agents` (`AGENT_COMMANDS`: `("Copilot CLI",
  "copilot")`), `no_transcripts_message()`, and `--self-check`'s list of
  read paths all include the new root.
- `session.db` in the same directory is **not** read. `events.jsonl` is
  enough, and reading it keeps the parser stdlib-JSON only.

### Record format

Each line: `{type, data, id, parentId, timestamp}`.

### Mapping

| Actualis concept | Copilot source |
|---|---|
| session id | the directory name, cross-checked against `session.start.data.sessionId` |
| project | `session.context_changed.data.gitRoot`, else `cwd`. The most recent value wins. |
| branch / ticket | `session.context_changed.data.branch`, then the existing `extract_ticket` |
| shell command | `tool.execution_start` with `toolName == "bash"`: `data.arguments.command`, timestamped by the event |
| other tool calls | `tool.execution_start`, other `toolName` values, sent to `add_tool` |
| supervision | a `bash` call counts as `copilot:prompted` if a `permission.requested` with `permissionRequest.kind == "shell"` and the same `toolCallId` exists, otherwise `copilot:auto`. Added to `permission_modes`. |
| refusal | `permission.completed` whose `result.kind` is not in {`approved`, `approved-for-location`}, sent to `add_refusal` with kind `copilot:<result.kind>` |
| cost | `session.shutdown.data.modelMetrics[model].usage`: `inputTokens`, `outputTokens`, `cacheReadTokens`, `cacheWriteTokens`, `reasoningTokens`. Priced through `rate_for(model)`, one record per model per session, via a new `add_copilot_session` modelled on `add_codex_session`. |
| premium requests | `session.shutdown.data.totalPremiumRequests`, a new counter `premium_requests_by_agent["copilot"]` |
| subagents | `subagent.completed.data`: `totalTokens`, `totalToolCalls`, `durationMs`, sent to `add_subagent` |
| replay | each `bash` command becomes a `ReplayEvent`, using the existing proximity grading (same session, same project, elsewhere) |

Shell commands go through the existing `audit_command`, `classify_secrets` and
`redact` unchanged.

### Limits, reported rather than guessed

- **Denials are unverified.** All 31 local `permission.completed` results were
  `approved` or `approved-for-location`. Any other `result.kind` counts as a
  refusal, and `--explain copilot` says this mapping comes from the schema,
  not from observed data. **Release blocker:** capture one real denied
  command in a test session and add its `result.kind` to the fixture.
- **Sessions without `session.shutdown`** are counted as `unpriced` and shown
  as `N Copilot sessions unpriced (no shutdown record)`. No cost is estimated
  from `assistant.message.outputTokens`.
- **"auto" includes allow-listed commands.** A command Copilot pre-approves
  through config produces no prompt, so it is counted as unsupervised.
  `--explain copilot` says so.
- `vendor_gaps()` gains a `copilot` column. Branch is ✓, which is better than
  Codex. Refusal is ✓ with the caveat above.

Observed locally: 356 `bash` calls against 23 shell permission prompts, about
94% unprompted.

### Tests

Synthetic fixture under `tests/fixtures/copilot/session-state/`, built from the
shapes above, with no real content:

1. A normal session: context, 3 `bash` calls (1 prompted and approved), a
   shutdown with 2 models in `modelMetrics`.
2. No `session.shutdown`.
3. A `permission.completed` with `result.kind: "denied-by-user"` (a
   placeholder until the real value is captured).
4. A `bash` command containing a seeded credential.

Assertions:

- Cost is counted once per model per session, and the total matches
  `rate_for` × usage.
- Session 2 is reported unpriced, not $0 and not omitted.
- Supervision: 2 auto, 1 prompted.
- The refusal is recorded as `copilot:denied-by-user`.
- The credential is grouped by fingerprint, and the value never appears in
  any output or in `--json`.
- `--replay <fp>` finds the in-session commands.
- `--self-check` lists `~/.copilot` as read, with sha256 values identical
  before and after a scan.
- `--agent copilot` filters to Copilot only.
- The `--agents` row is present.

---

## Release checklist (v0.2.0)

- [ ] Capture a real Copilot denial; replace the fixture placeholder.
- [ ] Regenerate the README demo images, including one hero and one terminal
      card from the demo fleet.
- [ ] Add a CHANGELOG entry.
- [ ] Update the actualis.app announcement: the launch line, both card styles,
      and the "Claude Code · Codex · Copilot CLI" line.
