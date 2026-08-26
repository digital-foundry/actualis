# Changelog

## Unreleased

### Changed

- **Both detector lists were audited against a real corpus rather than against
  intuition**, and the result went in both directions.

  **Added: Supabase personal access tokens.** A corpus scan found 58
  occurrences of `sbp_` followed by exactly 40 alphanumerics — one consistent
  shape, no detector. A Supabase PAT carries full account authority, so it is
  classified critical.

  **Rejected: Resend (`re_`).** The same scan found 180 `re_` matches across 37
  distinct shapes, every one an ordinary lowercase identifier
  (`re_deploy-preview-branch`) with no digits, no mixed case and no entropy.
  Adding it would have produced 180 false positives and zero true ones. A
  two-character prefix is too generic to carry a detector, and the rejection is
  recorded in the source with the measurement so it does not get re-proposed.

  **18 false positives removed.** All 49 distinct name-based detections on the
  corpus were reviewed by hand. The wrong ones were not one-offs — they fell
  into shapes, and each exclusion added names the case that produced it:
  `AUTHOR` (a trigger word starting a longer word, the same defect class as
  `FORKEY`), `SESSION_RECORDING_SAMPLE_RATE` (analytics config),
  `AUTH_PROVIDER_ID` (an identifier), `EMBED_TURNSTILE_SITE_KEY` (a site key is
  public by design; only its paired secret is secret),
  `TINFOPLIST_KEY_LSAPPLICATIONCATEGORYTYPE` (an Xcode build setting).

  On the corpus this took distinct secrets from 128 to 112 and distinct kinds
  from 61 to 45, with no true positive lost. Both batteries ship as tests.

### Fixed

- **A template placeholder no longer defeats an exclusion.** Names arrive
  wrapped as `__X__`, `{{X}}` or `%X%`, and the decoration is not part of the
  name, so one rule now covers every spelling.
- **A detector could be counted without being masked.** Adding Supabase to
  `SECRET_TYPES` without adding it to the redaction prefixes classified the
  token and then printed it. A test now checks the invariant across every typed
  detector, not just the named ones.

## 0.1.4 — 2026-08-26

Four correctness defects, all reproduced before being fixed. Two of them made
the tool state something arithmetically impossible on its own front page.

### Fixed

- **`--days N` reported N+1 active days.** The cutoff was a rolling timestamp,
  `now - N days`, which lands mid-day — so records from that partial date plus N
  further dates survived. A seven-day window reported eight active days, making
  the denominator of a headline rate exceed its own window. `--days N` now means
  the last N calendar days including today, in UTC, which is both what people
  mean by it and the only reading under which `active_days` is bounded by N.

- **"30 active days of 29".** The report compared a count of dates against an
  elapsed duration. Three consecutive dates span two days, so for any contiguous
  window the two differed by one, every time — off by one by construction, which
  reads as a bug because it is one. It now compares dates with dates
  (`span_dates`), and `span_days` keeps its old meaning with a docstring saying
  which is which.

- **Cache-write tokens with no TTL split were under-priced by 57%.** Older
  records carry only a flat `cache_creation_input_tokens`, so the multiplier is
  assumed, and it assumed 5m (1.25×). Measured across **71,903 deduplicated
  records that do carry the split, the real mix is 95.2% 1h and 4.8% 5m**. It
  now assumes 1h (2.00×) — the more expensive reading, matching how unknown
  model rates are handled. The assumed volume is counted as
  `tokens.cache_w_assumed` and shown in the report when non-zero, so the
  adjustment is never silent. On current transcripts it is zero.

### Added

- **AF012 — deduplication collapsed nothing, which should be impossible.**
  `docs/json.md` already said a zero repeat count on a large scan is suspicious.
  Nothing evaluated that sentence. If a transcript format stops carrying a
  message id, every record is billed again and cost silently doubles — the exact
  0.1.0 defect, reintroduced by a vendor change rather than by us. Now a
  critical finding above 500 messages.

- **AF013 — the rate table has not been checked in a long time.** Staleness
  already printed a line in the report, but a warning that exists only in
  rendered text is invisible to `--coach`, to `--json` and to the MCP server,
  which is where anything programmatic reads from.

## 0.1.3 — 2026-08-24

Detection got wider and better sourced, and there is now a way to tell it when
it is wrong. **If you are on 0.1.0, upgrade: it overstated cost by 2.13×.**

### Added

- **You can tell it when it is wrong, where you see it.** A detector that cries
  wolf gets ignored, and widening detection made that urgent rather than nice.

  ```sh
  actualis --suppress a41f9c02 --reason "test fixture in our CI config"
  actualis --suppressions
  ```

  **A suppression never removes a finding from the count.** It is held back from
  the actionable list and still appears in `--json` with `suppressed: true` and
  its reason, and `suppressed_secrets` reports the total. If suppressing deleted
  the finding, a heavily suppressed scan would be indistinguishable from a clean
  one, and the report would be lying by omission.

  The store is plain text — greppable, diffable, reviewable in a pull request,
  editable by hand six months later. Read from
  `$XDG_CONFIG_HOME/actualis/suppressions` and `./.actualis-suppressions`, so a
  team can commit a shared list. Every entry carries a reason, and `--suppress`
  without `--reason` says so rather than accepting a bare fingerprint quietly.

  The report shows how to suppress **next to the findings themselves**, plus a
  pre-filled issue URL for a detection that is wrong for everyone. The URL is
  printed. It is never opened and nothing is ever sent — the percent-encoder is
  hand-written rather than importing `urllib`, so "this file imports nothing
  that can open a socket" stays an absolute rather than a rule with an
  exception. A test asserts it matches `urllib.parse.quote` exactly.

- **Rate provenance is now an ordered pecking order, not a boolean.** A rate was
  either `VENDOR` or `AGGREGATOR`, which lumped a reputable third party together
  with an outright guess. There are now five tiers, best to worst: `vendor`,
  `vendor-doc`, `aggregator`, `family`, `default`.

  Resolution falls back through them: exact entry, then the nearest current
  sibling in the same model family, then the most expensive rate known for that
  provider, then the global ceiling. Each step reports the tier that answered,
  so a guess cannot present itself as a published price. An unseen
  `claude-sonnet-4-9` is now priced from the Sonnet family instead of the
  Opus-tier ceiling, which is roughly 40% closer.

  Inference errs **upward** on purpose — a bill that surprises you downward is a
  better failure than one that surprises you upward. Retired models are excluded
  from inference: `claude-opus-4-1` at $15/$75 is still priced exactly for
  historical transcripts, but must not set the ceiling for a model that does not
  exist yet.

- **The report says how much of a total rests on a published price.**
  `confident_pct` plus a per-tier breakdown, in the report and in `--json`. A
  total mixing published prices with inferences is only as sound as its weakest
  component, and without this a reader cannot tell an estimate from a
  measurement.

- **Staleness is reported, computed offline.** The tool makes no network calls,
  so it cannot know whether a price changed — but it can know how long since
  anyone checked. Past 90 days the report says so rather than quoting a dated
  number with a straight face.

- **`tools/price-check.py`** — the refresh path, deliberately outside the CLI.
  It reports table age and coverage offline, and with `--fetch` checks whether
  each priced model id still appears on its provider's page. It does **not**
  parse prices and never writes one: a silently mis-parsed rate would carry the
  authority of a checked one. A test asserts the CLI imports no networking
  module at all.

### Fixed

- **Named-secret detection missed 19 of 21 credential-shaped names.**
  `export STRIPE_KEY=...` was not flagged: the name list carried `SECRET`,
  `TOKEN` and `API_KEY` but no bare `KEY`. Also missed: `SIGNING_KEY`,
  `ENCRYPTION_KEY`, `MASTER_KEY`, `DEPLOY_KEY`, `OPENAI_KEY`, `SUPABASE_PAT`,
  `SENTRY_DSN`, `DB_CREDENTIAL`, `AUTH_HEADER`, `SESSION_COOKIE` and more.

  Underneath it was two lists that had drifted apart: redaction and
  classification each had their own idea of what a credential is called. So
  `AUTH_HEADER` was masked in output but never reached the rotation list —
  `secrets` undercounted, and nothing said so. There is now one list, used by
  both, and a test asserting anything counted is also masked.

  On a real 145k-command corpus this took distinct secrets from 83 to 126.

  Widening detection without measuring the noise is how a security tool becomes
  ignorable, so the false-positive battery ships as a test too. `PRIMARY_KEY`,
  `CACHE_KEY`, `IDEMPOTENCY_KEY`, `KEY_NAME`, `KEYBOARD_LAYOUT`, `MONKEY_PATCH`,
  `PATH` and `PATTERN` all stay quiet. So do **publishable** keys —
  `SUPABASE_ANON_KEY` and anything prefixed `NEXT_PUBLIC_` or `EXPO_PUBLIC_` is
  meant to ship to a browser, and telling someone to rotate one teaches them to
  ignore the tool.

### Added

- **Refusals are now joined to the commands they blocked.** A refusal is its own
  transcript record carrying `toolDenialKind`, with no `tool_use` block of its
  own — it points back at the call it stopped through `tool_use_id`. Reading the
  refusal alone tells you that something was refused and nothing about what.
  Joined, it tells you a great deal.

  New `REFUSALS` report section, a `refusals` block in `--json`, the same detail
  on the MCP `shell_audit` tool, and `--explain refusals`. Program names only,
  never command text: the commands people refuse are the ones least suited to
  being pasted into an issue.

  On a real corpus the join is exact — 359 of 359 — and the two gates turn out
  to guard different doors. Humans most often stop `git`; the auto-mode policy
  most often stops `export`, `source` and `op`, which read secrets rather than
  destroy things.

  This is one machine. Refusals are not deduplicated across developers and are
  bounded by transcript retention, and the output says so rather than letting a
  per-machine count read as an organisation-wide one.

- **Reports are content-addressed.** Every `--json` payload carries
  `report_sha256`, the SHA-256 of itself with that one key removed, serialised
  canonically (sorted keys, no incidental whitespace, UTF-8 rather than escaped
  ASCII). The human report prints the first 16 characters, so a screenshot can
  be checked against the payload it came from. docs/json.md gives the exact
  recomputation procedure in both Python and `jq`; both were run against real
  output, including non-ASCII project names, and agree.

  This proves a payload has not been altered since it was produced. It does not
  prove *when* it was produced or that a sequence of reports is complete — that
  needs a chain and a countersignature, which is separate work.

- **The `--json` output is now a frozen, versioned contract.** It carries
  `schema_version` (currently `1`), separate from the tool version, and
  `JSON_SCHEMA` in `actualis.py` declares every path and its type. The test
  suite validates real output against that declaration on both an empty and a
  populated fleet, so a key cannot be removed, renamed or retyped without the
  declaration changing in the same commit. docs/json.md states what may and may
  not change within a major version.

### Fixed

- **Money fields are always floats.** `sum([])` is `0` and `round(0, 4)` stays
  an `int`, so `cost_usd` and `cache.saved_usd` were integers on an empty fleet
  and floats otherwise. Anything validating types strictly would have broken on
  a day with no activity.

### Changed

- The release job no longer marks every release as `--latest`. A version
  carrying a PEP 440 pre-release marker (`a`, `b`, `rc`, `.dev`) is published
  with `--prerelease` instead, so a candidate cannot present itself as the
  current version.
- Every CI job now carries a `timeout-minutes`. A release run stalled on
  2026-08-24 with all of its steps green and the job never finishing; nothing
  would have stopped it before GitHub's 360-minute default. Concurrency groups
  also cancel superseded pull-request runs, though never a release: cancelling
  a publish mid-upload burns the PyPI filename permanently.

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
  library only, and it prints program names rather than command text. The join
  is exact — 359 of 359 on the corpus it was written against — and a refused
  command is never sent to a provider, so this is a signal that exists only in
  the local transcript. It is also what turned up the `command_head` bug above.

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
