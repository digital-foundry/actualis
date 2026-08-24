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
