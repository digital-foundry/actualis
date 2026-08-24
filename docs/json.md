# JSON output

`actualis --json` emits the full report as machine-readable data.
**Credentials are redacted by default**, including here; `--no-redact` disables
that and prints a warning.

## Top-level keys

| key | contents |
|---|---|
| `schema_version` | integer. The contract version of this document. See [Compatibility](#compatibility) |
| `version` | tool version. Changes far more often than `schema_version` and means something different |
| `window` | `from`, `to`, `days`, `active_days` |
| `scanned` | `files`, `bytes`, `roots[]` |
| `messages` | count of assistant messages with usage |
| `cost_usd` | total, at provider list prices |
| `cost_usd_from_unpriced_models` | how much of `cost_usd` came from models with no published rate |
| `cost_note` | how unpriced models are rated, and in which direction that errs |
| `duplicate_usage_records_skipped` | repeated records for the same message, counted once |
| `duplicate_note` | why repeats occur and how they are collapsed |
| `tokens` | `input`, `output`, `cache_w_1h`, `cache_w_5m`, `cache_read` |
| `by_agent` | cost per agent (`claude-code`, `codex`) |
| `subagents` | see below |
| `cache` | `fleet_hit_rate_pct`, `saved_usd`, `by_project{}` |
| `by_ticket[]` | see below |
| `by_ticket` | cost and message counts per ticket, parsed from branch names |
| `by_branch` | cost per branch bucket, including `trunk` and `detached HEAD` |
| `by_model` | cost per model |
| `by_project` | cost per project |
| `by_day` | cost per calendar day, ascending |
| `tools` | tool-call counts, descending |
| `bash` | `total`, `commands{}`, `flag_counts{}`, `flags[]` |
| `coach` | findings: `id`, `severity`, `title`, `evidence`, `action`, `impact` |
| `secrets` | array; see below |
| `secret_exposures` | commands containing credential material |
| `secret_projects` | those commands per project |
| `redacted` | whether values were masked (`true` unless `--no-redact`) |
| `permission_modes` | turns per permission mode |
| `denials` | rejections by kind |
| `unknown_models` | models seen with no pricing entry, billed at Opus-tier rates |
| `aggregator_priced_models` | models priced from a third party because the vendor publishes no rate for that id |

## Compatibility

`schema_version` is currently **1**. It describes the shape of this output and
is deliberately separate from the tool version: `actualis --version` moves on
every release, `schema_version` moves only when something breaks.

Within a major schema version:

| | |
|---|---|
| **May** | a new key appears |
| **May** | a new value appears in an existing enum, such as a new denial kind |
| **May** | a new field appears on an array element |
| **May** | a description, note string, or key order changes |
| **Never** | a key is removed or renamed |
| **Never** | a key changes type |
| **Never** | an existing key changes meaning |

So parse defensively for keys you do not recognise, and rely on the ones you do.

The freeze is machine-checked, not a promise in prose. `JSON_SCHEMA` in
`actualis.py` is a flat map of dotted path to type, and the test suite validates
real output against it on both an empty and a populated fleet. A key cannot be
removed, renamed or retyped without that declaration changing in the same commit,
which forces the author to decide whether they are breaking the contract.

Path syntax in that declaration:

| form | meaning |
|---|---|
| `a.b` | a fixed key |
| `a.*` | a map whose **keys are data** — project names, model ids, dates |
| `a[].b` | a field on each element of an array |
| `str\|null` | legitimately absent sometimes |

Two consequences worth knowing. Money fields are **always** floats, including
when they are zero — an earlier version emitted `0` on an empty fleet and `0.0`
otherwise, which broke strict type validation on a quiet day. And a `*` or `[]`
path is absent when the map or array is empty; that is not a missing key, it is
an empty collection.

## `secrets[]`

```json
{ "priority": "critical", "types": ["STRIPE_SECRET_KEY"], "id": "a41f9c02",
  "uses": 2, "first_seen": "2026-05-30", "last_seen": "2026-05-30",
  "projects": ["…"] }
```

`id` is `sha256[:8]` of the value. The value itself is never emitted.

## `by_ticket[]`

```json
{ "ticket": "#412", "cost_usd": 3337.23, "messages": 10788,
  "branches": ["feat/412-checkout-v2", "feat/412-checkout-api"],
  "projects": ["…"], "active_days": 5,
  "first_seen": "2026-05-06", "last_seen": "2026-06-02" }
```

## `subagents`

```json
{ "runs": 872, "by_model": {…}, "status": {…},
  "cost_floor_usd": 58.03,
  "cost_floor_note": "lower bound only; cumulative subagent spend is not
                      recoverable from the parent transcript",
  "tools": {…}, "lines": {…}, "wall_clock_hours": 63.9 }
```

`cost_floor_usd` is **a floor, not a total**, and is deliberately excluded from
`cost_usd`. The parent transcript records only each run's final message, so
cumulative subagent spend cannot be recovered and is not estimated.

# MCP tools

`actualis --mcp` speaks JSON-RPC over stdio. Register it with:

```sh
claude mcp add actualis -- actualis --mcp
```

| tool | returns |
|---|---|
| `fleet_summary` | window, spend, cache hit rate, top projects, unsupervised share |
| `ticket_cost` | cost for one ticket, or the most expensive ones |
| `exposed_secrets` | rotation list: priority, types, fingerprint, dates |
| `coach_findings` | `AF001`–`AF011` with evidence and actions |
| `shell_audit` | counts by category, permission modes, the subagent blind spot |
| `explain` | how a figure is computed, what it assumes, how to verify it |
| `verify_agents` | installed agent platforms and their signature status |

**What it deliberately does not return.** Everything here is read by a model and
written back into a transcript that this tool then scans, so the surface is
narrow by design: aggregates, types, `sha256[:8]` fingerprints and counts. Never
a secret value, never raw command text. Tests assert both.

Both the retired `initialize` handshake and the stateless 2026-07-28 style are
answered, since clients in the wild vary. The scan is cached for the life of the
process.


## Repeated records and unpriced models

Two keys exist because two numbers used to be silently wrong.

`duplicate_usage_records_skipped` counts records that were skipped because
another record already reported the same `message.id`. Claude Code re-emits an
assistant record while a response streams — same message id, same usage block,
a fresh record uuid each time — so one billable message can appear many times.
Billing each occurrence overstated real spend by **2.13x** on a live corpus, in
which 50.9% of usage records were repeats. Deduplication is by message id and
keeps the first occurrence; across 71,311 ids on that corpus no id ever carried
a differing usage payload, so the choice of which copy to keep does not matter.
A non-zero value here is normal and healthy. Zero on a large scan is suspicious.

`cost_usd_from_unpriced_models` is the share of `cost_usd` attributable to
models absent from the rate table. Those are priced at the top of the known
range for their provider, so that share is an upper bound among current models,
not a measurement. It is reported separately rather than folded in so you can
subtract it and see the floor. A model priced above everything in the table
would still be understated — which is exactly why the number is exposed instead
of being described as merely "unknown".
