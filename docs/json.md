# JSON output

`actualis --json` emits the full report as machine-readable data.
**Credentials are redacted by default**, including here; `--no-redact` disables
that and prints a warning.

## Top-level keys

| key | contents |
|---|---|
| `schema_version` | integer. The contract version of this document. See [Compatibility](#compatibility) |
| `report_sha256` | content address of this report. See [Verifying a report](#verifying-a-report) |
| `version` | tool version. Changes far more often than `schema_version` and means something different |
| `window` | `from`, `to`, `days`, `active_days` |
| `scanned` | `files`, `bytes`, `roots[]` |
| `messages` | count of assistant messages with usage |
| `cost_usd` | total, at provider list prices |
| `cost_usd_from_unpriced_models` | how much of `cost_usd` came from models with no published rate |
| `cost_note` | how unpriced models are rated, and in which direction that errs |
| `pricing` | where each rate came from, how old the table is, and how much of the total rests on a published price. See [Rate provenance](#rate-provenance) |
| `duplicate_usage_records_skipped` | repeated records for the same message, counted once |
| `duplicate_note` | why repeats occur and how they are collapsed |
| `tokens` | `input`, `output`, `cache_w_1h`, `cache_w_5m`, `cache_w_assumed`, `cache_read` |
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
| `suppressed_secrets` | credential findings marked as false positives on this machine |
| `suppressed_flags` | shell-audit findings marked as false positives on this machine |
| `suppression_note` | why a suppressed finding is still counted here |
| `secret_projects` | those commands per project |
| `redacted` | whether values were masked (`true` unless `--no-redact`) |
| `permission_modes` | turns per permission mode |
| `denials` | rejections by kind |
| `refusals` | what was stopped and by which gate, joined to the blocked command. See below |
| `unreadable_commands` | commands whose real content the transcript does not contain. See below |
| `vendors` | what each agent's transcript actually provides, and what it does not |
| `unknown_models` | models seen with no pricing entry, billed at Opus-tier rates |
| `aggregator_priced_models` | models priced from a third party because the vendor publishes no rate for that id |

## Inferred cache TTL

`tokens.cache_w_assumed` counts cache-write tokens from records that carry only
a flat total with no 1h/5m split. There is nothing to read, so the multiplier is
assumed.

It assumes **1h (2.00×)**. Measured across 71,903 deduplicated records that do
carry the split, the real mix is 95.2% 1h and 4.8% 5m — so the previous
assumption of 5m under-priced that component by 57%. Assuming the more expensive
reading matches how unknown model rates are handled: surprising someone downward
is a better failure than surprising them upward.

A non-zero value here means part of your cost rests on that assumption. On
current transcripts it is zero.

## Rate provenance

A cost tool that cannot say where a number came from is asking to be trusted
rather than checked. `pricing` says.

```json
{ "verified": "2026-08-24", "age_days": 0, "stale": false, "stale_after_days": 90,
  "tier_order": ["vendor","vendor-doc","aggregator","family","default"],
  "confident_pct": 28.17,
  "cost_by_tier":   { "vendor": 3.0, "aggregator": 3.15, "family": 4.5 },
  "models_by_tier": { "vendor": ["claude-sonnet-5"], "family": ["claude-sonnet-4-9"] } }
```

`tier_order` runs **best to worst**, and the order is the point:

| tier | means |
|---|---|
| `vendor` | the provider's own published price list |
| `vendor-doc` | provider docs, changelog or blog — not the price list |
| `aggregator` | a third party that tracks prices |
| `family` | **inferred** from the most expensive current sibling in the same model family |
| `default` | **inferred** from the most expensive rate known for that provider, or the global ceiling |

A model is resolved in that order: exact entry, then nearest family sibling,
then the provider ceiling, then the global ceiling. Each step reports the tier
that answered, so a guess cannot present itself as a published price.

Inference is deliberately biased **upward**. A bill that surprises you downward
is a far better failure than one that surprises you upward. Retired models are
excluded from inference: `claude-opus-4-1` is priced correctly for historical
transcripts, but must not set the ceiling for a model that does not exist yet.

`confident_pct` is the share of `cost_usd` priced from a provider's own rates.
**A total is only as sound as its weakest component**, and without this number
a reader cannot tell a measured figure from a mostly-inferred one.

### Staleness

The tool makes no network calls, so it cannot know whether a price changed. It
can know how long it has been since anyone checked, and `age_days` reports
exactly that, computed offline from `verified`. Past `stale_after_days` the
report says so rather than quoting an old number with a straight face.

Refreshing the table is a deliberate, human-run step — see `tools/price-check.py`
in the repository. The CLI will never fetch a price on your behalf.

## Verifying a report

Every report is content-addressed. `report_sha256` is the SHA-256 of the payload
with that one key removed, serialised canonically. The report itself prints the
first 16 characters, so a screenshot can be checked against the payload it came
from.

Recompute it yourself, without trusting this tool:

```sh
actualis --json > report.json

python3 - <<'EOF'
import hashlib, json
p = json.load(open("report.json"))
claimed = p.pop("report_sha256")
canonical = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
print("claimed:", claimed)
print("actual :", actual)
print("match  :", claimed == actual)
EOF
```

Or in one line, if you have `jq` and prefer not to run Python:

```sh
jq -Sc 'del(.report_sha256)' report.json | tr -d '\n' | shasum -a 256
```

Three things about the canonical form, because they are the whole reason two
runs agree:

- **Keys are sorted.** Dict ordering must not change the digest.
- **No incidental whitespace.** `separators=(",", ":")`.
- **`ensure_ascii=False`.** Non-ASCII stays as UTF-8 rather than being escaped
  into a second representation of the same text.

The digest covers everything except itself, including `version`. So the same
fleet scanned by two different releases produces two different digests, which
is correct: the report is not the same report.

This is deliberately the simplest possible form of the thing. It proves a
payload has not been altered since it was produced. It does **not** prove when
it was produced, or that a sequence of reports is complete — those need a chain
and a countersignature, which is separate work.

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

Each entry also carries `suppressed` and `suppressed_reason`. **A suppressed
finding is still listed here and still counted** — it is held back from the
actionable list in the report, not hidden. A scan with many suppressions must
not be indistinguishable from a clean one, and `suppressed_secrets` is the
number that makes the difference visible.

## `by_ticket[]`

```json
{ "ticket": "#412", "cost_usd": 3337.23, "messages": 10788,
  "branches": ["feat/412-checkout-v2", "feat/412-checkout-api"],
  "projects": ["…"], "active_days": 5,
  "first_seen": "2026-05-06", "last_seen": "2026-06-02" }
```

## `vendors`

Both agents are read; their transcripts do not contain the same things.

| Capability | Claude Code | Codex |
|---|---|---|
| Cost and token usage | yes | yes |
| Per-message dedup | yes | partial |
| Shell command text | yes | yes |
| Project attribution | yes | yes |
| Git branch | yes | no |
| Tool refusals | yes | no |
| Permission mode | yes | yes |
| Sandbox policy | no | yes |
| Subagent activity | partial | no |
| Subagent cost | no | no |
| Cache TTL split | partial | no |
| Reasoning effort | yes | no |

Every row in the payload also carries `depends_on`, naming the transcript field
the claim rests on, so it can be checked against the parser rather than taken on
trust.

The clearest case is refusals: Claude Code records every refused tool call with
a joinable `tool_use_id`, and **Codex records none** — so that whole section is
single-vendor, and the report says so in place when a Codex session is present.

This matters because **comparing two projects on different agents compares
different measurements**, and nothing previously said which.

## Suppressing a shell-audit finding

Each entry in `bash.flags[]` carries an `id`, keyed on **severity, category and
program** rather than on the command text. So the id survives the command
changing slightly, and suppressing one thing suppresses the class a person
actually means — *"`rm` being flagged destructive is expected in this
repository"* — rather than one exact invocation.

```sh
actualis --suppress 7ffabc7a --reason "build directory, every run"
```

Same rule as credentials: **a suppressed flag is still counted**, still appears
in `bash.flags[]` with `suppressed: true` and its reason, and
`suppressed_flags` reports the total. It leaves the actionable counts, it does
not leave the report.

## `unreadable_commands`

```json
{ "count": 1550, "pct_of_commands": 3.11,
  "by_shape": { "runs a variable": 1357, "eval": 93, "runs a local script": 83 } }
```

"Pattern matching has a ceiling" is true and vague. It does not distinguish
**we looked and found nothing** from **there was nothing here to look at**, and
only the second is a blind spot.

A command that runs `$CMD`, evals a string, pipes a download into a shell, or
executes a script whose contents live elsewhere is **unreadable**, not merely
unmatched. On a real corpus that is 3.11% of commands.

**Counted, never flagged.** Running a script is normal; this is not an
accusation. It is a statement about what the audit could and could not see, and
it is here so a clean report cannot be mistaken for a complete one.

## `refusals`

```json
{ "total": 359, "joined_to_a_command": 359,
  "by_gate":    { "user-rejected": { "Bash": 100, "AskUserQuestion": 18 } },
  "by_program": { "user-rejected": { "git": 36, "ls": 26, "find": 19 } },
  "by_project": { "user-rejected": { "some-project": 12 } },
  "by_week":    { "2026-W31": { "user-rejected": 40 } } }
```

A refusal is its own record, carrying `toolDenialKind`. It holds no `tool_use`
block of its own — it points back at the call it blocked through `tool_use_id`
on its `tool_result`. Reading the refusal record alone tells you that something
was refused and nothing about what.

Three gates: `user-rejected` is a human declining, `automode-blocked` is the
auto-mode policy, and `automode-unavailable` means the deciding model was
unreachable.

**Program names only, never command text.** The commands people refuse are the
ones least suited to being pasted into an issue.

Two limits worth stating. This is **one machine**: refusals are not deduplicated
across developers, so the same policy firing on ten laptops counts ten times.
And a refusal is **not a verdict** — it records that a gate fired, not that
firing was correct.

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
