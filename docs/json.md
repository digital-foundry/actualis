# JSON output

`actualis --json` emits the full report as machine-readable data.
**Credentials are redacted by default**, including here; `--no-redact` disables
that and prints a warning to stderr (stdout stays pure JSON).

## Top-level keys

| key | contents |
|---|---|
| `schema_version` | integer. The contract version of this document. See [Compatibility](#compatibility) |
| `report_sha256` | content address of this report. See [Verifying a report](#verifying-a-report) |
| `version` | tool version. Changes far more often than `schema_version` and means something different |
| `window` | `from`, `to`, `days`, `active_days` |
| `scanned` | `files`, `bytes`, `roots[]` |
| `scope` | the filters this run was given: `days` (`--days N`, or `null` for no limit), `project` (`--project`, `""` when not given), `agent` (`--agent`: `all` by default, or `claude`, `codex`, `copilot`, `gemini`, `qwen`). `--diff` warns when these or `scanned.roots` differ between the two reports |
| `messages` | count of assistant messages with usage |
| `cost_usd` | total, at provider list prices |
| `cost_usd_from_unpriced_models` | how much of `cost_usd` was estimated: models priced by family inference or the default ceiling, not from a price list, vendor docs or an aggregator. Despite the name it does **not** cover the `unpriced` tier (Gemini, Gemma and Qwen ids with no published rate), which adds $0 and is listed in `unpriced_model_tokens`; the key keeps its name for compatibility |
| `copilot_unpriced_sessions` | Copilot sessions with no shutdown record, counted but not priced (not $0) |
| `cost_note` | how unpriced models are rated, and in which direction that errs |
| `pricing` | where each rate came from, how old the table is, and how much of the total rests on a published price. See [Rate provenance](#rate-provenance) |
| `duplicate_usage_records_skipped` | repeated records for the same message, counted once |
| `duplicate_tool_calls_skipped` | tool calls seen again in another transcript (resumed and forked sessions copy history), counted once, by tool call id; the copy in the file read first is kept |
| `unparsable_lines` | transcript lines that would not decode (malformed JSON, or nested deeper than the decoder allows), plus Codex `arguments` strings that would not, plus legacy Gemini `.json` sessions over 64 MiB (not decoded, one each); each is skipped and counted, never fatal. Claude lines the prefilter skips are not decoded, so not counted |
| `unsupported_records` | Gemini CLI records that decode but are of a kind this version does not read: `$patch` lines (Gemini CLI 0.64 preview), any other `$` operation, and any other unknown shape. Skipped and counted, never fatal |
| `rewound_tool_calls` | Gemini CLI tool calls in messages a later `$rewindTo` took out of the conversation. They ran, so they are audited and inventoried like any other call (their network items carry `rewound: true`) and counted here |
| `duplicate_note` | why repeats occur and how they are collapsed |
| `tokens` | `input`, `output`, `cache_w_1h`, `cache_w_5m`, `cache_w_assumed`, `cache_read`. For Gemini CLI and Qwen Code, `input` is the prompt minus its cached part plus tool-use prompt tokens, `cache_read` the cached part, and `output` includes thinking tokens (billed at the output rate) |
| `by_agent` | cost per agent (`claude-code`, `codex`, `copilot`, `gemini`, `qwen`) |
| `subagents` | see below |
| `cache` | `fleet_hit_rate_pct`, `saved_usd`, `by_project{}`: per project, largest context first, `hit_rate_pct`, `context_tokens` (input plus cache writes plus cache reads) and `saved_usd` |
| `by_ticket[]` | see below |
| `by_ticket` | cost and message counts per ticket, parsed from branch names |
| `by_branch` | cost per branch bucket, including `trunk` and `detached HEAD` |
| `by_model` | cost per model |
| `by_project` | cost per project |
| `by_day` | cost per calendar day (UTC date), ascending |
| `tools` | tool-call counts, descending |
| `bash` | `total`, `commands{}` (program name to count; a program name that is itself a credential, such as a pasted token run as a command, is counted as `(credential)`), `flag_counts{}`, `oversized_commands` (commands over 32 KB, each also a medium `oversized-command` flag), `flagged.high` and `flagged.medium` (the report's "flagged N high M medium": one per command, suppressed flags left out; `flag_counts` counts per category and includes suppressed flags), `flags[]`: `id`, `severity`, `categories[]`, `program`, `project`, `when` (null when undated), `evidence` (240 characters, redacted unless `--no-redact`), `had_secret` (the command also contained a credential), `suppressed` and `suppressed_reason` |
| `coach` | findings: `id`, `severity`, `title`, `evidence`, `action`, `impact`, `project` (the project a per-project finding such as `AF002` or `AF006` is about, `""` for fleet-wide findings; `--diff` matches findings on `id` and `project`) |
| `secrets` | array; see below |
| `secret_exposures` | commands containing credential material |
| `suppressed_secrets` | credential findings marked as false positives on this machine |
| `suppressed_flags` | shell-audit findings marked as false positives on this machine |
| `suppression_note` | why a suppressed finding is still counted here |
| `secret_projects` | those commands per project |
| `redacted` | whether values were masked (`true` unless `--no-redact`) |
| `permission_modes` | turns per permission mode |
| `unsupervised_pct` | percentage of recorded turns that ran in a mode that does not stop for approval, as `--share` prints it (Codex `sandbox:` entries are not turns); `null` when no permission mode was recorded. It covers only turns with a recorded mode: read it with `unmoded_commands` |
| `moded_commands` | shell commands run with a recorded permission mode |
| `unmoded_commands` | shell commands with no recorded permission mode, so who approved them is unknown (every Gemini CLI command; older transcripts of other agents). They are in no supervision share's denominator; `--share`, `--card supervision`, the report and the tray name this count instead of leaving it out silently |
| `denials` | rejections by kind |
| `refusals` | what was stopped and by which gate, joined to the blocked command. See below |
| `unreadable_commands` | commands whose real content the transcript does not contain. See below |
| `vendors` | what each agent's transcript actually provides, and what it does not |
| `network` | downloads and fetches the agents made, with approval. See [network](#network) |
| `unknown_models` | models seen with no pricing entry, so priced by inference: the newest sibling in the model family, or else the most expensive rate on file for the provider (the global ceiling when the provider is unknown). Excludes those in `pricing.models_by_tier.unpriced`, which are not billed at all. A dated or alias id of a model in the table (`claude-sonnet-4-5-20250929`, `claude-sonnet-4@20250514`, `claude-opus-4-0`) is that model, priced from its own row, and is not listed here |
| `unpriced_model_tokens` | model to token count, for Gemini CLI and Qwen Code models with no published rate (tier `unpriced`): `gemini-3-pro-preview`, `gemini-3.5-flash`, every Qwen model, and any model id those agents report that has no price. Their tokens are in `tokens`; their cost is not in `cost_usd` and is not estimated |
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
{ "verified": "2026-10-08", "age_days": 0, "stale": false, "stale_after_days": 90,
  "tier_order": ["vendor","vendor-doc","aggregator","family","default","unpriced"],
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
| `unpriced` | **no price at all**: a Gemini, Gemma or Qwen model id with no published rate, or any model Gemini CLI or Qwen Code reports that would otherwise fall to `default`. Priced at zero and listed, never estimated: a Claude ceiling on a Flash model would overstate it 10-30x |

Gemini rows come from Google's price list (Standard paid tier), with the
long-prompt rate for Pro models above 200,000 prompt tokens and dated price
changes (`gemini-3.6-flash`, `gemini-3.8-flash`, `gemini-4-argon`) applied by
the UTC date of each message. Free-tier Gemini use is not distinguishable in
the transcript, so Gemini cost is an API-equivalent figure.

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

### Cache-read and long-prompt rates

The cache-read multiplier is per model. It is 0.10 of the input rate by
default, 0.05 for Opus 5.5 and Sonnet 5.5, and 0.025 for Fable 5.1 and
Mythos 5.1. `cache.saved_usd` uses each message's own multiplier, so a cheaper
read raises the saving. Cache writes stay at 1.25x (5m) and 2.00x (1h) for every
model.

Haiku 5.5 has two tiers. A message whose prompt (input + cache read + cache
write tokens) is 100,000 or fewer is priced at $0.10 / $0.50 per million; above
100,000 the whole message is priced at $0.50 / $2.50. Fast mode, batch pricing
and data-residency uplifts are not modelled.

A model id that is not in the table is priced as the newest known model in its
family (highest version number; the dearer one on a tie), tier `family`.

### Staleness

The tool makes no network calls, so it cannot know whether a price changed. It
can know how long it has been since anyone checked, and `age_days` reports
exactly that, computed offline from `verified`. Past `stale_after_days` the
report says so rather than quoting an old number with a straight face.

Refreshing the table is a deliberate, human-run step — see `tools/price-check.py`
in the repository. The CLI will never fetch a price on your behalf.

## Verifying a report

Every report is content-addressed. `report_sha256` is the SHA-256 of the payload
with four things removed, serialised canonically: the `report_sha256` key itself,
`pricing.age_days`, `pricing.stale`, and the `AF013` entry in `coach`. The last
three depend on today's date and not on the transcripts, so excluding them keeps
the same transcripts hashing the same tomorrow as today. A real change in
the data still changes the hash. The report itself prints the first 16
characters, so a screenshot can be checked against the payload it came from.

Digests are not comparable with those from 0.2.2 and earlier, which hashed the
clock-dependent fields. The schema did not change.

Recompute it yourself, without trusting this tool:

```sh
actualis --json > report.json

python3 - <<'EOF'
import hashlib, json
p = json.load(open("report.json"))
claimed = p.pop("report_sha256")
p["pricing"].pop("age_days")
p["pricing"].pop("stale")
p["coach"] = [f for f in p["coach"] if f["id"] != "AF013"]
canonical = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
print("claimed:", claimed)
print("actual :", actual)
print("match  :", claimed == actual)
EOF
```

Or in one line, if you have jq 1.7 or later and prefer not to run Python (jq 1.6
and earlier re-format numbers, so `0.0` becomes `0` and the digest never matches):

```sh
jq -Sc 'del(.report_sha256, .pricing.age_days, .pricing.stale) | .coach |= map(select(.id != "AF013"))' report.json | tr -d '\n' | shasum -a 256
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

## network

`actualis --network --html` embeds this same object, for the same flags, in the
page's `<script type="application/json" id="actualis-network">` element.

Every download, clone, install and web fetch the transcripts show and actualis
can read, recorded from shell commands and web tools. A shape the inventory does
not parse (a script, `poetry add`, `npm exec`) gives no item.

| key | meaning |
|---|---|
| `totals.items` | all network items found |
| `totals.asked` / `unasked` / `unknown` | items by approval, see below |
| `totals.failed` | items whose command is known to have failed |
| `totals.unparsed_segments` | command segments that could not be read: a segment with a quote left open, a command string (`bash -c`, `eval`, a here-string or heredoc fed to a shell) nested more than eight levels deep, substitutions nested more than 200 deep, a program word or URL whose brace expansion makes more than 16 words, a command whose nested strings exceed the 2 MiB lexing budget, or the part of a command past 1 MiB (counted once per command). Under `--ioc`, a command not fully read for one of the last five reasons is also listed as an item (`kind` `fetch`, `program` `(unreadable)`, `dynamic` `true`) and matched `unresolved` with reason `unreadable` |
| `by_kind` | counts of `install`, `clone`, `fetch` and `search` items |
| `by_day[]` | per UTC date with at least one item, oldest first: `date` (`YYYY-MM-DD`), `items`, `unasked`. Added in 0.3.0 |
| `by_day_undated` | items with no timestamp, so not in `by_day`; `sum(by_day[].items) + by_day_undated == totals.items` |
| `by_project[]` | per project, most items first: `project`, `items`, `unasked`; the sums equal `totals.items` and `totals.unasked` |
| `hosts[]` | per host: `count`, `unasked`, `first_seen` (the earliest item `ts` by UTC instant; the string keeps that item's own offset), and `trusted` if any item from it matched the trust list |
| `packages[]` | per `ecosystem` and `name`: `versions` seen, `pinned` (every install named an exact version: a full `MAJOR.MINOR.PATCH` for npm, crates and go, `==` for pypi, an `@sha256:` digest for images; for crates, `cargo add` is pinned only with `=1.2.3` and `cargo install --version 1.2.3` is exact; ranges, tags and prefixes are not pinned), `exec` (any install ran code), `count`, `unasked` |
| `items[]` | one record per item (`package`, `version` and `alias` are redacted like `url` unless `--no-redact`): `kind`, `program`, `host`, `host_inferred`, `url`, `dest`, `source`, `ecosystem`, `package`, `version`, `pinned`, `exec`, `dynamic` (`true` when the URL or registry is built from a shell variable, or when curl/wget read their URLs from a file: `wget -i`, `curl -K`; a variable only in the path or query keeps the literal `host`, so `https://evil.example/$VER/x` has `host` `evil.example`, while `https://$HOST/x` has `host` `null`; an install from `--registry "$R"` or `-i "$IDX"` has `host` `null`, never the public default; also `true` when the host is written in a form that cannot be normalised (`host` `null`), and when the same command redirects the transfer through a proxy or another address, which also keeps it untrusted; `host` is normalised as curl resolves it: percent-decoded, IDNA, lower case, no trailing dot, an IPv4 address in any numeric form as a dotted quad), `alias` (the name an npm alias installs under, `x` in `x@npm:evil@1.0.0`, where `package` is `evil`; else `null`), `failed` (`null` when unknown), `approval`, `trusted`, `agent`, `project`, `session`, `call_id` (the tool call's id in the transcript, an opaque string, `null` when there is none), `ts`, `ioc` (`match`, `unresolved` or `null`; see `network.ioc`), `reputation` (the offline host-reputation result, or `null` without `--reputation`; see [network.reputation](#networkreputation)), `mode` (the permission-mode key `approval` was judged from, or `null`), `why` (the assistant's own words before the call: the last sentence, at most 160 characters, or `null`), `prompt` (the person's last real message before the turn, at most 160 characters; `null` unless `--with-prompts`), `transcript` (`root`, `file` relative to `root`, and the 1-based `line` of the record that made the call; `line` is `null` for a `--ci-log` array; `transcript` is `null` for an item not read from a file), `rewound` (see below) |
| `items_truncated` | `true` when `items` was cut at the cap |
| `strict` | whether `--network-strict` was on |
| `trust` | the trusted host or host-and-path entries in force |
| `trust_sources[]` | where the trust entries came from: `source` (`flag` or `file`), `path` and `sha256` (both `null` for a flag), and `entries`. It shows whether an agent-editable file supplied the trust, so a reader can tell. `path` is absolute and not redacted, like `scanned.roots` |

**Finding the record behind an item.** `transcript` points at it exactly,
and `session` and `call_id` name it:

```sh
actualis --network --json | jq -r '.items[0].transcript | "\(.line) \(.root)/\(.file)"'
sed -n '<line>p' <root>/<file>                       # the record itself
actualis --network --json | jq -r '.items[0] | .session, .call_id'
grep -l '<call_id>' ~/.claude/projects/*/*.jsonl    # the transcript file(s) holding that tool call
```

**why and prompt.** Both are redacted and stripped of control characters when
they are read, so `--no-redact` does not reveal them. What each agent gives
is in `actualis --explain network`; a field the records do not give is
`null`. `--share` and `--card` never carry either.

**Approval values.** `asked`: the user was prompted and approved. `unasked`:
the agent ran it without asking, in a mode that does not prompt. `unknown`:
no record of who approved it: default mode, where an allowlist rule may have
approved it without asking, or an agent that records no approval at all.
**Gemini CLI records no approval and no approval mode**, so every Gemini item
is `unknown` with `mode` `null`; a call a person declined, or a policy blocked,
is a refusal and leaves the inventory. Qwen Code records its approval mode
(`qwen:yolo` and `qwen:auto` are `unasked`; `qwen:default`, `qwen:plan` and
`qwen:accept-edits`, Qwen's `auto-edit`, which still asks before a shell
command, are `unknown`).

**rewound.** `true` for a Gemini CLI call whose message a later `$rewindTo`
removed from the conversation; the call still ran. `false` otherwise.

**Cap.** `items` holds the newest 2000 items, newest first (by UTC instant), in a fixed total
order. `totals`, `hosts` and `packages` always cover every item.

**Redaction.** `url`, `dest` and `source` are redacted unless `--no-redact`.

Strict-mode findings are not repeated here. They are `bash.flags[]` entries
with the category `network-unasked`.

Verify: `actualis --json | jq '.network.totals'`

## network.ioc

What `--ioc` matched (see [ioc.md](ioc.md)). Always an object: without `--ioc`
it is `{"enabled": false, "sources": [], "totals": {...all zero}, "matches": [],
"matches_truncated": false}`, so every path keeps one type.

| key | meaning |
|---|---|
| `enabled` | whether `--ioc` was given |
| `sources[]` | one per `--ioc` file, in order: `path` (absolute, not redacted), `sha256` of every byte, `format`, `entries.package` / `entries.host`, `not_checkable.<ecosystem>`, `skipped` and `first_skipped_line` (malformed OSV records; `null` without a line), `withdrawn`, `ranges_git`, `ranges_with_limit`, `skipped_ranges` (OSV ranges that could not be read, treated as undecidable), `mtime_in_window` (the file changed between `window.from` and `window.to`) |
| `totals.match` / `unresolved` | items, not refused, with that verdict. Suppressed ones are still counted |
| `totals.refused` | matched items whose call a person refused |
| `totals.suppressed` | suppressed IOC findings (groups) |
| `totals.clean_name_matches` | items whose name was listed and whose version fell outside every spec |
| `totals.undecidable` | items whose check could not be decided (an unordered version, an unreadable range, an error); each is `unresolved`, never clean |
| `totals.items_checked` | downloads with a package or a named host to check |
| `totals.items_not_checkable` | the rest: `lockfile` (an install naming no package), `no_host`, `other` |
| `matches[]` | one row per matched item, refused ones included: `verdict`, `reason`, `refused`, `suppressed`, `flag_id` (`null` when refused), `refs` and `labels` (distinct, sorted, at most 20), `entry` (the first winning entry: `kind`, `ecosystem`, `name`, `spec`, `host`, `path`, `exact_host`, `ref`, `label`, `from`, `until`, `source`, `line`) and `item` (exactly as in `items[]`) |
| `matches_truncated` | `true` when `matches` was cut at 2000 |

**Enums.**

- `verdict`: `match` or `unresolved`.
- `reason`: `any-version`, `version-in-spec` or `host` (match);
  `version-unresolved`, `undecidable`, `module-prefix` (a Go package inside a
  listed module whose version cannot be ordered), `private-registry`,
  `name-from-url`, `error`, `unreadable` (part of the command was not read
  because of a nesting or length limit, or a brace or curl glob expands to more
  than 64 words), `host-unresolved` (the host is written in a form that cannot
  be normalised) or `redirected` (the command sends the transfer through a proxy
  or to another address) (unresolved).
- `format`: `lines`, `osv-json` or `osv-jsonl`.
- `entry.kind`: `package`, `host`, or `error` (a placeholder when checking the
  item failed or the command was not fully read; `source` is then `-1`).

**Order.** Not refused first, then match before unresolved, then newest, then
the item, then the entry's `(source, line)`: the same input gives the same
bytes.

`report_sha256` covers `network.ioc`, so two runs against different lists have
different digests. No `network.ioc` field depends on the clock: `from` and
`until` are copied from the list, and `mtime_in_window` compares the file's
modification time with the transcripts' window.

The findings are `bash.flags[]` entries with the categories `network-ioc`
(high) and `network-ioc-unresolved` (medium).

Verify: `actualis --ioc f --json | jq '.network.ioc.totals'`

## network.reputation

The host-reputation result (see [reputation.md](reputation.md)). Everything here
is additive under `schema_version` 1. Two places carry it: `network.items[].reputation`
for each item, and `network.reputation` for the whole run. `network.reputation` is
always an object; `enabled` is `false` without `--reputation`.

**network.items[].reputation** is `null` without `--reputation`, else an object:

| key | meaning |
|---|---|
| `state` | `none` (no local match), `candidate` (a local Safe Browsing prefix matched, not confirmed), `listed` (confirmed by Google within 30 minutes, or VirusTotal `malicious` at or above the threshold), `not-listed` (a fresh check found nothing), `suspicious` (VirusTotal: `1 <= malicious < threshold`, or `suspicious >= 1`), `unknown` (VirusTotal has never seen the host), `skipped` (a private or local host, never looked up) |
| `provider` | `google-safe-browsing`, `virustotal` or `null` |
| `threat_types[]` | Google threat types such as `MALWARE`, `SOCIAL_ENGINEERING`; empty for VirusTotal |
| `checked_at` | when the deciding check was made, or `null` |
| `advisory` | `"Advisory provided by Google"` for a `listed` or `candidate` Google result, else `null` (never set for VirusTotal) |

**network.reputation**:

| key | meaning |
|---|---|
| `enabled` | whether `--reputation` was given |
| `lists_status` | `ok`, `absent` or `corrupt`; `null` when not enabled |
| `provider_lists` | list name to the time it was fetched |
| `lists_age_hours` | age of the oldest list, in whole hours, or `null` |
| `stale` | `true` when the oldest list is over 7 days old |
| `vt_results` | VirusTotal results loaded (those over 7 days old are ignored) |
| `totals` | `checked`, `skipped`, `none`, `candidate`, `listed`, `not_listed`, `suspicious`, `unknown`: items by state |
| `candidates[]` | `prefix_b64`, the 4-byte hash prefix a confirmation would send, and `expressions`, how many of a host's expressions matched. Prefixes only: `actualis-reputation confirm` reads these and never sees a host |
| `advisory` | `text` and `url` of the Google advisory, or both `null` |
| `network_last_used` | `at` and `provider` of the last `actualis-reputation` network run, or both `null` |

The findings are `bash.flags[]` entries with the categories `reputation-listed`
(high), `reputation-candidate`, `reputation-suspicious` and `reputation-stale`
(medium).

Verify: `actualis --network --reputation --json | jq '.network.reputation.totals'`

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
`first_seen` and `last_seen` are `""` when no record that carried the credential
had a readable timestamp; they are never `null`.

Each entry also carries `suppressed` and `suppressed_reason`. **A suppressed
finding is still listed here and still counted** — it is held back from the
actionable list in the report, not hidden. A scan with many suppressions must
not be indistinguishable from a clean one, and `suppressed_secrets` is the
number that makes the difference visible.

`distinct_values` is how many different values were seen under the id in this
run. It is always 1 for an id taken from the value. For a password passed as an
option, the id comes from where the password appears (see
[secrets.md](secrets.md)), so it can be more than 1. When a suppressed id of that
kind has more than one value, it is reported as `suppressed: false` with
`suppressed_reason` "suppression covers one value; N seen", and it counts
toward `--fail-on`.

## `by_ticket[]`

```json
{ "ticket": "#412", "cost_usd": 3337.23, "messages": 10788,
  "branches": ["feat/412-checkout-v2", "feat/412-checkout-api"],
  "projects": ["…"], "active_days": 5,
  "first_seen": "2026-05-06", "last_seen": "2026-06-02" }
```

`first_seen` and `last_seen` are `""` when none of the ticket's records had a
readable timestamp; they are never `null`.

## `vendors`

Five agents are read; their transcripts do not contain the same things.

| Capability | Claude Code | Codex | Copilot CLI | Gemini CLI | Qwen Code |
|---|---|---|---|---|---|
| Cost and token usage | yes | yes | yes | yes | yes |
| Per-message dedup | yes | partial | partial | yes | yes |
| Shell command text | yes | yes | yes | yes | yes |
| Project attribution | yes | yes | yes | yes | yes |
| Git branch | yes | no | yes | no | yes |
| Tool refusals | yes | no | yes | partial | partial |
| Permission mode | yes | yes | yes | **no** | yes |
| Sandbox policy | no | yes | no | no | no |
| Subagent activity | partial | no | partial | yes | partial |
| Subagent cost | no | no | no | yes | partial |
| Cache TTL split | partial | no | no | no | no |
| Reasoning effort | yes | no | no | no | no |

Each capability row in the payload has `gemini` and `qwen` beside `claude`,
`codex` and `copilot`. Gemini CLI writes neither whether a person approved a
call nor the approval mode (YOLO, auto-edit) it ran in, so its approval is
always `unknown`; only a refusal ("User denied execution.") or a policy block
("Tool execution denied by policy.") is recorded.

The payload is `vendors.capabilities[]`, one row per capability above: `capability`
(the row's name), then `claude`, `codex`, `copilot`, `gemini` and `qwen` (`yes`,
`no` or `partial`), and `depends_on`; `vendors.note` says why it matters.

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

It also carries two strings: `join_note`, on how a refusal is joined to the call
it blocked (an unjoined one means the call was not in the same session file), and
`scope_note`, on what the counts cover (this machine only, bounded by transcript
retention).

A refusal is its own record, carrying `toolDenialKind`. It holds no `tool_use`
block of its own — it points back at the call it blocked through `tool_use_id`
on its `tool_result`. Reading the refusal record alone tells you that something
was refused and nothing about what.

Three gates: `user-rejected` is a human declining, `automode-blocked` is the
auto-mode policy, and `automode-unavailable` means the deciding model was
unreachable.

**Program names only, never command text.** The commands people refuse are the
ones least suited to being pasted into an issue. A program name that is itself a credential
(a pasted token run as a command) is counted as `(credential)`.

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
| `fleet_summary` | window, spend (with `cost_usd_from_unpriced_models` and `unpriced_model_tokens` as in `--json`), cache hit rate, top projects, unsupervised share (`unsupervised_pct` over turns with a recorded mode, with `moded_commands` and `unmoded_commands`) |
| `ticket_cost` | cost for one ticket, or the most expensive ones |
| `exposed_secrets` | rotation list: priority, types, fingerprint, dates (`first_seen`/`last_seen` are `""` when unknown, as in `--json`), and `suppressed`/`suppressed_reason` per row. `worth_rotating` leaves out suppressed credentials, as the report does; `suppressed` counts them. `priority` must be `critical`, `high`, `low` or `all` |
| `coach_findings` | `AF001`–`AF013` with evidence, actions and `project` (the project an AF002/AF006 row is about, else `""`) |
| `shell_audit` | counts by category, permission modes, the subagent blind spot |
| `explain` | how a figure is computed, what it assumes, how to verify it |
| `verify_agents` | installed agent platforms and their signature status |

**What it deliberately does not return.** Everything here is read by a model and
written back into a transcript that this tool then scans, so the surface is
narrow by design: aggregates, types, `sha256[:8]` fingerprints and counts. Never
a secret value, never raw command text. Tests assert both.

A bad argument is a JSON-RPC invalid-params error (`-32602`): an unknown
`priority`, or a `days` that is not a whole number (`"7"`, `7.5`).

The server answers only from the scope it was started with: `--root`, `--agent`,
`--days` and `--project` apply to every tool. A client's `days` or `project` can
narrow that scope, never widen it; a `project` outside the server's `--project` is
an invalid-params error. `--no-redact` and `--top` are refused (exit 2), because no
tool returns a credential value or a top-N list.

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
models absent from the rate table (priced by family inference or the default
ceiling): the *estimated* part. It excludes the `unpriced` tier, whose models
add no cost and are listed in `unpriced_model_tokens`; so a value of 0 with
models in `pricing.models_by_tier.unpriced` is consistent. Models priced from an aggregator are known, not unpriced; they are
listed in `aggregator_priced_models`. Those are priced at the top of the known
range for their provider, so that share is an upper bound among current models,
not a measurement. It is reported separately rather than folded in so you can
subtract it and see the floor. A model priced above everything in the table
would still be understated — which is exactly why the number is exposed instead
of being described as merely "unknown".
