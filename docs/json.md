# JSON output

`agentfleet --json` emits the full report as machine-readable data.
**Credentials are redacted by default**, including here; `--no-redact` disables
that and prints a warning.

## Top-level keys

| key | contents |
|---|---|
| `version` | tool version |
| `window` | `from`, `to`, `days`, `active_days` |
| `scanned` | `files`, `bytes`, `roots[]` |
| `messages` | count of assistant messages with usage |
| `cost_usd` | total, at provider list prices |
| `tokens` | `input`, `output`, `cache_w_1h`, `cache_w_5m`, `cache_read` |
| `by_agent` | cost per agent (`claude-code`, `codex`) |
| `subagents` | see below |
| `cache` | `fleet_hit_rate_pct`, `saved_usd`, `by_project{}` |
| `by_ticket[]` | see below |
| `by_branch` | cost per branch bucket, including `trunk` and `detached HEAD` |
| `by_model` | cost per model |
| `by_project` | cost per project |
| `by_day` | cost per calendar day, ascending |
| `tools` | tool-call counts, descending |
| `bash` | `total`, `commands{}`, `flag_counts{}`, `flags[]` |
| `coach` | findings: `id`, `severity`, `title`, `evidence`, `action`, `impact` |
| `secrets[]` | see below |
| `secret_exposures` | commands containing credential material |
| `secret_projects` | those commands per project |
| `redacted` | whether values were masked (`true` unless `--no-redact`) |
| `permission_modes` | turns per permission mode |
| `denials` | rejections by kind |
| `unknown_models` | models seen with no pricing entry |

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
