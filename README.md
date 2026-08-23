# agentfleet

**What your coding agents cost, and what they actually did.**

Terminal-native coding agents write a complete record of every session to your
disk: token usage per turn, every tool call, every shell command. What they don't
give you is a view across all of it. If you run agents in more than one project, or
more than one agent, you cannot currently answer:

- What did my agents cost last month?
- Which project is burning the budget?
- What did issue #1283 cost?
- What shell commands have my agents actually been running?
- Did a credential ever end up in a command?

`agentfleet` answers those four questions from data already on your machine,
across **Claude Code** and **Codex**, in one report.

```
$ agentfleet

FLEET ──────────────────────────────────────────────────────────────
  window        2026-07-09 → 2026-08-22  (44 days)
  transcripts   617 files, 1.31 GB
  messages      142,371
  cost          $46,012.29 notional, at API list price
  per week      $7,296.49   ·  annualized $379,417.50

BY PROJECT ─────────────────────────────────────────────────────────
    $37,462.22   81.4% ███████████████████████████ digital-business-cards
     $5,126.97   11.1% ███ systematic-venture-capital
       $318.04    0.7%  huestonhomes

  ▲ 81% of all spend is one project: digital-business-cards

SHELL AUDIT ────────────────────────────────────────────────────────
  bash calls    48,708  73% of all agent tool calls
  permission    auto=26,782  default=1,204  acceptEdits=1,133  plan=14
  denied        automode-blocked=213  user-rejected=118

  ▲ 1,315 commands contained credential material
  flagged   1,298 high   533 medium   of 48,708 commands
```

## Install

There isn't one. It's a single file with no dependencies beyond Python 3.9+.

```sh
curl -O https://.../agentfleet.py
python3 agentfleet.py
```

## Usage

```sh
python3 agentfleet.py                  # full report
python3 agentfleet.py --days 30        # last 30 days
python3 agentfleet.py --bash           # shell audit only
python3 agentfleet.py --coach          # findings and recommended actions only
python3 agentfleet.py --watch          # live alerting on new secrets
python3 agentfleet.py --project svc    # filter to matching projects
python3 agentfleet.py --json           # machine-readable
python3 agentfleet.py --top 25         # show more projects
python3 agentfleet.py --agent codex    # one agent only (claude | codex | all)
```

## Cost per ticket

Branch names almost always carry the issue number, so the same data that answers
"what did this project cost" also answers **"what did issue #1283 cost"** — the
unit engineering and finance already budget in.

```
BY TICKET  (top 5 of 166)
         cost  ticket         msgs   days  where
    $3,337.23  #1283        10,788      5  feat/1283-p4-pdf-web, feat/1283-p5-pdf-visio +1
    $1,689.12  #2500         4,551      2  fix/2500-no-credentials-in-argv
    $1,619.75  #1408         4,552      2  feat/1408-promote-signup-public-write

  $21,288.90 across 166 tickets (12 spanning several branches) · $13,088.85 on trunk
```

One ticket often spans several branches, so grouping by ticket rather than branch
is the point. `feat/1283-p4-…`, `p5-…` and `p6-…` are one number. Work on trunk or
in a detached HEAD is reported separately rather than guessed at.

Recognised: `feat/1283-slug`, `fix/2500-slug`, `PROJ-456`, `feature/PROJ-456`,
`issue-742`, `gh_91`, `1283-slug`. Anything else is left unattributed rather than
invented.

## The coach

The report says what happened; `--coach` says what to do about it. Findings carry
stable ids (`AF001`–`AF010`) so they can be quoted and documented, and each one
carries evidence, an action, and an impact estimate where one can be computed
honestly.

**Benchmarks are computed against you, not against other users.** Project versus
project, week versus week, ticket versus your median ticket. That needs no
telemetry, no account, and no population — it works on day one with one user, and
it keeps the no-network promise intact.

Findings are earned. On a fleet with nothing notable, the coach prints nothing.

## Cache efficiency

```
CACHE EFFICIENCY
  fleet hit rate  98.1% of input context served from cache
  saved           $274,083.25 versus sending the same context uncached

   hit rate         context        saved  project
      98.3%  53,502,084,188  $229,183.43  digital-business-cards
      97.5%   6,388,644,406   $27,240.68  systematic-venture-capital
      96.8%     357,231,826    $1,497.92  huestonhomes

  No project is more than 15 points below your median of 96.8%.
```

Hit rate is `cache_read / (input + cache_write + cache_read)` — the share of
**input context** served from cache. Output tokens are excluded because they are
not cacheable, and including them makes a chatty project look broken when its
caching is fine.

Savings are measured against the counterfactual of sending the same context
uncached, priced per model at the message level. Note that a project doing mostly
cache *writes* can show negative savings, since a 1-hour write costs 2.00x. That
is reported rather than clamped to zero.

A project more than 15 points below your own median is flagged (`AF002`) as
likely having something unstable early in its prompt prefix. Projects below the
reporting threshold are excluded from both the table and the coach, so the two
never disagree.

## Subagents

Subagent runs are reported separately: how many, which models, how much shell and
edit activity, wall-clock, and lines changed.

```
SUBAGENTS
  872 runs · 63.9 hours wall-clock · 146,282 lines added, 17,855 removed
       628  claude-sonnet-5
        90  claude-haiku-4-5-20251001
        89  claude-opus-4-8[1m]

  tool activity  bash 12,951 · read 4,469 · edit 3,051
  cost floor     $58.03 — a LOWER BOUND, excluded from the headline figure
```

**Their cost is a floor, not a total, and it is kept out of the headline number.**
The parent transcript records only each run's final message: `totalTokens` equals
the sum of that single `usage` object in 873 of 873 observed cases, and scales
about 2x from a 4-tool run to a 45-tool run, which is context growth rather than
summation. The cumulative spend of a subagent's turns is not recoverable, so it is
not estimated.

**The bigger finding is what the audit cannot see.** 12,951 shell commands ran
inside subagents — 21% of all shell activity — and their command text is never
written to the parent transcript. Subagents inherit the parent's permissions but
not its visibility. The shell audit says so explicitly rather than reporting a
number that looks complete.

## Sharing a summary

`--share` prints a postable summary containing nothing that identifies you: no
project names, branches, ticket ids, paths, commands, or fingerprints. Only
totals, rates, distributions, and generic finding titles.

```
  agentfleet · what my coding agents cost and did

  47 active days   2 agent(s)   142,781 messages   64,208,473,022 tokens

  $46,192.82 at API list price   ·   $982.83/active day
  98.1% of input context from cache, saving $274,101.80 against sending it uncached
  81% of spend in a single project
  $28.89 median cost per ticket, over 166 tickets

  48,875 shell commands   73% of all tool calls
  92% of turns ran unsupervised
  21% of shell activity happened inside subagents, where commands are not recorded
  72 distinct credentials found in command history   25 critical, 70 worth rotating

  coach   AF004  AF003  AF005  AF011  AF001  AF007  AF008  AF009
```

The test suite plants identifying strings — a project name, a branch, a path, a
live-shaped key, an internal hostname — and asserts that none of them can reach
this output. Secret fingerprints are excluded too, since a hash is still an
identifier that could be correlated.

## Privacy

Nothing leaves your machine. No network calls, no telemetry, no analytics, no
config file, no writes. It opens files under `~/.claude/projects` read-only and
prints to stdout. The whole program is one readable file; if you're about to point
a tool at your session history, you should be able to audit it in a sitting, so it
was written to be read.

Every transcript directory it scanned is printed in the report header. It checks
`~/.claude/projects` **and** `$CLAUDE_CONFIG_DIR/projects`, because a machine can
have both, and a fleet report that silently covers half your fleet is worse than
no report.

## About the cost number

Costs are Anthropic API list prices, verified 2026-08-22, including the cache
multipliers that dominate agent workloads:

| | multiplier on input rate |
|---|---|
| cache read | 0.10× |
| cache write, 5m TTL | 1.25× |
| cache write, 1h TTL | 2.00× |

This matters more than it sounds. On a typical agent workload **97% of all tokens
are cache reads**, so any tool that prices them at the input rate will overstate
your spend by roughly an order of magnitude.

**If you're on a Pro or Max subscription, this is not a bill.** Your actual outlay
is the flat subscription fee. Read the total as *what this would have cost at API
list price*: an opportunity-cost figure, a consumption signal, and a way to see
which project is eating your quota. Unknown models are priced at Opus-tier rates
and called out explicitly rather than silently guessed.

## The shell audit

72% of what a coding agent does is run shell commands. That is the largest surface
by far, and it's the one thing an MCP gateway structurally cannot see, because a
gateway sits between the agent and MCP servers and never observes a local `Bash`
call.

The audit is **deterministic**. Plain pattern matching, no model in the loop, no
scoring that drifts between runs. A command either matches a rule or it doesn't,
and you can read every rule in the source. Categories: `destructive`, `privilege`,
`remote-exec`, `credentials`, `egress`, `git`, `publish`, `database`, `audit`.

**A flag means "worth looking at", not "wrong".** Most `rm -rf` calls are a build
directory. The point is that you can see them at all.

The rules were tuned against 48,000 real agent commands, and tuning meant deleting
rules as much as adding them. A rule matching `>/dev/null 2>&1` as "audit
tampering" fired 1,206 times at essentially 100% false positive, so it's gone; a
noisy rule destroys trust in the rules that matter. Current flag rate is about 3.8%.

## Redaction

**Credentials are redacted from all output by default**, including `--json`.

Agent transcripts contain live secrets. This is not hypothetical: the first real
run of this tool surfaced a live deployment token sitting in plaintext in a saved
session. Since the output of a reporting tool gets pasted into issues, dropped into
chat, and screenshotted, redaction is the default and `--no-redact` is an explicit
opt-out that prints a warning.

Redaction covers `KEY=value` for secret-shaped names, ~25 known token prefixes
(`ghp_`, `sk-ant-`, `AKIA`, `vcp_`, `glpat-`, …), `Authorization:` headers, and
passwords in connection URLs. Shell variable *references* like `$VERCEL_TOKEN` are
left readable, because the reference isn't the secret and masking it only makes the
output harder to read. Redaction is idempotent.

If the report tells you commands contained credential material, those secrets are
sitting in plaintext in your transcripts. Rotate anything live.

## Which agents, and why not the others

| Agent | Supported | Why |
|---|---|---|
| **Claude Code** | yes | `~/.claude/projects/**/*.jsonl` |
| **Codex** | yes | `$CODEX_HOME/sessions/**/rollout-*.jsonl` |
| Cursor | **no** | Nothing to read. All `composerData` records are empty shells: `conversationMap {}`, `usageData {}`. The `ai_code_hashes` and `conversation_summaries` tables have zero rows. Content is server-side. |
| Windsurf | **no** | `globalStorage` holds config and auth only. No conversation or usage store. Server-side. |
| Cline, Aider | not yet | Both write local files. Untested, likely feasible. |

The pattern is clean: **terminal-native agents write local rollouts, IDE forks are
thin clients that keep everything server-side.** Supporting Cursor or Windsurf would
mean network calls and OAuth against their APIs, which would cost this tool the three
properties it's built on — no network, read-only, auditable in one sitting. That
trade isn't worth making, so the scope is stated honestly instead: every agent with
a shell on your machine.

Two provider quirks the cost code has to get right, because both silently overcharge
if handled like the other:

- **Anthropic** reports `input_tokens` *excluding* cache, with cache reads and
  writes as separate buckets.
- **OpenAI** reports `input_tokens` *including* `cached_input_tokens`, and
  `reasoning_output_tokens` as a subset of `output_tokens`. Neither is an addition.
- Codex's `total_token_usage` is **cumulative** across a session and its
  `token_count` events repeat, so the session total is the final value, never a sum.

## Limitations
- **Reporting only.** It observes; it does not enforce. Claude Code's own
  permission rules, sandboxing, and hooks are where enforcement belongs.
- **Pattern matching has a ceiling.** A command that builds a string dynamically,
  or runs a script whose contents live in a file, will not be caught. This raises
  the floor on visibility; it is not a security boundary.
- **Prices are hardcoded** and dated in the source. They will drift. OpenAI rates
  come from a third-party aggregator rather than OpenAI's own page.
- **Rates use active days**, not calendar span, so one stale session from months ago
  doesn't silently divide your weekly burn rate by five.
- **Cache TTL inference.** Older transcripts only record a flat cache-creation
  total, which is assumed to be 5-minute TTL and may under-price slightly.

## Verification

The cost pipeline was cross-checked against an independent `jq` implementation over
the same transcripts: 135,508 messages / $44,397.88 on the first root, matching to
the cent. Do the same before trusting any number here that matters to you.

## License

AGPL-3.0-or-later. Copyright (C) 2026 Digital Foundry Solutions, LLC.

**Running this tool places no obligation on you.** Use it privately, inside a
company, on client work, however you like. Running is not distributing, and the
copyleft never touches your code, your projects, or your data — none of which
this tool transmits anywhere in the first place.

Two situations do carry an obligation, and both are deliberate:

- **Distributing a modified version** means shipping its source under the same
  licence.
- **Running a modified version as a network service** means offering that source
  to its users (AGPL section 13). This is the clause GPL-3.0 lacks, and the
  reason for choosing AGPL: the plausible future product here is a multi-machine
  server, and AGPL is what stops someone taking this, closing it, and hosting it.

Copyright is held by a single entity, so a commercial licence for anyone who
cannot accept those terms remains available without a contributor agreement.
