# Findings reference

Every coach finding has a stable id so it can be quoted, searched, and argued
with. Ids are never reused: if a check is removed its id is retired.

Findings are **earned**. On a fleet with nothing notable the coach prints
nothing, and several of these never fire on a healthy setup.

**Benchmarks are computed against you**, not against other users — project
against project, week against week, ticket against your own median. There is no
telemetry, no account, and no population. This works on day one with a single
user, and it is why the thresholds below are mostly relative rather than absolute.

| id | severity | fires when |
|----|----------|-----------|
| [AF001](#af001) | info | one project is ≥50% of spend, with ≥3 projects |
| [AF002](#af002) | high | a project's cache hit rate is >15 points below your median |
| [AF003](#af003) | high | ≥75% of turns ran in an auto or bypass permission mode |
| [AF004](#af004) | critical | any critical-priority credential appears in command history |
| [AF005](#af005) | high | a non-trivial credential has been exposed ≥30 days |
| [AF006](#af006) | info | a project's correction rate is >3× your median |
| [AF007](#af007) | info | spend moved ≥40% week over week |
| [AF008](#af008) | info | >95% of turns ran at high effort or above |
| [AF009](#af009) | info | one ticket cost >8× your median ticket |
| [AF010](#af010) | info | >35% of spend cannot be tied to a ticket |
| [AF011](#af011) | high | ≥10% of shell activity happened inside subagents |

---

## AF001

**Spend is concentrated in one project.** Not a problem by itself. It matters
because it means your fleet-wide averages are really describing one project, so
read per-project numbers instead of the total. Requires at least three projects,
so a one-project setup is not nagged about being a one-project setup.

## AF002

**Cache efficiency below your own median.** Hit rate is
`cache_read / (input + cache_write + cache_read)` — the share of *input* context
served from cache. Output is excluded because it is not cacheable.

Caching dominates agent economics, so a project 15+ points below your median is
usually paying several times more than it needs to. The cause is almost always
something unstable early in the prompt prefix: a timestamp, a random id, unsorted
JSON. Stable content has to come first. Carries an estimated impact in dollars.

Only considers projects above the reporting threshold, so a tiny worktree with a
bad ratio and $4 of spend is ignored rather than flagged.

## AF003

**Most agent activity is unsupervised.** Counts turns in `auto` or `bypass`
permission modes. Defensible for throughput — most people running agents
seriously end up here — but it means the permission system is not the control
you may believe it is. The suggested pairing is deny rules for paths that should
never be touched, which cost nothing and fail closed.

## AF004

**Critical credentials sit in plaintext history.** Critical means money or
database god-mode: Stripe keys, AWS keys, model-provider keys, JWTs and service
keys, and passwords in remote connection strings. See
[secret types](secrets.md).

Rotation fixes exposure. It does **not** clean the archive: a key rotated today
is still sitting in a transcript from last month. The second half of the fix is
a retention policy.

## AF005

**A credential has been exposed for a long time.** Age matters more than
frequency. Something unrotated for 30+ days should be treated as compromised
rather than merely exposed, because you cannot know who has read the file in
that window. Reports the oldest non-trivial secret with its first-seen date and
use count.

## AF006

**The agent is being corrected more in one project.** Compares each project's
rate of `toolDenialKind` events — rejections, auto-mode blocks — against your
median, firing above 3× and 1%. Needs at least 200 messages in a project, so
small samples do not produce noise.

Usually a context problem rather than a model problem: the agent does not know
that project's conventions. A `CLAUDE.md` describing them is the cheapest fix.

## AF007

**Spend moved sharply week over week.** Compares the last 7 active days against
the 7 before, firing at ±40%. Not a judgement, just early warning: it is better
to know which project moved while you remember why.

## AF008

**Everything runs at premium reasoning effort.** Correct for hard work and
wasteful for mechanical edits. Dropping routine turns to low or medium effort is
usually the single cheapest saving available, because it costs nothing but a
setting.

## AF009

**One ticket cost far more than your typical ticket.** Fires above 8× your
median ticket, requiring at least 8 tickets so the median means something.

The branch count usually tells you which explanation applies. One branch and a
huge cost is genuinely big work; several branches is often a ticket that was
underscoped and restarted.

## AF010

**A large share of spend is not attributable to a ticket.** Work on trunk or in
a detached `HEAD` cannot be tied to an issue. Fine for exploration and ops, and
fatal for per-ticket chargeback. If cost attribution ever needs to be credible,
branch naming is the cheapest thing to fix.

## AF011

**Shell activity is partly invisible to the audit.** Subagents run their own
shell commands, and the command text is never written to the parent transcript —
only a count. So a percentage of your shell activity cannot be scanned for
credentials or destructive operations at all.

Subagents inherit the parent's permissions but not its visibility. If the audit
matters, prefer doing shell work in the main loop, or treat subagent runs as
unreviewed.
