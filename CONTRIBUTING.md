# Contributing

## Before you open a pull request

**Copyright is currently held by a single entity**, which keeps dual licensing
possible: AGPL-3.0 for everyone, and a commercial licence for organisations that
cannot accept copyleft. Accepting outside code without an agreement would end
that option permanently.

So for anything beyond a typo, please open an issue first. A lightweight CLA
will be sorted out before code is merged. This is about keeping an option open,
not about ownership of your work.

## Ground rules

**No dependencies.** Python 3.9+ standard library only. People point this tool
at their session history; it has to be readable in one sitting and carry no
supply chain. A dependency needs an extraordinary justification.

**No network, no writes.** The tool opens files read-only and prints. Nothing
else. `--watch` shells out to the platform notifier and that is the only
subprocess.

**Every bug becomes a test.** The suite is a list of defects found on real data,
and it exists so those specific mistakes cannot return. If you fix something,
pin it.

**Numbers must be right or absent.** This is the tool's only asset. Where a
figure cannot be computed honestly, say so instead of estimating — subagent cost
is reported as an explicit floor for exactly this reason. A visibly wrong number
costs more trust than ten correct ones earn.

**Deleting a rule counts as work.** The shell audit was tuned from 7.7% to 3.8%
by removing checks, not adding them. A rule that fires constantly destroys trust
in the rules that matter.

## Branching

Trunk-based. `main` is always releasable and is the only long-lived branch.

| branch | purpose | lifetime |
|---|---|---|
| `main` | releasable at every commit | permanent |
| `fix/…`, `feat/…`, `docs/…` | one change, one branch | until merged |
| `v*` tags | releases; `release.yml` publishes to PyPI on push | permanent |

There is no `develop`, no release branch and no long-lived integration branch.
For a project this size they cost more in merge overhead than they return.

**`main` is protected, including from maintainers.** Force-pushes and deletion
are blocked, every change goes through a pull request, and the Python test
matrix must pass before a merge. There are **no bypass actors** — an admin gets
the same refusal everyone else does:

```
! [remote rejected] main -> main (push declined due to repository rule violations)
  - 4 of 4 required status checks are expected.
  - Changes must be made through a pull request.
```

That last part was not true until 2026-08-24. The repository role held an
`always` bypass, so every maintainer push went straight to `main` and skipped
all four required checks. The rules read as protection and behaved as a
suggestion, which is worse than having none: it is protection you stop
checking.

So the loop is: branch, push the branch, open a PR, let the matrix run, merge.
Approvals are not required — a solo maintainer can merge their own PR — but the
checks are.

Tags are not covered by the ruleset, so `git push origin v1.2.3` still works
directly and still triggers `release.yml`. That is deliberate: the tag is cut
from a commit that already passed the matrix on `main`.

This protection is not decoration. This repository's history was rewritten
once, deliberately, to purge brand artwork and a stale binary — with the rules
now in place, the same operation means editing the ruleset first, on purpose,
rather than a stray `--force` succeeding quietly.

Outside contributors work from a fork. Fork pull requests require maintainer
approval before any workflow runs, so a first PR will sit until someone presses
the button — that is the abuse control, not a comment on the change.

Keep branches short-lived and rebase rather than merge, so history stays linear
and `git log` reads as a sequence of changes rather than a merge diagram.

### Maintainers currently bypass the rules

The ruleset applies to everyone except the maintainer role, who can still push
straight to `main`. That is deliberate while the project is one person: forcing
a pull request on yourself adds ceremony without adding a reviewer.

It should tighten the moment a second person has write access, or the first
outside contribution lands — whichever comes first. Both mean a push to `main`
can now surprise somebody.

To tighten, remove the bypass and require a reviewed pull request:

```sh
gh api repos/digital-foundry/actualis/rulesets            # find the ruleset id
gh api -X PUT repos/digital-foundry/actualis/rulesets/<id> --input - <<'JSON'
{ "bypass_actors": [],
  "rules": [ { "type": "deletion" },
             { "type": "non_fast_forward" },
             { "type": "required_status_checks", "parameters": { … } },
             { "type": "pull_request",
               "parameters": { "required_approving_review_count": 1,
                               "dismiss_stale_reviews_on_push": true,
                               "require_code_owner_review": false,
                               "require_last_push_approval": true } } ] }
JSON
```

Carry the existing `required_status_checks` block across unchanged, or the
required checks are dropped in the same call that adds review.

## Supply chain

Every GitHub Action is pinned to a full 40-character commit SHA, and the
repository rejects workflows that reference a mutable tag. A tag can be moved;
a SHA cannot. Dependabot proposes updates weekly and CI must pass before one
lands.

The version comment after each SHA is a human convenience only — the SHA is
what runs. When updating, change both.

This matters more here than in most repositories. Actualis exists to tell you
what your agents actually did; a compromised action in its own release pipeline
would undermine the claim at its root.

## Adding a coach finding

1. Give it the next free `AFxxx` id. Never reuse a retired one.
2. Benchmark against the user's own data — project vs project, week vs week — not
   against a hardcoded constant. There is no telemetry and there will not be.
3. Document it in `docs/findings.md`. A test enforces this.
4. Add a test proving it stays silent when it should.

## Running the suite

```sh
python3 -m unittest discover -s tests -v
```

No test runner, no config, no fixtures directory.
