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
python3 -m unittest discover -s tests -v   # or: make test
```

No test runner, no config, no fixtures directory.

The suite is hermetic. Every test module starts with `import _fixtures`, which
points `HOME`, every agent's home, `XDG_CONFIG_HOME` and the working directory
at temp directories for the whole run. An audit hook then refuses, and fails the
run for, any read under your real home outside the repo and the Python install,
so your own transcripts and suppressions can never change a result. A new test
module needs that import (a test checks). Timing checks go through
`tests/_timing.py`: `clock()` for the measurement (CPU time, so a busy machine
does not count), `assert_linear` for a growth check, and `budget()` for any
ceiling within 20x of the measured time.

## Personal data (`make pii`)

The repo is public and the suite is built around agent transcripts, so test
data, docs and examples must be synthetic. Never paste a real transcript, path,
host, session id or address. The PII gate enforces this:

```sh
make pii          # built-in detectors; CI runs this
make pii-full     # plus the private terms list; run before a release
```

It checks every git-tracked text file except `actualis.py` (the detector
corpus; gitleaks covers it) and prints `path:line: detector`, never the value,
so a failing CI log does not republish what it found. Detectors:

| detector | fires on |
|---|---|
| `home-path` | `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`, unless the name is a placeholder (`x`, `you`, `runner`, `someone`, ...) |
| `email` | any address, except `example.*` and reserved TLDs (`.test`, `.invalid`, ...), `digitalfoundry.tech`, `noreply@anthropic.com`, `git@host:` remotes and URL userinfo |
| `phone` | North American and E.164 numbers, except 555-0100 to 555-0199 |
| `tailnet` | `*.ts.net` hosts |
| `ip` | public IPv4 and IPv6 addresses; private, CGNAT, link-local, documentation (RFC 5737, `2001:db8::`), multicast and reserved ranges pass |
| `uuid` | UUIDs that do not look hand-typed (mostly zeros, few distinct digits, repeated groups) |
| `secret` | outside `tests/`: actualis's own token-prefix, Authorization-header and URL-password patterns |
| `term` | `pii-full` only: the private list of names, places and employers, outside attribution lines (copyright, authors, Co-Authored-By) |
| `decode` | text still changing after 8 rounds of HTML, percent and JSON unescaping |

Matching runs on the raw line and on a canonical form: decoded, NFKC,
invisible characters stripped, case-folded, Cyrillic and Greek look-alikes
mapped to Latin. `&#x2F;Users&#x2F;` and `/Us\u0435rs/` are caught.

**When it fires**, replace the value with synthetic data (`/Users/x`,
`dev@example.com`, `192.0.2.7`, `(617) 555-0142`). If the value is genuinely
not personal, allow it with a reason, either inline on the line
(`# pii-ok: <reason>`) or as an entry in `.pii-allow`
(`<exact value> # <reason>`). An entry without a reason fails the gate.

**The private terms list** never lives in this repo. `make pii-full` reads it
from the file named by `ACTUALIS_PII_TERMS`, or from the 1Password note
`Foundry Admin / actualis pii terms` through the Foundry Admin service account.
One term per line: a literal, matched as whole words case-insensitively with
any spaces, hyphens or underscores between them, or a `/regex/` (always
case-insensitive). A missing, empty or invalid list fails the gate (exit 2),
and the error never names a term.

## Security scan (`make security`)

```sh
make security                       # or: make security FUZZ_ITERATIONS=1000
make security-remote                # the same scan on the build server (SECURITY_HOST=mac-mini)
```

`make security-remote` runs it on the build server over SSH instead of here.
It runs outside GitHub Actions on purpose: this repo is public, and the build
server's runners do not take public repositories, because a fork's pull request
could otherwise run code on them. It sends a git bundle of `HEAD` (committed
work only), runs the same container under the build user's home directory (the
only place its Docker shares with containers), and copies `security-out/` back.

It needs Docker. It builds a Kali image from `tools/security/Dockerfile` and runs
`tools/security/run.sh` in it:

- **bandit**: static analysis of `actualis.py` and `tools/`. B404/B603/B607
  (subprocess use) are skipped: actualis only runs fixed argv lists.
- **trufflehog** and **gitleaks**: secrets anywhere in the git history.
- **the transcript fuzzer** (`tools/security/fuzz_transcripts.py`): mutates a
  synthetic Claude Code, Codex and Copilot fleet and runs actualis over it in
  several modes, looking for tracebacks, crashes, hangs and invalid `--json`.

The container is isolated: no network (`--network none`), the checkout mounted
read-only, a read-only root filesystem, a throwaway `HOME` under a tmpfs, and
your uid. It cannot see this machine's transcripts.

Reports land in `security-out/`: `bandit.txt`, `trufflehog.json` and
`gitleaks.json` (the two secret scanners' stderr beside them as `.err`), and
`fuzz/`, with one `case-NNNN/` directory per failing case: the mutated
transcripts plus `FAILURE.txt`, the command that failed and its error. The
fuzzer prints its `--seed`; rerun with it to repeat a run. How to read the
console summary:

- A line saying a scanner **FAILED** means it did not run properly. That is
  never a clean result; its stderr is printed below the line.
- gitleaks and trufflehog skip the files whose job is to hold invented
  credential shapes: `tests/`, `tools/make-demo-fleet.py` and
  `docs/superpowers/plans/`, gone from the tree but still in the history
  (`.gitleaks.toml`,
  `tools/security/trufflehog-exclude.txt`). They also skip `agentfleet.py`,
  actualis.py's name before the rename, so every revision of it in the history
  goes unscanned. The reason: it holds the redaction regexes for database URLs
  with a password (a `postgres://` URL with a user and password), which trufflehog's Postgres
  detector reads as credentials. The cost: a real secret committed to
  `agentfleet.py` before the rename would not be found. `actualis.py` is still
  scanned. Anything they report is outside those paths and worth a look.
- With no network, trufflehog cannot check a candidate against its provider,
  so it reports **unverified** candidates. A count above zero is a list to
  review, not proof of a live secret; "no candidates" means it found none.

The fuzzer also runs natively, with the same isolation of `HOME`:
`python3 tools/security/fuzz_transcripts.py --iterations 300 --out /tmp/fuzz`.
