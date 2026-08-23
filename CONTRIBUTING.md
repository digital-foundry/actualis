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
