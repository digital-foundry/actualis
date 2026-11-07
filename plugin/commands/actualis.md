---
description: Run the actualis report on local agent transcripts and summarise the top findings
argument-hint: "[actualis flags, e.g. --days 30 --project NAME]"
allowed-tools: Bash(actualis:*), Bash(command -v actualis)
---

Check that actualis is installed with `command -v actualis`. If it is not,
say so and suggest `pipx install actualis` (or `uv tool install actualis`);
do not install it.

Otherwise run `actualis $ARGUMENTS` (with no arguments, that is the default
full report). Do not read transcript files yourself, and never pass
`--no-redact`.

Then summarise in under 15 lines: the period and agents covered, total cost,
and the top findings by severity with their ids (for example `AF002`), and
what to do about each. Never print credential values. If the exit code is 3,
the findings are the answer, not an error. Offer `actualis --why AFxxx` for
any finding the user wants explained.
