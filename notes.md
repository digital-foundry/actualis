### Fixed

- **`command_head` reported redirects and flags as programs.** `most_run` was
  listing `-oE`, `-E` and `2>/dev/null` as if they were commands, in both the
  report and the MCP `shell_audit` tool. Two defects: skipping `cd` plus its
  path argument left a trailing redirect as the first surviving token, and an
  assignment whose value is a command substitution was skipped whole, walking
  the parser onto the next token — usually a flag. So `cd /tmp 2>/dev/null`
  reported `2>/dev/null`, and `TOK=$(grep -oE …)` reported `-oE` rather than
  `grep`, which is what actually runs.

  On a real corpus the correction redistributed the garbage into real programs
  rather than only removing it: in auto-mode denials `grep` went from 0 to 15,
  `cat` from 9 to 15, `gh` from 13 to 18.

### Added

- **`tools/denials.py`** — joins Claude Code's tool-refusal records to the exact
  commands they blocked, via `tool_use_id`. Read-only, no network, standard
  library only, and it prints program names rather than command text. The join
  is exact — 359 of 359 on the corpus it was written against — and a refused
  command is never sent to a provider, so this is a signal that exists only in
  the local transcript. It is also what turned up the `command_head` bug above.
