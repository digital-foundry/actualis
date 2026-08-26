Both detector lists audited against 49,879 real commands rather than against
intuition, and three things the tool asserted in prose that it can now show.

### Added

- **Commands the audit could not read are now counted and reported.** "Pattern
  matching has a ceiling" is true and vague: it does not distinguish *we looked
  and found nothing* from *there was nothing here to look at*, and only the
  second is a blind spot. A command that runs `$CMD`, evals a string, pipes a
  download into a shell, or executes a script whose contents live elsewhere is
  unreadable rather than unmatched. On a real corpus that is **3.11% of
  commands**. Counted, never flagged — running a script is normal, and this is
  a statement about what the audit could see rather than an accusation.

- **Shell-audit findings can be suppressed too.** 0.1.3 gave credentials
  `--suppress` and left 36 audit rules with no way to say they were wrong, which
  is arbitrary from a user's side: an `rm -rf build` flagged every run forever
  leaves only the options of ignoring the section or ignoring the tool. Flag ids
  are keyed on severity, category and program rather than command text, so
  suppressing one thing suppresses the class a person means. Same rule as
  before: a suppressed flag is still counted, and `suppressed_flags` reports the
  total.

- **A vendor capability matrix**, in `--explain vendors`, in `--json`, and on
  the site's limits page. Both agents are read and their transcripts do not
  contain the same things — Claude Code records every refused tool call and
  **Codex records none**, so that entire section is single-vendor. The report
  now says so in place when a Codex session is present. Every row names the
  transcript field it rests on, so a claim can be checked against the parser
  rather than taken on trust. Comparing two projects on different agents
  compares different measurements, and nothing previously said which.

### Changed

- **Both detector lists were audited against a real corpus rather than against
  intuition**, and the result went in both directions.

  **Added: Supabase personal access tokens.** A corpus scan found 58
  occurrences of `sbp_` followed by exactly 40 alphanumerics — one consistent
  shape, no detector. A Supabase PAT carries full account authority, so it is
  classified critical.

  **Rejected: Resend (`re_`).** The same scan found 180 `re_` matches across 37
  distinct shapes, every one an ordinary lowercase identifier
  (`re_deploy-preview-branch`) with no digits, no mixed case and no entropy.
  Adding it would have produced 180 false positives and zero true ones. A
  two-character prefix is too generic to carry a detector, and the rejection is
  recorded in the source with the measurement so it does not get re-proposed.

  **18 false positives removed.** All 49 distinct name-based detections on the
  corpus were reviewed by hand. The wrong ones were not one-offs — they fell
  into shapes, and each exclusion added names the case that produced it:
  `AUTHOR` (a trigger word starting a longer word, the same defect class as
  `FORKEY`), `SESSION_RECORDING_SAMPLE_RATE` (analytics config),
  `AUTH_PROVIDER_ID` (an identifier), `EMBED_TURNSTILE_SITE_KEY` (a site key is
  public by design; only its paired secret is secret),
  `TINFOPLIST_KEY_LSAPPLICATIONCATEGORYTYPE` (an Xcode build setting).

  On the corpus this took distinct secrets from 128 to 112 and distinct kinds
  from 61 to 45, with no true positive lost. Both batteries ship as tests.

### Fixed

- **`command_head` was wrong on 167 real commands.** Running it across 49,879
  distinct commands from a real corpus found violations in four shapes that
  unit tests had no cases for:

  - A **quoted path containing a space** was torn apart by a naive split, so a
    path fragment became the program on 100 commands.
  - **`for` and `if` were returned as programs** on 46, because header keywords
    were only checked at the start of a segment — `( for i in …` and
    `do if docker …` both reach one mid-segment.
  - **Heredoc bodies were treated as commands** on 121. Splitting on newlines
    made every line of a heredoc its own candidate, so a path inside a document
    became "the program".
  - **`if [ -f x ]`** returned the test's operand.

  Down to one, and that one is a variable-expanded path — honest rather than
  wrong. Distinct heads fell from 512 to 414, so roughly a hundred spurious
  entries left `most_run`, which appears in the report and in the MCP
  `shell_audit` tool.

  Fixing it needed two distinctions the code did not previously make. A quoted
  span must neither split nor disappear: dropping quoted spans lost the program
  when the program itself was quoted (`"$P" --check`). And `for x in LIST` takes
  a word list while `if CMD` takes a command, so the first abandons the rest of
  its segment and the second must be scanned into.

  The corpus cannot ship, so every shape it surfaced is now a fixture, and the
  test asserts the invariants — never a flag, a redirect, a keyword or blank —
  rather than only the expected answers.

- **A template placeholder no longer defeats an exclusion.** Names arrive
  wrapped as `__X__`, `{{X}}` or `%X%`, and the decoration is not part of the
  name, so one rule now covers every spelling.
- **A detector could be counted without being masked.** Adding Supabase to
  `SECRET_TYPES` without adding it to the redaction prefixes classified the
  token and then printed it. A test now checks the invariant across every typed
  detector, not just the named ones.
