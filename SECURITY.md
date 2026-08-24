# Security

actualis reads session transcripts that contain credentials. Its own
correctness is therefore a security property, not just a quality one.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** — the *Report a vulnerability*
button under this repository's Security tab. It is private, it threads, and it
needs no email address from either of us.

Please do not open a public issue for anything in the classes below. Expect an
acknowledgement within a few days.

## What counts as a vulnerability here

- **A credential reaching output that should be redacted.** Any input where
  `actualis` prints, logs, or emits a secret value without `--no-redact`.
- **Anything identifying reaching `--share`.** A project name, branch, ticket,
  path, command, hostname, or fingerprint in the postable summary.
- **A write or a network call.** The tool opens files read-only and makes no
  network requests. Any path that violates that is a bug of this class.
- **Reading outside the transcript directories** it reports in its header.

A proof-of-concept input string is the most useful report. Please redact your
own real secrets from it.

## What is not a vulnerability

- **A missed credential.** Detection is pattern matching and has a stated
  ceiling: dynamically constructed values, secrets read from files, and anything
  inside a subagent are not detectable. See [docs/secrets.md](docs/secrets.md).
  This raises the floor on visibility; **it is not a security boundary**.
- **A false positive.** Annoying, worth reporting as a normal issue, not a
  vulnerability.
- **Secrets in your transcripts.** The tool reports that condition; it does not
  cause it.

## Hardening

Transcripts contain whatever an agent typed, fetched, or was fed, including text
from web pages and files. All of it is treated as untrusted input.

- **Terminal escape sequences are stripped** from every string derived from a
  transcript, at the point it enters the data structure rather than at print
  time. Escape codes can move the cursor and overwrite text, which would let a
  crafted command hide its dangerous half from the audit that exists to reveal
  it. Found by probing, not review.
- **Regex quantifiers are bounded.** Wide character classes with unbounded `*`
  backtrack quadratically. A 140,000-character command took **164 seconds**
  before this was fixed; it now takes 80 ms, a 2,000x difference. Input is also
  capped per line and in total as defence in depth.

## Design commitments

These are properties, not aspirations, and each is covered by tests:

- Redaction is on by default everywhere, including `--json`.
- Secret values are hashed on sight and never stored.
- `--share` is tested by planting identifying strings and asserting none survive.
- No dependencies, so there is no supply chain beyond the Python standard
  library.
- One file, so the whole program can be read before you run it.
