# What gets detected

Credentials are found by matching command text, then **hashed to `sha256[:8]`
immediately**. The value is never stored, never printed, and never written to
JSON. A secret reused 200 times counts once; the same value under two variable
names is one secret carrying both names.

## Priorities

| priority | meaning | shown as |
|---|---|---|
| `critical` | money or database god-mode | `ROTATE` |
| `high` | service credentials | `rotate` |
| `low` | loopback development passwords | `dev` |

## Recognised by prefix

| type | priority | matches |
|---|---|---|
| Stripe key | critical | `sk_live_…`, `rk_live_…` |
| AWS access key | critical | `AKIA…`, `ASIA…` |
| Anthropic key | critical | `sk-ant-…` |
| OpenAI key | critical | `sk-…` (non-Anthropic) |
| JWT / service key | critical | `eyJ….…` |
| GitHub PAT | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| Google API key | high | `AIza…` |
| Slack token | high | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` |
| Vercel token | high | `vcp_…` |
| GitLab PAT | high | `glpat-…` |
| DigitalOcean | high | `dop_v1_…` |
| HuggingFace | high | `hf_…` |
| **Supabase PAT** | critical | `sbp_` + 40 alphanumerics. Full account authority |

## Recognised by shape

**Connection strings** — `scheme://user:password@host`. Remote hosts are
`critical`; loopback (`127.0.0.1`, `localhost`, `0.0.0.0`, `::1`,
`host.docker.internal`) is `low`, because rotating a dev password is busywork.

**Named assignments** — `NAME=value` where the name contains `SECRET`, `TOKEN`,
`PASSWORD`, `APIKEY`, `API_KEY`, `ACCESS_KEY`, or `PRIVATE_KEY`. Escalated to
`critical` when the name also mentions stripe, aws, service_role, private_key,
master, root, prod, payment, or billing — a variable called
`STRIPE_SECRET_KEY` is critical whatever its value looks like.

**Passwords passed as options** — `curl -u user:PASS` (also `-uuser:PASS`,
`--user`, `--user=`, `-U`, `--proxy-user`), `wget --password PASS` (also
`--http-password`, `--ftp-password`, `--proxy-password`), and
`docker login --password PASS` or `docker login -p PASS`. `high`. The user
part of `user:PASS` stays readable; only the password is masked. A `uid:gid`
pair, a shell reference and a placeholder are left alone, and the generic
`-p` (`mysql -pPASS`, `sshpass -p`) is not read: `-p` means other things in
other programs.

These ids are **not** `sha256(value)[:8]`. A person chose the password, so a
hash of it published in a report, a CI log or a committed
`.actualis-suppressions` would let anyone confirm a guess offline. The id is
derived from where the password appears instead: `sha256("opt:" + program +
":" + option + ":" + user)[:8]`. The program is lowercased. The option keeps
its case (`-U`, curl's proxy password, is not `-u`), and two spellings of one
option are one location (`--user` is `-u`, `--proxy-user` is `-U`, docker
login's `-p` is `--password`). The user is taken from `user:PASS`, `-u`,
`--username` or `--user` in the same command. `--password=PASS` and the other
`=` forms are read the same way as the space forms.

The same applies to every credential that actualis began counting in the same
release, since any of them may be a short, person-chosen password:

| credential | id from |
|---|---|
| a `PASSWORD`, `PASSWD` or `PASSPHRASE` variable whose value is 6 to 11 characters | the variable name and the command's program (`PGPASSWORD=… psql`) |
| a URL password shorter than 6 characters | `user@host` |
| an scp-style `user:password@host:` password | `user@host` |
| a password-less URL or scp userinfo longer than 20 characters | the host |
| an `Authorization:` header value with no recognised prefix | the program and the scheme word (`Bearer`, `Basic`, `token`) |

Credentials counted before that release keep their value-based ids: tokens
recognised by prefix, URL passwords of 6 characters or more, and named secrets
of 12 characters or more. A prefixed token passed as an option (`curl -u
alice:ghp_…`) is one entry with its value id, not two. Moving those to
location ids is a later change.

The trade-off is accepted: two different passwords at one location share one
id, so rotating one and reusing the line still shows as the same entry.

Because one such id can stand for several passwords, a suppression of it must
not silence a password it was never about. During a run, actualis keeps the
full `sha256` of each value seen under a location id, in memory only. They are
never written to JSON, a report or a log, and they are discarded when the run
ends. `--json` reports `distinct_values` for each secret, and the text report
says "N distinct values" when N is more than 1. If a suppressed location id has
more than one value in the run, it is treated as unsuppressed, for display and
for `--fail-on`, with the reason "suppression covers one value; N seen".

**The limit is per run.** Nothing about a value survives the run, so a new
password that appears in a later run, alone under its id in that run, cannot be
told apart from the one the suppression was recorded for. The suppression then
still applies.

## Deliberately not flagged

Both classes below were found firing on real data and removed. A scanner that
cries wolf is worse than none.

**Field and metric names that merely sound like secrets:** `output_tokens`,
`input_tokens`, `max_tokens`, `token_count`, `token_hash`, `api_key_enc`,
`access_token_enc`, `encrypted_password`, `token_id`, `token_expiry`.

**Bare plurals**, which name a collection rather than a credential: `TOKENS`,
`SECRETS`, `KEYS`, `PASSWORDS`, `CREDENTIALS`. This tool's own source tripped
that one.

**Vendor example credentials.** Every cloud vendor publishes a fake credential
in its own documentation, and those strings end up in tutorials, test fixtures
and issue threads. `AKIAIOSFODNN7EXAMPLE` is AWS's, and it appears in AWS's CLI
reference and a large share of every AWS tutorial written. It is not a
credential and is not reported as one.

AWS builds all of its examples the same way — the key body ends in `EXAMPLE` —
so that shape is excluded generally, not just the enumerated strings. The rule
is a suffix match, not a substring match: a real key that merely contains
`EXAMPLE` is still reported. Each enumerated entry names the vendor
documentation it comes from, so the list can be checked rather than believed.

Other vendors publish examples too. They are deliberately absent until someone
verifies them against the vendor's own docs — a plausible-looking string added
from memory is the kind of unchecked claim this tool exists to avoid.

**Placeholders and references:** `$SHELL_VAR`, `${VAR}`, `your_key_here`,
`changeme`, `example`, `dummy`, `placeholder`, `test_`, `fake`, `todo`, bare
numbers, and anything already redacted.

## Untrusted input

Command text is treated as hostile. Control characters are stripped before
anything is printed or written to JSON, and every pattern uses bounded
quantifiers so a pathological command cannot hang the scan. See
[SECURITY.md](../SECURITY.md#hardening).

## What it cannot see

Pattern matching has a ceiling, and it is stated here rather than discovered
later. A command that builds a credential dynamically, reads one from a file, or
runs a script whose contents live elsewhere will not be caught. **This raises the
floor on visibility. It is not a security boundary.**

Subagent shell commands are not in the parent transcript at all, so no secret
inside one can be detected. See [AF011](findings.md#af011).

## How this list is maintained

Detectors are added from evidence, not from a list of providers somebody has
heard of. A prefix earns a place by being distinctive enough that ordinary text
does not collide with it.

**Supabase PAT** was added on 2026-08-26 after a corpus scan found 58
occurrences with one consistent shape and no detector for them.

**Resend (`re_`)** was considered on the same pass and rejected. The corpus
contained 180 matches for `re_` plus sixteen or more opaque characters, across
37 distinct shapes — every one an ordinary lowercase identifier
(`re_deploy-preview-branch`), with no digits, no mixed case and no entropy.
Adding it would have produced 180 false positives and zero true ones. A
two-character prefix is too generic to carry a detector.

Exclusions are maintained the same way. On 2026-08-26 all 49 distinct
name-based detections on a real corpus were reviewed by hand; **18 were wrong**,
and each exclusion added since names the case that produced it rather than
describing a category in the abstract.
