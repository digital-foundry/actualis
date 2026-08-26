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

## Deliberately not flagged

Both classes below were found firing on real data and removed. A scanner that
cries wolf is worse than none.

**Field and metric names that merely sound like secrets:** `output_tokens`,
`input_tokens`, `max_tokens`, `token_count`, `token_hash`, `api_key_enc`,
`access_token_enc`, `encrypted_password`, `token_id`, `token_expiry`.

**Bare plurals**, which name a collection rather than a credential: `TOKENS`,
`SECRETS`, `KEYS`, `PASSWORDS`, `CREDENTIALS`. This tool's own source tripped
that one.

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
