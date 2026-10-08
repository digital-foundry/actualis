# Network inventory: what the agent downloaded, and whether anyone asked — design

Date: 2026-10-08
Status: draft, awaiting review

## Intent

**Goal (stated):** show what coding agents download or fetch, and which of
those downloads no person approved.

**Answers both questions in one section:**

- supply chain — what entered the machine (packages, repos, binaries);
- exposure — where the agent reached out to (hosts, first seen).

**Default behaviour (stated):** inventory only. Nothing in it changes the
grade, the exit code or the Action's pass/fail.

**Advanced behaviour (stated):** an opt-in strict mode makes every unasked
download from an untrusted source a finding. An explicit trust list cuts the
noise.

**Sequence:** this is the first of three sub-projects. The other two each get
their own spec:

1. network inventory (this spec);
2. security-tool export of findings;
3. `--correlate` with offline provider audit exports.

**Constraints (inherited, not negotiable):**

- Local, read-only, no network. `--self-check` must keep passing.
- Single file, no third-party dependencies, Python 3.9+, AGPL-3.0.
- Secrets never printed: every URL goes through the existing command
  redactor. `--no-redact` behaves as it does today.
- `--json` stays `schema_version` 1. A new top-level key is allowed within a
  major version (docs/json.md, Compatibility), so `--diff` keeps working
  against old baselines.

## 1. What counts as a download

A **network item** is one record, produced from either a shell command or a
tool call.

### 1.1 Shell commands — one extractor per program

Each command is split into its segments, on `&&`, `||`, `;`, `|` and
newline. Each segment is tokenised with `shlex` (`posix=True`; when that
fails, the segment is skipped and counted under `unparsed`).

Before matching the program, these prefixes are stripped:

- `sudo` (and its flags);
- `env`, `time`, `nice`, `nohup`;
- `VAR=value` assignments;
- a leading `cd <dir> &&`.

Commands nested inside other commands are scanned the same way:

- `$( … )` and backticks;
- the argument to `bash -c` / `sh -c` / `zsh -c`.

A segment whose program is not in the table yields nothing. The parser never
guesses.

| program | kinds | fields extracted |
|---|---|---|
| `curl` | fetch | URL, host, `-o`/`-O`/`--output` destination |
| `wget` | fetch | URL, host, `-O`/`-P` destination |
| `git clone`, `git fetch`, `git pull`, `git submodule update` | clone | remote URL or host; a remote *name* (e.g. `origin`) gives `host: null` |
| `gh repo clone`, `gh release download` | clone / fetch | `owner/repo` (host `github.com`) |
| `npm i/install/add`, `pnpm add/install`, `yarn add/install`, `bun add/install` | install | ecosystem `npm`, package names, `@version` → `pinned` |
| `npm ci`, `pnpm install --frozen-lockfile`, `yarn --immutable` | install | lockfile install: `pinned: true`, no names |
| `npx`, `pnpm dlx`, `bunx` | install | package, version; `exec: true` |
| `pip install`, `pip3 install`, `python -m pip install`, `uv pip install`, `uv add` | install | ecosystem `pypi`, names, `==version` → `pinned`; `-r FILE` → `source: FILE`; `git+URL` or URL → host |
| `uv sync`, `pip install -r` with hashes | install | lockfile/requirements install |
| `uvx`, `pipx run`, `pipx install` | install | ecosystem `pypi`, package; `exec: true` for `uvx`/`pipx run` |
| `brew install`, `brew tap` | install | ecosystem `brew`, formula or tap |
| `cargo install`, `cargo add` | install | ecosystem `crates`, crate, `--version` |
| `go install`, `go get` | install | ecosystem `go`, module path (host = first path element), `@version` |
| `docker pull`, `docker run`, `podman pull` | install | ecosystem `oci`, image, tag/digest (`@sha256:` → `pinned`) |

**Hosts:**

- a URL argument gives its host;
- a registry install with no URL gives the ecosystem's default registry host
  (`registry.npmjs.org`, `pypi.org`, `formulae.brew.sh`, `crates.io`,
  `proxy.golang.org`, `registry-1.docker.io`). This is recorded with
  `host_inferred: true`;
- `--registry` / `--index-url` / `-i` overrides it.

**Dynamic URLs:** a URL containing `$` or a backtick gives `host: null` and
`dynamic: true`.

### 1.2 Tool calls

| tool | kind | fields |
|---|---|---|
| Claude Code `WebFetch` | fetch | `url`, host |
| Claude Code `WebSearch`, Codex `web_search` | search | query is **not** stored; `host: null` |
| MCP tools whose name contains `fetch`, `browse`, `download` or `http` | fetch | `url` argument if present |

### 1.3 Outcome

When a tool result is joined to its call (by `tool_use_id`, as refusals are
today) and marks an error, the item gets `failed: true`. Failed items are
counted and shown, marked failed.

A refused call never ran. It gives no item and stays in the existing
refusals section.

### 1.4 Out of sight (stated in `--explain network`)

What happens inside the following is not visible in the transcript and is
not inferred:

- `bash script.sh`, `make`, `npm run`, `just`;
- postinstall hooks;
- language-level fetches (`requests.get` in a `python -c`).

## 2. Approval

Every item carries `approval`, which is one of `asked`, `unasked` or
`unknown`.

| agent | asked | unasked | unknown |
|---|---|---|---|
| Claude Code | a per-call approval record for the call, if the transcript has one (none confirmed yet: verify against a real session during implementation; if none exists, this column is empty for Claude Code) | the turn's `permissionMode` satisfies `is_ungated_mode()` (auto, `bypassPermissions`) | any other mode (`default`, `acceptEdits`, `plan`): a settings allowlist rule may have allowed it silently |
| Codex | — | turn `approval_policy` is `never` (`is_ungated_mode("codex:never")`) | any other policy |
| Copilot CLI | `permission.completed` result `approved` | `approved-for-location` (a standing rule) | no permission record |

**Reuse:** the per-turn mode lookup already used for the "auto or bypass"
statistic. The mapping goes through `is_ungated_mode()`, the single
definition that `--share` and `--card` already read, so "unasked" cannot
disagree with "unsupervised".

**Shown once in the report:** under the NETWORK header, a short note says
that `unknown` means "default mode, where an allowlist rule may have approved
it without asking".

## 3. Trust list

**Sources, merged:**

- `--network-trust ENTRY[,ENTRY…]`, repeatable;
- `./.actualis-network-trust` in the current directory, one entry per line,
  `#` comments and blank lines ignored. It is meant to be committed.

**Entry forms:**

- a host — `npmjs.org` matches that host and every subdomain (suffix match on
  a label boundary: `evilnpmjs.org` does not match);
- a host plus a path prefix — `github.com/digital-foundry` matches URLs and
  `owner/repo` under that prefix, on a segment boundary.

**Matching items:**

- an item with `host: null` never matches;
- an inferred registry host matches like any host.

**Rejected entries:** an entry with a scheme, a port, `*`, or that does not
parse as a host is rejected with exit 2 and a message naming the entry. This
follows the existing exit-code convention for a bad invocation.

`trusted` is recorded on every item. Outside strict mode it has no effect on
the outcome.

## 4. Strict mode

`--network-strict` (Action input `network-strict: true`) makes a finding of
each item where all of these hold:

- `approval` is `unasked` or `unknown`;
- `trusted` is false;
- `failed` is false.

**The finding:**

- category `network-unasked`, severity `med`;
- grouped like other findings (by program and host), so a thousand
  `npm i lodash` runs are one finding with a count;
- its id comes from `flag_id(severity, categories, program)` plus the host,
  so suppressions are stable across runs;
- `.actualis-suppressions` suppresses it with the existing mechanism, and a
  suppressed finding is still counted, as today;
- it feeds `--fail-on any`, but not `--fail-on high` or `--fail-on critical`.

The Action also gets input `network-trust`, passed through as
`--network-trust`.

## 5. Output

### 5.1 Text report

A `NETWORK` section after the commands audit, capped by `--top`:

```
NETWORK  412 downloads in 30 days · 63 unasked · 118 unknown
  unknown = default mode, where an allowlist rule may have approved it without asking
  INSTALLED   npm 214 · pypi 71 · brew 9 · crates 3      14 unpinned packages
  CLONED      19 repos   github.com 17 · gitlab.com 2
  FETCHED     88 urls    31 hosts, 6 first seen this period
  UNASKED     raw.githubusercontent.com  curl -o ~/bin/x      proj-a  2026-10-03
              registry.npmjs.org         npx create-foo@latest  proj-b  2026-10-05
```

- The UNASKED rows list unasked items first, then unknown, newest first.
  Asked items only contribute to the counts.
- With no network items, the section prints one line: `NETWORK  no
  downloads seen`.

### 5.2 `--json`

`schema_version` stays 1 (an additive key).

```json
"network": {
  "totals": {"items": 412, "unasked": 63, "unknown": 118, "asked": 231,
             "failed": 9, "unparsed_segments": 2},
  "by_kind": {"install": 297, "clone": 19, "fetch": 88, "search": 8},
  "hosts": [{"host": "pypi.org", "count": 71, "unasked": 4, "first_seen": "2026-09-10T…",
             "first_seen_in_window": false, "trusted": false}],
  "packages": [{"ecosystem": "npm", "name": "left-pad", "versions": [], "pinned": false,
                "exec": false, "count": 3}],
  "items": [{"kind": "fetch", "program": "curl", "host": "raw.githubusercontent.com",
             "host_inferred": false, "url": "<redacted URL>", "dest": "~/bin/x",
             "ecosystem": null, "package": null, "version": null, "pinned": false,
             "exec": false, "dynamic": false, "failed": false, "approval": "unasked",
             "trusted": false, "agent": "claude", "project": "proj-a",
             "session": "<id>", "ts": "2026-10-03T…"}],
  "strict": false,
  "trust": ["npmjs.org", "github.com/digital-foundry"]
}
```

- **`items` is capped** at 2,000, newest first, with `items_truncated: true`
  when the cap is hit. Totals are always exact.
- **`--share` and `--card`** get only `network.totals` and `by_kind`.
  Hosts, packages, projects and URLs never reach shareable output. The
  existing `--share` leak test is extended with network fixtures.
- **`docs/json.md`** documents the `network` key.

### 5.3 `--explain network`

A new `EXPLAIN` topic. It covers:

- what counts as a download;
- the approval mapping per agent;
- the `unknown` caveat;
- the out-of-sight list (§1.4);
- trust-list syntax;
- strict mode;
- a `verify` line: `actualis --json | jq '.network.totals'`.

## 6. Self-check and dependencies

- `shlex` (standard library) is the one new import. It is added to the
  import allowlist in `.github/workflows/test.yml`, and to whatever list
  `--self-check` prints, so the proof stays exact.
- No new file is written. `.actualis-network-trust` is only read.

## 7. Testing

- **Extractors:** a table per program, command string in, item(s) out:
  - prefixes;
  - compound and nested commands;
  - pinned and unpinned;
  - registry override;
  - dynamic URLs;
  - remote names;
  - unparseable quoting, counted as `unparsed`.
- **Tool calls:** `WebFetch`, `WebSearch` (query not stored), and MCP fetch
  name matching.
- **Approval:** the mapping per agent, built from real record shapes in the
  existing fixtures, including Copilot `approved-for-location` and Codex
  `never`.
- **Trust:** host suffix on a label boundary, path prefix on a segment
  boundary, comments, file plus flag merge, and invalid entries exiting 2.
- **Strict:** findings only for untrusted, unasked or unknown, and not
  failed; grouping and stable ids; suppression; `--fail-on any` trips while
  `--fail-on high` does not.
- **Output:**
  - `--json` shape and the `items` cap;
  - `schema_version` still 1, and `--diff` against a v0.2.1 baseline;
  - the `--share` leak test with network fixtures;
  - the empty-section line.
- **Demo:** `tools/make-demo-fleet.py` gains downloads, and the golden report
  is regenerated.
- **Self-check:** passes with `shlex` in the allowlist.

## 8. Not in this spec

- Typosquat detection, lockfile reading, and vulnerability lookups.
  Reading lockfiles or calling advisories would break "transcripts only, no
  network".
- Export in security-tool formats (sub-project 2) and `--correlate`
  (sub-project 3).
