# `--ioc`: matching downloads against a known-bad list

During a supply-chain incident the first question is: did any coding agent on
this machine, or in CI, install `X@bad-version` or contact `evil.example`, and
did anyone approve it? `--ioc FILE` answers it offline. It compares the network
inventory (see `--explain network`), every download the transcripts show and
actualis can read, against a list you supply.

```sh
actualis --ioc iocs.txt                       # the IOC block in NETWORK
actualis --ioc mal-npm.jsonl --fail-on high   # exit 3 on a known-bad install
actualis --ioc iocs.txt --json | jq '.network.ioc.totals'
```

- **Explicit only.** The list is read when named with `--ioc`, and never
  otherwise: there is no default path, environment variable or file in the
  current directory. A file called `.actualis-ioc` means nothing.
- **Repeatable.** `--ioc a.txt --ioc b.jsonl` loads both; the order sets each
  entry's `source` index.
- **No network.** Nothing is fetched. Getting the list is your step, and the
  [CI recipe](#ci) below shows where to put it.

## Verdicts

| verdict | when | finding |
|---|---|---|
| `match` | an any-version entry names the package; the installed version is inside the entry's spec; or a host entry matches the host the download came from | high, category `network-ioc` |
| `unresolved` | the name matches but the comparison cannot be decided: the install named no single version (`latest`, `^4.1.0`, none), the versions do not order, the package came from a private registry, the name was read from a git or tarball URL, a Go package inside a listed module could not be ordered, or checking the item failed | medium, category `network-ioc-unresolved` |

The `reason` says which: `any-version`, `version-in-spec` or `host` for a
match; `version-unresolved`, `undecidable`, `module-prefix`,
`private-registry`, `name-from-url` or `error` for unresolved.

**Go modules.** A Go install names a package (`go install
evil.example/m/cmd/x@v1.0.0`); lists name the module (`go:evil.example/m`). A Go
item is checked against its own path and every `/`-boundary prefix of it,
longest first, so a package inside a listed module matches with the version the
command named. When that version cannot be ordered against the module's spec,
the reason is `module-prefix`.

- **Refused calls** (a person denied the tool call) are listed with
  `refused: true`. They never produce a finding and never fail a gate.
- **A name match whose version is outside every spec** is clean. It is only
  counted, in `totals.clean_name_matches`.
- **The trust list never exempts a match.** `--network-trust` and
  `.actualis-network-trust` say where downloads may come from; a known-bad
  package from a trusted registry is still known-bad.
- **Fail closed.** If checking an item hits an error, or the list holds a
  range it cannot read, the item is `unresolved`, never clean, and counted in
  `totals.undecidable`.

One finding is raised per (verdict, key): forty installs of one bad version are
one finding saying `40 install(s)`. The key is `npm:name@1.2.3` (`@?` when the
version is unresolved) or `host:evil.example/path`.

Findings are suppressible like any other (`actualis --suppress <id> --reason
"..."`), because a private package can share a name with a public squat.
Suppressed findings stay counted and stay in `--json`.

## What can be checked

| ecosystem | written as | resolved version (the install names one release) |
|---|---|---|
| npm | `npm` | a full `MAJOR.MINOR.PATCH`, a leading `=` or `v` allowed. An alias `x@npm:evil@1.0.0` checks `evil@1.0.0`, and `x` as unresolved |
| pypi | `pypi`, `pip` | `==` or `===` |
| crates | `crates`, `crates.io`, `cargo`, `rust` | `cargo install --version 1.2.3`, or `cargo add x@=1.2.3`. `cargo add x@1.2.3` is a requirement, not a version |
| go | `go`, `golang` | a `v`-prefixed SemVer version, pseudo-versions included. `@latest`, `@v1.2` and `@1.2.3` are queries |
| oci | `oci`, `docker`, `container` | a tag other than `latest`, or a `sha256:` digest |
| brew | `brew`, `homebrew` | never: no version is recorded, so brew entries have no version spec |

`rubygems`, `nuget`, `maven`, `packagist`, `composer`, `pub`, `hex`, `erlang`,
`swift`, `swifturl`, `actions`, `github-actions`, `vscode`, `open-vsx` and `git`
entries are accepted and counted as not checkable: this inventory never sees
those installs. Any other ecosystem word is an error.

Names compare as each ecosystem does: npm and Go exactly (case-sensitive),
pypi by PEP 503 (`Foo_Bar`, `foo.bar` and `FOO-BAR` are one name), crates
lowercased with `_` as `-`, and images with Docker Hub spelled out or not
(`docker.io/library/nginx`, `library/nginx` and `nginx` are one name).

**Go hosts.** A Go module's host is the first element of its path, so a host
entry matches a module's origin (`host:github.com/evil` matches
`go get github.com/evil/mod`), not the proxy the download actually used.

**Not visible.** Lockfile installs (`npm ci`, `pip install -r`, `uv sync`),
scripts, Makefiles and postinstall hooks are out of sight, and only the
transcripts still on this machine are read. The coverage line says how many
downloads could be checked. **No match is not "not affected".**

## The `actualis-ioc` line format, version 1

One entry per line. `#` starts a comment at the start of a line or after a
space. Blank lines are ignored. UTF-8, LF or CR LF, a BOM allowed.

```
# Shai-Hulud wave 1
npm:@ctrl/tinycolor@=4.1.1||=4.1.2   id=GHSA-0000-0000-0000 label=shai-hulud from=2025-09-14 until=2025-09-17
npm:eslint-config-prettier@8.10.1||9.1.1||10.1.6||10.1.7   id=MAL-2025-6022
pypi:Requests_Darwin.Lite            # PEP 503 normalises to requests-darwin-lite
crates:evil_crate@>=0.1.0,<0.1.5
go:github.com/evil/mod@<v1.4.2
oci:ghcr.io/evil/img@=sha256:3f2a0000000000000000000000000000000000000000000000000000000000ff
brew:python@3.12                     # the whole thing is the formula name
rubygems:rest-client                 # accepted, not checkable
host:webhook.site                    label=exfil
host:github.com/evil-org
host:=203.0.113.7
```

**Package entries** are `ecosystem:name`, optionally `@spec`. The name and spec
split at the first `@` (npm: the first `@` after the scope's; oci: the last
`@`, since a registry port uses `:`; brew: never, `python@3.12` is a formula).

**Specs.**

- No spec, `*`, `>=0` and `>=0.0.0` mean any version.
- `||` separates alternatives; `,` joins comparators that must all hold:
  `>=1.0.0,<2.0.0||=3.1.4`.
- Operators: `=` (or `==`, or none), `>=`, `<=`, `>`, `<`, and `===` (pypi only:
  exact string equality).
- npm, crates and go versions are full SemVer 2.0.0, ordered by its section 11;
  pypi versions are PEP 440, ordered as `packaging` orders them.
- An image spec is `=TAG` or `=sha256:<64 hex>` alternatives; a tag compared
  with a digest is undecidable.
- Not accepted, each with a message saying what to write instead: `^` and `~`
  ranges, wildcards (`1.x`, `1.*`), two versions in one comma clause, words
  like `latest`, versions that are not full (`1.2` for npm), empty clauses, and
  spaces inside a spec.

**Host entries** are `host:hostname` or `host:hostname/path`. They match the
host and every subdomain, on a label boundary (`host:evil.io` matches
`a.evil.io`, not `notevil.io`), and a path on a segment boundary.
`host:=hostname` matches that host only. No scheme, port, wildcard or IPv6. A
host entry matches a host the command named, or one the session supplied as a
URL: a git remote added or cloned earlier in the session (`git pull up`), or a
`brew tap`'s `github.com/<owner>/homebrew-<repo>`. It never matches the default
registry a bare install implies (`registry.npmjs.org` for `npm i x`). A host entry with no path naming
`github.com`, a registry or another shared host loads with a warning, because
it matches every download from there.

**Attributes**, all optional, each at most once: `id=` (the advisory, shown as
the reference), `label=`, and `from=` / `until=` (dates, `YYYY-MM-DD`). `from`
and `until` are shown and **not yet applied**: a version listed for a window
matches whenever it was installed.

## OSV

An OSV file is detected by its first byte: `{` is one record (or JSONL, one
record per line), `[` is an array of records. Mapped as the
[OSV schema](https://ossf.github.io/osv-schema/) defines it:

- ecosystems `npm`, `PyPI`, `crates.io` and `Go`, matched exactly; every other
  ecosystem is counted as not checkable, never an error;
- `versions[]`, each an exact version (kept as text when it does not parse);
- `SEMVER` and `ECOSYSTEM` ranges: `introduced`, `fixed` and `last_affected`
  events; `limit` is ignored, which leaves the range open above (over-matching
  is the safe direction);
- an entry with neither versions nor a usable range matches any version;
- withdrawn records are skipped and counted; `GIT` ranges are counted;
- a range that cannot be read (a version that does not order, an unknown event
  or type, too many events) is undecidable: a name match against it is
  `unresolved`, never clean, and every such range is counted in `skipped_ranges`;
- malformed records are counted and reported with the first line, never fatal;
- `references[]` never become host entries.

For example, from a checkout of the OpenSSF malicious-packages repository:

```sh
find malicious-packages/osv/malicious/npm -name 'MAL-*.json' -exec cat {} + | jq -c . > mal-npm.jsonl
actualis --ioc mal-npm.jsonl
```

**Use malware lists, not vulnerability databases.** A CVE dump lists every
version of popular packages that ever had a bug. It turns every install into
a finding and teaches people to delete `--ioc` from CI.

**Converting a CSV.** For a CSV of package and version columns, check which
columns hold what first, then write one line per row. With the package in
column 1 and the version in column 2:

```sh
awk -F, 'NR > 1 { print "npm:" $1 "@=" $2 }' list.csv > iocs.txt
```

## Limits

An IOC list is untrusted input, so every limit is hard and enforced while
reading. Any of these exits 2, naming the file and, where there is one, the
line:

| limit | value |
|---|---|
| one file, and all files together | 1 GiB |
| a line-format file, an OSV array, or an OSV document parsed whole | 64 MiB (larger OSV: convert to JSONL, `jq -c '.[]' f > f.jsonl`) |
| one line | 1 MiB |
| lines in one file | 4,000,000 |
| entries in total | 1,000,000 |
| JSON nesting | 64 levels |
| alternatives in one line-format entry | 10,000 |
| a version / a name | 128 / 214 characters |
| no checkable entry in any file | exit 2: a gate that can check nothing must not pass |

An OSV entry with more than 10,000 alternatives, or a range of more than
10,000 events, is undecidable rather than an error.

## CI

The list must not be something the agent could have written. Fetch it in a
step **after** the agent step, outside the workspace, verify it if you pin it,
and pass its path:

```yaml
- name: Fetch the IOC list
  run: |
    curl -fsSL "$IOC_URL" -o "$RUNNER_TEMP/iocs.jsonl"
    echo "$IOC_SHA256  $RUNNER_TEMP/iocs.jsonl" | sha256sum -c

- run: pipx install actualis && actualis --ci-log "$LOG" --ioc "$RUNNER_TEMP/iocs.jsonl" --fail-on high
  env:
    LOG: ${{ steps.claude.outputs.execution_file }}
```

With the actualis Action, pass the path as the `ioc` input (one path per
line). Its `fail-on` defaults to `critical`, and IOC matches are `high`, so by
default a match does not fail the job; the Action prints a warning saying so.
Set `fail-on: high`. The `ioc-matches` output is the number of unsuppressed
match rows.

**Provenance.** The report records each file's absolute path, sha256 and
format, and `mtime_in_window` says whether the file changed while the agent
was working (between the first and last transcript record). A file fetched
after the agent step reads `false`. If the list sits where the agent could
write it, the agent could have edited it; the hash is what lets you tell.

## Output

`--json` carries `network.ioc` (always an object; `enabled: false` without
`--ioc`), and `network.items[].ioc` is `match`, `unresolved` or `null`. See
[json.md](json.md#networkioc). The findings are `bash.flags[]` entries with the
categories `network-ioc` and `network-ioc-unresolved`; see
[findings.md](findings.md#network-findings).
