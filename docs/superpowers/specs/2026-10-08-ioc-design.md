# N2a: `--ioc FILE`, offline known-bad matching (implementation spec, fix wave D)

Status: final (pass 3), 2026-10-08. Supersedes N2 in pass 1 and N2a in pass 2 wherever they differ.
Code baseline: branch worktree `actualis-network` at 51ed5c0 plus the uncommitted fix wave A diff. The line numbers on that branch are moving, so this spec names functions and never cites lines.
Normative words: MUST, MUST NOT and MAY.

## 0. What changed from pass 2, and why

These were checked against the code or a primary source in this pass.

| # | Pass 2 said | Pass 3 decision | Basis |
|---|---|---|---|
| D1 | `network.ioc` is `null` without the flag | `network.ioc` is **always an object**. Without `--ioc` it is `{"enabled": false, ...}`, with zero totals and empty arrays | The schema-freeze test (`TestJSONSchemaFreeze._walk` in `tests/test_actualis.py`) walks a dict into its children and records `null` as a leaf. It cannot declare an "object or null" path. `test_every_fixed_path_is_actually_emitted` would also fail on a path that is null in the populated fixture. An always-present object keeps every type stable |
| D2 | `--why` works for IOC flags "through the existing flag path" | Out of scope. `--explain ioc` is the explanation | `render_why` resolves only coach ids (`coach(fleet)`). It never looks at `fleet.flags` |
| D3 | `from=`/`until=`: parse and show, or reject? | Parse, validate, store and show. They have **no effect** on verdicts in N2a. A dim note says so whenever any loaded entry carries one | Rejecting them would make the N2b change a format break. Parsing them silently would imply a window check that does not exist, hence the note |
| D4 | Should `unresolved` trip `--fail-on high` when the item ran code (`npx`, `uvx`)? | **No.** It stays `med`. The evidence says `ran it (npx)`, and `matches[].item.exec` carries the flag | `flag_id` hashes the severity, so a later promotion needs a new category anyway (N2b's `network-ioc-window`). A high here would fire on every `npx <name>` for any listed name, whatever its version |
| D5 | npm alias `x@npm:evil@1.0.0` is unresolved and "trivial adversarial defeat" | The alias **target** is also checked, as npm `evil@1.0.0` | `_net_npm_package` stores `version="npm:evil@1.0.0"` (probe). Parsing it closes a bypass for about 5 lines |
| D6 | Unreadable file: `ap.error` | Every load failure exits **2** through `ap.error`, naming the file and, where there is one, the line. **A set of files with zero checkable entries also exits 2** | A gate that can check nothing must not print PASS |
| D7 | `--ioc` with other modes | `--ioc` combined with `--card`, `--watch` or `--mcp` is an `ap.error` (exit 2). It is never silently ignored | Silent no-op is the worst failure an IOC flag can have |
| D8 | Action `findings` output | Unchanged. A new output, `ioc-matches`, is added | Today `findings` counts coach findings plus unsuppressed secrets only (`action.yml`). Changing its meaning is a separate item (R1) |
| D9 | Crates resolution | It uses B1's corrected `pinned` (fix wave B), plus a full-SemVer check | `cargo install --version 1.2.3` is exact, and `cargo add serde@1.2` is a requirement. The item records only `program="cargo"`, so it cannot tell `add` from `install` without B1. Sources: https://doc.rust-lang.org/cargo/commands/cargo-install.html and https://doc.rust-lang.org/cargo/commands/cargo-add.html |

**Ordering dependency.** Wave D lands after wave B (B1). Before B1, `cargo add serde@1.2.3` carries `pinned=True` (probe), and N2a would wrongly treat it as resolved. Test T-RES-6 pins the post-B1 behaviour. If wave D must merge first, the crates rule falls back to "never resolved", and T-RES-6 is updated in B1.

---

## 1. CLI

```
actualis [scan options] --ioc FILE [--ioc FILE ...] [--fail-on LEVEL] [--json]
```

- **`--ioc FILE`**: `action="append"`, `metavar="FILE"`. It is declared in `build_parser` next to `--network-trust`.
  - Help text: `"known-bad packages and hosts to match the network inventory against: the actualis-ioc line format or OSV JSON/JSONL. Repeatable. Never read unless named."`
- **Completion.** `_VALUE_HINT["--ioc"] = "file"`.
- **No discovery.** There is no default path, no environment variable and no cwd file. `.actualis-ioc` has no meaning.
- **Mode rules,** checked in `main` next to the other `ap.error` combination checks:
  - with `--card`: `ap.error("--ioc does not apply to --card; the card never shows downloads.")`;
  - with `--watch` or `--mcp`: `ap.error("--ioc is not supported with --watch or --mcp yet.")`;
  - with `--explain`, `--agents`, `--suppressions`, `--suppress`, `--replay` and `--completions`: the file is **not loaded**. Those modes return before the load point, the same rule the trust file follows.
- **Load point.** In `main`, immediately after `load_network_trust_sources(...)`, inside a `try` that also catches the IOC errors:
  ```python
  try:
      network_trust, trust_sources = load_network_trust_sources(args.network_trust)
      ioc = load_ioc(args.ioc) if args.ioc else None
  except (ValueError, OSError) as exc:
      ap.error(str(exc))
  ```
  An `OSError` message is rewritten by `load_ioc` to `--ioc PATH: cannot read: <strerror>` before it propagates as a `ValueError`.
- **Apply point.** Immediately after `apply_network_policy(fleet, ...)` comes `apply_ioc(fleet, ioc)`, always, `ioc` possibly `None`. It precedes `--diff`, `--why`, `--json` and the renders, so every output sees the same state.

### Exit codes

The existing table in `actualis.py` (the "Exit codes" comment block) is unchanged.

| Code | When |
|---|---|
| 0 | No `--fail-on`, or nothing at or above it |
| 1 | `EXIT_CANNOT_RUN`, unchanged: no transcripts, or a bad `--root`. An IOC problem never produces 1 |
| 2 | Any IOC load error: unreadable or missing file, over a size cap, bad UTF-8, a grammar error, an unknown ecosystem word in the line format, a bad attribute, a JSON syntax error, over 1,000,000 entries, **zero checkable entries across all files**, or a forbidden mode combination |
| 3 | `EXIT_FINDINGS`: `--fail-on` tripped, IOC reasons included (§7) |

Error message format: `--ioc PATH line N: <what> — <how to write it>`. For example: `--ioc iocs.txt line 12: "npm:foo@^1.2" — ^ and ~ ranges are not accepted; write >=1.2.0,<2.0.0`.
`PATH` is the path as given, passed through `clean()`, and `N` is 1-based. A JSON error inside a whole-document OSV file has no line, so the message says `byte offset B` instead.

---

## 2. Input detection and limits

`load_ioc(paths: list[str]) -> IocSet` reads each file in order. The source index is the position in `--ioc`.

1. Open the file in binary mode. Hash it with `hashlib.sha256` **while reading**: the hash covers every byte, BOM included.
2. **Size.** If `os.stat().st_size` exceeds 1 GiB, exit 2: "over 1 GiB".
3. **Detection.** Skip a UTF-8 BOM and ASCII whitespace, then look at the first byte:
   - `[`: an **OSV JSON array**. It must be ≤ 64 MiB. A larger file exits 2 with "convert to JSONL: `jq -c '.[]' f > f.jsonl`".
   - `{`: **OSV**.
     - At most 64 MiB: try a whole-document parse (`json.loads`) first. If that raises `JSONDecodeError` with message "Extra data", reparse the file as JSONL.
     - Over 64 MiB: always JSONL, streamed line by line.
   - Anything else, including an empty file: the **line format**. It must be ≤ 64 MiB.
4. **Decoding.** The line format and JSONL decode as `utf-8-sig`, strictly. A `UnicodeDecodeError` exits 2 with the line number.
5. **Caps.**
   - A line-format or JSONL line longer than 1 MiB exits 2.
   - At most **1,000,000 entries in total**, across all files and both formats, counting one entry per `IocEntry` built. One more exits 2: "over 1,000,000 entries; split by ecosystem".
   - Version strings are at most 128 characters, names at most 214 (npm's limit), and labels and ids as their patterns state.
6. **No checkable entry.** After all files load, if `sum(entries.package + entries.host) == 0`, exit 2: `--ioc: none of the N entries can be checked (not checkable: rubygems 31, maven 6)`.

---

## 3. The `actualis-ioc` line format, version 1 (normative)

### 3.1 Grammar (ABNF, RFC 5234 notation)

```
file        = *( line EOL ) [ line ]
EOL         = LF / CR LF
line        = *WS [ entry *( 1*WS attr ) *WS ] [ comment ]
WS          = SP / HTAB
comment     = "#" *( %x09 / %x20-7E / %x80-10FFFF )   ; '#' only at line start or after WS
entry       = pkg-entry / host-entry
pkg-entry   = eco ":" pkg-body                       ; split per §3.3
host-entry  = "host:" [ "=" ] host-spec
host-spec   = hostname [ "/" path ]                  ; exactly _TRUST_ENTRY after lowercasing
eco         = 1*( ALPHA / DIGIT / "." / "-" )        ; case-insensitive; §3.2
attr        = attr-key "=" attr-value
attr-key    = "id" / "label" / "from" / "until"      ; case-insensitive
attr-value  = id-value / label-value / date          ; per key, §3.6
spec        = "*" / clause *( "||" clause )
clause      = comparator *( "," comparator )
comparator  = [ op ] version
op          = "===" / "==" / ">=" / "<=" / "=" / ">" / "<"    ; longest match first
version     = 1*128( ALPHA / DIGIT / "." / "-" / "+" / "_" / "!" / ":" )
date        = 4DIGIT "-" 2DIGIT "-" 2DIGIT           ; a real calendar date (date.fromisoformat)
```

**Lexing.**
- Split the line on runs of WS. The first token is the entry. Every later token is an attribute, or the start of a comment if it begins with `#`.
- An entry token never contains WS, so a converter strips the spaces from ranges (`">= 1.0, < 2.0"` becomes `">=1.0,<2.0"`).
- A blank or comment-only line is ignored.
- No valid entry form can contain `#`. A `#` *inside* a token, as in `npm:a#b`, is therefore a grammar error (exit 2), not a comment.

### 3.2 Ecosystem words

Comparison is case-insensitive.

| Written as | Normalised | Matched? |
|---|---|---|
| `npm` | `npm` | yes |
| `pypi`, `pip` | `pypi` | yes |
| `crates`, `crates.io`, `cargo`, `rust` | `crates` | yes |
| `go`, `golang` | `go` | yes |
| `oci`, `docker`, `container` | `oci` | yes |
| `brew`, `homebrew` | `brew` | yes |
| `rubygems`, `nuget`, `maven`, `packagist`, `composer`, `pub`, `hex`, `erlang`, `swift`, `swifturl`, `actions`, `github-actions`, `vscode`, `open-vsx`, `git` | the word itself, lowercased | **not checkable**: counted in `sources[].not_checkable.<word>`, never an error |
| anything else | — | **exit 2**: `unknown ecosystem "npn"; known: npm pypi crates go oci brew (and not-checkable: …)` |

A not-checkable entry is still syntax-checked as far as `eco ":" non-empty-body` goes, and its attributes are validated.

### 3.3 Name/version split, normalisation and validity

`_ioc_norm_name(eco, name) -> str` is the **single** normaliser, applied to IOC entries and items alike.

| eco | Split `pkg-body` into name and spec at | Normalisation | Valid name (after normalising; else exit 2) |
|---|---|---|---|
| npm | the first `@` at index ≥ 1 | **none**: npm names compare exactly, case-sensitively | `^(?:@[a-z0-9~][a-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$`, at most 214 characters. Uppercase is allowed, because legacy names such as `JSONStream` exist |
| pypi | the first `@` | PEP 503: `re.sub(r"[-_.]+", "-", n).lower()` | `^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$` |
| crates | the first `@` | `n.lower().replace("_", "-")` | `^[a-z0-9][a-z0-9-]{0,63}$` |
| go | the first `@` | none (module paths are case-sensitive) | `^[A-Za-z0-9.~_+-]+(?:/[A-Za-z0-9.~_+-]+)*$`. The first element contains a `.`, and there is no `.` or `..` segment |
| oci | the **last** `@` (a registry port uses `:`, never `@`) | `_oci_name()` (§3.4) | `^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$` |
| brew | **never split.** Everything after `brew:` is the name, because `python@3.12` and `openssl@3` are formula names | lowercase | `^[a-z0-9][a-z0-9@+._-]*(?:/[a-z0-9][a-z0-9@+._-]*){0,2}$`. That allows tap `user/tap/name` |

An empty spec after the separator (`npm:foo@`) exits 2.

### 3.4 `_oci_name(name)`

This function is shared with B1. If B1 has already added it, reuse it; otherwise N2a adds it and B1 reuses it.

1. Lowercase the name.
2. Strip one leading `docker.io/`, `index.docker.io/` or `registry-1.docker.io/`.
3. If the result has no `/`, prepend nothing.
4. Strip one leading `library/`.

So `docker.io/library/nginx`, `library/nginx` and `nginx` all become `nginx`. `ghcr.io/x/y` is unchanged.

### 3.5 Spec semantics per ecosystem

Specs are parsed **once at load**, by `_ioc_parse_spec(eco, text) -> Spec`.
- `Spec` is `None` (any version), or a tuple of clauses.
- A clause is a tuple of `(op, key, raw)`, where `key` is the precomputed sort key and `raw` the original string.
- `==` is a synonym of `=`.

**Any version.** An omitted spec, `*`, `>=0` and `>=0.0.0` all mean any version, giving `Spec = None`.

**Rejected everywhere** (exit 2). Each message names the fix.

| Input | Message hint |
|---|---|
| `^…` or `~…` | `^ and ~ ranges are not accepted; write >=X,<Y` |
| `x`, `X` or `*` inside a version (`1.x`, `1.*`) | `wildcards are not accepted; write >=1.0.0,<2.0.0` |
| A clause with two equality comparators (`=1.2.3,=1.2.4`, `1.2.3,1.2.4`) | `a comma means AND; use || between alternative versions` |
| `latest`, `next` or any non-version word | `an IOC names versions; latest moves` |
| A comparator version that does not parse for the ecosystem (below) | `"1.2" is not a full version for npm; write 1.2.0` |
| An empty clause (`a||`, `||a`, `a,,b`) | — |

**npm, crates and go: SemVer 2.0.0.**
- Parse with `^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`.
- The leading `v` is stripped, and build metadata, including Go's `+incompatible`, is ignored.
- `_ioc_semver_key(v)` gives `(major, minor, patch, prerelease_key)`:
  - `prerelease_key` is `(1,)` for a release.
  - For a pre-release it is `(0, ids)`, where each id is `(0, int)` if numeric and `(1, str)` otherwise.
  - That realises SemVer §11: a pre-release sorts below its release; numeric ids compare numerically and below alphanumeric ones, which compare in ASCII order; with an equal prefix, more fields sort higher.
- Go pseudo-versions (`v0.0.0-20210101000000-abcdefabcdef`, `v1.2.4-0.2021…`) are ordinary pre-releases under this rule.

**pypi: PEP 440.**
- Parse with the PEP 440 Appendix B regex (`VERSION_PATTERN` from the spec), compiled with `re.VERBOSE | re.IGNORECASE` and anchored. Input is capped at 128 characters.
- `_ioc_pep440_key(v)` gives `(epoch, release_padded, pre, post, dev)`:
  - `release_padded` drops trailing zeros, so `1.0 == 1.0.0`.
  - `pre` is `(letter_rank, n)`, with `a`/`alpha` as 0, `b`/`beta` as 1, and `rc`/`c`/`pre`/`preview` as 2.
  - The sentinels follow the `packaging` ordering: a dev release with no pre or post sorts before every pre-release, and a missing post sorts below `post0`.
  - A local `+…` part is ignored for ordering.
- `===X` is exact, case-sensitive string equality on the raw item version. It is decidable even when neither side parses.
- An unparseable **entry** version (other than after `===`) exits 2.

**oci.**
- No ordering. The spec must be `*` or `=V` alternatives joined by `||`.
- V is a digest (`sha256:` plus 64 lowercase hex characters) or a tag `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`, other than `latest`.
- Any other operator exits 2.

**brew.** There is no spec, by construction (§3.3).

### 3.6 Attributes

All attributes are optional; an unknown key or a repeated key exits 2.

| Key | Value pattern | Stored as | Effect in N2a |
|---|---|---|---|
| `id` | `^[A-Za-z0-9._:-]{1,64}$` | `ref` | Shown as the advisory reference |
| `label` | `^[A-Za-z0-9._-]{1,48}$` | `label` | Shown |
| `from` | `date` | `frm: datetime.date` | **None.** Shown; see D3 |
| `until` | `date`, and ≥ `from` when both are present | `until: datetime.date` | **None** |

No attribute value can hold a control character, so a value never needs `clean()`. It is applied on print anyway, as defence in depth.

### 3.7 Host entries

- **Parsing.**
  - Take the text after `host:`.
  - An optional leading `=` sets `exact_host`.
  - The rest is lowercased, stripped of one trailing `.`, and must fully match `_TRUST_ENTRY`. A scheme, port, wildcard, userinfo or query exits 2.
  - IPv4 literals pass `_TRUST_ENTRY`. IPv6 (`[`) fails it and exits 2.
- **Matching.**
  - `_ioc_host_match(entry, item)`: the item must have `host` set and `host_inferred` False.
  - When `exact_host` is set, the hosts must be equal. Otherwise the item host equals the entry host or ends with `"." + host`.
  - If the entry has a path, `_net_item_path(item)` must not be `None` and must equal the path or start with `path + "/"`. That is exactly the logic of `network_trusted`; factor it out as `_host_path_match(host, path, item, exact=False)` and have `network_trusted` call it too.
- **Warning, not an error.** A host entry with no path that names `github.com`, `gitlab.com`, `bitbucket.org`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `crates.io`, `proxy.golang.org`, `registry-1.docker.io` or `ghcr.io` prints this to stderr once per entry and still loads:
  `actualis: --ioc PATH line N: host:github.com matches every download from github.com; add a path`
- **Go items.** A Go item's host is the module path's first element (`_net_go`), so a host entry matches a Go module's **origin**, not the proxy actually contacted. `docs/ioc.md` says so.

### 3.8 Example (also used as a test fixture)

```
# Shai-Hulud wave 1, converted from the Wiz CSV, 2025-09-17
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

---

## 4. OSV input

Sources: https://ossf.github.io/osv-schema/ (read 2026-10-08), and the ossf record MAL-2025-6022 (read in pass 1).

### 4.1 Shapes

| Shape | When | Errors |
|---|---|---|
| A single record (object) | `{`, ≤ 64 MiB, and parses whole | A JSON syntax error exits 2 with the byte offset |
| An array of records | `[`, ≤ 64 MiB | As above |
| JSONL | `{` and over 64 MiB, or whole-document parsing failed with "Extra data" | Each non-blank line is `json.loads`ed on its own. A syntax error exits 2 with the line number. Blank lines are skipped |

### 4.2 Per record

A record is any JSON value at the top level, in the array, or on a JSONL line.

1. **Not an object.** Skip it and add to `skipped`, recording `first_skipped_line` if it is the first.
2. **Withdrawn.** If `withdrawn` is present and non-null, skip the record and add to `withdrawn`. The schema says that if the field is missing, the entry is not withdrawn.
3. **`id`.** `ref = id` if it is a string matching the `id` pattern of §3.6; otherwise `ref = None`. The record still loads.
4. **`affected`.** If it is not a non-empty list, skip the record and add to `skipped`.
5. **For each element of `affected[]`:**
   - **Shape.** If `package` is not an object, or `package.name` or `package.ecosystem` is not a non-empty string, add to `skipped` and continue.
   - **Ecosystem.** Map the **exact** OSV string: `npm` to npm, `PyPI` to pypi, `crates.io` to crates, `Go` to go. Every other value is not checkable: add to `not_checkable[key]`, where `key = re.sub(r"[^a-z0-9.-]", "-", eco.lower().split(":", 1)[0])[:32]`, then continue. OSV mode **never** exits 2 on an ecosystem, because OSV adds ecosystems over time.
   - **Name.** `_ioc_norm_name(eco, package.name)` must pass §3.3. Otherwise add to `skipped` and continue. `purl` is ignored.
   - **Spec.** It is the OR of the clauses below.
     - Each string in `versions[]` becomes one `=v` clause. If v parses for the ecosystem, it compares by key; otherwise it compares by **exact string** after stripping a leading `v`. OSV's `versions` list is authoritative strings, so it is not rejected.
     - Each element of `ranges[]` with `type` `SEMVER` or `ECOSYSTEM` is translated as in §4.3.
     - `type: GIT` adds 1 to `ranges_git` and contributes nothing. The schema says GIT ranges do not remove the need for a `versions` list, so `versions[]` still loads.
     - An unknown `type` adds to `skipped_ranges`.
   - **Neither `versions` nor a usable range.** If both are empty or absent, the spec is **any version**. This is the conservative direction, and the docs say so.
   - **Result.** Emit one `IocEntry`, with `line` set to the JSONL line or `None`.
6. **Ignored fields.** `aliases`, `summary`, `details`, `references`, `severity`, `database_specific`, `ecosystem_specific`, `published`, `modified`, `related`, `upstream` and `schema_version`. **`references[]` never become host entries.**

### 4.3 Range translation (`_ioc_osv_range(eco, events) -> list[clause] | UNDECIDABLE`)

- **Sorting.**
  - Collect the events, each a one-key object: `introduced`, `fixed`, `last_affected` or `limit`. Anything else adds to `skipped_ranges` and drops that range.
  - Sort them by version in the ecosystem's order. `introduced: "0"` sorts first.
  - If any event version other than `"0"` does not parse (SemVer for SEMVER ranges and for npm, crates and go ECOSYSTEM ranges; PEP 440 for PyPI ECOSYSTEM ranges), the range is **`UNDECIDABLE`**. A name match against it then gives `unresolved`, with reason `undecidable`, never `match` and never `clean`.
- **The walk.**
  - `introduced: X` opens an interval at `>=X`, or with no lower bound when X is `"0"`.
  - `fixed: Y` closes it at `<Y`.
  - `last_affected: Z` closes it at `<=Z`. The schema forbids mixing `fixed` and `last_affected` in one range. If both appear anyway, keep both and let the earliest close win.
  - `introduced` with no close is unbounded above.
  - `limit` is ignored, and `ranges_with_limit` is incremented. The interval stays unbounded above, which over-matches; that is the conservative direction.
- **Result.** Each interval becomes one clause: `(>=X,<Y)`, `(>=X,<=Z)`, `(>=X)`, or the any-version clause. An interval that opens with `introduced: "0"` and never closes makes the **whole entry** any-version (`Spec = None`). That is ossf's dominant shape.

### 4.4 Counters per source

| Counter | Meaning |
|---|---|
| `entries.package` | `IocEntry`s with a checkable ecosystem |
| `entries.host` | Host entries (always 0 for OSV) |
| `not_checkable.<eco>` | Entries in other ecosystems, keyed by name |
| `skipped`, `first_skipped_line` | Malformed records or `affected` elements |
| `withdrawn` | Records skipped because they were withdrawn |
| `ranges_git`, `ranges_with_limit` | As above |
| `skipped_ranges` | Ranges with an unknown type or event |

The text report prints `skipped N malformed (first at line L)` when `skipped > 0`. It is never silent, and never fatal.

---

## 5. Data model

All of it is new, in one block after `load_network_trust` in `actualis.py`. There are no new imports: `json`, `hashlib`, `re`, `os`, `datetime.date` and `typing.NamedTuple` are already imported at the top of `actualis.py` (`Rate` and `Text` are NamedTuples).

```python
class IocEntry(NamedTuple):
    kind: str                 # "package" | "host"
    eco: str | None           # npm pypi crates go oci brew; None for host
    name: str | None          # normalised (§3.3)
    spec: tuple | None        # None = any version; tuple of clauses; or UNDECIDABLE sentinel
    spec_text: str | None     # canonical text for output: "=4.1.1||=4.1.2", ">=1.0.0,<2.0.0", None
    host: str | None
    path: str                 # "" or "/a/b"
    exact_host: bool
    ref: str | None
    label: str | None
    frm: date | None
    until: date | None
    source: int               # index into IocSet.sources
    line: int | None

class IocSet:
    packages: dict[tuple[str, str], list[IocEntry]]   # (eco, normname) -> entries
    host_suffix: dict[str, list[IocEntry]]            # host -> non-exact host entries
    host_exact: dict[str, list[IocEntry]]             # host -> exact host entries
    sources: list[dict]                               # §8 sources[] shape, filled while loading
    has_window: bool                                  # any entry carries from/until (for the D3 note)
```

- **Host lookup.** For an item host `a.b.c.d`, look up `host_exact[a.b.c.d]` and `host_suffix[s]` for each suffix s in `a.b.c.d`, `b.c.d`, `c.d` and `d`. Stop at 127 labels. Then apply the path check to the few candidates.
- **Fleet state.** In `Fleet.__init__`:
  - `self.ioc: IocSet | None = None`;
  - `self.ioc_rows: list[dict] = []`, one per matched item (§6.4);
  - `self.ioc_totals: dict`, initialised to the zeroed shape of §8 `totals`.

### Functions and hook points

| Function | Purpose | Called from |
|---|---|---|
| `load_ioc(paths) -> IocSet` | §2 to §4. It raises `ValueError` with the §1 message format | `main`, at the load point |
| `parse_ioc_lines(text, src) -> None` | The line format, filling `IocSet` | `load_ioc` |
| `parse_ioc_osv(records_iter, src) -> None` | OSV records, from a whole document or a JSONL stream | `load_ioc` |
| `_ioc_norm_name(eco, name) -> str` | §3.3 | parsers and `match_ioc` |
| `_oci_name(name) -> str` | §3.4. Shared with B1 | `_ioc_norm_name` |
| `_ioc_parse_spec(eco, text) -> Spec` | §3.5 | the line parser |
| `_ioc_osv_range(eco, type, events)` | §4.3 | the OSV parser |
| `_ioc_semver_key(v) -> tuple \| None` and `_ioc_pep440_key(v) -> tuple \| None` | Version keys; `None` when unparseable | specs and matching |
| `_ioc_resolved(item) -> list[tuple[str, str]]` | The (normname, version) pairs to compare, version `""` when unresolved. Usually one pair; two for an npm alias (D5) | `match_ioc` |
| `_ioc_spec_contains(eco, spec, version) -> True \| False \| None` | `None` means undecidable | `match_ioc` |
| `_host_path_match(host, path, item, exact)` | Factored out of `network_trusted` | `network_trusted` and `match_ioc` |
| `match_ioc(item, ioc) -> (verdict, reason, entries) \| None` | §6 | `apply_ioc` |
| `apply_ioc(fleet, ioc) -> None` | Sets `fleet.ioc`, fills `ioc_rows` and `ioc_totals`, sets `item["ioc"]` on every item, and appends flags | `main`, right after `apply_network_policy` |
| `ioc_json(fleet, raw) -> dict` | `network.ioc` | `network_json` |
| `render_ioc(fleet, c, raw) -> None` | The text block | `render_network` |

`NETWORK_ITEM_KEYS` gains `"ioc"`. `_add_network` initialises `item["ioc"] = None`, so the key exists even without `--ioc`.

---

## 6. Matching

### 6.1 Which items

`apply_ioc` iterates **`fleet.network`**, not `fleet.network_items`, because refused items are needed. An item with `_refused` set is a refused attempt.

### 6.2 Item resolution (`_ioc_resolved`)

| Ecosystem | Resolved version when | Otherwise |
|---|---|---|
| npm | After stripping one leading `=` or `v`, the version parses as full SemVer. **Alias:** a version `npm:<name>@<ver>` yields a second pair, `(<name>, <ver>)`, resolved by the same rule | Unresolved: `latest`, `next`, `4`, `4.1`, `^4.1.0`, a tag, or none |
| pypi | The item has a `version`. The branch keeps one only for `==`/`===`, and it must parse as PEP 440 | Unresolved. A `===` comparator in the entry still decides by string equality |
| crates | `item["pinned"]` is True (B1 semantics) **and** the version parses as full SemVer (a leading `=` stripped) | Unresolved, including `cargo add serde@1.2` and `cargo add serde@1.2.3` |
| go | The version starts with `v` and parses as SemVer (pseudo-versions included) | Unresolved: `latest`, `upgrade`, `patch`, `none`, `master`, a hash, `v1.2`, `1.2.3` with no `v` (Go treats it as a query or a branch), or none |
| oci | A digest (`sha256:` plus 64 hex), or a tag other than `latest` | Unresolved: no tag, or `latest` |
| brew | Never; no version is recorded | — |

Sources for the Go and cargo rules: https://go.dev/ref/mod (`go get` version queries: a prefix `v0.3`, `latest`, `upgrade`, `patch`, `none`), and the cargo pages in D9.

The package key is `(item["ecosystem"], _ioc_norm_name(eco, item["package"]))`. For oci, the item's `package` goes through `_oci_name`, so `docker pull docker.io/library/nginx:1.25` and `docker run nginx` share the key `nginx`.

### 6.3 Verdicts

These are evaluated per (entry, resolved pair), and per host entry. Rank: `match` (2) > `unresolved` (1) > `clean` (0).

| Condition | Outcome | `reason` |
|---|---|---|
| A package entry with `spec is None` and a name match | `match` | `any-version` |
| A package entry with a spec; the item version is resolved; `_ioc_spec_contains` gives True | `match` | `version-in-spec` |
| As above, giving False | `clean`: counted in `clean_name_matches` only | — |
| As above, giving None (undecidable: an UNDECIDABLE range, a PEP 440 parse failure, or a digest compared with a tag) | `unresolved` | `undecidable` |
| A package entry with a spec, and the item version unresolved | `unresolved` | `version-unresolved` |
| A host entry that matches (§3.7) | `match` | `host` |
| **Downgrade.** A `match` from a package entry, where the item ecosystem is npm, pypi or crates, `host_inferred` is False, and the host is not `NETWORK_REGISTRY[eco]` | Becomes `unresolved` | `private-registry`. Evidence: `installed from <host>; the entry describes the public registry` |

**Combining.**
- The item's verdict is the highest rank over all entries. Its `entries` are every entry at that rank, ordered by (source, line).
- `item["ioc"]` is set to `"match"` or `"unresolved"` (or left `None`) on **non-refused** items only.
- **Refused items** keep their computed verdict in `ioc_rows`, with `refused: true`. They **never** produce a flag, never count in `match`/`unresolved`, never fail a gate, and add to `totals.refused`.
- **Failed items** (`failed is True`) keep their verdict; their evidence adds `(call failed)`. Codex and Copilot items have `failed: None` (unknown) and are treated as ran.
- **Trust.** The trust list **never** exempts a match. `item["trusted"]` is ignored by `apply_ioc`.

### 6.4 Checkability (the coverage line)

For each item in `fleet.network_items` (non-refused):
- **package-checkable** means `kind == "install"`, `ecosystem` is in the six, and `package` is set;
- **host-checkable** means `host` is set and `host_inferred` is False;
- **`items_checked`** counts items that are either.

The rest go to `items_not_checkable`:

| Key | Items |
|---|---|
| `lockfile` | `kind == "install"` and `package` is None (`_net_lockfile`) |
| `no_host` | No host (`dynamic`, or a remote name) |
| `other` | Anything else |

Refused items are excluded from coverage, to match what `network_items` counts.

### 6.5 Flags

There is one flag per group, where a group is (category, flag key). Groups are formed over **non-refused** matched rows only.

| Verdict | Severity | `categories` | Flag key (the `flag_id` program argument) |
|---|---|---|---|
| `match` | `high` | `["network-ioc"]` | Package: `f"{eco}:{normname}@{resolved_version or '?'}"`. Host: `f"host:{'=' if exact else ''}{entry.host}{entry.path}"`, the first matching host entry |
| `unresolved` | `med` | `["network-ioc-unresolved"]` | The same scheme |

- **Id.** `flag_id(severity, categories, key)` is the existing 8-hex id, so `--suppress` and `.actualis-suppressions` accept it unchanged.
- **Flag dict.** It uses exactly the shape `apply_network_policy` uses: `id`, `severity`, `categories`, `program` (the flag key), `project` and `when` (from the latest item, by `(ts, project)`), `evidence`, `had_secret` (False), `suppressed` and `suppressed_reason`.
- **Evidence.** It is built only from cleaned, redacted fields and capped at 240 characters:
  `f"{n} install(s) of {key} via {program} ({approval}){' — ran it (' + program + ')' if any exec else ''}; {ref or label or 'listed'}{'; ' + reason_text if reason in ('private-registry', 'undecidable') else ''}"`
- **Suppression.** `suppressed = fid in fleet.suppressions`. If it is set, increment `fleet.suppressed_flags` and `ioc_totals["suppressed"]`. A suppressed match stays in `ioc_rows` (`suppressed: true`) and in `bash.flags`.
- **Placement.** These flags go into `fleet.flags` beside `network-unasked`, so they appear in `bash.flags[]` in `--json`, in the shell-audit list, and in `--diff`'s flags family through `_flag_kinds`. That is intended.

---

## 7. `--fail-on` and suppression

`failing_findings` gains two reasons. Both are **split out of** the generic flag counts, exactly as `network-unasked` is today. The category compare becomes membership (`"network-ioc" in f["categories"]`), not list equality.

| Level | Counted |
|---|---|
| `critical` | Nothing from IOC. Flags are `high` or `med`; there is no critical flag severity (`SEVERITY_ORDER`) |
| `high` | Unsuppressed `network-ioc` flags give the reason `N known-bad download group(s) (IOC)`. They are **removed** from `N high-severity shell command(s) flagged` |
| `any` | The above, plus unsuppressed `network-ioc-unresolved` flags, giving `N unresolved IOC match group(s)`, removed from the medium count |

- **Never counted:** refused rows, suppressed flags and `clean` name matches.
- **Ordering.** The IOC reasons come right after the credential reasons, so a known-bad install is the first thing a failing pipeline prints.
- **Action default.** The Action's `fail-on` defaults to `critical`, so by default an IOC match does **not** fail the job. When `ioc` is set and `fail-on` is `critical`, the Action prints `::warning::IOC matches are high severity; set fail-on: high to gate on them`. The default is not changed silently.
- **Suppression rules** (#29 and #36): suppressible, still counted, and printed as `N suppressed` in the IOC line. Rationale: private packages that share a name with a public squat are a real false-positive class, and an unsuppressible high gets `--ioc` deleted from CI. `audit-config` stays the only unsuppressible flag.
- **The `flag_id` stability rule.** It goes in `docs/findings.md`: "A finding's id hashes its severity and category. A change in severity is a new category, never an edit, or every existing suppression silently stops matching." N2b's window promotion uses `network-ioc-window` for this reason.

---

## 8. Output

### 8.1 `--json` (`schema_version` stays 1; additive only)

`network_json` returns `"ioc": ioc_json(fleet, raw)` as the last key of `network`.

Without `--ioc` the object is:
```json
{"enabled": false, "sources": [], "totals": {"match": 0, "unresolved": 0, "refused": 0, "suppressed": 0,
 "clean_name_matches": 0, "items_checked": 0,
 "items_not_checkable": {"lockfile": 0, "no_host": 0, "other": 0}},
 "matches": [], "matches_truncated": false}
```

With it, a populated example:
```json
{"enabled": true,
 "sources": [{"path": "/abs/mal-npm.jsonl", "sha256": "3f2a…", "format": "osv-jsonl",
              "entries": {"package": 14202, "host": 0}, "not_checkable": {"rubygems": 31},
              "skipped": 2, "first_skipped_line": 811, "withdrawn": 5,
              "ranges_git": 0, "ranges_with_limit": 0, "skipped_ranges": 0,
              "mtime_in_window": false}],
 "totals": {...},
 "matches": [{"verdict": "match", "reason": "version-in-spec", "refused": false,
              "suppressed": false, "flag_id": "1a2b3c4d",
              "refs": ["MAL-2025-7000"], "labels": ["shai-hulud"],
              "entry": {"kind": "package", "ecosystem": "npm", "name": "@ctrl/tinycolor",
                        "spec": "=4.1.1||=4.1.2", "host": null, "path": null, "exact_host": false,
                        "ref": "MAL-2025-7000", "label": "shai-hulud",
                        "from": "2025-09-14", "until": "2025-09-17", "source": 0, "line": 17},
              "item": { <the network_json public() view of the item: NETWORK_ITEM_KEYS, redacted unless raw> }}],
 "matches_truncated": false}
```

**Semantics.**
- `path` is the absolute resolved path, as the trust file's is (`load_network_trust_sources` uses `str(path.resolve())`).
- `mtime_in_window` is True iff `window.from <= mtime <= window.to`, using the same values `to_json` emits for `window`. In CI the file is fetched after the agent step, so it falls after `window.to` and reads False. That is intended: the flag means "this file changed while the agent was working".
- `matches` holds one row per matched item, refused included, and is capped at **2,000** (`NETWORK_ITEMS_CAP`). `matches_truncated` says whether the cap was hit.
  - **Order** (total, so the bytes are deterministic): `refused` ascending, verdict rank descending, `ts` descending, then the `network_json` item tuple descending, then `(entry.source, entry.line)`.
- `flag_id` is null for refused rows.
- `refs` and `labels` are the sorted distinct values over the row's entries, capped at 20 each.
- `entry` is the first entry by `(source, line)` at the winning rank.
- `network.items[].ioc` is `"match"`, `"unresolved"` or `null`. It is unaffected by suppression, which lives on the flag.

**`JSON_SCHEMA` additions.** Every one of these is emitted by the populated fixture.

```
"network.items[].ioc": "str|null",
"network.ioc.enabled": "bool",
"network.ioc.sources": "array",
"network.ioc.sources[].path": "str",
"network.ioc.sources[].sha256": "str",
"network.ioc.sources[].format": "str",
"network.ioc.sources[].entries.package": "int",
"network.ioc.sources[].entries.host": "int",
"network.ioc.sources[].not_checkable.*": "int",
"network.ioc.sources[].skipped": "int",
"network.ioc.sources[].first_skipped_line": "int|null",
"network.ioc.sources[].withdrawn": "int",
"network.ioc.sources[].ranges_git": "int",
"network.ioc.sources[].ranges_with_limit": "int",
"network.ioc.sources[].skipped_ranges": "int",
"network.ioc.sources[].mtime_in_window": "bool",
"network.ioc.totals.match": "int",
"network.ioc.totals.unresolved": "int",
"network.ioc.totals.refused": "int",
"network.ioc.totals.suppressed": "int",
"network.ioc.totals.clean_name_matches": "int",
"network.ioc.totals.items_checked": "int",
"network.ioc.totals.items_not_checkable.lockfile": "int",
"network.ioc.totals.items_not_checkable.no_host": "int",
"network.ioc.totals.items_not_checkable.other": "int",
"network.ioc.matches": "array",
"network.ioc.matches[].verdict": "str",
"network.ioc.matches[].reason": "str",
"network.ioc.matches[].refused": "bool",
"network.ioc.matches[].suppressed": "bool",
"network.ioc.matches[].flag_id": "str|null",
"network.ioc.matches[].refs": "array",
"network.ioc.matches[].refs[]": "str",
"network.ioc.matches[].labels": "array",
"network.ioc.matches[].labels[]": "str",
"network.ioc.matches[].entry.kind": "str",
"network.ioc.matches[].entry.ecosystem": "str|null",
"network.ioc.matches[].entry.name": "str|null",
"network.ioc.matches[].entry.spec": "str|null",
"network.ioc.matches[].entry.host": "str|null",
"network.ioc.matches[].entry.path": "str|null",
"network.ioc.matches[].entry.exact_host": "bool",
"network.ioc.matches[].entry.ref": "str|null",
"network.ioc.matches[].entry.label": "str|null",
"network.ioc.matches[].entry.from": "str|null",
"network.ioc.matches[].entry.until": "str|null",
"network.ioc.matches[].entry.source": "int",
"network.ioc.matches[].entry.line": "int|null",
"network.ioc.matches[].item.<k>": <as network.items[].<k>, for every k in NETWORK_ITEM_KEYS>,
"network.ioc.matches_truncated": "bool",
```

- **Test fixture.** `TestJSONSchemaFreeze._populated()` gains an `IocSet` loaded from an in-memory line file. It must produce at least one `match` (package), one host `match`, one `unresolved` and one refused row, and must carry `from`/`until`, so that every `str|null` path is exercised as a string at least once. Pass the set to `apply_ioc(f, ioc)` after its `apply_network_policy` call.
- **Enum values** go in `docs/json.md`:
  - `verdict`: `match` or `unresolved`;
  - `reason`: `any-version`, `version-in-spec`, `host`, `version-unresolved`, `undecidable` or `private-registry`;
  - `format`: `lines`, `osv-json` or `osv-jsonl`.
- **`report_sha256`** covers `network.ioc`, so two runs with different IOC files differ. That is correct and documented.
- **`--diff`.** A 0.2.2 baseline (no `network`) and a pre-N2a branch baseline (no `network.ioc`) must both diff without error. IOC flags show in the flags family.

### 8.2 Text (`render_ioc`, called by `render_network`)

**Placement.**
- After the `trust:` line and before `INSTALLED`.
- **Also when there are no downloads.** `render_network` currently returns right after printing `no downloads seen`. With `--ioc`, the IOC block prints before that return.
- Nothing prints without `--ioc`.

**Format.** These are the real column widths: the label in 11 columns, as `INSTALLED` uses.

```
  IOC        2 match · 1 unresolved · 1 refused · 1 suppressed
             mal-npm.jsonl  sha256 3f2a9c1e04b1  osv-jsonl  14,202 package · 0 host
             not checkable: rubygems 31 · skipped 2 malformed (first at line 811) · withdrawn 5
             checked 297 of 412 downloads · not checkable: lockfile 40 · no host 75
  MATCH      npm @ctrl/tinycolor@4.1.1          proj-a      2025-09-15 unasked  MAL-2025-7000
  MATCH      host webhook.site (curl)           proj-a      2025-09-15 unasked  exfil
  UNRESOLVED npm @ctrl/tinycolor (latest)       proj-b      2025-09-15 unknown  version not resolved
  REFUSED    npm eslint-config-prettier@10.1.7  proj-d      2025-07-19 —        never ran
  No match is not "not affected": this covers the transcripts still on this machine in the
  window, and lockfile installs, scripts and postinstall hooks are not visible. See --explain ioc.
```

- **One provenance block per source.** The basename and `sha256[:12]` are always shown. The full path is in `--json`. Add `modified during the window` when `mtime_in_window` is set.
- **The D3 note.** It prints, dim, when `ioc.has_window`: `from/until are shown, not yet applied`.
- **Zero matches.** `IOC        no match in 297 checkable downloads (14,202 entries)`, followed by the provenance block and the caveat.
- **Rows.**
  - Order: the `matches` order with refused rows last, `MATCH` before `UNRESOLVED`.
  - **Never cut by `--top`.** After 50 rows, print `+N more (--json for all)`.
  - Columns are clipped with `clip()`. Every printed field passes through `clean()`, and `url`, `dest` and `source` through `redact()` unless `--no-redact` (they come from `network_json`'s `public()` view).
  - A suppressed row shows `suppressed` in place of the ref.

### 8.3 `--explain ioc`, the README and the docs

- **`EXPLAIN["ioc"]`.** It has the same keys as `EXPLAIN["network"]` (`measures`, `formula`, `assumes`, `verify`).
  - It covers the two verdicts and the reasons, what is not checkable, that the trust list never exempts a match, the D3 note, suppression, and that lockfile installs and transcript retention bound "no match".
  - `verify`: `actualis --ioc f --json | jq '.network.ioc.totals'`.
  - `EXPLAIN["network"]` gains one line pointing to it.
- **`docs/ioc.md`.** The grammar (§3), OSV usage, and the ossf one-liner `find malicious-packages/osv/malicious/npm -name 'MAL-*.json' -exec cat {} + | jq -c . > mal-npm.jsonl`. It also gives the Wiz CSV one-liner, the "malware lists only, not CVE dumps" warning, and the CI recipe below.
  - **No unverified claim.** In particular, it does not claim ossf includes GHSA malware; that is still to verify.
- **The CI recipe.** In a step **after** the agent step, fetch the list into `$RUNNER_TEMP`, verify it with `sha256sum -c` if it is pinned, and pass its path.
- **Also updated:** `docs/json.md` (keys and enums), `docs/findings.md` (the two categories and the `flag_id` rule from §7), the README (a short section, plus the "Limitations" line) and the CHANGELOG.

### 8.4 The Action (`action.yml`)

- **New input `ioc`.** Newline-separated paths (one per line, so a comma in a path is safe). Each non-empty line, stripped, becomes `--ioc LINE` in `net_args`, so **both** the gating run and the `--json` run receive it.
- **New output `ioc-matches`.** The number of unsuppressed match rows: `jq '[.network.ioc.matches[] | select(.verdict=="match" and (.refused|not) and (.suppressed|not))] | length'`. The same `python3 -c` style as `findings` is used, so there is no `jq` dependency.
- **The `::warning::` from §7.**
- **Input description.** "Paths to known-bad lists (actualis-ioc lines or OSV). Fetch them in a step after the agent step, outside the workspace, e.g. $RUNNER_TEMP."

---

## 9. Privacy and safety rules

1. **No network, no new write path, no new import.** `--self-check` is unchanged, and so is its import allowlist.
2. **Explicit path only.** No cwd, home or environment discovery. A test proves that a cwd `.actualis-ioc` is ignored.
3. **The IOC file is untrusted input.** Every regex in the parser is anchored and linear, with bounded repeats and no nested quantifiers over the same characters. No regex is ever built from file content. Host matching is dict lookups plus string compares. JSON is parsed by `json`, with size caps. Labels, refs and names reach output only after their validity pattern **and** `clean()`.
4. **Output redaction.** Matched item fields come from `network_json`'s `public()` view (redacted unless `--no-redact`). Evidence uses only fields that are already cleaned.
5. **`--share` and `--card` do not read `network` and must not read `network.ioc`.** The leak tests (`tests/test_network.py` and `tests/test_card.py`) gain an IOC fixture whose names, labels, refs, hosts and source path are canary strings. They assert that none of them, and no IOC count, appears in `--share` or `--card` output.
6. **Paths.** The source path appears in `--json`, and its basename in the text report. That is the same exposure class as the trust file.
7. **The IOC file is agent-writable** if it sits in a directory the agent could write. N2a's mitigations are provenance (the sha256, plus `mtime_in_window`) and the docs. The tripwire extension waits for W, in N2b. `--explain ioc` states this limit.

---

## 10. Tests (`tests/test_ioc.py`, stdlib `unittest`, fixtures built in code)

**Parser, line format**

- **T-LINE-1**: each §3.8 example line parses to the expected `IocEntry` (table-driven).
- **T-LINE-2**: comments (leading, trailing after WS), blank lines, BOM, CRLF and a final line with no EOL. `npm:a#b` exits 2.
- **T-LINE-3**: ecosystem aliases (`PyPI`, `pip`, `crates.io`, `cargo`, `rust`, `golang`, `docker`, `container`, `homebrew`) normalise. `npn:foo` exits 2. `rubygems:x` and `vscode:x` are counted as not checkable.
- **T-LINE-4**: scoped npm (`@s/n@1.2.3`, `@s/n`), plus `@s/n@` exits 2.
- **T-LINE-5**: `brew:python@3.12` gives the name `python@3.12` with no spec.
- **T-LINE-6**: OCI with a registry port (`localhost:5000/x/y@=v1`), a digest, and `latest` (exit 2).
- **T-LINE-7**: rejections, each with its message hint:
  - `^1.2`, `~1.2`, `1.x` and `1.*`;
  - `1.2.3,1.2.4` and `=1.2.3,=1.2.4`;
  - `latest`, and `1.2` for npm;
  - an empty clause, and whitespace inside the spec (that is, a second token that is not `key=value`);
  - an unknown attribute, a repeated attribute, a bad date, and `until < from`;
  - `host:https://x`, `host:x:8080`, `host:*.x.io` and `host:[::1]`.
- **T-LINE-8**: any-version equivalents (`npm:x`, `@*`, `@>=0`, `@>=0.0.0`) all give `spec is None`.
- **T-LINE-9**: the forge or registry host warning is printed to stderr, and the entry still loads.
- **T-LINE-10**: caps: a 1,000,001-entry input (generated) exits 2; a line over 1 MiB exits 2; a version over 128 characters exits 2.
- **T-LINE-11**: an empty file, and a file of only `rubygems:` entries, each exit 2 with "none of the N entries can be checked".

**OSV**

- **T-OSV-1**: a MAL-2025-6022-shaped record with `versions[]` gives one entry and four `=` clauses.
- **T-OSV-2**: `introduced: "0"` alone gives any version.
- **T-OSV-3**: introduced/fixed gives `>=X,<Y`, and introduced/last_affected gives `>=X,<=Z`. Unsorted events still translate correctly.
- **T-OSV-4**: a `limit` event increments `ranges_with_limit` and is unbounded above.
- **T-OSV-5**: a `GIT` range increments `ranges_git`, and the record's `versions[]` still load.
- **T-OSV-6**: a withdrawn record is skipped and counted.
- **T-OSV-7**: malformed input: a non-object record, a missing name, an unknown event and an unknown range type are each counted, with `first_skipped_line` set and no exit.
- **T-OSV-8**: object, array and JSONL forms give identical `IocSet`s. "Extra data" falls back to JSONL. A JSONL syntax error exits 2 with the line number.
- **T-OSV-9**: ecosystem mapping is exact. `npm`, `PyPI`, `crates.io` and `Go` map; `pypi` (lowercase), `RubyGems`, `Debian:12` and an invented `Foo` are not checkable, never exit 2.
- **T-OSV-10**: an unparseable PyPI ECOSYSTEM range event gives UNDECIDABLE, so a name match is `unresolved`/`undecidable`.
- **T-OSV-11**: `references` produce no host entry.
- **T-OSV-12**: the over-64-MiB path is exercised by monkeypatching the threshold constant (`IOC_WHOLE_JSON_MAX`) to 1 KiB, not by writing 64 MiB. Includes: `[` over the cap exits 2; `{` over the cap streams as JSONL.

**Versions**

- **T-VER-1**: SemVer §11 precedence table: `1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0`. Build metadata is ignored; `v` is stripped.
- **T-VER-2**: Go pseudo-versions order below their release. `+incompatible` is ignored.
- **T-VER-3**: PEP 440: `1.0 == 1.0.0`; `1.0.dev0 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1`; `1!0.1 > 2.0`; local `+x` ignored; `alpha`, `beta`, `c`, `pre` and `preview` normalise; `===` uses string equality.

**Resolution (item side)**

- **T-RES-1**: npm: `left-pad@4`, `@latest`, `@^4.1.0`, `@4.1` and none are all unresolved; `@4.1.1` and `@=4.1.1` are resolved.
- **T-RES-2**: the npm alias `x@npm:evil@1.0.0` matches entry `npm:evil@=1.0.0` (D5).
- **T-RES-3**: go: `@v1.2`, `@latest`, `@master` and `@1.2.3` are unresolved; `@v1.2.3` and a pseudo-version are resolved.
- **T-RES-4**: oci: `docker run nginx` (no tag) and `nginx:latest` are unresolved. `docker pull docker.io/library/nginx:1.25` matches `oci:nginx@=1.25`. A digest item compared with a tag entry is `undecidable`.
- **T-RES-5**: pypi: `pip install Foo_Bar==1.0` matches `pypi:foo-bar@=1.0.0`; `pip install 'foo>=2'` is unresolved.
- **T-RES-6** (after B1): `cargo install foo --version 1.2.3` is resolved; `cargo add serde@1.2` and `cargo add serde@1.2.3` are unresolved.
- **T-RES-7**: npm case: the item `JSONStream` does **not** match the entry `npm:jsonstream`, and does match `npm:JSONStream`.

**Matching**

- **T-MAT-1**: one test per verdict and reason row in §6.3.
- **T-MAT-2**: host: suffix on a label boundary (`a.evil.io` matches `host:evil.io`; `notevil.io` does not); `=` exact; path on a segment boundary (`github.com/evil-org` does not match `github.com/evil-organisation`); a dot-segment path never matches; an **inferred** host never matches (`host:registry.npmjs.org` against `npm i x`); an explicit `--registry` host does match.
- **T-MAT-3**: a Go item matches `host:github.com/evil` through its module origin.
- **T-MAT-4** (after B1): the npm forge shorthand `npm i github:evil-org/x` matches `host:github.com/evil-org`.
- **T-MAT-5**: the private-registry downgrade: `npm i --registry https://npm.corp x@1.0.0` against `npm:x@=1.0.0` gives `unresolved`/`private-registry`. The same install with no `--registry` gives `match`.
- **T-MAT-6**: a refused item (a Claude denial fixture, via `_network_outcome`) gives a row with `refused: true`, no flag, no gate effect and `totals.refused == 1`, and `network.items` does not contain it.
- **T-MAT-7**: a failed item keeps its verdict, and the evidence contains `(call failed)`.
- **T-MAT-8**: the trust list does not exempt a match (`--network-trust registry.npmjs.org`).
- **T-MAT-9**: several entries on one item: the strongest wins, and `refs` holds all the refs at that rank.
- **T-MAT-10**: coverage: lockfile, no-host and other counts, with `items_checked` adding up.

**Flags, gate and suppression**

- **T-GATE-1**: `match` trips `--fail-on high` and `any`, with its own reason, and is **absent** from the generic high-severity count. It does not trip `critical`.
- **T-GATE-2**: `unresolved` trips only `any`, with its own reason.
- **T-GATE-3**: refused and clean rows trip nothing.
- **T-GATE-4**: a suppressed match does not trip. It is counted in `totals.suppressed` and `fleet.suppressed_flags`, shown in the IOC line, and stays in `bash.flags` with `suppressed: true`.
- **T-GATE-5**: `flag_id` is stable across two runs, and differs between `network-ioc` and `network-ioc-unresolved` for the same key.
- **T-GATE-6**: 40 installs of one bad version give one flag, with `40 install(s)` in the evidence.

**CLI and output**

- **T-CLI-1**: a missing file, a directory, bad UTF-8 and a grammar error each exit 2, naming the file and the line.
- **T-CLI-2**: `--ioc` with `--card`, `--watch` or `--mcp` exits 2. With `--explain`, a broken IOC file does not matter.
- **T-CLI-3**: a cwd `.actualis-ioc` is ignored when `--ioc` is not given.
- **T-CLI-4**: the order of repeated `--ioc` files sets `source`. Duplicate entries across files both count.
- **T-OUT-1**: the schema-freeze tests pass with the populated fixture. `network.ioc.enabled` is False and every count is zero without `--ioc`.
- **T-OUT-2**: two runs give byte-identical `--json` and text output (determinism).
- **T-OUT-3**: the text block prints when there are no downloads. The 50-row cap and the `+N more` line. The no-match line and the caveat. The D3 note.
- **T-OUT-4**: `--diff` against a 0.2.2 baseline and against a pre-N2a branch baseline.
- **T-OUT-5**: the leak canaries for `--share` and `--card` (§9.5).
- **T-OUT-6**: an escape canary: ESC, CR, U+202E and U+009B placed in item fields and in an OSV `package.name`. The name fails validation and is skipped; nothing in `_STRIPPED_RANGES` reaches the text or JSON output.
- **T-OUT-7**: `--explain ioc` exists, and `--explain network` mentions it. The completions offer `--ioc` with a file hint.
- **T-OUT-8**: `--self-check` passes, with an unchanged import list.
- **T-ACT-1** (`tests/test_action.py`): the `ioc` input reaches both actualis invocations. The `ioc-matches` output. The `fail-on: critical` warning.

**Performance**

- **T-PERF-1**: see §11.

---

## 11. Performance budget

Measured in pass 2 on synthetic data on this Mac with `python3 -I`: 100k OSV records (118 MB JSONL) parse and index in 0.36 s; 100k line entries parse in 0.10 s; 100k package lookups take 0.04 s; 100k host-suffix lookups take 0.10 s. **Repeat these on a real ossf checkout before quoting them publicly.**

| Budget | Limit | How it is enforced |
|---|---|---|
| No `--ioc` | Zero per-item work. `apply_ioc(fleet, None)` only zeroes `ioc_totals` and sets `item["ioc"] = None` | Code review, plus T-OUT-1 |
| Loading 100k entries (either format) | ≤ 2 s on the dev Mac | **T-PERF-1** builds 100k synthetic line entries and 100k OSV JSONL records in memory or a temp directory. Its CI ceiling is a loose 10 s, so a slow shared runner does not flake |
| Matching 10k items against 100k entries | ≤ 1 s | T-PERF-1, with a 5 s ceiling |
| Memory | O(entries). No per-item allocation beyond each matched row | — |
| Cap | 1,000,000 entries in total | T-LINE-10 |
| Pathological input | Every parser regex is linear (§9.3). A 1 MiB line of `@` or `.` characters parses or fails in ≤ 50 ms | A T-PERF-1 sub-case |

Specs are pre-parsed into key tuples at load, so a comparison is tuple ordering.

---

## 12. Out of scope (N2b and later)

- Windows (`from`/`until` promoting `unresolved` under `network-ioc-window`).
- Mentions of IOC hosts in arbitrary Bash text.
- The IOC-file tripwire, on W.
- Registry tarball URL parsing.
- `--watch` and MCP support.
- GHSA, STIX and MISP converters, which will be docs only.
- `--why` for flags.

## 13. Effort

M. About 450 to 550 lines in `actualis.py`: the parsers about 200, PEP 440 and SemVer about 80, matching and flags about 120, and output about 100. About 600 lines of tests.
