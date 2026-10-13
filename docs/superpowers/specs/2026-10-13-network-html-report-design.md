# Network HTML report: the --network view as one self-contained page — design

Date: 2026-10-13
Status: draft, awaiting review
Tracks: digital-foundry/actualis-pro #77 (deferred part)
Builds on: PR #56 (chart strip, `network.by_day`, `network.by_project`)

## Intent

**Goal (stated):** a readable, shareable report of what coding agents
downloaded, with charts. The terminal view is capped at 100 columns and a few
rows per section, and this report is not.

**Approach (approved 2026-10-13, option A):**
- charts are drawn in Python as inline SVG;
- one small inline script sorts and filters tables;
- no third-party code goes into the page, and the Python side stays
  standard-library only.

**Rejected:**
- B, an inlined charting library: about 200 KB of vendored code in a tool
  whose selling point is no supply chain.
- C, pure HTML with no script: the safest option, but tables cannot be sorted.
  It stays available as a degradation, because the page reads fine with
  scripts off.

**Success:**
- One file opens offline in any current browser and fetches nothing.
- Every number on the page matches `actualis --network --json` for the same
  flags.
- The same input gives a byte-identical page.

## 1. Command and output

```
actualis --network --html [--out DIR] [--days N] [--host H] [--package P]
                          [--session S] [--unasked] [--with-prompts] [--no-redact]
```

- **Output file:**
  - writes `actualis-network.html` into `--out DIR`, or into the current
    directory when `--out` is not given;
  - never overwrites: when the name exists, it writes
    `actualis-network-2.html`, then `-3`, and so on. This is the same rule as
    `card_paths`.
- **File creation:**
  - uses `os.open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)`;
  - the file is readable by the user only;
  - a race with another writer fails rather than overwrites;
  - the page is rendered in full before the file is opened, so an error
    leaves no partial file.
- **stdout:** prints one line, the path written. Prints nothing else.
- **Exit codes:**
  - 0 on success;
  - 2 on a usage error, as other usage errors do;
  - `EXIT_CANNOT_RUN` (1) when the directory is missing or not writable. The
    message matches the card's: "actualis: cannot write the report to DIR:
    REASON", with no traceback.
- **Filters:**
  - `network_filter` narrows the fleet before anything renders, so `--days`,
    `--host`, `--package`, `--session` and `--unasked` narrow the whole page:
    totals, charts, tables and the embedded JSON alike;
  - the header names the active filters, using `network_filter_names`.

**Argument rules** (in `main`, next to the existing checks):
- `--html` requires `--network`: "--html requires --network: it writes the
  network report."
- `--html` with `--json` is an error: "--html writes a file; it cannot also
  emit --json."
- `--with-prompts` is allowed with `--json` or `--html`. The error text
  changes to "--with-prompts applies only to --json or --html; the text view
  already shows prompts."
- `--out` help text becomes "--card or --html: directory to write into
  (default: current directory)".
- No new conflict rule is needed for the other modes: `--html` requires
  `--network`, and the existing loop already rejects `--card`, `--share` and
  the rest alongside `--network`.

## 2. Page contents

The page has one column with a max width of 1100px. Sections appear in this
order, the same as the text view.

1. **Header:**
   - title "actualis network report";
   - actualis version;
   - scan window, as first and last item dates in UTC;
   - active filters;
   - one line explaining the approval words (asked, unasked, unknown) from
     `--explain network`.
2. **Summary tiles:**
   - downloads;
   - unasked, with its percent;
   - unknown;
   - hosts;
   - packages;
   - sessions;
   - projects.
3. **Charts (inline SVG):**
   - **Downloads per day:** a bar chart from `network.by_day`, with the unasked
     part stacked on top. Days with no downloads show a gap and are not
     dropped. Any `by_day_undated` count is shown as a note under the chart.
   - **Approval:** one stacked horizontal bar of unasked, unknown and asked,
     using the terminal's three shades as three fills, with a legend.
   - **Top hosts and top packages:** horizontal bars, unasked over total, up
     to 15 rows each.
   - **By project:** horizontal bars. Shown only when there are two or more
     projects, as in the text view.
   - **Hover values:** each bar carries an SVG `<title>`, so the browser shows
     exact values with no script.
4. **Tables:**
   - hosts: host, downloads, unasked, unknown, first seen, last seen;
   - packages: ecosystem, name, version or pin, downloads, unasked;
   - projects: project, downloads, unasked;
   - sessions: start, project, session id (8 characters), downloads, unasked;
   - items: when (UTC), host, what, approval, mode, agent, project, session,
     why, trace;
   - the trace column holds the call id and `file:line`, as in the filtered
     text view;
   - the prompt column is present only with `--with-prompts`.
5. **Data:**
   - the embedded JSON (§3), in a `<details>` element that is collapsed by
     default;
   - its sha256;
   - the shell line that checks it (§3).

**Limits:**
- The items table holds `network.items`, which is already capped at
  `NETWORK_ITEMS_CAP` (2,000), newest first.
- When `network.items_truncated` is true, a line says how many were left out
  (`totals.items` minus the rows shown) and suggests `--days` or `--session`.
- The other tables are complete.

**Script behaviour** (inline, under 4 KB, no `eval`, no network):
- Clicking a column header sorts that table, numeric or text, and a second
  click reverses the order.
- One text box per table filters rows by substring.
- **With scripts off:** tables show in their default order (§4) and every row
  is visible.

**Styling:**
- inline `<style>` only;
- system font stack;
- light and dark themes via `prefers-color-scheme`;
- the yellow, dim and plain roles of the terminal map to three CSS variables.

## 3. Embedded JSON and its check

- The page embeds a `<script type="application/json" id="actualis-network">`
  block. It holds exactly the object `actualis --network --json` prints for
  the same flags: filters, `--days`, `--with-prompts` and `--no-redact`.
- **Serialisation:**
  - `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`;
  - then `<`, `>` and `&` are replaced with `<`, `>` and `&`,
    so no value can close the script element;
  - those escapes are valid JSON, so the parsed object is unchanged.
- **Digest:**
  - the page shows `sha256` of the serialised text, after escaping;
  - the explanation gives a check that compares parsed objects, not bytes:
    `python3 -c` with a short script that reads the block from the file and
    compares it to `actualis --network --json`.
  - Comparing parsed objects keeps the check independent of key order and
    whitespace in `--json`.
- Every chart and tile value is computed from this same object, never from a
  second pass over the fleet. One source keeps the page and `--json` from
  disagreeing.

## 4. Safety

- **Escaping:**
  - every transcript-derived string reaches HTML through one helper,
    `html.escape(s, quote=True)`, applied after `clean()` and redaction;
  - this applies in text, in attribute values and in SVG `<title>`;
  - nothing is inserted with a raw string format.
- **Redaction:**
  - the same `redact()` path as the text view and `--json`;
  - `--no-redact` behaves exactly as it does for `--json`;
  - as everywhere, redaction runs before truncation.
- **Prompts:** included only with `--with-prompts`, matching `--json`. This is
  stricter than the text view because a file travels.
- **Content Security Policy:**
  - `<meta http-equiv="Content-Security-Policy" content="default-src 'none';
    style-src 'unsafe-inline'; script-src 'sha256-<hash of the inline
    script>'; img-src data:; base-uri 'none'; form-action 'none'">`;
  - the script hash is computed at render time from the one script block;
  - so the browser blocks any fetch, injected script, form post or frame.
- **No external references:**
  - no URL appears in `href`, `src` or CSS `url()`;
  - hosts and URLs from transcripts appear only as text, never as links.
- **Determinism:**
  - no timestamps of the run, random ids or locale-dependent formatting;
  - numbers use `f"{n:,}"`;
  - dates are UTC ISO.
- **File mode:** 0600, set at creation (§1).

## 5. Code shape

- Everything lives in `actualis.py`, keeping the tool a single file.
- New code sits next to the network renderers.
- `render_network_html(n: dict, *, filters: list[str], items: list[dict],
  version: str, with_prompts: bool) -> str` builds the page as a string and
  is pure: no I/O and no clock.
- Chart helpers, each returning an SVG string:
  - `_svg_day_bars(by_day, undated) -> str`;
  - `_svg_approval_bar(totals) -> str`;
  - `_svg_rank_bars(rows, label_key) -> str`.
- **Shared values:** the bar-scale and largest-remainder logic from #56
  (`_net_approval_bar`) is factored into one function returning integer cell
  shares. The terminal and the SVG both call it, so the two cannot disagree on
  proportions.
- `write_network_html(page: str, out_dir: Path) -> Path` handles the naming,
  the `O_EXCL` open and the 0600 mode.
- `_NET_HTML_SCRIPT` and `_NET_HTML_STYLE` are module constants.
- The non-ASCII glyph test covers the new source. HTML output uses entities or
  plain ASCII, so it adds no `_GLYPH_FALLBACK` entries.
- `JSON_SCHEMA` is unchanged: no new `--json` keys.

## 6. Documentation

- README: one usage line under the network section.
- `--explain network`: one paragraph on the HTML report and its JSON check.
- `docs/json.md`: a note that the page embeds the `--network --json` object.
- CHANGELOG 0.3.0, Added: one bullet.

## 7. Testing

All tests use synthetic transcripts under a temporary HOME. They never read
real transcripts.

- **Escaping:**
  - host, `why`, project, package and session values containing `<script>`,
    `"><img src=x onerror=1>`, `</script>`, `]]>` and a bidi override appear
    only escaped;
  - the parsed page (`html.parser`) has exactly one `<script>` element with
    executable content.
- **Embedded JSON:**
  - the block parses and equals `network_json(...)` for the same fleet and
    flags;
  - with `--with-prompts` its prompts are present;
  - without the flag they are null and no prompt column appears.
- **Redaction:** a secret in a command or URL never appears in the page, and
  `--no-redact` shows it.
- **CSP:**
  - the meta tag is present;
  - the script hash in it equals the sha256 of the inline script.
- **No external references:** no `http:`, `https:` or `//` appears inside any
  `href`, `src` or `url(` in the page.
- **Never overwrite:**
  - existing `actualis-network.html` and `-2` lead to `-3`;
  - a pre-created target makes `O_EXCL` fail without truncating it.
- **File mode:** the written file is 0600.
- **Determinism:** two renders of the same fleet are byte-identical.
- **Arguments:**
  - `--html` without `--network`, and `--html --json`, each exit 2 with the
    messages in §1;
  - `--with-prompts --html` is accepted.
- **Caps:**
  - 2,001 items leave 2,000 rows and a "1 more" line, with
    `NETWORK_ITEMS_CAP` patched low in the test to keep it fast;
  - empty data renders a page saying there were no downloads, with no chart
    errors.
- **Filters:** `--host` narrows the items table and the header names the
  filter.
- **Shared shares:** the terminal and SVG approval bars get identical shares
  from the shared function.
- **Python 3.9:** the network test modules run under 3.9, as in #56.

## 8. Not in this spec

- **An HTML version of the main report**, which is everything that is not
  `--network`.
- **Opening the browser automatically:** the tool prints the path. The tray's
  "Open Network Report" item can adopt `--html` later, in its own change.
- **Live updates:** `--watch` stays terminal only.
- **Links out to hosts or package registries:** these were left out on
  purpose, for the CSP and no-reference rules.

## 9. Amendments during planning and build (2026-10-13)

- **Signature:** `render_network_html` takes no `items` argument. Items come
  from `n["items"]`.
- **Hosts table:** host, downloads, unasked, first seen, trusted. `unknown`
  and `last seen` are not in `network.hosts[]`, and §3 forbids a second pass
  over the fleet.
- **Sessions:** the sessions table and tile come from `n["items"]`. When that
  list is truncated they are labelled "in listed items".
- **Naming:** a lost name race takes the next name, up to 100 tries. A
  dangling symlink counts as taken (`os.path.lexists`), so it is never
  followed and never loops. It still never overwrites.
- **Imports:** `base64` and `html` join the import freeze (T-OUT-8). Neither
  opens a socket, and `--self-check` still passes.
- **`--out` and `--style`:** they get separate errors: "--style applies only
  to --card." and "--out applies only to --card or --html."
