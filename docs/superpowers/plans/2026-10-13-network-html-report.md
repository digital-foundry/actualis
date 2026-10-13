# Network HTML report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `actualis --network --html` writes the network view as one
self-contained, offline HTML page with inline SVG charts, sortable tables and
the `--network --json` object embedded.

**Architecture:**
- All code goes in `actualis.py`, beside the network renderers.
- A pure renderer (`render_network_html`) turns the `network_json` dict into
  a string.
- A writer (`write_network_html`) creates the file with `O_EXCL` and mode
  0600 under a never-overwrite name.
- `main` wires the `--html` flag, its argument rules and the `--out`
  directory.

**Tech Stack:** Python 3.9+ standard library only (`html`, `hashlib`,
`base64`, `json`, `os`), unittest.

**Spec:** `docs/superpowers/specs/2026-10-13-network-html-report-design.md`

## Global Constraints

- Single file `actualis.py`, standard library only, Python 3.9+. No
  backslash inside an f-string expression.
- Every raw non-ASCII character in the source needs a `_GLYPH_FALLBACK`
  entry. Use HTML entities (`&middot;`, `&hellip;`) or `\u` escapes, so the
  source adds no non-ASCII characters.
- `JSON_SCHEMA` is unchanged: no new `--json` keys.
- Every transcript-derived string reaches HTML through `_h()`, which runs
  `clean()` and then `html.escape(quote=True)`.
- No `http:`, `https:` or `//` in any `href`, `src` or `url(` in the page.
- CSP: `default-src 'none'; style-src 'unsafe-inline'; script-src
  'sha256-<b64>'; img-src data:; base-uri 'none'; form-action 'none'`.
- The file is created with `os.open(..., O_WRONLY|O_CREAT|O_EXCL, 0o600)`,
  named `actualis-network.html`, then `-2`, `-3` and so on.
- The page is byte-identical for the same input: no run timestamp and no
  randomness.
- Tests use synthetic transcripts and a temporary HOME only.

## Review Focus

1. A span of years, or a date near 9999-12-31, in `by_day` must render
   without `OverflowError` or a 3,000-bar chart. Task 2 reuses
   `_net_buckets` (120 cells) and clamps the end date; the test is
   `test_far_dates_render`.
2. When the item list is truncated, the session and tile counts derive from
   listed items. The page must say so and not imply totals. Task 2 test:
   `test_truncated_says_more`.
3. Losing a race for the file name must take the next name, never
   overwrite. Task 3 test: `test_race_takes_next_name`.
4. On Windows, mode 0600 is not enforceable. The mode test skips on `nt`, and
   the write must still succeed. Task 3 test.
5. `--out` used without `--card` or `--html` must still be rejected, and
   `--style` without `--card` too. Task 4 test: `test_out_rules`.

Rulings against the spec (also amended in the spec's §9):
- **`render_network_html` signature:** it takes no `items` argument; items
  come from `n["items"]`.
- **Hosts table columns:** host, downloads, unasked, first seen, trusted.
  `unknown` and `last seen` are not in `network.hosts[]`, and §3 forbids a
  second pass.
- **Sessions table and tile:** derived from `n["items"]`, labelled as listed
  items when truncated.
- **A lost name race takes the next name.** It still never overwrites.

---

### Task 1: One share function for terminal and SVG bars

**Files:**
- Modify: `actualis.py` (`_net_approval_bar`, about line 8255)
- Test: `tests/test_network_html.py` (new)

**Interfaces:**
- Produces: `_net_shares(values: list[int], width: int) -> list[int]`.

- [ ] **Step 1: Failing test.** Create `tests/test_network_html.py` with the
  standard loader header (copy lines 1–27 of
  `tests/test_network_charts.py`, adding `import base64, hashlib, html.parser`
  and `from datetime import datetime, timedelta, timezone`), then:

```python
class TestShares(unittest.TestCase):
    def test_shares_add_up_and_floor_non_zero(self):
        self.assertEqual(af._net_shares([1, 1000, 0], 20), [1, 19, 0])
        self.assertEqual(sum(af._net_shares([3, 5, 7], 1000)), 1000)
        self.assertEqual(af._net_shares([0, 0, 0], 10), [0, 0, 0])

    def test_terminal_bar_uses_the_same_shares(self):
        t = {"unasked": 7, "unknown": 2, "asked": 1}
        bar = af._net_approval_bar(t, 30)
        cells = af._net_shares([7, 2, 1], 30)
        self.assertEqual([bar.count("█"), bar.count("▒"), bar.count("░")], cells)
```

- [ ] **Step 2:** Run `python3 -m unittest tests.test_network_html -q`.
  Expect `AttributeError: _net_shares`.
- [ ] **Step 3: Implement.** Add above `_net_approval_bar`:

```python
def _net_shares(values: list[int], width: int) -> list[int]:
    """`width` cells shared among `values` by largest remainder, so they add
    up to `width`; a value above zero always gets a cell, taken from the
    largest share. The terminal approval bar and the HTML charts both use it,
    so the two cannot disagree on proportions."""
    total = sum(values)
    if not total or width <= 0:
        return [0] * len(values)
    exact = [v * width / total for v in values]
    cells = [int(e) for e in exact]
    for k in sorted(range(len(values)), key=lambda k: -(exact[k] - cells[k]))[:width - sum(cells)]:
        cells[k] += 1
    for k in range(len(values)):
        if values[k] and not cells[k]:
            cells[k] = 1
            cells[max(range(len(values)), key=lambda j: cells[j])] -= 1
    return cells
```

  Rewrite the body of `_net_approval_bar` to use it:

```python
    parts = [(t["unasked"], "█"), (t["unknown"], "▒"), (t["asked"], "░")]
    if not sum(v for v, _ in parts):
        return " " * width
    cells = _net_shares([v for v, _ in parts], width)
    colours = (c.yellow, c.dim, "") if c else ("", "", "")
    off = c.off if c else ""
    return "".join(f"{col}{g * n}{off}" if n and col else g * n
                   for (_, g), n, col in zip(parts, cells, colours))
```

- [ ] **Step 4:** Run `python3 -m unittest tests.test_network_html
  tests.test_network_charts -q`. Expect PASS.
- [ ] **Step 5:** Commit: "Network: one share function for the terminal and
  HTML bars".

### Task 2: The page renderer

**Files:**
- Modify: `actualis.py`:
  - add `import base64` and `import html as _html` to the imports;
  - add a new block after `_render_network_sessions`, before `def render(`.
- Test: `tests/test_network_html.py`

**Interfaces:**
- Consumes: `_net_shares`, `_net_buckets(by_day, width)`, `_net_what(r)`,
  `_net_path(t)`, `network_json(fleet, raw)`, `clean`.
- Produces:
  - `render_network_html(n: dict, *, filters: list[str], version: str,
    with_prompts: bool) -> str`;
  - `_NET_HTML_SCRIPT: str`;
  - `_net_html_blob(n: dict) -> str`.

- [ ] **Step 1: Failing tests.** Append:

```python
TS0 = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
HOSTILE = '"><img src=x onerror=1></script><script>alert(1)</script>‮]]>'


def fleet(n=6, with_prompts=False):
    f = af.Fleet()
    f.with_prompts = with_prompts
    for k in range(n):
        f.add_tool("proj-" + HOSTILE if k == 0 else f"proj-{k % 2}", "Bash",
                   {"command": f"curl -O https://h{k % 3}.example/{HOSTILE}.sh" if k == 1
                    else f"npm i pkg{k}@1.0.{k}"},
                   TS0 + timedelta(days=k), "bypassPermissions" if k % 2 else "default",
                   session=f"{k % 2:08x}-0000-4000-8000-000000000000", call_id=f"toolu_{k:03d}",
                   why=HOSTILE if k == 2 else "Because.", prompt="secret plan" if k == 3 else None)
    return f


def page(f=None, filters=(), with_prompts=False, raw=False):
    f = f or fleet(with_prompts=with_prompts)
    return af.render_network_html(af.network_json(f, raw), filters=list(filters),
                                  version="9.9.9", with_prompts=with_prompts)


class Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.refs, self._in = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "src"):
            if k in a:
                self.refs.append(a[k])
        if tag == "script":
            self._in = a.get("type", "")
            self.scripts.append([self._in, ""])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in = None

    def handle_data(self, data):
        if self._in is not None:
            self.scripts[-1][1] += data


def parse(p):
    s = Scripts()
    s.feed(p)
    return s


class TestPage(unittest.TestCase):
    def test_hostile_strings_only_escaped(self):
        p = page()
        self.assertNotIn("<img", p)
        self.assertNotIn("<script>alert", p)
        self.assertNotIn("‮", p)
        runnable = [s for s in parse(p).scripts if s[0] != "application/json"]
        self.assertEqual(len(runnable), 1)
        self.assertEqual(runnable[0][1], af._NET_HTML_SCRIPT)

    def test_embedded_json_equals_network_json(self):
        f = fleet()
        p = page(f)
        [blob] = [s[1] for s in parse(p).scripts if s[0] == "application/json"]
        self.assertEqual(json.loads(blob), json.loads(json.dumps(af.network_json(f))))
        self.assertIn(hashlib.sha256(blob.encode()).hexdigest(), p)

    def test_prompts_only_with_the_flag(self):
        self.assertNotIn("secret plan", page())
        self.assertNotIn("<th data-k=\"10\">prompt</th>", page())
        p = page(with_prompts=True)
        self.assertIn("secret plan", p)
        self.assertIn(">prompt</th>", p)

    def test_csp_hash_matches_the_script(self):
        p = page()
        h = base64.b64encode(hashlib.sha256(af._NET_HTML_SCRIPT.encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{h}'", p)
        self.assertIn("default-src 'none'", p)

    def test_no_external_references(self):
        p = page()
        for ref in parse(p).refs:
            self.assertNotRegex(ref, r"^(https?:|//)")
        self.assertNotRegex(p, r"url\(\s*['\"]?(https?:|//)")

    def test_deterministic(self):
        self.assertEqual(page(), page())

    def test_secret_redacted_unless_raw(self):
        f = af.Fleet()
        secret = "sk-ant-api03-" + "Q" * 40
        f.add_tool("p", "Bash", {"command": f"curl https://a.example/x?key={secret}"}, TS0, "auto")
        self.assertNotIn("Q" * 20, page(f))
        self.assertIn("Q" * 20, page(f, raw=True))

    def test_empty(self):
        p = page(af.Fleet())
        self.assertIn("No downloads were recorded", p)
        self.assertNotIn("<svg", p)

    def test_truncated_says_more(self):
        with mock.patch.object(af, "NETWORK_ITEMS_CAP", 3):
            p = page(fleet(8))
        self.assertIn("5 more not listed", p)
        self.assertIn("in listed items", p)

    def test_far_dates_render(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "npm i a"}, datetime(2001, 1, 1, tzinfo=timezone.utc), "auto")
        f.add_tool("p", "Bash", {"command": "npm i b"}, datetime(9999, 12, 31, tzinfo=timezone.utc), "auto")
        p = page(f)
        self.assertLessEqual(p.count("<title>"), 130)
        self.assertIn("9999-12-31", p)

    def test_filters_named(self):
        self.assertIn("host h1.example", page(filters=["host h1.example"]))
```

- [ ] **Step 2:** Run the tests. Expect `AttributeError:
  render_network_html`.
- [ ] **Step 3: Implement.** Add after `_render_network_sessions`:

```python
# --------------------------------------------------------------------------
# --network --html: the network view as one self-contained page. Pure: the
# page is a function of network_json and the flags, so the same input gives
# the same bytes. Everything from a transcript goes through _h().

NET_HTML_NAME = "actualis-network"
NET_HTML_DAY_CELLS = 120        # bars in the per-day chart; wider spans share a bar
NET_HTML_RANK_ROWS = 15

_NET_HTML_SCRIPT = (
    "document.querySelectorAll('th').forEach(function(th){th.addEventListener('click',function(){"
    "var tb=th.closest('table').tBodies[0],k=+th.dataset.k,d=th.dataset.d==='1'?-1:1;"
    "th.dataset.d=d===1?'1':'0';var rows=Array.prototype.slice.call(tb.rows);"
    "rows.sort(function(a,b){var x=a.cells[k].textContent,y=b.cells[k].textContent,"
    "nx=parseFloat(x.replace(/,/g,'')),ny=parseFloat(y.replace(/,/g,''));"
    "return(!isNaN(nx)&&!isNaN(ny)&&/^[\\d,.]+$/.test(x)&&/^[\\d,.]+$/.test(y)?nx-ny:x.localeCompare(y))*d;});"
    "rows.forEach(function(r){tb.appendChild(r);});});});"
    "document.querySelectorAll('input.flt').forEach(function(i){i.hidden=false;"
    "i.addEventListener('input',function(){var q=i.value.toLowerCase();"
    "Array.prototype.forEach.call(document.getElementById(i.dataset.t).tBodies[0].rows,"
    "function(r){r.hidden=!!q&&r.textContent.toLowerCase().indexOf(q)<0;});});});")

_NET_HTML_STYLE = (
    ":root{--bg:#fbfaf7;--fg:#1d1c1a;--mut:#6b6862;--line:#e3e0d8;--un:#c99700;--uk:#a8a49b;"
    "--as:#e8e5de;--card:#fff}"
    "@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mut:#9d9a93;"
    "--line:#2c2b28;--un:#e6b422;--uk:#6e6b65;--as:#3a3935;--card:#1c1c1a}}"
    "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);"
    "font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}"
    "main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0}"
    "h2{font-size:16px;margin:32px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}"
    "h3{font-size:14px;margin:16px 0 6px;color:var(--mut)}.meta,.note{color:var(--mut);font-size:13px}"
    ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:16px}"
    ".tile{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px}"
    ".tile b{display:block;font-size:22px;font-variant-numeric:tabular-nums}"
    ".tile span{color:var(--mut);font-size:12px}svg{width:100%;height:auto;display:block}"
    ".b-unasked{fill:var(--un)}.b-unknown{fill:var(--uk)}.b-asked{fill:var(--as)}"
    ".b-other{fill:var(--uk);opacity:.45}.ax{font-size:11px;fill:var(--mut)}.axis{stroke:var(--line)}"
    ".lg{display:inline-block;width:10px;height:10px;margin:0 4px 0 12px;border-radius:2px}"
    ".lg.b-unasked{background:var(--un)}.lg.b-unknown{background:var(--uk)}"
    ".lg.b-asked{background:var(--as)}.lg.b-other{background:var(--uk);opacity:.45}"
    ".cols{display:grid;grid-template-columns:1fr 1fr;gap:24px}"
    "@media(max-width:720px){.cols{grid-template-columns:1fr}}"
    ".rk{display:grid;grid-template-columns:minmax(0,40%) 1fr auto;gap:8px;align-items:center;"
    "font-size:13px;margin:3px 0}.rk svg{height:10px}.rl{overflow-wrap:anywhere}"
    ".rn{font-variant-numeric:tabular-nums;color:var(--mut)}"
    ".tw{overflow-x:auto;border:1px solid var(--line);border-radius:6px}"
    "table{border-collapse:collapse;width:100%;font-size:13px}"
    "th,td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}"
    "th{cursor:pointer;background:var(--card);white-space:nowrap}td.n{text-align:right;"
    "font-variant-numeric:tabular-nums}td{max-width:340px;overflow-wrap:anywhere}"
    ".flt{margin:6px 0;padding:4px 8px;border:1px solid var(--line);border-radius:4px;"
    "background:var(--card);color:var(--fg)}code,pre{font:12px ui-monospace,Menlo,monospace}"
    "pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;"
    "background:var(--card);padding:8px;border:1px solid var(--line)}")


def _h(s: object) -> str:
    """Any value as HTML text or attribute: cleaned, then escaped."""
    if s is None:
        return ""
    return _html.escape(clean(s) if isinstance(s, str) else str(s), quote=True)


def _net_html_when(ts: str | None) -> str:
    """An item timestamp as YYYY-MM-DD HH:MM in UTC."""
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, OverflowError):
        return ts[:16]


def _net_html_blob(n: dict) -> str:
    """The JSON as embedded: sorted, compact, ASCII, and with < > & escaped so
    no value can close the script element. Still valid JSON for the same object."""
    s = json.dumps(n, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _svg_day_bars(by_day: list[dict], undated: int) -> str:
    if not by_day:
        return '<p class="note">No dated downloads.</p>'
    totals, unasked, step = _net_buckets(by_day, NET_HTML_DAY_CELLS)
    first = datetime.strptime(by_day[0]["date"], "%Y-%m-%d").date()
    last = datetime.strptime(by_day[-1]["date"], "%Y-%m-%d").date()
    vmax = max(totals) or 1
    w, h, pad = 1000, 160, 4
    bw = (w - 2 * pad) / len(totals)
    out = [f'<svg viewBox="0 0 {w} {h + 24}" role="img" aria-label="Downloads per day">']
    for k, (items, un) in enumerate(zip(totals, unasked)):
        if not items:
            continue
        start = first + timedelta(days=k * step)
        end = last if (last - start).days < step - 1 else start + timedelta(days=step - 1)
        when = start.isoformat() if start == end else f"{start.isoformat()} to {end.isoformat()}"
        x, hi, hu = pad + k * bw, h * items / vmax, h * un / vmax
        out.append(f'<g><title>{when}: {items:,} downloads, {un:,} unasked</title>'
                   f'<rect class="b-other" x="{x:.1f}" y="{h - hi:.1f}" width="{bw * 0.8:.1f}" '
                   f'height="{hi - hu:.1f}"/><rect class="b-unasked" x="{x:.1f}" y="{h - hu:.1f}" '
                   f'width="{bw * 0.8:.1f}" height="{hu:.1f}"/></g>')
    out.append(f'<line class="axis" x1="{pad}" y1="{h}" x2="{w - pad}" y2="{h}"/>'
               f'<text class="ax" x="{pad}" y="{h + 18}">{first.isoformat()}</text>'
               f'<text class="ax" x="{w - pad}" y="{h + 18}" text-anchor="end">{last.isoformat()}</text>'
               "</svg>")
    out.append('<p class="note"><span class="lg b-unasked"></span>unasked'
               '<span class="lg b-other"></span>unknown or asked'
               + (f" &middot; one bar is {step} days" if step > 1 else "") + "</p>")
    if undated:
        out.append(f'<p class="note">{undated:,} downloads have no date and are not in this chart.</p>')
    return "".join(out)


def _svg_approval_bar(t: dict) -> str:
    parts = [("unasked", t["unasked"], "b-unasked"), ("unknown", t["unknown"], "b-unknown"),
             ("asked", t["asked"], "b-asked")]
    total = sum(v for _, v, _ in parts) or 1
    cells = _net_shares([v for _, v, _ in parts], 1000)
    out, x = ['<svg viewBox="0 0 1000 34" role="img" aria-label="Approval">'], 0
    for (name, v, cls), wd in zip(parts, cells):
        if wd:
            out.append(f'<rect class="{cls}" x="{x}" y="0" width="{wd}" height="34">'
                       f'<title>{name}: {v:,} ({v * 100 // total}%)</title></rect>')
        x += wd
    out.append("</svg><p class=\"note\">")
    out.append("".join(f'<span class="lg {cls}"></span>{name} {v:,}' for name, v, cls in parts))
    return "".join(out) + "</p>"


def _svg_rank_bars(title: str, rows: list[tuple[str, int, int]]) -> str:
    """Rows of (label, unasked, total), drawn as total with unasked over it."""
    if not rows:
        return ""
    vmax = max(whole for _, _, whole in rows) or 1
    out = [f"<h3>{title}</h3><div class=\"ranks\">"]
    for label, part, whole in rows:
        out.append(f'<div class="rk"><span class="rl">{_h(label)}</span>'
                   f'<svg viewBox="0 0 100 10" preserveAspectRatio="none" role="img" '
                   f'aria-label="{_h(label)}"><title>{_h(label)}: {part:,} unasked of {whole:,}</title>'
                   f'<rect class="b-other" width="{100 * whole / vmax:.2f}" height="10"/>'
                   f'<rect class="b-unasked" width="{100 * part / vmax:.2f}" height="10"/></svg>'
                   f'<span class="rn">{part:,} / {whole:,}</span></div>')
    return "".join(out) + "</div>"


def _html_table(tid: str, cols: list[str], rows: list[list]) -> str:
    """A table whose int cells are right-aligned and comma-grouped. The filter
    box is hidden until the script shows it, so with scripts off it is absent."""
    head = "".join(f'<th data-k="{k}">{_h(c)}</th>' for k, c in enumerate(cols))
    body = []
    for r in rows:
        cells = "".join(f'<td class="n">{v:,}</td>' if isinstance(v, int) and not isinstance(v, bool)
                        else f"<td>{v}</td>" for v in r)
        body.append(f"<tr>{cells}</tr>")
    return (f'<input class="flt" data-t="{tid}" placeholder="filter" aria-label="filter" hidden>'
            f'<div class="tw"><table id="{tid}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def render_network_html(n: dict, *, filters: list[str], version: str, with_prompts: bool) -> str:
    """The --network --html page. Every number on it is read from `n`, the
    object --network --json prints, which is also embedded verbatim."""
    t = n["totals"]
    items = n["items"]
    truncated = len(items) < t["items"]
    blob = _net_html_blob(n)
    digest = hashlib.sha256(blob.encode("ascii")).hexdigest()
    sh = base64.b64encode(hashlib.sha256(_NET_HTML_SCRIPT.encode("ascii")).digest()).decode()
    csp = (f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{sh}'; "
           "img-src data:; base-uri 'none'; form-action 'none'")
    window = (f"{n['by_day'][0]['date']} to {n['by_day'][-1]['date']} UTC"
              if n["by_day"] else "no dated downloads")
    sessions: dict = {}
    for i in items:
        s = sessions.setdefault(i["session"] or "-", {"start": i["ts"] or "", "project": i["project"],
                                                      "n": 0, "u": 0})
        s["start"] = min(s["start"], i["ts"] or s["start"])
        s["n"] += 1
        s["u"] += i["approval"] == "unasked"
    listed = " in listed items" if truncated else ""
    pct = t["unasked"] * 100 // t["items"] if t["items"] else 0

    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
           f"<title>actualis network report</title><style>{_NET_HTML_STYLE}</style></head>"
           "<body><main><h1>actualis network report</h1>"
           f'<p class="meta">actualis {_h(version)} &middot; {_h(window)} &middot; filters: '
           f'{_h(", ".join(filters)) if filters else "none"}</p>'
           '<p class="meta"><b>unasked</b>: ran in a mode that never stops to ask. '
           "<b>unknown</b>: the mode could have asked; the transcript does not say. "
           "<b>asked</b>: a person approved it.</p>"]
    if not t["items"]:
        out.append("<p>No downloads were recorded"
                   + (" for these filters" if filters else "") + ".</p>")
    else:
        tiles = [(t["items"], "downloads"), (t["unasked"], f"unasked ({pct}%)"),
                 (t["unknown"], "unknown"), (t["asked"], "asked"),
                 (len(n["hosts"]), "hosts"), (len(n["packages"]), "packages"),
                 (len(sessions), "sessions" + listed), (len(n["by_project"]), "projects")]
        out.append('<div class="tiles">' + "".join(
            f'<div class="tile"><b>{v:,}</b><span>{_h(label)}</span></div>' for v, label in tiles)
            + "</div>")
        out.append("<h2>Downloads per day</h2>" + _svg_day_bars(n["by_day"], n["by_day_undated"]))
        out.append("<h2>Approval</h2>" + _svg_approval_bar(t))
        hosts = [(h["host"], h["unasked"], h["count"]) for h in n["hosts"][:NET_HTML_RANK_ROWS]]
        pkgs = [(f"{p['ecosystem']} {p['name']}", p["unasked"], p["count"])
                for p in n["packages"][:NET_HTML_RANK_ROWS]]
        out.append('<div class="cols"><div>' + _svg_rank_bars("Top hosts (unasked / total)", hosts)
                   + "</div><div>" + _svg_rank_bars("Top packages (unasked / total)", pkgs)
                   + "</div></div>")
        if len(n["by_project"]) > 1:
            out.append(_svg_rank_bars("By project (unasked / total)", [
                (p["project"] or "-", p["unasked"], p["items"])
                for p in n["by_project"][:NET_HTML_RANK_ROWS]]))
        out.append("<h2>Hosts</h2>" + _html_table("t-hosts", ["host", "downloads", "unasked",
                                                             "first seen (UTC)", "trusted"], [
            [_h(h["host"]), h["count"], h["unasked"], _h(_net_html_when(h["first_seen"])),
             "yes" if h["trusted"] else "no"] for h in n["hosts"]]))
        out.append("<h2>Packages</h2>" + _html_table("t-packages", ["ecosystem", "name", "versions",
                                                                   "pinned", "downloads", "unasked"], [
            [_h(p["ecosystem"]), _h(p["name"]), _h(", ".join(p["versions"])) or "-",
             "yes" if p["pinned"] else "no", p["count"], p["unasked"]] for p in n["packages"]]))
        out.append("<h2>Projects</h2>" + _html_table("t-projects", ["project", "downloads", "unasked"], [
            [_h(p["project"] or "-"), p["items"], p["unasked"]] for p in n["by_project"]]))
        out.append(f"<h2>Sessions{listed}</h2>" + _html_table(
            "t-sessions", ["start (UTC)", "project", "session", "downloads", "unasked"], [
                [_h(_net_html_when(s["start"])), _h(s["project"] or "-"), _h(sid[:8]), s["n"], s["u"]]
                for sid, s in sorted(sessions.items(), key=lambda kv: (kv[1]["start"], kv[0]),
                                     reverse=True)]))
        cols = ["when (UTC)", "host", "what", "approval", "mode", "agent", "project", "session",
                "why", "trace"] + (["prompt"] if with_prompts else [])
        rows = []
        for i in items:
            row = [_h(_net_html_when(i["ts"])), _h(i["host"] or "-"), _h(_net_what(i)),
                   _h(i["approval"]), _h(i["mode"] or "-"), _h(i["agent"] or "-"),
                   _h(i["project"] or "-"), _h((i["session"] or "-")[:8]), _h(i["why"] or ""),
                   f"{_h(i['call_id'] or '-')} &middot; {_h(_net_path(i['transcript']))}"]
            if with_prompts:
                row.append(_h(i["prompt"] or ""))
            rows.append(row)
        out.append("<h2>Every download</h2>" + _html_table("t-items", cols, rows))
        if truncated:
            out.append(f'<p class="note">{t["items"] - len(items):,} more not listed; '
                       "narrow with --days or --session.</p>")
    check = ("actualis --network --json SAME-FLAGS | python3 -c 'import json,re,sys; "
             "p=open(sys.argv[1]).read(); print(json.loads(re.search(r\"actualis-network\\\">"
             "(.*?)</script>\", p, re.S).group(1)) == json.load(sys.stdin))' REPORT.html")
    out.append("<h2>Data</h2>"
               '<p class="meta">Every number above is read from the object '
               "<code>actualis --network --json</code> prints for the same flags, embedded below. "
               f"sha256 of the embedded text: <code>{digest}</code></p>"
               f'<p class="meta">Check it (prints True):</p><pre>{_h(check)}</pre>'
               f'<details><summary>embedded JSON</summary><pre>{_h(json.dumps(n, indent=1, sort_keys=True))}'
               "</pre></details>"
               f'<script type="application/json" id="actualis-network">{blob}</script>'
               f"<script>{_NET_HTML_SCRIPT}</script></main></body></html>\n")
    return "".join(out)
```

- [ ] **Step 4:** Run `python3 -m unittest tests.test_network_html
  tests.test_actualis -q`. Expect PASS, including the glyph test.
- [ ] **Step 5:** Commit: "Network: render the --html page".

### Task 3: Writing the file

**Files:** Modify `actualis.py` (after `render_network_html`). Test:
`tests/test_network_html.py`.

**Interfaces:**
- Produces:
  - `network_html_path(out_dir: Path) -> Path`;
  - `write_network_html(page: str, out_dir: Path) -> Path`.

- [ ] **Step 1: Failing tests.**

```python
class TestWrite(unittest.TestCase):
    def test_never_overwrites_and_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "actualis-network.html").write_text("keep")
            (d / "actualis-network-2.html").write_text("keep2")
            p = af.write_network_html("<p>x</p>", d)
            self.assertEqual(p.name, "actualis-network-3.html")
            self.assertEqual((d / "actualis-network.html").read_text(), "keep")
            self.assertEqual(p.read_text(), "<p>x</p>")

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            p = af.write_network_html("x", Path(d))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_race_takes_next_name(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            real = af.network_html_path
            def racing(out_dir):
                p = real(out_dir)
                if p.name == "actualis-network.html":
                    p.write_text("other writer")
                return p
            with mock.patch.object(af, "network_html_path", side_effect=racing):
                p = af.write_network_html("mine", d)
            self.assertEqual((d / "actualis-network.html").read_text(), "other writer")
            self.assertEqual(p.read_text(), "mine")
```

- [ ] **Step 2:** Run. Expect `AttributeError`.
- [ ] **Step 3: Implement.**

```python
def network_html_path(out_dir: Path) -> Path:
    """The first actualis-network[-N].html that does not exist yet."""
    k = 1
    while True:
        p = out_dir / (f"{NET_HTML_NAME}.html" if k == 1 else f"{NET_HTML_NAME}-{k}.html")
        if not p.exists():
            return p
        k += 1


def write_network_html(page: str, out_dir: Path) -> Path:
    """Write the page, never over an existing file: O_EXCL makes that hold
    even under a race, and a lost race takes the next name. 0600 because the
    page holds commands and URLs from the user's transcripts."""
    data = page.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    while True:
        path = network_html_path(out_dir)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        break
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path
```

- [ ] **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: "Network: write the --html page without
  overwriting, mode 0600".

### Task 4: The `--html` flag

**Files:** Modify `actualis.py`:
- argparse, next to `--with-prompts`;
- the argument checks;
- the `--style`/`--out` rule;
- the directory check after the `card_dir` block;
- dispatch before `if args.json:`;
- `_VALUE_HINT` needs no entry, because `--html` is a boolean.

Test: `tests/test_network_html.py`.

- [ ] **Step 1: Failing tests.** Add a CLI fixture:

```python
SID = "cccc3333-0000-4000-8000-000000000003"


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "projects"
        (self.root / "-Users-x-proj").mkdir(parents=True)
        recs = [{"type": "assistant", "timestamp": "2026-10-07T14:22:00Z",
                 "permissionMode": "bypassPermissions", "sessionId": SID,
                 "message": {"id": "m1", "role": "assistant", "usage": {"input_tokens": 1, "output_tokens": 1},
                             "content": [{"type": "tool_use", "id": "toolu_01", "name": "Bash",
                                          "input": {"command": "npm i lodash@4.17.21"}}]}}]
        (self.root / "-Users-x-proj" / f"{SID}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n")
        self.home = base / "home"
        self.home.mkdir()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"), "NO_COLOR": "1"}
        old = os.getcwd()
        os.chdir(self.home)
        try:
            with mock.patch.dict(os.environ, env), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main([*argv, "--root", str(self.root), "--days", "3650"])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old)
        return code, out.getvalue(), err.getvalue()

    def test_writes_into_cwd_and_prints_path(self):
        code, out, err = self.run_main("--network", "--html")
        self.assertEqual(code, 0, err)
        p = Path(out.strip())
        self.assertEqual(p, self.home / "actualis-network.html")
        self.assertIn("lodash", p.read_text())

    def test_out_dir_and_embedded_equals_json(self):
        d = self.home / "reports"
        d.mkdir()
        code, out, _ = self.run_main("--network", "--html", "--out", str(d))
        self.assertEqual(code, 0)
        page_text = Path(out.strip()).read_text()
        blob = [s[1] for s in parse(page_text).scripts if s[0] == "application/json"][0]
        _, js, _ = self.run_main("--network", "--json")
        self.assertEqual(json.loads(blob), json.loads(js))

    def test_argument_errors(self):
        for argv, msg in ((["--html"], "--html requires --network"),
                          (["--network", "--html", "--json"], "--html writes a file")):
            code, _, err = self.run_main(*argv)
            self.assertEqual(code, 2)
            self.assertIn(msg, err)
        code, _, err = self.run_main("--network", "--html", "--with-prompts")
        self.assertEqual(code, 0, err)

    def test_out_rules(self):
        code, _, err = self.run_main("--network", "--out", str(self.home))
        self.assertEqual(code, 2)
        self.assertIn("--out applies only to --card or --html", err)
        code, _, err = self.run_main("--style", "terminal")
        self.assertEqual(code, 2)
        self.assertIn("--style applies only to --card", err)

    def test_missing_dir(self):
        code, _, err = self.run_main("--network", "--html", "--out", str(self.home / "nope"))
        self.assertEqual(code, 1)
        self.assertIn("is not a directory", err)
```

- [ ] **Step 2:** Run. Expect failures (unrecognized `--html`).
- [ ] **Step 3: Implement.**
  - argparse, after `--with-prompts`:

```python
    net.add_argument("--html", action="store_true",
                     help="--network: write the report as one self-contained HTML page "
                          "(actualis-network.html, never overwritten; see --out)")
```

  - `--with-prompts` help: "--json or --html: include ...".
  - Replace the `--with-prompts` check with:

```python
    if args.html and not args.network:
        ap.error("--html requires --network: it writes the network report.")
    if args.html and args.json:
        ap.error("--html writes a file; it cannot also emit --json.")
    if args.with_prompts and not (args.json or args.html):
        ap.error("--with-prompts applies only to --json or --html; "
                 "the text view already shows prompts.")
```

  - Replace `if not args.card and (args.style != "hero" or args.out):` with:

```python
    if not args.card and args.style != "hero":
        ap.error("--style applies only to --card.")
    if args.out and not (args.card or args.html):
        ap.error("--out applies only to --card or --html.")
```

  - `--out` help: "--card or --html: directory to write into (default:
    current directory)".
  - After the `if args.card:` block that sets `card_dir`, add:

```python
    if args.html:
        html_dir = Path(args.out).expanduser() if args.out else Path.cwd()
        if not html_dir.is_dir():
            print(f"actualis: {html_dir} is not a directory.\n"
                  "  --out takes the directory the report is written into.", file=sys.stderr)
            return EXIT_CANNOT_RUN
```

  - Dispatch, immediately before `if args.json:`:

```python
    if args.html:
        page = render_network_html(network_json(fleet, raw=args.no_redact),
                                   filters=network_filter_names(args), version=__version__,
                                   with_prompts=args.with_prompts)
        try:
            path = write_network_html(page, html_dir)
        except OSError as exc:
            print(f"actualis: cannot write the report to {html_dir}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_CANNOT_RUN
        print(path)
        if args.no_redact:
            print("actualis: --no-redact is on: this report may contain live secrets.",
                  file=sys.stderr)
        return EXIT_OK
```

- [ ] **Step 4:** Run the full suite: `python3 -m unittest discover -s tests
  -q`. Update any test that asserted the old "--style and --out apply only to
  --card." text. Expect PASS.
- [ ] **Step 5:** Commit: "Network: --html writes the report page".

### Task 5: Docs and spec amendments

**Files:** `README.md`, `actualis.py` (the `--explain network` text),
`docs/json.md`, `CHANGELOG.md`, and the spec (§9 amendments).

- [ ] **README:** under the network usage, add
  `actualis --network --html            # one self-contained page: charts, sortable tables`.
- [ ] **`--explain network`:** add the paragraph "--html writes the same
  report as one self-contained page (actualis-network.html, never
  overwritten, readable by you only). It loads nothing from the network, and
  it embeds the --network --json object, so every number can be checked."
- [ ] **`docs/json.md`:** add a note that `--network --html` embeds this
  object in `<script id="actualis-network">`.
- [ ] **CHANGELOG 0.3.0, Added:** "**`--network --html`** writes the network
  report as one offline page with charts, sortable tables and the `--json`
  object embedded. Never overwrites; mode 0600."
- [ ] **Spec:** append "## 9. Amendments during planning (2026-10-13)" with
  the four rulings listed under Review Focus.
- [ ] Run the full suite, an ASCII-terminal run of `--explain network`, and
  under Python 3.9 `tests.test_network_html`. Commit: "Network: document
  --html".

### Task 6: Verify on real data (aggregate only)

- [ ] Run `actualis --network --html --out "$SCRATCH"`. Check:
  - exit 0;
  - the file is 0600;
  - the page contains no `http` inside `href`/`src`;
  - the embedded JSON equals `--network --json`.
- [ ] Print only those booleans and the file size. Never print page content.
- [ ] Open a screenshot of the page at 1200px and 390px wide, and check
  there is no horizontal page scroll.
