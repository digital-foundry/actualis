Four correctness defects, all reproduced before being fixed. Two of them made
the tool state something arithmetically impossible on its own front page.

### Fixed

- **`--days N` reported N+1 active days.** The cutoff was a rolling timestamp,
  `now - N days`, which lands mid-day — so records from that partial date plus N
  further dates survived. A seven-day window reported eight active days, making
  the denominator of a headline rate exceed its own window. `--days N` now means
  the last N calendar days including today, in UTC, which is both what people
  mean by it and the only reading under which `active_days` is bounded by N.

- **"30 active days of 29".** The report compared a count of dates against an
  elapsed duration. Three consecutive dates span two days, so for any contiguous
  window the two differed by one, every time — off by one by construction, which
  reads as a bug because it is one. It now compares dates with dates
  (`span_dates`), and `span_days` keeps its old meaning with a docstring saying
  which is which.

- **Cache-write tokens with no TTL split were under-priced by 57%.** Older
  records carry only a flat `cache_creation_input_tokens`, so the multiplier is
  assumed, and it assumed 5m (1.25×). Measured across **71,903 deduplicated
  records that do carry the split, the real mix is 95.2% 1h and 4.8% 5m**. It
  now assumes 1h (2.00×) — the more expensive reading, matching how unknown
  model rates are handled. The assumed volume is counted as
  `tokens.cache_w_assumed` and shown in the report when non-zero, so the
  adjustment is never silent. On current transcripts it is zero.

### Added

- **AF012 — deduplication collapsed nothing, which should be impossible.**
  `docs/json.md` already said a zero repeat count on a large scan is suspicious.
  Nothing evaluated that sentence. If a transcript format stops carrying a
  message id, every record is billed again and cost silently doubles — the exact
  0.1.0 defect, reintroduced by a vendor change rather than by us. Now a
  critical finding above 500 messages.

- **AF013 — the rate table has not been checked in a long time.** Staleness
  already printed a line in the report, but a warning that exists only in
  rendered text is invisible to `--coach`, to `--json` and to the MCP server,
  which is where anything programmatic reads from.
