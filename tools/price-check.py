#!/usr/bin/env python3
"""Check the rate table against its sources. A maintainer tool, not the CLI.

`actualis` makes no network calls. That is a promise, not a default, so the
refresh path lives here instead: a human runs this, reads the diff, and edits
PRICING by hand. Nothing writes a price automatically -- scraping a pricing page
into a cost tool is exactly how a wrong number acquires the authority of a
published one.

    python3 tools/price-check.py            # age and coverage, offline
    python3 tools/price-check.py --fetch    # also fetch sources and report drift

Without --fetch this makes no requests at all and still answers the question
that matters most: how stale is the table, and how much of a real fleet's spend
currently rests on an inference rather than a published price.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import actualis as A  # noqa: E402


def offline_report() -> int:
    age = A.pricing_age_days()
    stale = age > A.PRICING_STALE_DAYS
    print(f"\n  table verified {A.PRICING_VERIFIED}, {age} days ago"
          f"{'  ** STALE **' if stale else ''}")
    print(f"  stale after {A.PRICING_STALE_DAYS} days\n")

    by_tier: dict[str, list[str]] = {}
    for model, rate in sorted(A.PRICING.items()):
        by_tier.setdefault(rate.tier, []).append(model)
    print("  what the table contains, best-sourced first:")
    for tier in A.RATE_TIERS:
        models = by_tier.get(tier, [])
        if models:
            print(f"    {tier:<12} {len(models):>2}  {', '.join(models[:4])}"
                  + (" …" if len(models) > 4 else ""))
    weak = [m for m, r in A.PRICING.items() if not r.confident]
    if weak:
        print(f"\n  not from a provider's own price list ({len(weak)}):")
        for m in weak:
            print(f"    {m:<22}{A.PRICING[m].note}")

    print("\n  sources:")
    for k, v in A.RATE_SOURCES.items():
        print(f"    {k:<12} {v}")
    print("\n  Refreshing is manual on purpose. Read the source pages, edit PRICING,"
          "\n  and move PRICING_VERIFIED to today only if you actually checked.\n")
    return 1 if stale else 0


def fetch_report() -> int:
    """Fetch each source and report whether the models we price still appear.

    Deliberately weak: it reports presence and surrounding text, not a parsed
    price. Pricing pages are marketing pages, their markup changes without
    notice, and a scraper that silently mis-parses one is worse than no scraper.
    """
    import urllib.request

    print("\n  fetching sources (this is the only part that touches the network)\n")
    seen: dict[str, str] = {}
    for name, url in A.RATE_SOURCES.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "actualis-price-check"})
            with urllib.request.urlopen(req, timeout=20) as r:
                seen[name] = r.read().decode("utf-8", "replace")
            print(f"    {name:<12} {len(seen[name]):>8} bytes  {url}")
        except Exception as exc:
            print(f"    {name:<12} FAILED  {type(exc).__name__}: {exc}")

    if not seen:
        print("\n  no sources reachable; nothing to compare.\n")
        return 2

    print("\n  model ids not found on their provider's page — either renamed,")
    print("  retired, or the page changed shape. Check by hand:\n")
    missing = []
    for model, rate in sorted(A.PRICING.items()):
        body = seen.get(rate.provider)
        if body is None:
            continue
        # Model ids appear on pricing pages in several spellings.
        variants = {model, model.replace("-", " "), model.replace("-", ".")}
        if not any(v.lower() in body.lower() for v in variants):
            missing.append((model, rate))
            print(f"    {model:<22}{rate.tier:<12}{rate.note[:44]}")
    if not missing:
        print("    none — every priced model id still appears on its source page")
    print("\n  Presence is not confirmation of the NUMBER. This tool deliberately")
    print("  does not parse prices: a silently mis-parsed rate would carry the")
    print("  authority of a checked one. Read the pages.\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="price-check",
                                 description="Check the rate table against its sources.")
    ap.add_argument("--fetch", action="store_true",
                    help="also fetch the source pages (the only networked path)")
    args = ap.parse_args()
    code = offline_report()
    if args.fetch:
        code = fetch_report() or code
    return code


if __name__ == "__main__":
    raise SystemExit(main())
