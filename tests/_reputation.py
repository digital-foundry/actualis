"""Synthetic host-reputation caches and a fake provider server, for the tests.

Every host is invented (*.example). The cache layout is the one the companion
writes (docs/reputation.md): gsb/state.json names one checksum-named prefix
file per list, gsb/confirmations.json, vt/results.json, network-log.jsonl.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

LISTS = ("mw-4b", "se-4b", "uws-4b", "uwsa-4b", "pha-4b")


def full(expr: str) -> bytes:
    return hashlib.sha256(expr.encode()).digest()


def prefix(expr: str) -> bytes:
    return full(expr)[:4]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def write_cache(root: Path, lists: dict | None = None, *, fetched_at: datetime | None = None,
                confirmations=(), vt: list | None = None, vt_threshold: int = 2, log=()) -> Path:
    """lists: {list name: [4-byte prefixes]}; every list in LISTS is written."""
    gsb = root / "gsb"
    gsb.mkdir(parents=True, exist_ok=True)
    fetched_at = fetched_at or datetime.now(timezone.utc)
    entries = []
    for name in LISTS:
        blob = b"".join(sorted(set((lists or {}).get(name, []))))
        sha = hashlib.sha256(blob).hexdigest()
        fname = f"{name}.{sha[:16]}.prefixes"
        (gsb / fname).write_bytes(blob)
        entries.append({"name": name, "version": b64(name.encode()), "sha256": sha, "file": fname,
                        "fetched_at": iso(fetched_at),
                        "next_update_at": iso(fetched_at + timedelta(minutes=30)),
                        "prefix_count": len(blob) // 4})
    (gsb / "state.json").write_text(json.dumps({"schema": 1, "lists": entries}))
    if confirmations:
        (gsb / "confirmations.json").write_text(json.dumps({"schema": 1, "entries": list(confirmations)}))
    if vt is not None:
        (root / "vt").mkdir(exist_ok=True)
        (root / "vt" / "results.json").write_text(json.dumps(
            {"schema": 1, "vt_threshold": vt_threshold, "daily": {"date": "", "count": 0}, "results": vt}))
    if log:
        (root / "network-log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in log))
    return root


def confirmation(prefix_expr: str, *, listed=(), threat: str = "MALWARE", at: datetime | None = None,
                 cache_s: int = 300, canary: bool = False) -> dict:
    """A confirmations.json entry for the prefix of `prefix_expr`. `listed`:
    expressions whose full hashes the provider returned for it."""
    at = at or datetime.now(timezone.utc)
    return {"prefix": b64(prefix(prefix_expr)),
            "full_hashes": [{"hash": b64(full(e)), "threat_types": [] if canary else [threat],
                             "canary": canary} for e in listed],
            "confirmed_at": iso(at), "cache_until": iso(at + timedelta(seconds=cache_s))}


def vt_result(host: str, malicious: int = 0, suspicious: int = 0, *, status: str = "found",
              at: datetime | None = None) -> dict:
    return {"host": host, "status": status, "checked_at": iso(at or datetime.now(timezone.utc)),
            "stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 50,
                      "undetected": 20, "timeout": 0}}
