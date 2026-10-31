"""Synthetic host-reputation caches and a fake provider server, for the tests.

Every host is invented (*.example). The cache layout is the one the companion
writes (docs/reputation.md): gsb/state.json names one checksum-named prefix
file per list, gsb/confirmations.json, vt/results.json, network-log.jsonl.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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
                 cache_s: int = 1800, canary: bool = False) -> dict:
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


class FakeProvider:
    """A local stand-in for both providers. routes: {path: [(status, body bytes|dict)]},
    answered in order (the last one repeats). Records (method, path, query, headers)."""

    def __init__(self, routes: dict | None = None):
        self.routes = {k: list(v) for k, v in (routes or {}).items()}
        self.requests: list[dict] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                u = urlsplit(self.path)
                owner.requests.append({"path": u.path, "query": parse_qs(u.query),
                                       "headers": {k.lower(): v for k, v in self.headers.items()}})
                answers = owner.routes.get(u.path) or [(404, {"error": "no route"})]
                status, body = answers.pop(0) if len(answers) > 1 else answers[0]
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def factory(self, session):
        import actualis_reputation as ar
        netloc = f"127.0.0.1:{self.port}"
        # proxies={}: a developer's HTTPS_PROXY must not catch requests to the local fake.
        return ar.Http(session, endpoints={ar.GSB_HOST: netloc, ar.VT_HOST: netloc}, scheme="http", proxies={})

    def close(self):
        self.server.shutdown()
        self.server.server_close()
