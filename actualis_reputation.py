#!/usr/bin/env python3
"""actualis-reputation: the only part of actualis that uses the network.

actualis itself never opens a socket (`actualis --self-check` proves it).
This companion downloads Google Safe Browsing threat lists, confirms local
matches with 4-byte hash prefixes, and (only when asked) looks hosts up on
VirusTotal. It writes the reputation cache that `actualis --reputation`
reads offline. Before any request it says what it will send, asks, shows a
live line while a request is in flight, and records what it did.

    actualis-reputation update      [--yes] [--dry-run] [--receipt FILE] [--key-command CMD]
    actualis-reputation confirm  NET.json   (same options)
    actualis-reputation virustotal NET.json [--vt-threshold N] (same options)
    actualis-reputation status
    actualis-reputation forget [--yes]

See docs/reputation.md. Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import actualis as af

__version__ = af.__version__
GSB_HOST = "safebrowsing.googleapis.com"
VT_HOST = "www.virustotal.com"
PROVIDERS = {"gsb": ("Google Safe Browsing", GSB_HOST, "ACTUALIS_GSB_KEY"),
             "vt": ("VirusTotal", VT_HOST, "ACTUALIS_VT_KEY")}
MARK = af.NET_MARK
LIST_RESPONSE_MAX = 64 << 20
SMALL_RESPONSE_MAX = 1 << 20
MAX_WAIT = 86400.0                                # a server-set refresh wait is clamped to 24 h
REPORT_MAX = 256 << 20
TIMEOUT = 30
EXIT_OK, EXIT_RUNTIME, EXIT_USAGE = 0, 1, 2
CACHE_FILES = ("gsb/state.json", "gsb/confirmations.json", "vt/results.json", "network-log.jsonl",
               "in-flight.json")


class UsageError(Exception):
    """Exit 2: nothing was sent."""


class NetError(Exception):
    """Exit 1: a request failed, a quota was hit, or a response was bad."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


class Scrubber:
    """Replaces every form of every secret it has seen with ***."""

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def add(self, secret: str) -> None:
        if secret:
            forms = {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)}
            self._secrets = sorted(set(self._secrets) | forms, key=len, reverse=True)

    def __call__(self, text: object) -> str:
        text = str(text)
        for s in self._secrets:
            text = text.replace(s, "***")
        return text


_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-")


def _key_shaped(key: str) -> bool:
    return 16 <= len(key) <= 512 and all(ch in _KEY_CHARS for ch in key)


def need_consent_possible(args, ctx) -> None:
    """Refuse a run that consent would refuse, before any key is read (so a
    --key-command never runs for it)."""
    if not (args.dry_run or args.yes or (ctx["stdin"] is not None and ctx["stdin"].isatty())):
        raise UsageError("nothing sent: there is no terminal to ask. Pass --yes to send, "
                         "or --dry-run to see exactly what would be sent.")


def read_key(provider: str, key_command: "str | None", scrub: Scrubber, env=os.environ) -> str:
    label, _host, var = PROVIDERS[provider]
    if key_command:
        try:
            argv = shlex.split(key_command)
        except ValueError as exc:
            raise UsageError(f"--key-command: {exc}") from None
        if not argv:
            raise UsageError("--key-command is empty")
        if len(argv) == 1 and _key_shaped(argv[0]):
            raise UsageError("--key-command looks like a key, not a command; pass a command that prints "
                             "the key (for example `op read ...`), or set the key variable instead")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=120)   # noqa: S603 (no shell)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UsageError(f"--key-command could not run ({type(exc).__name__})") from None
        key = r.stdout.strip()
        if r.returncode != 0:
            if _key_shaped(key):
                scrub.add(key)
            raise UsageError(f"--key-command exited {r.returncode}; its output is not shown") from None
    else:
        key = env.get(var, "").strip()
    if not key:
        raise UsageError(f"no {label} key: set ${var} or pass --key-command CMD (see docs/reputation.md)")
    if not _key_shaped(key):
        raise UsageError(f"the {label} key is not shaped like an API key (16 to 512 letters, digits, "
                         f". _ ~ -); check --key-command or ${var}")
    scrub.add(key)
    return key


def _key_line(args, provider: str) -> str:
    """The disclosure's Key line. Says whether the variable is set; never its value."""
    if args.dry_run:
        return "(not read: --dry-run)"
    if args.key_command:
        return "--key-command (not shown)"
    var = PROVIDERS[provider][2]
    return f"${var} (set, not shown)" if os.environ.get(var, "").strip() else f"${var} (not set)"


def cache_root() -> Path:
    return af.reputation_dir()


def ensure_dir(path: Path) -> None:
    """Create `path` (0700) and refuse it if it, or the cache root, is a symlink."""
    root = cache_root()
    chain = [root]
    try:
        rel = path.relative_to(root)
        chain += [root.joinpath(*rel.parts[:i]) for i in range(1, len(rel.parts) + 1)]
    except ValueError:
        chain.append(path)
    for p in chain:                                # before mkdir: create nothing through a link
        if os.path.islink(p):
            raise NetError(f"{p} is a symlink; refusing to write through it")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        for p in chain:
            os.chmod(p, 0o700)


def write_atomic(path: Path, data: bytes) -> None:
    """Write to a temp file in the same directory, fsync, rename. 0600, never
    through a symlink."""
    ensure_dir(path.parent)
    if os.path.islink(path):
        raise NetError(f"{path.name} is a symlink; refusing to write through it")
    tmp = path.parent / f".tmp-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, obj) -> None:
    write_atomic(path, (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode())


def disclose(lines: "list[tuple[str, str]]", out) -> None:
    """The block printed before the first byte is sent (spec 6.2)."""
    out.write(f"{MARK} actualis-reputation uses the network.\n")
    for label, text in lines:
        for k, part in enumerate(text.split("\n")):
            out.write(f"  {label if k == 0 else '':<9} {part}\n")
    out.flush()


def consent(question: str, *, yes: bool, dry_run: bool, stdin, out) -> bool:
    if dry_run:
        return False
    if yes:
        return True
    if not (stdin is not None and stdin.isatty()):
        raise UsageError("nothing sent: there is no terminal to ask. Pass --yes to send, "
                         "or --dry-run to see exactly what would be sent.")
    out.write(f"{question} [y/N] ")
    out.flush()
    try:
        answer = stdin.readline()
    except (KeyboardInterrupt, EOFError):
        answer = ""
    return answer.strip().lower() in ("y", "yes")


class NetSession:
    """One run's network use: the live line, the closing summary (printed on
    success, failure and Ctrl-C), the receipt, the network-use log and the
    tray's in-flight marker."""

    def __init__(self, command: str, provider: str, scrub: Scrubber, *, receipt: "str | None", out) -> None:
        self.command, self.provider, self.scrub, self.receipt, self.out = command, provider, scrub, receipt, out
        self.requests: list[dict] = []
        self.failure: str | None = None
        self.started = _now()
        self._live = False
        self._flight = False

    def __enter__(self) -> "NetSession":
        try:
            write_json(cache_root() / "in-flight.json",
                       {"pid": os.getpid(), "provider": self.provider, "started_at": _iso(self.started)})
            self._flight = True
        except (OSError, NetError):
            pass                                  # the tray badge is a courtesy; never block on it
        return self

    def live(self, text: str) -> None:
        self.out.write(f"{MARK} {text}\n")
        self.out.flush()
        self._live = True

    def live_done(self) -> None:
        self._live = False

    def record(self, row: dict) -> None:
        self.requests.append(json.loads(self.scrub(json.dumps(row))))

    def fail(self, reason: str) -> None:
        self.failure = self.scrub(reason)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._flight:
            try:
                os.unlink(cache_root() / "in-flight.json")
            except OSError:
                pass
        if exc_type is KeyboardInterrupt and not self.failure:
            self.failure = "interrupted"
        elif exc_type is not None and not self.failure:
            self.failure = self.scrub(exc_type.__name__)
        hosts = sorted({r["host"] for r in self.requests})
        n = len(self.requests)
        if n:
            line = (f"{MARK} network used: {n} request{'' if n == 1 else 's'} to {', '.join(hosts)}, "
                    f"nothing else contacted")
        else:
            line = f"{MARK} network used: nothing sent"
        if self.failure:
            line += f" (stopped: {self.failure})"
        self.out.write(self.scrub(line) + "\n")
        self.out.flush()
        if self.receipt:
            try:
                body = self.scrub(json.dumps(
                    {"command": self.command, "provider": self.provider, "started_at": _iso(self.started),
                     "finished_at": _iso(_now()), "requests": self.requests, "failure": self.failure},
                    indent=1)) + "\n"
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) \
                    | getattr(os, "O_BINARY", 0)
                fd = os.open(self.receipt, flags, 0o600)
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)            # a receipt that already existed ends up 0600 too
                with os.fdopen(fd, "wb") as fh:
                    fh.write(body.encode())
            except OSError as e:
                self.out.write(f"actualis-reputation: cannot write the receipt: {e.strerror or e}\n")
        if n:
            sent = {"gsb": "prefixes" if self.command == "confirm" else "list-diff", "vt": "hostnames"}[self.provider]
            self._log({"at": _iso(self.started), "command": self.command, "provider": self.provider,
                       "contacted": hosts, "requests": n, "sent": sent})

    def _log(self, rec: dict) -> None:
        path = cache_root() / "network-log.jsonl"
        try:
            ensure_dir(path.parent)
            if os.path.islink(path):
                return
            if path.exists() and path.stat().st_size > (1 << 20):
                keep = path.read_text(errors="replace").splitlines()[-500:]
                write_atomic(path, ("\n".join(keep) + "\n").encode())
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except (OSError, NetError):
            pass


def read_report(path: str, stdin) -> dict:
    """The network object from `actualis --network --json` (or the full --json
    payload's network key)."""
    try:
        if path == "-":
            raw = (stdin or sys.stdin).read(REPORT_MAX + 1)
        else:
            with af._open_regular(Path(path)) as fh:
                raw = fh.read(REPORT_MAX + 1)
    except OSError as exc:
        raise UsageError(f"cannot read the report file: {exc.strerror or exc}") from None
    if len(raw) > REPORT_MAX:
        raise UsageError(f"the report file is over {REPORT_MAX >> 20} MiB")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise UsageError("the report file is not JSON; pass the output of actualis --network --json") from None
    net = doc.get("network", doc) if isinstance(doc, dict) else None
    if not isinstance(net, dict) or not isinstance(net.get("hosts"), list):
        raise UsageError("the report file is not actualis --network --json output")
    return net


def cmd_status(args, ctx) -> int:
    out = ctx["stdout"]
    data = af.load_reputation()
    out.write(f"cache: {data.directory}\n")
    out.write(f"Google Safe Browsing lists: {data.status}" + (f" ({data.error})" if data.error else "") + "\n")
    for name, st in sorted(data.state.items()):
        nxt = st["next_update_at"]
        out.write(f"  {name:<8} {st['prefix_count']:>9,} prefixes  fetched {_iso(st['fetched_at'])}"
                  + (f"  next refresh allowed {_iso(nxt)}" if nxt else "") + "\n")
    now = _now()
    fresh = sum(1 for c in data.confirmations.values() if af._confirmation_fresh(c, now))
    out.write(f"confirmations: {len(data.confirmations)} stored, {fresh} fresh (under 30 minutes)\n")
    out.write(f"VirusTotal results: {len(data.vt)}\n")
    last = data.last_network
    out.write(f"{MARK} network last used: " + (f"{last['at']} ({last['provider']})" if last else "never") + "\n")
    return EXIT_OK


def cmd_forget(args, ctx) -> int:
    root = cache_root()
    if os.path.islink(root):
        raise UsageError(f"{root} is a symlink; refusing to delete through it")
    if not root.exists():
        ctx["stdout"].write("nothing to forget\n")
        return EXIT_OK
    if not consent(f"Delete the reputation cache in {root}?", yes=args.yes, dry_run=False,
                   stdin=ctx["stdin"], out=ctx["stderr"]):
        ctx["stderr"].write("nothing deleted\n")
        return EXIT_OK
    removed = 0
    subdirs = []
    for name in ("gsb", "vt"):
        if os.path.islink(root / name):
            ctx["stderr"].write(f"skipped {root / name}: it is a symlink; nothing was deleted through it\n")
        else:
            subdirs.append(root / name)
    live = [root] + subdirs
    targets = [root / f for f in CACHE_FILES if os.path.dirname(f) == "" or root / os.path.dirname(f) in subdirs] \
        + (list((root / "gsb").glob("*.prefixes")) if root / "gsb" in subdirs else []) \
        + [p for d in live if d.is_dir() for p in d.glob(".tmp-*")]
    for p in targets:
        try:
            if p.is_file() or p.is_symlink():
                p.unlink()
                removed += 1
        except OSError:
            pass
    for d in (*reversed(subdirs), root):
        try:
            d.rmdir()
        except OSError:
            pass                                   # not empty: something that is not ours stays
    ctx["stdout"].write(f"deleted {removed} file(s) from {root}\n")
    return EXIT_OK


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):                # never echo arguments: one may be a key
        if message.startswith("argument ") and ": " in message:
            head, tail = message.split(": ", 1)
            for q in ("'", '"'):                  # drop anything quoted: it may be a key
                tail = tail.split(q)[0]
            message = f"{head}: {tail.strip(' :')}"
        elif ": " in message:
            message = message.split(": ", 1)[0]
        else:
            message = "".join(message.split("'")[0:1]).rstrip()
        message += " (the value is not repeated here, in case it is a key)"
        super().error(message)


def _threshold(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number from 1 to 100") from None
    if not 1 <= n <= 100:
        raise argparse.ArgumentTypeError("a whole number from 1 to 100")
    return n


def build_parser() -> argparse.ArgumentParser:
    ap = _Parser(prog="actualis-reputation", allow_abbrev=False,
                 description="The only part of actualis that uses the network. See docs/reputation.md.")
    ap.add_argument("--version", action="version", version=f"actualis-reputation {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def common(p):
        p.add_argument("--yes", action="store_true", help="send without asking (needed without a terminal)")
        p.add_argument("--dry-run", action="store_true", help="print exactly what would be sent; send nothing")
        p.add_argument("--receipt", metavar="FILE", help="write every request made (no key) to FILE as JSON")
        p.add_argument("--key-command", metavar="CMD",
                       help="run CMD (no shell) and use its output as the key, e.g. \"op read op://…\"")

    common(sub.add_parser("update", allow_abbrev=False, help="download Safe Browsing list updates"))
    cf = sub.add_parser("confirm", allow_abbrev=False, help="confirm local candidates with Google (prefixes only)")
    cf.add_argument("report", metavar="NET.json", help="actualis --network --reputation --json output, or -")
    common(cf)
    vt = sub.add_parser("virustotal", allow_abbrev=False, help="look hostnames up on VirusTotal (sends hostnames)")
    vt.add_argument("report", metavar="NET.json", help="actualis --network --json output, or -")
    vt.add_argument("--vt-threshold", type=_threshold, default=None, metavar="N",
                    help="engines flagging malicious for a high finding (default 2; kept from the last run)")
    common(vt)
    sub.add_parser("status", allow_abbrev=False, help="lists, ages, last network use; never networks")
    fg = sub.add_parser("forget", allow_abbrev=False, help="delete the reputation cache")
    fg.add_argument("--yes", action="store_true", help="delete without asking")
    return ap


# http.client's base error, reached through urllib.request (which imports it), so
# this module's import list stays unchanged. Covers BadStatusLine and friends.
_HTTPException = urllib.request.http.client.HTTPException


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is returned as an error, never followed: a redirect could lead
    anywhere, and only the two provider hosts may be contacted."""

    def redirect_request(self, *args, **kwargs):
        return None


def _read_capped(resp, limit: int) -> bytes:
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise NetError(f"the response is over {max(limit >> 20, 1)} MiB; refusing it")
    return data


class Http:
    """HTTPS GETs to the two provider hosts and nothing else, with certificate
    verification, no redirects, a timeout and a size cap. Each request is
    shown while in flight and recorded for the receipt."""

    def __init__(self, session: NetSession, *, endpoints: "dict | None" = None,
                 context: "ssl.SSLContext | None" = None, scheme: str = "https",
                 proxies: "dict | None" = None) -> None:
        if scheme not in ("https", "http"):
            raise ValueError("scheme must be https or http")
        self.session = session
        self.endpoints = dict(endpoints or {GSB_HOST: GSB_HOST, VT_HOST: VT_HOST})
        self.context = context or ssl.create_default_context()
        self.scheme = scheme
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=self.context)]
        if proxies is not None:                  # None: honour HTTPS_PROXY and the system settings
            handlers.append(urllib.request.ProxyHandler(proxies))
        self.opener = urllib.request.build_opener(*handlers)

    def get(self, host: str, path: str, *, query=(), headers: "dict | None" = None,
            limit: int = SMALL_RESPONSE_MAX, sent: dict, describe: str) -> "tuple[int, bytes]":
        if host not in self.endpoints:
            raise NetError(f"refusing to contact {host}: only {', '.join(sorted(self.endpoints))}")
        url = f"{self.scheme}://{self.endpoints[host]}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(list(query))
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": f"actualis-reputation/{__version__}", "Accept": "application/json", **(headers or {})})
        status, body = 0, b""
        self.session.live(f"{describe} -> {host}")
        try:
            try:
                # https to the two pinned provider hosts only (checked above), no redirects
                with self.opener.open(req, timeout=TIMEOUT) as resp:  # nosec B310
                    status = resp.status
                    body = _read_capped(resp, limit)
            except urllib.error.HTTPError as exc:
                status = exc.code
                try:
                    body = _read_capped(exc, SMALL_RESPONSE_MAX) if exc.fp else b""
                finally:
                    exc.close()
            except (urllib.error.URLError, OSError, ValueError, _HTTPException) as exc:
                reason = getattr(exc, "reason", exc)
                raise NetError(self.session.scrub(f"cannot reach {host}: {reason}")) from None
        finally:
            self.session.live_done()
            self.session.record({"method": "GET", "host": host, "path": path, "sent": sent,
                                 "status": status, "bytes": len(body), "at": _iso(_now())})
        return status, body


GSB_BATCH_PATH = "/v5/hashLists:batchGet"


def _b64(text: object) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 text")
    pad = "=" * (-len(text) % 4)
    if "-" in text or "_" in text:
        return base64.urlsafe_b64decode(text + pad)
    return base64.b64decode(text + pad, validate=True)


def parse_duration(text: object) -> float:
    """A protobuf Duration ("3.5s") in seconds; 0.0 for anything else."""
    if not isinstance(text, str) or not text.endswith("s") or len(text) > 32:
        return 0.0
    try:
        v = float(text[:-1])
    except ValueError:
        return 0.0
    return min(v, MAX_WAIT) if math.isfinite(v) and v > 0 else 0.0


def rice_decode(first_value: int, k: int, count: int, data: bytes) -> "list[int]":
    """Golomb-Rice deltas as Google encodes them: per entry a unary quotient
    (1s ended by a 0) then k remainder bits, least significant bit first,
    bytes little-endian; each value is the previous plus (q << k | r)."""
    if not 0 <= first_value <= 0xFFFFFFFF:
        raise ValueError("first value is not a uint32")
    if count and not 3 <= k <= 30:
        raise ValueError(f"rice parameter {k} is outside 3..30")
    if count > len(data) * 8:
        raise ValueError("more entries than encoded bits")
    out, v, pos, nbits = [first_value], first_value, 0, len(data) * 8
    for _ in range(count):
        q = 0
        while True:
            if pos >= nbits:
                raise ValueError("encoded data ends early")
            bit = (data[pos >> 3] >> (pos & 7)) & 1
            pos += 1
            if not bit:
                break
            q += 1
            if v + (q << k) > 0xFFFFFFFF:          # bounds the loop: a longer run must overflow
                raise ValueError("value overflows 32 bits")
        if pos + k > nbits:
            raise ValueError("encoded data ends early")
        r = 0
        for i in range(k):
            r |= ((data[pos >> 3] >> (pos & 7)) & 1) << i
            pos += 1
        v += (q << k) | r
        if v > 0xFFFFFFFF:
            raise ValueError("value overflows 32 bits")
        out.append(v)
    return out


def _rice_field(obj: object) -> "list[int]":
    if obj is None:
        return []
    if not isinstance(obj, dict):
        raise ValueError("a Rice field is not an object")
    try:
        first = int(obj.get("firstValue") or 0)
        k = int(obj.get("riceParameter") or 0)
        n = int(obj.get("entriesCount") or 0)
    except (TypeError, ValueError):
        raise ValueError("a Rice field has a non-numeric parameter") from None
    data = _b64(obj.get("encodedData") or "")
    if n < 0:
        raise ValueError("negative entry count")
    return rice_decode(first, k, n, data)


def apply_list_update(old: bytes, hl: dict) -> bytes:
    """The new sorted list after one HashList: a full list replaces `old`; a
    partial one removes by index, then adds. The caller checks the checksum."""
    for wide in ("additionsEightBytes", "additionsSixteenBytes", "additionsThirtyTwoBytes"):
        if wide in hl:
            raise ValueError(f"{wide}: only 4-byte lists are supported")
    partial = hl.get("partialUpdate") is True
    entries = [old[i:i + 4] for i in range(0, len(old), 4)] if partial else []
    if partial:
        removals = _rice_field(hl.get("compressedRemovals"))
        if removals:
            drop = set(removals)
            if max(drop) >= len(entries):
                raise ValueError("a removal index is past the end of the list")
            entries = [e for i, e in enumerate(entries) if i not in drop]
    entries += [v.to_bytes(4, "big") for v in _rice_field(hl.get("additionsFourBytes"))]
    entries.sort()
    return b"".join(entries)


def _verify(blob: bytes, hl: dict, old: bytes) -> bool:
    if "sha256Checksum" not in hl:
        # No checksum means no change was sent; the list must then be the old one.
        return blob == old
    return hashlib.sha256(blob).digest() == _b64(hl["sha256Checksum"])


def _gsb_status(status: int, body: bytes) -> None:
    if status == 200:
        return
    hint = {400: "the request was refused", 401: "the key was rejected",
            403: "the key was rejected or the Safe Browsing API is not enabled for its project",
            429: "quota reached; try again later"}
    raise NetError(f"Safe Browsing answered HTTP {status}: {hint.get(status, 'server error')}")


def _batch(http: Http, key: str, names: "list[str]", versions: dict, describe: str) -> "list[dict]":
    query = [("names", n) for n in names] + [("version", versions[n]) for n in names if versions.get(n)]
    status, body = http.get(GSB_HOST, GSB_BATCH_PATH, query=query, headers={"X-Goog-Api-Key": key},
                            limit=LIST_RESPONSE_MAX, sent={"list_update": names}, describe=describe)
    _gsb_status(status, body)
    try:
        lists = json.loads(body)["hashLists"]
        if (not isinstance(lists, list) or len(lists) != len(names)
                or not all(isinstance(h, dict) for h in lists)):
            raise ValueError
    except (ValueError, KeyError, TypeError, RecursionError):
        raise NetError("Safe Browsing sent a response that is not a hash list") from None
    return lists


def _check_names(names: "list[str]", lists: "list[dict]") -> None:
    """Lists are paired with the requested names by position; refuse a reply
    whose names do not match, so a reordered reply cannot be stored under the wrong list."""
    for name, hl in zip(names, lists):
        if hl.get("name") != name:
            raise NetError("Safe Browsing sent its lists in an unexpected order or with other names")


def _apply_checked(old: bytes, hl: dict) -> "bytes | None":
    """The new list if it applies and matches its checksum, else None."""
    try:
        blob = apply_list_update(old, hl)
        return blob if _verify(blob, hl, old) else None
    except (ValueError, TypeError):
        return None


def cmd_update(args, ctx) -> int:
    out, scrub, now = ctx["stderr"], ctx["scrub"], ctx["now"]()
    data = af.load_reputation()
    state = data.state if data.status == "ok" else {}
    due = [n for n in af.REPUTATION_LISTS
           if n not in state or not state[n]["next_update_at"] or state[n]["next_update_at"] <= now]
    if not due:
        nxt = min(s["next_update_at"] for s in state.values())
        out.write(f"lists are current (next refresh allowed at {_iso(nxt)}); no request sent\n")
        return EXIT_OK
    first = not state
    disclose([("Provider", "Google Safe Browsing v5, list download"),
              ("Sends", "nothing about your hosts: downloads list updates"
                        + (" (full lists on this first run)" if first else "")),
              ("Never", "commands, paths, query strings, credentials, transcript text"),
              ("Key", _key_line(args, "gsb"))], out)
    if args.dry_run:
        out.write(f"would request: GET https://{GSB_HOST}{GSB_BATCH_PATH} for {', '.join(due)}\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    need_consent_possible(args, ctx)               # before any key command runs
    key = read_key("gsb", args.key_command, scrub)
    if not consent("Download Safe Browsing list updates from Google?", yes=args.yes, dry_run=False,
                   stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    versions = {n: state[n]["version"] for n in due if n in state and state[n].get("version")}
    with NetSession("update", "gsb", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            new: "dict[str, tuple[bytes, dict]]" = {}
            lists = _batch(http, key, due, versions, f"downloading {len(due)} list update(s)")
            retry = []
            _check_names(due, lists)
            for name, hl in zip(due, lists):
                blob = _apply_checked(data.lists.get(name, b""), hl)
                if blob is None:
                    retry.append(name)
                else:
                    new[name] = (blob, hl)
            if retry:
                lists = _batch(http, key, retry, {}, f"checksum mismatch: downloading {len(retry)} full list(s)")
                _check_names(retry, lists)
                for name, hl in zip(retry, lists):
                    blob = _apply_checked(b"", {**hl, "partialUpdate": False})
                    if blob is None or "sha256Checksum" not in hl:
                        raise NetError(f"{name}: the full list failed its checksum; nothing was written")
                    new[name] = (blob, hl)
            _commit_lists(data, state, new, now)
        except (NetError, OSError) as exc:
            session.fail(str(exc))
            raise
    return EXIT_OK


def _clean_version(version: object) -> "str | None":
    """The list version to store: a short base64 string, else None (which
    forces a full fetch next time)."""
    if not isinstance(version, str) or len(version) > 4096:
        return None
    try:
        _b64(version)
    except ValueError:
        return None
    return version


def _commit_lists(data, state: dict, new: dict, now: datetime) -> None:
    """Write each changed list under a checksum name, then state.json last
    (the commit point), then remove list files nothing names."""
    gsb = cache_root() / "gsb"
    entries = []
    for name in af.REPUTATION_LISTS:
        if name in new:
            blob, hl = new[name]
            sha = hashlib.sha256(blob).hexdigest()
            fname = f"{name}.{sha[:16]}.prefixes"
            write_atomic(gsb / fname, blob)
            wait = parse_duration(hl.get("minimumWaitDuration"))
            entries.append({"name": name, "version": _clean_version(hl.get("version")), "sha256": sha, "file": fname,
                            "fetched_at": _iso(now), "next_update_at": _iso(now + timedelta(seconds=wait)),
                            "prefix_count": len(blob) // 4})
        else:
            st = state[name]
            sha = hashlib.sha256(data.lists[name]).hexdigest()
            entries.append({"name": name, "version": st.get("version"), "sha256": sha,
                            "file": f"{name}.{sha[:16]}.prefixes", "fetched_at": _iso(st["fetched_at"]),
                            "next_update_at": _iso(st["next_update_at"]) if st["next_update_at"] else _iso(now),
                            "prefix_count": st["prefix_count"]})
    write_json(gsb / "state.json", {"schema": 1, "lists": entries})
    keep = {e["file"] for e in entries}
    for p in gsb.glob("*.prefixes"):
        if p.name not in keep:
            try:
                p.unlink()
            except OSError:
                pass


GSB_SEARCH_PATH = "/v5/hashes:search"
DECOY_TOTAL = 30
SEARCH_REAL_MAX = 970                            # a request is topped up to 30 prefixes with decoys, so
                                                 # it holds at most 970 real ones; a full chunk gets 0 decoys
ENFORCEABLE = frozenset({"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"})


def make_decoys(real: "set[bytes]", total: int, pool: "list[bytes] | None" = None,
                avoid: "set[bytes] | None" = None) -> "list[bytes]":
    """Decoy prefixes so that real + decoys reach `total`. They are drawn from
    `pool` (the downloaded lists, as blobs of 4-byte records), so they look like
    real list entries; random bytes only fill a shortfall. Never a real prefix
    (`real`, or anything in `avoid`), never a duplicate."""
    out: "set[bytes]" = set()
    need = max(0, total - len(real))
    banned = set(real) | set(avoid or ())
    n = sum(len(b) // 4 for b in pool or ())
    rng = secrets.SystemRandom()
    tries = 0
    while len(out) < need and n and tries < need * 20 + 100:
        tries += 1
        i = rng.randrange(n)
        for blob in pool or ():
            if i < len(blob) // 4:
                d = blob[4 * i:4 * i + 4]
                break
            i -= len(blob) // 4
        if d not in banned and d not in out:
            out.add(d)
    while len(out) < need:
        d = secrets.token_bytes(4)
        if d not in banned and d not in out:
            out.add(d)
    return sorted(out)


def _window(seconds: float) -> str:
    s = int(seconds)
    if s % 60 == 0:
        return f"{s // 60} minute{'' if s == 60 else 's'}"
    return f"{s} seconds"


def _candidates(net: dict) -> "list[bytes]":
    rep = net.get("reputation")
    if not isinstance(rep, dict) or not rep.get("enabled"):
        raise UsageError("this report has no reputation data; make it with actualis --network --reputation --json")
    out = set()
    for c in rep.get("candidates") or []:
        try:
            p = _b64(c.get("prefix_b64")) if isinstance(c, dict) else b""
        except ValueError:
            continue
        if len(p) == 4:
            out.add(p)
    return sorted(out)


def cmd_confirm(args, ctx) -> int:
    out, scrub = ctx["stderr"], ctx["scrub"]
    net = read_report(args.report, ctx["stdin"])
    real = _candidates(net)
    if not real:
        out.write(f"no candidates to confirm; {MARK} network used: nothing sent\n")
        return EXIT_OK
    chunks = [real[i:i + SEARCH_REAL_MAX] for i in range(0, len(real), SEARCH_REAL_MAX)]
    decoy_counts = [max(0, DECOY_TOTAL - len(c)) for c in chunks]
    totals = (net.get("reputation") or {}).get("totals")
    skipped = totals.get("skipped", 0) if isinstance(totals, dict) else 0
    plural = "" if len(real) == 1 else "s"
    disclose([("Provider", "Google Safe Browsing v5, hash-prefix lookup"),
              ("Sends", f"4-byte SHA-256 prefixes for {len(real)} candidate{plural}, "
                        f"mixed with {sum(decoy_counts)} random decoys drawn from the downloaded lists.\nGoogle never sees a host or URL."),
              ("Skips", f"{skipped} private or local hosts"),
              ("Never", "commands, paths, query strings, credentials, transcript text"),
              ("Key", _key_line(args, "gsb"))], out)
    if args.dry_run:
        for c, d in zip(chunks, decoy_counts):
            out.write(f"would send: {', '.join(base64.b64encode(p).decode() for p in c)} "
                      f"+ {d} random decoys\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    need_consent_possible(args, ctx)               # before any key command runs
    key = read_key("gsb", args.key_command, scrub)
    if not consent(f"Send {len(real)} lookup{plural} to Google?", yes=args.yes,
                   dry_run=False, stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    now = ctx["now"]()
    entries: "dict[str, dict]" = {}
    try:
        pool = [b for b in af.load_reputation().lists.values() if b]
    except (OSError, ValueError, RecursionError):
        pool = []
    window = float(af.REPUTATION_CONFIRM_TTL)
    allreal = set(real)
    with NetSession("confirm", "gsb", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            for chunk, nd in zip(chunks, decoy_counts):
                mine = set(chunk)
                sendable = chunk + make_decoys(mine, len(chunk) + nd, pool, allreal)
                secrets.SystemRandom().shuffle(sendable)
                status, body = http.get(
                    GSB_HOST, GSB_SEARCH_PATH, headers={"X-Goog-Api-Key": key},
                    query=[("hashPrefixes", base64.b64encode(p).decode()) for p in sendable],
                    sent={"prefixes": len(chunk), "decoys": nd},
                    describe=f"sending {len(chunk)} lookup(s)")
                _gsb_status(status, body)
                try:
                    doc = json.loads(body or b"{}")
                    found = doc.get("fullHashes") or []
                    if not isinstance(found, list):
                        raise ValueError
                except (ValueError, AttributeError, RecursionError):
                    raise NetError("Safe Browsing sent a search response that is not JSON") from None
                cache_s = parse_duration(doc.get("cacheDuration"))
                window = min(window, cache_s)
                until = now + timedelta(seconds=cache_s)
                by_prefix: "dict[bytes, list]" = {p: [] for p in chunk}
                for fh in found:
                    try:
                        h = _b64(fh.get("fullHash"))
                    except (ValueError, AttributeError):
                        continue
                    if len(h) != 32 or h[:4] not in mine:
                        continue                         # a decoy's answer, or junk: dropped
                    types, canary = set(), False
                    details = fh.get("fullHashDetails")
                    for det in details if isinstance(details, list) else []:
                        if not isinstance(det, dict) or not isinstance(det.get("threatType"), str):
                            continue
                        if det["threatType"] not in ENFORCEABLE:
                            continue
                        attrs = det.get("attributes")
                        attrs = {a for a in attrs if isinstance(a, str)} if isinstance(attrs, list) else set()
                        if "THREAT_ATTRIBUTE_UNSPECIFIED" in attrs:
                            continue
                        if "CANARY" in attrs:
                            canary = True
                            continue
                        types.add(det["threatType"])
                    by_prefix[h[:4]].append({"hash": base64.b64encode(h).decode(),
                                             "threat_types": sorted(types), "canary": canary})
                for p, hashes in by_prefix.items():
                    entries[base64.b64encode(p).decode()] = {
                        "prefix": base64.b64encode(p).decode(), "full_hashes": hashes,
                        "confirmed_at": _iso(now), "cache_until": _iso(until)}
        except NetError as exc:
            session.fail(str(exc))
            raise
        finally:
            if entries:
                _merge_confirmations(entries, now, out)
    listed = sum(1 for e in entries.values() if any(fh["threat_types"] for fh in e["full_hashes"]))
    if window > 0:
        tail = f"run actualis again within {_window(window)} to see the result."
    else:
        tail = "Google gave no cache time; this result cannot be used to mark a host listed."
    out.write(f"{len(entries)} candidate(s) confirmed: {listed} listed; {tail}\n")
    return EXIT_OK


def _merge_confirmations(new: dict, now: datetime, out) -> None:
    path = cache_root() / "gsb" / "confirmations.json"
    old = {}
    try:
        for p, e in af._load_confirmations(path).items():
            if now - e["confirmed_at"] < timedelta(hours=24):
                old[base64.b64encode(p).decode()] = {
                    "prefix": base64.b64encode(p).decode(),
                    "full_hashes": [{"hash": base64.b64encode(fh["hash"]).decode(),
                                     "threat_types": fh["threat_types"], "canary": fh["canary"]}
                                    for fh in e["full_hashes"]],
                    "confirmed_at": _iso(e["confirmed_at"]), "cache_until": _iso(e["cache_until"])}
    except (OSError, ValueError, RecursionError):
        old = {}
        out.write("actualis-reputation: the earlier confirmations file could not be read; "
                  "its entries were dropped\n")
    old.update(new)
    write_json(path, {"schema": 1, "entries": [old[k] for k in sorted(old)]})


VT_PER_MINUTE = 4
VT_DAILY = 500
VT_RECHECK = timedelta(hours=24)
VT_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def _public_hosts(net: dict) -> "tuple[list[str], int, int]":
    """(sorted canonical public hostnames, private or local count, unusable-name
    count). A name goes into a URL path, so only a canonical form is sent."""
    hosts, private, unusable = set(), 0, 0
    for h in net.get("hosts") or []:
        name = h.get("host") if isinstance(h, dict) else None
        if not isinstance(name, str):
            continue
        canon = af._host_canon(name)
        if canon is None or canon != name.lower():
            unusable += 1
        elif af.reputation_skip(canon):
            private += 1
        else:
            hosts.add(canon)
    return sorted(hosts), private, unusable


def _vt_doc(out=None) -> dict:
    path = cache_root() / "vt" / "results.json"
    try:
        raw = af._read_cache_file(path)
        doc = json.loads(raw) if raw else None
    except (OSError, ValueError, RecursionError):
        doc = False
    if (doc is not None and (not isinstance(doc, dict) or doc.get("schema") != 1
                             or not isinstance(doc.get("results"), list)
                             or not isinstance(doc.get("daily"), dict))):
        doc = False
    if doc is False and out is not None:
        out.write("actualis-reputation: the earlier VirusTotal results file could not be read; "
                  "its results and today's count were reset\n")
    if not doc:
        doc = {"schema": 1, "vt_threshold": 2, "daily": {"date": "", "count": 0}, "results": []}
    return doc


def _vt_stats(body: bytes) -> "dict | None":
    try:
        stats = json.loads(body)["data"]["attributes"]["last_analysis_stats"]
        if not isinstance(stats, dict):
            return None
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return None
    clean = {}
    for k in VT_STAT_KEYS:
        v = stats.get(k, 0)
        clean[k] = v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < (1 << 31) else 0
    return clean


def cmd_virustotal(args, ctx) -> int:
    out, scrub, sleep = ctx["stderr"], ctx["scrub"], ctx["sleep"]
    now = ctx["now"]()
    net = read_report(args.report, ctx["stdin"])
    hosts, private, unusable = _public_hosts(net)
    doc = _vt_doc(out)
    results = {r["host"]: r for r in doc["results"] if isinstance(r, dict) and isinstance(r.get("host"), str)}
    stored = doc.get("vt_threshold")
    threshold = args.vt_threshold if args.vt_threshold is not None else (
        stored if isinstance(stored, int) and not isinstance(stored, bool) and 1 <= stored <= 100 else 2)
    if args.vt_threshold is not None and not args.dry_run and stored != args.vt_threshold:
        write_json(cache_root() / "vt" / "results.json", {**doc, "vt_threshold": args.vt_threshold})
        doc["vt_threshold"] = args.vt_threshold
        out.write(f"VirusTotal threshold set to {args.vt_threshold}\n")
    today = now.date().isoformat()
    count = doc["daily"].get("count", 0)
    used = count if doc["daily"].get("date") == today and isinstance(count, int) \
        and not isinstance(count, bool) and count >= 0 else 0
    recent = set()
    for h, r in results.items():
        at = af._parse_utc(r.get("checked_at"))
        if at is not None and timedelta(0) <= now - at < VT_RECHECK:
            recent.add(h)
    todo = [h for h in hosts if h not in recent]
    plan = todo[:max(0, VT_DAILY - used)]
    if not plan:
        why = "no public hosts to look up" if not hosts else (
            "every host was checked in the last 24 hours" if not todo else "today's VirusTotal budget is used up")
        out.write(f"{why}; {MARK} network used: nothing sent\n")
        return EXIT_OK
    minutes = math.ceil(len(plan) / VT_PER_MINUTE)
    plural = "" if len(plan) == 1 else "s"
    disclose([("Provider", "VirusTotal v3, domain and IP reports"),
              ("Sends", f"{len(plan)} hostname{plural} in plain text to VirusTotal, "
                        f"which may keep them.\nFree tier: about {minutes} minute{'' if minutes == 1 else 's'} "
                        f"at {VT_PER_MINUTE} a minute."),
              ("Skips", f"{private} private or local hosts, {unusable} unusable names, "
                        f"{len(hosts) - len(todo)} checked in the last 24 h"),
              ("Never", "URLs, paths, commands, credentials, transcript text"),
              ("Key", _key_line(args, "vt"))], out)
    if args.dry_run:
        for h in plan:
            out.write(f"would send: {h}\n")
        out.write(f"{MARK} network used: nothing sent (--dry-run)\n")
        return EXIT_OK
    need_consent_possible(args, ctx)               # before any key command runs
    key = read_key("vt", args.key_command, scrub)
    if not consent(f"Send {len(plan)} hostname{plural} to VirusTotal?", yes=args.yes,
                   dry_run=False, stdin=ctx["stdin"], out=out):
        out.write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    checked = 0
    with NetSession("virustotal", "vt", scrub, receipt=args.receipt, out=out) as session:
        try:
            http = ctx["http_factory"](session)
            for i, host in enumerate(plan):
                if i:
                    sleep(60.0 / VT_PER_MINUTE)
                at = ctx["now"]()
                if at.date().isoformat() != today:      # the UTC day rolled over mid-run
                    today, used = at.date().isoformat(), 0
                used += 1                                # counted before the call: a timeout may still cost quota
                kind = "ip_addresses" if af._SB_IPV4.fullmatch(host) else "domains"
                status, body = http.get(VT_HOST, f"/api/v3/{kind}/{host}", headers={"x-apikey": key},
                                        sent={"hostnames": [host]}, describe=f"looking up {host}")
                if status == 429:
                    raise NetError(f"VirusTotal quota reached after {checked} of {len(plan)} hosts; "
                                   f"the rest can be checked later")
                if status in (401, 403):
                    raise NetError(f"VirusTotal answered HTTP {status}: the key was rejected")
                if status == 404:
                    results[host] = {"host": host, "status": "unknown", "stats": {}, "checked_at": _iso(at)}
                elif status == 200:
                    stats = _vt_stats(body)
                    if stats is None:
                        raise NetError(f"VirusTotal sent a report for {host} that is not readable")
                    results[host] = {"host": host, "status": "found", "stats": stats, "checked_at": _iso(at)}
                else:
                    raise NetError(f"VirusTotal answered HTTP {status} for {host}")
                checked += 1
        except NetError as exc:
            session.fail(str(exc))
            raise
        finally:
            keep = {}
            for h, r in results.items():
                t = af._parse_utc(r.get("checked_at"))
                if t is not None and ctx["now"]() - t < timedelta(days=7):
                    keep[h] = r
            write_json(cache_root() / "vt" / "results.json",
                       {"schema": 1, "vt_threshold": threshold, "daily": {"date": today, "count": used},
                        "results": [keep[h] for h in sorted(keep)]})
    out.write(f"{checked} host(s) checked on VirusTotal. Run actualis --network --reputation to see the result.\n")
    return EXIT_OK


COMMANDS = {"status": cmd_status, "forget": cmd_forget, "update": cmd_update,
            "confirm": cmd_confirm, "virustotal": cmd_virustotal}


def main(argv=None, *, http_factory=None, now=None, sleep=time.sleep, stdin=None, stdout=None,
         stderr=None) -> int:
    stdout, stderr, stdin = stdout or sys.stdout, stderr or sys.stderr, stdin or sys.stdin
    old_err = sys.stderr
    sys.stderr = stderr                           # argparse writes its errors here
    try:
        try:
            args = build_parser().parse_args(argv)
        except SystemExit as exc:
            return int(exc.code or 0)
    finally:
        sys.stderr = old_err
    scrub = Scrubber()
    ctx = {"stdin": stdin, "stdout": stdout, "stderr": stderr, "scrub": scrub, "sleep": sleep,
           "now": now or _now, "http_factory": http_factory or (lambda session: Http(session))}
    try:
        return COMMANDS[args.command](args, ctx)
    except UsageError as exc:
        stderr.write(f"actualis-reputation: {scrub(exc)}\n")
        return EXIT_USAGE
    except NetError as exc:
        stderr.write(f"actualis-reputation: {scrub(exc)}\n")
        return EXIT_RUNTIME
    except KeyboardInterrupt:
        stderr.write("actualis-reputation: interrupted\n")
        return 130
    except Exception as exc:                       # noqa: BLE001 -- never a traceback that could hold a key
        stderr.write(f"actualis-reputation: unexpected {type(exc).__name__}: {af.redact(scrub(exc))[:300]}\n")
        return EXIT_RUNTIME


def _cli() -> None:
    af.make_output_printable(False)
    sys.exit(main())


if __name__ == "__main__":
    _cli()
