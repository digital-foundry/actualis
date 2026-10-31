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


def read_key(provider: str, key_command: "str | None", scrub: Scrubber, env=os.environ) -> str:
    label, _host, var = PROVIDERS[provider]
    if key_command:
        try:
            argv = shlex.split(key_command)
        except ValueError as exc:
            raise UsageError(f"--key-command: {exc}") from None
        if not argv:
            raise UsageError("--key-command is empty")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=120)   # noqa: S603 (no shell)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UsageError(f"--key-command could not run ({type(exc).__name__})") from None
        key = r.stdout.strip()
        if r.returncode != 0:
            scrub.add(key)
            raise UsageError(f"--key-command exited {r.returncode}; its output is not shown") from None
    else:
        key = env.get(var, "").strip()
    if not key:
        raise UsageError(f"no {label} key: set ${var} or pass --key-command CMD (see docs/reputation.md)")
    scrub.add(key)
    if len(key) > 512 or not key.isprintable() or any(ch.isspace() for ch in key):
        raise UsageError(f"the {label} key holds spaces or control characters; check --key-command or ${var}")
    return key


def cache_root() -> Path:
    return af.reputation_dir()


def ensure_dir(path: Path) -> None:
    """Create `path` (0700) and refuse it if it, or the cache root, is a symlink."""
    root = cache_root()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in {root, path}:
        if os.path.islink(p):
            raise NetError(f"{p} is a symlink; refusing to write through it")
        if os.name != "nt":
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

    def __enter__(self) -> "NetSession":
        try:
            write_json(cache_root() / "in-flight.json",
                       {"pid": os.getpid(), "provider": self.provider, "started_at": _iso(self.started)})
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
        try:
            os.unlink(cache_root() / "in-flight.json")
        except OSError:
            pass
        if exc_type is KeyboardInterrupt and not self.failure:
            self.failure = "interrupted"
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
                Path(self.receipt).write_text(self.scrub(json.dumps(
                    {"command": self.command, "provider": self.provider, "started_at": _iso(self.started),
                     "finished_at": _iso(_now()), "requests": self.requests, "failure": self.failure},
                    indent=1)) + "\n")
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
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    if len(raw) > REPORT_MAX:
        raise UsageError(f"{path} is over {REPORT_MAX >> 20} MiB")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise UsageError(f"{path} is not JSON; pass the output of actualis --network --json") from None
    net = doc.get("network", doc) if isinstance(doc, dict) else None
    if not isinstance(net, dict) or not isinstance(net.get("hosts"), list):
        raise UsageError(f"{path} is not actualis --network --json output")
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
    targets = [root / f for f in CACHE_FILES] + list((root / "gsb").glob("*.prefixes")) \
        + [p for d in (root, root / "gsb", root / "vt") if d.is_dir() for p in d.glob(".tmp-*")]
    for p in targets:
        try:
            if p.is_file() or p.is_symlink():
                p.unlink()
                removed += 1
        except OSError:
            pass
    for d in (root / "gsb", root / "vt", root):
        try:
            d.rmdir()
        except OSError:
            pass                                   # not empty: something that is not ours stays
    ctx["stdout"].write(f"deleted {removed} file(s) from {root}\n")
    return EXIT_OK


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):                # never echo arguments: one may be a key
        if message.startswith("unrecognized arguments") or message.startswith("argument command"):
            message = message.split(":", 1)[0] + " (not repeated here, in case one is a key)"
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
    vt.add_argument("--vt-threshold", type=_threshold, default=2, metavar="N",
                    help="engines flagging malicious for a high finding (default 2)")
    common(vt)
    sub.add_parser("status", allow_abbrev=False, help="lists, ages, last network use; never networks")
    fg = sub.add_parser("forget", allow_abbrev=False, help="delete the reputation cache")
    fg.add_argument("--yes", action="store_true", help="delete without asking")
    return ap


class Http:                                      # replaced in Task 6
    def __init__(self, session, **kw):
        raise NetError("no network client yet")


def cmd_update(args, ctx) -> int:                # completed in Task 6
    disclose([("Provider", "Google Safe Browsing v5, list download"),
              ("Sends", "nothing about your hosts: downloads list updates")], ctx["stderr"])
    if not args.dry_run:
        read_key("gsb", args.key_command, ctx["scrub"])
    if not consent("Download Safe Browsing list updates from Google?", yes=args.yes, dry_run=args.dry_run,
                   stdin=ctx["stdin"], out=ctx["stderr"]):
        ctx["stderr"].write(f"{MARK} network used: nothing sent\n")
        return EXIT_OK
    return EXIT_OK


COMMANDS = {"status": cmd_status, "forget": cmd_forget, "update": cmd_update}


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
