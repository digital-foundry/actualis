#!/usr/bin/env python3
"""PII gate: fail when tracked files carry personal data.

actualis is public and its tests are built around agent transcripts, so the
rule is synthetic data only. This enforces it on every git-tracked text file:
home paths with a real-looking user name, emails, phone numbers, tailnet
hosts, public IPs, UUIDs that are not obviously invented, credentials
actualis itself recognises (known token prefixes, Authorization headers, URL
passwords; outside tests/), and, with --full, a private list of personal
terms that never lives in this repo.

Text is decoded (HTML entities, percent-encoding, JSON escapes; up to 8
passes) and canonicalised (NFKC, format characters stripped, case-folded,
look-alike letters mapped to Latin) before matching, so `&#x2F;Users&#x2F;`
and Cyrillic look-alikes do not slip through. Both the raw and the canonical
text are checked.

Output is `path:line: detector` and nothing else: never the matched value,
so a failing CI log does not republish what it found.

Allow a line with an inline `pii-ok: <reason>` marker, or a value with a
line in .pii-allow: `<exact value> # <reason>`. Every allowance needs a reason.

Exit codes: 0 clean, 1 findings, 2 configuration error (fails closed).

Standard library only. Usage:
    python tools/pii-gate.py                 # whole tree, built-in detectors
    python tools/pii-gate.py --changed BASE  # only files changed since BASE
    python tools/pii-gate.py --full          # also the private terms list
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
ALLOW_FILE = ".pii-allow"
TERMS_ENV = "ACTUALIS_PII_TERMS"
TERMS_OP_REF = "op://Foundry Admin/actualis pii terms/notesPlain"

# actualis.py is the detector corpus itself: its regexes and the shapes in its
# docstrings would all match. The org-required gitleaks scan covers it.
SKIP_FILES = {"actualis.py"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".icns", ".ttf", ".otf",
                 ".woff", ".woff2", ".mp4", ".webm", ".pdf", ".zip", ".gz", ".sum"}
MAX_PASSES = 8

# User names that are plainly placeholders. A real name in a path is the leak
# this catches; anything else needs a .pii-allow line with a reason.
FAKE_USERS = {"a", "u", "x", "me", "you", "user", "username", "name", "runner",
              "someone", "example", "dev", "test", "first", "secret", "shared",
              "alice", "bob"}
ALLOWED_EMAILS = {"noreply@anthropic.com"}
ALLOWED_EMAIL_DOMAINS = {"digitalfoundry.tech", "example.com", "example.org", "example.net"}
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal"}
# Public resolvers every networking example uses; nobody's personal address.
WELL_KNOWN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}

HOME_RX = re.compile(r"(?:/users/|/home/|[a-z]:\\{1,2}users\\{1,2})([a-z0-9][a-z0-9._-]*)")
# Bounded quantifiers and a lookbehind keep these linear on long unbroken
# runs (base64, hex) that contain no match.
EMAIL_RX = re.compile(r"(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.[a-z]{2,24})")
PHONE_RX = re.compile(r"(?<![\w.+-])(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\)[ .-]?|[2-9]\d{2}[ .-])\d{3}[ .-]\d{4}(?![\w.-])"
                      r"|(?<![\w.+-])\+[1-9]\d{0,3}(?:[ .-]?\d{1,4}){2,6}(?![\w.-])")
TAILNET_RX = re.compile(r"(?<![a-z0-9.-])[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.ts\.net\b")
IP_RX = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
IP6_RX = re.compile(r"(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:.])")
UUID_RX = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
OK_MARKER_RX = re.compile(r"pii-ok:\s*\S")
# Lines that are attribution, where the maintainer's name belongs.
# Anchored at the start of the line (after comment marks, quotes, bullets), so
# "copyright" elsewhere on a line does not exempt it.
ATTRIBUTION_RX = re.compile(r"^[\W_]*(?:copyright\b|\u00a9|co-authored-by:|authors?\s*[=:]|author:)", re.I)

# Look-alike letters (Cyrillic, Greek) folded to the Latin letter they imitate.
CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
    "\u0501": "d", "\u0261": "g", "\u03bf": "o", "\u03b1": "a", "\u03b5": "e",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c1": "p", "\u03c4": "t",
    "\u03c5": "u", "\u0131": "i",
})
JSON_ESC_RX = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\/")


def _json_unescape(text: str) -> str:
    def sub(m):
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(2):
            return chr(int(m.group(2), 16))
        return "/"
    return JSON_ESC_RX.sub(sub, text)


def decode(text: str) -> tuple[str, bool]:
    """Undo HTML, percent and JSON escaping until the text stops changing.
    Returns (decoded, settled); text still changing after MAX_PASSES is
    treated as a hit by the caller, since nesting that deep is evasion."""
    for _ in range(MAX_PASSES):
        nxt = _json_unescape(unquote(html.unescape(text)))
        if nxt == text:
            return text, True
        text = nxt
    return text, False


def _visible(text: str) -> str:
    """NFKC, with format characters (zero-width and friends) and control
    characters other than tab removed."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text
                   if c == "\t" or unicodedata.category(c) not in ("Cf", "Cc"))


def canon(text: str) -> str:
    return _visible(text).casefold().translate(CONFUSABLES)


def _email_ok(text: str, m: re.Match) -> bool:
    value, domain = m.group(0), m.group(1)
    if value in ALLOWED_EMAILS or domain in ALLOWED_EMAIL_DOMAINS:
        return True
    labels = domain.split(".")
    if labels[-1] in RESERVED_TLDS or "example" in labels:
        return True
    before = text[m.start() - 1] if m.start() else ""
    after = text[m.end()] if m.end() < len(text) else ""
    if value.startswith("git@") and after == ":":
        return True        # git@host:owner/repo is an SSH remote, not a mailbox
    if re.search(r"[a-z][a-z0-9+.-]{0,20}://[^\s/@]{0,256}$", text[max(0, m.start() - 300):m.start()]):
        return True        # userinfo right after scheme://, with or without a password
    if before == ":" and after == ":":
        return True        # scp-style user:token@host:path
    return False


def _uuid_synthetic(value: str) -> bool:
    digits = value.replace("-", "")
    if len(set(digits)) <= 4 or digits.count("0") >= 16:
        return True
    # Two or more groups like 1111 or 8333 (one digit repeated): hand-typed.
    groups = value.split("-")
    if sum(1 for g in groups if len(set(g)) <= 2) >= 2:
        return True
    return any(g in "0123456789abcdef0123456789abcdef" for g in groups if len(g) >= 8)


def _ip_ok(value: str) -> bool:
    if "." in value and ":" not in value:
        # 06.06.06.06: leading zeros are refused by ipaddress on 3.9.5+
        # but accepted by 3.9.0-3.9.4; read every octet as decimal everywhere.
        octets = value.split(".")
        if len(octets) != 4 or any(int(o) > 255 for o in octets):
            return True    # 999.1.1.1 and friends are not addresses
        value = ".".join(str(int(o)) for o in octets)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True        # not an address (a time like 12:34:56, a C++ scope)
    # Private, loopback, CGNAT, documentation (RFC 5737), benchmarking,
    # and reserved ranges are non-global; multicast is "global" but nobody's.
    return value in WELL_KNOWN_IPS or not ip.is_global or ip.is_multicast


def _phone_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return True        # too short or long to be a dialable number
    last = digits[-10:]
    # 555-0100 to 555-0199 are reserved for fiction
    return last[3:6] == "555" and last[6:8] == "01"


class Gate:
    def __init__(self, allow: set[str], terms: list[re.Pattern],
                 secret_rxs: "list[re.Pattern] | None" = None):
        self.allow = allow
        self.allow_canon = {canon(a) for a in allow}
        self.terms = terms
        self.secret_rxs = secret_rxs or []

    def _allowed(self, value: str) -> bool:
        return value in self.allow or canon(value) in self.allow_canon

    def scan_line(self, line: str, *, in_tests: bool) -> list[str]:
        """Detector ids that fire on one line (deduplicated, in order)."""
        if OK_MARKER_RX.search(line):
            return []
        hits: list[str] = []
        views = [line]
        decoded, settled = decode(line) if re.search(r"[&%\\]", line) else (line, True)
        if not settled:
            hits.append("decode")
        views.append(canon(decoded))
        if decoded != line:
            views.append(decoded)
        # Case kept (token prefixes are case-sensitive), but decoded and
        # NFKC-folded, so ghp%5F... and fullwidth letters are still read.
        folded = _visible(decoded)
        secret_views = [line] + ([folded] if folded != line else [])

        def add(det):
            if det not in hits:
                hits.append(det)

        for text in views:
            low = text.casefold()
            for m in HOME_RX.finditer(low):
                if m.group(1).rstrip("._-") not in FAKE_USERS and not self._allowed(low[m.start():m.end()]):
                    add("home-path")
            for m in (EMAIL_RX.finditer(low) if "@" in low else ()):
                if not _email_ok(low, m) and not self._allowed(low[m.start():m.end()]):
                    add("email")
            for m in PHONE_RX.finditer(text):
                if not _phone_ok(m.group(0)) and not self._allowed(m.group(0)):
                    add("phone")
            for m in (TAILNET_RX.finditer(low) if "ts.net" in low else ()):
                if not self._allowed(low[m.start():m.end()]):
                    add("tailnet")
            for m in IP_RX.finditer(text):
                if not _ip_ok(m.group(0)) and not self._allowed(m.group(0)):
                    add("ip")
            for m in (IP6_RX.finditer(low) if "::" in low or low.count(":") >= 7 else ()):
                if not _ip_ok(m.group(0)) and not self._allowed(m.group(0)):
                    add("ip")
            for m in UUID_RX.finditer(low):
                if not _uuid_synthetic(m.group(0)) and not self._allowed(m.group(0)):
                    add("uuid")
            if self.terms and not ATTRIBUTION_RX.search(text):
                c = canon(text)
                if any(t.search(c) for t in self.terms):
                    add("term")
        if not in_tests:
            for text in secret_views:
                for rx in self.secret_rxs:
                    # The whole match, or the credential group alone (the value
                    # after `Bearer`, the password in a URL), may be allowed.
                    if any(not self._allowed(m.group(0))
                           and not (rx.groups >= 2 and self._allowed(m.group(2)))
                           for m in rx.finditer(text)):
                        add("secret")
        return hits

    def scan_file(self, rel: str, text: str) -> list[tuple[int, str]]:
        in_tests = rel.startswith("tests/")
        out = []
        # "\n" only: splitlines() also breaks on \f, \x1c and U+2028, which
        # would shift line numbers away from what git and editors show.
        for n, line in enumerate(text.split("\n"), 1):
            for det in self.scan_line(line, in_tests=in_tests):
                out.append((n, det))
        return out


def load_allow(path: Path) -> "set[str]":
    allow = set()
    if not path.exists():
        return allow
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        raise SystemExit(f"pii-gate: cannot read {ALLOW_FILE} as UTF-8 text")
    for n, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        value, sep, reason = raw.rpartition(" # ")
        if not sep or not value.strip() or not reason.strip():
            raise SystemExit(f"pii-gate: {ALLOW_FILE}:{n}: every entry needs ' # <reason>'")
        allow.add(value.strip())
    return allow


def parse_terms(text: str) -> list[re.Pattern]:
    """One term per line: `/regex/` or a literal matched as whole words,
    case-insensitively, with any run of spaces, hyphens or underscores between
    its words. Blank lines and `#` comments are skipped. Matching runs on
    case-folded text, so every regex is case-insensitive. An empty list is an
    error: --full with nothing to match must not pass."""
    terms = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"/(.+)/([a-z]*)", line)
        try:
            if m:
                terms.append(re.compile(m.group(1), re.I))
            else:
                words = [re.escape(w) for w in re.split(r"[\W_]+", canon(line)) if w]
                if words:
                    terms.append(re.compile(r"(?<![^\W_])" + r"[\W_]+".join(words) + r"(?![^\W_])"))
        except re.error:
            # Fail closed, and do not echo the term: the list is private.
            raise SystemExit("pii-gate: the terms list has an invalid regex")
    if not terms:
        raise SystemExit("pii-gate: the terms list is empty")
    return terms


def load_terms() -> list[re.Pattern]:
    path = os.environ.get(TERMS_ENV)
    if path:
        try:
            return parse_terms(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise SystemExit(f"pii-gate: cannot read the file named by {TERMS_ENV}")
    if os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        try:
            res = subprocess.run(["op", "read", TERMS_OP_REF], capture_output=True,
                                 text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            raise SystemExit("pii-gate: could not run `op read` for the terms list")
        if res.returncode == 0 and res.stdout.strip():
            return parse_terms(res.stdout)
        raise SystemExit("pii-gate: `op read` returned no terms list")
    raise SystemExit(f"pii-gate: --full needs {TERMS_ENV} or OP_SERVICE_ACCOUNT_TOKEN")


def tracked_files(root: Path, changed_base: "str | None") -> list[str]:
    if changed_base:
        cmd = ["git", "diff", "-z", "--name-only", "--diff-filter=ACMR", f"{changed_base}...HEAD"]
    else:
        cmd = ["git", "ls-files", "-z"]
    # -z: no core.quotepath octal escaping of non-ASCII names
    res = subprocess.run(cmd, cwd=root, capture_output=True)
    if res.returncode != 0:
        raise SystemExit(f"pii-gate: `{' '.join(cmd)}` failed")
    names = res.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [f for f in names
            if f and f not in SKIP_FILES and Path(f).suffix.lower() not in SKIP_SUFFIXES]


def _load_secret_rxs() -> list[re.Pattern]:
    """actualis's own high-signal credential patterns: known token prefixes,
    Authorization headers and scheme://user:password@ URLs. Its KEY=value
    heuristics are tuned for shell commands and too noisy on prose and code;
    the org-required gitleaks scan covers the rest."""
    sys.path.insert(0, str(ROOT))
    try:
        import actualis
    except ImportError:
        raise SystemExit("pii-gate: cannot import actualis for the secret detector")
    rxs = list(actualis._SECRET_PATTERNS[1:4])
    # The list is positional; fail closed if it is reordered rather than
    # silently checking the wrong patterns.
    if (len(rxs) != 3 or "ghp_" not in rxs[0].pattern
            or "authorization" not in rxs[1].pattern or "://" not in rxs[2].pattern):
        raise SystemExit("pii-gate: actualis._SECRET_PATTERNS changed shape; update _load_secret_rxs")
    return rxs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fail when tracked files carry personal data.")
    ap.add_argument("--changed", metavar="BASE", help="only files changed since BASE")
    ap.add_argument("--full", action="store_true",
                    help=f"also match the private terms list ({TERMS_ENV} or 1Password)")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = args.root
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")   # non-ASCII paths on cp1252
    try:
        gate = Gate(load_allow(root / ALLOW_FILE), load_terms() if args.full else [],
                    _load_secret_rxs())
        files = tracked_files(root, args.changed)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2
    findings = 0
    hit_files = 0
    for rel in files:
        try:
            data = (root / rel).read_bytes()
        except OSError:
            continue       # deleted in the working tree
        if b"\0" in data:
            continue       # binary (UTF-16 text has NULs too; none is tracked)
        text = data.decode("utf-8", errors="replace")
        hits = gate.scan_file(rel, text)
        if hits:
            hit_files += 1
        for n, det in hits:
            print(f"{rel}:{n}: {det}")
            findings += 1
    scope = "full" if args.full else "built-in detectors"
    if findings:
        print(f"pii-gate: {findings} finding(s) in {hit_files} file(s) ({scope}). "
              "Replace with synthetic data, or allow with a reason (CONTRIBUTING.md).",
              file=sys.stderr)
        return 1
    print(f"pii-gate: clean, {len(files)} files ({scope})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
