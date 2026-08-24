#!/usr/bin/env python3
"""What your coding agent was not allowed to do.

Claude Code records every refused tool call. The refusal lands on its own
transcript record carrying `toolDenialKind`, and it points back at the tool call
it blocked through `tool_use_id`. Join the two and you get the exact command
that was stopped, and who stopped it: a human, or the auto-mode policy.

That data exists on your disk right now and nothing reads it. It also cannot
exist anywhere upstream: a refused command is never sent, so no API-layer tool
has a record of it.

Read-only. No network. Standard library only. Prints counts and program names,
never full command text -- the commands people refuse are exactly the ones worth
not pasting into an issue.

    python3 tools/denials.py            # this machine
    python3 tools/denials.py --json     # machine-readable
    python3 tools/denials.py --root DIR # a specific transcript directory
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

# --- transcript discovery (mirrors actualis.py, kept standalone on purpose) ---

def transcript_roots(explicit: str | None = None) -> list[Path]:
    if explicit:
        return [Path(explicit).expanduser()]
    seen, out = set(), []
    for base in filter(None, [os.environ.get("CLAUDE_CONFIG_DIR"), "~/.claude"]):
        p = (Path(base).expanduser() / "projects")
        try:
            rp = p.resolve()
        except OSError:
            continue
        if p.is_dir() and rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


# --- the one piece of real parsing: what program is this command running? ---

_HEADER_KEYWORDS = {"for", "while", "until", "if", "case", "select", "function", "elif"}
_BODY_KEYWORDS = {"do", "then", "else", "fi", "done", "esac", "in", "{", "(", "!"}
_PREFIX_WORDS = {"sudo", "env", "exec", "time", "nohup", "command", "builtin", "nice", "xargs"}
_TAKES_PATH_ARG = {"cd", "pushd", "popd"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECT = re.compile(r"^\d*(?:>>?|<<?|&>|>&)")
_ASSIGN_SUBST = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=[\"']?(?:\$\(|`)([A-Za-z0-9_./+-]+)")


def command_head(cmd: str) -> str | None:
    """The program actually being run, not the first token.

    Agent commands arrive as `cd path && VAR=$(grep ...) | head`. Taking the
    first token reports `cd`; skipping naively reports a flag or a redirect.
    """
    for segment in re.split(r"&&|\|\||;|\||\n", (cmd or "").strip()):
        tokens = segment.split()
        if not tokens or tokens[0] in _HEADER_KEYWORDS:
            continue
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if _ASSIGNMENT.match(tok):
                inner = _ASSIGN_SUBST.match(tok)
                if inner:
                    return inner.group(1)      # VAR=$(grep ...) runs grep
                continue
            if tok in _BODY_KEYWORDS or tok in _PREFIX_WORDS or tok == "\\":
                continue
            if _REDIRECT.match(tok) or tok.startswith("-"):
                continue                       # never a program
            if tok in _TAKES_PATH_ARG:
                skip_next = True
                continue
            return tok
    first = (cmd or "").strip().split()
    return first[0] if first else None


# --- the join ---------------------------------------------------------------

def collect(roots: list[Path]) -> dict:
    calls: dict[str, tuple[str, dict]] = {}   # tool_use_id -> (tool name, input)
    denials: list[tuple[str, str, str]] = []  # (kind, tool_use_id, reason)
    files = 0

    for root in roots:
        if not root.is_dir():
            print(f"denials: {root} is not a directory", file=sys.stderr)
            continue
        for project in sorted(p for p in root.iterdir() if p.is_dir()):
            for path in project.glob("*.jsonl"):
                files += 1
                try:
                    fh = path.open(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                with fh:
                    for line in fh:
                        # Cheap prefilter: most records are neither.
                        if '"tool_use"' not in line and '"toolDenialKind"' not in line:
                            continue
                        try:
                            rec = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        if not isinstance(rec, dict):
                            continue
                        msg = rec.get("message")
                        if not isinstance(msg, dict):
                            continue
                        blocks = msg.get("content")
                        if not isinstance(blocks, list):
                            continue

                        for b in blocks:
                            if not isinstance(b, dict):
                                continue
                            if b.get("type") == "tool_use" and b.get("id"):
                                calls[b["id"]] = (b.get("name") or "?", b.get("input") or {})
                            elif rec.get("toolDenialKind") and b.get("type") == "tool_result":
                                denials.append((str(rec["toolDenialKind"]),
                                                b.get("tool_use_id") or "",
                                                str(b.get("content") or "")[:120]))

    by_kind: dict[str, dict] = {}
    joined = 0
    for kind, tid, reason in denials:
        k = by_kind.setdefault(kind, {"total": 0, "joined": 0,
                                      "tools": collections.Counter(),
                                      "programs": collections.Counter(),
                                      "reasons": collections.Counter()})
        k["total"] += 1
        k["reasons"][re.sub(r"\s+", " ", reason)[:64]] += 1
        if tid in calls:
            joined += 1
            k["joined"] += 1
            name, inp = calls[tid]
            k["tools"][name] += 1
            if name == "Bash":
                k["programs"][command_head(inp.get("command") or "") or "?"] += 1

    return {"files": files, "tool_calls": len(calls), "denials": len(denials),
            "joined": joined, "by_kind": by_kind}


def render(d: dict) -> None:
    print(f"\n  {d['files']:,} transcript files · {d['tool_calls']:,} tool calls · "
          f"{d['denials']:,} refusals")
    if not d["denials"]:
        print("\n  No refusals recorded. Either nothing was ever blocked, or this "
              "machine runs\n  with approvals off entirely — which is itself the finding.\n")
        return
    pct = d["joined"] / d["denials"] * 100
    print(f"  {d['joined']:,} of {d['denials']:,} joined to the exact command ({pct:.0f}%)\n")

    for kind in sorted(d["by_kind"], key=lambda k: -d["by_kind"][k]["total"]):
        k = d["by_kind"][kind]
        who = "a human said no" if kind == "user-rejected" else "the policy said no"
        print(f"  {kind}  ({k['total']}, {who})")
        tools = ", ".join(f"{t} {v}" for t, v in k["tools"].most_common(5))
        print(f"    tools     {tools or '—'}")
        if k["programs"]:
            progs = "  ".join(f"{p}:{v}" for p, v in k["programs"].most_common(10))
            print(f"    programs  {progs}")
        top = k["reasons"].most_common(1)
        if top:
            print(f"    reason    {top[0][0]}")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="denials",
        description="What your coding agent was not allowed to do.")
    ap.add_argument("--root", metavar="DIR", help="transcript directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    roots = transcript_roots(args.root)
    if not roots:
        print("denials: no Claude Code transcripts found.", file=sys.stderr)
        return 1
    d = collect(roots)

    if args.json:
        out = {"files": d["files"], "tool_calls": d["tool_calls"],
               "denials": d["denials"], "joined": d["joined"],
               "by_kind": {k: {"total": v["total"], "joined": v["joined"],
                               "tools": dict(v["tools"].most_common()),
                               "programs": dict(v["programs"].most_common())}
                           for k, v in d["by_kind"].items()}}
        json.dump(out, sys.stdout, indent=2)
        print()
    else:
        render(d)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
