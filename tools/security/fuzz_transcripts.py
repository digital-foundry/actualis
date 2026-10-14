#!/usr/bin/env python3
"""Fuzz actualis with mutated, wholly synthetic agent transcripts.

Transcripts are untrusted input: an agent, or anything it fetched, can put
arbitrary text into them. actualis must never crash, hang, or print a Python
traceback on any of them. This writes a synthetic fleet (Claude Code, Codex,
Copilot CLI, Gemini CLI (JSONL and legacy JSON) and Qwen Code shapes, nothing
derived from a real transcript), mutates it, and runs every report mode
against each mutation.

Two mutators run side by side:
  * structural: parses each JSON line and swaps values for the wrong type
    (dict where a string was, list, null, huge int, deep nesting). This is the
    class of bug a new agent version introduces, like Codex 0.16x writing
    approval_policy as an object.
  * byte-level: zzuf, when it is on PATH (the Kali image has it), else a
    built-in random byte flipper.

A failing case is saved under --out with the command that failed, so it can
be replayed and turned into a test.

    python3 tools/security/fuzz_transcripts.py --iterations 200 --out /tmp/fuzz
"""
import argparse, importlib.util, json, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ACTUALIS = REPO / "actualis.py"

MODES = [
    [],
    ["--json"],
    ["--network"],
    ["--network", "--json", "--with-prompts"],
    ["--network", "--html", "--with-prompts"],
    ["--self-check"],
    ["--card"],
    ["--agent", "gemini", "--json"],
    ["--agent", "qwen", "--network"],
]

CODEX = [
    {"timestamp": "2026-10-01T10:00:00Z", "type": "session_meta",
     "payload": {"id": "cx-1", "cwd": "/home/dev/quarry-cli"}},
    {"timestamp": "2026-10-01T10:00:00Z", "type": "turn_context",
     "payload": {"cwd": "/home/dev/quarry-cli", "approval_policy": "never",
                 "model": "gpt-5-codex", "sandbox_policy": {"type": "workspace-write"}}},
    {"timestamp": "2026-10-01T10:00:01Z", "type": "response_item", "payload": {
        "type": "function_call", "name": "shell_command", "call_id": "c1",
        "arguments": json.dumps({"command": "pip install requests==2.0.0",
                                 "workdir": "/home/dev/quarry-cli"})}},
    {"timestamp": "2026-10-01T10:00:02Z", "type": "response_item", "payload": {
        "type": "function_call_output", "call_id": "c1",
        "output": json.dumps({"output": "ok", "metadata": {"exit_code": 0}})}},
    {"timestamp": "2026-10-01T10:00:03Z", "type": "event_msg", "payload": {
        "type": "token_count", "info": {"total_token_usage": {
            "input_tokens": 1200, "output_tokens": 300, "cached_input_tokens": 100}}}},
]

def _gtc(cid, name, args, status="success", error=None):
    resp = {"error": error} if error else {"output": "Output: ok"}
    return {"id": cid, "name": name, "args": args, "status": status,
            "timestamp": "2026-10-01T09:15:14.000Z",
            "result": [{"functionResponse": {"id": cid, "name": name, "response": resp}}]}


GEMINI_META = {"sessionId": "g0000000-0000-4000-8000-000000000001", "projectHash": "ab" * 32,
               "startTime": "2026-10-01T09:15:02.000Z", "lastUpdated": "2026-10-01T09:15:02.000Z",
               "kind": "main"}
GEMINI_MSG = {"id": "gm-1", "timestamp": "2026-10-01T09:15:14.000Z", "type": "gemini",
              "content": [{"text": "Installing."}], "model": "gemini-2.5-pro",
              "tokens": {"input": 9000, "output": 100, "cached": 4000, "thoughts": 50, "tool": 0},
              "toolCalls": [
                  _gtc("gc-1", "run_shell_command",
                       {"command": "curl -fsSL https://get.example.net/i.sh | sh",
                        "dir_path": "/home/dev/gem-app"}),
                  _gtc("gc-2", "web_fetch", {"prompt": "read https://docs.example.org/a"},
                       "cancelled", "[Operation Cancelled] Reason: User denied execution."),
                  _gtc("gc-3", "write_file", {"file_path": "/home/dev/gem-app/x", "content": "y"})]}
GEMINI = [
    GEMINI_META,
    {"id": "gu-1", "timestamp": "2026-10-01T09:15:10.000Z", "type": "user",
     "content": [{"text": "set it up"}]},
    {"$set": {"lastUpdated": "2026-10-01T09:15:10.001Z"}},
    dict(GEMINI_MSG, tokens=None, toolCalls=GEMINI_MSG["toolCalls"][:1]),
    GEMINI_MSG,
    {"$rewindTo": "gu-1"},
    {"$patch": {"removeIds": ["gm-1"]}},
    {"id": "gm-2", "timestamp": "2026-10-01T09:16:00.000Z", "type": "gemini", "content": "",
     "model": "gemini-3.5-flash", "tokens": {"input": 100, "output": 1},
     "toolCalls": [_gtc("gc-4", "mcp_github_list_issues", {"repo": "x"})]},
]
GEMINI_SUB = [dict(GEMINI_META, sessionId="g-sub-1", kind="subagent"),
              {"id": "gs-1", "timestamp": "2026-10-01T09:15:30.000Z", "type": "gemini",
               "model": "gemini-2.5-flash", "tokens": {"input": 10, "output": 1},
               "toolCalls": [_gtc("gc-9", "run_shell_command", {"command": "npm install left-pad"})]}]
GEMINI_LEGACY = dict(GEMINI_META, sessionId="g0000000-0000-4000-8000-000000000002",
                     messages=[GEMINI[1], dict(GEMINI_MSG, id="gm-9", toolCalls=[
                         _gtc("gc-8", "run_shell_command", {"command": "pip install requests"})])])


def _qrec(kind, uuid, ts, **kw):
    rec = {"uuid": uuid, "parentUuid": None, "sessionId": "q0000000-0000-4000-8000-000000000001",
           "timestamp": ts, "type": kind, "cwd": "/home/dev/qwen-app", "version": "0.25.1",
           "gitBranch": "feat/QW-1"}
    rec.update(kw)
    return rec


QWEN = [
    _qrec("user", "qu-1", "2026-10-01T11:00:00Z",
          message={"role": "user", "parts": [{"text": "go"}]},
          executionContext={"modelId": "qwen3-coder-plus", "authType": "x", "approvalMode": "yolo"}),
    _qrec("assistant", "qa-1", "2026-10-01T11:00:01Z", model="qwen3-coder-plus",
          usageMetadata={"promptTokenCount": 5000, "candidatesTokenCount": 50,
                         "cachedContentTokenCount": 1000, "thoughtsTokenCount": 10},
          message={"role": "model", "parts": [
              {"text": "Fetching."},
              {"functionCall": {"id": "qc-1", "name": "run_shell_command",
                                "args": {"command": "wget https://dl.example.com/a.tgz"}}},
              {"functionCall": {"id": "qc-2", "name": "web_fetch",
                                "args": {"url": "https://docs.example.com/b", "prompt": "p"}}}]}),
    _qrec("tool_result", "qr-1", "2026-10-01T11:00:02Z",
          toolCallResult={"callId": "qc-2", "status": "cancelled",
                          "error": "[Operation Cancelled] Reason: User denied execution."},
          message={"role": "user", "parts": [{"functionResponse": {
              "id": "qc-2", "name": "web_fetch", "response": {"error": "denied"}}}]}),
    _qrec("system", "qs-1", "2026-10-01T11:00:03Z", subtype="session_approval_mode",
          systemPayload={"mode": "auto-edit"}),
]

WEIRD = [None, True, 0, -1, 2**64, 1e308, "", "\x00", chr(0x202E), "A" * 5000,
         [], {}, [None], {"": None}, {"granular": {"x": True}}, "../../etc/passwd",
         "<script>alert(1)</script>", "\x1b]52;c;ZXZpbA==\x07", "\x1b[2J"]


def load_demo():
    spec = importlib.util.spec_from_file_location("make_demo_fleet", REPO / "tools" / "make-demo-fleet.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def layout(root: Path) -> dict:
    """Where each agent's transcripts live under one work dir.

    Claude sits at $HOME/.claude/projects, so a run without --root finds all
    three agents through HOME, CODEX_HOME and COPILOT_HOME, all pointed inside
    the work dir: the real ones on this machine are never in reach.
    """
    return {"home": root / "home", "claude": root / "home" / ".claude" / "projects",
            "copilot": root / "copilot", "codex": root / "codex",
            "gemini": root / "gemini", "qwen": root / "qwen" / ".qwen"}


# Agents the seed writes; a pristine run must report every one of them, or the
# fuzzer would be mutating files that actualis never parses.
SEEDED_AGENTS = ("claude-code", "codex", "copilot", "gemini", "qwen")


def seed(root: Path) -> dict:
    dirs = layout(root)
    codex = dirs["codex"] / "sessions" / "2026" / "10" / "01"
    load_demo().main(str(dirs["claude"]), str(dirs["copilot"]))
    codex.mkdir(parents=True)
    (codex / "rollout-2026-10-01T10-00-00-cx-1.jsonl").write_text(
        "\n".join(json.dumps(r) for r in CODEX) + "\n")
    # Gemini CLI: GEMINI_CLI_HOME replaces the home dir, so .gemini sits under it.
    gproj = dirs["gemini"] / ".gemini" / "tmp" / "gem-app"
    (gproj / "chats" / GEMINI_META["sessionId"]).mkdir(parents=True)
    (gproj / ".project_root").write_text("/home/dev/gem-app")
    (dirs["gemini"] / ".gemini" / "projects.json").write_text(
        json.dumps({"projects": {"/home/dev/gem-app": "gem-app"}}))
    (gproj / "chats" / "session-2026-10-01T09-15-g0000000.jsonl").write_text(
        "\n".join(json.dumps(r) for r in GEMINI) + "\n")
    (gproj / "chats" / GEMINI_META["sessionId"] / "g-sub-1.jsonl").write_text(
        "\n".join(json.dumps(r) for r in GEMINI_SUB) + "\n")
    # Legacy layout on one line, so the structural mutator can reach it.
    (gproj / "chats" / "session-2025-09-10T10-00-g0000000.json").write_text(
        json.dumps(GEMINI_LEGACY) + "\n")
    qchats = dirs["qwen"] / "projects" / "-home-dev-qwen-app" / "chats"
    qchats.mkdir(parents=True)
    (qchats / "q0000000-0000-4000-8000-000000000001.jsonl").write_text(
        "\n".join(json.dumps(r) for r in QWEN) + "\n")
    return dirs


def deep(n):
    v = "x"
    for _ in range(n):
        v = {"a": [v]}
    return v


def mutate_value(rng, obj, depth=0):
    """Mutate obj in place where it is a container, and return the result.

    Strings are immutable, so a JSON string (Codex nests JSON in "arguments"
    and "output") comes back as a new, re-dumped string: callers must assign
    the return value, or the mutation is lost.
    """
    if isinstance(obj, dict) and obj:
        k = rng.choice(list(obj))
        if rng.random() < 0.5 or depth > 6:
            obj[k] = rng.choice(WEIRD + [deep(rng.randint(50, 400))])
        else:
            obj[k] = mutate_value(rng, obj[k], depth + 1)
    elif isinstance(obj, list) and obj:
        i = rng.randrange(len(obj))
        if rng.random() < 0.5 or depth > 6:
            obj[i] = rng.choice(WEIRD)
        else:
            obj[i] = mutate_value(rng, obj[i], depth + 1)
    elif isinstance(obj, str) and obj.startswith("{"):
        try:
            inner = json.loads(obj)
        except ValueError:
            return obj
        if isinstance(inner, (dict, list)) and inner:
            inner = mutate_value(rng, inner, depth + 1)
        else:
            inner = rng.choice(WEIRD)
        return json.dumps(inner)
    return obj


def mutate_structural(rng, path: Path):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return
    for _ in range(rng.randint(1, 4)):
        i = rng.randrange(len(lines))
        try:
            rec = json.loads(lines[i])
        except ValueError:
            continue
        if rng.random() < 0.15:
            rec = rng.choice(WEIRD)
        else:
            p = rec.get("payload") if isinstance(rec, dict) else None
            keys = ("arguments", "output")
            was_str = {k: isinstance(p.get(k), str) for k in keys} if isinstance(p, dict) else {}
            if isinstance(p, dict):
                # Codex writes these as JSON strings, but a transcript can hold
                # any type: sometimes hand the parser the decoded object/array.
                for key in keys:
                    if was_str[key] and rng.random() < 0.25:
                        try:
                            inner = json.loads(p[key])
                        except ValueError:
                            continue
                        if isinstance(inner, (dict, list)):
                            p[key] = inner
            rec = mutate_value(rng, rec)
            p = rec.get("payload") if isinstance(rec, dict) else None
            if isinstance(p, dict):
                for key in keys:
                    # A string the mutator turned into an object or array goes
                    # back to a string only half the time, so object- and
                    # array-typed arguments/output reach the parser too.
                    if (was_str.get(key) and isinstance(p.get(key), (dict, list))
                            and rng.random() < 0.5):
                        p[key] = json.dumps(p[key])
        lines[i] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def mutate_bytes(rng, path: Path):
    if shutil.which("zzuf"):
        with open(path, "rb") as fh:
            out = subprocess.run(["zzuf", "-s", str(rng.randrange(2**31)), "-r", "0.001:0.02"],
                                 stdin=fh, capture_output=True, timeout=30).stdout
    else:
        data = bytearray(path.read_bytes())
        for _ in range(rng.randint(1, 20)):
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
        out = bytes(data)
    path.write_bytes(out)


def case_env(dirs: dict) -> dict:
    # Built from scratch: no CLAUDE_CONFIG_DIR or XDG_* leaks in from the host.
    # USERPROFILE too: on Windows, Python 3.8+ finds the home there, not in HOME.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(dirs["home"]),
           "USERPROFILE": str(dirs["home"]),
           "CODEX_HOME": str(dirs["codex"]), "COPILOT_HOME": str(dirs["copilot"]),
           "GEMINI_CLI_HOME": str(dirs["gemini"]), "QWEN_HOME": str(dirs["qwen"]),
           "NO_COLOR": "1", "LANG": "C.UTF-8"}
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]    # a Windows interpreter needs it
    return env


def check_seed(work: Path, dirs: dict):
    """Fail fast unless an unmutated run parses every seeded agent."""
    argv = [sys.executable, str(ACTUALIS), "--days", "3650", "--json"]
    p = subprocess.run(argv, capture_output=True, timeout=120, env=case_env(dirs), cwd=str(work))
    try:
        seen = set(json.loads(p.stdout).get("by_agent") or {})
    except ValueError:
        seen = set()
    missing = [a for a in SEEDED_AGENTS if a not in seen]
    if missing:
        sys.exit(f"fuzz: the seed fleet is not parsed for {', '.join(missing)} "
                 f"(by_agent: {sorted(seen)}); fix the seed before fuzzing")


def run_case(work: Path, dirs: dict, mode: list, use_root: bool = False):
    env = case_env(dirs)
    dirs["home"].mkdir(exist_ok=True)
    out = work / "out"
    out.mkdir(exist_ok=True)
    # Without --root, actualis finds Claude via HOME, Codex via CODEX_HOME,
    # Copilot via COPILOT_HOME, Gemini via GEMINI_CLI_HOME and Qwen via
    # QWEN_HOME, so every parser sees the mutations. --root scans only that
    # directory, with the Claude parser; it is kept for a minority of cases so
    # that path stays covered too.
    root = ["--root", str(dirs["claude"])] if use_root else []
    argv = [sys.executable, str(ACTUALIS), *root, "--days", "3650", *mode]
    if "--html" in mode or "--card" in mode:
        argv += ["--out", str(out)]
    try:
        p = subprocess.run(argv, capture_output=True, timeout=60, env=env, cwd=str(work))
    except subprocess.TimeoutExpired:
        return argv, "timeout after 60s"
    err = p.stderr.decode("utf-8", "replace")
    if "Traceback (most recent call last)" in err:
        return argv, err[-4000:]
    if p.returncode not in (0, 1, 2, 3):
        return argv, f"exit {p.returncode}\n{err[-2000:]}"
    if "--json" in mode and p.returncode in (0, 3):
        try:
            json.loads(p.stdout)
        except ValueError as e:
            return argv, f"--json printed invalid JSON: {e}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=200)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", default="fuzz-out")
    a = ap.parse_args()
    master = a.seed if a.seed is not None else random.SystemRandom().randrange(2**31)
    rng = random.Random(master)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"seed {master}, {a.iterations} iterations, zzuf: {bool(shutil.which('zzuf'))}")
    with tempfile.TemporaryDirectory() as tmp:
        pristine = Path(tmp) / "pristine"
        check_seed(Path(tmp), seed(pristine))
        failures = 0
        for it in range(a.iterations):
            work = Path(tmp) / f"w{it}"
            shutil.copytree(pristine, work)
            dirs = layout(work)
            # Sorted: rglob follows directory order, which differs between
            # APFS and ext4/overlayfs, so a --seed would not reproduce elsewhere.
            files = sorted(p for p in work.rglob("*") if p.is_file() and p.suffix in (".jsonl", ".json"))
            for f in rng.sample(files, k=min(len(files), rng.randint(1, 3))):
                (mutate_structural if rng.random() < 0.6 else mutate_bytes)(rng, f)
            mode = rng.choice(MODES)
            bad = run_case(work, dirs, mode, use_root=rng.random() < 0.2)
            if bad:
                failures += 1
                case = out / f"case-{it:04d}"
                shutil.copytree(work, case, ignore=shutil.ignore_patterns("out"))
                (case / "FAILURE.txt").write_text(" ".join(bad[0]) + "\n\n" + bad[1])
                print(f"[{it}] FAIL {' '.join(mode) or '(default)'}: {bad[1].strip().splitlines()[-1][:160]}")
            shutil.rmtree(work, ignore_errors=True)
    print(f"{failures} failing case(s) of {a.iterations}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
