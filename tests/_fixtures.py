"""Synthetic Copilot CLI sessions and an isolated home, for the tests.

Every value is invented. The shapes follow Copilot CLI 1.0.70's events.jsonl,
checked against 17 real sessions; no real content was copied. Written at test
time rather than committed, so the credential canary is assembled at runtime
and never sits in the tree as a literal.

Importing this module also makes the whole test process hermetic (see
_isolate_process below). Every test module imports it first, so no test can
read the developer's real transcripts, suppression files or agent config.
"""
import atexit
import contextlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

# Every variable that points actualis (or an agent) at a config or transcript
# directory. The suite runs with each one inside a temp directory.
AGENT_VARS = ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME",
              "QWEN_HOME", "QWEN_RUNTIME_DIR", "XDG_CONFIG_HOME",
              "XDG_CACHE_HOME", "ACTUALIS_REPUTATION_DIR", "LOCALAPPDATA")
# Hosts a test may resolve or connect to; anything else is refused (see audit).
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0"})
ORIGINAL_ENV = dict(os.environ)     # for tools that are not actualis (go), never for actualis
REAL_HOME = None                    # set by _isolate_process
TEMP_HOME = None
TEMP_CWD = None
LEAKS = []                          # (event, path) a test tried to read under the real home


def _isolate_process():
    """Point HOME, every agent's home, XDG_CONFIG_HOME and the cwd at temp dirs
    for the rest of the process, and refuse (and record) any open or directory
    listing under the real home outside the repo and the Python install.

    Without this, every Fleet() reads ~/.config/actualis/suppressions and
    ./.actualis-suppressions, and a scan with no --root reads ~/.claude/projects:
    a developer's own suppressions or transcripts would change the results.
    """
    global REAL_HOME, TEMP_HOME, TEMP_CWD
    if getattr(sys, "_actualis_tests_isolated", False):     # imported under a second name
        return
    sys._actualis_tests_isolated = True
    REAL_HOME = os.path.expanduser("~")
    orig_cwd = os.getcwd()
    repo = str(Path(__file__).resolve().parent.parent)
    # Hex only: mkdtemp's random part may hold "__", which a test reads as an
    # unfilled template placeholder once the temp HOME is in a generated unit.
    while True:
        root = os.path.join(tempfile.gettempdir(), "actualis-tests-" + os.urandom(6).hex())
        try:
            os.mkdir(root, 0o700)
            break
        except FileExistsError:
            continue
    TEMP_HOME, TEMP_CWD = os.path.join(root, "home"), os.path.join(root, "cwd")
    os.makedirs(TEMP_HOME)
    os.makedirs(TEMP_CWD)
    os.environ.pop("CLAUDE_CONFIG_DIR", None)
    os.environ.update(
        HOME=TEMP_HOME, USERPROFILE=TEMP_HOME,
        XDG_CONFIG_HOME=os.path.join(TEMP_HOME, ".config"),
        CODEX_HOME=os.path.join(TEMP_HOME, ".codex"),
        COPILOT_HOME=os.path.join(TEMP_HOME, ".copilot"),
        GEMINI_CLI_HOME=TEMP_HOME,
        QWEN_HOME=os.path.join(TEMP_HOME, ".qwen"),
        QWEN_RUNTIME_DIR=os.path.join(TEMP_HOME, ".qwen"),
        XDG_CACHE_HOME=os.path.join(TEMP_HOME, ".cache"),
        ACTUALIS_REPUTATION_DIR=os.path.join(TEMP_HOME, ".cache", "actualis", "reputation"),
        LOCALAPPDATA=os.path.join(TEMP_HOME, "AppData", "Local"))
    os.chdir(TEMP_CWD)

    def norm(p):
        return os.path.normcase(os.path.abspath(p))
    real = norm(REAL_HOME)
    # Under the real home, only the code under test and the interpreter may be
    # read. The interpreter includes its bytecode cache when that lives outside
    # the source tree: Apple's /usr/bin/python3 (3.9.6) sets sys.pycache_prefix
    # to ~/Library/Caches/com.apple.python and reads and writes every .pyc there.
    pycache = getattr(sys, "pycache_prefix", None)
    allowed = tuple(sorted({norm(p) + os.sep for p in
                            (repo, sys.prefix, sys.base_prefix, sys.exec_prefix,
                             tempfile.gettempdir(), *(p for p in sys.path if p),
                             *((pycache,) if pycache else ()))
                            if norm(p) != real}))
    real_prefix = real + os.sep
    project_file = norm(os.path.join(orig_cwd, ".actualis-suppressions"))

    def audit(event, args):
        if event == "socket.getaddrinfo" and args:
            if str(args[0]).lower() not in _LOOPBACK:
                raise PermissionError(f"test isolation: DNS lookup of {args[0]}")
            return
        if event == "socket.connect" and len(args) > 1:
            addr = args[1]
            host = addr[0] if isinstance(addr, tuple) and addr else addr
            if isinstance(host, str) and host.lower() not in _LOOPBACK:
                raise PermissionError(f"test isolation: connect to {host}")
            return
        if event not in ("open", "os.scandir", "os.listdir") or not args or args[0] is None:
            return
        try:
            path = os.fspath(args[0])
        except TypeError:                      # a file descriptor
            return
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        full = norm(path)
        if full == project_file or ((full + os.sep).startswith(real_prefix)
                                    and not (full + os.sep).startswith(allowed)):
            LEAKS.append((event, full))
            raise PermissionError(f"test isolation: {event} on {full}, outside the temp home")

    sys.addaudithook(audit)

    def report():
        # Registered before anything below, so it runs last: after the temp
        # tree is gone and after unittest has printed its result.
        if LEAKS:
            sys.stdout.flush()
            sys.stderr.write("\nFAILED test isolation: tests touched the real home:\n"
                             + "".join(f"  {e} {p}\n" for e, p in sorted(set(LEAKS))))
            sys.stderr.flush()
            os._exit(1)
    atexit.register(report)
    atexit.register(shutil.rmtree, root, True)


_isolate_process()

CANARY = "sk_live_" + "abcdefghijklmnopqrst"
A = "aaaaaaaa-0000-4000-8000-000000000001"   # normal session, two models
B = "aaaaaaaa-0000-4000-8000-000000000002"   # no session.shutdown
C = "aaaaaaaa-0000-4000-8000-000000000003"   # a denied command
D = "aaaaaaaa-0000-4000-8000-000000000004"   # a credential in a command

USAGE_A = {
    "claude-haiku-4.5": {"inputTokens": 1_000_000, "outputTokens": 100_000,
                         "cacheReadTokens": 600_000, "cacheWriteTokens": 300_000,
                         "reasoningTokens": 20_000},
    "gpt-5-mini": {"inputTokens": 200_000, "outputTokens": 10_000,
                   "cacheReadTokens": 150_000, "cacheWriteTokens": 0,
                   "reasoningTokens": 5_000},
}
USAGE_D = {"claude-sonnet-4.5": {"inputTokens": 50_000, "outputTokens": 5_000,
                                 "cacheReadTokens": 0, "cacheWriteTokens": 0,
                                 "reasoningTokens": 0}}


def _start(sid, cwd, branch, ts):
    return ("session.start", {"sessionId": sid, "copilotVersion": "1.0.70",
                              "context": {"cwd": cwd, "gitRoot": cwd, "branch": branch}}, ts)


def _bash(call, cmd, ts):
    return ("tool.execution_start", {"toolCallId": call, "toolName": "bash",
                                     "arguments": {"command": cmd, "description": "x"}}, ts)


def _ask(call, req, ts):
    return ("permission.requested", {"requestId": req, "permissionRequest": {
        "kind": "shell", "toolCallId": call, "fullCommandText": "x"}}, ts)


def _done(call, req, kind, ts):
    return ("permission.completed", {"requestId": req, "toolCallId": call,
                                     "result": {"kind": kind}}, ts)


def _shutdown(metrics, premium, ts):
    return ("session.shutdown", {"shutdownType": "routine", "totalPremiumRequests": premium,
                                 "modelMetrics": {m: {"usage": u} for m, u in metrics.items()}},
            ts)


SESSIONS = {
    A: [_start(A, "/home/dev/orbital-ledger", "feature/ORB-412-ledger", "2026-09-02T10:00:00.000Z"),
        _bash("a1", "git status", "2026-09-02T10:01:00.000Z"),
        _ask("a2", "r1", "2026-09-02T10:02:00.000Z"),
        _done("a2", "r1", "approved", "2026-09-02T10:02:04.000Z"),
        _bash("a2", "npm test", "2026-09-02T10:02:05.000Z"),
        _bash("a3", "ls -la", "2026-09-02T10:03:00.000Z"),
        ("tool.execution_start", {"toolCallId": "a4", "toolName": "view",
                                  "arguments": {"path": "README.md"}}, "2026-09-02T10:04:00.000Z"),
        ("subagent.completed", {"toolCallId": "a5", "agentName": "explore",
                                "model": "claude-haiku-4.5", "totalTokens": 1200,
                                "totalToolCalls": 4, "durationMs": 5000},
         "2026-09-02T10:05:00.000Z"),
        _shutdown(USAGE_A, 0.33, "2026-09-02T11:00:00.000Z")],
    B: [_start(B, "/home/dev/atlas-gateway", "main", "2026-09-03T10:00:00.000Z"),
        _bash("b1", "make build", "2026-09-03T10:01:00.000Z")],
    C: [_start(C, "/home/dev/mesa-scheduler", "feature/MSA-9", "2026-09-04T10:00:00.000Z"),
        # The order and result kind of a real denial: the call starts, the
        # prompt is raised, and the person declines it.
        _bash("c1", "rm -rf ./dist", "2026-09-04T10:01:00.000Z"),
        _ask("c1", "r1", "2026-09-04T10:01:01.000Z"),
        _done("c1", "r1", "denied-interactively-by-user", "2026-09-04T10:01:05.000Z"),
        _shutdown({}, 0, "2026-09-04T11:00:00.000Z")],
    D: [_start(D, "/home/dev/quarry-cli", "fix/QRY-9", "2026-09-05T10:00:00.000Z"),
        _bash("d1", f"export STRIPE_KEY={CANARY}", "2026-09-05T10:01:00.000Z"),
        _bash("d2", "make deploy", "2026-09-05T10:02:00.000Z"),
        _shutdown(USAGE_D, 1.0, "2026-09-05T11:00:00.000Z")],
}


def write_sessions(state: Path) -> Path:
    """Write the four sessions under `state` (a session-state directory)."""
    for sid, events in SESSIONS.items():
        d = state / sid
        d.mkdir(parents=True, exist_ok=True)
        with (d / "events.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for n, (kind, data, ts) in enumerate(events):
                fh.write(json.dumps({"type": kind, "data": data, "id": f"e{n}",
                                     "parentId": None, "timestamp": ts}) + "\n")
    return state


def fresh_prices(af):
    """Patch the rate table to "verified today", by actualis's own clock.

    coach() adds AF013 to every fleet once the table is PRICING_STALE_DAYS old,
    so a test that expects no findings would start failing on a date, for no
    code reason. Such tests run under this instead of the wall clock.
    """
    today = af.datetime.now(af.timezone.utc).strftime("%Y-%m-%d")
    return mock.patch.object(af, "PRICING_VERIFIED", today)


@contextlib.contextmanager
def isolated_home():
    """A temp HOME with no agent config in it, on POSIX and Windows alike."""
    with tempfile.TemporaryDirectory() as td:
        env = {k: v for k, v in os.environ.items() if k not in AGENT_VARS}
        env.update(HOME=td, USERPROFILE=td)
        with mock.patch.dict(os.environ, env, clear=True):
            yield Path(td)
