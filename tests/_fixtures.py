"""Synthetic Copilot CLI sessions and an isolated home, for the tests.

Every value is invented. The shapes follow Copilot CLI 1.0.70's events.jsonl,
checked against 17 real sessions; no real content was copied. Written at test
time rather than committed, so the credential canary is assembled at runtime
and never sits in the tree as a literal.
"""
import contextlib
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

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


@contextlib.contextmanager
def isolated_home():
    """A temp HOME with no agent config in it, on POSIX and Windows alike."""
    with tempfile.TemporaryDirectory() as td:
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME")}
        env.update(HOME=td, USERPROFILE=td)
        with mock.patch.dict(os.environ, env, clear=True):
            yield Path(td)
