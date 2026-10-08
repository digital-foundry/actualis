#!/usr/bin/env python3
"""Write a wholly invented agent fleet, for generating documentation images.

Nothing here derives from a real transcript. Project names, branches, commands
and credential shapes are all fabricated, so an image rendered from this can
never leak anything from the machine that built it. That is the entire point:
the alternative is scrubbing real output by hand, which goes wrong once.

    python3 tools/make-demo-fleet.py /tmp/actualis-demo-fleet [/tmp/actualis-demo-copilot]
"""
import json, pathlib, random, sys
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 7, 20, 9, 0, tzinfo=timezone.utc)
PROJECTS = {"-home-dev-orbital-ledger": ("ORB", 0.46),
            "-home-dev-atlas-gateway": ("ATL", 0.24),
            "-home-dev-mesa-scheduler": ("MSA", 0.16),
            "-home-dev-pinnacle-docs": ("PIN", 0.09),
            "-home-dev-quarry-cli": ("QRY", 0.05)}
MODELS = [("claude-opus-5", .74), ("claude-sonnet-5", .18), ("claude-haiku-4-5", .08)]
SAFE = ["npm test -- --run", "go build ./...", "git rebase -i origin/main", "pytest -q",
        "make lint", "docker compose up -d", "terraform plan", "rg TODO src/",
        "gh pr create --fill", "cargo clippy --all-targets"]
# Invented credential shapes. None has ever been valid anywhere.
LEAKY = ["export STRIPE_KEY=sk_live_00fictionalvalue0000",
         "curl -H 'Authorization: Bearer ghp_0000fictionalpat00000000' https://api.example.invalid",
         "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE aws s3 ls",
         "echo 'sk-ant-api03-0000fictionalkey0000' >> .env"]
RISKY = ["rm -rf ./build", "sudo systemctl restart orbital", "chmod 777 /tmp/cache"]

COPILOT_MODELS = ("claude-sonnet-4.5", "gpt-5-mini")


def copilot_sessions(dest: str) -> None:
    """Two invented Copilot CLI sessions, in its events.jsonl shape.

    Written after the Claude fleet, so the random stream that fleet consumes is
    unchanged and its images stay byte-identical.
    """
    state = pathlib.Path(dest) / "session-state"
    for s in range(2):
        sid = f"00000000-0000-4000-8000-00000000000{s + 1}"
        day = BASE + timedelta(days=8 + s * 12)
        events = [("session.start", {"sessionId": sid, "copilotVersion": "1.0.70",
                   "context": {"cwd": "/home/dev/orbital-ledger",
                               "gitRoot": "/home/dev/orbital-ledger",
                               "branch": f"feature/ORB-{700 + s}"}}, day)]
        for i in range(20):
            ts, call = day + timedelta(minutes=3 * i), f"call-{s}-{i}"
            if random.random() < .1:
                events.append(("permission.requested", {"requestId": call,
                               "permissionRequest": {"kind": "shell", "toolCallId": call}}, ts))
                events.append(("permission.completed", {"requestId": call, "toolCallId": call,
                               "result": {"kind": "approved"}}, ts))
            events.append(("tool.execution_start", {"toolCallId": call, "toolName": "bash",
                           "arguments": {"command": random.choice(SAFE)}}, ts))
        events.append(("session.shutdown", {
            "shutdownType": "routine", "totalPremiumRequests": 1.65,
            "modelMetrics": {m: {"usage": {
                "inputTokens": 900_000, "cacheReadTokens": 780_000,
                "cacheWriteTokens": 60_000 if m.startswith("claude") else 0,
                "outputTokens": 14_000, "reasoningTokens": 3_000}} for m in COPILOT_MODELS}},
            day + timedelta(hours=2)))
        d = state / sid
        d.mkdir(parents=True, exist_ok=True)
        with (d / "events.jsonl").open("w") as fh:
            for n, (kind, data, ts) in enumerate(events):
                fh.write(json.dumps({"type": kind, "data": data, "id": f"e{n}",
                                     "parentId": None, "timestamp": ts.isoformat()}) + "\n")


def pick(weighted):
    r, c = random.random(), 0.0
    for value, p in weighted:
        c += p
        if r < c:
            return value
    return weighted[-1][0]


def main(dest: str, copilot_dest=None) -> None:
    root = pathlib.Path(dest)
    random.seed(7)  # fixed: the same fleet every time, so images are reproducible
    for pdir, (tag, share) in PROJECTS.items():
        d = root / pdir
        d.mkdir(parents=True, exist_ok=True)
        with (d / "session.jsonl").open("w") as fh:
            for _ in range(int(300 * share)):
                ts = (BASE + timedelta(days=random.randint(0, 30),
                                       hours=random.randint(0, 10),
                                       minutes=random.randint(0, 59))).isoformat()
                fh.write(json.dumps({
                    "timestamp": ts,
                    "gitBranch": f"feature/{tag}-{random.randint(100, 999)}",
                    "permissionMode": random.choice(["auto", "auto", "auto", "default"]),
                    "message": {"model": pick(MODELS), "usage": {
                        "input_tokens": random.randint(200, 3_000),
                        "output_tokens": random.randint(300, 4_500),
                        "cache_read_input_tokens": random.randint(180_000, 900_000),
                        "cache_creation_input_tokens": random.randint(2_000, 24_000)}}}) + "\n")
                if random.random() < .55:
                    cmd = random.choice(SAFE)
                    if random.random() < .05:
                        cmd = random.choice(LEAKY)
                    elif random.random() < .08:
                        cmd = random.choice(RISKY)
                    fh.write(json.dumps({
                        "timestamp": ts,
                        "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                 "input": {"command": cmd}}]}}) + "\n")
    print(f"  synthetic fleet: {len(list(root.rglob('*.jsonl')))} files, "
          f"{len(PROJECTS)} projects, at {root}")
    if copilot_dest:
        copilot_sessions(copilot_dest)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
