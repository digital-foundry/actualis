#!/usr/bin/env python3
"""Write a wholly invented agent fleet, for generating documentation images.

Nothing here derives from a real transcript. Project names, branches, commands
and credential shapes are all fabricated, so an image rendered from this can
never leak anything from the machine that built it. That is the entire point:
the alternative is scrubbing real output by hand, which goes wrong once.

    python3 tools/make-demo-fleet.py /tmp/actualis-demo-fleet
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


def pick(weighted):
    r, c = random.random(), 0.0
    for value, p in weighted:
        c += p
        if r < c:
            return value
    return weighted[-1][0]


def main(dest: str) -> None:
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


if __name__ == "__main__":
    main(sys.argv[1])
