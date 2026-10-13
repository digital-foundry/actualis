"""Transcripts are untrusted: any field can hold any JSON type.

Each case here came from tools/security/fuzz_transcripts.py, which mutates
synthetic transcripts and fails on a traceback. A wrong-typed field must be
skipped or read as absent, never crash the run.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
spec.loader.exec_module(af)


def claude_line(**over):
    rec = {"type": "assistant", "timestamp": "2026-10-01T10:00:00Z", "sessionId": "s1",
           "cwd": "/home/dev/orbital-ledger",
           "message": {"id": "m1", "model": "claude-sonnet-5", "role": "assistant",
                       "usage": {"input_tokens": 100, "output_tokens": 50},
                       "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                                    "input": {"command": "npm i left-pad"}}]}}
    for k, v in over.items():
        *parents, leaf = k.split("__")
        target = rec
        for p in parents:
            target = target[p]
        target[leaf] = v
    return rec


def scan(*recs):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "-home-dev-orbital-ledger"
        d.mkdir()
        (d / "s1.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        f = af.Fleet()
        f.scan([Path(tmp)], None, None, False)
        return f


class TestParseTs(unittest.TestCase):
    def test_non_strings_are_absent(self):
        for raw in (0, 17.5, True, [], {}, ["2026-10-01"], {"t": 1}):
            self.assertIsNone(af.parse_ts(raw), raw)

    def test_string_still_parses(self):
        self.assertEqual(af.parse_ts("2026-10-01T10:00:00Z").year, 2026)

    def test_wrong_typed_timestamp_does_not_crash_a_scan(self):
        for raw in (1, {}, [], 2.5, False):
            scan(claude_line(timestamp=raw))


class TestTokenCounts(unittest.TestCase):
    def test_tokens_coercion(self):
        cases = [(5, 5), (5.9, 5), ("100", 0), (None, 0), (True, 0), (-3, 0),
                 (float("nan"), 0), (float("inf"), 0), ([1], 0), ({}, 0)]
        for raw, want in cases:
            self.assertEqual(af._tokens(raw), want, raw)

    def test_string_and_negative_tokens_cost_nothing(self):
        f = scan(claude_line(message__usage={"input_tokens": "1000", "output_tokens": -500,
                                             "cache_creation": "x"}))
        self.assertEqual(f.messages, 1)
        self.assertGreaterEqual(sum(f.cost_by_tier.values()), 0)


class TestToolInputAndIds(unittest.TestCase):
    def test_string_tool_input_is_skipped(self):
        rec = claude_line()
        rec["message"]["content"][0]["input"] = "npm i left-pad"
        f = scan(rec)
        self.assertEqual(f.network_items, [])

    def test_unhashable_message_id(self):
        f = scan(claude_line(message__id=["m1"]), claude_line(message__id={"x": 1}))
        self.assertEqual(f.messages, 2)


if __name__ == "__main__":
    unittest.main()
