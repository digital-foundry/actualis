"""Network item detail: why, prompt, mode and the transcript record behind it.

why is the assistant's own text before the tool call; prompt is the person's
last real message before the turn; transcript points at the exact file and
line. All synthetic.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(spec)
    sys.modules["actualis"] = af
    spec.loader.exec_module(af)

SECRET = "sk-ant-api03-" + "Z" * 40
USAGE = {"input_tokens": 10, "output_tokens": 5}


def user(content, ts="2026-10-07T14:20:00Z", **extra):
    return {"type": "user", "timestamp": ts, "sessionId": "3f2a1b2c-0000-4000-8000-00000000000a",
            "message": {"role": "user", "content": content}, **extra}


def assistant(mid, blocks, ts="2026-10-07T14:22:00Z", mode="bypassPermissions"):
    return {"type": "assistant", "timestamp": ts, "permissionMode": mode,
            "sessionId": "3f2a1b2c-0000-4000-8000-00000000000a",
            "message": {"id": mid, "role": "assistant", "model": "claude-opus-5-5",
                        "content": blocks, "usage": USAGE}}


def text(t):
    return {"type": "text", "text": t}


def use(tid, name, inp):
    return {"type": "tool_use", "id": tid, "name": name, "input": inp}


LONG = "Then " + " ".join(["I will carefully reproduce the failing install"] * 12) + " now"

CLAUDE = [
    user(f"Please add lodash to the project\nand pin it. token={SECRET}"),         # 1
    user("<local-command-caveat>Caveat: ignore</local-command-caveat>", isMeta=True),  # 2
    user("<command-name>/clear</command-name>\n<command-message>clear</command-message>"),  # 3
    user("<local-command-stdout>cleared</local-command-stdout>"),                   # 4
    user([text("<system-reminder>be careful</system-reminder>")]),                   # 5
    assistant("m1", [text("I checked the docs. Now I will install lodash at an exact "
                          "version so builds are reproducible.")]),                 # 6
    assistant("m1", [use("toolu_1", "Bash", {"command": "npm i lodash@4.17.21"})]),  # 7
    user([{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]),      # 8
    assistant("m2", [use("toolu_2", "Bash", {"command": "curl -o s.json https://api.example/s"}),
                     text("this text comes after the call")]),                      # 9
    user([text("Now fetch the \x1b[31mschema\x1b[0m"), {"type": "image", "source": {}}]),  # 10
    assistant("m3", [text("Fetching.\n\nIt is on the docs\tsite."),
                     use("toolu_3", "WebFetch", {"url": "https://docs.example/schema"})]),  # 11
    assistant("m4", [text(LONG + "."), use("toolu_4", "Bash", {"command": "pip install six==1.16.0"})],
              mode="default"),                                                      # 12
]


def write_claude(base: Path) -> Path:
    root = base / "projects"
    (root / "-Users-x-proj").mkdir(parents=True)
    (root / "-Users-x-proj" / "3f2a.jsonl").write_text(
        "\n".join(json.dumps(r) for r in CLAUDE) + "\n")
    return root


def by_call(fleet):
    return {i["call_id"]: i for i in fleet.network_items}


class TestClaudeDetail(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = write_claude(Path(self._tmp.name))
        self.fleet = af.Fleet()
        self.fleet.scan([self.root], None, None, progress=False)
        self.items = by_call(self.fleet)

    def test_why_is_the_last_sentence_before_the_call_in_the_same_message(self):
        self.assertEqual(self.items["toolu_1"]["why"],
                         "Now I will install lodash at an exact version so builds are reproducible.")

    def test_text_after_the_call_is_not_why(self):
        self.assertIsNone(self.items["toolu_2"]["why"])

    def test_why_in_the_same_record_is_cleaned_and_collapsed(self):
        self.assertEqual(self.items["toolu_3"]["why"], "It is on the docs site.")

    def test_long_why_is_cut_on_a_word_boundary(self):
        why = self.items["toolu_4"]["why"]
        self.assertLessEqual(len(why), 160)
        self.assertTrue(why.endswith("…"), why)
        self.assertTrue(LONG.startswith(why[:-1].rstrip()), why)

    def test_prompt_is_the_last_real_user_message(self):
        p = self.items["toolu_1"]["prompt"]
        self.assertTrue(p.startswith("Please add lodash to the project and pin it."), p)
        self.assertNotIn("Z" * 12, p)                   # redacted at ingest
        self.assertNotIn("\n", p)
        # tool_result-only, isMeta, command wrappers and reminders never replace it
        self.assertEqual(self.items["toolu_2"]["prompt"], p)
        self.assertEqual(self.items["toolu_3"]["prompt"], "Now fetch the [31mschema[0m")
        self.assertNotIn("\x1b", self.items["toolu_3"]["prompt"])

    def test_mode_is_the_key_approval_was_judged_from(self):
        self.assertEqual(self.items["toolu_1"]["mode"], "bypassPermissions")
        self.assertEqual(self.items["toolu_4"]["mode"], "default")
        self.assertEqual(self.items["toolu_4"]["approval"], "unknown")

    def test_transcript_names_root_file_and_line(self):
        t = self.items["toolu_1"]["transcript"]
        self.assertEqual(t, {"root": str(self.root), "file": "-Users-x-proj/3f2a.jsonl", "line": 7})
        self.assertEqual(self.items["toolu_3"]["transcript"]["line"], 11)

    def test_the_reported_line_holds_the_call_id(self):
        """sed -n '<line>p' <root>/<file> shows the exact record."""
        for cid, item in self.items.items():
            t = item["transcript"]
            lines = (Path(t["root"]) / t["file"]).read_text().splitlines()
            self.assertIn(cid, lines[t["line"] - 1], cid)

    def test_why_and_prompt_are_redacted_even_with_no_redact(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://a.example/x"}, None, "auto",
                   why=f"use key {SECRET}", prompt=f"key={SECRET}\nplease")
        [i] = f.network_items
        self.assertNotIn("Z" * 12, i["why"] + i["prompt"])
        self.assertNotIn("\n", i["prompt"])
        pub = af._net_public(i, raw=True, prompts=True)
        self.assertNotIn("Z" * 12, pub["why"] + pub["prompt"])


class TestOtherAgentsDetail(unittest.TestCase):
    def test_codex_reasoning_and_message_text(self):
        recs = [
            {"timestamp": "2026-10-01T10:00:00Z", "type": "session_meta",
             "payload": {"id": "cx-1", "cwd": "/Users/x/proj"}},
            {"timestamp": "2026-10-01T10:00:00Z", "type": "turn_context",
             "payload": {"cwd": "/Users/x/proj", "approval_policy": "never"}},
            {"timestamp": "2026-10-01T10:00:01Z", "type": "response_item", "payload": {
                "type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "<environment_context>x</environment_context>"}]}},
            {"timestamp": "2026-10-01T10:00:01Z", "type": "event_msg",
             "payload": {"type": "user_message", "message": "install requests please"}},
            {"timestamp": "2026-10-01T10:00:02Z", "type": "response_item", "payload": {
                "type": "reasoning", "summary": [{"type": "summary_text", "text": "**Plan** Need requests."}]}},
            {"timestamp": "2026-10-01T10:00:03Z", "type": "response_item", "payload": {
                "type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "Installing requests now."}]}},
            {"timestamp": "2026-10-01T10:00:04Z", "type": "response_item", "payload": {
                "type": "function_call", "name": "shell_command", "call_id": "c1",
                "arguments": json.dumps({"command": "pip install requests"})}},
            {"timestamp": "2026-10-01T10:00:05Z", "type": "response_item", "payload": {
                "type": "function_call_output", "call_id": "c1", "output": "ok"}},
            {"timestamp": "2026-10-01T10:00:06Z", "type": "response_item", "payload": {
                "type": "function_call", "name": "shell_command", "call_id": "c2",
                "arguments": json.dumps({"command": "curl -O https://b.example/f"})}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            day = Path(tmp) / "2026" / "10" / "01"
            day.mkdir(parents=True)
            (day / "rollout-2026-10-01T10-00-00-cx-1.jsonl").write_text(
                "\n".join(json.dumps(r) for r in recs) + "\n")
            f = af.Fleet()
            f.scan_codex([Path(tmp)], None, None)
        first, second = sorted(f.network_items, key=lambda i: i["transcript"]["line"])
        self.assertEqual((first["why"], first["prompt"], first["mode"]),
                         ("Installing requests now.", "install requests please", "codex:never"))
        self.assertEqual(first["transcript"],
                         {"root": tmp, "file": "2026/10/01/rollout-2026-10-01T10-00-00-cx-1.jsonl",
                          "line": 7})
        self.assertIsNone(second["why"])                # its output came back first
        self.assertEqual((second["prompt"], second["transcript"]["line"]),
                         ("install requests please", 9))

    def test_copilot_user_and_assistant_messages(self):
        sid = "ffffffff-0000-0000-0000-000000000001"
        events = [
            {"type": "session.start", "timestamp": "2026-10-01T10:00:00Z",
             "data": {"sessionId": sid, "context": {"cwd": "/Users/x/proj"}}},
            {"type": "user.message", "timestamp": "2026-10-01T10:00:01Z",
             "data": {"content": "grab the API docs"}},
            {"type": "assistant.message", "timestamp": "2026-10-01T10:00:02Z",
             "data": {"content": "I'll fetch the page.", "toolRequests": []}},
            {"type": "tool.execution_start", "timestamp": "2026-10-01T10:00:03Z",
             "data": {"toolCallId": "k1", "toolName": "web_fetch",
                      "arguments": {"url": "https://a.io/doc"}}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / sid
            d.mkdir(parents=True)
            (d / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
            f = af.Fleet()
            f.scan_copilot([Path(tmp)], None, None)
        [i] = f.network_items
        self.assertEqual((i["why"], i["prompt"], i["mode"]),
                         ("I'll fetch the page.", "grab the API docs", "copilot:auto"))
        self.assertEqual(i["transcript"], {"root": tmp, "file": f"{sid}/events.jsonl", "line": 4})


class TestJson(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = write_claude(base)
        self.home = base / "home"
        self.home.mkdir()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")}
        old = os.getcwd()
        os.chdir(self.home)
        try:
            with mock.patch.dict(os.environ, env), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = af.main([*argv, "--root", str(self.root)])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old)
        return code, out.getvalue(), err.getvalue()

    def test_items_carry_the_new_keys_and_prompt_is_null_by_default(self):
        for argv, pick in ((["--network", "--json"], lambda d: d),
                           (["--json"], lambda d: d["network"])):
            code, out, err = self.run_main(*argv)
            self.assertEqual(code, 0, err)
            items = pick(json.loads(out))["items"]
            self.assertTrue(items)
            for i in items:
                self.assertIn("why", i)
                self.assertIn("mode", i)
                self.assertIsNone(i["prompt"])
                self.assertEqual(set(i["transcript"]), {"root", "file", "line"})
            self.assertNotIn("Please add lodash", out)

    def test_with_prompts_emits_them_redacted(self):
        code, out, err = self.run_main("--network", "--json", "--with-prompts")
        self.assertEqual(code, 0, err)
        prompts = {i["prompt"] for i in json.loads(out)["items"]}
        self.assertTrue(any(p and p.startswith("Please add lodash") for p in prompts))
        self.assertNotIn("Z" * 12, out)
        code, out, _ = self.run_main("--json", "--with-prompts")
        self.assertTrue(any(i["prompt"] for i in json.loads(out)["network"]["items"]))

    def test_with_prompts_needs_json(self):
        code, _, err = self.run_main("--network", "--with-prompts")
        self.assertEqual(code, 2)
        self.assertIn("--with-prompts", err)

    def test_schema_declares_the_keys(self):
        for key, typ in (("network.items[].why", "str|null"), ("network.items[].prompt", "str|null"),
                         ("network.items[].mode", "str|null"),
                         ("network.items[].transcript", "object|null"),
                         ("network.items[].transcript.root", "str"),
                         ("network.items[].transcript.file", "str"),
                         ("network.items[].transcript.line", "int|null")):
            self.assertEqual(af.JSON_SCHEMA.get(key), typ, key)
        self.assertEqual(af.JSON_SCHEMA_VERSION, 1)

    def test_explain_documents_what_each_agent_provides(self):
        out = io.StringIO()
        with redirect_stdout(out):
            af.render_explain("network", af.C(False))
        flat = " ".join(out.getvalue().split())
        for needle in ("why", "--with-prompts", "Codex", "Copilot", "sed -n"):
            self.assertIn(needle, flat)


if __name__ == "__main__":
    unittest.main()
