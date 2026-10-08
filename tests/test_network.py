"""Network inventory: what the agent downloaded, and whether anyone asked."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
af = importlib.util.module_from_spec(spec)
sys.modules["actualis"] = af
spec.loader.exec_module(af)
af.SRC_TEXT = (ROOT / "actualis.py").read_text(encoding="utf-8")
af.SRC_PATH = ROOT / "actualis.py"

TS = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def items(cmd):
    return af.network_items_from_command(cmd)[0]


def one(cmd):
    found = items(cmd)
    assert len(found) == 1, (cmd, found)
    return found[0]


class TestUrlHost(unittest.TestCase):
    def test_hosts(self):
        cases = {
            "https://raw.githubusercontent.com/a/b/x.sh": "raw.githubusercontent.com",
            "https://user:pw@Example.COM:8443/p?q=1": "example.com",
            "git@github.com:digital-foundry/actualis.git": "github.com",
            "ssh://git@gitlab.com/x/y.git": "gitlab.com",
            "$URL": None,
            "origin": None,
            "": None,
        }
        for url, host in cases.items():
            self.assertEqual(af.url_host(url), host, url)

    def test_paths(self):
        self.assertEqual(af.url_path("https://github.com/digital-foundry/actualis?x=1"), "/digital-foundry/actualis")
        self.assertEqual(af.url_path("git@github.com:digital-foundry/actualis.git"), "/digital-foundry/actualis.git")
        self.assertEqual(af.url_path("https://example.com"), "")


class TestFetchers(unittest.TestCase):
    def test_curl_output_and_host(self):
        it = one("curl -fsSL -o ~/bin/x https://raw.githubusercontent.com/a/b/x")
        self.assertEqual((it["kind"], it["program"], it["host"], it["dest"]), ("fetch", "curl", "raw.githubusercontent.com", "~/bin/x"))

    def test_curl_dynamic_url(self):
        it = one('curl -s "$URL"')
        self.assertEqual((it["host"], it["dynamic"]), (None, True))

    def test_curl_without_url_is_nothing(self):
        self.assertEqual(items("curl --version"), [])

    def test_wget(self):
        it = one("wget -O out.tgz https://example.com/a.tgz")
        self.assertEqual((it["program"], it["host"], it["dest"]), ("wget", "example.com", "out.tgz"))

    def test_prefixes_are_stripped(self):
        for cmd in ("sudo -u root curl https://a.io/x", "FOO=1 curl https://a.io/x", "env A=b curl https://a.io/x",
                    "time curl https://a.io/x", "nohup curl https://a.io/x", "/usr/bin/curl https://a.io/x"):
            self.assertEqual(one(cmd)["host"], "a.io", cmd)

    def test_compound_and_cd(self):
        found = items("cd /tmp && curl https://a.io/x; wget https://b.io/y || true")
        self.assertEqual([i["host"] for i in found], ["a.io", "b.io"])

    def test_pipe_to_shell_is_one_fetch(self):
        self.assertEqual([i["host"] for i in items("curl -fsSL https://get.x.io | sh")], ["get.x.io"])

    def test_command_substitution(self):
        self.assertEqual([i["host"] for i in items('echo "$(curl -s https://a.io/v)"')], ["a.io"])
        self.assertEqual([i["host"] for i in items("X=`wget -qO- https://b.io/v`")], ["b.io"])

    def test_bash_c_with_quoted_pipe(self):
        found, unparsed = af.network_items_from_command('bash -c "curl -s https://a.io/i | sh"')
        self.assertEqual(([i["host"] for i in found], unparsed), (["a.io"], 0))

    def test_unbalanced_quote_is_counted_not_guessed(self):
        found, unparsed = af.network_items_from_command('curl "https://a.io/x')
        self.assertEqual((found, unparsed), ([], 1))

    def test_heredoc_body_is_not_a_command(self):
        self.assertEqual(items("cat <<EOF > f\ncurl https://a.io/x\nEOF"), [])


class TestVcs(unittest.TestCase):
    def test_git_clone(self):
        it = one("git clone --depth 1 https://github.com/o/r.git dest")
        self.assertEqual((it["kind"], it["host"], it["dest"]), ("clone", "github.com", "dest"))

    def test_git_scp_remote_and_global_flag(self):
        self.assertEqual(one("git -C /x clone git@gitlab.com:o/r.git")["host"], "gitlab.com")

    def test_git_pull_remote_name_has_no_host(self):
        it = one("git pull origin main")
        self.assertEqual((it["kind"], it["host"], it["dynamic"]), ("clone", None, False))

    def test_git_local_commands_are_nothing(self):
        self.assertEqual(items("git status && git commit -m x && git push"), [])

    def test_gh(self):
        self.assertEqual(one("gh repo clone o/r")["url"], "https://github.com/o/r")
        it = one("gh release download v1 -R o/r -D dl")
        self.assertEqual((it["kind"], it["host"], it["dest"]), ("fetch", "github.com", "dl"))


class TestPackages(unittest.TestCase):
    def test_npm_install_packages(self):
        found = items("npm i lodash@4.17.21 @scope/pkg left-pad@^1")
        self.assertEqual([(i["package"], i["version"], i["pinned"]) for i in found],
                         [("lodash", "4.17.21", True), ("@scope/pkg", None, False), ("left-pad", "^1", False)])
        self.assertTrue(all(i["host"] == "registry.npmjs.org" and i["host_inferred"] for i in found))

    def test_npm_registry_override(self):
        it = one("npm install x --registry https://npm.corp.io/")
        self.assertEqual((it["host"], it["host_inferred"]), ("npm.corp.io", False))

    def test_lockfile_installs_are_pinned(self):
        for cmd in ("npm ci", "pnpm install --frozen-lockfile", "yarn --immutable", "uv sync"):
            it = one(cmd)
            self.assertEqual((it["kind"], it["package"], it["pinned"]), ("install", None, True), cmd)

    def test_bare_npm_install_is_unpinned(self):
        it = one("npm install")
        self.assertEqual((it["package"], it["pinned"]), (None, False))

    def test_npm_git_specs(self):
        self.assertEqual(one("npm i github:o/r")["host"], "github.com")
        self.assertEqual(one("npm i git+https://gitlab.com/o/r.git")["host"], "gitlab.com")
        self.assertEqual(items("npm i ./local-pkg"), [])

    def test_npx_is_exec(self):
        it = one("npx -y create-foo@latest app")
        self.assertEqual((it["program"], it["package"], it["version"], it["exec"], it["pinned"]),
                         ("npx", "create-foo", "latest", True, False))
        self.assertEqual(one("pnpm dlx cowsay")["exec"], True)

    def test_pip(self):
        found = items("pip install requests==2.32.3 'httpx>=0.27' -i https://pypi.corp.io/simple")
        self.assertEqual([(i["package"], i["version"], i["pinned"], i["host"]) for i in found],
                         [("requests", "2.32.3", True, "pypi.corp.io"), ("httpx", None, False, "pypi.corp.io")])

    def test_python_m_pip_and_requirements(self):
        it = one("python3 -m pip install -r requirements.txt")
        self.assertEqual((it["program"], it["source"], it["package"]), ("pip", "requirements.txt", None))

    def test_pip_git_url(self):
        self.assertEqual(one("pip install git+https://github.com/o/r.git")["host"], "github.com")

    def test_uv(self):
        self.assertEqual(one("uv add httpx")["package"], "httpx")
        self.assertEqual(one("uv pip install ruff==0.6.0")["pinned"], True)

    def test_uvx_and_pipx(self):
        it = one("uvx ruff@0.6.0 check")
        self.assertEqual((it["package"], it["version"], it["exec"], it["pinned"]), ("ruff", "0.6.0", True, True))
        self.assertEqual(one("pipx install black")["exec"], False)
        self.assertEqual(one("pipx run black")["exec"], True)

    def test_brew_cargo_go_docker(self):
        self.assertEqual([i["package"] for i in items("brew install jq gh")], ["jq", "gh"])
        it = one("cargo install ripgrep --version 14.1.0")
        self.assertEqual((it["ecosystem"], it["package"], it["pinned"], it["host"]), ("crates", "ripgrep", True, "crates.io"))
        it = one("go install golang.org/x/tools/gopls@v0.16.1")
        self.assertEqual((it["host"], it["pinned"], it["host_inferred"]), ("golang.org", True, False))
        it = one("docker pull ghcr.io/o/img@sha256:abc")
        self.assertEqual((it["host"], it["package"], it["pinned"]), ("ghcr.io", "ghcr.io/o/img", True))
        it = one("docker run --rm -v /a:/b node:20 npm test")
        self.assertEqual((it["host"], it["package"], it["version"], it["host_inferred"]),
                         ("registry-1.docker.io", "node", "20", True))

    def test_item_keys_are_fixed(self):
        keys = {"kind", "program", "host", "host_inferred", "url", "dest", "source", "ecosystem",
                "package", "version", "pinned", "exec", "dynamic"}
        for cmd in ("curl https://a.io", "npm ci", "git pull", "docker pull x"):
            self.assertEqual(set(one(cmd)), keys, cmd)


class TestReviewFixes(unittest.TestCase):
    def test_nested_substitution_keeps_outer_curl(self):
        for cmd in ("echo $(curl https://o.io/$(date))", "x=$(curl -s https://o.io/$(cat v))"):
            it = one(cmd)
            self.assertEqual((it["program"], it["host"]), ("curl", "o.io"), cmd)

    def test_three_level_nesting(self):
        found = items("echo $(echo $(echo $(curl https://deep.io/x)))")
        self.assertEqual([i["host"] for i in found], ["deep.io"])

    def test_escaped_quotes(self):
        found, unparsed = af.network_items_from_command(r'sh -c "bash -c \"curl https://a.io\""')
        self.assertEqual(([i["host"] for i in found], unparsed), (["a.io"], 0))
        found, unparsed = af.network_items_from_command(r'echo \"; curl https://a.io')
        self.assertEqual(([i["host"] for i in found], unparsed), (["a.io"], 0))

    def test_ipv6_hosts(self):
        self.assertEqual(af.url_host("http://[::1]:8080/"), "[::1]")
        self.assertEqual(af.url_host("https://[2001:DB8::1]/x"), "[2001:db8::1]")

    def test_brew_tap_clones_from_github(self):
        it = one("brew tap foo/bar")
        self.assertEqual((it["kind"], it["host"], it["url"], it["host_inferred"]),
                         ("clone", "github.com", "https://github.com/foo/homebrew-bar", True))
        self.assertEqual(one("brew install jq")["host"], "formulae.brew.sh")

    def test_file_url_is_a_fetch_without_host(self):
        it = one("curl file:///etc/passwd")
        self.assertEqual((it["kind"], it["host"], it["dynamic"]), ("fetch", None, False))

    def test_unbalanced_substitutions_are_linear(self):
        import time
        cmd = "$(" * 20000 + "curl https://a.io"
        start = time.monotonic()
        af.network_items_from_command(cmd)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_paren_inside_quotes_does_not_end_substitution(self):
        found, unparsed = af.network_items_from_command('x=$(echo ")"); curl https://b.io')
        self.assertEqual(([i["host"] for i in found], unparsed), (["b.io"], 0))
        found, unparsed = af.network_items_from_command('x=$(echo ")" ; curl https://a.io)')
        self.assertEqual(([i["host"] for i in found], unparsed), (["a.io"], 0))

    def test_nesting_beyond_the_cap_is_counted(self):
        cmd = "echo $(echo $(echo $(echo $(echo $(curl https://a.io)))))"
        self.assertGreaterEqual(af.network_items_from_command(cmd)[1], 1)


class TestToolCalls(unittest.TestCase):
    def test_webfetch_and_search(self):
        it = af.network_items_from_tool("WebFetch", {"url": "https://docs.x.io/a", "prompt": "p"})[0]
        self.assertEqual((it["kind"], it["program"], it["host"]), ("fetch", "WebFetch", "docs.x.io"))
        it = af.network_items_from_tool("WebSearch", {"query": "secret plans"})[0]
        self.assertEqual((it["kind"], it["host"]), ("search", None))
        self.assertNotIn("secret plans", json.dumps(it))

    def test_copilot_and_mcp_names(self):
        self.assertEqual(af.network_items_from_tool("web_fetch", {"url": "https://a.io"})[0]["host"], "a.io")
        self.assertEqual(af.network_items_from_tool("mcp__browser__fetch_page", {"uri": "https://b.io/x"})[0]["host"], "b.io")
        self.assertEqual(af.network_items_from_tool("Read", {"file_path": "/x"}), [])
        self.assertEqual(af.network_items_from_tool("Bash", {"command": "curl https://a.io"}), [])


class TestApproval(unittest.TestCase):
    def test_mapping(self):
        cases = {"auto": "unasked", "bypassPermissions": "unasked", "codex:never": "unasked",
                 "copilot:auto": "unasked", "copilot:prompted": "asked", "default": "unknown",
                 "acceptEdits": "unknown", "plan": "unknown", "codex:on-request": "unknown", None: "unknown"}
        for mode, want in cases.items():
            self.assertEqual(af.network_approval(mode), want, mode)


def claude_session(tmp, records):
    d = Path(tmp) / "-Users-x-proj"
    d.mkdir(exist_ok=True)
    (d / "s.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n")
    f = af.Fleet()
    f.scan([Path(tmp)], None, None, progress=False)
    return f


def call(tid, command=None, name="Bash", inp=None, mode=None, ts="2026-10-01T10:00:00Z"):
    rec = {"timestamp": ts, "type": "assistant", "uuid": "a" + tid, "sessionId": "sess-1",
           "message": {"id": "m" + tid, "role": "assistant",
                       "content": [{"type": "tool_use", "id": tid, "name": name,
                                    "input": inp if inp is not None else {"command": command}}]}}
    if mode:
        rec["permissionMode"] = mode
    return rec


def result(tid, is_error, denial=None):
    rec = {"timestamp": "2026-10-01T10:00:01Z", "type": "user", "uuid": "r" + tid,
           "message": {"role": "user", "content": [
               {"type": "tool_result", "tool_use_id": tid, "is_error": is_error, "content": "x"}]}}
    if denial:
        rec["toolDenialKind"] = denial
    return rec


class TestFleetIntegration(unittest.TestCase):
    def test_claude_items_carry_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", "curl -o x https://a.io/x", mode="bypassPermissions")])
        [it] = f.network_items
        self.assertEqual((it["agent"], it["approval"], it["session"], it["failed"], it["trusted"]),
                         ("claude", "unasked", "sess-1", False, False))
        self.assertEqual(it["ts"], "2026-10-01T10:00:00+00:00")

    def test_failed_result_marks_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", "curl https://a.io/x"), result("t1", True)])
        self.assertIs(f.network_items[0]["failed"], True)

    def test_refused_call_is_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", "curl https://a.io/x"), result("t1", True, "user-rejected")])
        self.assertEqual(f.network_items, [])
        self.assertEqual(f.refusals, 1)

    def test_webfetch_through_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", name="WebFetch", inp={"url": "https://docs.x.io"}, mode="auto")])
        self.assertEqual([(i["kind"], i["host"]) for i in f.network_items], [("fetch", "docs.x.io")])

    def test_direct_add_tool_infers_agent_from_mode(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "npm i x"}, TS, "codex:never")
        f.add_tool("p", "Bash", {"command": "curl 'https://a.io"}, TS, "codex:never")
        self.assertEqual([(i["agent"], i["approval"], i["failed"]) for i in f.network_items],
                         [("codex", "unasked", None)])
        self.assertEqual(f.network_unparsed, 1)

    def test_existing_counters_unchanged(self):
        f = af.Fleet()
        f.add_tool("p", "WebFetch", {"url": "https://a.io"}, TS, "auto")
        self.assertEqual((f.tools["WebFetch"], f.bash_total), (1, 0))


class TestOtherAgents(unittest.TestCase):
    def test_codex_shell_command_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rollout-2026-10-01T10-00-00-cx-1.jsonl"
            recs = [
                {"timestamp": "2026-10-01T10:00:00Z", "type": "session_meta", "payload": {"id": "cx-1", "cwd": "/Users/x/proj"}},
                {"timestamp": "2026-10-01T10:00:00Z", "type": "turn_context", "payload": {"cwd": "/Users/x/proj", "approval_policy": "never"}},
                {"timestamp": "2026-10-01T10:00:01Z", "type": "response_item", "payload": {
                    "type": "function_call", "name": "shell_command", "call_id": "c1",
                    "arguments": json.dumps({"command": "pip install requests", "workdir": "/Users/x/proj"})}},
            ]
            p.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
            f = af.Fleet()
            f.scan_codex([Path(tmp)], None, None)
        [it] = f.network_items
        self.assertEqual((it["agent"], it["approval"], it["session"], it["failed"], it["package"]),
                         ("codex", "unasked", "cx-1", None, "requests"))

    def test_copilot_web_fetch_keeps_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            sid = "ffffffff-0000-0000-0000-000000000001"
            d = Path(tmp) / "session-state" / sid
            d.mkdir(parents=True)
            events = [
                {"type": "session.start", "timestamp": "2026-10-01T10:00:00Z",
                 "data": {"sessionId": sid, "context": {"cwd": "/Users/x/proj"}}},
                {"type": "tool.execution_start", "timestamp": "2026-10-01T10:00:01Z",
                 "data": {"toolCallId": "k1", "toolName": "web_fetch", "arguments": {"url": "https://a.io/doc"}}},
            ]
            (d / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
            f = af.Fleet()
            f.scan_copilot([Path(tmp) / "session-state"], None, None)
        [it] = f.network_items
        self.assertEqual((it["agent"], it["host"], it["approval"], it["session"]),
                         ("copilot", "a.io", "unasked", sid))


class TestFleetFixRound1(unittest.TestCase):
    def test_error_only_result_does_not_move_subagent_counters(self):
        sub = result("t1", True)
        sub["toolUseResult"] = {"toolStats": {"bashCount": 1}, "status": "completed",
                                "totalDurationMs": 5, "resolvedModel": "claude-sonnet-4-5"}
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", "curl https://a.io/x"), sub])
            base = claude_session(tmp, [call("t1", "curl https://a.io/x")])
        self.assertEqual(f.sub_calls, base.sub_calls)
        self.assertEqual(f.sub_calls, 0)
        self.assertIs(f.network_items[0]["failed"], True)

    def test_denial_without_is_error_drops_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = claude_session(tmp, [call("t1", "curl https://a.io/x"),
                                     result("t1", False, "user-rejected")])
        self.assertEqual(f.network_items, [])
        self.assertEqual(f.refusals, 1)

    def test_refusal_in_a_later_file_drops_the_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "-Users-x-proj"
            d.mkdir()
            (d / "a.jsonl").write_text(json.dumps(call("t1", "curl https://a.io/x")) + "\n")
            (d / "b.jsonl").write_text(json.dumps(result("t1", True, "user-rejected")) + "\n")
            f = af.Fleet()
            f.scan([Path(tmp)], None, None, progress=False)
        self.assertEqual(f.network_items, [])


class TestTrust(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(af.parse_trust(["NPMjs.org", "github.com/digital-foundry/", " ", "pypi.org/simple"]),
                         [("npmjs.org", ""), ("github.com", "/digital-foundry"), ("pypi.org", "/simple")])

    def test_rejects(self):
        for bad in ("https://npmjs.org", "npmjs.org:443", "*.npmjs.org", "localhost", "a b"):
            with self.assertRaises(ValueError, msg=bad):
                af.parse_trust([bad])

    def test_trust_boundaries(self):
        trust = af.parse_trust(["npmjs.org", "github.com/digital-foundry"])
        def t(**kw):
            return af.network_trusted(af._net_item("fetch", "x", **kw), trust)
        self.assertTrue(t(host="registry.npmjs.org"))
        self.assertTrue(t(host="npmjs.org"))
        self.assertFalse(t(host="evilnpmjs.org"))
        self.assertTrue(t(host="github.com", url="https://github.com/digital-foundry/actualis.git"))
        self.assertTrue(t(host="github.com", url="https://github.com/digital-foundry"))
        self.assertFalse(t(host="github.com", url="https://github.com/digital-foundry-evil/x"))
        self.assertFalse(t(host="github.com", url="https://github.com/other/x"))
        self.assertFalse(t(host=None, dynamic=True))
        go = af._net_item("install", "go", ecosystem="go", package="github.com/digital-foundry/x", host="github.com")
        self.assertTrue(af.network_trusted(go, trust))

    def test_file_and_flag_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / af.NETWORK_TRUST_FILE).write_text("# team list\npypi.org  # registry\n\n")
            self.assertEqual(af.load_network_trust(["npmjs.org,crates.io"], Path(tmp)),
                             [("npmjs.org", ""), ("crates.io", ""), ("pypi.org", "")])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(af.load_network_trust(None, Path(tmp)), [])


class TestStrict(unittest.TestCase):
    def fleet(self):
        f = af.Fleet()
        f.suppressions = {}
        for cmd, mode in (("npm i lodash", "auto"), ("npm i react", "auto"),
                          ("curl https://evil.io/x", "default"), ("curl https://ok.io/x", "copilot:prompted"),
                          ("pip install requests", "auto")):
            f.add_tool("p", "Bash", {"command": cmd}, TS, mode)
        return f

    def test_off_by_default(self):
        f = self.fleet()
        af.apply_network_policy(f, af.parse_trust(["pypi.org"]), strict=False)
        self.assertEqual(f.flags, [])
        self.assertEqual([i["trusted"] for i in f.network_items], [False, False, False, False, True])

    def test_strict_groups_and_ids(self):
        f = self.fleet()
        af.apply_network_policy(f, af.parse_trust(["pypi.org"]), strict=True)
        net = [fl for fl in f.flags if fl["categories"] == ["network-unasked"]]
        self.assertEqual([(fl["program"], fl["severity"]) for fl in net], [("curl", "med"), ("npm", "med")])
        self.assertEqual(net[1]["id"], af.flag_id("med", ["network-unasked"], "npm@registry.npmjs.org"))
        self.assertRegex(net[0]["id"], r"^[0-9a-f]{8}$")
        self.assertIn("2 unasked", net[1]["evidence"])
        self.assertEqual(f.network_trust, ["pypi.org"])

    def test_failed_and_asked_are_not_findings(self):
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("p", "Bash", {"command": "curl https://ok.io/x"}, TS, "copilot:prompted")
        f.add_tool("p", "Bash", {"command": "curl https://bad.io/x"}, TS, "auto", call_id="c", agent="claude")
        f._network_outcome("claude:c", refused=False)
        af.apply_network_policy(f, [], strict=True)
        self.assertEqual(f.flags, [])

    def test_fail_on_and_suppression(self):
        f = self.fleet()
        af.apply_network_policy(f, [], strict=True)
        self.assertTrue(af.failing_findings(f, "any"))
        self.assertEqual(af.failing_findings(f, "high"), [])
        g = self.fleet()
        g.suppressions = {fl_id: "ok" for fl_id in (
            af.flag_id("med", ["network-unasked"], "npm@registry.npmjs.org"),
            af.flag_id("med", ["network-unasked"], "curl@evil.io"),
            af.flag_id("med", ["network-unasked"], "pip@pypi.org"))}
        af.apply_network_policy(g, [], strict=True)
        self.assertEqual((g.suppressed_flags, af.failing_findings(g, "any")), (3, []))

    def test_cli_rejects_bad_trust(self):
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            af.main(["--network-trust", "https://x.io", "--json"])
        self.assertEqual(cm.exception.code, 2)


class TestTrustFixes(unittest.TestCase):
    def run_cli(self, argv, trust_text):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / af.NETWORK_TRUST_FILE).write_text(trust_text)
            old = os.getcwd()
            os.chdir(tmp)
            try:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    try:
                        return af.main(argv)
                    except SystemExit as exc:
                        return exc.code
            finally:
                os.chdir(old)

    def test_bad_file_does_not_break_early_modes(self):
        self.assertEqual(self.run_cli(["--explain", "cache"], "https://bad\n"), 0)
        self.assertEqual(self.run_cli(["--agents"], "https://bad\n"), 0)

    def test_bad_file_still_exits_2_before_scan(self):
        self.assertEqual(self.run_cli(["--root", "/nonexistent-actualis", "--json"], "https://bad\n"), 2)

    def test_dot_segments_untrusted_by_path_entry(self):
        path_entry = af.parse_trust(["github.com/digital-foundry"])
        bare = af.parse_trust(["github.com"])
        for url in ("https://github.com/digital-foundry/../evil/x",
                    "https://github.com/digital-foundry/%2e%2E/evil/x",
                    "https://github.com/digital-foundry/./x",
                    "https://github.com/digital-foundry/%2E%2e/x"):
            item = af._net_item("fetch", "x", host="github.com", url=url)
            self.assertFalse(af.network_trusted(item, path_entry), url)
            self.assertTrue(af.network_trusted(item, bare), url)

    def test_paths_case_insensitive(self):
        a = af.parse_trust(["GitHub.com/Digital-Foundry"])
        self.assertEqual(a, [("github.com", "/digital-foundry")])
        item = af._net_item("fetch", "x", host="github.com", url="https://github.com/digital-foundry/x")
        self.assertTrue(af.network_trusted(item, a))
        b = af.parse_trust(["github.com/digital-foundry"])
        item = af._net_item("fetch", "x", host="github.com", url="https://GitHub.com/Digital-Foundry/x")
        self.assertTrue(af.network_trusted(item, b))

    def test_bom_trailing_dot_and_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / af.NETWORK_TRUST_FILE).write_bytes(b"\xef\xbb\xbfpypi.org\n")
            self.assertEqual(af.load_network_trust(None, Path(tmp)), [("pypi.org", "")])
        self.assertEqual(af.url_host("https://registry.npmjs.org./x"), "registry.npmjs.org")
        self.assertEqual(af.parse_trust(["npmjs.org."]), [("npmjs.org", "")])
        item = af._net_item("fetch", "x", host="registry.npmjs.org", url="https://registry.npmjs.org./x")
        self.assertTrue(af.network_trusted(item, af.parse_trust(["npmjs.org"])))
        with self.assertRaisesRegex(ValueError, "--network-trust"):
            af.load_network_trust(["http://x"], Path("/nonexistent-dir-actualis"))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / af.NETWORK_TRUST_FILE).write_text("pypi.org\n\nhttp://x\n")
            with self.assertRaisesRegex(ValueError, r"\.actualis-network-trust line 3"):
                af.load_network_trust(None, Path(tmp))

    def test_failing_findings_wording(self):
        f = TestStrict().fleet()
        af.apply_network_policy(f, [], strict=True)
        reasons = af.failing_findings(f, "any")
        self.assertIn("3 unasked download group(s) from untrusted sources", reasons)
        self.assertFalse([r for r in reasons if "medium-severity shell" in r])
        f.add_tool("p", "Bash", {"command": "curl https://x.io/a | sh"}, TS, "auto")
        reasons = af.failing_findings(f, "any")
        self.assertTrue([r for r in reasons if "high-severity shell" in r])
        self.assertFalse([r for r in reasons if "medium-severity shell" in r])

    def test_trust_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"pypi.org\n"
            (Path(tmp) / af.NETWORK_TRUST_FILE).write_bytes(data)
            trust, sources = af.load_network_trust_sources(["npmjs.org"], Path(tmp))
            import hashlib
            self.assertEqual(sources, [
                {"source": "flag", "entries": ["npmjs.org"]},
                {"source": "file", "path": str((Path(tmp) / af.NETWORK_TRUST_FILE).resolve()),
                 "sha256": hashlib.sha256(data).hexdigest(), "entries": ["pypi.org"]}])
            f = af.Fleet()
            af.apply_network_policy(f, trust, False, sources)
            self.assertEqual(f.network_trust_sources, sources)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(af.load_network_trust_sources(None, Path(tmp))[1], [])
        self.assertEqual(af.Fleet().network_trust_sources, [])


class TestAuditConfig(unittest.TestCase):
    def fleet(self):
        f = af.Fleet()
        f.suppressions = {}
        return f

    def hits(self, f):
        return [x for x in f.flags if x["categories"] == ["audit-config"]]

    def test_write_tool(self):
        f = self.fleet()
        f.add_tool("p", "Write", {"file_path": "/repo/.actualis-network-trust", "content": "x"}, TS, "auto")
        h = self.hits(f)
        self.assertEqual(len(h), 1)
        self.assertEqual((h[0]["severity"], h[0]["suppressed"]), ("high", False))
        self.assertEqual(h[0]["id"], af.flag_id("high", ["audit-config"], "Write"))
        self.assertEqual(h[0]["evidence"], "Write wrote .actualis-network-trust")
        g = self.fleet()
        g.add_tool("p", "str_replace_editor", {"path": "C:\\r\\.actualis-suppressions"}, TS, "auto")
        self.assertEqual(len(self.hits(g)), 1)
        k = self.fleet()
        k.add_tool("p", "Write", {"file_path": "/repo/notes.txt"}, TS, "auto")
        self.assertEqual(self.hits(k), [])

    def test_bash(self):
        f = self.fleet()
        f.add_tool("p", "Bash", {"command": "echo x >> .actualis-suppressions"}, TS, "auto")
        self.assertEqual(len(self.hits(f)), 1)
        for cmd in ("cat .actualis-suppressions", "ls", "echo hi > out.txt",
                    "cat .actualis-suppressions 2>/dev/null",
                    "grep x .actualis-network-trust >/dev/null 2>&1",
                    "cat .actualis-suppressions > /tmp/copy", "ls -la .actualis-*",
                    "echo x>/tmp/out", "diff a .actualis-suppressions > /tmp/out",
                    "cat a >| /tmp/out", "echo x 2>&1"):
            g = self.fleet()
            g.add_tool("p", "Bash", {"command": cmd}, TS, "auto")
            self.assertEqual(self.hits(g), [], cmd)
        for cmd in ("sed -i s/a/b/ .actualis-network-trust", "rm .actualis-suppressions",
                    "printf x | tee .actualis-network-trust", "printf 'a\\n' > ./.actualis-network-trust",
                    "tee -a .actualis-suppressions", "mv /tmp/t .actualis-network-trust",
                    "echo x >>.actualis-suppressions",
                    "echo x>>.actualis-suppressions", "echo x>.actualis-network-trust",
                    "cat a >| .actualis-suppressions", "echo x > .actualis-s*",
                    "echo x > ./.actualis-?uppressions"):
            g = self.fleet()
            g.add_tool("p", "Bash", {"command": cmd}, TS, "auto")
            self.assertEqual(len(self.hits(g)), 1, cmd)

    def test_never_suppressible_and_fails_high(self):
        f = self.fleet()
        fid = af.flag_id("high", ["audit-config"], "Write")
        f.suppressions = {fid: "agent says ok"}
        f.add_tool("p", "Write", {"file_path": ".actualis-suppressions"}, TS, "auto")
        self.assertFalse(self.hits(f)[0]["suppressed"])
        self.assertEqual(f.suppressed_flags, 0)
        self.assertTrue(af.failing_findings(f, "high"))


class TestNetworkJson(unittest.TestCase):
    def fleet(self):
        f = af.Fleet()
        f.suppressions = {}
        f.add_tool("p", "Bash", {"command": "curl -o x 'https://x.io/a?token=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"}, TS, "auto")
        f.add_tool("p", "Bash", {"command": "npm i b@1.0.0 a"}, TS, "default")
        f.add_tool("q", "Bash", {"command": "pip install c"}, TS, "copilot:prompted")
        f.add_tool("q", "WebSearch", {"query": "q"}, TS, "auto")
        af.apply_network_policy(f, af.parse_trust(["pypi.org"]), strict=False)
        return f

    def test_shape(self):
        n = af.network_json(self.fleet())
        self.assertEqual(n["totals"], {"items": 5, "asked": 1, "unasked": 2, "unknown": 2,
                                       "failed": 0, "unparsed_segments": 0})
        self.assertEqual(n["by_kind"], {"install": 3, "clone": 0, "fetch": 1, "search": 1})
        self.assertEqual([h["host"] for h in n["hosts"]], ["registry.npmjs.org", "pypi.org", "x.io"])
        self.assertEqual([(p["ecosystem"], p["name"]) for p in n["packages"]],
                         [("npm", "a"), ("npm", "b"), ("pypi", "c")])
        self.assertEqual(set(n["items"][0]), set(af.NETWORK_ITEM_KEYS))
        self.assertEqual((n["strict"], n["trust"], n["items_truncated"]), (False, ["pypi.org"], False))

    def test_urls_are_redacted(self):
        blob = json.dumps(af.network_json(self.fleet()))
        self.assertNotIn("AAAAAAAAAAAAAAAA", blob)
        self.assertIn("AAAAAAAAAAAAAAAA", json.dumps(af.network_json(self.fleet(), raw=True)))

    def test_cap(self):
        f = af.Fleet()
        for i in range(af.NETWORK_ITEMS_CAP + 5):
            f.add_tool("p", "Bash", {"command": f"curl https://h{i}.io"}, TS, "auto")
        n = af.network_json(f)
        self.assertEqual((len(n["items"]), n["items_truncated"], n["totals"]["items"]),
                         (af.NETWORK_ITEMS_CAP, True, af.NETWORK_ITEMS_CAP + 5))

    def test_network_json_is_deterministic(self):
        a = json.dumps(af.network_json(self.fleet()), sort_keys=False)
        b = json.dumps(af.network_json(self.fleet()), sort_keys=False)
        self.assertEqual(a, b)
        f = af.Fleet()
        for cmd in ("curl https://b.io", "curl https://a.io", "npm i z", "npm i y"):
            f.add_tool("p", "Bash", {"command": cmd}, TS, "auto")
        n = af.network_json(f)
        self.assertEqual([h["host"] for h in n["hosts"]], ["registry.npmjs.org", "a.io", "b.io"])

    def test_empty_fleet_emits_fixed_paths(self):
        n = af.network_json(af.Fleet())
        self.assertEqual((n["totals"]["items"], n["hosts"], n["items"]), (0, [], []))
        self.assertIn("network", af._to_json_body(af.Fleet(), False))

    def test_trust_sources_have_one_shape(self):
        f = self.fleet()
        f.network_trust_sources = [
            {"source": "flag", "entries": ["pypi.org"]},
            {"source": "file", "path": "/h/trust", "sha256": "ab" * 32, "entries": ["x.io"]}]
        ts = af.network_json(f)["trust_sources"]
        self.assertEqual(ts[0], {"source": "flag", "path": None, "sha256": None,
                                 "entries": ["pypi.org"]})
        self.assertEqual(set(ts[1]), set(ts[0]))
        self.assertEqual(ts[1]["path"], "/h/trust")
        self.assertEqual(af.network_json(af.Fleet())["trust_sources"], [])


class TestUserinfoRedaction(unittest.TestCase):
    CMDS = ("git clone https://ZqTOKEN@github.com/o/r.git",
            "npm i git+https://ZqTOKEN@github.com/o/r.git",
            "git clone user:ZqTOKEN@github.com:o/r.git")

    def test_token_userinfo_is_masked_everywhere(self):
        for cmd in self.CMDS:
            with self.subTest(cmd=cmd):
                f = af.Fleet()
                f.add_tool("p", "Bash", {"command": cmd}, TS, "auto")
                self.assertTrue(f.network_items)
                self.assertNotIn("ZqTOKEN", json.dumps(af.network_json(f)))
                self.assertNotIn("ZqTOKEN", af.redact(cmd))

    def test_plain_remotes_stay_readable(self):
        for cmd in ("git clone git@github.com:o/r.git", "git clone https://github.com/o/r"):
            self.assertEqual(af.redact(cmd), cmd)

    def test_redact_is_idempotent_on_userinfo(self):
        once = af.redact(self.CMDS[2])
        self.assertEqual(af.redact(once), once)


class TestRedactLinearAndMultiAt(unittest.TestCase):
    def test_pathological_inputs_are_fast(self):
        import time
        for text in ("a@" + "b." * 15000, "b." * 16000, "x://" * 8000, "a@" * 16000,
                     "=" * 32000, "a=" * 16000, "x:" * 16000, "k=v&" * 8190,
                     "a=b:" * 8000, "=a:" * 10000):
            t0 = time.perf_counter()
            af.redact(text)
            self.assertLess(time.perf_counter() - t0, 0.1, text[:12])

    def test_assignment_name_survives_scp_masking(self):
        out = af.redact("X=user:ZqPW@h:/p")
        self.assertTrue(out.startswith("X="), out)
        self.assertNotIn("ZqPW", out)

    def test_every_at_in_the_authority_is_userinfo(self):
        out = af.redact("curl https://user:p@ssZqTOKEN@host/x")
        self.assertNotIn("ZqTOKEN", out)
        self.assertNotIn("p@ss", out)
        self.assertIn("host/x", out)
        out = af.redact("curl https://ZqA@ZqB@host/x")
        self.assertNotIn("ZqA", out)
        self.assertNotIn("ZqB", out)
        self.assertIn("host/x", out)



class TestReport(unittest.TestCase):
    def out(self, f, raw=False):
        buf = io.StringIO()
        with redirect_stdout(buf):
            af.render_network(f, af.C(False), top=12, raw=raw)
        return buf.getvalue()

    def test_empty(self):
        self.assertIn("no downloads seen", self.out(af.Fleet()))

    def test_sections_and_unknown_note(self):
        f = af.Fleet()
        f.add_tool("proj-a", "Bash", {"command": "curl -o ~/bin/x https://raw.githubusercontent.com/a"}, TS, "auto")
        f.add_tool("proj-b", "Bash", {"command": "npm i lodash"}, TS, "default")
        f.add_tool("proj-b", "Bash", {"command": "git clone https://github.com/o/r"}, TS, "copilot:prompted")
        text = self.out(f)
        for needle in ("NETWORK", "3 downloads", "1 unasked", "1 unknown", "INSTALLED", "CLONED",
                       "FETCHED", "UNASKED", "raw.githubusercontent.com", "allowlist rule"):
            self.assertIn(needle, text, needle)

    def test_report_redacts_urls(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl 'https://x.io/?token=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"}, TS, "auto")
        self.assertNotIn("AAAAAAAAAAAAAAAA", self.out(f))

    def test_trust_sources_printed(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://x.io/a"}, TS, "auto")
        f.network_trust_sources = [
            {"source": "flag", "entries": ["a.io", "b.io/x"]},
            {"source": "file", "path": "/w/.actualis-network-trust",
             "sha256": "0123456789abcdef" * 4, "entries": ["c.io", "d.io", "e.io"]}]
        text = self.out(f)
        self.assertIn("trust: --network-trust (2 entries)", text)
        self.assertIn(".actualis-network-trust /w/.actualis-network-trust sha256 0123456789ab (3 entries)", text)
        self.assertNotIn("0123456789abc", text)

    def test_no_trust_line_without_sources(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://x.io/a"}, TS, "auto")
        self.assertNotIn("trust:", self.out(f))

    def test_bracketed_ipv6_host_survives(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "git clone http://[::1]:8080/o/r.git"}, TS, "auto")
        self.assertIn("NETWORK", self.out(f))

    def test_explain_topic(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = af.render_explain("network", af.C(False))
        self.assertEqual(rc, 0)
        self.assertIn("unknown", buf.getvalue())

    def test_explain_covers_limits_and_audit_config(self):
        entry = af.EXPLAIN["network"]
        text = " ".join(entry["formula"] + entry["assumes"])
        for needle in ("tripwire", "not a guarantee", "python -c", "node -e", "postinstall",
                       "Makefiles", "eval", "$CMD", "xargs", "busybox", "3 levels",
                       "unparsed_segments", ".actualis-network-trust", ".actualis-suppressions",
                       "cannot be suppressed", "tee", "sed -i", "Write/Edit", "dd of=", "cp x ."):
            self.assertIn(needle, text, needle)
        for line in entry["formula"] + entry["assumes"]:
            self.assertLessEqual(len(line), 78, line)

    def test_render_includes_section(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://x.io/a"}, TS, "auto")
        buf = io.StringIO()
        with redirect_stdout(buf):
            af.render(f, af.C(False), False, 12)
        self.assertIn("NETWORK", buf.getvalue())


class TestReportFixes(unittest.TestCase):
    def out(self, f, top=12):
        buf = io.StringIO()
        with redirect_stdout(buf):
            af.render_network(f, af.C(False), top=top)
        return buf.getvalue()

    def test_escapes_do_not_reach_output(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://evil.io/\x1b[2K\x1b[1Ahidden"}, TS, "auto")
        f.add_tool("p", "Bash", {"command": "npm i 'pkg\x1b]8;;http://x\x07'"}, TS, "auto")
        f.add_tool("p", "WebFetch", {"url": "https://h\x1b[31m.io/x"}, TS, "auto")
        for text in (self.out(f), json.dumps(af.network_json(f)), json.dumps(af.network_json(f, True))):
            for bad in ("\x1b", "\x07", "\r"):
                self.assertNotIn(bad, text)
        self.assertIn("evil.io", self.out(f))

    def test_newline_in_field_becomes_space(self):
        f = af.Fleet()
        f.add_tool("p", "WebFetch", {"url": "https://a.io/x\ny"}, TS, "auto")
        self.assertNotIn("\n", f.network[0]["url"])

    def test_long_urls_show_and_rows_fit(self):
        f = af.Fleet()
        for k in range(50):
            f.add_tool("project-number-one", "Bash",
                       {"command": f"curl https://example-host-{k}.io/a/very/long/path/segment/{k}/more"},
                       TS, "auto")
        rows = [l for l in self.out(f, top=50).splitlines() if "example-host" in l and "auto" not in l
                and "unasked" in l]
        self.assertEqual(len(rows), 50)
        for l in rows:
            self.assertLessEqual(len(l), 100, l)
            self.assertRegex(l, r"curl https://\S")

    def test_labels_per_group(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://a.io/1"}, TS, "default")
        f.add_tool("p", "Bash", {"command": "curl https://b.io/1"}, TS, "default")
        text = self.out(f)
        self.assertEqual(text.count("UNKNOWN"), 1)
        self.assertNotIn("UNASKED", text)
        f.add_tool("p", "Bash", {"command": "curl https://c.io/1"}, TS, "auto")
        text = self.out(f)
        self.assertEqual((text.count("UNASKED"), text.count("UNKNOWN")), (1, 1))

    def test_singular(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://a.io/1"}, TS, "auto")
        self.assertIn("1 download ·", self.out(f))

    def test_top_caps_rows(self):
        f = af.Fleet()
        for k in range(10):
            f.add_tool("p", "Bash", {"command": f"curl https://h{k}.io/x"}, TS, "auto")
        rows = [l for l in self.out(f, top=3).splitlines() if l.rstrip().endswith("unasked")]
        self.assertEqual(len(rows), 3)

    def test_refused_only_fleet_is_empty(self):
        f = af.Fleet()
        f.add_tool("p", "Bash", {"command": "curl https://a.io/x"}, TS, "auto", call_id="c1")
        f._network_outcome("claude:c1", True)
        self.assertIn("no downloads seen", self.out(f))

    def test_deep_bash_c_counts_unparsed(self):
        cmd = "curl https://a.io"
        for _ in range(5):
            cmd = "bash -c " + json.dumps(cmd)
        found, unparsed = af.network_items_from_command(cmd)
        self.assertGreaterEqual(unparsed, 1)

    def test_explain_prefix_list(self):
        text = " ".join(af.EXPLAIN["network"]["formula"])
        self.assertIn("command, exec", text)


if __name__ == "__main__":
    unittest.main()


class TestHarnessFieldEscapes(unittest.TestCase):
    """I4 and M14: model-written audit-config evidence and harness-written
    fields (permission mode, denial kind, Codex model, approval policy,
    sandbox type) never carry a stripped character to any output."""
    BAD = "\x1b]52;c;ZXZpbA==\x07\x1b[2J\r\x9b31m‮evil"

    def fleet(self, tmp):
        bad = self.BAD
        d = Path(tmp) / "claude" / "-Users-x-proj"
        d.mkdir(parents=True)
        recs = [
            call("t1", f"echo x > .actualis-suppressions # {bad}\nsecond line", mode="auto" + bad),
            call("t2", "rm -rf /tmp/build", mode="default"),
            result("t2", True, "user-rejected" + bad),
            {"timestamp": "2026-10-01T10:00:02Z", "type": "assistant", "uuid": "u3", "sessionId": "sess-1",
             "message": {"id": "m3", "role": "assistant", "model": "claude-x" + bad, "content": [],
                         "usage": {"input_tokens": 10, "output_tokens": 10}}},
        ]
        (d / "s.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        cx = Path(tmp) / "codex"
        cx.mkdir()
        crecs = [
            {"timestamp": "2026-10-01T10:00:00Z", "type": "session_meta", "payload": {"id": "cx-1", "cwd": "/Users/x/proj"}},
            {"timestamp": "2026-10-01T10:00:00Z", "type": "turn_context", "payload": {
                "cwd": "/Users/x/proj", "model": "gpt-x" + bad, "approval_policy": "never" + bad,
                "sandbox_policy": {"type": "danger" + bad}}},
            {"timestamp": "2026-10-01T10:00:01Z", "type": "response_item", "payload": {
                "type": "function_call", "name": "shell_command", "call_id": "c1",
                "arguments": json.dumps({"command": "ls"})}},
            {"timestamp": "2026-10-01T10:00:02Z", "type": "event_msg", "payload": {
                "type": "token_count", "info": {"total_token_usage": {
                    "input_tokens": 100, "output_tokens": 10, "total_tokens": 110}}}},
        ]
        (cx / "rollout-2026-10-01T10-00-00-cx-1.jsonl").write_text("\n".join(json.dumps(r) for r in crecs) + "\n")
        f = af.Fleet()
        f.scan([Path(tmp) / "claude"], None, None, progress=False)
        f.scan_codex([cx], None, None)
        return f

    def test_no_stripped_character_reaches_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fleet(tmp)
        [ev] = [fl["evidence"] for fl in f.flags if "audit-config" in fl["categories"]]
        self.assertNotIn("\n", ev)
        self.assertIn("second line", ev)
        outs = {}
        for name, fn in (("render", lambda: af.render(f, af.C(False), False, 12)),
                         ("share", lambda: af.render_share(f, af.C(False)))):
            buf = io.StringIO()
            with redirect_stdout(buf):
                fn()
            outs[name] = buf.getvalue()
        for mode in ("cost", "supervision", "volume"):
            outs["card-" + mode] = json.dumps(af.card_model(f, mode), ensure_ascii=False)
        outs["json"] = json.dumps(af.to_json(f), ensure_ascii=False)
        self.assertIn("never", outs["render"])
        for name, text in outs.items():
            for lo, hi, why in af._STRIPPED_RANGES:
                for ch in text:
                    self.assertFalse(lo <= ord(ch) <= hi, f"{name}: U+{ord(ch):04X} ({why})")


class TestOptionValueRedaction(unittest.TestCase):
    """I6: a credential passed as an option value is masked, and counted."""
    PW = "Zq9secretPW"
    MASKED = (
        "curl -u alice:{pw} https://a.io", "curl -ualice:{pw} https://a.io",
        "curl --user alice:{pw} https://a.io", "curl --user=alice:{pw} https://a.io",
        "curl -U proxy:{pw} https://a.io", "curl --proxy-user proxy:{pw} https://a.io",
        "curl --proxy-user=proxy:{pw} https://a.io", "curl -u 'alice:{pw}' https://a.io",
        "wget --password {pw} https://a.io", "wget --http-password {pw} https://a.io",
        "wget --ftp-password {pw} ftp://a.io", "wget --proxy-password '{pw}' https://a.io",
        "curl -H 'Authorization: token {pw}long' https://api.github.com",
        "git -c http.extraheader='Authorization: token {pw}long' clone https://x",
        "docker login --password {pw} reg.io", "docker login -u bob -p {pw} reg.io",
        "docker login -p{pw} reg.io", "PGPASSWORD={pw} psql -h db",
    )
    UNTOUCHED = (
        "docker run -u 1000:1000 img", "sudo -u root ls", "git push -u origin main:main",
        "pip install -U git+https://github.com/o/r", "pip install --user git+https://github.com/o/r",
        "mkdir -p /tmp/x", "ssh -p 22 host", "docker run -p 8080:80 img",
        "docker login --password-stdin reg.io", "curl -u alice:$PW https://a.io",
        "mysql --password --host db", "sort -u file.txt",
    )

    def test_credential_is_masked_and_user_kept(self):
        for form in self.MASKED:
            cmd = form.format(pw=self.PW)
            with self.subTest(cmd=cmd):
                out = af.redact(cmd)
                self.assertNotIn(self.PW, out)
                self.assertTrue(af.contains_secret(cmd))
                self.assertTrue(af.classify_secrets(cmd))
                self.assertEqual(af.redact(out), out)
        self.assertIn("alice:", af.redact(f"curl -u alice:{self.PW} https://a.io"))
        self.assertIn("token ", af.redact(f"curl -H 'Authorization: token {self.PW}long' x"))

    def test_other_option_shapes_are_untouched(self):
        for cmd in self.UNTOUCHED:
            with self.subTest(cmd=cmd):
                self.assertEqual(af.redact(cmd), cmd)
                self.assertFalse(af.classify_secrets(cmd))

    def test_generic_dash_p_is_not_a_password(self):
        # -p means other things in other programs; only `docker login -p` is read.
        for cmd in ("mysql -pZq9secretPW db", "sshpass -p Zq9secretPW ssh h"):
            self.assertIn("Zq9secretPW", af.redact(cmd))

    def test_option_rules_are_linear(self):
        import time
        for text in ("-u " * 10900, "--user " * 4600, "--password " * 2900, "-u a:" * 6500,
                     "a:" * 16000, "a=" * 16000, "docker login " * 2500, "docker login -p" * 2000,
                     "-ua:" * 8000, "--user=" * 4600, "Authorization: token " * 1500):
            t0 = time.perf_counter()
            af.redact(text)
            af.classify_secrets(text)
            self.assertLess(time.perf_counter() - t0, 0.1, text[:16])


class TestDetectorAgreement(unittest.TestCase):
    """Roadmap S1: what redact() masks, classify_secrets() counts. The
    exceptions are masked for display and deliberately not counted."""
    EXCEPTIONS = {
        "export X=AKIAIOSFODNN7EXAMPLE": "AWS's documented example key: masked, never counted (#51)",
        "output_tokens=1234567890123": "a metric name in _NOT_SECRET_NAMES",
        "token_hash=abcdef1234567890": "a hash column in _NOT_SECRET_NAMES",
        "encrypted_password=abcdef1234567890": "an encrypted column in _NOT_SECRET_NAMES",
        "TOKENS=abcdefghijklmnop": "a bare plural names a collection",
        "SECRET=your_secret_here": "a placeholder value",
        "API_KEY=placeholder1234": "a placeholder value",
        "postgres://admin@db.internal": "a short password-less userinfo is a username (M6)",
        "git clone https://ZqTOKEN@github.com/o/r.git": "a short password-less userinfo is a username (M6)",
    }
    CORPUS = (
        TestOptionValueRedaction.UNTOUCHED
        + tuple(f.format(pw=TestOptionValueRedaction.PW) for f in TestOptionValueRedaction.MASKED)
        + ("export X=ghp_abcdefghijklmnopqrst", "export X=sk-ant-api03-abcdefghijklmnop",
           "export X=vcp_notarealtokenjustafixture01", "export X=glpat-abcdefghijklmnop",
           "MY_API_KEY=supersecretvalue123", "psql postgresql://admin:hunter2pass@db:5432/prod",
           "curl -H 'Authorization: Bearer sk-ant-fixtureonlyvalue1' https://x",
           'curl -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/x',
           "TOKEN=ghp_abcdefghijklmnopqrs", "psql postgresql://u:passwordvalue@h/db",
           "npm run build && git push origin main", "git clone https://github.com/foo/bar.git",
           "gh pr create --title 'Add token refresh' --body 'fixes auth'",
           "grep -rn 'password' src/ | head -20", "export K=sk_live_abcdefghijklmnopqrst",
           "gh auth --with-token ghp_abcdefghijklmnopqrst", "STRIPE_SECRET_KEY=abcdefghijklmnop",
           "psql postgresql://u:devpassword@127.0.0.1:5432/db", "TOKEN=abcdefghijklmnop",
           "PGPASSWORD=s3cr3t psql", "wget --password=Zq9secretPW https://a.io",
           "git -c http.extraheader='Authorization: Basic Zq9secretPWlong' clone https://x",
           "git clone user:ZqTOKENvalue@github.com:o/r.git", "ci:tok@h:/srv",
           "git clone https://ghp_abcdefghijklmnopqrstuvwx@github.com/o/r.git",
           "git clone git@github.com:o/r.git", "curl -u alice:changeme https://a.io",
           "export X_TOKEN=Zq9secretPWlong")
        + tuple(EXCEPTIONS)
    )

    def test_contains_secret_agrees_with_classify(self):
        for x in self.CORPUS:
            with self.subTest(cmd=x):
                if x in self.EXCEPTIONS:
                    self.assertTrue(af.contains_secret(x))
                    self.assertFalse(af.classify_secrets(x))
                else:
                    self.assertEqual(af.contains_secret(x), bool(af.classify_secrets(x)))


class TestRedirections(unittest.TestCase):
    """I2: a redirection is never a package, a host or a destination."""

    def test_review_examples(self):
        cases = {
            "npm install foo > /dev/null 2>&1": ["foo"],
            "pip install requests 2>/dev/null": ["requests"],
            "cargo install rg 2> err.log": ["rg"],
            "brew install jq 2>&1": ["jq"],
            "npm i a >> log.txt b": ["a", "b"],
            "npm i a &> /dev/null": ["a"],
            "npm i a &>/dev/null": ["a"],
            "npm i a < input.txt": ["a"],
            "npm i a <<< 'word'": ["a"],
            "npm i a >| out.txt": ["a"],
            "npm i a >|out.txt": ["a"],
            "npm i a 1>out.txt": ["a"],
            "npm i a >& out.txt": ["a"],
            "pip install 'requests>=2'": ["requests"],
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual([i["package"] for i in items(cmd)], want)

    def test_git_dest_and_curl_host(self):
        it = one("git clone https://github.com/o/r 2>&1")
        self.assertEqual((it["host"], it["dest"]), ("github.com", None))
        it = one("git clone https://github.com/o/r dir > log 2>&1")
        self.assertEqual(it["dest"], "dir")
        it = one("curl https://a.io>/tmp/x")
        self.assertEqual((it["host"], it["url"]), ("a.io", "https://a.io"))
        it = one("curl https://a.io</dev/null")
        self.assertEqual(it["host"], "a.io")
        it = one("curl 'https://a.io/?q=>x'")
        self.assertEqual(it["url"], "https://a.io/?q=>x")

    def test_no_redirect_shaped_items(self):
        cmd = "npm i x > /dev/null 2>&1; pip install y 2>/dev/null; brew install z 2>&1"
        for it in items(cmd):
            for v in (it["package"], it["dest"], it["host"]):
                self.assertNotIn(v, (">", "2", "2>", "2>&1", "/dev/null", "&1"))

    def test_audit_config_redirects_still_seen(self):
        self.assertTrue(af.writes_audit_config("echo x>.actualis-suppressions"))
        self.assertTrue(af.writes_audit_config("echo x >| .actualis-suppressions"))
        self.assertFalse(af.writes_audit_config("cat .actualis-suppressions 2>&1"))


class TestEverydayShapes(unittest.TestCase):
    """I3: control flow, wrappers and nested commands that hid downloads."""

    def test_control_flow_and_wrappers(self):
        cases = {
            "for p in a b; do npm i lodash; done": ("npm", "lodash"),
            "if curl -fsS https://a.io/x; then echo ok; fi": ("curl", "a.io"),
            "while true; do curl https://a.io/x; sleep 1; done": ("curl", "a.io"),
            "until curl https://a.io/x; do sleep 1; done": ("curl", "a.io"),
            "if true; then echo; else curl https://a.io/x; fi": ("curl", "a.io"),
            "if a; then b; elif curl https://a.io/x; then c; fi": ("curl", "a.io"),
            "{ curl https://a.io/x; }": ("curl", "a.io"),
            "(curl https://a.io/x)": ("curl", "a.io"),
            "( cd /tmp && curl https://a.io/x )": ("curl", "a.io"),
            "! curl https://a.io/x": ("curl", "a.io"),
            "timeout 60 pip install requests": ("pip", "requests"),
            "timeout -s KILL -k 5 60s pip install requests": ("pip", "requests"),
            "timeout --preserve-status 1m curl https://a.io/x": ("curl", "a.io"),
            "stdbuf -o0 curl https://a.io/x": ("curl", "a.io"),
            "stdbuf -o L -e 0 curl https://a.io/x": ("curl", "a.io"),
            "doas curl https://a.io/x": ("curl", "a.io"),
            "doas -u root npm i lodash": ("npm", "lodash"),
            "busybox wget https://a.io/x": ("wget", "a.io"),
            "nice -n 10 curl https://a.io/x": ("curl", "a.io"),
            "xargs -I{} curl https://a.io/{}": ("curl", "a.io"),
            "cat list | xargs -n 1 -P 4 npm i lodash": ("npm", "lodash"),
            "eval 'curl https://a.io/x'": ("curl", "a.io"),
            'eval "npm i lodash"': ("npm", "lodash"),
            "bash -lc 'curl https://a.io/x'": ("curl", "a.io"),
            "sh -xc 'pip install requests'": ("pip", "requests"),
            "zsh -ec 'curl https://a.io/x'": ("curl", "a.io"),
        }
        for cmd, (prog, what) in cases.items():
            with self.subTest(cmd=cmd):
                it = one(cmd)
                self.assertEqual(it["program"].split()[0], prog)
                self.assertIn(what, (it["host"], it["package"]))

    def test_xargs_reading_urls_from_stdin_is_unknown(self):
        it = one("cat urls.txt | xargs curl -sS")
        self.assertEqual((it["program"], it["host"], it["dynamic"]), ("curl", None, True))

    def test_shell_c_clusters_keep_the_depth_cap(self):
        for flag in ("-lc", "-xc", "-ec"):
            cmd = "curl https://a.io"
            for _ in range(2):
                cmd = f"bash {flag} " + json.dumps(cmd)
            self.assertEqual(af.network_items_from_command(cmd)[1], 0)
            self.assertEqual(one(cmd)["host"], "a.io")
            for _ in range(3):
                cmd = f"bash {flag} " + json.dumps(cmd)
            self.assertGreaterEqual(af.network_items_from_command(cmd)[1], 1)

    def test_ordinary_uses_are_not_downloads(self):
        for cmd in ("timeout 5 ls", "stdbuf -o0 make", "eval \"$CMD\"", "xargs rm -f",
                    "if [ -f x ]; then cat x; fi", "for f in *.txt; do wc -l $f; done"):
            with self.subTest(cmd=cmd):
                self.assertEqual(items(cmd), [])

    def test_shell_flag_cluster_check_is_linear(self):
        import time
        for tok in ("-" + "c" * 32000 + "!", "-" + "x" * 32000, "-" + "c" * 32000):
            t0 = time.perf_counter()
            af.network_items_from_command(f"bash {tok} 'curl https://a.io'")
            self.assertLess(time.perf_counter() - t0, 0.1, tok[:8])
