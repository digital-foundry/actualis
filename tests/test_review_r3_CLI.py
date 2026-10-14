"""Review r3, slice R3D: the gate behind a closed stderr, flags never silently
dropped (R4, R14), the MCP server's scope and arguments, --why for per-project
findings, one-line suppression reasons, and the --json docs.
Synthetic data only, under a temp HOME."""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_D import _Env, SCAN, CANARY_FP, ROOT, af  # noqa: E402


# --- R3D1: a closed stderr must not lose the gate's verdict -------------------

class _BrokenAfterFirst(io.StringIO):
    """A stderr whose reader goes away after the first line."""

    def __init__(self):
        super().__init__()
        self.n = 0

    def write(self, s):
        self.n += 1
        if self.n > 1:
            raise BrokenPipeError(32, "Broken pipe")
        return super().write(s)


class TestR3D1GateBehindClosedStderr(_Env):

    def _run(self, where, *argv):
        """Run the CLI with stdout/stderr into pipes whose read end is closed.
        where: "err" (stderr closed), "same" (2>&1 into a closed pipe), "both"."""
        fds = []

        def closed_pipe():
            r, w = os.pipe()
            os.close(r)
            fds.append(w)
            return w
        devnull = open(os.devnull, "w")
        try:
            out = closed_pipe() if where in ("same", "both") else devnull.fileno()
            err = out if where == "same" else closed_pipe()
            p = subprocess.run(
                [sys.executable, "-I", str(ROOT / "actualis.py"), "--root", str(self.state),
                 "--agent", "copilot", *argv],
                stdout=out, stderr=err, env=os.environ.copy(), timeout=120)
        finally:
            for w in fds:
                os.close(w)
            devnull.close()
        return p.returncode

    def test_failing_gate_exits_3_whatever_happens_to_stderr_and_stdout(self):
        for where in ("err", "same", "both"):
            for extra in ((), ("--json",)):
                with self.subTest(where=where, json=bool(extra)):
                    self.assertEqual(self._run(where, *extra, "--fail-on", "critical"), 3)

    def test_passing_gate_and_no_gate_still_exit_0(self):
        for where in ("err", "both"):
            with self.subTest(where=where):
                self.assertEqual(self._run(where, "--json"), 0)

    def test_in_process_verdict_survives_stderr_breaking_mid_verdict(self):
        err = _BrokenAfterFirst()
        with mock.patch.object(sys, "stdout", io.StringIO()), mock.patch.object(sys, "stderr", err):
            code = af._cli(["--root", str(self.state), "--agent", "copilot",
                            "--json", "--fail-on", "critical"])
        self.assertEqual(code, af.EXIT_FINDINGS)
        self.assertIn("FAIL at --fail-on critical", err.getvalue())
        self.assertEqual(af._PENDING_GATE, [])


class _WindowsClosedPipe(io.StringIO):
    """A stream as Windows reports a pipe with no reader: EINVAL, not EPIPE."""

    def write(self, s):
        raise OSError(22, "Invalid argument")

    def flush(self):
        raise OSError(22, "Invalid argument")


class TestWindowsClosedPipeIsEinval(_Env):
    """Windows reports a write to a closed pipe as OSError(EINVAL); the gate
    code must survive it there just as it survives EPIPE on POSIX."""

    def test_reader_gone_only_for_epipe_or_windows_einval_without_a_file(self):
        self.assertTrue(af._reader_gone(BrokenPipeError(32, "Broken pipe")))
        with mock.patch.object(af.sys, "platform", "win32"):
            self.assertTrue(af._reader_gone(OSError(22, "Invalid argument")))
            # A bad path is EINVAL on Windows too, and it names the file.
            self.assertFalse(af._reader_gone(OSError(22, "Invalid argument", "a:b")))
            self.assertFalse(af._reader_gone(OSError(13, "Permission denied")))
            self.assertFalse(af._reader_gone(ValueError("x")))
        for platform in ("linux", "darwin"):
            with mock.patch.object(af.sys, "platform", platform):
                self.assertFalse(af._reader_gone(OSError(22, "Invalid argument")))

    def _cli(self, platform, *argv):
        err = io.StringIO()
        with mock.patch.object(af.sys, "platform", platform), \
                mock.patch.object(sys, "stdout", _WindowsClosedPipe()), \
                mock.patch.object(af, "_silence_stdout", lambda: None), \
                contextlib.redirect_stderr(err):
            code = af._cli(["--root", str(self.state), "--agent", "copilot", *argv])
        return code, err.getvalue()

    def test_gate_code_survives_einval_on_windows(self):
        for argv, want in ((("--json", "--fail-on", "critical"), af.EXIT_FINDINGS),
                           (("--fail-on", "critical"), af.EXIT_FINDINGS),
                           (("--json",), af.EXIT_OK)):
            with self.subTest(argv=argv):
                code, err = self._cli("win32", *argv)
                self.assertEqual(code, want, err)
                self.assertNotIn("Traceback", err)

    def test_einval_is_not_swallowed_on_posix(self):
        with self.assertRaises(OSError):
            self._cli("linux", "--json")


# --- R3D2, R3D3, R3D4: never silently drop a flag (rows added, R4/R14) --------

REFUSED = [
    # R3D2: option flags outside the one mode that reads them
    (SCAN + ("--reason", "x"), ("--reason", "--suppress")),
    (SCAN + ("--quiet",), ("--quiet", "--watch")),
    (SCAN + ("--interval", "9"), ("--interval", "--watch")),
    (("--ci-log", "{log}", "--quiet"), ("--quiet",)),
    (("--service", "newsyslog", "--quiet"), ("--service", "--quiet")),
    (("--service", "newsyslog", "--interval", "30"), ("--service", "--interval")),
    # R3D2: scope flags the mode would ignore
    (("--watch", "--days", "3"), ("--watch", "--days")),
    (("--watch", "--project", "x"), ("--watch", "--project")),
    (("--service", "systemd", "--days", "3"), ("--service", "--days")),
    (("--service", "systemd", "--project", "x"), ("--service", "--project")),
    (("--completions", "bash", "--root", "{root}"), ("--completions", "--root")),
    (("--completions", "bash", "--agent", "codex"), ("--completions", "--agent")),
    (("--completions", "bash", "--days", "3"), ("--completions", "--days")),
    (("--completions", "bash", "--no-redact"), ("--completions", "--no-redact")),
    (("--agents", "--root", "{root}"), ("--agents", "--root")),
    (("--agents", "--days", "3"), ("--agents", "--days")),
    (("--explain", "cost", "--days", "3"), ("--explain", "--days")),
    (("--explain", "--no-redact"), ("--explain", "--no-redact")),
    (("--suppressions", "--root", "{root}"), ("--suppressions", "--root")),
    (("--suppress", CANARY_FP, "--days", "3"), ("--suppress", "--days")),
    (("--self-check", "--project", "x"), ("--self-check", "--project")),
    (("--self-check", "--no-redact"), ("--self-check", "--no-redact")),
    (SCAN + ("--replay", CANARY_FP, "--no-redact"), ("--replay", "--no-redact")),
    (SCAN + ("--share", "--no-redact"), ("--share", "--no-redact")),
    (SCAN + ("--why", "AF004", "--no-redact"), ("--why", "--no-redact")),
    # R3D2: --top outside the text report
    (SCAN + ("--top", "3", "--json"), ("--top", "--json")),
    (SCAN + ("--top", "3", "--network", "--json"), ("--top", "--json")),
    (SCAN + ("--top", "3", "--share"), ("--top", "--share")),
    (SCAN + ("--top", "3", "--coach"), ("--top", "--coach")),
    (SCAN + ("--top", "3", "--card", "--out", "{out}"), ("--top", "--card")),
    (SCAN + ("--top", "3", "--network", "--html", "--out", "{out}"), ("--top", "--html")),
    (SCAN + ("--top", "3", "--diff", "{old}"), ("--top", "--diff")),
    (("--watch", "--top", "3"), ("--top", "--watch")),
    (("--self-check", "--top", "3"), ("--top", "--self-check")),
    # R3D3: --mcp honours the scope it can; the rest are refused
    (("--mcp", "--no-redact"), ("--mcp", "--no-redact")),
    (("--mcp", "--top", "3"), ("--top", "--mcp")),
    (("--mcp", "--root", "/nonexistent/actualis-r3d3"), ("--mcp", "--root")),
    # R3D4: --network-strict / --network-trust where nothing reads them
    (SCAN + ("--coach", "--network-strict"), ("--network-strict", "--coach", "--fail-on")),
    (SCAN + ("--aisvs", "--network-strict"), ("--network-strict", "--aisvs", "--fail-on")),
    (SCAN + ("--share", "--network-strict"), ("--network-strict", "--share", "--fail-on")),
    (SCAN + ("--coach", "--network-trust", "x.com"), ("--network-trust", "--coach")),
    (SCAN + ("--share", "--network-trust", "x.com"), ("--network-trust", "--share")),
    (("--explain", "--network-strict"), ("--network-strict", "--explain")),
    (("--agents", "--network-trust", "x.com"), ("--network-trust", "--agents")),
    (("--watch", "--network-strict"), ("--network-strict", "--watch")),
    (("--mcp", "--network-strict"), ("--network-strict", "--mcp")),
    (SCAN + ("--replay", CANARY_FP, "--network-strict"), ("--network-strict", "--replay")),
    (SCAN + ("--why", "AF004", "--network-strict"), ("--network-strict", "--why")),
    (SCAN + ("--card", "--out", "{out}", "--network-strict"), ("--network-strict", "--card")),
    (("--suppressions", "--network-strict"), ("--network-strict", "--suppressions")),
    (("--completions", "bash", "--network-trust", "x.com"), ("--network-trust", "--completions")),
    # R3D7: a suppression reason is one line
    (("--suppress", "abcdef12", "--reason", "ok\nabcdef13  x"), ("--reason",)),
]

ALLOWED = [
    SCAN + ("--top", "3"), SCAN + ("--top", "3", "--bash"), SCAN + ("--top", "3", "--network"),
    ("--ci-log", "{log}", "--top", "3"),
    ("--suppress", "abcdef12", "--reason", "a vendor example"),
    ("--watch", "--quiet", "--interval", "9"), ("--service", "launchd", "--quiet"),
    ("--service", "newsyslog"),
    ("--self-check", "--root", "{root}", "--agent", "copilot", "--days", "3"),
    SCAN + ("--replay", CANARY_FP, "--days", "3", "--project", "x"),
    ("--mcp", "--root", "{root}", "--agent", "copilot", "--days", "3", "--project", "x"),
    SCAN + ("--coach", "--network-strict", "--fail-on", "any"),
    SCAN + ("--share", "--network-trust", "x.com", "--fail-on", "any"),
    SCAN + ("--network-strict",), SCAN + ("--bash", "--network-strict"),
    SCAN + ("--json", "--network-strict", "--network-trust", "x.com"),
    SCAN + ("--diff", "{old}", "--network-strict"),
    SCAN + ("--json", "--no-redact"), SCAN + ("--network", "--no-redact"),
    SCAN + ("--diff", "{old}", "--no-redact"),
    ("--agents", "--agent", "all"),
]


class TestR3D2FlagsNeverDropped(_Env):

    def test_refused_combinations(self):
        for argv, names in REFUSED:
            with self.subTest(argv=argv):
                self.assertUsage(*argv, names=names)

    def test_allowed_combinations(self):
        for argv in ALLOWED:
            with self.subTest(argv=argv):
                self.assertAccepted(*argv)

    def test_a_refused_reason_writes_nothing(self):
        self.assertUsage("--suppress", "abcdef14", "--reason", "ok\x1b[2Jx", names=("--reason",))
        self.assertUsage("--suppress", "abcdef14", "--reason", "a b", names=("--reason",))
        self.assertUsage("--suppress", "abcdef14", "--reason", "a\tb", names=("--reason",))
        _, out, _ = self.run_main("--suppressions")
        self.assertNotIn("abcdef14", out)

    def test_defaults_still_apply_when_not_given(self):
        seen = {}
        with mock.patch.object(af, "watch", lambda r, c, interval, *a: seen.update(i=interval) or 0), \
                mock.patch.object(af, "render", lambda *a, **k: seen.update(top=k["top"])), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            af.main(["--watch"])
            af.main(list(self.expand(SCAN)))
        self.assertEqual(seen, {"i": 4.0, "top": 12})


# --- R3D3: the MCP server answers only from the scope it was started with ----

class TestR3D3McpScope(_Env):

    def test_main_passes_the_scope_to_the_server(self):
        got = []
        with mock.patch.object(af, "mcp_serve", lambda scope=None: got.append(scope) or 0):
            af.main(["--mcp", "--root", str(self.state), "--agent", "copilot",
                     "--days", "7", "--project", "alpha"])
        self.assertEqual(got, [{"root": str(self.state), "agent": "copilot",
                                "days": 7, "project": "alpha"}])

    def test_root_and_agent_are_the_only_roots_read(self):
        boom = mock.Mock(side_effect=AssertionError("default roots must not be read"))
        with mock.patch.multiple(af, transcript_roots=boom, codex_roots=boom,
                                 copilot_roots=boom, gemini_roots=boom, qwen_roots=boom):
            f = af._MCPCache({"root": str(self.state), "agent": "copilot"}).fleet()
        self.assertEqual(f.roots, [self.state])
        self.assertGreater(f.messages + f.bash_total, 0)

    def test_agent_without_root_reads_only_that_agent(self):
        boom = mock.Mock(side_effect=AssertionError("other agents must not be read"))
        with mock.patch.multiple(af, transcript_roots=boom, codex_roots=boom,
                                 gemini_roots=boom, qwen_roots=boom,
                                 copilot_roots=lambda: [self.state]):
            f = af._MCPCache({"agent": "copilot"}).fleet()
        self.assertEqual(f.roots, [self.state])

    def test_days_and_project_only_narrow(self):
        c = af._MCPCache({"days": 7, "project": "svc"})
        self.assertEqual(c._narrow(None, None), (7, "svc"))
        self.assertEqual(c._narrow(30, None), (7, "svc"))
        self.assertEqual(c._narrow(3, "my-svc-api"), (3, "my-svc-api"))
        self.assertEqual(c._narrow(None, "sv"), (7, "svc"))
        with self.assertRaises(af._MCPClientError):
            c._narrow(None, "other")
        self.assertEqual(af._MCPCache()._narrow(30, "x"), (30, "x"))


# --- R3D5: MCP exposed_secrets arguments and suppressions ---------------------

class TestR3D5McpExposedSecrets(unittest.TestCase):

    def _cache(self):
        f = af.Fleet()
        base = {"kinds": {"github"}, "uses": 1, "first": None, "last": None, "projects": set()}
        f.secrets = {"aaaa1111": dict(base, priority="high", suppressed=True),
                     "bbbb2222": dict(base, priority="high", suppressed=False),
                     "cccc3333": dict(base, priority="critical")}
        return mock.Mock(fleet=lambda *a: f)

    def test_unknown_priority_is_invalid_params(self):
        for bad in ("medium", "", "ALL", "High"):
            with self.subTest(priority=bad), self.assertRaises(af._MCPClientError):
                af._mcp_call("exposed_secrets", {"priority": bad}, self._cache())

    def test_non_integer_days_is_invalid_params(self):
        for bad in ("7", 7.5, True, [7], float("nan")):
            with self.subTest(days=bad), self.assertRaises(af._MCPClientError):
                af._mcp_call("fleet_summary", {"days": bad}, self._cache())
        af._mcp_call("fleet_summary", {"days": 7}, self._cache())
        af._mcp_call("fleet_summary", {"days": None}, self._cache())

    def test_suppressed_rows_are_marked_and_not_worth_rotating(self):
        r = af._mcp_call("exposed_secrets", {}, self._cache())
        self.assertEqual(r["distinct_secrets"], 3)
        self.assertEqual(r["worth_rotating"], 2)
        marks = {s["fingerprint"]: s["suppressed"] for s in r["secrets"]}
        self.assertEqual(marks, {"aaaa1111": True, "bbbb2222": False, "cccc3333": False})

    def test_server_replies_invalid_params(self):
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "exposed_secrets",
                                      "arguments": {"priority": "medium"}}})
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", mock.Mock(buffer=io.BytesIO((line + "\n").encode()))), \
                mock.patch.object(sys, "stdout", out), \
                mock.patch.object(af, "_MCPCache", lambda *a: self._cache()):
            af.mcp_serve()
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], -32602)


# --- R3D6: --why explains every project a per-project finding fires for -------

class TestR3D6WhyEveryProject(unittest.TestCase):

    def test_every_project_is_explained(self):
        rows = [af.Finding("AF002", "medium", "Low cache", f"{p} reads 10% from cache",
                           "do x", project=p) for p in ("alpha", "beta", "gam\nma")]
        out = io.StringIO()
        with mock.patch.object(af, "coach", lambda f: rows), contextlib.redirect_stdout(out):
            code = af.render_why("AF002", af.Fleet(), af.C(False))
        text = out.getvalue()
        self.assertEqual(code, 0)
        for p in ("alpha reads", "beta reads", "Firing for 3 projects", "gam ma"):
            self.assertIn(p, text)
        self.assertNotIn("gam\nma,", text)

    def test_one_project_reads_as_before(self):
        rows = [af.Finding("AF002", "medium", "Low cache", "alpha reads 10%", "do x",
                           project="alpha")]
        out = io.StringIO()
        with mock.patch.object(af, "coach", lambda f: rows), contextlib.redirect_stdout(out):
            af.render_why("AF002", af.Fleet(), af.C(False))
        self.assertNotIn("Firing for", out.getvalue())


# --- R3D7: a suppression reason cannot write a second entry -------------------

class TestR3D7ReasonIsOneLine(unittest.TestCase):

    def test_control_characters_are_refused_before_writing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(af, "suppression_paths", lambda: [Path(td) / "s"]):
            for bad in ("ok\n620e24b6  x", "ok\r620e24b6", "a\x00b", "a\x85b", "a b"):
                with self.subTest(reason=bad), self.assertRaises(ValueError):
                    af.add_suppression("11111111", bad)
            self.assertFalse((Path(td) / "s").exists())
            af.add_suppression("11111111", "one line")
            entries = [ln for ln in (Path(td) / "s").read_text().splitlines()
                       if ln and not ln.startswith("#")]
            self.assertEqual(len(entries), 1)


# --- R3D8: the docs match the build ---------------------------------------------

class TestR3D8Docs(unittest.TestCase):

    def test_every_schema_leaf_is_documented(self):
        doc = (ROOT / "docs" / "json.md").read_text(encoding="utf-8")
        missing = sorted({k for k in af.JSON_SCHEMA
                          for leaf in [k.split(".")[-1].replace("[]", "").replace("*", "")]
                          if leaf and not re.search(r"(?<!\w)" + re.escape(leaf) + r"(?!\w)", doc)})
        self.assertEqual(missing, [])

    def test_readme_exit_2_is_ours(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("argparse's, not ours", readme)


if __name__ == "__main__":
    unittest.main()
