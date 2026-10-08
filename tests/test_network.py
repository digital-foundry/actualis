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


if __name__ == "__main__":
    unittest.main()
