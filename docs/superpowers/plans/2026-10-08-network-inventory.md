# Network Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a NETWORK section and `--json` key that inventory every download
and fetch a coding agent made, with whether anyone asked. An opt-in
`--network-strict` turns unasked downloads from untrusted sources into
findings.

**Architecture:**
- **Pure functions** in `actualis.py` turn a shell command, or a tool call,
  into network items. They reuse the existing `_shell_tokens()` and
  `_without_heredocs()`.
- **`Fleet.add_tool`** records the items with approval, agent, project,
  session and time. Claude Code tool results mark items failed, and refused
  calls are dropped.
- **After the scan,** `apply_network_policy()` applies the trust list and,
  in strict mode, appends `med` entries to `fleet.flags`, so suppressions and
  `--fail-on any` work unchanged.
- **Output:** `network_json()` feeds `--json`, and `render_network()` feeds
  the text report.

**Tech Stack:** Python 3.9+ standard library only, a single file
(`actualis.py`), and unittest.

**Spec:** `docs/superpowers/specs/2026-10-08-network-inventory-design.md`.
Read §9 (amendments) first: it overrides earlier sections where they
conflict.

## Global Constraints

- **Dependencies:** local, read-only, no network. Single file, no
  third-party dependencies, Python 3.9+. **No new import.** `shlex` is not
  used; reuse `_shell_tokens()`.
- **Self-check:** `--self-check` must keep passing, and the CI import
  allowlist in `.github/workflows/test.yml` stays unchanged.
- **Redaction:** every URL, `dest` and `source` printed or emitted goes
  through `redact()`, unless `raw` / `--no-redact` is set.
- **JSON:** `schema_version` stays **1**. Every new `network.*` path is
  declared in `JSON_SCHEMA`, and every fixed path is always emitted, even for
  an empty fleet.
- **Share and card:** `--share` and `--card` never read network data.
- **Approval values:** exactly `asked`, `unasked` and `unknown`. Kinds:
  exactly `install`, `clone`, `fetch` and `search`.
- **Strict findings:**
  - category `network-unasked`, severity `med`;
  - id `flag_id("med", ["network-unasked"], f"{program}@{host or '?'}")`;
  - they feed `--fail-on any`, and not `high` or `critical`.
- **Trust file:** `./.actualis-network-trust`. Flags `--network-trust`
  (repeatable, comma-separated) and `--network-strict`. Action inputs
  `network-trust` and `network-strict`.
- **`items` cap:** 2,000, newest first, with `items_truncated`.
- **Determinism:** every list in the output has a total sort order, with
  ties broken by fixed keys. No set or dict order reaches output unsorted.
- **Demo fleet:** `tools/make-demo-fleet.py` and the card goldens stay
  untouched.
- **Test command:** `python3 -m unittest discover -s tests -v`.

## Review Focus

1. **Quoted pipes inside `bash -c "curl x | sh"`:** they must parse as two
   inner commands, not as two unbalanced outer segments. → Task 1 test
   `test_bash_c_with_quoted_pipe`.
2. **A refused Claude Code call:** it must not appear in the inventory,
   even though its `tool_use` record was read first. → Task 2 test
   `test_refused_call_is_dropped`.
3. **The trust suffix `npmjs.org`:** it must not trust `evilnpmjs.org`, and
   path `github.com/digital-foundry` must not trust
   `github.com/digital-foundry-evil`. → Task 3 test
   `test_trust_boundaries`.
4. **Credentials in a fetched URL:** for example
   `curl https://x.io/?token=sk-…`. They must never reach text or JSON
   unredacted. → Task 4 test `test_urls_are_redacted`, and Task 5 test
   `test_report_redacts_urls`.
5. **Two runs on the same input:** they must give byte-identical `network`
   JSON, including ties in host and package counts. → Task 4 test
   `test_network_json_is_deterministic`.

---

### Task 1: Command extractors (pure functions)

**Files:**
- Modify: `actualis.py`. Insert a new block, `# --- network inventory ---`,
  directly after `command_category()` (search `def command_category`; put it
  after that function ends).
- Create: `tests/test_network.py`

**Interfaces:**
- Consumes: `_shell_tokens(segment: str) -> list[str]`,
  `_without_heredocs(cmd: str) -> str` and `MAX_SCAN_TOTAL`, all existing.
- Produces:
  - `url_host(url: str) -> str | None`
  - `url_path(url: str) -> str`
  - `network_items_from_command(cmd: str) -> tuple[list[dict], int]`
    (items, unparsed segment count)
  - `NETWORK_REGISTRY: dict[str, str]`
  - `_net_item(kind, program, **kw) -> dict`
  - `_net_url_item(kind, program, url, **kw) -> dict`
  - Each item dict has exactly these keys: `kind`, `program`, `host`,
    `host_inferred`, `url`, `dest`, `source`, `ecosystem`, `package`,
    `version`, `pinned`, `exec`, `dynamic`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_network.py`:

```python
"""Network inventory: what the agent downloaded, and whether anyone asked."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_network -v`
Expected: ERROR or FAIL with `AttributeError: module 'actualis' has no attribute 'network_items_from_command'` (or `url_host`).

- [ ] **Step 3: Implement the extractors**

Insert after `command_category()` in `actualis.py`:

```python
# --- network inventory -------------------------------------------------------
#
# What an agent downloaded, and from where. Only commands and tool calls the
# transcript shows are read; a script that downloads (`bash install.sh`,
# `make`, `npm run x`, a postinstall hook) is out of sight and not guessed at.
# The tokenizer is _shell_tokens(), the same one command_head() uses, so the
# inventory and the audit agree on what a command is.

NETWORK_REGISTRY: dict[str, str] = {
    "npm": "registry.npmjs.org", "pypi": "pypi.org", "brew": "formulae.brew.sh",
    "crates": "crates.io", "go": "proxy.golang.org", "oci": "registry-1.docker.io",
}
NETWORK_ITEMS_CAP = 2000

_NET_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# scp-style git remote: [user@]host.tld:owner/repo
_NET_SCP = re.compile(r"^(?:[^@/\s]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,}):(?!//)(\S+)$")
_NET_EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
_NET_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NET_PREFIX_VALUE_FLAGS = {"sudo": {"-u", "-g", "-C", "-h", "-p"}, "nice": {"-n"}, "env": {"-u", "-C"}}
_NET_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_NET_SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def url_host(url: str) -> str | None:
    """Lowercased host of a URL or scp-style git remote, without user or port.

    None for anything that is not one: a remote name, a path, or a URL built
    from a shell variable, whose host cannot be known from the transcript.
    """
    if not url or "$" in url or "`" in url:
        return None
    if _NET_URL.match(url):
        rest = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
        host = rest.rsplit("@", 1)[-1].split(":", 1)[0]
        return host.lower() or None
    m = _NET_SCP.match(url)
    return m.group(1).lower() if m else None


def url_path(url: str) -> str:
    """The path of a URL or scp-style remote, starting with '/', or ''."""
    if _NET_URL.match(url or ""):
        rest = re.split(r"[?#]", url.split("://", 1)[1], maxsplit=1)[0]
        return rest[rest.find("/"):] if "/" in rest else ""
    m = _NET_SCP.match(url or "")
    return "/" + m.group(2) if m else ""


def _net_item(kind: str, program: str, **kw) -> dict:
    item = {"kind": kind, "program": program, "host": None, "host_inferred": False,
            "url": None, "dest": None, "source": None, "ecosystem": None, "package": None,
            "version": None, "pinned": False, "exec": False, "dynamic": False}
    item.update(kw)
    return item


def _net_url_item(kind: str, program: str, url: str, **kw) -> dict:
    host = url_host(url)
    return _net_item(kind, program, host=host, url=url,
                     dynamic=host is None and ("$" in url or "`" in url), **kw)


def _net_registry_item(program: str, ecosystem: str, name: str | None, version: str | None,
                       registry: str | None, exec_: bool = False) -> dict:
    host = url_host(registry) if registry else None
    return _net_item("install", program, ecosystem=ecosystem, package=name, version=version,
                     pinned=bool(version and _NET_EXACT_VERSION.match(version)), exec=exec_,
                     host=host or NETWORK_REGISTRY[ecosystem], host_inferred=not host)


def _net_lockfile(program: str, ecosystem: str, registry: str | None = None) -> dict:
    item = _net_registry_item(program, ecosystem, None, None, registry)
    item["pinned"] = True
    return item


def _net_positionals(args: list[str], takes_value: frozenset = frozenset()) -> tuple[list[str], dict]:
    """Split argv into positionals and options. An option in `takes_value`
    consumes the next token; `--opt=value` is split; everything after `--`
    is positional."""
    pos: list[str] = []
    opts: dict[str, str] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos += args[i + 1:]
            break
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            opts[k] = v
        elif a.startswith("-") and len(a) > 1:
            if a in takes_value and i + 1 < len(args):
                opts[a] = args[i + 1]
                i += 1
            else:
                opts[a] = ""
        else:
            pos.append(a)
        i += 1
    return pos, opts


def _net_split(text: str) -> tuple[list[str], bool]:
    """Split on && || ; | and newline, outside quotes. Returns the parts and
    whether a quote was left open (the last part is then unusable)."""
    parts, buf, quote, i = [], [], "", 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif text.startswith(("&&", "||"), i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        elif ch in ";|\n":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts, bool(quote)


def _net_strip_prefixes(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if _NET_ASSIGN.match(t):
            i += 1
            continue
        if t in ("sudo", "env", "time", "nice", "nohup", "command", "exec"):
            takes = _NET_PREFIX_VALUE_FLAGS.get(t, set())
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 2 if tokens[i] in takes else 1
            continue
        break
    return tokens[i:]


def _net_segments(cmd: str, depth: int = 0) -> tuple[list[list[str]], int]:
    """Token lists for every simple command in `cmd`, nested ones included
    ($(...), backticks, bash -c "..."), and how many segments could not be
    tokenised because a quote was left open."""
    out: list[list[str]] = []
    unparsed = 0
    text = _without_heredocs(cmd)
    if depth < 3:
        for m in _NET_SUBST.finditer(text):
            inner, bad = _net_segments(m.group(1) or m.group(2) or "", depth + 1)
            out += inner
            unparsed += bad
    parts, open_quote = _net_split(_NET_SUBST.sub(" ", text))
    if open_quote:
        parts = parts[:-1]
        unparsed += 1
    for segment in parts:
        tokens = _net_strip_prefixes(_shell_tokens(segment))
        if not tokens:
            continue
        if (depth < 3 and Path(tokens[0]).name in _NET_SHELLS
                and "-c" in tokens[1:-1]):
            inner, bad = _net_segments(tokens[tokens.index("-c", 1) + 1], depth + 1)
            out += inner
            unparsed += bad
            continue
        out.append(tokens)
    return out, unparsed


_CURL_VALUE = frozenset(
    "-o --output -H --header -d --data --data-raw --data-binary --data-urlencode -X --request "
    "-u --user -A --user-agent -e --referer -b --cookie -c --cookie-jar -F --form -T --upload-file "
    "-w --write-out -m --max-time --connect-timeout -x --proxy --retry -r --range --cacert --cert "
    "--key -K --config --resolve --url -E".split())
_WGET_VALUE = frozenset("-O --output-document -P --directory-prefix -o --output-file -U --user-agent "
                        "--header -t --tries -T --timeout -e --execute".split())
_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree"})
_GIT_CLONE_VALUE = frozenset("--depth -b --branch -o --origin --reference --filter -c --config "
                             "-j --jobs --template --separate-git-dir".split())
_GH_DOWNLOAD_VALUE = frozenset({"-R", "--repo", "-p", "--pattern", "-D", "--dir", "-O", "--output",
                                "-A", "--archive"})
_NPM_VALUE = frozenset("--registry --prefix -w --workspace --tag --cache -C --dir --filter".split())
_NPM_INSTALL = {"npm": {"i", "install", "add"}, "pnpm": {"add", "install", "i"},
                "yarn": {"add", "install"}, "bun": {"add", "install", "i"}}
_NPX_VALUE = frozenset({"-p", "--package", "--registry", "-c", "--call"})
_PIP_VALUE = frozenset("-r --requirement -c --constraint -i --index-url --extra-index-url -t --target "
                       "--prefix --root -e --editable -f --find-links --python -p --platform".split())
_UVX_VALUE = frozenset({"--from", "--with", "-p", "--python", "--index-url", "-i"})
_CARGO_VALUE = frozenset({"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path",
                          "--registry", "--index", "-F", "--features", "--root"})
_GO_VALUE = frozenset({"-C", "-modfile", "-tags", "-ldflags", "-o"})
_DOCKER_VALUE = frozenset("-v --volume -e --env -p --publish --name -w --workdir --network --entrypoint "
                          "-u --user --platform --env-file -l --label --mount -h --hostname --add-host "
                          "--cpus -m --memory --restart --pull --log-driver --gpus".split())
_PIP_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^,;\s]*)")


def _net_is_url_arg(a: str) -> bool:
    return "://" in a or "$" in a or "`" in a


def _net_curl(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _CURL_VALUE)
    urls = [u for u in pos if _net_is_url_arg(u)] + ([opts["--url"]] if opts.get("--url") else [])
    dest = opts.get("-o") or opts.get("--output") or (
        "(remote name)" if "-O" in opts or "--remote-name" in opts else None)
    return [_net_url_item("fetch", "curl", u, dest=dest) for u in urls]


def _net_wget(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _WGET_VALUE)
    dest = (opts.get("-O") or opts.get("--output-document") or opts.get("-P")
            or opts.get("--directory-prefix"))
    return [_net_url_item("fetch", "wget", u, dest=dest) for u in pos if _net_is_url_arg(u)]


def _net_git(args: list[str]) -> list[dict]:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in _GIT_GLOBAL_VALUE else 1
    if i >= len(args):
        return []
    sub, rest = args[i], args[i + 1:]
    if sub == "clone":
        pos, _ = _net_positionals(rest, _GIT_CLONE_VALUE)
        if not pos:
            return []
        return [_net_url_item("clone", "git", pos[0], dest=pos[1] if len(pos) > 1 else None)]
    if sub in ("fetch", "pull"):
        pos, _ = _net_positionals(rest, frozenset({"--depth", "-j", "--jobs"}))
        if pos and (_NET_URL.match(pos[0]) or url_host(pos[0])):
            return [_net_url_item("clone", "git", pos[0])]
        return [_net_item("clone", "git")]
    if sub == "submodule" and rest[:1] == ["update"]:
        return [_net_item("clone", "git")]
    return []


def _net_gh(args: list[str]) -> list[dict]:
    if args[:2] == ["repo", "clone"] and len(args) > 2:
        repo = args[2]
        url = repo if "://" in repo or url_host(repo) else f"https://github.com/{repo}"
        return [_net_url_item("clone", "gh", url)]
    if args[:2] == ["release", "download"]:
        _, opts = _net_positionals(args[2:], _GH_DOWNLOAD_VALUE)
        dest = opts.get("-D") or opts.get("--dir") or opts.get("-O") or opts.get("--output")
        repo = opts.get("-R") or opts.get("--repo")
        if repo:
            return [_net_url_item("fetch", "gh", f"https://github.com/{repo}", dest=dest)]
        return [_net_item("fetch", "gh", host="github.com", dest=dest)]
    return []


def _net_npm_package(program: str, spec: str, registry: str | None, exec_: bool = False) -> dict | None:
    forge = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
    prefix = spec.split(":", 1)[0]
    if prefix in forge and ":" in spec and "://" not in spec:
        return _net_item("install", program, ecosystem="npm", host=forge[prefix], package=spec, exec=exec_)
    if "://" in spec:
        url = spec[4:] if spec.startswith("git+") else spec
        return _net_url_item("install", program, url, ecosystem="npm", exec=exec_)
    if spec.startswith((".", "/", "~", "file:")):
        return None
    at = spec.find("@", 1)
    name, version = (spec, None) if at < 0 else (spec[:at], spec[at + 1:] or None)
    return _net_registry_item(program, "npm", name, version, registry, exec_)


def _net_npm(prog: str, args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _NPM_VALUE)
    registry = opts.get("--registry")
    lockfile = ((prog == "npm" and pos[:1] == ["ci"])
                or (prog == "pnpm" and pos[:1] == ["install"] and "--frozen-lockfile" in opts)
                or (prog == "yarn" and pos[:1] in ([], ["install"]) and "--immutable" in opts))
    if lockfile:
        return [_net_lockfile(prog, "npm", registry)]
    if prog == "yarn" and not pos:
        pos = ["install"]
    if not pos or pos[0] not in _NPM_INSTALL[prog]:
        return []
    if len(pos) == 1:
        return [_net_registry_item(prog, "npm", None, None, registry)]
    found = (_net_npm_package(prog, s, registry) for s in pos[1:])
    return [i for i in found if i]


def _net_npx(prog: str, args: list[str]) -> list[dict]:
    label = "pnpm dlx" if prog == "pnpm" else prog
    if prog == "pnpm":
        args = args[1:]                      # drop "dlx"
    pos, opts = _net_positionals(args, _NPX_VALUE)
    spec = opts.get("-p") or opts.get("--package") or (pos[0] if pos else None)
    if not spec:
        return []
    item = _net_npm_package(label, spec, opts.get("--registry"), exec_=True)
    return [item] if item else []


def _net_pip_package(program: str, spec: str, registry: str | None, exec_: bool = False) -> dict | None:
    if spec == "@" or spec.startswith((".", "/", "~")):
        return None
    if "://" in spec:
        url = spec.split("+", 1)[1] if spec.startswith("git+") else spec
        return _net_url_item("install", program, url, ecosystem="pypi", exec=exec_)
    if "@" in spec:                          # uvx / pipx style name@version
        name, _, ver = spec.partition("@")
        spec = f"{name}=={ver}"
    m = _PIP_SPEC.match(spec)
    if not m:
        return None
    exact = m.group(3) in ("==", "===") and "*" not in m.group(4)
    return _net_registry_item(program, "pypi", m.group(1), m.group(4) if exact else None, registry, exec_)


def _net_pip(prog: str, args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _PIP_VALUE)
    if not pos or pos[0] != "install":
        return []
    registry = opts.get("-i") or opts.get("--index-url")
    out: list[dict] = []
    req = opts.get("-r") or opts.get("--requirement")
    if req:
        item = _net_registry_item(prog, "pypi", None, None, registry)
        item["source"] = req
        out.append(item)
    for spec in pos[1:]:
        item = _net_pip_package(prog, spec, registry)
        if item:
            out.append(item)
    return out


def _net_uv(args: list[str]) -> list[dict]:
    if args[:2] == ["pip", "install"]:
        return _net_pip("uv pip", args[1:])
    if args[:1] == ["add"]:
        return _net_pip("uv", ["install"] + args[1:])
    if args[:1] == ["sync"]:
        return [_net_lockfile("uv", "pypi")]
    return []


def _net_uvx(prog: str, args: list[str]) -> list[dict]:
    exec_ = True
    if prog == "pipx":
        if not args or args[0] not in ("run", "install"):
            return []
        exec_, args = args[0] == "run", args[1:]
    pos, opts = _net_positionals(args, _UVX_VALUE)
    spec = opts.get("--from") or (pos[0] if pos else None)
    if not spec:
        return []
    item = _net_pip_package(prog, spec, opts.get("-i") or opts.get("--index-url"), exec_=exec_)
    return [item] if item else []


def _net_brew(args: list[str]) -> list[dict]:
    pos, _ = _net_positionals(args)
    if not pos or pos[0] not in ("install", "reinstall", "tap"):
        return []
    return [_net_registry_item("brew", "brew", f, None, None) for f in pos[1:]]


def _net_cargo(args: list[str]) -> list[dict]:
    pos, opts = _net_positionals(args, _CARGO_VALUE)
    if not pos or pos[0] not in ("install", "add") or opts.get("--path"):
        return []
    if opts.get("--git"):
        return [_net_url_item("install", "cargo", opts["--git"], ecosystem="crates",
                              package=pos[1] if len(pos) > 1 else None)]
    version = opts.get("--version") or opts.get("--vers")
    out = []
    for spec in pos[1:]:
        name, _, ver = spec.partition("@")
        out.append(_net_registry_item("cargo", "crates", name, ver or version, None))
    return out


def _net_go(args: list[str]) -> list[dict]:
    pos, _ = _net_positionals(args, _GO_VALUE)
    if not pos or pos[0] not in ("install", "get"):
        return []
    out = []
    for spec in pos[1:]:
        mod, _, ver = spec.partition("@")
        first = mod.split("/", 1)[0]
        if spec.startswith((".", "/")) or "." not in first:
            continue                         # local package or standard library
        out.append(_net_item("install", "go", ecosystem="go", package=mod, version=ver or None,
                             pinned=bool(ver and ver != "latest" and _NET_EXACT_VERSION.match(ver)),
                             host=first.lower()))
    return out


def _net_docker(prog: str, args: list[str]) -> list[dict]:
    if not args or args[0] not in ("pull", "run"):
        return []
    pos, _ = _net_positionals(args[1:], _DOCKER_VALUE)
    if not pos:
        return []
    ref = pos[0]
    name, _, digest = ref.partition("@")
    first = name.split("/", 1)[0]
    explicit = "/" in name and ("." in first or ":" in first or first == "localhost")
    last = name.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    pkg = name[:len(name) - len(tag) - 1] if tag else name
    host = first.split(":", 1)[0].lower() if explicit else None
    return [_net_item("install", prog, ecosystem="oci", package=pkg, version=digest or tag,
                      pinned=digest.startswith("sha256:"),
                      host=host or NETWORK_REGISTRY["oci"], host_inferred=not host)]


def _net_extract(tokens: list[str]) -> list[dict]:
    prog, args = Path(tokens[0]).name, tokens[1:]
    if re.fullmatch(r"python(?:\d(?:\.\d+)?)?", prog) and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    if prog == "curl":
        return _net_curl(args)
    if prog == "wget":
        return _net_wget(args)
    if prog == "git":
        return _net_git(args)
    if prog == "gh":
        return _net_gh(args)
    if prog in ("npx", "bunx") or (prog == "pnpm" and args[:1] == ["dlx"]):
        return _net_npx(prog, args)
    if prog in _NPM_INSTALL:
        return _net_npm(prog, args)
    if prog in ("pip", "pip3"):
        return _net_pip(prog, args)
    if prog == "uv":
        return _net_uv(args)
    if prog in ("uvx", "pipx"):
        return _net_uvx(prog, args)
    if prog == "brew":
        return _net_brew(args)
    if prog == "cargo":
        return _net_cargo(args)
    if prog == "go":
        return _net_go(args)
    if prog in ("docker", "podman"):
        return _net_docker(prog, args)
    return []


def network_items_from_command(cmd: str) -> tuple[list[dict], int]:
    """Every download the command shows, and how many segments could not be read."""
    segments, unparsed = _net_segments((cmd or "")[:MAX_SCAN_TOTAL])
    found: list[dict] = []
    for tokens in segments:
        found += _net_extract(tokens)
    return found, unparsed
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_network -v`
Expected: all of `TestUrlHost`, `TestFetchers`, `TestVcs` and `TestPackages`
PASS. If a case fails, fix the extractor, not the test. The tests are the
spec's behaviour.

Then run the full suite: `python3 -m unittest discover -s tests -v`
Expected: all PASS, including the import-allowlist and `--self-check`
tests. No new import was added: `Path` and `re` already exist.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_network.py
git commit -m "feat(network): extract downloads from shell commands"
```

---

### Task 2: Tool calls, approval, and Fleet integration

**Files:**
- Modify: `actualis.py`:
  - add `network_items_from_tool` and `network_approval` after
    `network_items_from_command`;
  - `Fleet.__init__` (search `self.flags: list[dict] = []`);
  - `Fleet.add_tool` (search `def add_tool(`);
  - `Fleet._ingest_claude` (search `def _ingest_claude`);
  - the `tool_use` loop in `_ingest_claude` (search `calls[block["id"]] = (`);
  - `Fleet._scan_file` prefilter (search `'"toolDenialKind"' not in line`);
  - `Fleet._scan_codex_file` (search `if kind == "session_meta":` and
    `for cmd, ts, mode in pending:`);
  - `Fleet._scan_copilot_file` (search `kind == "tool.execution_start"` and
    `for call_id, name, cmd, ts in calls:`).
- Test: `tests/test_network.py`

**Interfaces:**
- Consumes: `network_items_from_command` and `_net_item`/`_net_url_item`
  (Task 1), and the existing `is_ungated_mode(key: str) -> bool`.
- Produces:
  - `network_items_from_tool(name: str, tool_input: dict) -> list[dict]`
  - `network_approval(mode: str | None) -> str`
  - `Fleet.network: list[dict]` (raw, including refused)
  - `Fleet.network_items` (property: list of dicts, excluding refused)
  - `Fleet.network_unparsed: int`
  - `Fleet.network_trust: list[str]` (default `[]`)
  - `Fleet.network_strict: bool` (default `False`)
  - `Fleet.add_tool(project, name, tool_input, ts, mode=None, *, session=None, call_id=None, agent=None)`
  - Each stored item has Task 1's keys plus `approval`, `agent` (`claude`,
    `codex` or `copilot`), `project`, `session` (str or None), `ts` (ISO str
    or None), `failed` (bool for Claude Code, None otherwise) and `trusted`
    (False until Task 3).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_network.py`, before the `if __name__` block:

```python
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
```

Codex and Copilot shapes: add these two tests. They reuse
`tests/_fixtures.py` for Copilot. Read that file first: its
`_start`/`_bash`/`_ask`/`_done` helpers and `write_sessions`/`isolated_home`
show the event shapes.

```python
class TestOtherAgents(unittest.TestCase):
    def test_codex_shell_command_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rollout.jsonl"
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
        import _fixtures as fx   # tests/ is on sys.path under unittest discover
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
```

The Copilot test imports `_fixtures` only to fail loudly if the fixture
module moves. If `scan_copilot` needs a different root layout, the
signature is `scan_copilot(roots, since, project_filter)`. Match it to
`tests/test_copilot.py`'s usage, and keep the test's assertions unchanged.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_network -v`
Expected: the new classes FAIL or ERROR with `no attribute 'network_items_from_tool'` / `'network_items'`.

- [ ] **Step 3: Add the tool and approval functions** (after `network_items_from_command`)

```python
_NET_TOOL_WORDS = ("fetch", "browse", "download", "http")


def network_items_from_tool(name: str, tool_input: dict) -> list[dict]:
    """A non-shell tool call that reaches the network. A search keeps no query:
    the query is the user's words, not a destination."""
    n = (name or "").lower()
    if n in ("bash", "shell_command"):
        return []
    if n in ("websearch", "web_search"):
        return [_net_item("search", name)]
    if n in ("webfetch", "web_fetch") or any(w in n for w in _NET_TOOL_WORDS):
        inp = tool_input if isinstance(tool_input, dict) else {}
        url = next((inp[k] for k in ("url", "uri", "href") if isinstance(inp.get(k), str)), None)
        return [_net_url_item("fetch", name, url) if url else _net_item("fetch", name)]
    return []


def network_approval(mode: str | None) -> str:
    """asked / unasked / unknown, from the mode key the call ran under.

    The same is_ungated_mode() that --share and --card read, so "unasked" here
    cannot disagree with "unsupervised" there. Claude Code writes no record
    for a call a person approved, so outside auto or bypass it is unknown:
    an allowlist rule in settings may have let it through silently.
    """
    if mode == "copilot:prompted":
        return "asked"
    return "unasked" if mode and is_ungated_mode(mode) else "unknown"
```

- [ ] **Step 4: Wire up `Fleet`**

In `Fleet.__init__`, directly after `self.flags: list[dict] = []`:

```python
        # Network inventory. `network` keeps refused calls (flagged
        # `_refused`) so a later refusal record can find them by call id;
        # everything downstream reads `network_items`, which drops them.
        self.network: list[dict] = []
        self.network_unparsed = 0
        self.network_trust: list[str] = []
        self.network_strict = False
        self._net_by_call: dict[str, list[int]] = {}
```

Replace the `add_tool` signature and its first three lines:

```python
    def add_tool(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                 mode: str | None = None, *, session: str | None = None,
                 call_id: str | None = None, agent: str | None = None) -> None:
        project = clean(project)[:120] or "unknown"
        name = clean(name)[:48] or "?"
        self.tools[name] += 1
        self._add_network(project, name, tool_input or {}, ts, mode, session, call_id, agent)
        if name != "Bash":
            return
```

The rest of `add_tool` is unchanged. Add these methods to `Fleet`, directly
after `add_tool`:

```python
    def _add_network(self, project: str, name: str, tool_input: dict, ts: datetime | None,
                     mode: str | None, session: str | None, call_id: str | None,
                     agent: str | None) -> None:
        if name == "Bash":
            cmd = tool_input.get("command")
            if not isinstance(cmd, str) or not cmd:
                return
            found, unparsed = network_items_from_command(cmd)
            self.network_unparsed += unparsed
        else:
            found = network_items_from_tool(name, tool_input)
        if not found:
            return
        if not agent:
            agent = ("codex" if (mode or "").startswith("codex:")
                     else "copilot" if (mode or "").startswith("copilot:") else "claude")
        for item in found:
            item.update(approval=network_approval(mode), agent=agent, project=project,
                        session=clean(str(session))[:80] if session else None,
                        ts=ts.isoformat() if ts else None,
                        failed=False if agent == "claude" else None, trusted=False)
            if call_id:
                self._net_by_call.setdefault(f"{agent}:{call_id}", []).append(len(self.network))
            self.network.append(item)

    def _network_outcome(self, key: str, refused: bool) -> None:
        """A call's result: refused calls leave the inventory, errors mark it failed."""
        for i in self._net_by_call.pop(key, ()):
            if refused:
                self.network[i]["_refused"] = True
            else:
                self.network[i]["failed"] = True

    def _network_results(self, rec: dict) -> None:
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        if not self._net_by_call or not isinstance(content, list):
            return
        refused = bool(rec.get("toolDenialKind"))
        for b in content:
            if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error"):
                self._network_outcome(f"claude:{b.get('tool_use_id') or ''}", refused)

    @property
    def network_items(self) -> list[dict]:
        return [i for i in self.network if not i.get("_refused")]
```

In `_ingest_claude`, directly after `if since and ts and ts < since:` /
`return`, insert:

```python
        self._network_results(rec)
```

In the `_ingest_claude` `tool_use` loop, replace the `self.add_tool(...)`
call with:

```python
                    self.add_tool(project, block.get("name") or "?",
                                  block.get("input") or {}, ts, self._mode,
                                  session=rec.get("sessionId"), call_id=block.get("id"),
                                  agent="claude")
```

In the `_scan_file` prefilter, add the error-result case so failed and
refused results reach `_ingest_claude`. A plain successful `tool_result`
stays skipped, which keeps the prefilter cheap:

```python
                    if ('"usage"' not in line and '"tool_use"' not in line
                            and '"permissionMode"' not in line
                            and '"toolDenialKind"' not in line
                            and '"is_error":true' not in line
                            and '"is_error": true' not in line):
                        continue
```

**Codex**, in `_scan_codex_file`:
- initialise `session = None` where `cwd` is initialised;
- in the `session_meta` branch add
  `session = payload.get("id") or session`;
- change the replay call to
  `self.add_tool(project, "Bash", {"command": cmd}, ts, mode, session=session, agent="codex")`.

**Copilot**, in `_scan_copilot_file`:
- in the `tool.execution_start` branch, append the arguments:
  `calls.append((str(data.get("toolCallId") or ""), name, cmd, ts, args if isinstance(args, dict) else {}))`;
- next to `prompted: set[str] = set()` add
  `prompted_any: set[str] = set()`;
- in the `permission.requested` branch, record every prompted call before
  the shell check:

```python
                    elif kind == "permission.requested":
                        req = data.get("permissionRequest")
                        if isinstance(req, dict) and req.get("toolCallId"):
                            prompted_any.add(str(req["toolCallId"]))
                        if isinstance(req, dict) and req.get("kind") == "shell" \
                                and req.get("toolCallId"):
                            prompted.add(str(req["toolCallId"]))
```

Replace the replay loop's two `add_tool` calls:

```python
        sid = path.parent.name
        for call_id, name, cmd, ts, targs in calls:
            if not in_window(ts):
                continue
            active = True
            if cmd:
                mode = "copilot:prompted" if call_id in prompted else "copilot:auto"
                self.permission_modes[mode] += 1
                # Normalised onto "Bash", as Codex is, so the audit is one view.
                self.add_tool(project, "Bash", {"command": cmd}, ts, mode,
                              session=sid, call_id=call_id, agent="copilot")
                if call_id:
                    joined[call_id] = ("Bash", cmd[:MAX_SCAN_LINE])
            else:
                # The arguments go to the network inventory only; add_tool
                # counts nothing else for a non-Bash tool.
                net_mode = "copilot:prompted" if call_id in prompted_any else "copilot:auto"
                self.add_tool(project, name, targs, ts, net_mode,
                              session=sid, call_id=call_id, agent="copilot")
                if call_id:
                    joined[call_id] = (name, "")
```

In the refusals loop that follows, add
`self._network_outcome(f"copilot:{call_id}", refused=True)` inside the
`if in_window(ts):` block. Then grep for any other unpacking of the Copilot
`calls` tuple (`grep -n "in calls:" actualis.py`) and update each one to the
5-tuple.

- [ ] **Step 5: Run the tests**

Run: `python3 -m unittest tests.test_network -v`, then the full suite:
`python3 -m unittest discover -s tests -v`.
Expected: all PASS. The existing Copilot, refusal and Codex tests must stay
green; their counters are untouched.

- [ ] **Step 6: Commit**

```bash
git add actualis.py tests/test_network.py
git commit -m "feat(network): record downloads per agent with approval, failure and refusal"
```

---

### Task 3: Trust list, strict mode, CLI flags

**Files:**
- Modify: `actualis.py`:
  - add the functions after `network_approval`;
  - add the two flags in `build_parser` (search `ap.add_argument("--fail-on"`);
  - load trust and apply the policy in `main`. Load trust right after the
    `ap.error` argument checks (search the last `ap.error(` in `main`).
    Apply the policy right after the `if fleet.messages == 0 and
    fleet.bash_total == 0:` block.
- Test: `tests/test_network.py`

**Interfaces:**
- Consumes:
  - `Fleet.network_items`, `Fleet.flags`, `Fleet.suppressions`,
    `Fleet.suppressed_flags`;
  - `flag_id`, `url_path` and `failing_findings(fleet, level)`.
- Produces:
  - `NETWORK_TRUST_FILE = ".actualis-network-trust"`
  - `parse_trust(entries: list[str]) -> list[tuple[str, str]]`: `(host,
    "/path" or "")`; raises `ValueError`.
  - `load_network_trust(cli: list[str] | None, cwd: Path | None = None) -> list[tuple[str, str]]`
  - `network_trusted(item: dict, trust: list[tuple[str, str]]) -> bool`
  - `apply_network_policy(fleet, trust: list[tuple[str, str]], strict: bool) -> None`
  - Flags `--network-trust` (`action="append"`, dest `network_trust`) and
    `--network-strict` (`store_true`).

- [ ] **Step 1: Write the failing tests**

```python
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
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()):
            import contextlib
            with contextlib.redirect_stderr(io.StringIO()):
                af.main(["--network-trust", "https://x.io", "--json"])
        self.assertEqual(cm.exception.code, 2)
```

`failing_findings` also checks coach findings and secrets. On these fleets
there are none: no usage, so no coach output. If the assertion trips on an
unrelated coach item, filter the returned reasons for the
`medium-severity` string rather than weakening the check.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_network -v`
Expected: `TestTrust` and `TestStrict` ERROR with missing attributes.

- [ ] **Step 3: Implement** (after `network_approval`)

```python
NETWORK_TRUST_FILE = ".actualis-network-trust"
_TRUST_ENTRY = re.compile(r"^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)"
                          r"(/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?/?$")


def parse_trust(entries: list[str]) -> list[tuple[str, str]]:
    """Trust entries as (host, "/path" or ""). A bad entry is an error, never
    a silent skip: a typo in a trust list would otherwise trust nothing, or
    worse, be read as something broader than meant."""
    out: list[tuple[str, str]] = []
    for raw in entries:
        e = raw.strip()
        if not e:
            continue
        host, _, path = e.partition("/")
        m = _TRUST_ENTRY.match(host.lower() + ("/" + path if path else ""))
        if "://" in e or "*" in e or not m:
            raise ValueError(f"network trust entry {raw.strip()!r} is not a host or host/path "
                             "(no scheme, port or wildcard)")
        out.append((m.group(1), (m.group(2) or "").rstrip("/")))
    return out


def load_network_trust(cli: list[str] | None, cwd: Path | None = None) -> list[tuple[str, str]]:
    """--network-trust values (comma-separated, repeatable), then ./.actualis-network-trust."""
    entries: list[str] = []
    for value in cli or []:
        entries += value.split(",")
    try:
        text = ((cwd or Path.cwd()) / NETWORK_TRUST_FILE).read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        entries.append(line.split("#", 1)[0])
    return parse_trust(entries)


def _net_item_path(item: dict) -> str:
    if item.get("url"):
        return url_path(item["url"])
    pkg = item.get("package") or ""
    if item.get("ecosystem") == "go" and "/" in pkg:
        return "/" + pkg.split("/", 1)[1]
    return ""


def network_trusted(item: dict, trust: list[tuple[str, str]]) -> bool:
    """Host suffix on a label boundary; path prefix on a segment boundary.
    An item with no known host is never trusted."""
    host = item.get("host")
    if not host:
        return False
    path = _net_item_path(item)
    for h, p in trust:
        if host != h and not host.endswith("." + h):
            continue
        if not p or path == p or path.startswith(p + "/"):
            return True
    return False


def apply_network_policy(fleet: "Fleet", trust: list[tuple[str, str]], strict: bool) -> None:
    """Mark trusted items, and in strict mode turn each untrusted, unapproved,
    not-failed group (program, host) into one medium shell-audit flag. Run once,
    after the scan."""
    fleet.network_trust = [h + p for h, p in trust]
    fleet.network_strict = strict
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in fleet.network_items:
        item["trusted"] = network_trusted(item, trust)
        if strict and not item["trusted"] and item["approval"] != "asked" and item["failed"] is not True:
            groups.setdefault((item["program"], item["host"] or "?"), []).append(item)
    for (program, host), group in sorted(groups.items()):
        fid = flag_id("med", ["network-unasked"], f"{program}@{host}")
        suppressed = fid in fleet.suppressions
        if suppressed:
            fleet.suppressed_flags += 1
        latest = max(group, key=lambda i: (i["ts"] or "", i["project"]))
        where = "a URL built from a variable" if host == "?" else host
        fleet.flags.append({
            "id": fid, "severity": "med", "categories": ["network-unasked"],
            "program": program, "project": latest["project"], "when": latest["ts"],
            "evidence": f"{len(group)} unasked download(s) via {program} from {where}"[:240],
            "had_secret": False, "suppressed": suppressed,
            "suppressed_reason": fleet.suppressions.get(fid) if suppressed else None,
        })
```

Before committing, open the existing flag dict in `add_tool` (search
`self.flags.append({`). Confirm the key set and value types match:
`had_secret` and `suppressed_reason` exactly as that dict builds them. If
that dict computes `suppressed_reason` differently (for example `""`
rather than `None`), copy its form.

In `build_parser`, after the `--fail-on` argument:

```python
    ap.add_argument("--network-trust", metavar="HOST[/PATH],...", action="append",
                    help="trusted download sources for --network-strict; also read from "
                         "./.actualis-network-trust")
    ap.add_argument("--network-strict", action="store_true",
                    help="make every unasked download from an untrusted source a medium finding")
```

In `main`, after the argument-conflict `ap.error` checks:

```python
    try:
        network_trust = load_network_trust(args.network_trust)
    except ValueError as exc:
        ap.error(str(exc))
```

In `main`, right after the `if fleet.messages == 0 and fleet.bash_total ==
0:` block returns:

```python
    apply_network_policy(fleet, network_trust, args.network_strict)
```

If `main` names the parser something other than `ap`, use that name.
`ap.error` exits with code 2.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest tests.test_network -v`, then the full suite.
Expected: all PASS. The `--completions` test picks up the new flags
automatically. If it asserts an exact flag list, add the two flags to its
expectation.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_network.py
git commit -m "feat(network): trust list and --network-strict findings"
```

---

### Task 4: `--json` network key, schema and docs

**Files:**
- Modify: `actualis.py`:
  - add `NETWORK_ITEM_KEYS` and `network_json` after `apply_network_policy`;
  - `_to_json_body`: add `"network": network_json(fleet, raw),` before
    `"unknown_models"`;
  - `JSON_SCHEMA`: add the paths below after the `"refusals.*"` entries.
- Modify: `docs/json.md`: add a `network` row to the top-level table, and a
  `## network` section.
- Test: `tests/test_network.py`

**Interfaces:**
- Consumes: `Fleet.network_items`, `network_unparsed`, `network_strict`,
  `network_trust`, `redact`.
- Produces: `network_json(fleet, raw: bool = False) -> dict` and
  `NETWORK_ITEM_KEYS: tuple[str, ...]`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

The existing schema tests in `tests/test_actualis.py` (every emitted key
declared, every declared key emitted) are the check that the
`JSON_SCHEMA` additions are complete. Run them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_network -v`
Expected: `TestNetworkJson` ERROR with `no attribute 'network_json'`.

- [ ] **Step 3: Implement**

```python
NETWORK_ITEM_KEYS = ("kind", "program", "host", "host_inferred", "url", "dest", "source",
                     "ecosystem", "package", "version", "pinned", "exec", "dynamic", "failed",
                     "approval", "trusted", "agent", "project", "session", "ts")


def network_json(fleet: "Fleet", raw: bool = False) -> dict:
    """The `network` key of --json. Every list has a total order, so the same
    input gives the same bytes."""
    items = fleet.network_items
    approval = Counter(i["approval"] for i in items)
    kinds = Counter(i["kind"] for i in items)

    hosts: dict[str, dict] = {}
    for i in items:
        if not i["host"]:
            continue
        h = hosts.setdefault(i["host"], {"host": i["host"], "count": 0, "unasked": 0,
                                         "first_seen": None, "trusted": False})
        h["count"] += 1
        h["unasked"] += 1 if i["approval"] == "unasked" else 0
        if i["ts"] and (h["first_seen"] is None or i["ts"] < h["first_seen"]):
            h["first_seen"] = i["ts"]
        h["trusted"] = h["trusted"] or i["trusted"]

    packages: dict[tuple[str, str], dict] = {}
    for i in items:
        if not i["package"]:
            continue
        p = packages.setdefault((i["ecosystem"] or "", i["package"]), {
            "ecosystem": i["ecosystem"], "name": i["package"], "versions": set(),
            "pinned": True, "exec": False, "count": 0})
        p["count"] += 1
        if i["version"]:
            p["versions"].add(i["version"])
        p["pinned"] = p["pinned"] and i["pinned"]
        p["exec"] = p["exec"] or i["exec"]

    def public(i: dict) -> dict:
        out = {k: i[k] for k in NETWORK_ITEM_KEYS}
        if not raw:
            for k in ("url", "dest", "source"):
                if out[k]:
                    out[k] = redact(out[k])
        return out

    order = sorted(items, key=lambda i: (i["ts"] or "", i["agent"], i["project"], i["program"],
                                         i["host"] or "", i["url"] or "", i["package"] or ""),
                   reverse=True)
    return {
        "totals": {"items": len(items), "asked": approval["asked"], "unasked": approval["unasked"],
                   "unknown": approval["unknown"],
                   "failed": sum(1 for i in items if i["failed"] is True),
                   "unparsed_segments": fleet.network_unparsed},
        "by_kind": {k: kinds.get(k, 0) for k in ("install", "clone", "fetch", "search")},
        "hosts": sorted(hosts.values(), key=lambda h: (-h["count"], h["host"])),
        "packages": [{**p, "versions": sorted(p["versions"])}
                     for _, p in sorted(packages.items(), key=lambda kv: (-kv[1]["count"], kv[0]))],
        "items": [public(i) for i in order[:NETWORK_ITEMS_CAP]],
        "items_truncated": len(items) > NETWORK_ITEMS_CAP,
        "strict": fleet.network_strict,
        "trust": list(fleet.network_trust),
    }
```

`test_shape` expects `packages` order `a, b, c`. All counts are 1, so ties
break on `(ecosystem, name)`. Hosts expect `registry.npmjs.org` (count 2)
first, then `pypi.org` and `x.io` alphabetically.

In `_to_json_body`'s returned dict, before `"unknown_models": ...`, add:

```python
        "network": network_json(fleet, raw),
```

`JSON_SCHEMA` additions. Use only the type names the schema already uses
(`int`, `float`, `bool`, `str`, `str|null`, `array`). For `failed`, check
how the schema test parses `|null`. If it splits on `|` generically, use
`"bool|null"`. Otherwise add `bool|null` support to that parser in the
same commit, with one line of comment.

```python
    "network.totals.items": "int",
    "network.totals.asked": "int",
    "network.totals.unasked": "int",
    "network.totals.unknown": "int",
    "network.totals.failed": "int",
    "network.totals.unparsed_segments": "int",
    "network.by_kind.install": "int",
    "network.by_kind.clone": "int",
    "network.by_kind.fetch": "int",
    "network.by_kind.search": "int",
    "network.hosts[].host": "str",
    "network.hosts[].count": "int",
    "network.hosts[].unasked": "int",
    "network.hosts[].first_seen": "str|null",
    "network.hosts[].trusted": "bool",
    "network.packages[].ecosystem": "str",
    "network.packages[].name": "str",
    "network.packages[].versions": "array",
    "network.packages[].pinned": "bool",
    "network.packages[].exec": "bool",
    "network.packages[].count": "int",
    "network.items[].kind": "str",
    "network.items[].program": "str",
    "network.items[].host": "str|null",
    "network.items[].host_inferred": "bool",
    "network.items[].url": "str|null",
    "network.items[].dest": "str|null",
    "network.items[].source": "str|null",
    "network.items[].ecosystem": "str|null",
    "network.items[].package": "str|null",
    "network.items[].version": "str|null",
    "network.items[].pinned": "bool",
    "network.items[].exec": "bool",
    "network.items[].dynamic": "bool",
    "network.items[].failed": "bool|null",
    "network.items[].approval": "str",
    "network.items[].trusted": "bool",
    "network.items[].agent": "str",
    "network.items[].project": "str",
    "network.items[].session": "str|null",
    "network.items[].ts": "str|null",
    "network.items_truncated": "bool",
    "network.strict": "bool",
    "network.trust": "array",
```

If the schema test's "every declared key is emitted" check runs on a fleet
with no network items, the `[]` paths are not checked against it. That is
the documented behaviour for array element fields. Confirm by reading the
test at `tests/test_actualis.py` (class around line 1199). If it does build
a fleet that should exercise the paths, extend that fleet with one `curl`
command.

`docs/json.md`:
- add a top-level table row:
  `` | `network` | downloads and fetches the agents made, with approval. See [network](#network) | ``
- add a `## network` section before `## Compatibility`. It needs:
  - a table of the keys above with one-line meanings;
  - the approval values;
  - a sentence that `unknown` means "default mode, where an allowlist rule
    may have approved it without asking";
  - the cap;
  - that URLs are redacted unless `--no-redact`;
  - `verify: actualis --json | jq '.network.totals'`.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS, including the two schema-freeze tests in
`tests/test_actualis.py`.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_network.py docs/json.md
git commit -m "feat(network): --json network key, schema and docs"
```

---

### Task 5: NETWORK report section, `--explain network`, leak tests

**Files:**
- Modify: `actualis.py`:
  - add `render_network` before `render` (search
    `def render(fleet: Fleet, c: C`);
  - call it in `render` directly before
    `if not bash_only:\n        render_coach(coach(fleet), c)`;
  - add an `EXPLAIN["network"]` entry (search `"cache": {` inside `EXPLAIN`).
- Modify: `tests/test_actualis.py` (`TestShareLeakage`) and
  `tests/test_card.py` (`TestCardLeaksNothing`), as in Step 1.
- Test: `tests/test_network.py`

**Interfaces:**
- Consumes: `network_json(fleet, raw)` (Task 4), `rule(c, title)`, `C`,
  `num()`, `clip()` and `redact()`.
- Produces: `render_network(fleet: Fleet, c: C, top: int, raw: bool = False) -> None`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_network.py`:

```python
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

    def test_explain_topic(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = af.render_explain("network", af.C(False))
        self.assertEqual(rc, 0)
        self.assertIn("unknown", buf.getvalue())
```

In `tests/test_actualis.py` `TestShareLeakage`, add a method. Read
`_share_output` first and copy how it builds and renders:

```python
    def test_network_data_never_reaches_share(self):
        f = af.Fleet()
        f.add_tool("leaky-project", "Bash", {"command": "curl https://leaky-host.example/secret-path"},
                   datetime(2026, 10, 1, tzinfo=timezone.utc), "auto")
        f.add_tool("leaky-project", "WebFetch", {"url": "https://other-leak.example/x"},
                   datetime(2026, 10, 1, tzinfo=timezone.utc), "auto")
        buf = io.StringIO()
        with redirect_stdout(buf):
            af.render_share(f, af.C(False))
        out = buf.getvalue()
        for needle in ("leaky-host", "secret-path", "other-leak", "leaky-project"):
            self.assertNotIn(needle, out)
```

Add any imports this needs (`io`, `redirect_stdout`, `datetime`,
`timezone`) only if `tests/test_actualis.py` lacks them.

In `tests/test_card.py` `TestCardLeaksNothing`, add a method that builds the
same fleet and asserts none of the needles appear in
`json.dumps(af.card_model(f, mode))` for every card mode the class already
iterates. Read the class first and reuse its mode list and the
fleet-building helper. If `card_model` raises `CardError` on a fleet with
no usage, add one usage record the way `_fleet()` does.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_network -v`
Expected: `TestReport` ERROR with `no attribute 'render_network'`, and the
explain test returns 1. The two leak tests should already PASS, since share
and card read no network data. They are guards, and stay in.

- [ ] **Step 3: Implement**

```python
def render_network(fleet: Fleet, c: C, top: int, raw: bool = False) -> None:
    """NETWORK: what came in, and from where; unasked first."""
    n = network_json(fleet, raw)
    t = n["totals"]
    rule(c, "NETWORK")
    if not t["items"]:
        print(f"  {c.dim}no downloads seen{c.off}")
        return
    print(f"  {num(t['items'])} downloads · {c.yellow}{num(t['unasked'])} unasked{c.off}"
          f" · {num(t['unknown'])} unknown"
          + (f" · {num(t['failed'])} failed" if t["failed"] else ""))
    if t["unknown"]:
        print(f"  {c.dim}unknown = default mode, where an allowlist rule may have approved it "
              f"without asking{c.off}")
    items = fleet.network_items

    eco = Counter(i["ecosystem"] for i in items if i["kind"] == "install" and i["ecosystem"])
    unpinned = sum(1 for p in n["packages"] if not p["pinned"])
    if eco:
        parts = " · ".join(f"{k} {num(v)}" for k, v in sorted(eco.items(), key=lambda kv: (-kv[1], kv[0])))
        print(f"  {'INSTALLED':<11} {parts}"
              + (f"   {c.dim}{num(unpinned)} unpinned package(s){c.off}" if unpinned else ""))

    clones = Counter(i["host"] or "(remote name)" for i in items if i["kind"] == "clone")
    if clones:
        parts = " · ".join(f"{h} {num(v)}" for h, v in sorted(clones.items(), key=lambda kv: (-kv[1], kv[0]))[:top])
        print(f"  {'CLONED':<11} {num(sum(clones.values()))}   {parts}")

    fetches = [i for i in items if i["kind"] in ("fetch", "search")]
    if fetches:
        fhosts = {i["host"] for i in fetches if i["host"]}
        print(f"  {'FETCHED':<11} {num(len(fetches))}   {num(len(fhosts))} host(s)")

    rows = [i for i in n["items"] if i["approval"] in ("unasked", "unknown")]
    rows.sort(key=lambda i: (i["approval"] != "unasked", ), )   # stable: keeps newest-first within each
    for k, i in enumerate(rows[:top]):
        label = "UNASKED" if k == 0 else ""
        what = i["url"] or i["package"] or i["program"]
        print(f"  {label:<11} {clip(i['host'] or '?', 28):<28} {clip(i['program'] + ' ' + (what or ''), 40):<40}"
              f" {c.dim}{clip(i['project'], 16)}  {(i['ts'] or '')[:10]}  {i['approval']}{c.off}")
```

`n["items"]` is already redacted unless `raw`, so `what` is safe to print.
Check `clip`'s signature (search `def clip(`). If it is `clip(s, n)`, this
matches; otherwise adapt the calls, not the behaviour.

In `render`, directly before `if not bash_only:` /
`render_coach(coach(fleet), c)`:

```python
    render_network(fleet, c, top, raw)
```

`EXPLAIN["network"]` entry. Insert it in alphabetical position among the
topics, if the dict is ordered that way; otherwise put it after `"cache"`:

```python
    "network": {
        "measures": "Downloads and fetches the agents made, and whether a person approved each.",
        "formula": [
            "Shell commands are split on && || ; | and newlines (outside quotes), with",
            "$(...), backticks and bash -c \"...\" read as commands of their own. Prefixes",
            "(sudo, env, time, nice, nohup, VAR=value) are skipped. Recognised programs:",
            "curl wget git gh npm pnpm yarn bun npx bunx pip pip3 uv uvx pipx brew cargo",
            "go docker podman. Tool calls: WebFetch, WebSearch, web_fetch, web_search,",
            "and any tool named like fetch/browse/download/http.",
            "",
            "approval  asked    Copilot asked the person before the call",
            "          unasked  the call ran in auto or bypass mode, Codex 'never', or a",
            "                   Copilot standing rule",
            "          unknown  default mode: an allowlist rule may have approved it",
            "                   without asking; the transcript does not say",
            "",
            "--network-strict makes each untrusted, unasked or unknown, not-failed",
            "(program, host) group a medium finding. --network-trust HOST[/PATH] and",
            "./.actualis-network-trust list trusted sources: host suffix on a label",
            "boundary, path prefix on a segment boundary.",
        ],
        "assumes": [
            "Only what the transcript shows. Downloads inside a script, a Makefile, an",
            "npm script or a postinstall hook are out of sight and not guessed at.",
            "A registry install with no URL is attributed to the ecosystem's default",
            "registry (host_inferred: true). Failed is known for Claude Code only.",
        ],
        "verify": "actualis --json | jq '.network.totals, .network.hosts[:5]'",
    },
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS. If a whole-report snapshot or length test in
`tests/test_actualis.py` changes because the new section prints on a fleet
with commands, update that expectation in the same commit, and say so in
the commit message.

- [ ] **Step 5: Commit**

```bash
git add actualis.py tests/test_network.py tests/test_actualis.py tests/test_card.py
git commit -m "feat(network): NETWORK report section, --explain network, leak guards"
```

---

### Task 6: Action inputs, CHANGELOG, README

**Files:**
- Modify: `action.yml`
- Modify: `CHANGELOG.md` (the `Unreleased` section; create it at the top in
  the file's existing style if it is absent)
- Modify: `README.md`: one bullet in "What it finds that you probably don't
  know"
- Test: `tests/test_action.py`

**Interfaces:**
- Consumes: the CLI flags `--network-trust` and `--network-strict` (Task 3).
- Produces: Action inputs `network-strict` (default `"false"`) and
  `network-trust` (default `""`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_action.py`. Read the file first, and reuse how it loads
`action.yml` (as text). Write this as a text-level check, in the file's
style:

```python
    def test_network_inputs_reach_both_runs(self):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        for needle in ("network-strict:", "network-trust:",
                       "NETWORK_STRICT: ${{ inputs.network-strict }}",
                       "NETWORK_TRUST: ${{ inputs.network-trust }}"):
            self.assertIn(needle, text)
        self.assertEqual(text.count('net_args+=(--network-strict)'), 1)
        self.assertIn('actualis --ci-log "${EXECUTION_FILE}" "${net_args[@]}" --json', text)
```

If `ROOT` is not defined in `tests/test_action.py`, use whatever path
constant it uses for `action.yml`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_action -v`
Expected: FAIL on `network-strict:` not found.

- [ ] **Step 3: Implement**

`action.yml` inputs, after `fail-on`:

```yaml
  network-strict:
    description: >-
      "true" makes every download the agent made without asking, from a source
      not in network-trust or .actualis-network-trust, a medium finding (which
      fail-on: any then fails on).
    required: false
    default: "false"
  network-trust:
    description: >-
      Comma-separated trusted download sources, host or host/path
      (e.g. "npmjs.org,github.com/your-org"). Added to .actualis-network-trust.
    required: false
    default: ""
```

On the `Audit the agent session` step, add to `env:`:

```yaml
          NETWORK_STRICT: ${{ inputs.network-strict }}
          NETWORK_TRUST: ${{ inputs.network-trust }}
```

In its `run:` script, directly after
`args=(--ci-log "${EXECUTION_FILE}")`:

```bash
          net_args=()
          [ "${NETWORK_STRICT}" = "true" ] && net_args+=(--network-strict)
          [ -n "${NETWORK_TRUST}" ] && net_args+=(--network-trust "${NETWORK_TRUST}")
          args+=("${net_args[@]}")
```

Then change the JSON run line to:

```bash
          actualis --ci-log "${EXECUTION_FILE}" "${net_args[@]}" --json > "${work}/report.json" 2>/dev/null || true
```

The `run:` block above uses 10-space indentation. Match the indentation the
file actually uses. Under `set -u`, an empty array expansion
`"${net_args[@]}"` errors on bash older than 4.4. If the script sets `-u`,
write `${net_args[@]+"${net_args[@]}"}` in both places, and change the
test's last needle to match.

Do not put `${{ }}` in comments. `tests/test_action.py` rejects empty or
unclosed expressions anywhere in the file.

`CHANGELOG.md`, under `Unreleased` → `Added`:

```markdown
- **Network inventory.** A NETWORK section and a `network` key in `--json` list
  every download and fetch the agents made — packages installed, repos cloned,
  URLs fetched — and whether a person approved each (`asked`, `unasked`, or
  `unknown` in default mode, where an allowlist rule may have allowed it
  silently). `--network-strict` turns unasked downloads from sources not in
  `--network-trust` / `.actualis-network-trust` into medium findings. The
  Action gains `network-strict` and `network-trust` inputs. `schema_version`
  stays 1.
```

`README.md`, add a bullet after the "Every command the agent ran" bullet:

```markdown
- **What it downloaded, and whether anyone asked.** Packages installed, repos
  cloned, URLs fetched — each marked asked, unasked, or unknown — and, with
  `--network-strict`, a finding for every unasked download from a source you
  have not trusted.
```

- [ ] **Step 4: Run all tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS.

Then run a smoke check on a synthetic fleet, with no real transcripts:

```bash
T=$(mktemp -d) && mkdir -p "$T/-Users-x-proj" && printf '%s\n' \
'{"timestamp":"2026-10-01T10:00:00Z","type":"assistant","permissionMode":"auto","sessionId":"s","message":{"id":"m","role":"assistant","content":[{"type":"tool_use","id":"t","name":"Bash","input":{"command":"npm i lodash && curl -o x https://a.io/x"}}]}}' \
> "$T/-Users-x-proj/s.jsonl" && python3 actualis.py --root "$T" --days 3650 --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["network"]["totals"])' \
&& python3 actualis.py --root "$T" --days 3650 --network-strict --fail-on any >/dev/null; echo "exit $?"
```

Expected: totals show `items: 2, unasked: 2`, and the exit is `3`
(findings). If `--root` takes a different form, check `--help` and adapt
the flag; the expectation does not change.

- [ ] **Step 5: Commit**

```bash
git add action.yml tests/test_action.py CHANGELOG.md README.md
git commit -m "feat(network): Action inputs, changelog, README"
```
