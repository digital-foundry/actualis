"""The Claude Code plugin: manifests, skill and command stay valid and in step with the CLI."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
SKILL = PLUGIN / "skills" / "actualis" / "SKILL.md"
COMMAND = PLUGIN / "commands" / "actualis.md"


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


af = _load("actualis")
rep = _load("actualis_reputation")


def _frontmatter(path: Path) -> dict:
    m = re.match(r"---\n(.*?)\n---\n", path.read_text(encoding="utf-8"), re.S)
    assert m, f"{path} has no frontmatter"
    out = {}
    for line in m.group(1).splitlines():
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _flags(parser) -> set:
    return {s for a in parser._actions for s in a.option_strings}


class PluginTests(unittest.TestCase):
    def test_manifests_parse_and_marketplace_source_exists(self):
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertTrue(market["name"] and market["owner"]["name"])
        names = []
        for p in market["plugins"]:
            names.append(p["name"])
            src = ROOT / p["source"]
            self.assertTrue((src / ".claude-plugin" / "plugin.json").is_file(), p["source"])
        self.assertEqual(names, ["actualis"])
        manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "actualis")
        self.assertEqual(manifest["author"]["name"], "Digital Foundry")

    def test_plugin_version_matches_cli(self):
        manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["version"], af.__version__,
                         "bump plugin/.claude-plugin/plugin.json with __version__")

    def test_frontmatter_keys(self):
        skill = _frontmatter(SKILL)
        self.assertEqual(skill["name"], "actualis")
        self.assertGreater(len(skill["description"]), 40)
        self.assertLess(len(SKILL.read_text().splitlines()), 200)
        self.assertTrue(_frontmatter(COMMAND)["description"])

    def test_every_flag_mentioned_exists(self):
        known = _flags(af.build_parser()) | _flags(rep.build_parser())
        for path in (SKILL, COMMAND):
            text = path.read_text(encoding="utf-8")
            body = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.S)
            for flag in set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", body + text)):
                self.assertIn(flag, known, f"{path.name} mentions unknown flag {flag}")


if __name__ == "__main__":
    unittest.main()
