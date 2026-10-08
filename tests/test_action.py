"""The GitHub Action and the workflows must at least load.

GitHub evaluates every `${{ ... }}` in a workflow or action file before any
step runs -- inside `run:` blocks and inside shell comments alike. An empty or
unclosed one makes the whole file invalid ("An expression was expected"), and
the action self-test only runs after a release, so v0.2.0 shipped an action
that could not load because a comment explaining the problem contained `${{ }}`.

    python3 -m unittest discover -s tests -v
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "action.yml", *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]
OPEN = re.compile(r"\$\{\{")
COMPLETE = re.compile(r"\$\{\{\s*[^\s}][^}]*\}\}")


class TestExpressionsAreComplete(unittest.TestCase):

    def test_every_expression_is_closed_and_non_empty(self):
        for path in FILES:
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                opened = len(OPEN.findall(line))
                complete = len(COMPLETE.findall(line))
                with self.subTest(file=path.name, line=n):
                    self.assertEqual(opened, complete,
                                     f"{path.name}:{n} has an empty or unclosed "
                                     f"expression GitHub will refuse to load: {line.strip()}")

    def test_the_checker_catches_what_broke_v0_2_0(self):
        bad = "          # a run: block interpolates ${{ }} inside"
        self.assertNotEqual(len(OPEN.findall(bad)), len(COMPLETE.findall(bad)))
        self.assertEqual(len(OPEN.findall("x: ${{ inputs.version }}")),
                         len(COMPLETE.findall("x: ${{ inputs.version }}")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
