"""Review r3: findings from the third pass. Every fixture is synthetic."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fixtures  # noqa: E402,F401  (first: a temp HOME, agent homes and cwd for the whole run)
from test_review_r2_X import af, ioc_gate  # noqa: E402


def packages(cmd: str) -> list:
    items, _ = af.network_items_from_command(cmd)
    return [i.get("package") for i in items]


class TestLegacyArithmetic(unittest.TestCase):
    """`$[ … ]` is bash's legacy arithmetic, like `$(( ))`: a `<<` inside it is
    a shift, never a heredoc, so the lines after it are still commands."""

    def test_shift_in_legacy_arithmetic_opens_no_heredoc(self):
        self.assertEqual(packages("echo $[1<<EOF]\nnpm i left-pad\nEOF]\n"), ["left-pad"])

    def test_inside_double_quotes_and_nested_brackets(self):
        self.assertEqual(packages('echo "$[1<<EOF]"\nnpm i left-pad\n'), ["left-pad"])
        self.assertEqual(packages("echo $[a[1]<<2]\nnpm i left-pad\n"), ["left-pad"])

    def test_plain_legacy_arithmetic_unchanged(self):
        self.assertEqual(packages("echo $[1+2]\nnpm i left-pad\n"), ["left-pad"])

    def test_gate_sees_the_install(self):
        code, _ = ioc_gate("echo $[1<<EOF]\nnpm i evil@1.0.0\nEOF]")
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
