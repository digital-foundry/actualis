"""The GitHub Action and the workflows must at least load.

GitHub evaluates every `${{ ... }}` in a workflow or action file before any
step runs -- inside `run:` blocks and inside shell comments alike. An empty or
unclosed one makes the whole file invalid ("An expression was expected"), and
the action self-test only runs after a release, so v0.2.0 shipped an action
that could not load because a comment explaining the problem contained `${{ }}`.

    python3 -m unittest discover -s tests -v
"""

import re
import shutil
import sys
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

    def test_network_inputs_reach_both_runs(self):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        for needle in ("network-strict:", "network-trust:",
                       "NETWORK_STRICT: ${{ inputs.network-strict }}",
                       "NETWORK_TRUST: ${{ inputs.network-trust }}"):
            self.assertIn(needle, text)
        self.assertEqual(text.count('net_args+=(--network-strict)'), 1)
        # The audit script runs under `set -u`, where expanding an empty array
        # errors on bash older than 4.4, so both uses are guarded.
        guarded = '${net_args[@]+"${net_args[@]}"}'
        self.assertIn("set -uo pipefail", text)
        self.assertEqual(text.count(guarded), 2)
        self.assertIn(f'actualis --ci-log "${{EXECUTION_FILE}}" {guarded} --json', text)

    def test_a_broken_run_warns_even_without_the_gate(self):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn('echo "::warning::actualis could not complete the audit (exit ${rc})"', text)
        self.assertLess(text.index("::warning::actualis could not complete"),
                        text.index('echo "exit-code=${rc}"'))
        outputs = text[text.index("outputs:"):text.index("runs:")]
        self.assertIn("2 a usage error", outputs)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("`2` usage error", readme)
        inputs = re.findall(r"^  ([a-z-]+):\n    description", text[:text.index("outputs:")], re.M)
        self.assertEqual(len(inputs), 8)
        for name in inputs:
            self.assertIn(f"| `{name}` |", readme)

    def test_ioc_input_reaches_both_runs(self):                         # T-ACT-1
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("  ioc:\n    description:", text)
        self.assertIn("IOC: ${{ inputs.ioc }}", text)
        self.assertIn('net_args+=(--ioc "${ioc_path}")', text)
        self.assertIn('done <<< "${IOC}"', text)
        # net_args feeds both the gating run and the --json run.
        self.assertLess(text.index("net_args+=(--ioc"), text.index('args+=(${net_args[@]+"${net_args[@]}"})'))
        self.assertEqual(text.count('${net_args[@]+"${net_args[@]}"}'), 2)

    def test_ioc_matches_output(self):                                  # T-ACT-1
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        outputs = text[text.index("outputs:"):text.index("runs:")]
        self.assertIn("ioc-matches:", outputs)
        self.assertIn("value: ${{ steps.audit.outputs.ioc-matches }}", outputs)
        self.assertIn('echo "ioc-matches=${ioc_matches}" >> "$GITHUB_OUTPUT"', text)
        self.assertIn("r.get('verdict') == 'match' and not r.get('refused') and not r.get('suppressed')", text)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("| `ioc-matches` |", readme)

    def test_ioc_warns_under_the_critical_default(self):               # T-ACT-1
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn('[ "${FAIL_ON}" = "critical" ]', text)
        self.assertIn('echo "::warning::IOC matches are high severity; set fail-on: high to gate on them"', text)

    @unittest.skipIf(sys.platform == "win32" or not shutil.which("bash"), "needs bash on PATH")
    def test_the_ioc_loop_runs_in_bash(self):
        """The input loop, run for real: blank lines and padding dropped, a comma kept."""
        import subprocess
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        start = text.index("        while IFS= read -r ioc_path; do")
        end = text.index('        done <<< "${IOC}"') + len('        done <<< "${IOC}"')
        script = "net_args=()\n" + text[start:end] + '\nprintf "%s|" "${net_args[@]}"'
        out = subprocess.run(["bash", "-c", script], env={"IOC": "  /a/x.txt  \n\n/b/y,z.jsonl\n", "PATH": "/usr/bin:/bin"},
                             capture_output=True, text=True)
        self.assertEqual(out.stdout, "--ioc|/a/x.txt|--ioc|/b/y,z.jsonl|")

    def test_the_checker_catches_what_broke_v0_2_0(self):
        bad = "          # a run: block interpolates ${{ }} inside"
        self.assertNotEqual(len(OPEN.findall(bad)), len(COMPLETE.findall(bad)))
        self.assertEqual(len(OPEN.findall("x: ${{ inputs.version }}")),
                         len(COMPLETE.findall("x: ${{ inputs.version }}")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
