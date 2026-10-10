#!/usr/bin/env python3
"""Print the Homebrew formula for a released version. A maintainer tool, not the CLI.

The formula lives in the tap (github.com/digital-foundry/homebrew-tap,
Formula/actualis.rb). It installs the sdist that PyPI already serves, so brew,
pip and uv all install byte-identical code, and the checksum is PyPI's own.

    python3 tools/brew-formula.py            # latest version on PyPI
    python3 tools/brew-formula.py 0.3.0      # a specific version
    python3 tools/brew-formula.py --offline URL SHA256 VERSION

This is the only part of the release that touches the network, and it only
reads: it fetches PyPI's JSON for the version and prints Ruby to stdout. A human
copies the result into the tap and opens a PR there.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

FORMULA = '''\
class Actualis < Formula
  desc "What actually ran: local, read-only audit of coding-agent transcripts"
  homepage "https://actualis.app"
  url "{url}"
  sha256 "{sha256}"
  license "AGPL-3.0-or-later"

  # Standard library only, so there are no resources to vendor: the formula
  # installs one file and a wrapper that runs it with brew's Python.
  depends_on "python@3.13"

  def install
    libexec.install "actualis.py"
    (bin/"actualis").write <<~SH
      #!/bin/bash
      exec "#{{formula_opt_bin("python@3.13")}}/python3.13" "#{{libexec}}/actualis.py" "$@"
    SH
  end

  test do
    assert_match "actualis {version}", shell_output("#{{bin}}/actualis --version")
    # A fresh HOME has no transcripts: it must say so and exit 1, not crash.
    ENV["HOME"] = testpath
    assert_match "no agent transcripts found", shell_output("#{{bin}}/actualis 2>&1", 1)
  end
end
'''


def from_pypi(version: str | None) -> tuple[str, str, str]:
    path = f"actualis/{version}/json" if version else "actualis/json"
    with urllib.request.urlopen(f"https://pypi.org/pypi/{path}", timeout=30) as r:
        data = json.load(r)
    for f in data["urls"]:
        if f["packagetype"] == "sdist":
            return f["url"], f["digests"]["sha256"], data["info"]["version"]
    sys.exit(f"no sdist on PyPI for actualis {data['info']['version']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?", help="default: latest on PyPI")
    ap.add_argument("--offline", nargs=3, metavar=("URL", "SHA256", "VERSION"))
    a = ap.parse_args()
    url, sha, ver = a.offline if a.offline else from_pypi(a.version)
    sys.stdout.write(FORMULA.format(url=url, sha256=sha, version=ver))
    return 0


if __name__ == "__main__":
    sys.exit(main())
