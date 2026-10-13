"""--network --html: one self-contained page. Everything escaped, nothing
fetched, the embedded JSON equal to --network --json. All synthetic."""
from __future__ import annotations

import base64
import hashlib
import html.parser
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if "actualis" in sys.modules:
    af = sys.modules["actualis"]
else:
    spec = importlib.util.spec_from_file_location("actualis", ROOT / "actualis.py")
    af = importlib.util.module_from_spec(spec)
    sys.modules["actualis"] = af
    spec.loader.exec_module(af)


class TestShares(unittest.TestCase):
    def test_shares_add_up_and_floor_non_zero(self):
        self.assertEqual(af._net_shares([1, 1000, 0], 20), [1, 19, 0])
        self.assertEqual(sum(af._net_shares([3, 5, 7], 1000)), 1000)
        self.assertEqual(af._net_shares([0, 0, 0], 10), [0, 0, 0])

    def test_terminal_bar_uses_the_same_shares(self):
        t = {"unasked": 7, "unknown": 2, "asked": 1}
        bar = af._net_approval_bar(t, 30)
        cells = af._net_shares([7, 2, 1], 30)
        self.assertEqual([bar.count("\u2588"), bar.count("\u2592"), bar.count("\u2591")], cells)
