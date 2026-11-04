#!/usr/bin/env python3
"""Supply-chain pins in action.yml. Run: python3 tests/action_pins_test.py"""
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
STEPS = ACTION["runs"]["steps"]


class ActionPins(unittest.TestCase):
    def test_go_version_is_exact(self):
        versions = [s["with"]["go-version"] for s in STEPS if str(s.get("uses", "")).startswith("actions/setup-go@")]
        self.assertTrue(versions, "no setup-go step")
        for v in versions:
            self.assertRegex(str(v), r"^\d+\.\d+\.\d+$", f"go-version must be exact x.y.z, got {v!r}")

    def test_pip_install_is_hash_locked(self):
        run = next(s["run"] for s in STEPS if "pip install" in s.get("run", ""))
        line = next(l for l in run.splitlines() if "pip install" in l)
        self.assertIn("--require-hashes", line)
        m = re.search(r'-r "?\$GITHUB_ACTION_PATH/([\w./-]+)"?', line)
        self.assertTrue(m, "pip install must read a committed requirements file")
        reqs = (ROOT / m.group(1)).read_text()
        self.assertIn("-I", line.split("pip")[0].split(), "keep python -I")
        entries = re.findall(r"^(?!#)(\S+==\S+) \\\n((?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n?)+)", reqs, re.M)
        names = {e[0].split("==")[0] for e in entries}
        self.assertEqual(names, {"ruff", "zizmor", "pyyaml"}, "requirements file must pin and hash all three")
        # every requirement line has hashes: no bare pins
        pins = re.findall(r"^[A-Za-z][\w.-]*==", reqs, re.M)
        self.assertEqual(len(pins), len(entries), "a requirement has no hashes")

    def test_sarif_retention_is_an_input(self):
        self.assertEqual(ACTION["inputs"]["sarif-retention-days"]["default"], "90")
        up = next(s for s in STEPS if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
        self.assertEqual(up["with"]["retention-days"], "${{ inputs.sarif-retention-days }}")


if __name__ == "__main__":
    unittest.main()
