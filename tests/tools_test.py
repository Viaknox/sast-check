#!/usr/bin/env python3
"""Tests for the rule-quality tools (tools/rule_mutation.py, tools/fp_sweep.py). Run: python3 tests/tools_test.py"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import fp_sweep  # noqa: E402
import rule_mutation as rm  # noqa: E402
import rules_test  # noqa: E402

RULE = {"rules": [{"id": "sast.x.r", "languages": ["python"], "message": "m", "severity": "ERROR",
                   "pattern-either": [{"pattern": "a(...)"}, {"patterns": [{"pattern": "b($X)"},
                                                                          {"pattern-not": "b(1)"}]}]}]}


class ChangedRules(unittest.TestCase):
    def test_test_yml_fixture_maps_to_its_rule(self):
        got = rm.changed_rules(["rules/custom/gha/remote-fetch-no-checksum.test.yml"])
        self.assertEqual(got, [rm.RULES / "gha" / "remote-fetch-no-checksum.yaml"])

    def test_test_yaml_fixture_is_not_taken_for_a_rule(self):
        got = rm.changed_rules(["rules/custom/k8s/ingress-nginx-vulnerable.test.yaml"])
        self.assertEqual(got, [rm.RULES / "k8s" / "ingress-nginx-vulnerable.yaml"])

    def test_code_fixture_and_rule(self):
        got = rm.changed_rules(["rules/custom/js/code-eval.js", "rules/custom/js/ssrf.yaml", "README.md"])
        self.assertEqual(got, [rm.RULES / "js" / "code-eval.yaml", rm.RULES / "js" / "ssrf.yaml"])


class MutantIds(unittest.TestCase):
    def test_ids_survive_a_new_sibling_branch(self):
        before = {mid for mid, _, _ in rm.mutants(RULE)}
        doc = json.loads(json.dumps(RULE))
        doc["rules"][0]["pattern-either"].insert(0, {"pattern": "c(...)"})
        after = {mid for mid, _, _ in rm.mutants(doc)}
        self.assertTrue(before <= after, sorted(before - after))

    def test_identical_elements_get_distinct_ids(self):
        doc = json.loads(json.dumps(RULE))
        doc["rules"][0]["pattern-either"].append({"pattern": "a(...)"})
        ids = [mid for mid, _, _ in rm.mutants(doc)]
        self.assertEqual(len(ids), len(set(ids)))


class BaselineReason(unittest.TestCase):
    def test_only_a_written_reason_counts(self):
        for entry in ({}, {"why": ""}, {"why": "  "}, {"why": "TODO: add a fixture line or justify"}, "x", None):
            self.assertEqual(rm.baseline_reason(entry), "", entry)
        self.assertTrue(rm.baseline_reason({"why": "equivalent to the branch above for Opengrep"}))


class EngineFailure(unittest.TestCase):
    def test_no_json_is_an_engine_failure_not_a_fixture_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            eng = Path(td) / "opengrep"
            eng.write_text("#!/bin/sh\nexit 3\n")
            eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
            _, fails = rules_test.rule_failures(str(eng), rm.RULES / "js" / "code-eval.yaml")
        self.assertTrue(fails and all(rules_test.ENGINE_FAILED in f for f in fails), fails)


class FpReport(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.work = Path(self.td.name)
        self.f = [{"repo": "o/a", "rule": "r1", "path": "x.js", "line": 3},
                  {"repo": "o/b", "rule": "r1", "path": "y.js", "line": 9}]
        (self.work / "findings.json").write_text(json.dumps(self.f))
        (self.work / "scanned.json").write_text(json.dumps(["o/a", "o/b", "o/c"]))
        self.corpus = [{"repo": r, "sha": "0" * 40} for r in ("o/a", "o/b", "o/c", "o/d")]

    def tearDown(self):
        self.td.cleanup()

    def lab(self, *labels):
        return [{**f, "label": lab} for f, lab in zip(self.f, labels)]

    def test_counts_per_rule_and_repo(self):
        rep = fp_sweep.report(self.work, self.lab("fp", "tp_test"), self.corpus)
        self.assertEqual(rep["rules"]["r1"]["repos"], {"o/a": {"fp": 1}, "o/b": {"tp_test": 1}})
        self.assertEqual(rep["rules"]["r1"]["noise"], 0.5)
        self.assertEqual([c["repo"] for c in rep["corpus"]], ["o/a", "o/b", "o/c"])   # o/d was never scanned

    def test_partial_duplicate_stale_or_unknown_labels_are_refused(self):
        bad = [self.lab("fp"),                                            # a finding without a label
               self.lab("fp", "tp") + self.lab("fp"),                     # labelled twice
               self.lab("fp", "tp") + [{**self.f[0], "line": 99, "label": "fp"}],   # matches no finding
               self.lab("fp", "maybe")]                                   # unknown label
        for labels in bad:
            with self.assertRaises(ValueError):
                fp_sweep.report(self.work, labels, self.corpus)


if __name__ == "__main__":
    os.chdir(ROOT)
    unittest.main(verbosity=1)
