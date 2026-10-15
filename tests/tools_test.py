#!/usr/bin/env python3
"""Tests for the rule-quality tools (tools/rule_mutation.py, tools/fp_sweep.py). Run: python3 tests/tools_test.py"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


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

    def test_repeated_element_keeps_its_id_when_a_branch_is_inserted(self):
        doc = {"rules": [{"id": "r", "pattern-either": [
            {"patterns": [{"pattern": "f($X)"}, {"pattern-not": "f(1)"}]},
            {"patterns": [{"pattern": "g($X)"}, {"pattern-not": "f(1)"}]}]}]}
        before = {mid for mid, _, _ in rm.mutants(doc)}
        doc["rules"][0]["pattern-either"].insert(0, {"patterns": [{"pattern": "h($X)"}, {"pattern-not": "f(1)"}]})
        doc["rules"][0]["pattern-either"].reverse()
        after = {mid for mid, _, _ in rm.mutants(doc)}
        self.assertTrue(before <= after, sorted(before - after))

    def test_identical_inner_lists_in_different_outer_branches_keep_ids(self):
        inner = {"pattern-either": [{"pattern": "a == b"}, {"pattern": "a != b"}]}
        doc = {"rules": [{"id": "r", "pattern-either": [
            {"patterns": [inner, {"pattern-inside": "def f(): ..."}]},
            {"patterns": [inner, {"pattern-inside": "def g(): ..."}]}]}]}
        before = {mid for mid, _, _ in rm.mutants(doc)}
        doc["rules"][0]["pattern-either"].reverse()
        after = {mid for mid, _, _ in rm.mutants(doc)}
        self.assertEqual(before, after)
        self.assertFalse(any("#" in m for m in before), sorted(before))

    def test_identical_elements_get_distinct_ids(self):
        doc = json.loads(json.dumps(RULE))
        doc["rules"][0]["pattern-either"].append({"pattern": "a(...)"})
        ids = [mid for mid, _, _ in rm.mutants(doc)]
        self.assertEqual(len(ids), len(set(ids)))


class Aliases(unittest.TestCase):
    def test_a_mutant_deletes_one_alias_occurrence_only(self):
        doc = yaml.safe_load("rules:\n- id: a\n  patterns:\n  - pattern-either: &x\n    - pattern: f(1)\n    - pattern: f(2)\n"
                             "  - pattern-not-inside:\n      pattern-either: *x\n")
        for _, _, m in rm.mutants(doc):
            pats = m["rules"][0]["patterns"]
            kept = [len(p["pattern-either"]) for p in pats if "pattern-either" in p] + \
                   [len(p["pattern-not-inside"]["pattern-either"]) for p in pats if "pattern-not-inside" in p]
            self.assertIn(2, kept, "a deletion removed the element from both alias occurrences")


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


class EngineExit(unittest.TestCase):
    def test_nonzero_exit_with_json_is_an_engine_failure(self):
        with tempfile.TemporaryDirectory() as td:
            eng = Path(td) / "opengrep"
            eng.write_text('#!/bin/sh\necho \'{"results": [], "errors": []}\'\nexit 2\n')
            eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
            _, fails = rules_test.rule_failures(str(eng), rm.RULES / "js" / "code-eval.yaml")
        self.assertTrue(fails and all(rules_test.ENGINE_FAILED in f for f in fails), fails)


class BatchedMutants(unittest.TestCase):
    RULE = rm.RULES / "js" / "code-eval.yaml"

    def test_a_batch_that_fails_is_split_until_each_mutant_runs_alone(self):
        muts = rm.mutants(yaml.safe_load(self.RULE.read_text()))[:3]
        with tempfile.TemporaryDirectory() as td:
            eng, log = Path(td) / "opengrep", Path(td) / "calls"
            # rejects any config holding more than one rule; a single rule scans cleanly and finds nothing
            eng.write_text('#!/bin/sh\nprev=""\nfor a; do [ "$prev" = --config ] && conf="$a"; prev="$a"; done\n'
                           f'n=$(grep -c "^- " "$conf")\necho "$n" >> "{log}"\n'
                           'if [ "$n" -gt 1 ]; then exit 7; fi\necho \'{"results": [], "errors": []}\'\n')
            eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
            got = rm.batch_failures(str(eng), self.RULE, muts)
            alone = [rules_test.rule_failures(str(eng), self.RULE, yaml.safe_dump(m, sort_keys=False))[1]
                     for _, _, m in muts]
            sizes = log.read_text().split()
        self.assertEqual(got, alone)
        self.assertEqual(sizes[:5], ["3", "1", "2", "1", "1"])   # 3 fails -> [1] alone, [2] fails -> two alone

    def test_mutants_the_engine_rejects_are_predicted(self):
        doc = {"rules": [{"id": "r", "patterns": [{"pattern-inside": "f(...)"}, {"pattern-not": "f(1)"}]},
                         {"id": "s", "pattern-either": [{"pattern": "a"}]}]}
        rejected = {el for _, el, m in rm.mutants(doc) if rm.likely_rejected(m)}
        # deleting the only positive element, or emptying a list, leaves a rule the engine rejects
        self.assertEqual(rejected, {"pattern-inside: f(...)", "pattern: a"})

    @unittest.skipUnless(os.environ.get("OPENGREP"), "set OPENGREP to the engine to compare with the real engine")
    def test_batched_results_equal_one_scan_per_mutant(self):
        eng = os.environ["OPENGREP"]
        muts = rm.mutants(yaml.safe_load(self.RULE.read_text()))[:12]
        alone = [rules_test.rule_failures(eng, self.RULE, yaml.safe_dump(m, sort_keys=False))[1] for _, _, m in muts]
        got = rm.batch_failures(eng, self.RULE, muts)
        self.assertEqual([bool(f) for f in got], [bool(f) for f in alone])
        self.assertTrue(any(alone) and not all(alone), "pick mutants with both outcomes")


class FpReport(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.work = Path(self.td.name)
        self.f = [{"repo": "o/a", "rule": "r1", "path": "x.js", "line": 3},
                  {"repo": "o/b", "rule": "r1", "path": "y.js", "line": 9}]
        self.corpus = [{"repo": r, "sha": "0" * 40} for r in ("o/a", "o/b", "o/c", "o/d")]
        cur = ["0" * 40, fp_sweep.rules_digest()]
        for f in self.f:
            f.update(sha=cur[0], rules=cur[1])
        (self.work / "findings.json").write_text(json.dumps(self.f))
        (self.work / "scanned.json").write_text(json.dumps({"o/a": cur, "o/b": cur, "o/c": cur}))

    def tearDown(self):
        self.td.cleanup()

    def lab(self, *labels):
        return [{**f, "label": lab} for f, lab in zip(self.f, labels)]

    def test_counts_per_rule_and_fp_repos(self):
        rep = fp_sweep.report(self.work, self.lab("fp", "tp_test"), self.corpus)
        self.assertEqual(rep["rules"]["r1"]["fp_by_repo"], {"o/a": 1})
        self.assertEqual((rep["rules"]["r1"]["correct"], rep["rules"]["r1"]["noise"]), (1, 0.5))
        self.assertEqual([c["repo"] for c in rep["corpus"]], ["o/a", "o/b", "o/c"])   # o/d was never scanned

    def test_findings_from_another_commit_or_rule_bundle_are_excluded(self):
        stale = {"repo": "o/c", "rule": "r1", "path": "z.js", "line": 1, "sha": "1" * 40, "rules": "old"}
        (self.work / "findings.json").write_text(json.dumps(self.f + [stale]))
        rep = fp_sweep.report(self.work, self.lab("fp", "tp") + [{**stale, "label": "fp"}], self.corpus)
        self.assertEqual(rep["stale_findings_excluded"], 1)
        self.assertEqual(rep["rules"]["r1"]["fp"], 1)

    def test_a_true_positive_is_never_tied_to_a_repository(self):
        rep = fp_sweep.report(self.work, self.lab("tp", "tp"), self.corpus)
        text = json.dumps(rep["rules"])
        self.assertNotIn('"tp"', text)
        self.assertEqual(rep["rules"]["r1"]["fp_by_repo"], {})

    def test_two_findings_on_one_line_are_labelled_by_id(self):
        other = {**self.f[0], "message": "second finding on the same line"}
        (self.work / "findings.json").write_text(json.dumps(self.f + [other]))
        with self.assertRaises(ValueError):   # a location-only label is ambiguous here
            fp_sweep.report(self.work, self.lab("fp", "tp") + [{**self.f[0], "label": "fp"}], self.corpus)
        ids = [{**x, "id": fp_sweep.finding_id(x), "label": "fp"} for x in self.f + [other]]
        with self.assertRaises(ValueError):   # the same id twice and one finding left out
            fp_sweep.report(self.work, [ids[0], ids[0], ids[1]], self.corpus)
        self.assertEqual(fp_sweep.report(self.work, ids, self.corpus)["rules"]["r1"]["fp"], 3)

    def test_a_label_with_the_id_of_a_stale_finding_is_skipped(self):
        stale = {"repo": "o/a", "rule": "r1", "path": "old.js", "line": 5, "sha": "1" * 40, "rules": "old"}
        (self.work / "findings.json").write_text(json.dumps(self.f + [stale]))
        labels = [{**x, "id": fp_sweep.finding_id(x), "label": "fp"} for x in self.f + [stale]]
        self.assertEqual(fp_sweep.report(self.work, labels, self.corpus)["rules"]["r1"]["fp"], 2)

    def test_an_unreadable_engine_version_is_an_error_not_an_empty_digest(self):
        with tempfile.TemporaryDirectory() as td:
            eng = Path(td) / "opengrep"
            for body in ("exit 1", "exit 0", "echo 1.30.2; exit 3"):
                eng.write_text(f"#!/bin/sh\n{body}\n")
                eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
                path = os.environ["PATH"]
                os.environ["PATH"] = f"{td}{os.pathsep}{path}"
                try:
                    with self.assertRaises(ValueError, msg=body):
                        fp_sweep.rules_digest()
                finally:
                    os.environ["PATH"] = path

    def test_a_label_with_another_findings_id_is_refused(self):
        ids = [{**x, "id": fp_sweep.finding_id(x), "label": "fp"} for x in self.f]
        swapped = [{**ids[0], "id": ids[1]["id"]}, {**ids[1], "id": ids[0]["id"]}]
        with self.assertRaises(ValueError):
            fp_sweep.report(self.work, swapped, self.corpus)

    def test_unknown_repo_filter_is_refused(self):
        argv = sys.argv
        sys.argv = ["fp_sweep", "--work", str(self.work), "--repos", "no/such-repo"]
        try:
            self.assertEqual(fp_sweep.main(), 2)
        finally:
            sys.argv = argv

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
