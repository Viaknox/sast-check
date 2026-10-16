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
import rule_perf  # noqa: E402
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
        # every 10th mutant the engine accepts: a mix of killed and survived on the current rule
        muts = [x for x in rm.mutants(yaml.safe_load(self.RULE.read_text())) if not rm.likely_rejected(x[2])][::10]
        alone = [rules_test.rule_failures(eng, self.RULE, yaml.safe_dump(m, sort_keys=False))[1] for _, _, m in muts]
        got = rm.batch_failures(eng, self.RULE, muts)
        self.assertEqual([bool(f) for f in got], [bool(f) for f in alone])
        self.assertTrue(any(alone) and not all(alone), "pick mutants with both outcomes")


class RulePerf(unittest.TestCase):
    def test_slow_only_when_both_ratio_and_seconds_are_exceeded(self):
        self.assertTrue(rule_perf.too_slow(20.0, 6.0))      # 3.3x and 14 s slower
        self.assertFalse(rule_perf.too_slow(2.0, 1.0))      # 2x but only 1 s: runner noise on a short scan
        self.assertFalse(rule_perf.too_slow(14.0, 10.0))    # 4 s slower but only 1.4x
        self.assertTrue(rule_perf.too_slow(61.0, None))     # a new rule over the cap
        self.assertFalse(rule_perf.too_slow(59.0, None))

    def test_a_failed_scan_is_an_error_not_a_pass(self):
        with tempfile.TemporaryDirectory() as td:
            eng = Path(td) / "opengrep"
            eng.write_text("#!/bin/sh\nexit 7\n")
            eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
            status, detail = rule_perf.check_rule(str(eng), rm.RULES / "js" / "code-eval.yaml", Path(td) / "base")
        self.assertEqual(status, "ERROR", detail)

    def fake_engine(self, td, body):
        eng = Path(td) / "opengrep"
        eng.write_text("#!/bin/sh\nprev=\"\"\nfor a; do [ \"$prev\" = --config ] && conf=\"$a\"; prev=\"$a\"; t=\"$a\"; done\n" + body)
        eng.chmod(eng.stat().st_mode | stat.S_IEXEC)
        return str(eng)

    def test_an_engine_error_in_clean_json_output_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            eng = self.fake_engine(td, 'echo \'{"results": [], "errors": [{"type": "Rule parse error", "message": "bad"}], '
                                       '"paths": {"scanned": ["big.js"]}}\'\n')
            status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", Path(td) / "base")
        self.assertEqual(status, "ERROR", detail)
        self.assertIn("engine error", detail)

    def test_a_base_version_that_skips_the_file_is_not_compared(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base" / "rules" / "custom" / "js"
            base.mkdir(parents=True)
            (base / "code-eval.yaml").write_text("rules: [] # BASEMARK\n")
            # the base version scans nothing (its paths skip the file); the changed version scans it
            eng = self.fake_engine(td, 'if grep -q BASEMARK "$conf"; then s=""; else s="\\"$t\\""; fi\n'
                                       'echo "{\\"results\\": [], \\"errors\\": [], \\"paths\\": {\\"scanned\\": [$s]}}"\n')
            status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", Path(td) / "base")
        self.assertEqual(status, "ok", detail)
        self.assertIn("no comparable base", detail)

    def test_list_prints_no_line_when_no_rule_changed(self):
        import subprocess  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            changed = Path(td) / "changed.txt"
            changed.write_text("README.md\n")
            out = subprocess.run([sys.executable, str(ROOT / "tools" / "rule_perf.py"), "--list", "--changed-files",
                                  str(changed)], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out, "")   # an empty line would make CI fetch the directory itself (PR #18 run)

    def base_and_engine(self, td, body, base_text="rules: [] # BASEMARK\n"):
        """A base version of js/code-eval and a fake engine running BODY ($conf = config, $t = target)."""
        base = Path(td) / "base" / "rules" / "custom" / "js"
        base.mkdir(parents=True)
        (base / "code-eval.yaml").write_text(base_text)
        return Path(td) / "base", self.fake_engine(td, body)

    SCANNED = 'echo "{\\"results\\": [], \\"errors\\": [], \\"paths\\": {\\"scanned\\": [\\"$t\\"]}}"\n'

    def test_a_much_slower_changed_rule_is_slow(self):
        with tempfile.TemporaryDirectory() as td:
            # the base version is instant; the changed version takes 3.5 s (over 1.5x and over 3 s slower)
            base, eng = self.base_and_engine(td, 'grep -q BASEMARK "$conf" || sleep 3.5\n' + self.SCANNED)
            status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", base)
        self.assertEqual(status, "SLOW", detail)

    def test_a_changed_rule_that_never_finishes_is_slow_and_a_base_that_never_finishes_is_an_error(self):
        old = rule_perf.SCAN_TIMEOUT
        rule_perf.SCAN_TIMEOUT = 1
        try:
            with tempfile.TemporaryDirectory() as td:
                base, eng = self.base_and_engine(td, 'grep -q BASEMARK "$conf" || sleep 5\n' + self.SCANNED)
                status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", base)
            self.assertEqual(status, "SLOW", detail)
            with tempfile.TemporaryDirectory() as td:
                base, eng = self.base_and_engine(td, 'grep -q BASEMARK "$conf" && sleep 5\n' + self.SCANNED)
                status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", base)
            self.assertEqual(status, "ERROR", detail)
        finally:
            rule_perf.SCAN_TIMEOUT = old

    def test_a_rule_started_near_the_end_of_the_budget_stops_at_the_deadline(self):
        import time  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            base, eng = self.base_and_engine(td, 'sleep 20\n' + self.SCANNED)   # both versions far over the budget left
            t = time.monotonic()
            status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", base, deadline=t + 1)
            took = time.monotonic() - t
        self.assertEqual(status, "ERROR", detail)
        self.assertIn("budget", detail)
        self.assertLess(took, 5)   # cut at the deadline, not after the 300 s scan limit

    def test_an_empty_base_file_is_an_error_not_a_new_rule(self):
        with tempfile.TemporaryDirectory() as td:
            # an empty config makes the engine fail (as opengrep does); it must not count as "new rule"
            base, eng = self.base_and_engine(td, '[ -s "$conf" ] || exit 7\n' + self.SCANNED, base_text="")
            status, detail = rule_perf.check_rule(eng, rm.RULES / "js" / "code-eval.yaml", base)
        self.assertEqual(status, "ERROR", detail)

    def test_only_plain_rule_paths_are_fetched(self):
        for ok in ("rules/custom/js/code-eval.yaml", "rules/custom/k8s/ingress-nginx_v2.yaml"):
            self.assertTrue(rule_perf.SAFE_PATH.match(ok), ok)
        for bad in ("rules/custom/js/a b.yaml", "rules/custom/js/a?ref=x.yaml", "rules/custom/js/a#b.yaml",
                    "rules/custom/../x.yaml", "rules/custom/js/a\\nb.yaml"):
            self.assertFalse(rule_perf.SAFE_PATH.match(bad), bad)

    def test_a_long_line_fixture_does_not_make_a_huge_file(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Path(td) / "x.js"
            fx.write_text("a" * 1_000_000 + "\n")   # one 1 MB line
            out = Path(td) / "out"
            out.mkdir()
            cwd, rel = rule_perf.big_target(fx, "rules: []\n", out)
            self.assertLessEqual((cwd / rel).stat().st_size, rule_perf.MAX_BYTES + 1_000_001)

    def test_time_spent_before_the_check_counts_against_the_budget(self):
        import subprocess  # noqa: PLC0415
        import time  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            changed = Path(td) / "changed.txt"
            changed.write_text("rules/custom/js/code-eval.yaml\n")
            # the step started 16 minutes ago (slow fetches): no time is left, so the rule is not scanned
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "rule_perf.py"), "--engine", "/bin/opengrep-absent/opengrep",
                                "--base-dir", td, "--changed-files", str(changed), "--started-at", str(time.time() - 16 * 60)],
                               capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("budget", r.stdout)

    def test_the_generated_file_keeps_the_fixture_name_for_name_filters(self):
        with tempfile.TemporaryDirectory() as td:
            fx = Path(td) / "eslint-risk.config.js"
            fx.write_text("x = 1\n")
            out = Path(td) / "out"
            out.mkdir()
            rule = 'rules: [{id: r, paths: {include: ["*.config.js"]}}]\n'
            _, rel = rule_perf.big_target(fx, rule, out)
        self.assertEqual(rel.name, "eslint-risk.config.js")

    def test_a_fixture_over_the_size_cap_is_an_error(self):
        old = rule_perf.MAX_BYTES
        rule_perf.MAX_BYTES = 10   # every real fixture is over this
        try:
            with tempfile.TemporaryDirectory() as td:
                status, detail = rule_perf.check_rule("/bin/false", rm.RULES / "js" / "code-eval.yaml", Path(td))
        finally:
            rule_perf.MAX_BYTES = old
        self.assertEqual(status, "ERROR", detail)
        self.assertIn("too large", detail)

    def test_yaml_fixture_becomes_separate_documents_at_a_workflow_path(self):
        rule = rm.RULES / "gha" / "remote-fetch-no-checksum.yaml"
        with tempfile.TemporaryDirectory() as td:
            cwd, rel = rule_perf.big_target(rules_test.fixture_for(rule), rule.read_text(), Path(td))
            text = (cwd / rel).read_text()
        self.assertEqual(rel.parent, Path(".github/workflows"))
        self.assertGreaterEqual(text.count("\n"), rule_perf.LINES // 2)
        self.assertGreater(text.count("---\n"), 1)
        self.assertTrue(all(d is None or isinstance(d, dict) for d in yaml.safe_load_all(text)))


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
        return [{**f, "label": lab} for f, lab in zip(self.f, labels, strict=False)]   # a shorter label list is a test case

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


class OpengrepOnly(unittest.TestCase):
    """Opengrep is the only engine (Semgrep CE was dropped on 2026-10-16). These fail if a Semgrep dependency
    comes back, or if a missing Opengrep lets the gate pass without running the custom rules."""

    ENGINE = "sem" + "grep"   # split so this file does not match its own check

    def test_no_code_or_workflow_runs_or_installs_semgrep(self):
        """No script, tool, test or workflow calls, installs or configures the dropped engine."""
        import re  # noqa: PLC0415
        e = self.ENGINE
        # a call, an install or an env variable for it; nosemgrep comments and .semgrepignore names are fine
        bad = re.compile(rf"""["']{e}["']|{e}==|command -v {e}|\b{e.upper()}\b|^\s*{e}\s|pip3?\s+install[^\n]*\b{e}\b""", re.M)
        files = [*ROOT.glob("scripts/*.py"), *ROOT.glob("tools/*.py"), *ROOT.glob("tests/*.py"),
                 *ROOT.glob("tests/*.sh"), *ROOT.glob(".github/workflows/*.yml"), ROOT / "action.yml"]
        hits = [f"{f.relative_to(ROOT)}: {m.group(0).strip()}" for f in files if f.resolve() != Path(__file__).resolve()
                for m in bad.finditer(f.read_text())]
        self.assertEqual(hits, [])

    def test_a_gate_without_opengrep_is_an_error_and_never_calls_another_engine(self):
        """Without opengrep the gate exits 2, even with fail_on_tool_error = false, and never runs a look-alike engine."""
        import subprocess  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bin_ = td / "bin"
            bin_.mkdir()
            marker = td / "called"
            fake = bin_ / self.ENGINE   # a look-alike engine that records any call
            fake.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            repo = td / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("x = 1\n")
            # even a repo that lets scanner crashes pass must fail when the custom-rule engine never ran
            (repo / ".sast-check.toml").write_text("[policy]\nfail_on_tool_error = false\n")
            git = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
            for cmd in (["git", "init", "-q"], ["git", "add", "-A"], [*git, "commit", "-qm", "init"]):
                subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
            env = {**os.environ, "PATH": f"{bin_}:/usr/bin:/bin"}   # git, but no opengrep
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "sast.py"), "--repo", str(repo),
                                "--mode", "full", "--only", "opengrep", "--out", str(td / "out")],
                               capture_output=True, text=True, env=env, check=False)
            runs = json.loads((td / "out" / "findings.json").read_text())["runs"]
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertEqual([(x["name"], x["status"]) for x in runs], [("opengrep", "error")])
            self.assertIn("runs Opengrep only", runs[0]["detail"])
            self.assertFalse(marker.exists(), "the gate ran another engine")


class UnscannedChecks(unittest.TestCase):
    """Submodule/LFS detection: only a complete LFS pointer counts, and a lookup failure fails closed."""

    @staticmethod
    def _sast():
        """Import scripts/sast.py as a module."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import sast  # noqa: PLC0415
        return sast

    def test_only_a_complete_lfs_pointer_counts(self):
        """A file that merely starts with the LFS version URL is ordinary content, not a pointer."""
        ok = self._sast().is_lfs_pointer
        v = b"version https://git-lfs.github.com/spec/v1\n"
        self.assertTrue(ok(v + b"oid sha256:" + b"a" * 64 + b"\nsize 12\n"))
        self.assertFalse(ok(v))                                              # no oid/size
        self.assertFalse(ok(v + b"see the docs for the pointer format\n"))  # prose after the URL
        self.assertFalse(ok(v + b"oid sha256:abc\nsize 12\n"))              # short oid
        self.assertFalse(ok(v + b"oid sha256:" + b"a" * 64 + b"\nsize x\n"))
        self.assertFalse(ok(v + b"oid sha256:" + b"a" * 64 + b"\nsize 12\n" + b"x" * 1100))   # too big
        good = b"oid sha256:" + b"a" * 64 + b"\nsize 12"
        self.assertTrue(ok(v + good))                                        # no final newline
        self.assertTrue(ok((v + good + b"\n").replace(b"\n", b"\r\n")))     # CRLF
        self.assertTrue(ok(b"  \n" + v + good + b"\n\n"))                     # surrounding whitespace
        self.assertTrue(ok(b"version https://hawser.github.com/spec/v1\n" + good))   # legacy URL
        self.assertTrue(ok(v + b"oid\rx\n" + good))   # a stray CR line is skipped, never a crash
        self.assertTrue(ok(v + b"\n" + good))                                 # blank separator line
        self.assertTrue(ok(v + b"oid sha256:" + b"a" * 64 + b"\nsize +12\n"))  # signed size

    def test_every_form_git_lfs_accepts_is_a_pointer(self):
        """Whatever `git lfs pointer --check` calls a valid pointer, is_lfs_pointer must too (fail closed)."""
        import shutil, subprocess  # noqa: E401, PLC0415
        if not shutil.which("git-lfs"):
            self.skipTest("git-lfs not installed")
        ok = self._sast().is_lfs_pointer
        oid, sz = b"oid sha256:" + b"4d7a" * 16, b"size 12"
        variants = [b"\n".join([b"version https://git-lfs.github.com/spec/v1", oid, sz]) + end
                    for end in (b"", b"\n", b"\n\n", b"\r\n")]
        variants += [b"version https://git-lfs.github.com/spec/v1\n\n" + oid + b"\n" + sz + b"\n",
                     b"  version https://git-lfs.github.com/spec/v1\n" + oid + b"\n" + sz + b"\n",
                     b"version https://git-lfs.github.com/spec/v1\n" + oid + b"\nsize +12\n",
                     b"version https://hawser.github.com/spec/v1\n" + oid + b"\n" + sz + b"\n",
                     b"version https://git-lfs.github.com/spec/v1\r\n" + oid + b"\r\n" + sz + b"\r\n"]
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ptr"
            for body in variants:
                f.write_bytes(body)
                lfs_ok = subprocess.run(["git", "lfs", "pointer", "--check", f"--file={f}"], capture_output=True,
                                        check=False, cwd=td).returncode == 0
                if lfs_ok:
                    self.assertTrue(ok(body), body)

    def test_a_missing_blob_is_a_lookup_failure(self):
        """`git cat-file --batch-check` prints "<sha> missing" and exits 0; that must raise, not read as "not LFS"."""
        with tempfile.TemporaryDirectory() as td:
            import subprocess  # noqa: PLC0415
            subprocess.run(["git", "init", "-q", td], check=True, capture_output=True)
            with self.assertRaises(RuntimeError):
                self._sast().lfs_pointer_blobs(Path(td), ["0" * 40])

    def test_a_failed_lookup_is_an_integrity_error_with_reports_written(self):
        """If the submodule/LFS check itself fails, the gate exits 2 and still writes findings.json."""
        import subprocess  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415
        sast = self._sast()
        with tempfile.TemporaryDirectory() as td:
            repo, out = Path(td) / "repo", Path(td) / "out"
            repo.mkdir()
            (repo / ".sast-check.toml").write_text("[policy]\nfail_on_tool_error = false\n")
            (repo / "a.py").write_text("x = 1\n")
            git = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
            for cmd in (["git", "init", "-q"], ["git", "add", "-A"], [*git, "commit", "-qm", "base"]):
                subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
            (repo / "a.py").write_text("x = 2\n")
            for cmd in (["git", "add", "-A"], [*git, "commit", "-qm", "change"]):
                subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
            with mock.patch.object(sast, "unscanned_changes", side_effect=RuntimeError("git cat-file exited 128")):
                code = sast.main(["--repo", str(repo), "--mode", "diff", "--base", "HEAD~1", "--only", "ruff", "--out", str(out)])
            runs = json.loads((out / "findings.json").read_text())["runs"]
            self.assertEqual(code, 2)
            self.assertIn(("lfs", "error"), [(r["name"], r["status"]) for r in runs])


if __name__ == "__main__":
    os.chdir(ROOT)
    unittest.main(verbosity=1)
