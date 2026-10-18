#!/usr/bin/env python3
"""Tests for tools/learner_rules.py (learner P3). Run: python3 tests/learner_rules_test.py

The model is replaced by canned drafts (tests/fixtures/learner/drafts.json), so the tests are offline and
deterministic. The engine tests need opengrep: $OPENGREP or on PATH."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import learner_rules as lr  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "learner"
PATTERNS = lr.load_patterns(FX / "patterns.json")
DRAFTS = json.loads((FX / "drafts.json").read_text())
OPENGREP = os.environ.get("OPENGREP") or shutil.which("opengrep")
ENGINES = [OPENGREP]
YAML_ID = "sast.python.lp-py-yaml-unsafe-load"


def pattern(pid: str) -> dict:
    return json.loads(json.dumps(next(p for p in PATTERNS if p["id"] == pid)))


class Drafter:
    """Stands in for the model: returns the canned drafts in order (the last one repeats) and records
    every request, so a test can check what the model was shown."""

    def __init__(self, drafts: dict):
        self.drafts, self.calls = drafts, []

    def __call__(self, p, train, rule_id, ext, feedback):
        self.calls.append({"id": p["id"], "train": train, "feedback": feedback,
                           "prompt": lr.prompt(p, train, rule_id, ext, feedback)})
        mine = self.drafts[p["id"]]
        return mine[min(sum(c["id"] == p["id"] for c in self.calls) - 1, len(mine) - 1)]


def repo_copy(td: str) -> Path:
    """A throwaway copy of this repo for the tool to write into."""
    dst = Path(td) / "repo"
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "sast-results"))
    return dst


def need_engines():
    """Stop the engine tests with a clear message when opengrep is not available."""
    if not (OPENGREP and Path(OPENGREP).name == "opengrep"):
        raise RuntimeError("these tests need opengrep (set $OPENGREP or put it on PATH)")


class Patterns(unittest.TestCase):
    def test_a_file_in_another_format_is_an_error_not_an_empty_run(self):
        with tempfile.TemporaryDirectory() as td:
            for doc in ({"patterns": []}, {"schema": "learner-patterns/v2", "patterns": []}, [],
                        {"schema": lr.SCHEMA, "patterns": {}}):
                f = Path(td) / "p.json"
                f.write_text(json.dumps(doc))
                with self.assertRaises(ValueError):
                    lr.load_patterns(f)

    def test_malformed_patterns_get_a_reason(self):
        base = pattern("lp-py-yaml-unsafe-load")
        self.assertEqual(lr.check_pattern(base), "")
        for k, v in (("id", "LP-Yaml"), ("id", "lp-../x"), ("cwe", "502"), ("cwe", 502), ("cwe", ""), ("impact_band", "severe"),
                     ("stack", "cobol"), ("hits", "6"), ("hits", True), ("examples", []),
                     ("examples", [{"before": "x"}]), ("id", "lp-yaml\n"), ("cwe", "CWE-502\n")):
            self.assertNotEqual(lr.check_pattern({**base, k: v}), "", (k, v))
        self.assertIn("cwe missing", lr.check_pattern({k: v for k, v in base.items() if k != "cwe"}))

    def test_a_repeated_example_is_never_both_shown_and_held_out(self):
        a, b, c = ({"before": f"x{i} = 1", "after": f"x{i} = 2"} for i in range(3))
        train, held = lr.split_examples([a, b, {**a, "before": "x0  =  1"}, c])
        self.assertEqual((train, held), ([a, b], [c]))

    def test_a_pattern_with_fewer_than_3_distinct_examples_is_skipped_before_drafting(self):
        p = pattern("lp-py-yaml-unsafe-load")
        two = {**p, "examples": p["examples"][:2] + [p["examples"][0]]}   # 3 listed, 2 distinct
        rep = lr.run([two], ROOT, ["/no/engine"], lambda *a: self.fail("drafted a pattern with 2 examples"))
        self.assertEqual(rep["skipped"], [{"id": p["id"], "reason": "needs 3+ distinct examples so one can be held out (has 2)"}])
        self.assertEqual((rep["accepted"], rep["rejected"]), ([], []))

    def test_every_third_example_is_held_out(self):
        train, held = lr.split_examples([{"n": i, "before": str(i), "after": ""} for i in range(7)])
        self.assertEqual([e["n"] for e in held], [2, 5])
        self.assertEqual([e["n"] for e in train], [0, 1, 3, 4, 6])


class BuildRule(unittest.TestCase):
    D = DRAFTS["lp-py-yaml-unsafe-load"][0]

    def test_metadata_and_severity_come_from_the_pattern_not_the_draft(self):
        cases = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}
        for band, sev in cases.items():
            p = {**pattern("lp-py-yaml-unsafe-load"), "impact_band": band}
            text, _ = lr.build_rule(p, self.D, YAML_ID)
            r = yaml.safe_load(text)["rules"][0]
            self.assertEqual((r["id"], r["severity"], r["metadata"]["sast_severity"]), (YAML_ID, sev, band))
            self.assertEqual(r["metadata"]["cwe"], "CWE-502")
            self.assertEqual(r["metadata"]["learner_pattern_id"], "lp-py-yaml-unsafe-load")

    def test_a_pattern_without_a_cwe_takes_the_drafted_one_and_a_given_cwe_wins(self):
        p = {**pattern("lp-py-yaml-unsafe-load"), "cwe": None}
        self.assertEqual(lr.check_pattern(p), "")
        self.assertIn('"cwe"', lr.prompt(p, p["examples"], YAML_ID, ".py", ""))
        self.assertNotIn('"cwe"', lr.prompt(pattern("lp-py-yaml-unsafe-load"), [], YAML_ID, ".py", ""))
        r = yaml.safe_load(lr.build_rule(p, {**self.D, "cwe": "CWE-20"}, YAML_ID)[0])["rules"][0]
        self.assertEqual(r["metadata"]["cwe"], "CWE-20")
        self.assertEqual(r["metadata"]["references"], ["https://cwe.mitre.org/data/definitions/20.html"])
        given = yaml.safe_load(lr.build_rule(pattern("lp-py-yaml-unsafe-load"), {**self.D, "cwe": "CWE-20"}, YAML_ID)[0])
        self.assertEqual(given["rules"][0]["metadata"]["cwe"], "CWE-502")
        for bad in (None, "", "cwe-20", "CWE-0", "CWE-20; rm -rf", 20, "CWE-20\n"):
            with self.assertRaises(lr.Reject, msg=bad):
                lr.build_rule(p, {**self.D, "cwe": bad}, YAML_ID)

    def test_a_draft_cannot_set_its_own_paths_options_or_metadata(self):
        p = pattern("lp-py-yaml-unsafe-load")
        for extra in ("paths:\n  include: [x]\n", "options:\n  symbolic_propagation: true\n",
                      "metadata:\n  sast_severity: low\n", "mode: search\n", "mode: taint\n"):
            with self.assertRaises(lr.Reject, msg=extra):
                lr.build_rule(p, {**self.D, "rule": self.D["rule"] + extra}, YAML_ID)

    def test_a_taint_draft_needs_mode_sources_and_sinks_only(self):
        p = pattern("lp-py-yaml-unsafe-load")
        src, snk = "pattern-sources:\n  - pattern: input()\n", "pattern-sinks:\n  - pattern: eval(...)\n"
        lr.build_rule(p, {**self.D, "rule": "mode: taint\n" + src + snk}, YAML_ID)
        for rule in ("mode: taint\n" + snk, "mode: taint\n" + src, src + snk,
                     "mode: taint\n" + src + snk + "pattern: eval(...)\n"):
            with self.assertRaises(lr.Reject, msg=rule):
                lr.build_rule(p, {**self.D, "rule": rule}, YAML_ID)

    def test_a_whole_rule_file_keeps_only_its_matching_part(self):
        whole = yaml.safe_dump({"rules": [{"id": "sast.python.other", "severity": "INFO", "languages": ["js"],
                                           **yaml.safe_load(self.D["rule"])}]})
        r = yaml.safe_load(lr.build_rule(pattern("lp-py-yaml-unsafe-load"), {**self.D, "rule": whole}, YAML_ID)[0])
        self.assertEqual((r["rules"][0]["id"], r["rules"][0]["languages"]), (YAML_ID, ["python"]))

    def test_missing_fields_and_non_json_replies_are_rejected(self):
        for d in ({**self.D, "fixture": ""}, {k: v for k, v in self.D.items() if k != "message"}):
            with self.assertRaises(lr.Reject):
                lr.build_rule(pattern("lp-py-yaml-unsafe-load"), d, YAML_ID)
        for reply in ("no json here", "[1, 2]", None):
            with self.assertRaises(lr.Reject):
                lr.parse_reply(reply)
        self.assertEqual(lr.parse_reply('```json\n{"a": 1}\n```'), {"a": 1})

    def test_a_fixture_line_copied_from_an_example_is_found(self):
        p = pattern("lp-py-yaml-unsafe-load")
        self.assertEqual(lr.copied_line(self.D["fixture"], p["examples"]), "")
        stolen = self.D["fixture"] + "        job   = yaml.load(body, Loader=yaml.Loader)\n"
        self.assertEqual(lr.copied_line(stolen, p["examples"]), "job = yaml.load(body, Loader=yaml.Loader)")


class Secrets(unittest.TestCase):
    KEY = "sk-or-v1-test-must-never-be-printed"

    def test_the_api_key_is_sent_but_never_printed_or_recorded(self):
        p = pattern("lp-py-yaml-unsafe-load")
        sent = {}

        def fail(req, timeout):
            sent["auth"] = req.get_header("Authorization")
            raise urllib.error.HTTPError(lr.OPENROUTER_URL, 401, f"bad key {self.KEY}", {}, io.BytesIO(self.KEY.encode()))

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": self.KEY}), \
                mock.patch("urllib.request.urlopen", fail), redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(lr.Reject) as cm:
                lr.draft_with_llm(p, p["examples"], YAML_ID, ".py", "", "m")
        self.assertEqual(sent["auth"], f"Bearer {self.KEY}")
        for text in (str(cm.exception), out.getvalue(), err.getvalue()):
            self.assertNotIn(self.KEY, text)

    def test_a_report_path_inside_dist_or_rules_is_refused_before_anything_runs(self):
        """A --report path inside dist/ or rules/ exits 2 before any draft runs."""
        base = ["learner_rules.py", "--patterns", str(FX / "patterns.json"), "--engine", "/x/opengrep"]
        for report in ("dist/rules.yaml", str(ROOT / "dist" / "rule-ids.lock"), "rules/custom/python/x.yaml"):
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), \
                    mock.patch.object(sys, "argv", base + ["--report", str(ROOT / report)]), \
                    mock.patch.object(lr, "run", side_effect=AssertionError("ran with a bad --report")), \
                    redirect_stderr(io.StringIO()) as err:
                self.assertEqual(lr.main(), 2, report)
            self.assertIn("--report must be outside dist/ and rules/", err.getvalue())

    def test_no_key_stops_the_run_before_anything_is_drafted(self):
        """Without OPENROUTER_API_KEY the tool exits 2 before drafting anything."""
        env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
        argv = ["learner_rules.py", "--patterns", str(FX / "patterns.json"), "--engine", "/x/opengrep"]
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, "argv", argv), \
                mock.patch.object(lr, "run", side_effect=AssertionError("drafted without a key")), redirect_stderr(io.StringIO()):
            self.assertEqual(lr.main(), 2)


class OpenPr(unittest.TestCase):
    REPORT = {"accepted": [{"id": "lp-py-yaml-unsafe-load", "rule_id": YAML_ID, "cwe": "CWE-502", "hits": 6,
                            "severity": "high", "blocking": True,
                            "files": ["rules/custom/python/lp-py-yaml-unsafe-load.yaml",
                                      "rules/custom/python/lp-py-yaml-unsafe-load.py"]}],
              "rejected": [{"id": "lp-js-open-redirect", "reason": "no javascript code"}], "skipped": []}

    def test_one_pr_on_a_dated_branch_and_never_a_merge(self):
        cmds = []

        def runner(cmd, repo):
            cmds.append(cmd)
            return mock.Mock(stdout="https://github.com/o/r/pull/1\n")

        self.assertEqual(lr.open_pr(ROOT, self.REPORT, "main", "m", runner), "https://github.com/o/r/pull/1")
        branch = f"learner/rules-{date.today().isoformat()}"
        self.assertIn(["git", "checkout", "-b", branch], cmds)
        self.assertEqual(cmds[1], ["git", "add", "--", *self.REPORT["accepted"][0]["files"],
                                   "dist/rules.yaml", "dist/rule-ids.lock"])
        self.assertEqual(sum(c[:3] == ["gh", "pr", "create"] for c in cmds), 1)
        flat = [x for c in cmds for x in c]
        for banned in ("merge", "--auto", "--force", "-f", "--admin", "--approve"):
            self.assertNotIn(banned, flat)

    def test_rules_from_another_orgs_code_are_listed_for_owner_approval(self):
        self.assertEqual(lr.source_orgs({"repos": ["Viaknox/app", "SathiaAI/x", "SathiaAI/y"]}), ["SathiaAI", "Viaknox"])
        self.assertEqual(lr.source_orgs({}), ["unknown"])
        ours = {**self.REPORT["accepted"][0], "orgs": ["SathiaAI"]}
        self.assertNotIn("Owner approval needed", lr.pr_body({**self.REPORT, "accepted": [ours]}, "m"))
        for orgs in (["SathiaAI", "Viaknox"], ["unknown"]):
            body = lr.pr_body({**self.REPORT, "accepted": [{**ours, "orgs": orgs}]}, "m")
            self.assertIn("Owner approval needed", body)
            self.assertIn(f"`{YAML_ID}` (from {', '.join(orgs)})", body)

    def test_the_pr_body_has_reasons_but_no_example_code(self):
        body = lr.pr_body(self.REPORT, "m")
        self.assertIn("no javascript code", body)
        self.assertIn(YAML_ID, body)
        for e in pattern("lp-py-yaml-unsafe-load")["examples"]:
            for ln in (e["before"] + e["after"]).splitlines():
                if len(ln.strip()) > 12:
                    self.assertNotIn(ln.strip(), body)


class FixtureRun(unittest.TestCase):
    """The exit test: the whole fixture through the real checks, with both engines."""

    @classmethod
    def setUpClass(cls):
        need_engines()
        cls.td = tempfile.TemporaryDirectory()
        cls.repo = repo_copy(cls.td.name)
        cls.drafter = Drafter(DRAFTS)
        cls.report = lr.run(PATTERNS, cls.repo, ENGINES, cls.drafter)
        cls.build_error = lr.build_dist(cls.repo, cls.report)

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_good_drafts_are_accepted_and_bad_ones_rejected_with_reasons(self):
        self.assertEqual(self.build_error, "")
        self.assertEqual([a["id"] for a in self.report["accepted"]],
                         ["lp-py-yaml-unsafe-load", "lp-py-tar-extractall-unfiltered", "lp-py-requests-no-timeout"])
        rejected = {r["id"]: r["reason"] for r in self.report["rejected"]}
        self.assertEqual(sorted(rejected), ["lp-js-open-redirect", "lp-py-subprocess-unchecked"])
        self.assertIn("fires on this repo's own code", rejected["lp-py-subprocess-unchecked"])
        self.assertIn("no javascript code", rejected["lp-js-open-redirect"])
        self.assertEqual(self.report["skipped"], [{"id": "lp-py-md5-password", "reason": "2 hits (needs 3)"}])

    def test_a_draft_that_matches_fixed_code_is_retried_with_the_reason(self):
        calls = [c for c in self.drafter.calls if c["id"] == "lp-py-requests-no-timeout"]
        self.assertEqual(len(calls), 2)
        self.assertIn("matches the fixed code", calls[1]["feedback"])

    def test_the_model_never_sees_held_out_examples(self):
        for p in PATTERNS:
            _, held = lr.split_examples(p["examples"])
            for c in (c for c in self.drafter.calls if c["id"] == p["id"]):
                self.assertTrue(held, p["id"])
                for e in held:
                    self.assertNotIn(e, c["train"])
                    self.assertNotIn(e["before"].strip(), c["prompt"])

    def test_accepted_rules_catch_held_out_examples_and_are_silent_on_clean_code(self):
        clean = lr.clean_files(self.repo, (".py",))
        self.assertGreater(len(clean), 5)
        with tempfile.TemporaryDirectory() as td:
            for a in self.report["accepted"]:
                _, held = lr.split_examples(pattern(a["id"])["examples"])
                files = []
                for i, e in enumerate(held):
                    files.append(Path(td) / f"{a['id']}-{i}.py")
                    files[-1].write_text(e["before"])
                for eng in ENGINES:
                    hits = lr.scan(eng, self.repo / a["files"][0], files)
                    self.assertEqual(sorted(hits), sorted(f.resolve() for f in files), (a["id"], eng))
                    self.assertEqual(lr.scan(eng, self.repo / a["files"][0], clean), {}, (a["id"], eng))

    def test_written_rules_carry_the_contract_metadata_and_severity(self):
        for a, sev in zip(self.report["accepted"], ("ERROR", "ERROR", "WARNING"), strict=True):
            r = yaml.safe_load((self.repo / a["files"][0]).read_text())["rules"][0]
            self.assertEqual(r["severity"], sev)
            self.assertEqual(r["metadata"]["cwe"], pattern(a["id"])["cwe"])
            self.assertEqual(r["metadata"]["learner_pattern_id"], a["id"])
            self.assertTrue((self.repo / a["files"][1]).exists())

    def test_rejected_rules_never_land(self):
        lock = (self.repo / "dist" / "rule-ids.lock").read_text().split()
        bundle = (self.repo / "dist" / "rules.yaml").read_text()
        for a in self.report["accepted"]:
            self.assertIn(a["rule_id"], lock)
        for r in self.report["rejected"] + self.report["skipped"]:
            self.assertEqual(list((self.repo / "rules" / "custom").glob(f"*/{r['id']}.*")), [], r["id"])
            self.assertFalse(any(r["id"] in x for x in lock), r["id"])
            self.assertNotIn(r["id"], bundle)


class LocalDrafter(Drafter):
    """The canned drafts, with fixture annotations naming the `local.` id the rule gets in a private rules repo."""

    def __call__(self, p, train, rule_id, ext, feedback):
        d = super().__call__(p, train, rule_id, ext, feedback)
        return {**d, "fixture": d["fixture"].replace(rule_id.replace("local.", "sast.", 1), rule_id)}


class TargetRun(unittest.TestCase):
    """--target: the same checks, but accepted rules land as `local.` rules in a private rules repo's
    .sast-check/rules/ (fixtures in its tests/ subfolder), never in this public repo."""

    @classmethod
    def setUpClass(cls):
        need_engines()
        cls.td = tempfile.TemporaryDirectory()
        cls.repo = repo_copy(cls.td.name)
        cls.target = Path(cls.td.name) / "private-rules"
        cls.target.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=cls.target, check=True)
        (cls.target / ".sast-check.toml").write_text('[paths]\nexclude = [".sast-check/rules/tests/**"]\n')
        before = sorted(p.relative_to(cls.repo).as_posix() for p in cls.repo.rglob("*"))
        cls.report = lr.run(PATTERNS, cls.repo, ENGINES, LocalDrafter(DRAFTS), target=cls.target)
        cls.check_error = lr.check_target(cls.target, cls.report)
        cls.repo_unchanged = before == sorted(p.relative_to(cls.repo).as_posix() for p in cls.repo.rglob("*"))

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_rules_land_in_the_private_repo_as_local_rules_that_sast_check_accepts(self):
        self.assertEqual(self.check_error, "")
        self.assertTrue(self.repo_unchanged)          # nothing written to the public repo
        self.assertEqual([a["rule_id"] for a in self.report["accepted"]],
                         ["local.python.lp-py-yaml-unsafe-load", "local.python.lp-py-tar-extractall-unfiltered",
                          "local.python.lp-py-requests-no-timeout"])
        for a in self.report["accepted"]:
            self.assertEqual(a["files"], [f".sast-check/rules/{a['id']}.yaml", f".sast-check/rules/tests/{a['id']}.py"])
            for f in a["files"]:
                self.assertTrue((self.target / f).is_file(), f)
        sys.path.insert(0, str(ROOT / "scripts"))
        import sast
        got = sast.parse_local_rules(sast.local_rule_files(self.target, None))
        self.assertEqual(sorted(r["id"] for r in got), sorted(a["rule_id"] for a in self.report["accepted"]))

    def test_a_second_run_skips_rules_the_private_repo_already_has(self):
        again = lr.run([pattern("lp-py-yaml-unsafe-load")], self.repo, ENGINES, LocalDrafter(DRAFTS), target=self.target)
        self.assertEqual(again["accepted"], [])
        self.assertIn("already exists", again["skipped"][0]["reason"])

    def test_a_rule_set_sast_check_would_refuse_keeps_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=target, check=True)
            (target / ".sast-check" / "rules").mkdir(parents=True)
            (target / ".sast-check" / "rules" / "a.yaml").write_text("rules:\n  - id: sast.not.local\n")
            mine = target / ".sast-check" / "rules" / "new.yaml"
            mine.write_text("rules: []\n")
            report = {"accepted": [{"id": "new", "files": [".sast-check/rules/new.yaml"]}]}
            self.assertIn("must start with `local.`", lr.check_target(target, report))
            self.assertFalse(mine.exists())
            self.assertEqual(report["accepted"], [])

    def test_the_pr_goes_to_the_private_repo_without_dist_files(self):
        cmds = []

        def runner(cmd, repo):
            cmds.append((cmd, repo))
            return mock.Mock(stdout="url\n")

        lr.open_pr(self.target, self.report, "main", "m", runner, dist=False)
        self.assertTrue(all(repo == self.target for _, repo in cmds))
        add = next(c for c, _ in cmds if c[:2] == ["git", "add"])
        self.assertEqual(add[3:], [f for a in self.report["accepted"] for f in a["files"]])

    def test_the_target_must_be_a_separate_checkout(self):
        for bad in (str(ROOT), str(ROOT / "rules"), self.td.name):
            with mock.patch.object(sys, "argv", ["learner_rules.py", "--patterns", str(FX / "patterns.json"),
                                                 "--target", bad]), \
                    mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(lr.main(), 2, bad)
            self.assertIn("--target", err.getvalue())
        with mock.patch.object(sys, "argv", ["learner_rules.py", "--patterns", str(FX / "patterns.json"), "--target",
                                             str(self.target), "--report", str(self.target / "run.json")]), \
                mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(lr.main(), 2)          # the report would be committed with the rules
        self.assertIn("outside the --target checkout", err.getvalue())


class TargetSafety(unittest.TestCase):
    """--target refuses anything that could leak private-derived rules or text, or write outside the checkout."""

    def target(self, td, toml='[paths]\nexclude = [".sast-check/rules/tests/**"]\n'):
        """A git checkout in TD with an optional .sast-check.toml."""
        t = Path(td) / "t"
        t.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=t, check=True)
        if toml is not None:
            (t / ".sast-check.toml").write_text(toml)
        return t

    def test_links_on_the_way_and_scanned_fixtures_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = self.target(td)
            self.assertEqual(lr.target_problem(t), "")
            (t / ".sast-check" / "rules").mkdir(parents=True)
            os.symlink(td, t / ".sast-check" / "rules" / "tests")
            self.assertIn("must be a folder", lr.target_problem(t))
        with tempfile.TemporaryDirectory() as td:
            self.assertIn("must exclude the fixtures", lr.target_problem(self.target(td, toml=None)))
        with tempfile.TemporaryDirectory() as td:
            self.assertIn("invalid", lr.target_problem(self.target(td, toml="[nope]\n")))

    def test_the_pr_only_goes_to_a_private_repo(self):
        for out, ok in (('{"nameWithOwner": "o/r", "visibility": "PRIVATE"}', True),
                        ('{"nameWithOwner": "o/r", "visibility": "PUBLIC"}', False),
                        ('{"nameWithOwner": "o/r", "visibility": "INTERNAL"}', False), ("not json", False)):
            def fake(cmd, **kw):
                return mock.Mock(returncode=0, stdout="https://github.com/o/r\n" if cmd[:2] == ["git", "remote"] else out)
            with mock.patch.object(lr.subprocess, "run", fake):
                if ok:
                    self.assertEqual(lr.private_repo(Path(".")), "o/r")
                else:
                    with self.assertRaises(ValueError, msg=out):
                        lr.private_repo(Path("."))
        cmds = []
        lr.open_pr(Path("."), OpenPr.REPORT, "main", "m", lambda c, r: cmds.append(c) or mock.Mock(stdout="u"),
                   dist=False, gh_repo="o/r")
        self.assertEqual(next(c for c in cmds if c[:3] == ["gh", "pr", "create"])[3:5], ["-R", "o/r"])

    def test_a_copied_example_line_is_never_quoted_in_a_reason(self):
        p = pattern("lp-py-yaml-unsafe-load")
        stolen = "job = yaml.load(body, Loader=yaml.Loader)\n"
        with tempfile.TemporaryDirectory() as td, self.assertRaises(lr.Reject) as e:
            lr.evaluate(p, "rules: []\n", stolen, p["examples"], [], ROOT, ENGINES, Path(td))
        self.assertNotIn("yaml.load", str(e.exception))

    def test_an_existing_fixture_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            t = self.target(td)
            fx = t / ".sast-check" / "rules" / "tests" / "lp-py-yaml-unsafe-load.py"
            fx.parent.mkdir(parents=True)
            fx.write_text("mine\n")
            got = lr.run([pattern("lp-py-yaml-unsafe-load")], ROOT, ENGINES, LocalDrafter(DRAFTS), target=t)
            self.assertEqual(got["accepted"], [])
            self.assertEqual(fx.read_text(), "mine\n")

    def test_the_rules_check_uses_the_requested_engine_and_survives_bad_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            t = self.target(td)
            (t / ".sast-check" / "rules").mkdir(parents=True)
            (t / ".sast-check" / "rules" / "a.yaml").write_bytes(b"\xff\xfe")
            self.assertEqual(lr.target_ids(t), set())                 # unreadable: no crash
            self.assertIn("UTF-8", lr.check_target(t, {"accepted": []}))
        sys.path.insert(0, str(ROOT / "scripts"))
        import sast
        with tempfile.TemporaryDirectory() as td, mock.patch.object(sast, "validate_local_rules") as v:
            lr.check_target(self.target(td), {"accepted": []}, "/x/opengrep")
        self.assertEqual(v.call_args.args[1], "/x/opengrep")

    def test_a_report_in_this_repo_or_an_existing_local_branch_stops_the_run(self):
        with tempfile.TemporaryDirectory() as td:
            t = self.target(td)
            for extra in (["--report", str(ROOT / "run.json")], ["--report", str(t / "run.json")]):
                with mock.patch.object(sys, "argv", ["learner_rules.py", "--patterns", str(FX / "patterns.json"),
                                                     "--target", str(t), *extra]), \
                        mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(lr.main(), 2, extra)
                self.assertIn("--report must be outside", err.getvalue())
            git = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
            subprocess.run([*git, "commit", "-qm", "init", "--allow-empty"], cwd=t, check=True)
            subprocess.run(["git", "add", "-A"], cwd=t, check=True)
            subprocess.run([*git, "commit", "-qm", "toml"], cwd=t, check=True)
            subprocess.run(["git", "branch", f"learner/rules-{date.today().isoformat()}"], cwd=t, check=True)
            with mock.patch.object(sys, "argv", ["learner_rules.py", "--patterns", str(FX / "patterns.json"),
                                                 "--target", str(t), "--open-pr"]), \
                    mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(lr.main(), 2)
            self.assertIn("already exists in the checkout", err.getvalue())


class Rejections(unittest.TestCase):
    """Each acceptance check on its own: the draft is rejected, with a reason, and nothing is written."""

    @classmethod
    def setUpClass(cls):
        need_engines()
        cls.td = tempfile.TemporaryDirectory()
        cls.repo = repo_copy(cls.td.name)

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def one(self, rule: str, pid="lp-py-yaml-unsafe-load", **fields):
        drafter = Drafter({pid: [{**DRAFTS[pid][0], "rule": rule, **fields}]})
        rep = lr.run([pattern(pid)], self.repo, ENGINES, drafter)
        self.assertEqual(rep["accepted"], [])
        self.assertEqual(list((self.repo / "rules" / "custom").glob(f"*/{pid}.*")), [])
        return rep["rejected"][0]["reason"], drafter

    def test_missing_a_held_out_example_rejects_without_a_retry(self):
        rule = ("pattern-either:\n  - pattern: yaml.load($S)\n  - pattern: yaml.load($S, Loader=yaml.Loader)\n"
                "  - pattern: yaml.load($S, yaml.FullLoader)\n")
        reason, drafter = self.one(rule)
        self.assertIn("misses a held-out vulnerable example", reason)
        self.assertEqual(len(drafter.calls), 1)

    def test_an_untested_pattern_element_is_a_mutation_survivor(self):
        rule = DRAFTS["lp-py-yaml-unsafe-load"][0]["rule"] + "  - pattern-not: yaml.load($S, Loader=yaml.BaseLoader)\n"
        reason, _ = self.one(rule)
        self.assertIn("mutation check: NEW SURVIVOR", reason)

    def test_a_rule_the_engine_rejects(self):
        reason, _ = self.one("patterns:\n  - pattern: yaml.load(\n")
        self.assertIn("rejects the rule", reason)

    def test_a_fixture_that_does_not_match_its_annotations(self):
        reason, _ = self.one(DRAFTS["lp-py-yaml-unsafe-load"][0]["rule"],
                             fixture=DRAFTS["lp-py-yaml-unsafe-load"][0]["fixture"].replace("# ok:", "# ruleid:", 1))
        self.assertIn("fixture test", reason)

    def test_a_pattern_without_a_cwe_lands_with_the_drafted_cwe_marked_for_review(self):
        pid = "lp-py-yaml-unsafe-load"
        rep = lr.run([{**pattern(pid), "cwe": None}], self.repo, ENGINES, Drafter({pid: [{**DRAFTS[pid][0], "cwe": "CWE-502"}]}))
        try:
            self.assertEqual([(a["cwe"], a["cwe_source"]) for a in rep["accepted"]], [("CWE-502", "drafted")])
            self.assertIn("CWE-502 (drafted: check it)", lr.pr_body(rep, "m"))
        finally:
            for a in rep["accepted"]:
                for f in a["files"]:
                    (self.repo / f).unlink(missing_ok=True)

    def test_a_failed_build_keeps_nothing(self):
        rep = lr.run([pattern("lp-py-yaml-unsafe-load")], self.repo, ENGINES, Drafter(DRAFTS))
        self.assertEqual(len(rep["accepted"]), 1)
        retired = self.repo / "rules" / "RETIRED.txt"
        old = retired.read_text() if retired.exists() else None
        retired.write_text((old or "") + YAML_ID + "\n")   # the rule-ID lock now refuses this id
        try:
            err = lr.build_dist(self.repo, rep)
        finally:
            retired.unlink() if old is None else retired.write_text(old)
        self.assertIn("retired rule ids must never be reused", err)
        self.assertEqual(rep["accepted"], [])
        self.assertEqual(list((self.repo / "rules" / "custom").glob("*/lp-py-yaml-unsafe-load.*")), [])


if __name__ == "__main__":
    unittest.main()
