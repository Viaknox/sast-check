#!/usr/bin/env python3
"""Tests for the gitleaks exclude push-down (issue #26) against the real gitleaks.

Needs gitleaks on PATH and fails (never skips) without it. Run: python3 -m unittest tests.gitleaks_pushdown_test
(or python3 tests/gitleaks_pushdown_test.py). tests/e2e.sh runs it in CI.
"""
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRET = 'K = "AKIAIOSFODNN7ABCDEFG"\n'
CUSTOM = 'T = "MYTOK_ABCDE12345"\n'


def load_sast():
    """Import scripts/sast.py as a fresh module."""
    spec = importlib.util.spec_from_file_location("sast_pd", ROOT / "scripts" / "sast.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# near-miss and nested paths around the exclude globs below
EXCLUDES = ["vendor/**", "node_modules/**", "big dir/**", "src/gen*", "docs/**/*", "a?b*", "x/[ab]*",
            "**/gen/**", "**/*.min.js", ".*", "sast-results/**"]
FILES = ["vendor/k.py", "vendorx/k.py", "avendor/k.py", "src/vendor/k.py", "node_modules/k.py",
         "deep/node_modules/k.py", "big dir/sub/k.py", "big dir2/k.py", "src/gen1/k.py", "src/gen/k.py",
         "src/generic.py", "src/live.py", "docs/a/b.py", "docs.py", "aXb/k.py", "ab/k.py", "abc/k.py",
         "x/a1.py", "x/b/k.py", "x/c1.py", "pkg/gen/k.py", "pkg/genx/k.py", "web/app.min.js", "web/app.js",
         ".hidden/k.py", "sast-results/r.json", "top.py"]


class Base(unittest.TestCase):
    """Builds one repo with the corpus and runs sast.run_gitleaks on it with and without push-down."""

    @classmethod
    def setUpClass(cls):
        """Create the corpus repo."""
        if not shutil.which("gitleaks"):
            raise AssertionError("gitleaks is required on PATH (this test never skips)")
        cls.td = tempfile.mkdtemp()
        cls.repo = Path(cls.td) / "repo"
        cls.repo.mkdir()
        for f in FILES:
            p = cls.repo / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(SECRET + CUSTOM)
        cls.git("init", "-q", "-b", "main")
        cls.git("config", "user.email", "t@example.com")
        cls.git("config", "user.name", "t")
        cls.commit("corpus")

    @classmethod
    def tearDownClass(cls):
        """Remove the corpus repo."""
        shutil.rmtree(cls.td, ignore_errors=True)

    @classmethod
    def git(cls, *a):
        """Run git in the corpus repo."""
        subprocess.run(["git", *a], cwd=cls.repo, check=True, capture_output=True)

    @classmethod
    def commit(cls, msg):
        """Commit everything."""
        cls.git("add", "-A")
        cls.git("commit", "-qm", msg)

    def scan(self, pushdown=True, patch=None, base=None, excludes=None, env=None):
        """Run run_gitleaks; return (sorted (path, line, rule) findings, notes, tree-config-used flag)."""
        sast = load_sast()
        seen = {}
        orig = sast.gitleaks_runs

        def spy(ctx, runs, settings, td, alias=None, tree=None):
            """Record whether the whole-tree run got a push-down config."""
            seen["tree"] = tree
            return orig(ctx, runs, settings, td, alias, tree)
        sast.gitleaks_runs = spy
        if patch:
            patch(sast)
        ctx = sast.Ctx(repo=self.repo, cfg={"paths": {"exclude": excludes or EXCLUDES}}, mode="full", base=base)
        old = {k: os.environ.get(k) for k in ["SAST_GITLEAKS_PUSHDOWN", *(env or {})]}
        os.environ.pop("SAST_GITLEAKS_PUSHDOWN", None)
        if not pushdown:
            os.environ["SAST_GITLEAKS_PUSHDOWN"] = "0"
        os.environ.update(env or {})
        try:
            fs = sast.run_gitleaks(ctx)
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return sorted((f.path, f.line, f.rule) for f in fs), ctx.notes, bool(seen.get("tree"))


class Differential(Base):
    """Item 1-3: post-filtered findings with push-down equal those without; an over-broad regex is caught."""

    def test_differential_equal(self):
        """Push-down on and off report identical findings on the near-miss corpus."""
        on, _, used = self.scan(True)
        off, _, used_off = self.scan(False)
        self.assertTrue(used, "push-down was not active, the comparison would prove nothing")
        self.assertFalse(used_off)
        self.assertEqual(on, off)
        paths = {p for p, _, _ in on}
        for kept in ["vendorx/k.py", "avendor/k.py", "big dir2/k.py", "docs.py", "x/c1.py",
                     "pkg/genx/k.py", "src/live.py", "web/app.js"]:
            self.assertIn(kept, paths, kept)
        for gone in ["vendor/k.py", "node_modules/k.py", "big dir/sub/k.py", "src/gen1/k.py", "src/generic.py", "docs/a/b.py", ".hidden/k.py"]:
            self.assertNotIn(gone, paths, gone)

    def test_differential_equal_on_pr_scan(self):
        """Same equality when the settings come from a base branch."""
        self.assertEqual(self.scan(True, base="HEAD")[0], self.scan(False, base="HEAD")[0])

    def test_negative_control_overbroad_regex_is_caught(self):
        """A secret at vendorx/k.py is not excluded by glob_any but 'vendor.*' would skip it: must differ."""
        def broad(sast):
            """Replace the generator with one regex that also matches vendorx/."""
            sast.gitleaks_exclude_regexes = lambda globs: ["(?s)^vendor.*$"]
        on, _, used = self.scan(True, patch=broad)
        off, _, _ = self.scan(False)
        self.assertTrue(used)
        self.assertIn(("vendorx/k.py", 1, "secret.aws-access-token"), off)
        self.assertNotIn("vendorx/k.py", {p for p, _, _ in on})
        self.assertNotEqual(on, off)

    def test_mutation_broader_regex_fails_differential(self):
        """Mutation proof: a deliberately broader generator (skip all of src/) makes the equality check fail."""
        def broad(sast):
            """Skip all of src/ instead of only the excluded trees."""
            sast.gitleaks_exclude_regexes = lambda globs: ["(?s)^src(/.*)?$"] + [sast.glob_regex(g) for g in globs if g.endswith("*") and g != "src/gen*"]
        self.assertNotEqual(self.scan(True, patch=broad)[0], self.scan(False)[0])


class Generated(Base):
    """Item 4-5: anchored, RE2-safe regexes that the real gitleaks accepts; round-trip checked TOML."""
    GLOBS = ["node_modules/**", "vendor/**", "big dir/**", "src/vendor2*", "**/gen/**", "docs/**/*", "a**", "a?b*",
             "x/[ab]*", "x/[!ab]*", "x/[]a]*", "x/[^a]*", "x/[[:alpha:]]*", "x/[a-c]?*", "p[*", "q.+(1)*", "x/[a\\]*",
             "$h{x}^*", "é/**", 'q"uote*', "back\\slash*"]

    def setUp(self):
        self.sast = load_sast()

    def test_regexes_are_anchored(self):
        """Every pushed-down regex is ^...$ anchored (so re.search equals a full match)."""
        rxs = self.sast.gitleaks_exclude_regexes(self.GLOBS)
        self.assertTrue(rxs)
        for rx in rxs:
            self.assertTrue(rx.startswith("(?s)^") and rx.endswith("$"), rx)

    def test_equivalent_to_glob_any_with_re_search(self):
        """re.search of each regex agrees with glob_any over a path corpus (also files nested under each tree)."""
        paths = set(FILES) | {"x/a", "x/b1", "x/c", "x/]", "x/^", "p[x", "q.+(1)", "q.+(1)/z", "é/x", "a1b", "ab",
                              'q"uote/x', "back\\slash/x", "$h{x}^/y", "vendor2", "src/vendor2/k", ""}
        paths |= {p + "/n/m.py" for p in list(paths) if p}
        for g in self.GLOBS:
            for rx in self.sast.gitleaks_exclude_regexes([g]):
                for p in paths:
                    self.assertEqual(bool(re.search(rx, p)), self.sast.glob_any(p, [g]), (g, p))

    def test_real_gitleaks_accepts_generated_config(self):
        """gitleaks loads the generated config for all test globs (RE2 compiles every regex) and still finds a secret."""
        rxs = self.sast.gitleaks_exclude_regexes(self.GLOBS)
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "d"
            (d / "keep").mkdir(parents=True)
            (d / "keep" / "k.py").write_text(SECRET)
            cfg = Path(td) / "c.toml"
            cfg.write_text(self.sast.gitleaks_exclude_config(None, rxs))
            p = subprocess.run(["gitleaks", "dir", ".", "--config", str(cfg), "--no-banner", "--exit-code", "0",
                                "--report-format", "json", "--report-path", str(Path(td) / "r.json")],
                               cwd=d, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr[-500:])
            self.assertNotRegex(p.stderr, r"\b(ERR|FTL)\b|panic")
            self.assertIn("keep/k.py", (Path(td) / "r.json").read_text())

    def test_roundtrip_accepts_exact_and_rejects_drift(self):
        """The TOML round-trip passes for the built string and fails when the text drifts from the regex list."""
        rxs = self.sast.gitleaks_exclude_regexes(self.GLOBS)
        for ext in (None, "/some dir/own.toml"):
            text = self.sast.gitleaks_exclude_config(ext, rxs)
            self.assertEqual(tomllib.loads(text)["allowlists"][0]["paths"], rxs)
            self.assertTrue(self.sast.gitleaks_config_roundtrips(text, ext, rxs))
            self.assertFalse(self.sast.gitleaks_config_roundtrips(text, ext, rxs[:-1]))
            self.assertFalse(self.sast.gitleaks_config_roundtrips(text, ext, rxs + ["x"]))
            self.assertFalse(self.sast.gitleaks_config_roundtrips(text.replace("^", "", 1), ext, rxs))
            self.assertFalse(self.sast.gitleaks_config_roundtrips(text[:-3], ext, rxs))   # broken TOML
        self.assertFalse(self.sast.gitleaks_config_roundtrips(self.sast.gitleaks_exclude_config(None, rxs), "x.toml", rxs))


class Fallback(Base):
    """Item 6-8: fail closed with a full scan and a note; kill switch; version pin."""

    def test_roundtrip_failure_falls_back(self):
        """A failed round-trip means no push-down, a note, and the same findings."""
        on, notes, used = self.scan(True, patch=lambda s: setattr(s, "gitleaks_config_roundtrips", lambda *a: False))
        self.assertFalse(used)
        self.assertEqual(on, self.scan(False)[0])
        self.assertEqual(len(notes), 1)
        self.assertIn("exclusions were applied afterwards", notes[0])

    def test_regex_generation_failure_falls_back(self):
        """An exception while generating regexes means a full scan and a note."""
        def boom(sast):
            """Make the generator raise."""
            def f(globs):
                """Raise like a buggy generator."""
                raise ValueError("x")
            sast.gitleaks_exclude_regexes = f
        on, notes, used = self.scan(True, patch=boom)
        self.assertFalse(used)
        self.assertEqual(on, self.scan(False)[0])
        self.assertEqual(len(notes), 1)

    def test_gitleaks_rejecting_the_config_reruns_without_pushdown(self):
        """A regex gitleaks cannot compile (valid TOML) makes the tree scan rerun plain, with one note."""
        bad = lambda s: setattr(s, "gitleaks_exclude_regexes", lambda globs: ["(unclosed"])  # noqa: E731
        on, notes, used = self.scan(True, patch=bad)
        self.assertTrue(used)
        self.assertEqual(on, self.scan(False)[0])
        self.assertEqual(len([n for n in notes if "rejected" in n]), 1)

    def shim(self, body):
        """A fake gitleaks first on PATH; returns the PATH value and the shim dir."""
        d = tempfile.mkdtemp(dir=self.td)
        f = Path(d) / "gitleaks"
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
        return d

    def test_unrelated_gitleaks_failure_stays_a_scanner_error(self):
        """A failure of the tree run that is not about the config is raised, not retried."""
        real = shutil.which("gitleaks")
        d = self.shim(f'if [ "$1" = version ]; then echo 8.30.1; exit 0; fi\n'
                      f'case "$*" in *tree.toml*) echo "boom: disk on fire" >&2; exit 1;; esac\nexec "{real}" "$@"\n')
        with self.assertRaisesRegex(RuntimeError, "disk on fire"):
            self.scan(True, env={"PATH": d + os.pathsep + os.environ["PATH"]})

    def test_kill_switch(self):
        """SAST_GITLEAKS_PUSHDOWN=0 disables push-down; unset or other values leave it on."""
        self.assertFalse(self.scan(False)[2])
        self.assertTrue(self.scan(True)[2])
        self.assertTrue(self.scan(True, env={"SAST_GITLEAKS_PUSHDOWN": "1"})[2])

    def test_other_gitleaks_version_scans_everything_with_one_note(self):
        """A gitleaks that reports another version gets no push-down; `gitleaks version` runs once per scan."""
        real = shutil.which("gitleaks")
        log = Path(self.td) / "ver.log"
        d = self.shim(f'if [ "$1" = version ]; then echo v8.29.0 >> "{log}"; echo 8.29.0; exit 0; fi\nexec "{real}" "$@"\n')
        log.unlink(missing_ok=True)
        on, notes, used = self.scan(True, env={"PATH": d + os.pathsep + os.environ["PATH"]})
        self.assertFalse(used)
        self.assertEqual(on, self.scan(False)[0])
        self.assertEqual(len(notes), 1)
        self.assertIn("8.30.1", notes[0])
        self.assertIn("8.29.0", notes[0])
        self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_pinned_version_constant_matches_ci(self):
        """The constant equals the version action.yml and test.yml install."""
        sast = load_sast()
        for f in ["action.yml", ".github/workflows/test.yml"]:
            self.assertIn(f"gitleaks/v8@v{sast.GITLEAKS_PUSHDOWN_VERSION}", (ROOT / f).read_text(), f)
        self.assertEqual(sast.GITLEAKS_PUSHDOWN_VERSION, "8.30.1")


class RepoSettings(Base):
    """Item 10: the repo's own custom rule and [[allowlists]] behave the same with push-down on."""

    @classmethod
    def setUpClass(cls):
        """Add a .gitleaks.toml with a custom rule, its own allowlist and the default rules."""
        super().setUpClass()
        (cls.repo / ".gitleaks.toml").write_text(
            '[extend]\nuseDefault = true\n\n[[rules]]\nid = "my-token"\ndescription = "my token"\n'
            'regex = \'\'\'MYTOK_[A-Z0-9]{10}\'\'\'\n\n[[allowlists]]\npaths = [\'\'\'^src/live\\.py$\'\'\']\n')
        cls.commit("settings")

    def test_custom_rule_and_allowlist_unchanged_by_pushdown(self):
        """Custom rule found, repo allowlist honoured, and on == off, in tree and base-branch scans."""
        for base in (None, "HEAD"):
            on, _, used = self.scan(True, base=base)
            off, _, _ = self.scan(False, base=base)
            self.assertTrue(used, base)
            self.assertEqual(on, off, base)
            self.assertIn(("vendorx/k.py", 2, "secret.my-token"), on)
            self.assertIn(("vendorx/k.py", 1, "secret.aws-access-token"), on)
            self.assertNotIn("src/live.py", {p for p, _, _ in on})   # the repo's own allowlist still applies
            self.assertNotIn("vendor/k.py", {p for p, _, _ in on})   # the exclude still applies


if __name__ == "__main__":
    unittest.main()
