#!/usr/bin/env python3
"""Tests for scripts/workflow_guard.py. Run: python3 tests/workflow_guard_test.py"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import workflow_guard as wg  # noqa: E402

HEAD, OLD = "b" * 40, "a" * 40


def review(user, state="APPROVED", sha=HEAD):
    """Build a review record shaped like the GitHub API's."""
    return {"user": {"login": user}, "state": state, "commit_id": sha}


class Protected(unittest.TestCase):
    def test_paths(self):
        for p in (".github/workflows/test.yml", ".github/workflows/sub/x.yaml", "action.yml", ".sast-check.toml",
                  ".gitleaks.toml", ".github/zizmor.yml", "osv-scanner.toml", "trivy.yaml", ".trivyignore",
                  ".github/CODEOWNERS", "scripts/workflow_guard.py"):
            self.assertTrue(wg.is_protected(p), p)
        for p in ("README.md", "scripts/sast.py", "src/.github/workflows/x.yml", "docs/action.yml"):
            self.assertFalse(wg.is_protected(p), p)


class Evaluate(unittest.TestCase):
    def run_guard(self, changed, reviews, roles=None, owners=()):
        """Run the decision with defaults; returns (ok, message)."""
        return wg.evaluate(changed, HEAD, reviews, roles or {}, set(owners))

    def test_no_protected_files_passes(self):
        self.assertTrue(self.run_guard(["README.md", "tools/x.py"], [])[0])

    def test_workflow_change_without_approval_fails(self):
        self.assertFalse(self.run_guard([".github/workflows/test.yml"], [])[0])

    def test_maintainer_approval_on_current_head_passes(self):
        self.assertTrue(self.run_guard(["action.yml"], [review("m")], {"m": "maintain"})[0])
        self.assertTrue(self.run_guard(["action.yml"], [review("a")], {"a": "admin"})[0])

    def test_approval_on_older_commit_fails(self):
        self.assertFalse(self.run_guard(["action.yml"], [review("m", sha=OLD)], {"m": "admin"})[0])

    def test_non_maintainer_approval_fails(self):
        self.assertFalse(self.run_guard(["action.yml"], [review("w")], {"w": "write"})[0])
        self.assertFalse(self.run_guard(["action.yml"], [review("w")], {"w": "none"})[0])

    def test_codeowner_approval_passes(self):
        self.assertTrue(self.run_guard(["action.yml"], [review("Owner")], {"Owner": "write"}, ["owner"])[0])

    def test_later_changes_requested_or_dismissed_revokes(self):
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            reviews = [review("m"), review("m", state)]
            self.assertFalse(self.run_guard(["action.yml"], reviews, {"m": "admin"})[0], state)

    def test_comment_after_approval_keeps_it(self):
        reviews = [review("m"), review("m", "COMMENTED")]
        self.assertTrue(self.run_guard(["action.yml"], reviews, {"m": "admin"})[0])

    def test_missing_role_fails_closed(self):
        self.assertFalse(self.run_guard(["action.yml"], [review("m")], {})[0])


class Main(unittest.TestCase):
    def api(self, pr, reviews, perms, files):
        """Return a fake GitHub API function over canned data."""
        def get(path):
            if path.endswith("/files"):
                return files
            if path.endswith("/reviews"):
                return reviews
            if "/collaborators/" in path:
                return perms[path.split("/")[-2]]
            if "/contents/.github/CODEOWNERS" in path:
                return {"content": ""}
            return pr
        return get

    def test_api_error_fails(self):
        def boom(path):
            raise RuntimeError("HTTP 502")
        ok, msg = wg.check("o/r", 5, "", boom)
        self.assertFalse(ok)
        self.assertIn("502", msg)

    def test_stale_event_head_fails(self):
        get = self.api({"head": {"sha": HEAD}, "base": {"ref": "main"}}, [], {}, [])
        self.assertFalse(wg.check("o/r", 5, OLD, get)[0])

    def test_rename_out_of_protected_path_counts(self):
        files = [{"filename": "x.yml", "previous_filename": ".github/workflows/test.yml"}]
        get = self.api({"head": {"sha": HEAD}, "base": {"ref": "main"}}, [], {}, files)
        self.assertFalse(wg.check("o/r", 5, HEAD, get)[0])

    def test_approved_end_to_end(self):
        get = self.api({"head": {"sha": HEAD}, "base": {"ref": "main"}}, [review("m")],
                       {"m": {"role_name": "maintain"}}, [{"filename": "action.yml"}])
        self.assertTrue(wg.check("o/r", 5, HEAD, get)[0])


if __name__ == "__main__":
    unittest.main()
