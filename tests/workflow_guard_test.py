#!/usr/bin/env python3
"""Tests for scripts/workflow_guard.py. Run: python3 tests/workflow_guard_test.py"""
import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import workflow_guard as wg  # noqa: E402

HEAD, OLD = "b" * 40, "a" * 40
PR = {"head": {"sha": HEAD}, "base": {"ref": "main"}, "changed_files": 1}


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
        """Run the decision with defaults; roles maps login to a role, owners are logins owning everything."""
        trusted = {u for u, r in (roles or {}).items() if r in wg.TRUSTED_ROLES}
        rules = wg.parse_codeowners("* " + " ".join("@" + o for o in owners)) if owners else []
        return wg.evaluate(changed, HEAD, reviews, trusted, rules)

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
    def api(self, pr, reviews, perms, files, codeowners=""):
        """Return a fake GitHub API function over canned data."""
        def get(path):
            if path.endswith("/files"):
                return files
            if path.endswith("/reviews"):
                return reviews
            if "/collaborators/" in path:
                return perms[path.split("/")[-2]]
            if "/contents/.github/CODEOWNERS" in path:
                return {"content": base64.b64encode(codeowners.encode()).decode()}
            return pr
        return get

    def test_api_error_fails(self):
        def boom(path):
            raise RuntimeError("HTTP 502")
        ok, msg = wg.check("o/r", 5, "", boom)
        self.assertFalse(ok)
        self.assertIn("502", msg)

    def test_stale_event_head_fails(self):
        get = self.api({**PR, "changed_files": 0}, [], {}, [])
        self.assertFalse(wg.check("o/r", 5, OLD, get)[0])

    def test_rename_out_of_protected_path_counts(self):
        files = [{"filename": "x.yml", "previous_filename": ".github/workflows/test.yml"}]
        get = self.api(PR, [], {}, files)
        self.assertFalse(wg.check("o/r", 5, HEAD, get)[0])

    def test_approved_end_to_end(self):
        get = self.api(PR, [review("m")],
                       {"m": {"role_name": "maintain"}}, [{"filename": "action.yml"}])
        self.assertTrue(wg.check("o/r", 5, HEAD, get)[0])

    def test_truncated_file_list_fails_closed(self):
        """Fewer files listed than changed_files, or the 3000 cap, must fail (threads 4298042457/4298076538/4298129563)."""
        files = [{"filename": "a.txt"}]
        ok, msg = wg.check("o/r", 5, HEAD, self.api({**PR, "changed_files": 2}, [], {}, files))
        self.assertFalse(ok)
        self.assertIn("incomplete", msg)
        capped = [{"filename": f"f{i}"} for i in range(3000)]
        self.assertFalse(wg.check("o/r", 5, HEAD, self.api({**PR, "changed_files": 3000}, [], {}, capped))[0])
        self.assertFalse(wg.check("o/r", 5, HEAD, self.api({k: v for k, v in PR.items() if k != "changed_files"}, [], {}, files))[0])
        self.assertTrue(wg.check("o/r", 5, HEAD, self.api(PR, [], {}, files))[0])

    def test_custom_role_inheriting_admin_or_maintain_is_trusted(self):
        """Custom role names are judged by privilege booleans / legacy permission (thread 4298042477)."""
        for resp in ({"role_name": "release-captain", "permission": "write", "user": {"permissions": {"maintain": True}}},
                     {"role_name": "super", "permission": "admin", "user": {"permissions": {}}},
                     {"role_name": "super", "permission": "write", "user": {"permissions": {"admin": True}}}):
            get = self.api(PR, [review("c")], {"c": resp}, [{"filename": "action.yml"}])
            self.assertTrue(wg.check("o/r", 5, HEAD, get)[0], resp)
        for resp in ({"role_name": "triager", "permission": "read", "user": {"permissions": {"push": True}}},
                     {"role_name": "x"}, {"permission": "write"}, {}):
            get = self.api(PR, [review("c")], {"c": resp}, [{"filename": "action.yml"}])
            self.assertFalse(wg.check("o/r", 5, HEAD, get)[0], resp)

    def test_codeowners_last_matching_rule_per_path(self):
        """Only an individual owner of the path's last matching rule counts (thread 4298042472)."""
        text = "* @alice\n/docs/ @docsguy\n/.github/workflows/ @ciguy @org/team\n"
        wf = [{"filename": ".github/workflows/test.yml"}]
        low = {"d": {"permission": "write"}}
        for who, want in (("ciguy", True), ("docsguy", False), ("alice", False), ("org", False)):
            get = self.api(PR, [review(who)], {who: low["d"]}, wf, text)
            self.assertEqual(wg.check("o/r", 5, HEAD, get)[0], want, who)

    def test_codeowners_every_path_needs_cover(self):
        """Two protected paths with different owners: one owner is not enough, two together are."""
        text = "action.yml @a\n.sast-check.toml @b\n"
        files = [{"filename": "action.yml"}, {"filename": ".sast-check.toml"}]
        pr = {**PR, "changed_files": 2}
        w = {"permission": "write"}
        self.assertFalse(wg.check("o/r", 5, HEAD, self.api(pr, [review("a")], {"a": w}, files, text))[0])
        self.assertTrue(wg.check("o/r", 5, HEAD, self.api(pr, [review("a"), review("b")], {"a": w, "b": w}, files, text))[0])
        self.assertTrue(wg.check("o/r", 5, HEAD, self.api(pr, [review("m")], {"m": {"permission": "admin"}}, files, text))[0])


class CodeownersMatch(unittest.TestCase):
    def owners(self, text, path):
        """Owners of path under the given CODEOWNERS text."""
        return wg.owners_for(path, wg.parse_codeowners(text))

    def test_patterns(self):
        t = "* @s\n/a/*.yml @x\ndocs/ @d\n**/logs @l\n/build/** @b\n"
        self.assertEqual(self.owners(t, "README.md"), {"s"})
        self.assertEqual(self.owners(t, "a/k.yml"), {"x"})
        self.assertEqual(self.owners(t, "a/sub/k.yml"), {"s"})
        self.assertEqual(self.owners(t, "z/docs/n.md"), {"d"})
        self.assertEqual(self.owners(t, "p/logs/x"), {"l"})
        self.assertEqual(self.owners(t, "build/o/p"), {"b"})

    def test_no_owner_and_unparseable_fail_closed(self):
        self.assertEqual(self.owners("* @s\n/a.yml\n", "a.yml"), set())
        self.assertEqual(self.owners("* @s\n[ab].yml @t\n", "a.yml"), set())
        self.assertEqual(self.owners("* @s\n!x.yml @t\n", "q"), set())
        self.assertEqual(self.owners("", "a"), set())


if __name__ == "__main__":
    unittest.main()
