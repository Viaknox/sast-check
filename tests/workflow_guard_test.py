#!/usr/bin/env python3
"""Tests for scripts/workflow_guard.py (label-based approval). Run: python3 tests/workflow_guard_test.py"""
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import workflow_guard as wg  # noqa: E402

HEAD, OLD = "b" * 40, "a" * 40
LABEL = wg.APPROVAL_LABEL
T_PUSH, T_BEFORE, T_AFTER = "2026-01-01T10:00:00Z", "2026-01-01T09:00:00Z", "2026-01-01T11:00:00Z"
T_MID, T_LATE, T_END = "2026-01-01T09:30:00Z", "2026-01-01T10:30:00Z", "2026-01-01T12:00:00Z"
WF = [{"filename": ".github/workflows/test.yml"}]
ADMIN = {"role_name": "admin", "permission": "admin"}


def labeled(actor="own", at=T_AFTER, eid=10, kind="User", name=LABEL, event="labeled"):
    """Build an issue event shaped like the GitHub API's."""
    return {"id": eid, "event": event, "created_at": at, "label": {"name": name},
            "actor": None if actor is None else {"login": actor, "type": kind}}


def run(at=T_PUSH, sha=HEAD, path=".github/workflows/workflow-guard.yml@refs/heads/main", prs=(), event="pull_request_target",
        branch="feat", repo="o/r", conclusion="success", action="synchronize", title=None):
    """Build a workflow run shaped like the GitHub API's."""
    return {"head_sha": sha, "created_at": at, "path": path, "event": event, "conclusion": conclusion,
            "display_title": title if title is not None else f"workflow-guard {action} {sha}", "head_branch": branch,
            "head_repository": None if repo is None else {"full_name": repo}, "pull_requests": [{"number": n} for n in prs]}


class Fake:
    """Fake GitHub API over mutable canned state; records label deletions."""

    def __init__(self, files=WF, labels=(LABEL,), events=None, runs=None, perms=None, author="own", **pr):
        self.pr = {"head": {"sha": HEAD, "ref": "feat", "repo": {"full_name": "o/r"}}, "changed_files": len(files), "user": {"login": author}, **pr}
        self.labels = list(labels)
        self.files = files
        self.events = [labeled()] if events is None else events
        self.runs = [run()] if runs is None else runs
        self.perms = {"own": ADMIN} if perms is None else perms
        self.deleted = []
        self.fail_delete = False

    def get(self, path):
        """Answer a GET path from the canned state."""
        if path.endswith("/files"):
            return self.files
        if path.endswith("/events"):
            return self.events
        if "/collaborators/" in path:
            return self.perms[path.split("/")[-2]]
        if "/actions/runs" in path:
            return {"workflow_runs": self.runs}
        return {**self.pr, "labels": [{"name": n} for n in self.labels]}

    def delete(self, path):
        """Handle a label DELETE: remove it from the state or raise like gh would."""
        if self.fail_delete:
            raise RuntimeError("HTTP 403")
        self.deleted.append(path)
        self.labels = []

    def check(self, event_head=HEAD, **kw):
        """Run wg.check against this fake."""
        return wg.check("o/r", 5, event_head, self.get, self.delete, **kw)


class Protected(unittest.TestCase):
    def test_paths(self):
        for p in (".github/workflows/test.yml", ".github/workflows/sub/x.yaml", "action.yml", ".sast-check.toml",
                  ".gitleaks.toml", ".github/zizmor.yml", "osv-scanner.toml", "trivy.yaml", ".trivyignore",
                  ".github/CODEOWNERS", "scripts/workflow_guard.py"):
            self.assertTrue(wg.is_protected(p), p)
        for p in ("README.md", "scripts/sast.py", "src/.github/workflows/x.yml", "docs/action.yml"):
            self.assertFalse(wg.is_protected(p), p)


class Verdict(unittest.TestCase):
    def test_no_protected_paths_passes_without_label(self):
        f = Fake(files=[{"filename": "README.md"}], labels=[], events=[], runs=[])
        self.assertTrue(f.check()[0])
        self.assertTrue(Fake(files=[{"filename": "README.md"}]).check()[0])   # and whatever the label

    def test_protected_without_label_fails_with_clear_message(self):
        ok, msg = Fake(labels=[]).check()
        self.assertFalse(ok)
        self.assertIn("This PR changes protected files (.github/workflows/test.yml)", msg)
        self.assertIn(f"A repo admin must review it and add the label `{LABEL}`. Any new commit removes the approval.", msg)

    def test_label_by_trusted_human_after_push_passes(self):
        self.assertTrue(Fake().check()[0])
        self.assertTrue(Fake(perms={"own": {"role_name": "maintain"}}).check()[0])

    def test_label_before_latest_push_fails(self):
        for at in (T_BEFORE, T_PUSH):   # strictly later is required
            ok, msg = Fake(events=[labeled(at=at)]).check()
            self.assertFalse(ok, at)
            self.assertIn("before the current head", msg)

    def test_label_by_non_admin_fails(self):
        for resp in ({"role_name": "write", "permission": "write"}, {"permission": "read"}, {}):
            self.assertFalse(Fake(perms={"own": resp}).check()[0], resp)

    def test_label_by_bot_fails(self):
        self.assertFalse(Fake(events=[labeled(actor="github-actions[bot]", kind="Bot")], perms={"github-actions[bot]": ADMIN}).check()[0])
        self.assertFalse(Fake(events=[labeled(actor="x[bot]", kind="User")], perms={"x[bot]": ADMIN}).check()[0])
        self.assertFalse(Fake(events=[labeled(actor="own", kind="Bot")]).check()[0])
        self.assertFalse(Fake(events=[labeled(actor=None)]).check()[0])

    def test_latest_labeled_event_wins(self):
        f = Fake(events=[labeled("own", eid=10), labeled("rando", eid=11)], perms={"own": ADMIN, "rando": {"permission": "write"}})
        self.assertFalse(f.check()[0])
        f = Fake(events=[labeled("rando", eid=3), labeled("own", eid=9)], perms={"own": ADMIN, "rando": {"permission": "write"}})
        self.assertTrue(f.check()[0])   # order in the list does not matter, the highest id does
        self.assertTrue(Fake(events=[labeled("own", eid=9), labeled("rando", eid=3)], perms={"own": ADMIN}).check()[0])

    def test_other_labels_and_events_are_ignored(self):
        events = [labeled(name="bug", eid=50), labeled(event="unlabeled", eid=60, actor="rando")]
        self.assertFalse(Fake(events=events).check()[0])                       # no labeled event for ours
        self.assertTrue(Fake(events=[labeled(eid=1)] + events).check()[0])

    def test_stale_event_head_fails(self):
        self.assertFalse(Fake().check(event_head=OLD)[0])
        self.assertFalse(Fake().check(event_head="")[0])

    def test_no_workflow_run_for_head_fails(self):
        for runs in ([], [run(sha=OLD)], [run(path=".github/workflows/other.yml@refs/heads/main")], [run(event="pull_request")],
                     [run(prs=[99]), run(branch="other"), run(repo="evil/fork"), run(repo=None)]):
            ok, msg = Fake(runs=runs).check()
            self.assertFalse(ok, runs)
            self.assertIn("no matching workflow-guard run found", msg)

    def test_latest_push_run_dates_the_push(self):
        runs = [run(at=T_BEFORE), run(at=T_PUSH)]
        self.assertFalse(Fake(events=[labeled(at=T_MID)], runs=runs).check()[0])
        self.assertTrue(Fake(events=[labeled(at=T_LATE)], runs=runs).check()[0])
        pages = [{"workflow_runs": [run(at=T_BEFORE)]}, {"workflow_runs": [run(at=T_PUSH)]}]
        self.assertEqual(wg.push_time(pages, HEAD, 5, "feat", "o/r"), wg.parse_ts(T_PUSH))

    def test_repush_of_older_sha_after_label_fails(self):
        """The old sha already had a synchronize run; re-pushing it makes a new one, which voids the earlier label."""
        runs = [run(at=T_BEFORE), run(at=T_AFTER)]
        ok, msg = Fake(events=[labeled(at=T_LATE)], runs=runs).check()
        self.assertFalse(ok)
        self.assertIn("before the current head", msg)
        self.assertTrue(Fake(events=[labeled(at=T_END)], runs=runs).check()[0])   # label after the re-push passes
        f = Fake(events=[labeled(at=T_LATE)], runs=runs)
        f.check(action="synchronize")
        self.assertEqual(len(f.deleted), 1)                                         # and the tidy-up removes it

    def test_label_runs_never_count_as_a_push(self):
        for action in ("labeled", "unlabeled", "ready_for_review"):
            runs = [run(at=T_PUSH), run(at=T_AFTER, action=action)]
            self.assertTrue(Fake(events=[labeled(at=T_LATE)], runs=runs).check()[0], action)
        self.assertIsNone(wg.push_time([{"workflow_runs": [run(action="labeled")]}], HEAD, 5, "feat", "o/r"))

    def test_edited_run_invalidates_an_older_label(self):
        """An edited run (base retarget or title edit) counts as a push: fail closed."""
        runs = [run(at=T_PUSH), run(at=T_AFTER, action="edited")]
        self.assertFalse(Fake(events=[labeled(at=T_LATE)], runs=runs).check(action="edited")[0])
        self.assertTrue(Fake(events=[labeled(at=T_END)], runs=runs).check(action="edited")[0])

    def test_display_title_mismatch_is_ignored(self):
        for title in ("evil", "workflow-guard synchronize " + OLD, "workflow-guard synchronize " + HEAD + " x", "", None):
            runs = [run(at=T_PUSH), {**run(at=T_AFTER), "display_title": title}]
            self.assertTrue(Fake(events=[labeled(at=T_LATE)], runs=runs).check()[0], title)   # the odd run is not a push
            ok, msg = Fake(runs=[{**run(at=T_PUSH), "display_title": title}]).check()
            self.assertFalse(ok, title)
            self.assertIn("no matching workflow-guard run", msg)

    def test_cancelled_run_still_dates_the_push(self):
        """A run cancelled by concurrency stays in the runs list; it counts, whatever its conclusion or status."""
        runs = [run(at=T_PUSH), run(at=T_AFTER, conclusion="cancelled")]
        self.assertFalse(Fake(events=[labeled(at=T_LATE)], runs=runs).check()[0])
        self.assertTrue(Fake(events=[labeled(at=T_END)], runs=runs).check()[0])
        f = Fake(events=[labeled(at=T_LATE)], runs=runs)
        f.check(action="synchronize")
        self.assertEqual(len(f.deleted), 1)

    def test_runs_of_other_branch_repo_or_pr_are_ignored(self):
        """Runs for the same sha elsewhere (also with empty pull_requests) must not date this PR's push."""
        good = run(at=T_PUSH, prs=())
        for bad in (run(at=T_AFTER, prs=(), branch="other"), run(at=T_AFTER, prs=(), repo="evil/fork"),
                    run(at=T_AFTER, prs=(), repo=None), run(at=T_AFTER, prs=[99])):
            self.assertEqual(wg.push_time([{"workflow_runs": [bad, good]}], HEAD, 5, "feat", "o/r"), wg.parse_ts(T_PUSH))
            self.assertTrue(Fake(events=[labeled(at=T_LATE)], runs=[bad, good]).check()[0])
            self.assertFalse(Fake(events=[labeled(at=T_MID)], runs=[bad, good]).check()[0])
        f = Fake()
        f.pr["head"]["repo"] = None   # deleted fork
        self.assertFalse(f.check()[0])

    def test_api_error_fails(self):
        f = Fake()
        def boom(path):
            raise RuntimeError("HTTP 502")
        ok, msg = wg.check("o/r", 5, HEAD, boom, f.delete)
        self.assertFalse(ok)
        self.assertIn("502", msg)
        def runs_boom(path):
            if "/actions/runs" in path:
                raise RuntimeError("HTTP 500")
            return f.get(path)
        self.assertFalse(wg.check("o/r", 5, HEAD, runs_boom, f.delete)[0])

    def test_unparseable_or_missing_timestamp_fails(self):
        for bad in ("yesterday", "2026-01-01T10:00:00", None, 5):
            self.assertFalse(Fake(events=[labeled(at=bad)]).check()[0], bad)
            self.assertFalse(Fake(runs=[run(at=bad)]).check()[0], bad)

    def test_malformed_responses_fail_closed(self):
        self.assertFalse(Fake(events="nope").check()[0])
        self.assertFalse(Fake(events=[labeled(eid="x")]).check()[0])
        self.assertFalse(Fake(events=[{"id": 1, "event": "labeled", "label": {"name": LABEL}, "created_at": T_AFTER}]).check()[0])
        f = Fake()
        def odd(path):
            r = f.get(path)
            return {**r, "labels": "x"} if path.endswith("/pulls/5") else r
        self.assertFalse(wg.check("o/r", 5, HEAD, odd, f.delete)[0])

    def test_self_approval_setting(self):
        self.assertTrue(Fake(author="own").check(allow_self=True)[0])
        ok, msg = Fake(author="own").check(allow_self=False)
        self.assertFalse(ok)
        self.assertIn("self-approval is disabled", msg)
        self.assertFalse(Fake(author="OWN").check(allow_self=False)[0])
        self.assertTrue(Fake(author="someone").check(allow_self=False)[0])

    def test_synchronize_removes_stale_label_and_failed_removal_fails(self):
        stale = [labeled(at=T_BEFORE)]
        f = Fake(events=stale)
        ok, msg = f.check(action="synchronize")
        self.assertEqual(f.deleted, [f"repos/o/r/issues/5/labels/{LABEL}"])
        self.assertFalse(ok)                       # the label is gone, so the PR needs a fresh approval
        self.assertIn("add the label", msg)
        f = Fake(files=[{"filename": "README.md"}], events=stale)
        self.assertTrue(f.check(action="synchronize")[0])
        self.assertEqual(len(f.deleted), 1)        # cleanup happens even when nothing is protected
        f = Fake(events=stale)
        f.fail_delete = True
        ok, msg = f.check(action="synchronize")
        self.assertFalse(ok)
        self.assertIn("could not remove", msg)
        f = Fake(files=[{"filename": "README.md"}], events=stale)
        f.fail_delete = True
        self.assertFalse(f.check(action="synchronize")[0])
        f = Fake(events=stale)
        f.check(action="labeled")
        self.assertEqual(f.deleted, [])            # other actions never remove it
        for ev in ([], [labeled(at=T_PUSH)]):       # no labeled event, or one at (not after) the push, is stale too
            f = Fake(events=ev)
            f.check(action="synchronize")
            self.assertEqual(len(f.deleted), 1)
        f = Fake(runs=[])                           # push time unknown: stale
        f.check(action="synchronize")
        self.assertEqual(len(f.deleted), 1)

    def test_synchronize_keeps_label_added_after_push(self):
        """A label an admin added after the new head was pushed must survive a delayed synchronize run."""
        f = Fake(events=[labeled(at=T_AFTER)])
        ok, msg = f.check(action="synchronize")
        self.assertEqual(f.deleted, [])
        self.assertTrue(ok, msg)

    def test_base_change_after_label_voids_it(self):
        """A retarget after the label means the approved diff may differ: fail. A retarget before the label is fine."""
        retarget = lambda at, eid=5: {"id": eid, "event": "base_ref_changed", "created_at": at, "actor": {"login": "x", "type": "User"}}
        ok, msg = Fake(events=[labeled(at=T_AFTER), retarget(T_LATE)]).check(action="edited")
        self.assertTrue(ok, msg)                                              # base changed 10:30, label 11:00
        ok, msg = Fake(events=[labeled(at=T_LATE), retarget(T_AFTER)]).check(action="edited")
        self.assertFalse(ok)
        self.assertIn("base branch changed", msg)
        self.assertFalse(Fake(events=[labeled(at=T_AFTER), retarget(T_AFTER)]).check()[0])   # same instant: not strictly later
        self.assertFalse(Fake(events=[labeled(at=T_AFTER), retarget("garbage")]).check()[0])
        self.assertTrue(Fake(files=[{"filename": "README.md"}], events=[retarget(T_AFTER)], labels=[]).check()[0])

    def test_ci_runs_the_guard_tests(self):
        """tests/workflow_guard_test.py must be a CI step in test.yml (it needs the PyYAML installed there)."""
        text = (ROOT / ".github/workflows/test.yml").read_text()
        self.assertIn("python tests/workflow_guard_test.py", text)
        self.assertIn("pyyaml", text)

    def test_old_label_is_invalid_without_cleanup(self):
        """Security must not depend on the cleanup: a label from before the push fails even if it was never removed."""
        self.assertFalse(Fake(events=[labeled(at=T_BEFORE)]).check(action="labeled")[0])

    def test_rename_out_of_protected_path_counts(self):
        files = [{"filename": "x.yml", "previous_filename": ".github/workflows/test.yml"}]
        self.assertFalse(Fake(files=files, labels=[]).check()[0])

    def test_truncated_file_list_fails_closed(self):
        """Fewer files listed than changed_files, or the 3000 cap, must fail."""
        files = [{"filename": "a.txt"}]
        f = Fake(files=files)
        f.pr["changed_files"] = 2
        ok, msg = f.check()
        self.assertFalse(ok)
        self.assertIn("incomplete", msg)
        f = Fake(files=[{"filename": f"f{i}"} for i in range(3000)])
        self.assertFalse(f.check()[0])
        f = Fake(files=files)
        del f.pr["changed_files"]
        self.assertFalse(f.check()[0])

    def test_custom_role_inheriting_admin_or_maintain_is_trusted(self):
        """Custom role names are judged by privilege booleans / legacy permission."""
        for resp in ({"role_name": "release-captain", "permission": "write", "user": {"permissions": {"maintain": True}}},
                     {"role_name": "super", "permission": "admin", "user": {"permissions": {}}},
                     {"role_name": "super", "permission": "write", "user": {"permissions": {"admin": True}}}):
            self.assertTrue(Fake(perms={"own": resp}).check()[0], resp)
        for resp in ({"role_name": "triager", "permission": "read", "user": {"permissions": {"push": True}}},
                     {"role_name": "x"}, {"permission": "write"}, {}):
            self.assertFalse(Fake(perms={"own": resp}).check()[0], resp)


class WorkflowFile(unittest.TestCase):
    def load(self):
        """Parse the guard workflow with yaml (YAML 1.1 reads `on` as True)."""
        doc = yaml.safe_load((ROOT / ".github/workflows/workflow-guard.yml").read_text())
        return doc, doc.get("on", doc.get(True))

    def test_triggers_permissions_concurrency(self):
        doc, on = self.load()
        self.assertEqual(set(on), {"pull_request_target"})
        self.assertEqual(sorted(on["pull_request_target"]["types"]),
                         sorted(["opened", "reopened", "synchronize", "ready_for_review", "labeled", "unlabeled", "edited"]))
        self.assertNotIn("workflow_run", on)
        self.assertEqual(doc["permissions"], {"contents": "read", "pull-requests": "write", "actions": "read"})
        self.assertEqual(doc["concurrency"], {"group": "workflow-guard-${{ github.event.pull_request.number }}", "cancel-in-progress": False})
        self.assertEqual(doc["run-name"], "workflow-guard ${{ github.event.action }} ${{ github.event.pull_request.head.sha }}")
        self.assertEqual(list(doc["jobs"]), ["guard"])

    def test_no_pr_code_and_no_expressions_in_run(self):
        doc, _ = self.load()
        steps = doc["jobs"]["guard"]["steps"]
        self.assertEqual(steps[0]["uses"].split("@")[0], "actions/checkout")
        self.assertNotIn("ref", steps[0].get("with", {}))
        self.assertFalse(steps[0]["with"].get("persist-credentials", True))
        for s in steps:
            self.assertNotIn("${{", s.get("run", ""))
        self.assertEqual(steps[1]["env"]["ALLOW_SELF_APPROVAL"], "true")
        self.assertEqual(steps[1]["env"]["APPROVAL_LABEL"], wg.APPROVAL_LABEL)

    def test_retrigger_workflow_is_gone(self):
        self.assertFalse((ROOT / ".github/workflows/workflow-guard-retrigger.yml").exists())
        for f in (ROOT / ".github/workflows").glob("*.y*ml"):
            doc = yaml.safe_load(f.read_text())
            triggers = doc.get("on", doc.get(True))
            self.assertNotIn("workflow_run", triggers if isinstance(triggers, (dict, list)) else [triggers], f.name)

if __name__ == "__main__":
    unittest.main()
