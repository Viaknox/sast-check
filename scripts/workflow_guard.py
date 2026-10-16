#!/usr/bin/env python3
"""Workflow guard: a PR that touches the gate's workflows or settings needs an admin's label on its current head.

Runs from the base branch only (see .github/workflows/workflow-guard.yml); never reads PR code. Stdlib only.

Approval model (label based, fail closed):
  * a repo admin/maintainer reviews the PR and adds the label APPROVAL_LABEL;
  * the label counts only if the LATEST `labeled` event for it was made by a human admin/maintainer AND the server
    timestamp of that event is strictly later than the first workflow run GitHub created for the current head commit
    (that run's created_at is when the head was pushed). Labels are not bound to a commit, and commit dates are
    forgeable by the PR author, so both timestamps used here are assigned by GitHub's servers;
  * a new commit therefore invalidates the approval by itself; removing the label on `synchronize` is only cleanup.
Env: GH_TOKEN, REPO, PR_NUMBER, HEAD_SHA (head the event was raised for), EVENT_ACTION (optional), and the optional
settings APPROVAL_LABEL, ALLOW_SELF_APPROVAL ("true" default / "false"). Settings come from the base workflow file only.
Any error fails the check (exit 1).
"""
import fnmatch
import json
import os
# sast-ignore[ruff.S404]: fixed argv to the gh CLI, no shell
import subprocess
import sys
from datetime import datetime
from urllib.parse import quote

APPROVAL_LABEL = "workflow-change-approved"
WORKFLOW_FILE = ".github/workflows/workflow-guard.yml"
PROTECTED = (".github/workflows/*", "action.yml", "action.yaml", "CODEOWNERS", ".github/CODEOWNERS",
             "docs/CODEOWNERS", ".sast-check.toml", ".gitleaks.toml", ".gitleaksignore", ".github/zizmor.yml",
             ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml", "osv-scanner.toml", "trivy.yaml", ".trivyignore",
             "scripts/workflow_guard.py")
TRUSTED_ROLES = ("admin", "maintain")
FILES_API_CAP = 3000


def is_protected(path: str) -> bool:
    """True if the path is a workflow, action, settings or guard file."""
    return any(fnmatch.fnmatchcase(path, p) for p in PROTECTED)


def is_trusted_permission(resp) -> bool:
    """True if a collaborator-permission response shows admin or maintain (custom roles included); unknown is False."""
    if not isinstance(resp, dict):
        return False
    perms = (resp.get("user") or {}).get("permissions")
    if isinstance(perms, dict) and (perms.get("admin") is True or perms.get("maintain") is True):
        return True   # privilege booleans reflect the base level a custom role inherits
    return resp.get("permission") == "admin" or resp.get("role_name") in TRUSTED_ROLES


def gh_get(path: str):
    """GET a GitHub API path with gh (paginated); raises RuntimeError on any failure."""
    try:
        # sast-ignore[ruff.S603]: argv is a fixed list; only the API path varies, no shell
        p = subprocess.run(["gh", "api", "--paginate", "--slurp", path], capture_output=True, text=True, timeout=120)  # sast-ignore[ruff.S607]: gh from the runner's PATH, as in test.yml
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"gh api {path}: {e}") from e
    if p.returncode != 0:
        raise RuntimeError(f"gh api {path}: {p.stderr.strip()[:300]}")
    data = json.loads(p.stdout)
    if isinstance(data, list) and data and all(isinstance(x, list) for x in data):
        data = [i for page in data for i in page]   # --slurp wraps each page; flatten lists
    elif isinstance(data, list) and len(data) == 1:
        data = data[0]
    return data




def gh_delete(path: str) -> None:
    """DELETE a GitHub API path with gh; raises RuntimeError on any failure."""
    try:
        # sast-ignore[ruff.S603]: argv is a fixed list; only the API path varies, no shell
        p = subprocess.run(["gh", "api", "-X", "DELETE", path], capture_output=True, text=True, timeout=120)  # sast-ignore[ruff.S607]: gh from the runner's PATH, as in test.yml
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"gh api -X DELETE {path}: {e}") from e
    if p.returncode != 0:
        raise RuntimeError(f"gh api -X DELETE {path}: {p.stderr.strip()[:300]}")


def clean(text) -> str:
    """Make attacker-controlled text (file names) safe for logs and the job summary: no control chars, markup or long lines."""
    out = "".join(c if c.isprintable() and c not in "`<>|\\" else "?" for c in str(text))
    return out[:200]


def listing(paths: list) -> str:
    """Comma-separated, sanitized list of at most 10 paths (with a count of the rest)."""
    shown = ", ".join(clean(p) for p in paths[:10])
    return shown + (f" and {len(paths) - 10} more" if len(paths) > 10 else "")


def parse_ts(value) -> datetime:
    """Parse a GitHub ISO-8601 timestamp into an aware datetime; raises ValueError when it is not one."""
    if not isinstance(value, str):
        raise ValueError(f"timestamp is not a string: {value!r}")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(f"timestamp has no time zone: {value!r}")
    return stamp


def same_label(a, b) -> bool:
    """True if both are strings naming the same label (GitHub label names are case-insensitive)."""
    return isinstance(a, str) and isinstance(b, str) and a.casefold() == b.casefold()


def has_label(info: dict, label: str) -> bool:
    """True if the PR (as returned by the pulls API) currently carries the label; a malformed labels field raises."""
    labels = info["labels"]
    if not isinstance(labels, list) or not all(isinstance(x, dict) for x in labels):
        raise TypeError("PR labels field is malformed")
    return any(same_label(x.get("name"), label) for x in labels)


def latest_label_event(events: list, label: str):
    """The `labeled` event for label with the highest id (the most recent), or None; malformed events raise."""
    if not isinstance(events, list):
        raise TypeError("issue events response is not a list")
    best = None
    for ev in events:
        if not isinstance(ev, dict):
            raise TypeError("issue event is not an object")
        lab = ev.get("label")
        if ev.get("event") == "labeled" and isinstance(lab, dict) and same_label(lab.get("name"), label):
            if not isinstance(ev.get("id"), int) or isinstance(ev.get("id"), bool):
                raise TypeError("labeled event has no integer id")
            if best is None or ev["id"] > best["id"]:
                best = ev
    return best


def first_push_time(resp, head: str, pr: int):
    """Earliest created_at of this guard's runs for head (when GitHub first saw the head), or None if there is none.

    resp is the actions/runs response: one object, or a list of page objects. Runs of other workflows, other events or
    other PRs are ignored; a matching run with a bad timestamp raises (fail closed).
    """
    pages = [resp] if isinstance(resp, dict) else resp
    if not isinstance(pages, list) or not all(isinstance(pg, dict) and isinstance(pg.get("workflow_runs"), list) for pg in pages):
        raise TypeError("workflow runs response is malformed")
    times = []
    for pg in pages:
        for run in pg["workflow_runs"]:
            if not isinstance(run, dict) or run.get("head_sha") != head or run.get("event") != "pull_request_target":
                continue
            if str(run.get("path") or "").split("@")[0] != WORKFLOW_FILE:
                continue
            prs = run.get("pull_requests")
            if isinstance(prs, list) and prs and not any(isinstance(p, dict) and p.get("number") == pr for p in prs):
                continue   # the same commit pushed for a different PR does not date this PR's push
            times.append(parse_ts(run["created_at"]))
    return min(times) if times else None


def check(repo: str, pr: int, event_head: str, get=gh_get, delete=gh_delete, action: str = "",
          label: str = APPROVAL_LABEL, allow_self: bool = True) -> tuple:
    """Decide (ok, message) for one PR from live server state; any error or odd value fails closed.

    get/delete are the API callables (replaced in tests); action is the event's action (synchronize removes the label).
    """
    try:
        info = get(f"repos/{repo}/pulls/{pr}")
        head = info["head"]["sha"]
        if not isinstance(head, str) or not head:
            return False, "PR head sha is missing (failing closed)"
        if not event_head or event_head != head:
            return False, (f"stale run: event is for {clean(event_head)[:7] or 'no commit'} but the PR head is {head[:7]}; "
                           "a newer run covers it")
        quoted = quote(label, safe="")
        if action == "synchronize" and has_label(info, label):   # cleanup only; the timestamp check does not rely on it
            try:
                delete(f"repos/{repo}/issues/{pr}/labels/{quoted}")
            except RuntimeError as e:
                info = get(f"repos/{repo}/pulls/{pr}")
                if has_label(info, label):
                    return False, f"could not remove the approval label `{clean(label)}` after a new commit (failing closed): {e}"
            info = get(f"repos/{repo}/pulls/{pr}")
            if info["head"]["sha"] != head:
                return False, f"the PR head moved during the check; a newer run covers it (was {head[:7]})"
        files = get(f"repos/{repo}/pulls/{pr}/files")
        total = int(info["changed_files"])
        if total >= FILES_API_CAP or len(files) != total:   # the files API silently stops at 3000
            return False, (f"file list incomplete (listed {len(files)} of {total}; API cap {FILES_API_CAP}): "
                           "cannot prove no protected file changed (failing closed)")
        changed = [n for f in files for n in (f["filename"], f.get("previous_filename")) if n]
        hit = sorted({p for p in changed if is_protected(p)})
        if not hit:
            return True, "no protected files changed"
        need = (f"This PR changes protected files ({listing(hit)}). A repo admin must review it and add the label "
                f"`{clean(label)}`. Any new commit removes the approval.")
        if not has_label(info, label):
            return False, need
        ev = latest_label_event(get(f"repos/{repo}/issues/{pr}/events"), label)
        if ev is None:
            return False, need + " (the label is present but no `labeled` event was found)"
        actor = ev.get("actor")
        login = actor.get("login") if isinstance(actor, dict) else None
        if (not isinstance(login, str) or not login or login.casefold().endswith("[bot]")
                or actor.get("type") != "User"):
            return False, f"the latest `{clean(label)}` label was not added by a human user; " + need
        if not is_trusted_permission(get(f"repos/{repo}/collaborators/{quote(login, safe='')}/permission")):
            return False, f"`{clean(login)}` added the label but is not a repo admin/maintainer; " + need
        if not allow_self:
            author = info["user"]["login"]
            if not isinstance(author, str) or author.casefold() == login.casefold():
                return False, f"`{clean(login)}` is the PR author and self-approval is disabled; another admin must add the label"
        pushed = first_push_time(get(f"repos/{repo}/actions/runs?head_sha={head}&event=pull_request_target&per_page=100"), head, pr)
        if pushed is None:
            return False, f"no workflow-guard run found for {head[:7]}, so its push time is unknown (failing closed); " + need
        if not parse_ts(ev.get("created_at")) > pushed:
            return False, f"the label was added before the current head {head[:7]} was pushed; " + need
        return True, f"approved: `{clean(label)}` added by `{clean(login)}` after {head[:7]} was pushed ({listing(hit)})"
    except (RuntimeError, KeyError, TypeError, ValueError, AttributeError) as e:
        return False, f"guard could not verify (failing closed): {clean(e)}"


def write_summary(ok: bool, head: str, msg: str) -> None:
    """Append the verdict, head SHA and required action to $GITHUB_STEP_SUMMARY when it is set."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    todo = "none" if ok else ("a repo admin must review the PR and add the approval label (see the message); "
                              "new commits remove it" if "label" in msg else "see the message; push a fix or re-run")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"### workflow-guard: {'PASS' if ok else 'FAIL'}\n\n- Head: `{clean(head)}`\n- {msg}\n- Action needed: {todo}\n")


def main() -> int:
    """Entry point: check the PR the event concerns; exit 1 on any failure."""
    try:
        repo, number, sha = os.environ["REPO"], int(os.environ["PR_NUMBER"]), os.environ["HEAD_SHA"]
    except (KeyError, ValueError) as e:
        print(f"workflow-guard: FAIL (missing or invalid event data): {clean(e)}")
        return 1
    label = os.environ.get("APPROVAL_LABEL") or APPROVAL_LABEL
    allow_self = os.environ.get("ALLOW_SELF_APPROVAL", "true").strip().lower() == "true"   # anything else is strict
    ok, msg = check(repo, number, sha, action=os.environ.get("EVENT_ACTION", ""), label=label, allow_self=allow_self)
    print(f"workflow-guard: PR #{number}: {'ok' if ok else 'FAIL'}: {msg}")
    write_summary(ok, sha, msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
