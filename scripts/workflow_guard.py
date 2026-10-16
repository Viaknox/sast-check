#!/usr/bin/env python3
"""Workflow guard: a PR that touches the gate's workflows or settings needs a trusted approval of its current head.

Runs from the base branch only (see .github/workflows/workflow-guard.yml); never reads PR code. Stdlib only.
Env: GH_TOKEN, REPO, PR_NUMBER (optional), HEAD_SHA (the commit the event was raised for).
Any error fails the check (exit 1).
"""
import base64
import fnmatch
import json
import os
import re
# sast-ignore[ruff.S404]: fixed argv to the gh CLI, no shell
import subprocess
import sys

PROTECTED = (".github/workflows/*", "action.yml", "action.yaml", "CODEOWNERS", ".github/CODEOWNERS",
             "docs/CODEOWNERS", ".sast-check.toml", ".gitleaks.toml", ".gitleaksignore", ".github/zizmor.yml",
             ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml", "osv-scanner.toml", "trivy.yaml", ".trivyignore",
             "scripts/workflow_guard.py")
TRUSTED_ROLES = ("admin", "maintain")
FILES_API_CAP = 3000


def is_protected(path: str) -> bool:
    """True if the path is a workflow, action, settings or guard file."""
    return any(fnmatch.fnmatchcase(path, p) for p in PROTECTED)


def current_approvers(reviews: list, head_sha: str) -> list:
    """Logins whose latest decisive review is an approval of exactly head_sha."""
    latest = {}
    for r in reviews:
        if r.get("state") in ("COMMENTED", "PENDING"):
            continue   # a plain comment neither grants nor revokes
        latest[r["user"]["login"]] = r
    return [u for u, r in latest.items() if r["state"] == "APPROVED" and r.get("commit_id") == head_sha]


def evaluate(changed: list, head_sha: str, reviews: list, trusted: set, rules: list) -> tuple:
    """Decide (ok, message): every protected path needs an approval of head_sha from a trusted user or an owner of that path.

    trusted is the set of approver logins with admin/maintain; rules is parse_codeowners() output.
    """
    hit = sorted({p for p in changed if is_protected(p)})
    if not hit:
        return True, "no protected files changed"
    approvers = current_approvers(reviews, head_sha)
    if any(u in trusted for u in approvers):
        missing = []   # an admin/maintainer approval covers every path
    else:
        missing = [p for p in hit if not any(u.lower() in owners_for(p, rules) for u in approvers)]
    if not missing:
        return True, f"approved at {head_sha[:7]} by trusted reviewers"
    return False, (f"protected files changed ({', '.join(missing[:5])}{' ...' if len(missing) > 5 else ''}): needs an "
                   f"approval of {head_sha[:7]} from a repo admin/maintainer or a CODEOWNER of each path")


def is_trusted_permission(resp) -> bool:
    """True if a collaborator-permission response shows admin or maintain (custom roles included); unknown is False."""
    if not isinstance(resp, dict):
        return False
    perms = (resp.get("user") or {}).get("permissions")
    if isinstance(perms, dict) and (perms.get("admin") is True or perms.get("maintain") is True):
        return True   # privilege booleans reflect the base level a custom role inherits
    return resp.get("permission") == "admin" or resp.get("role_name") in TRUSTED_ROLES


def pattern_regex(pat: str):
    """Compile a gitignore-style CODEOWNERS pattern to a regex over repo paths; None if it cannot be parsed."""
    if not pat or any(c in pat for c in "!\\[]"):
        return None
    dir_only = pat.endswith("/")
    pat = pat.rstrip("/")
    anchored = "/" in pat
    pat = pat.lstrip("/")
    if not pat:
        return None
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**/", i) and i == 0:
            out, i = out + "(?:.*/)?", i + 3
        elif pat.startswith("/**/", i):
            out, i = out + "/(?:.*/)?", i + 4
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out, i = out + "/.*", i + 3
        elif pat[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pat[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pat[i]), i + 1
    return re.compile(("^" if anchored else "^(?:.*/)?") + out + ("/.*$" if dir_only else "(?:/.*)?$"))


def parse_codeowners(text: str) -> list:
    """CODEOWNERS text -> ordered [(regex or None, individual @user logins)]; teams and emails are dropped (fail closed)."""
    rules = []
    for line in text.splitlines():
        toks = line.split("#", 1)[0].split()
        if toks:
            users = {t[1:].lower() for t in toks[1:] if t.startswith("@") and "/" not in t}
            rules.append((pattern_regex(toks[0]), users))
    return rules


def owners_for(path: str, rules: list) -> set:
    """Individual owners of the LAST rule matching path; an unparseable rule counts as matching with no owner."""
    owners = set()
    for rx, users in rules:
        if rx is None or rx.match(path):
            owners = users if rx is not None else set()
    return owners


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


def check(repo: str, pr: int, event_head: str, get=gh_get) -> tuple:
    """Fetch the PR's live state through get() and evaluate it."""
    try:
        info = get(f"repos/{repo}/pulls/{pr}")
        head = info["head"]["sha"]
        if event_head and event_head != head:
            return False, f"stale run: event is for {event_head[:7]} but the PR head is {head[:7]}; a newer run covers it"
        files = get(f"repos/{repo}/pulls/{pr}/files")
        total = int(info["changed_files"])
        if total >= FILES_API_CAP or len(files) != total:   # the files API silently stops at 3000
            return False, (f"file list incomplete (listed {len(files)} of {total}; API cap {FILES_API_CAP}): "
                           "cannot prove no protected file changed (failing closed)")
        changed = [n for f in files for n in (f["filename"], f.get("previous_filename")) if n]
        if not any(is_protected(p) for p in changed):
            return True, "no protected files changed"
        reviews = get(f"repos/{repo}/pulls/{pr}/reviews")
        trusted = {u for u in current_approvers(reviews, head) if is_trusted_permission(get(f"repos/{repo}/collaborators/{u}/permission"))}
        rules = []
        try:   # CODEOWNERS is read from the base branch, never the PR
            doc = get(f"repos/{repo}/contents/.github/CODEOWNERS?ref={info['base']['ref']}")
            rules = parse_codeowners(base64.b64decode(doc.get("content", "")).decode("utf-8", "replace"))
        except RuntimeError as e:
            if "HTTP 404" not in str(e):
                raise
        return evaluate(changed, head, reviews, trusted, rules)
    except (RuntimeError, KeyError, TypeError, ValueError, AttributeError) as e:
        return False, f"guard could not verify (failing closed): {e}"


def resolve_pr(repo: str, number: str, sha: str, get=gh_get) -> list:
    """PR numbers to check: the given one, or the open PRs whose head is sha (workflow_run events)."""
    if number:
        return [int(number)]
    prs = get(f"repos/{repo}/commits/{sha}/pulls")
    return [p["number"] for p in prs if p.get("state") == "open" and p["head"]["sha"] == sha]


def main() -> int:
    """Entry point: check every PR the event concerns; exit 1 on any failure."""
    repo, sha = os.environ["REPO"], os.environ.get("HEAD_SHA", "")
    try:
        numbers = resolve_pr(repo, os.environ.get("PR_NUMBER", ""), sha)
    except (RuntimeError, KeyError, TypeError, ValueError) as e:
        print(f"workflow-guard: FAIL (could not find the PR): {e}")
        return 1
    if not numbers:
        print("workflow-guard: no open PR at this commit; nothing to check")
        return 0
    bad = 0
    for n in numbers:
        ok, msg = check(repo, n, sha)
        print(f"workflow-guard: PR #{n}: {'ok' if ok else 'FAIL'}: {msg}")
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
