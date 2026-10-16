#!/usr/bin/env python3
"""False-positive sweep: run the custom Opengrep rules over a pinned corpus of well-maintained open-source
repositories (tools/fp-corpus.json) and collect every finding for triage.

Each finding is labelled later (by a reviewer or a triage agent) as:
  fp      - the code is safe; the rule is wrong here -> becomes an ok: fixture (hand-written, never copied)
  tp      - a real weakness -> NOT published: keep it local, follow the project's security policy
  tp_test - the rule is right, but only in test/example/docs code (a path-handling signal, not a rule bug)
  unclear - needs a closer look
Per-rule noise = fp / (fp + tp + tp_test). Raw findings (paths, lines, snippets) stay in --work and are never committed;
the committed report (--report) has only per-rule counts; repositories are named only for false positives (a rule
bug), never for correct findings, and tp is reported only inside a combined "correct" count.
The report is refused unless the labels match --work/findings.json one to one.

Usage:
  tools/fp_sweep.py --work /tmp/fp                       # clone (cached) + scan; writes /tmp/fp/findings.json
  tools/fp_sweep.py --work /tmp/fp --labels labels.json --report docs/fp-report.json
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tools" / "fp-corpus.json"


LABELS = ("fp", "tp", "tp_test", "unclear")


def git(d: Path, *args: str) -> subprocess.CompletedProcess:
    """Run git in d with a timeout (a hung network or lock never stalls the sweep)."""
    return subprocess.run(["git", *args], cwd=d, capture_output=True, text=True, timeout=900)


def checkout(work: Path, repo: str, sha: str) -> Path:
    """A clean checkout of repo at sha: a cached clone is reset and cleaned, so local edits or stray files
    from an earlier inspection never reach the scan."""
    d = work / "repos" / repo.replace("/", "__")
    if not ((d / ".git").exists() and git(d, "rev-parse", "HEAD").stdout.strip() == sha):
        d.mkdir(parents=True, exist_ok=True)
        for args in (["init", "-q"], ["remote", "add", "origin", f"https://github.com/{repo}.git"],
                     ["fetch", "-q", "--depth", "1", "origin", sha], ["checkout", "-q", "FETCH_HEAD"]):
            r = git(d, *args)
            if r.returncode and "already exists" not in r.stderr:
                raise RuntimeError(f"{repo}: git {' '.join(args)}: {r.stderr.strip()[:200]}")
    for args in (["reset", "-q", "--hard", sha], ["clean", "-qfdx"]):
        if git(d, *args).returncode:
            raise RuntimeError(f"{repo}: git {' '.join(args)} failed")
    if git(d, "rev-parse", "HEAD").stdout.strip() != sha or git(d, "status", "--porcelain").stdout.strip():
        raise RuntimeError(f"{repo}: checkout is not a clean copy of {sha}")
    return d


def rules_digest() -> str:
    """Hash of the rule bundle and the Opengrep version the sweep scans with: findings from another rule
    revision or engine version are stale (targeting and parsing can change between versions)."""
    eng, ver = shutil.which("opengrep"), "none"
    if eng:   # a version we cannot read must not hash as "" and match another engine's findings
        try:
            r = subprocess.run([eng, "--version"], capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ValueError(f"cannot read the Opengrep version: {e}") from e
        ver = r.stdout.strip()
        if r.returncode or not ver:
            raise ValueError(f"cannot read the Opengrep version: `opengrep --version` exited {r.returncode} "
                             f"with output {ver!r}")
    return hashlib.sha256((ROOT / "dist" / "rules.yaml").read_bytes() + b"\0" + ver.encode()).hexdigest()[:16]


def scan(work: Path, repo: str, d: Path, sha: str, digest: str) -> list[dict]:
    """Opengrep findings for one checkout, from a fresh sast.py run (never an older report), tagged with the
    commit and rule bundle they came from."""
    out = work / "out" / repo.replace("/", "__")
    (out / "findings.json").unlink(missing_ok=True)
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "sast.py"), "--repo", str(d), "--mode", "full",
                        "--only", "opengrep", "--out", str(out)], capture_output=True, text=True, timeout=3600)
    if r.returncode not in (0, 1):   # 0 pass, 1 blocking findings; anything else is a failed run
        raise RuntimeError(f"{repo}: sast.py exited {r.returncode}: {r.stderr.strip()[-200:]}")
    data = json.loads((out / "findings.json").read_text())
    og = [x for x in data.get("runs", []) if x.get("name") == "opengrep"]
    if not og or og[0].get("status") != "ran":   # skipped (not installed) or error: nothing was scanned
        raise RuntimeError(f"{repo}: opengrep did not run: {og[0] if og else 'no run recorded'}")
    found = []
    for f in data["findings"]:
        try:
            lines = (d / f["path"]).read_text(errors="ignore").splitlines()
            snippet = "\n".join(lines[max(0, f["line"] - 4): f["line"] + 3])
        except OSError:
            snippet = ""
        found.append({"repo": repo, "sha": sha, "rules": digest, "rule": f["rule"], "path": f["path"], "line": f["line"],
                      "end_line": f.get("end_line"),
                      "severity": f["severity"], "message": f["message"], "context": snippet})
    return found


def key(x: dict) -> tuple:
    """Location of a finding or a label (several findings can share one)."""
    return x["repo"], x["rule"], x["path"], x["line"]


def finding_id(x: dict) -> str:
    """Full identity of a finding: location plus end line and message (sast.py keeps findings apart by both)."""
    ident = json.dumps([*key(x), x.get("end_line"), x.get("message")])
    return hashlib.sha1(ident.encode(), usedforsecurity=False).hexdigest()[:12]


def report(work: Path, labels: list[dict], corpus: list[dict]) -> dict:
    """Aggregate labels into per-rule counts. Labels must match the current findings one to one (by `id`, or by
    location when exactly one finding is there), so a partial, duplicated or stale label file never yields a
    plausible score. The report names repositories only for false positives (a rule bug): a correct finding is
    never attributed to a repository, so a third-party weakness cannot be located from the committed report."""
    allf = json.loads((work / "findings.json").read_text())
    # only findings from the pinned commit and the current rule bundle count; older ones stay for triage
    pinned, digest = {c["repo"]: c["sha"] for c in corpus}, rules_digest()
    findings = [x for x in allf if pinned.get(x["repo"]) == x.get("sha") and x.get("rules") == digest]
    sc = work / "scanned.json"
    scanned = json.loads(sc.read_text()) if sc.exists() else {}
    scanned = scanned if isinstance(scanned, dict) else {}   # an older list-format file records no SHA: ignored
    current = {x["repo"] for x in findings} | {r for r, v in scanned.items() if v == [pinned.get(r), digest]}
    by_id = {finding_id(x): x for x in findings}
    at: dict[tuple, list[str]] = {}
    for i, x in by_id.items():
        at.setdefault(key(x), []).append(i)
    stale_loc = {key(x) for x in allf} - set(at)   # labels for stale findings stay in the file but do not count
    stale_ids = {finding_id(x) for x in allf} - set(by_id)   # the same, for labels that carry an id
    problems, labelled, matched = [], Counter(), {}
    if bad := sorted({x.get("label") for x in labels} - set(LABELS), key=str):
        problems.append(f"unknown labels {bad} (allowed: {', '.join(LABELS)})")
    for x in labels:
        if x["repo"] not in current or x.get("id") in stale_ids or (not x.get("id") and key(x) in stale_loc):
            continue
        ids = [x["id"]] if x.get("id") else at.get(key(x), [])
        if len(ids) != 1 or ids[0] not in by_id:
            problems.append(f"label {key(x)} matches {'no' if not ids or ids[0] not in by_id else 'more than one'} "
                            "current finding (give it the finding's id)")
            continue
        if x.get("id") and key(x) != key(by_id[ids[0]]):
            problems.append(f"label {key(x)} carries the id of a different finding {key(by_id[ids[0]])}")
            continue
        labelled[ids[0]] += 1
        matched[ids[0]] = x["label"]
    if dup := [i for i, n in labelled.items() if n > 1]:
        problems.append(f"{len(dup)} findings labelled more than once, e.g. {key(by_id[dup[0]])}")
    if missing := [i for i in by_id if i not in labelled]:
        problems.append(f"{len(missing)} findings have no label, e.g. {key(by_id[missing[0]])}")
    if problems:
        raise ValueError("labels do not match --work/findings.json: " + "; ".join(problems[:5]))
    per: dict[str, dict] = {}
    for i, lab in matched.items():   # counted by the matched finding's rule and repo, never the label's copy
        f = by_id[i]
        r = per.setdefault(f["rule"], {"counts": Counter(), "fp_repos": Counter()})
        r["counts"][lab] += 1
        if lab == "fp":
            r["fp_repos"][f["repo"]] += 1
    out = {"rules_bundle": digest, "corpus": [{"repo": c["repo"], "sha": c["sha"]} for c in corpus if c["repo"] in current],
           "stale_findings_excluded": len(allf) - len(findings), "rules": {}}
    for rule, r in sorted(per.items()):
        c = r["counts"]
        correct = c["tp"] + c["tp_test"]   # a correct match in test code is still correct; tp is never shown alone
        judged = c["fp"] + correct
        out["rules"][rule] = {"fp": c["fp"], "correct": correct, "unclear": c["unclear"],
                              "noise": round(c["fp"] / judged, 2) if judged else None,
                              "fp_by_repo": dict(sorted(r["fp_repos"].items()))}
    return out


def main() -> int:
    """Clone the pinned corpus, scan it with the current rules, and write the noise report from the labels."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True, help="scratch dir for clones and raw findings (never committed)")
    ap.add_argument("--repos", nargs="*", help="subset of corpus repos (owner/name)")
    ap.add_argument("--labels", help="JSON list of {repo, rule, path, line, label} from triage")
    ap.add_argument("--report", help="write the aggregate report (no paths or code) here")
    a = ap.parse_args()
    work = Path(a.work)
    corpus = json.loads(CORPUS.read_text())["repos"]
    if a.labels:
        try:
            rep = report(work, json.loads(Path(a.labels).read_text()), corpus)
        except (ValueError, OSError, KeyError, json.JSONDecodeError) as e:
            print(f"cannot build the report: {e}", file=sys.stderr)
            return 2
        print(json.dumps(rep["rules"], indent=1))
        if a.report:
            Path(a.report).write_text(json.dumps(rep, indent=1) + "\n")
        return 0
    if unknown := sorted(set(a.repos or []) - {c["repo"] for c in corpus}):   # a typo must not "succeed" with 0 scans
        print(f"not in tools/fp-corpus.json: {', '.join(unknown)}", file=sys.stderr)
        return 2
    if not shutil.which("opengrep"):   # the only engine sast.py runs; say so before cloning anything
        print("opengrep is required for a sweep (the CI engine); install it first", file=sys.stderr)
        return 2
    # sast.py reuses dist/rules.yaml: rebuild it so the sweep scans the rules as they are now
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "build_rules.py")], check=True, timeout=600)
    try:
        digest = rules_digest()
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    allf, failed = [], []
    for c in corpus:
        if a.repos and c["repo"] not in a.repos:
            continue
        try:
            d = checkout(work, c["repo"], c["sha"])
            f = scan(work, c["repo"], d, c["sha"], digest)
            for x in f:
                x["id"] = finding_id(x)   # label by this id when one line has several findings
            print(f"{c['repo']:50} {len(f):5} findings", flush=True)
            allf += f
        except (RuntimeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
            failed.append(c["repo"])
            print(f"{c['repo']:50} FAILED {str(e)[:150]}", flush=True)
    prev = work / "findings.json"
    # keep earlier findings for repos not run now and for repos that failed now (a transient error must not
    # erase triage material); a repo removed from the corpus is dropped
    names = {c["repo"] for c in corpus}
    keep = [x for x in (json.loads(prev.read_text()) if prev.exists() else [])
            if x["repo"] in names and ((a.repos and x["repo"] not in a.repos) or x["repo"] in failed)]
    prev.write_text(json.dumps(keep + allf, indent=1))
    sc = work / "scanned.json"   # repo -> [sha, rules] of its last completed scan (a repo with 0 findings counts)
    prev_sc = json.loads(sc.read_text()) if sc.exists() else {}
    scanned = {r: v for r, v in (prev_sc if isinstance(prev_sc, dict) else {}).items() if r in names and isinstance(v, list)}
    scanned |= {c["repo"]: [c["sha"], digest] for c in corpus
                if (not a.repos or c["repo"] in a.repos) and c["repo"] not in failed}
    sc.write_text(json.dumps(dict(sorted(scanned.items())), indent=1))
    print("by rule:", dict(Counter(x["rule"] for x in keep + allf).most_common()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
