#!/usr/bin/env python3
"""False-positive sweep: run the custom Opengrep rules over a pinned corpus of well-maintained open-source
repositories (tools/fp-corpus.json) and collect every finding for triage.

Each finding is labelled later (by a reviewer or a triage agent) as:
  fp      - the code is safe; the rule is wrong here -> becomes an ok: fixture (hand-written, never copied)
  tp      - a real weakness -> NOT published: keep it local, follow the project's security policy
  tp_test - the rule is right, but only in test/example/docs code (a path-handling signal, not a rule bug)
  unclear - needs a closer look
Per-rule noise = fp / (fp + tp + tp_test). Raw findings (paths, lines, snippets) stay in --work and are never committed;
the committed report (--report) has only rule, repository, counts and labels (per rule and per repository).
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
    """Hash of the rule bundle the sweep scans with (findings from another rule revision are stale)."""
    return hashlib.sha256((ROOT / "dist" / "rules.yaml").read_bytes()).hexdigest()[:16]


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
                      "severity": f["severity"], "message": f["message"], "context": snippet})
    return found


def key(x: dict) -> tuple:
    """Identity of a finding or a label."""
    return x["repo"], x["rule"], x["path"], x["line"]


def report(work: Path, labels: list[dict], corpus: list[dict]) -> dict:
    """Aggregate labels into per-rule (and per-repository) counts. Labels must match the current findings in
    --work one to one, so a partial, duplicated or stale label file never yields a plausible score."""
    allf = json.loads((work / "findings.json").read_text())
    # only findings from the pinned commit and the current rule bundle count; older ones stay for triage
    pinned, digest = {c["repo"]: c["sha"] for c in corpus}, rules_digest()
    findings = [x for x in allf if pinned.get(x["repo"]) == x.get("sha") and x.get("rules") == digest]
    sc = work / "scanned.json"
    scanned = json.loads(sc.read_text()) if sc.exists() else {}
    current = {x["repo"] for x in findings} | {r for r, v in scanned.items() if v == [pinned.get(r), digest]}
    fk = Counter(map(key, findings))
    stale = {key(x) for x in allf} - set(fk)   # labels for stale findings are kept in the file but not counted
    labels = [x for x in labels if x["repo"] in current and key(x) not in stale]
    lk = Counter(map(key, labels))
    problems = []
    if bad := sorted({x["label"] for x in labels} - set(LABELS)):
        problems.append(f"unknown labels {bad} (allowed: {', '.join(LABELS)})")
    if dup := [k for k, n in lk.items() if n != fk.get(k, n)]:   # two findings on one line need two labels
        problems.append(f"{len(dup)} findings labelled a different number of times than found, e.g. {dup[0]}")
    if missing := [k for k in fk if k not in lk]:
        problems.append(f"{len(missing)} findings have no label, e.g. {missing[0]}")
    if stale := [k for k in lk if k not in fk]:
        problems.append(f"{len(stale)} labels match no current finding, e.g. {stale[0]}")
    if problems:
        raise ValueError("labels do not match --work/findings.json: " + "; ".join(problems))
    per: dict[str, dict] = {}
    for x in labels:
        r = per.setdefault(x["rule"], {"counts": Counter(), "repos": {}})
        r["counts"][x["label"]] += 1
        r["repos"].setdefault(x["repo"], Counter())[x["label"]] += 1
    out = {"rules_bundle": digest, "corpus": [{"repo": c["repo"], "sha": c["sha"]} for c in corpus if c["repo"] in current],
           "stale_findings_excluded": len(allf) - len(findings), "rules": {}}
    for rule, r in sorted(per.items()):
        c = r["counts"]
        judged = c["fp"] + c["tp"] + c["tp_test"]   # a correct match in test code is still correct
        out["rules"][rule] = {**c, "noise": round(c["fp"] / judged, 2) if judged else None,
                              "repos": {repo: dict(n) for repo, n in sorted(r["repos"].items())}}
    return out


def main() -> int:
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
    if not shutil.which("opengrep"):   # sast.py would fall back to semgrep: scores must come from the CI engine
        print("opengrep is required for a sweep (the CI engine); install it first", file=sys.stderr)
        return 2
    # sast.py reuses dist/rules.yaml: rebuild it so the sweep scans the rules as they are now
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "build_rules.py")], check=True, timeout=600)
    digest = rules_digest()
    allf, failed = [], []
    for c in corpus:
        if a.repos and c["repo"] not in a.repos:
            continue
        try:
            d = checkout(work, c["repo"], c["sha"])
            f = scan(work, c["repo"], d, c["sha"], digest)
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
    scanned = {r: v for r, v in (json.loads(sc.read_text()) if sc.exists() else {}).items()
               if r in names and isinstance(v, list)}
    scanned |= {c["repo"]: [c["sha"], digest] for c in corpus
                if (not a.repos or c["repo"] in a.repos) and c["repo"] not in failed}
    sc.write_text(json.dumps(dict(sorted(scanned.items())), indent=1))
    print("by rule:", dict(Counter(x["rule"] for x in keep + allf).most_common()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
