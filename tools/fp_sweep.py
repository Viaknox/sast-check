#!/usr/bin/env python3
"""False-positive sweep: run the custom Opengrep rules over a pinned corpus of well-maintained open-source
repositories (tools/fp-corpus.json) and collect every finding for triage.

Each finding is labelled later (by a reviewer or a triage agent) as:
  fp      - the code is safe; the rule is wrong here -> becomes an ok: fixture (hand-written, never copied)
  tp      - a real weakness -> NOT published: keep it local, follow the project's security policy
  tp_test - the rule is right, but only in test/example/docs code (a path-handling signal, not a rule bug)
  unclear - needs a closer look
Per-rule noise = fp / (fp + tp + tp_test). Raw findings (paths, lines, snippets) stay in --work and are never committed;
the committed report (--report) has only rule, repository, counts and labels.

Usage:
  tools/fp_sweep.py --work /tmp/fp                       # clone (cached) + scan; writes /tmp/fp/findings.json
  tools/fp_sweep.py --work /tmp/fp --labels labels.json --report docs/fp-report.json
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tools" / "fp-corpus.json"


def checkout(work: Path, repo: str, sha: str) -> Path:
    d = work / "repos" / repo.replace("/", "__")
    if (d / ".git").exists() and subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True,
                                                 text=True).stdout.strip() == sha:
        return d
    d.mkdir(parents=True, exist_ok=True)
    for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", f"https://github.com/{repo}.git"],
                ["git", "fetch", "-q", "--depth", "1", "origin", sha], ["git", "checkout", "-q", "FETCH_HEAD"]):
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=900)
        if r.returncode and "already exists" not in r.stderr:
            raise RuntimeError(f"{repo}: {' '.join(cmd)}: {r.stderr.strip()[:200]}")
    return d


def scan(work: Path, repo: str, d: Path) -> list[dict]:
    out = work / "out" / repo.replace("/", "__")
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "sast.py"), "--repo", str(d), "--mode", "full",
                        "--only", "opengrep", "--out", str(out)], capture_output=True, text=True, timeout=3600)
    data = json.loads((out / "findings.json").read_text())
    errs = [x for x in data.get("runs", []) if x.get("status") == "error"]
    if errs:
        raise RuntimeError(f"{repo}: scanner error: {errs[0].get('detail', '')[:200]}")
    found = []
    for f in data["findings"]:
        try:
            lines = (d / f["path"]).read_text(errors="ignore").splitlines()
            snippet = "\n".join(lines[max(0, f["line"] - 4): f["line"] + 3])
        except OSError:
            snippet = ""
        found.append({"repo": repo, "rule": f["rule"], "path": f["path"], "line": f["line"],
                      "severity": f["severity"], "message": f["message"], "context": snippet})
    return found


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
        labels = json.loads(Path(a.labels).read_text())
        per: dict[str, Counter] = {}
        for x in labels:
            per.setdefault(x["rule"], Counter())[x["label"]] += 1
        report = {"corpus": [{"repo": c["repo"], "sha": c["sha"]} for c in corpus], "rules": {}}
        for rule, c in sorted(per.items()):
            judged = c["fp"] + c["tp"] + c["tp_test"]   # a correct match in test code is still correct
            report["rules"][rule] = {**c, "noise": round(c["fp"] / judged, 2) if judged else None}
        print(json.dumps(report["rules"], indent=1))
        if a.report:
            Path(a.report).write_text(json.dumps(report, indent=1) + "\n")
        return 0
    allf, failed = [], []
    for c in corpus:
        if a.repos and c["repo"] not in a.repos:
            continue
        try:
            d = checkout(work, c["repo"], c["sha"])
            f = scan(work, c["repo"], d)
            print(f"{c['repo']:50} {len(f):5} findings", flush=True)
            allf += f
        except (RuntimeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
            failed.append(c["repo"])
            print(f"{c['repo']:50} FAILED {str(e)[:150]}", flush=True)
    prev = work / "findings.json"
    keep = [x for x in (json.loads(prev.read_text()) if prev.exists() else [])
            if a.repos and x["repo"] not in a.repos]
    prev.write_text(json.dumps(keep + allf, indent=1))
    print("by rule:", dict(Counter(x["rule"] for x in keep + allf).most_common()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
