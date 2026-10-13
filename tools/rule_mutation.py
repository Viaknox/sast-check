#!/usr/bin/env python3
"""Rule mutation testing: does each rule's fixture actually exercise every part of the rule?

For every list of pattern elements in a rule (pattern-either, patterns, pattern-sources, pattern-sinks,
pattern-sanitizers, pattern-propagators), delete one element at a time and rerun the rule's fixture with
tests/rules_test.py. Outcomes per mutant:
  killed   - the fixture now fails (good: some ruleid:/ok: line depends on that element)
  survived - the fixture still passes (no test exercises that element: add a fixture line, or justify it)
  invalid  - the engine rejects the mutated rule (not counted in the score)
Score = killed / (killed + survived). Shipped rule files are never modified.

Mutant ids are stable across edits elsewhere in the rule: <rule id>:<list path>:<hash of the element>.

Usage:
  tools/rule_mutation.py                      # all rules, print a table
  tools/rule_mutation.py --rules js/ssrf.yaml # some rules (paths under rules/custom)
  tools/rule_mutation.py --changed-since origin/main   # rules whose yaml or fixture changed
  tools/rule_mutation.py --changed-files files.txt     # same, from a list of changed paths (CI)
  tools/rule_mutation.py --json out.json      # full results
  tools/rule_mutation.py --check tests/mutation-baseline.json   # CI: fail on any survivor not in the baseline
  tools/rule_mutation.py --write-baseline tests/mutation-baseline.json
"""
import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from rules_test import fixture_for, rule_failures  # noqa: E402

RULES = ROOT / "rules" / "custom"
LIST_KEYS = ("pattern-either", "patterns", "pattern-sources", "pattern-sinks", "pattern-sanitizers",
             "pattern-propagators")


def mutants(doc: dict) -> list[tuple[str, str, dict]]:
    """(mutant id, the deleted element as yaml, mutated document) for every single-element deletion."""
    sites = []   # (rule index, steps to the dict holding the list, key, element index, id)

    def walk(node, steps, ri, rid):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in LIST_KEYS and isinstance(v, list):
                    for i, elem in enumerate(v):
                        h = hashlib.sha1(yaml.safe_dump(elem, sort_keys=True).encode(), usedforsecurity=False).hexdigest()[:8]
                        path = "".join(f".{x}" if isinstance(x, str) else f"[{x}]" for x in steps)
                        sites.append((ri, steps, k, i, f"{rid}:{path}.{k}:{h}"))
                walk(v, steps + [k], ri, rid)
        elif isinstance(node, list):
            for i, x in enumerate(node):
                walk(x, steps + [i], ri, rid)

    for ri, r in enumerate(doc["rules"]):
        walk(r, [], ri, r["id"])
    out = []
    for ri, steps, key, idx, mid in sites:
        m = copy.deepcopy(doc)
        holder = m["rules"][ri]
        for st in steps:
            holder = holder[st]
        elem = holder[key].pop(idx)
        out.append((mid, yaml.safe_dump(elem, sort_keys=True).strip(), m))
    return out


def run_rule(engine: str, rule: Path) -> dict:
    doc = yaml.safe_load(rule.read_text())
    _, base_fails = rule_failures(engine, rule)
    if base_fails:   # the unmodified rule must pass first, or "killed" means nothing
        return {"rule": str(rule.relative_to(RULES)), "error": "unmodified rule fails: " + base_fails[0], "mutants": []}
    res = []
    for mid, elem, m in mutants(doc):
        n, fails = rule_failures(engine, rule, yaml.safe_dump(m, sort_keys=False))
        status = ("invalid" if fails and all("engine error" in f for f in fails)
                  else "killed" if fails else "survived")
        res.append({"id": mid, "status": status, "element": elem[:300]})
    return {"rule": str(rule.relative_to(RULES)), "mutants": res}


def changed_rules(names: list[str]) -> list[Path]:
    """Rule files whose yaml or fixture is among the changed repo paths."""
    out = set()
    for n in names:
        if not n.startswith("rules/custom/"):
            continue
        p = ROOT / n
        y = p if p.suffix == ".yaml" else p.with_suffix(".yaml")
        if y.exists():
            out.add(y)
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", default=shutil.which("opengrep") or shutil.which("semgrep"))
    ap.add_argument("--rules", nargs="*", help="rule files under rules/custom (default: all)")
    ap.add_argument("--changed-since", help="only rules whose yaml or fixture changed since this git ref")
    ap.add_argument("--changed-files", help="only rules whose yaml or fixture is listed in this file (one path per line)")
    ap.add_argument("--json", help="write full results here")
    ap.add_argument("--check", help="baseline file: fail if a survivor is not listed in it")
    ap.add_argument("--write-baseline", help="write current survivors as the new baseline")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    a = ap.parse_args()
    if not a.engine or Path(a.engine).name != "opengrep":
        print("opengrep is required (the CI engine); install it or pass --engine", file=sys.stderr)
        return 2
    if a.changed_since:
        rules = changed_rules(subprocess.run(["git", "diff", "--name-only", f"{a.changed_since}...HEAD"], cwd=ROOT,
                                             capture_output=True, text=True, check=True).stdout.split())
    elif a.changed_files:
        rules = changed_rules(Path(a.changed_files).read_text().split())
    elif a.rules:
        rules = [RULES / r for r in a.rules]
    else:
        rules = sorted(p for p in RULES.glob("*/*.yaml") if fixture_for(p))
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        results = list(ex.map(lambda r: run_rule(a.engine, r), rules))
    errors = [r for r in results if r.get("error")]
    print(f"{'rule':45} {'killed':>6} {'surv':>5} {'inval':>5} {'score':>6}")
    for r in results:
        c = {s: sum(m["status"] == s for m in r["mutants"]) for s in ("killed", "survived", "invalid")}
        tot = c["killed"] + c["survived"]
        score = f"{100 * c['killed'] / tot:.0f}%" if tot else "-"
        print(f"{r['rule']:45} {c['killed']:6} {c['survived']:5} {c['invalid']:5} {score:>6}"
              + (f"  ERROR {r['error'][:80]}" if r.get("error") else ""))
    allm = [m for r in results for m in r["mutants"]]
    k, s = sum(m["status"] == "killed" for m in allm), sum(m["status"] == "survived" for m in allm)
    print(f"TOTAL killed {k} survived {s} score {100 * k / max(1, k + s):.0f}%")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1))
    survivors = {m["id"]: m["element"] for m in allm if m["status"] == "survived"}
    if a.write_baseline:
        old = json.loads(Path(a.write_baseline).read_text()) if Path(a.write_baseline).exists() else {}
        Path(a.write_baseline).write_text(json.dumps(
            {i: old.get(i, {"element": e, "why": "TODO: add a fixture line or justify"}) for i, e in sorted(survivors.items())},
            indent=1) + "\n")
    if errors:
        return 2
    if a.check:
        base = json.loads(Path(a.check).read_text())
        new = sorted(set(survivors) - set(base))
        for i in new:
            print(f"NEW SURVIVOR {i}: no fixture line depends on this element:\n  {survivors[i][:200]}")
        return 1 if new else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
