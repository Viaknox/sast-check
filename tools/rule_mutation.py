#!/usr/bin/env python3
"""Rule mutation testing: does each rule's fixture actually exercise every part of the rule?

For every list of pattern elements in a rule (pattern-either, patterns, pattern-sources, pattern-sinks,
pattern-sanitizers, pattern-propagators), delete one element at a time and rerun the rule's fixture with
tests/rules_test.py. Outcomes per mutant:
  killed   - the fixture now fails (good: some ruleid:/ok: line depends on that element)
  survived - the fixture still passes (no test exercises that element: add a fixture line, or justify it)
  invalid  - the engine rejects the mutated rule (not counted in the score)
Score = killed / (killed + survived). Shipped rule files are never modified.

Mutant ids are stable across edits elsewhere in the rule: <rule id>:<keys to the list>:<hash of the element>.

Usage:
  tools/rule_mutation.py                      # all rules, print a table
  tools/rule_mutation.py --rules js/ssrf.yaml # some rules (paths under rules/custom)
  tools/rule_mutation.py --changed-since origin/main   # rules whose yaml or fixture changed
  tools/rule_mutation.py --changed-files files.txt     # same, from a list of changed paths (CI)
  tools/rule_mutation.py --json out.json      # full results
  tools/rule_mutation.py --report docs/mutation-report.json   # the committed summary (full run)
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from rules_test import ENGINE_FAILED, fixture_for, fixture_mismatch, rule_failures, scan_fixture  # noqa: E402

RULES = ROOT / "rules" / "custom"
LIST_KEYS = ("pattern-either", "patterns", "pattern-sources", "pattern-sinks", "pattern-sanitizers",
             "pattern-propagators")


def h8(x) -> str:
    """Short content hash of a YAML node."""
    return hashlib.sha1(yaml.safe_dump(x, sort_keys=True).encode(), usedforsecurity=False).hexdigest()[:8]


def mutants(doc: dict) -> list[tuple[str, str, dict]]:
    """(mutant id, the deleted element as yaml, mutated document) for every single-element deletion.

    The id is <rule id>:<keys from the rule root to the list>:<hash of the element>, with no list positions, so
    adding or reordering sibling branches elsewhere in the rule never renames a mutant. Identical elements under
    the same keys (a pattern repeated in several branches) are told apart by a hash of the branches that hold
    them, from the rule root down (@<hash>), and only identical elements in identical branches fall back to #2, #3... in document order."""
    # YAML anchors/aliases load as one shared object: a JSON round trip gives every occurrence its own copy,
    # so a mutant deletes one occurrence only (not every place the anchor is reused)
    doc = json.loads(json.dumps(doc))
    sites = []   # (rule index, steps to the dict holding the list, key, element index, base id, parent hash)

    def walk(node, steps, ri, rid, parent):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in LIST_KEYS and isinstance(v, list):
                    keys = "".join(f".{x}" for x in steps if isinstance(x, str))
                    for i, elem in enumerate(v):
                        sites.append((ri, steps, k, i, f"{rid}:{keys}.{k}:{h8(elem)}", parent))
                    for i, elem in enumerate(v):   # the branch's identity includes all of its ancestors
                        walk(elem, steps + [k, i], ri, rid, h8([parent, elem]))
                else:
                    walk(v, steps + [k], ri, rid, parent)
        elif isinstance(node, list):
            for i, x in enumerate(node):
                walk(x, steps + [i], ri, rid, parent)

    for ri, r in enumerate(doc["rules"]):
        walk(r, [], ri, r["id"], "")
    count = Counter(base for *_, base, _ in sites)
    seen: Counter = Counter()
    out = []
    for ri, steps, key, idx, base, parent in sites:
        mid = base
        if count[base] > 1:
            mid = f"{base}@{parent}" if parent else base
            seen[mid] += 1
            if seen[mid] > 1:
                mid = f"{mid}#{seen[mid]}"
        m = copy.deepcopy(doc)
        holder = m["rules"][ri]
        for st in steps:
            holder = holder[st]
        elem = holder[key].pop(idx)
        out.append((mid, yaml.safe_dump(elem, sort_keys=True).strip(), m))
    return out


def batch_failures(engine: str, rule: Path, muts: list[tuple[str, str, dict]]) -> list[list[str]]:
    """The fixture failures of each mutant, the same as rule_failures() run on it alone, from as few engine runs
    as possible. Engine start-up is most of a small scan, so the mutants run together as renamed copies of the
    mutated rule in one config. A batch that does not scan cleanly (a mutant the engine rejects, a time-out) is
    split in half until each mutant that caused it runs on its own, exactly as before."""
    if len(muts) == 1:
        return [rule_failures(engine, rule, yaml.safe_dump(muts[0][2], sort_keys=False))[1]]
    fx = fixture_for(rule)
    copies = []
    for i, (_, _, m) in enumerate(muts):
        for r in m["rules"]:   # each copy gets an id no other copy ends with (m1 is not a suffix of m11)
            copies.append({**r, "id": f"{r['id']}--mutant{i}"})
    out, problem = scan_fixture(engine, rule, yaml.safe_dump({"rules": copies}, sort_keys=False))
    if problem:
        half = len(muts) // 2
        return batch_failures(engine, rule, muts[:half]) + batch_failures(engine, rule, muts[half:])
    return [[f for r in m["rules"] for f in fixture_mismatch(out, fx, r["id"], f"{r['id']}--mutant{i}")]
            for i, (_, _, m) in enumerate(muts)]


def likely_rejected(node) -> bool:
    """True when a mutated rule has a list left empty, or a `patterns` with no positive element: the engine
    rejects those, and one rejected rule in a batch makes the whole batch split. Such mutants run alone instead.
    (A guess only decides how a mutant is run, never its result.)"""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in LIST_KEYS and isinstance(v, list) and (not v or k == "patterns" and not any(
                    isinstance(e, dict) and e.keys() & {"pattern", "pattern-either", "patterns", "pattern-regex",
                                                         "pattern-inside"} for e in v)):
                return True
            if likely_rejected(v):
                return True
    elif isinstance(node, list):
        return any(likely_rejected(x) for x in node)
    return False


def run_rule(engine: str, rule: Path) -> dict:
    doc = yaml.safe_load(rule.read_text())
    _, base_fails = rule_failures(engine, rule)
    if base_fails:   # the unmodified rule must pass first, or "killed" means nothing
        return {"rule": str(rule.relative_to(RULES)), "error": "unmodified rule fails: " + base_fails[0], "mutants": []}
    muts = mutants(doc)
    alone = {i for i, (_, _, m) in enumerate(muts) if likely_rejected(m)}
    together = [i for i in range(len(muts)) if i not in alone]
    found = {}
    for idx in [[i] for i in sorted(alone)] + ([together] if together else []):
        found.update(zip(idx, batch_failures(engine, rule, [muts[i] for i in idx])))
    res = []
    for i, (mid, elem, _) in enumerate(muts):
        fails = found[i]
        if any(ENGINE_FAILED in f for f in fails):   # the scan did not complete: nothing was evaluated
            return {"rule": str(rule.relative_to(RULES)), "error": f"mutant {mid}: {fails[0]}", "mutants": res}
        status = ("invalid" if fails and all("engine error" in f for f in fails)
                  else "killed" if fails else "survived")
        res.append({"id": mid, "status": status, "element": elem[:300]})
    return {"rule": str(rule.relative_to(RULES)), "mutants": res}


def changed_rules(names: list[str]) -> list[Path]:
    """Rule files whose yaml or fixture is among the changed repo paths. A fixture is matched back to its rule
    with the same lookup the tests use (fixture_for), so `x.test.yml`, `x.test.yaml` and `x.js` all map to
    `x.yaml`, and a fixture is never taken for a rule."""
    rules = [p for p in RULES.glob("*/*.yaml") if not p.name.endswith((".test.yaml", ".test.yml"))]
    fixtures = {fx: r for r in rules if (fx := fixture_for(r))}
    out = set()
    for n in names:
        p = ROOT / n
        if p in fixtures:
            out.add(fixtures[p])
        elif p in rules:
            out.add(p)
    return sorted(out)


def baseline_reason(entry) -> str:
    """The written reason for a baseline entry, or "" when it has none a reviewer could accept."""
    why = entry.get("why") if isinstance(entry, dict) else None
    return why.strip() if isinstance(why, str) and why.strip() and not why.strip().upper().startswith("TODO") else ""


def summary(results: list[dict], engine: str) -> dict:
    """The committed report (docs/mutation-report.json): per-rule counts and scores, no rule text."""
    ver = subprocess.run([engine, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    rules = {}
    for r in results:
        c = {s: sum(m["status"] == s for m in r["mutants"]) for s in ("killed", "survived", "invalid")}
        tot = c["killed"] + c["survived"]
        rules[r["rule"]] = {**c, "score": round(c["killed"] / tot, 2) if tot else None}
    k, s = sum(v["killed"] for v in rules.values()), sum(v["survived"] for v in rules.values())
    return {"date": date.today().isoformat(), "engine": f"{Path(engine).name} {ver}".strip(),
            "total": {"killed": k, "survived": s, "score": round(k / max(1, k + s), 2)}, "rules": rules}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", default=shutil.which("opengrep") or shutil.which("semgrep"))
    ap.add_argument("--rules", nargs="*", help="rule files under rules/custom (default: all)")
    ap.add_argument("--changed-since", help="only rules whose yaml or fixture changed since this git ref")
    ap.add_argument("--changed-files", help="only rules whose yaml or fixture is listed in this file (one path per line)")
    ap.add_argument("--json", help="write full results here")
    ap.add_argument("--report", help="write the committed per-rule summary here (full runs only)")
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
    # a rule with a single scalar pattern has no list element to delete: say so, never imply it was mutation-tested
    for r in results:
        if not r.get("error") and not r["mutants"]:
            print(f"NOT MUTATION-TESTED {r['rule']}: no list of pattern elements to delete (its fixture still runs in rules_test)")
    k, s = sum(m["status"] == "killed" for m in allm), sum(m["status"] == "survived" for m in allm)
    print(f"TOTAL killed {k} survived {s} score {100 * k / max(1, k + s):.0f}%")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1))
    if a.report and not errors:
        if a.rules or a.changed_since or a.changed_files:
            print("--report needs a full run (no --rules / --changed-*)", file=sys.stderr)
            return 2
        Path(a.report).write_text(json.dumps(summary(results, a.engine), indent=1) + "\n")
    survivors = {m["id"]: m["element"] for m in allm if m["status"] == "survived"}
    if errors:   # an incomplete run must not rewrite the baseline or pass the check
        for r in errors:
            print(f"ERROR {r['rule']}: {r['error']}", file=sys.stderr)
        return 2
    if a.write_baseline:
        old = json.loads(Path(a.write_baseline).read_text()) if Path(a.write_baseline).exists() else {}
        # a partial run (--rules / --changed-*) rewrites only the rules it ran; other rules' entries stay
        ran = {x["id"] for r in results for x in yaml.safe_load((RULES / r["rule"]).read_text())["rules"]}
        kept = {i: v for i, v in old.items() if i.split(":", 1)[0] not in ran}
        kept |= {i: old.get(i, {"element": e, "why": "TODO: add a fixture line or justify"}) for i, e in survivors.items()}
        Path(a.write_baseline).write_text(json.dumps(dict(sorted(kept.items())), indent=1) + "\n")
    if a.check:
        base = json.loads(Path(a.check).read_text())
        # a baseline entry counts only with a written reason: `{}`, a blank or a TODO reason is not one
        new = sorted(i for i in survivors if not baseline_reason(base.get(i)))
        for i in new:
            what = "is listed without a reason" if i in base else "no fixture line depends on this element"
            print(f"NEW SURVIVOR {i}: {what}:\n  {survivors[i][:200]}")
        # a waiver for a rule that ran must still be needed: once a fixture kills the mutant (or the element is
        # gone), the entry has to be removed, or later losing that fixture line would pass silently
        ran = {x["id"] for r in results for x in yaml.safe_load((RULES / r["rule"]).read_text())["rules"]}
        stale = sorted(i for i in base if i.split(":", 1)[0] in ran and i not in survivors)
        for i in stale:
            print(f"STALE BASELINE {i}: no longer survives; remove it from {a.check}")
        return 1 if new or stale else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
