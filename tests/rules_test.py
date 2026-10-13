#!/usr/bin/env python3
"""Engine-agnostic rule tests: for each rules/custom/<area>/<slug>.yaml, scan its fixture
and compare flagged lines with the `ruleid:` / `ok:` annotations.

Uses opengrep if installed (the CI engine), else semgrep. Usage: tests/rules_test.py [--engine X]
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANN = re.compile(r"(ruleid|ok):\s*([\w.\-]+)")


def fixture_for(rule: Path) -> Path | None:
    for c in sorted(rule.parent.glob(rule.stem + ".*")):
        if c != rule:
            return c
    return None


def expected(fx: Path, rid: str) -> tuple[set[int], set[int]]:
    want, ok = set(), set()
    lines = fx.read_text(errors="ignore").splitlines()
    for i, ln in enumerate(lines, 1):
        for kind, r in ANN.findall(ln):
            if r != rid:
                continue
            # annotation applies to the next non-annotation line (or same line if code precedes it)
            code_before = ln.split("ruleid:")[0].split("ok:")[0]
            target = i if re.search(r"\w", re.sub(r"(//|#|<!--|/\*|\{\{!|\{#)\s*$", "", code_before)) else i + 1
            while target <= len(lines) and target != i and ANN.search(lines[target - 1]):
                target += 1
            (want if kind == "ruleid" else ok).add(target)
    return want, ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=shutil.which("opengrep") or shutil.which("semgrep"))
    a = ap.parse_args()
    if not a.engine:
        print("no engine installed", file=sys.stderr)
        return 2
    is_og = Path(a.engine).name == "opengrep"
    failures = total = 0
    for rule in sorted((ROOT / "rules" / "custom").glob("*/*.yaml")):
        if rule.name.endswith(".test.yaml"):
            continue
        fx = fixture_for(rule)
        import yaml  # noqa: PLC0415 - dev dependency
        rids = [r["id"] for r in yaml.safe_load(rule.read_text())["rules"]]
        if not fx:
            print(f"FAIL {rule.relative_to(ROOT)}: no fixture")
            failures += 1
            continue
        cmd = [a.engine, "scan", "--config", str(rule), "--json", "--quiet", "--scan-unknown-extensions"]
        cmd += ["--taint-intrafile"] if is_og else ["--metrics=off", "--disable-version-check"]
        # a rule limited to workflow files is tested on a copy of its fixture at such a path
        include = [p for r in yaml.safe_load(rule.read_text())["rules"] for p in r.get("paths", {}).get("include", [])]
        with tempfile.TemporaryDirectory() as td:
            cwd, target = None, str(fx)
            if any(p.startswith(".github/workflows/") for p in include):
                (Path(td) / ".github" / "workflows").mkdir(parents=True)
                shutil.copyfile(fx, Path(td) / ".github" / "workflows" / fx.name)
                cwd, target = td, f".github/workflows/{fx.name}"
            out = json.loads(subprocess.run(cmd + [target], cwd=cwd, capture_output=True, text=True).stdout or "{}")
        # a rule the engine cannot parse is silently skipped -> treat it as a failure
        rule_errs = [e for e in out.get("errors", []) if "Syntax error" not in str(e.get("type"))
                     and "PartialParsing" not in str(e.get("type"))]
        if rule_errs:
            failures += len(rids)
            total += len(rids)
            print(f"FAIL {rule.relative_to(ROOT)}: engine error: {str(rule_errs[0].get('message'))[:200]}")
            continue
        for rid in rids:
            total += 1
            got = {r["start"]["line"] for r in out.get("results", []) if r["check_id"].endswith(rid)}
            want, ok = expected(fx, rid)
            # exact: every annotated ruleid line must match, and nothing else may match
            missed, wrong = want - got, got - want
            if len(want) < 3 or len(ok) < 3:   # docs/RULE_SPEC.md: >=3 true positives, >=3 safe look-alikes
                failures += 1
                print(f"FAIL {rid}: fixture needs >=3 ruleid: and >=3 ok: annotations (has {len(want)}/{len(ok)})")
            elif missed or wrong:
                failures += 1
                print(f"FAIL {rid}: missed lines {sorted(missed)} unexpected lines {sorted(wrong)}")
    print(f"{total - failures}/{total} rules passed with {Path(a.engine).name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
