#!/usr/bin/env python3
"""Rule tests: for each rules/custom/<area>/<slug>.yaml, scan its fixture
and compare flagged lines with the `ruleid:` / `ok:` annotations.

Runs Opengrep, the only supported engine. Usage: tests/rules_test.py [--engine PATH-TO-OPENGREP]
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
ENGINE_FAILED = "engine failed"   # the scan did not complete (crash, timeout, no JSON): never a pass or a kill
ENGINE_TIMEOUT = 600


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


def rule_failures(engine: str, rule: Path, text: str | None = None) -> tuple[int, list[str]]:
    """Run one rule file on its fixture. Returns (number of rule ids, failure messages).
    `text` replaces the rule file's content (used by tools/rule_mutation.py); the fixture stays the same."""
    import yaml  # noqa: PLC0415 - dev dependency
    text = rule.read_text() if text is None else text
    rids = [r["id"] for r in yaml.safe_load(text)["rules"]]
    fx = fixture_for(rule)
    if not fx:
        return len(rids), [f"{rule.relative_to(ROOT)}: no fixture"]
    out, problem = scan_fixture(engine, rule, text)
    if problem:
        return len(rids), [problem] * len(rids)
    return len(rids), [f for rid in rids for f in fixture_mismatch(out, fx, rid)]


def fixture_mismatch(out: dict, fx: Path, rid: str, check_id: str | None = None) -> list[str]:
    """Compare one rule's findings in a scan result with the fixture's annotations for `rid`.
    `check_id` is the id the rule ran under, when it differs from `rid` (tools/rule_mutation.py runs renamed copies)."""
    got = {r["start"]["line"] for r in out.get("results", []) if r["check_id"].endswith(check_id or rid)}
    want, ok = expected(fx, rid)
    # exact: every annotated ruleid line must match, and nothing else may match
    missed, wrong = want - got, got - want
    if len(want) < 3 or len(ok) < 3:   # docs/RULE_SPEC.md: >=3 true positives, >=3 safe look-alikes
        return [f"{rid}: fixture needs >=3 ruleid: and >=3 ok: annotations (has {len(want)}/{len(ok)})"]
    if missed or wrong:
        return [f"{rid}: missed lines {sorted(missed)} unexpected lines {sorted(wrong)}"]
    return []


def scan_fixture(engine: str, rule: Path, text: str) -> tuple[dict, str | None]:
    """Scan `rule`'s fixture with the rules in `text`. Returns (engine JSON, None), or ({}, the reason) when the
    scan did not complete cleanly: an engine failure, or an engine error such as a rule it rejects."""
    import yaml  # noqa: PLC0415 - dev dependency
    fx = fixture_for(rule)
    cmd = [engine, "scan", "--json", "--quiet", "--scan-unknown-extensions", "--taint-intrafile"]
    # a rule limited to workflow files is tested on a copy of its fixture at such a path
    include = [p for r in yaml.safe_load(text)["rules"] for p in r.get("paths", {}).get("include", [])]
    with tempfile.TemporaryDirectory() as td:
        conf = Path(td) / "rule.yaml"
        conf.write_text(text)
        cwd, target = None, str(fx)
        if any(p.startswith(".github/workflows/") for p in include):
            (Path(td) / ".github" / "workflows").mkdir(parents=True)
            shutil.copyfile(fx, Path(td) / ".github" / "workflows" / fx.name)
            cwd, target = td, f".github/workflows/{fx.name}"
        try:
            r = subprocess.run(cmd + ["--config", str(conf), target], cwd=cwd, capture_output=True, text=True,
                               timeout=ENGINE_TIMEOUT)
            out = json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            msg = "timed out" if isinstance(e, subprocess.TimeoutExpired) else f"exit {r.returncode}, no JSON output"
            return {}, f"{rule.relative_to(ROOT)}: {ENGINE_FAILED}: {msg}"
    # a rule the engine cannot parse is silently skipped -> treat it as a failure
    rule_errs = [e for e in out.get("errors", []) if "Syntax error" not in str(e.get("type"))
                 and "PartialParsing" not in str(e.get("type"))]
    if rule_errs:
        return {}, f"{rule.relative_to(ROOT)}: engine error: {str(rule_errs[0].get('message'))[:200]}"
    if r.returncode != 0:   # JSON but a failed run (results may be incomplete): never a pass or a kill
        return {}, f"{rule.relative_to(ROOT)}: {ENGINE_FAILED}: exit {r.returncode}"
    return out, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=shutil.which("opengrep"))
    a = ap.parse_args()
    if not a.engine or Path(a.engine).name != "opengrep":
        print("opengrep is required (the only supported engine); install it or pass --engine", file=sys.stderr)
        return 2
    failures = total = 0
    for rule in sorted((ROOT / "rules" / "custom").glob("*/*.yaml")):
        if rule.name.endswith(".test.yaml"):
            continue
        n, fails = rule_failures(a.engine, rule)
        total += n
        failures += len(fails)
        for f in fails:
            print(f"FAIL {f}")
    print(f"{total - failures}/{total} rules passed with {Path(a.engine).name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
