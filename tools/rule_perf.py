#!/usr/bin/env python3
"""Rule performance guard: is a changed rule much slower than the base branch's version of it?

Each changed rule runs on a large file built from its own fixture (the fixture repeated to about LINES lines),
with the base branch's version of the rule and with the changed version, on the same machine. A rule that looks
too slow is run again, alternating with the base version, and the faster of the runs of each counts. A rule fails when it is both RATIO times slower and SLACK seconds slower
than the base version, or, for a new rule, when it takes over NEW_RULE_CAP seconds. The engine runs with the
gate's own flags (scripts/sast.py): no per-file timeout, so a slow rule is slow here exactly as in a real scan.
PR #11 found two rules 30-45x slower by hand; this makes that a failing check.

Usage:
  tools/rule_perf.py --changed-files files.txt --base-dir DIR   # CI: DIR holds the base versions at their repo paths
  tools/rule_perf.py --rules python/django-httpresponse-xss.yaml --base-dir DIR
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))
from rule_mutation import RULES, changed_rules  # noqa: E402
from rules_test import fixture_for  # noqa: E402

LINES = 2000         # size of the generated file: large enough that matching, not start-up, dominates
RATIO = 1.5          # fail when the changed rule is this many times slower...
SLACK = 3.0          # ...and also this many seconds slower (runner noise on short scans)
NEW_RULE_CAP = 60.0  # no base version to compare (a new rule, or one whose old paths skip the file): fail only over this
RUNS = 2             # at most this many runs per version (the second only to confirm a failure); fastest counts


def big_target(fx: Path, rule_text: str, out: Path) -> tuple[Path, Path]:
    """Write the fixture repeated to about LINES lines; returns (scan directory, target relative to it).
    YAML fixtures are joined as separate documents so the result still parses; a rule limited to workflow files
    gets the file at a workflow path, as tests/rules_test.py does."""
    text = fx.read_text(errors="ignore").rstrip("\n") + "\n"
    n = max(1, LINES // max(1, text.count("\n")))
    sep = "---\n" if fx.suffix in (".yml", ".yaml") else ""
    include = [p for r in yaml.safe_load(rule_text)["rules"] for p in r.get("paths", {}).get("include", [])]
    rel = Path(".github/workflows" if any(p.startswith(".github/workflows/") for p in include) else ".") / f"big{fx.suffix}"
    (out / rel).parent.mkdir(parents=True, exist_ok=True)
    (out / rel).write_text(sep.join([text] * n))
    return out, rel


def scan_seconds(engine: str, rule_text: str, cwd: Path, target: Path) -> tuple[float, bool]:
    """(seconds, whether the rule scanned the target) for one scan with the gate's flags. A failed scan raises,
    including one that exits cleanly but reports an engine error in its JSON: an incomplete scan is not 'fast'."""
    conf = cwd / "perf-rule.yaml"
    conf.write_text(rule_text)
    cmd = [engine, "scan", "--config", str(conf), "--json", "--quiet", "--disable-version-check", "--disable-nosem",
           "--x-ignore-semgrepignore-files", "--max-target-bytes=0", "--timeout", "0", "--timeout-threshold", "0",
           "--taint-intrafile", str(target)]
    t = time.monotonic()
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900, check=False)
    took = time.monotonic() - t
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        out = None
    if r.returncode not in (0, 1) or not isinstance(out, dict):
        raise RuntimeError(f"scan failed (exit {r.returncode}): {r.stderr.strip()[:200]}")
    # the same filter as tests/rules_test.py: only a syntax error in the scanned code is tolerated
    errs = [e for e in out.get("errors", []) if "Syntax error" not in str(e.get("type"))
            and "PartialParsing" not in str(e.get("type"))]
    if errs:
        raise RuntimeError(f"engine error: {str(errs[0].get('message'))[:200]}")
    return took, str(target) in out.get("paths", {}).get("scanned", [])


def check_rule(engine: str, rule: Path, base_dir: Path) -> tuple[str, str]:
    """('ok' | 'SLOW' | 'ERROR', one-line detail) for one rule."""
    rel = rule.relative_to(ROOT)
    head = rule.read_text()
    base_file = base_dir / rel
    base = base_file.read_text() if base_file.is_file() and base_file.stat().st_size else None
    fx = fixture_for(rule)
    if not fx:
        return "ERROR", "no fixture to build a test file from"
    with tempfile.TemporaryDirectory() as td:
        cwd, target = big_target(fx, head, Path(td))
        try:
            times = {"head": [], "base": []}
            for _ in range(RUNS):   # alternate, so a slow patch of the runner hits both versions
                if base is not None:
                    took, scanned = scan_seconds(engine, base, cwd, target)
                    if not scanned:   # the base version's paths or languages skip this file: nothing to compare
                        base = None
                    else:
                        times["base"].append(took)
                took, scanned = scan_seconds(engine, head, cwd, target)
                if not scanned:
                    return "ERROR", f"the rule does not scan a file built from its own fixture ({target})"
                times["head"].append(took)
                if not too_slow(min(times["head"]), min(times["base"]) if base is not None else None):
                    break   # a second run only confirms a failure; a pass needs one run of each
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return "ERROR", str(e)
    h = min(times["head"])
    if base is None:
        return ("SLOW" if too_slow(h, None) else "ok"), f"new rule or no comparable base: {h:.1f}s (cap {NEW_RULE_CAP:.0f}s)"
    b = min(times["base"])
    return ("SLOW" if too_slow(h, b) else "ok"), f"base {b:.1f}s, changed {h:.1f}s ({h / max(b, 0.01):.2f}x)"


def too_slow(head: float, base: float | None) -> bool:
    """The failure test: much slower than the base version, or over the cap for a new rule."""
    return head > NEW_RULE_CAP if base is None else head > RATIO * base and head - base > SLACK


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", default=shutil.which("opengrep"))
    ap.add_argument("--base-dir", default="", help="the base branch's rule files at their repo paths")
    ap.add_argument("--changed-files", help="changed repo paths, one per line")
    ap.add_argument("--rules", nargs="*", help="rule files under rules/custom")
    ap.add_argument("--list", action="store_true", help="only print the repo paths of the rules it would check")
    a = ap.parse_args()
    if a.list and a.changed_files:   # CI fetches these rules' base versions into --base-dir first
        print("\n".join(str(r.relative_to(ROOT)) for r in changed_rules(Path(a.changed_files).read_text().split())))
        return 0
    if not a.engine or Path(a.engine).name != "opengrep":
        print("opengrep is required (the CI engine); install it or pass --engine", file=sys.stderr)
        return 2
    if not a.base_dir:
        print("--base-dir is required", file=sys.stderr)
        return 2
    if a.changed_files:
        rules = changed_rules(Path(a.changed_files).read_text().split())
    elif a.rules:
        rules = [RULES / r for r in a.rules]
    else:
        print("pass --changed-files or --rules", file=sys.stderr)
        return 2
    bad = err = 0
    for rule in rules:
        status, detail = check_rule(a.engine, rule, Path(a.base_dir))
        print(f"{status:5} {rule.relative_to(RULES)}: {detail}", flush=True)
        bad += status == "SLOW"
        err += status == "ERROR"
    if not rules:
        print("no changed rules")
    if bad:
        print(f"{bad} rule(s) much slower than on the base branch: see docs/rule-quality.md (performance)")
    return 2 if err else 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
