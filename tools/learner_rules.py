#!/usr/bin/env python3
"""Learner P3: turn recurring review findings (patterns.json from the quality-gate learner) into custom rules.

For each pattern with >= 3 hits, a cheap model on OpenRouter drafts an Opengrep rule and a synthetic
fixture. The draft is accepted only if, with Opengrep (the only engine):
  - it matches every "before" example, including the held-out ones the model never saw (every third example),
  - it matches none of the "after" examples,
  - it is silent on this repo's own code of that language (rules/custom fixtures, dist/ and tests/fixtures/ excluded),
  - its fixture has >= 3 true positives and >= 3 safe look-alikes, passes tests/rules_test.py, and copies no
    example line (examples may come from private repositories; fixtures must be new, synthetic code),
  - tools/rule_mutation.py finds no surviving mutant (every pattern element is exercised by the fixture).
Anything else is discarded, with the reason in the run report; a rejected draft is never written to rules/custom.
A pattern with `cwe: null` (P2 sets a CWE only when a scanner tagged the finding) gets the CWE the model proposes
with the rule; a CWE the pattern gives always wins. Either way it must be CWE-<n>.
Accepted rules go to rules/custom/<area>/lp-....yaml with metadata.cwe and metadata.learner_pattern_id, then
scripts/build_rules.py rebuilds dist/ and checks the rule-ID lock. With --open-pr the result becomes one pull
request for a human to review and merge. This tool never merges and never enables auto-merge.

The OpenRouter key is read from OPENROUTER_API_KEY and is never printed or written anywhere.

Usage:
  tools/learner_rules.py --patterns patterns.json                     # write accepted rules to the working tree
  tools/learner_rules.py --patterns patterns.json --report run.json   # also write the accept/reject report
  tools/learner_rules.py --patterns patterns.json --open-pr           # commit them on a new branch and open a PR
  tools/learner_rules.py --patterns patterns.json --target ../rules --open-pr   # private rules repo (below)

Rules learned from private code must never reach this public repo. With --target <checkout of a private rules
repo>, accepted rules are written as `local.<area>.<id>` rules to its .sast-check/rules/ (fixtures in
.sast-check/rules/tests/), checked with sast-check's own reader (docs/local-rules.md), and the PR opens there.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "learner-patterns/v1"
MIN_HITS = 3
LOCAL_DIR = ".sast-check/rules"   # where sast-check reads a repo's own rules (scripts/sast.py LOCAL_RULES_DIR)
HOME_ORG = "SathiaAI"   # owner of this repo; a rule from another org's code needs the owner's recorded approval
MIN_EXAMPLES = 3   # distinct examples: fewer leaves no held-out example, so the rule would be untested on unseen code
DEFAULT_MODEL = "qwen/qwen3-coder-30b-a3b-instruct"   # cheap, non-frontier coding model; override with --model
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
ENGINE_TIMEOUT = 600
# stack -> (rules/custom area, rule languages, fixture extension, extensions of this repo's own code to scan)
STACKS = {
    "python": ("python", ["python"], ".py", (".py",)),
    "javascript": ("js", ["javascript", "typescript"], ".js", (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")),
    "typescript": ("js", ["javascript", "typescript"], ".ts", (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")),
}
STACKS["node"] = STACKS["javascript"]
COMMENT = {".py": "#", ".js": "//", ".ts": "//"}
# docs/RULE_SPEC.md: critical/high -> ERROR (blocking), medium -> WARNING, low -> INFO
SEVERITY = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}
# the only rule keys a draft may set; id, languages, severity, message and metadata are set here
ALLOWED_KEYS = {"pattern", "patterns", "pattern-either", "pattern-regex", "mode", "pattern-sources",
                "pattern-sinks", "pattern-sanitizers"}
PATTERN_ID = re.compile(r"^lp-[a-z0-9][a-z0-9-]{0,60}$")
CWE = re.compile(r"^CWE-[1-9][0-9]*$")
# never scanned as "clean" code: intentionally vulnerable fixtures and generated files
NOT_CLEAN = ("rules/custom/", "dist/", "tests/fixtures/", "sast-results/", "node_modules/", ".git/", ".venv/", "venv/")
COPY_MIN = 25   # a fixture line equal to an example line this long (whitespace collapsed) counts as copied


class Reject(Exception):
    """A draft (or a pattern) that must not become a rule; the message is the recorded reason."""


class HeldOutMiss(Reject):
    """The draft missed an example the model never saw: no retry, so held-out examples stay unseen."""


def load_patterns(path: Path) -> list[dict]:
    """The patterns of a learner-patterns/v1 file. A file in any other format is an error, never an empty run."""
    doc = json.loads(path.read_text())
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("patterns"), list):
        raise ValueError(f"{path}: not a {SCHEMA} file")
    return doc["patterns"]


def check_pattern(p) -> str:
    """Why this pattern cannot become a rule ("" when it can)."""
    if not isinstance(p, dict):
        return "malformed pattern: not an object"
    for k, t in (("id", str), ("stack", str), ("hits", int), ("impact_band", str),
                 ("summary", str), ("examples", list)):
        if not isinstance(p.get(k), t) or isinstance(p.get(k), bool):
            return f"malformed pattern: {k} missing or not a {t.__name__}"
    if not PATTERN_ID.fullmatch(p["id"]):
        return "pattern id is not of the form lp-<lowercase letters, digits, dashes>"
    if "cwe" not in p:
        return "malformed pattern: cwe missing (it may be null, but the key must be there)"
    if p["cwe"] is not None and not (isinstance(p["cwe"], str) and CWE.fullmatch(p["cwe"])):
        return f"cwe {p.get('cwe')!r} is not CWE-<n> or null"
    if p["impact_band"] not in SEVERITY:
        return f"impact_band {p['impact_band']!r} is not one of {sorted(SEVERITY)}"
    if p["stack"] not in STACKS:
        return f"stack {p['stack']!r} is not supported (supported: {sorted(STACKS)})"
    if not p["examples"] or not all(isinstance(e, dict) and isinstance(e.get("before"), str)
                                    and isinstance(e.get("after"), str) for e in p["examples"]):
        return "every example needs a before and an after string"
    return ""


def source_orgs(p: dict) -> list[str]:
    """The GitHub orgs of the repos a pattern was seen in ("unknown" when P2 gives none, so it is never taken as ours)."""
    return sorted({r.split("/", 1)[0] for r in p.get("repos") or [] if isinstance(r, str) and "/" in r}) or ["unknown"]


def split_examples(examples: list[dict]) -> tuple[list[dict], list[dict]]:
    """(examples shown to the model, held-out examples it never sees): every third example is held out.
    Repeats (the same before/after, e.g. two review tools on one line) are dropped first, so a held-out example
    is never also shown to the model."""
    seen: set = set()
    examples = [e for e in examples
                if not ((k := (" ".join(e["before"].split()), " ".join(e["after"].split()))) in seen or seen.add(k))]
    return ([e for i, e in enumerate(examples) if i % 3 != 2], [e for i, e in enumerate(examples) if i % 3 == 2])


def clean_files(repo: Path, exts: tuple[str, ...]) -> list[Path]:
    """This repo's own code in one language, the sample a new rule must stay silent on."""
    out = []
    for f in sorted(repo.rglob("*")):
        rel = f.relative_to(repo).as_posix()
        if f.is_file() and f.suffix in exts and not any(rel.startswith(x) or f"/{x}" in f"/{rel}" for x in NOT_CLEAN):
            out.append(f)
    return out


# ---------------------------------------------------------------- drafting (OpenRouter)
def prompt(p: dict, train: list[dict], rule_id: str, ext: str, feedback: str) -> str:
    """The drafting request. Held-out examples are never part of it."""
    c = COMMENT[ext]
    cwe_field = "" if p["cwe"] else '\n- "cwe": the CWE id that fits this weakness best, as CWE-<n>.'
    ex = "\n\n".join(f"### Example {i + 1}\nVulnerable (before):\n```\n{e['before']}\n```\nFixed (after):\n```\n{e['after']}\n```"
                     for i, e in enumerate(train))
    return f"""Write one Opengrep rule (language: {p['stack']}) for this recurring weakness.

Weakness: {p['summary']}
Kind of mistake: {p.get('pattern', 'unknown')}
CWE: {p['cwe'] or 'not known: propose the one CWE that fits best, in the "cwe" field'}
Rule id: {rule_id}

{ex}

Reply with ONE JSON object and nothing else, with these string fields:
- "rule": YAML for the matching part of the rule only, using only these keys: {", ".join(sorted(ALLOWED_KEYS))}
  (and inside them pattern-not, pattern-inside, pattern-not-inside, metavariable-regex, metavariable-pattern,
  focus-metavariable). No id, languages, severity, message, metadata, paths or options.
  It must match every vulnerable example, none of the fixed ones, and not ordinary safe code.
- "message": one or two plain English sentences: what is wrong, why it matters, how to fix it.
- "fix": one short concrete fix.{cwe_field}
- "fixture": a NEW synthetic {p['stack']} test file. Do not reuse lines from the examples. Put the comment
  `{c} ruleid: {rule_id}` on the line before each line the rule must flag (at least 3), and `{c} ok: {rule_id}`
  on the line before each safe look-alike it must not flag (at least 3). Every element of the rule (each
  pattern-either branch, each pattern-not) must be needed by at least one annotated line.
""" + (f"\nYour previous draft was rejected: {feedback}\nFix that.\n" if feedback else "")


def draft_with_llm(p: dict, train: list[dict], rule_id: str, ext: str, feedback: str, model: str) -> dict:
    """Ask the model for a draft. Returns the parsed JSON object; raises Reject on any failure."""
    key = os.environ.get("OPENROUTER_API_KEY", "")
    body = json.dumps({"model": model, "temperature": 0.2, "messages": [
        {"role": "system", "content": "You write precise Opengrep security rules. Reply with JSON only."},
        {"role": "user", "content": prompt(p, train, rule_id, ext, feedback)}]}).encode()
    req = urllib.request.Request(OPENROUTER_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json", "X-Title": "sast-check learner"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:   # noqa: S310 - fixed https URL
            content = json.loads(r.read())["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        raise Reject(f"drafting failed: OpenRouter HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise Reject(f"drafting failed: {type(e).__name__}") from None
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise Reject("drafting failed: unexpected OpenRouter response") from None
    return parse_reply(content)


def parse_reply(content) -> dict:
    """The JSON object in a model reply (a ```json fence around it is tolerated)."""
    if not isinstance(content, str):
        raise Reject("draft is not text")
    m = re.search(r"\{.*\}", content, re.S)
    try:
        d = json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        d = None
    if not isinstance(d, dict):
        raise Reject("draft is not a JSON object")
    return d


# ---------------------------------------------------------------- building and checking a draft
def build_rule(p: dict, d: dict, rule_id: str) -> tuple[str, str]:
    """(rule file text, fixture text) from a draft; raises Reject when the draft breaks the contract."""
    for k in ("rule", "message", "fix", "fixture"):
        if not isinstance(d.get(k), str) or not d[k].strip():
            raise Reject(f"draft field {k!r} missing or empty")
    if len(d["message"]) > 500 or len(d["fix"]) > 300:
        raise Reject("draft message or fix is too long")
    try:
        body = yaml.safe_load(d["rule"])
    except yaml.YAMLError:
        raise Reject("draft rule is not valid YAML") from None
    if isinstance(body, dict) and isinstance(body.get("rules"), list) and len(body["rules"]) == 1:
        body = body["rules"][0]   # a whole rule file: keep only its matching part (checked below)
        body = {k: v for k, v in body.items() if k not in ("id", "languages", "severity", "message", "metadata")}
    if not isinstance(body, dict) or not body:
        raise Reject("draft rule is not a YAML mapping")
    extra = sorted(set(body) - ALLOWED_KEYS)
    if extra:
        raise Reject(f"draft rule uses keys that are not allowed: {extra}")
    taint = {"mode", "pattern-sources", "pattern-sinks", "pattern-sanitizers"}
    if taint & set(body) and (body.get("mode") != "taint" or not {"pattern-sources", "pattern-sinks"} <= set(body)
                              or set(body) - taint):
        raise Reject("draft rule: a taint rule needs mode: taint, pattern-sources and pattern-sinks, and nothing else")
    _, langs, _, _ = STACKS[p["stack"]]
    cwe = p["cwe"] or d.get("cwe")   # the pattern's CWE wins; the model's is used only when the pattern has none
    if not (isinstance(cwe, str) and CWE.fullmatch(cwe)):
        raise Reject(f"draft gives no CWE of the form CWE-<n> (got {cwe!r})")
    n = cwe.split("-", 1)[1]
    rule = {"id": rule_id, "languages": langs, "severity": SEVERITY[p["impact_band"]],
            "message": " ".join(d["message"].split()),
            "metadata": {"sast_severity": p["impact_band"], "confidence": "medium", "cwe": cwe,
                         "category": "security", "fix": " ".join(d["fix"].split()),
                         "learner_pattern_id": p["id"],
                         "references": [f"https://cwe.mitre.org/data/definitions/{n}.html"]},
            **body}
    head = (f"# Drafted by tools/learner_rules.py from learner pattern {p['id']} ({p['hits']} hits).\n"
            "# Accepted by its checks; a human reviews and merges it.\n")
    return head + yaml.dump({"rules": [rule]}, Dumper=BlockDumper, sort_keys=False, width=1000), d["fixture"].rstrip() + "\n"


class BlockDumper(yaml.SafeDumper):
    """Writes multi-line patterns (pattern-inside blocks) as readable `|` blocks."""


BlockDumper.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None))


def norm(line: str) -> str:
    return " ".join(line.split())


def copied_line(fixture: str, examples: list[dict]) -> str:
    """A fixture line that repeats an example line (examples can be private code), or ""."""
    seen = {norm(ln) for e in examples for s in (e["before"], e["after"]) for ln in s.splitlines()
            if len(norm(ln)) >= COPY_MIN}
    return next((norm(ln) for ln in fixture.splitlines() if norm(ln) in seen), "")


def engine_cmd(engine: str) -> list[str]:
    """The scan command, with the same flags as tests/rules_test.py."""
    return [engine, "scan", "--json", "--quiet", "--scan-unknown-extensions", "--taint-intrafile"]


def scan(engine: str, rule_file: Path, files: list[Path]) -> dict[Path, list[int]]:
    """Flagged lines per file. An engine that rejects the rule or fails to finish raises Reject (fail closed)."""
    if not files:
        return {}
    try:
        r = subprocess.run(engine_cmd(engine) + ["--config", str(rule_file), "--"] + [str(f) for f in files],
                           capture_output=True, text=True, timeout=ENGINE_TIMEOUT)
        out = json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        raise Reject(f"{Path(engine).name} timed out") from None
    except json.JSONDecodeError:
        raise Reject(f"{Path(engine).name} failed (exit {r.returncode}, no JSON)") from None
    errs = [e for e in out.get("errors", []) if "Syntax error" not in str(e.get("type"))
            and "PartialParsing" not in str(e.get("type"))]
    if errs:
        raise Reject(f"{Path(engine).name} rejects the rule: {' '.join(str(errs[0].get('message')).split())[:200]}")
    if r.returncode != 0:
        raise Reject(f"{Path(engine).name} failed (exit {r.returncode})")
    hits: dict[Path, list[int]] = {}
    for res in out.get("results", []):
        hits.setdefault(Path(res["path"]).resolve(), []).append(res["start"]["line"])
    return hits


def evaluate(p: dict, rule_text: str, fixture: str, train: list[dict], held: list[dict], repo: Path,
             engines: list[str], work: Path) -> None:
    """Run every acceptance check on one draft; raises Reject (or HeldOutMiss) with the first failure."""
    area, _, ext, exts = STACKS[p["stack"]]
    slug = p["id"]
    line = copied_line(fixture, train + held)
    if line:
        # the line itself is never quoted: examples can be private code, and reasons reach reports and PR bodies
        raise Reject("fixture copies a line from an example; fixtures must be new synthetic code")
    ex = work / "examples"
    shutil.rmtree(ex, ignore_errors=True)
    ex.mkdir(parents=True)
    files = {}
    for kind, group in (("train", train), ("held", held)):
        for i, e in enumerate(group):
            for side in ("before", "after"):
                f = ex / f"{kind}-{i}-{side}{ext}"
                f.write_text(e[side])
                files[(kind, i, side)] = f.resolve()
    rule_file = work / "rule.yaml"
    rule_file.write_text(rule_text)
    clean = [f.resolve() for f in clean_files(repo, exts)]
    for eng in engines:
        name = Path(eng).name
        hits = scan(eng, rule_file, list(files.values()))
        for (kind, i, side), f in sorted(files.items()):
            if side == "after" and f in hits:
                which = "a held-out example" if kind == "held" else f"example {i + 1}"
                raise Reject(f"{name}: matches the fixed code of {which}")
            if side == "before" and f not in hits:
                if kind == "held":
                    raise HeldOutMiss(f"{name}: misses a held-out vulnerable example")
                raise Reject(f"{name}: misses the vulnerable code of example {i + 1}")
        hits = scan(eng, rule_file, clean)
        if hits:
            f, lines = sorted(hits.items())[0]
            raise Reject(f"{name}: fires on this repo's own code ({f.relative_to(repo.resolve()).as_posix()}:{lines[0]})")
    # the fixture, with the repo's own test tools, in a scratch copy holding only this rule
    mini = work / "mini"
    shutil.rmtree(mini, ignore_errors=True)
    for rel in ("tests/rules_test.py", "tools/rule_mutation.py", "tests/mutation-baseline.json"):
        (mini / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / rel, mini / rel)
    (mini / "rules" / "custom" / area).mkdir(parents=True)
    (mini / "rules" / "custom" / area / f"{slug}.yaml").write_text(rule_text)
    (mini / "rules" / "custom" / area / f"{slug}{ext}").write_text(fixture)
    for eng in engines:
        r = subprocess.run([sys.executable, str(mini / "tests" / "rules_test.py"), "--engine", eng],
                           capture_output=True, text=True, timeout=ENGINE_TIMEOUT)
        if r.returncode != 0:
            fail = next((ln for ln in r.stdout.splitlines() if ln.startswith("FAIL")), r.stderr.strip()[-200:])
            raise Reject(f"fixture test ({Path(eng).name}): {fail[:240]}")
    r = subprocess.run([sys.executable, str(mini / "tools" / "rule_mutation.py"), "--engine", engines[0],
                        "--rules", f"{area}/{slug}.yaml", "--check", str(mini / "tests" / "mutation-baseline.json")],
                       capture_output=True, text=True, timeout=ENGINE_TIMEOUT * 4)
    if r.returncode != 0:
        why = next((ln for ln in (r.stdout + r.stderr).splitlines() if ln.startswith(("NEW SURVIVOR", "ERROR"))),
                   f"exit {r.returncode}")
        raise Reject(f"mutation check: {why[:240]}")


# ---------------------------------------------------------------- the run
def target_ids(target: Path) -> set[str]:
    """Rule ids already in a private rules repo's .sast-check/rules/ (unreadable files count as taken names only)."""
    ids = set()
    for f in sorted((target / LOCAL_DIR).glob("*.y*ml")):
        try:
            ids |= {r["id"] for r in yaml.safe_load(f.read_text())["rules"] if isinstance(r, dict) and "id" in r}
        except (yaml.YAMLError, TypeError, KeyError, OSError, ValueError):   # ValueError: not UTF-8
            continue   # check_target refuses the whole folder later
    return ids


def run(patterns: list, repo: Path, engines: list[str], drafter, attempts: int = 2, target: Path | None = None) -> dict:
    """Process every pattern. Writes accepted rules and fixtures under repo/rules/custom and nothing else, or,
    with TARGET (a checkout of a private rules repo), under TARGET/.sast-check/rules as `local.` rules.
    Returns {"accepted": [...], "rejected": [...], "skipped": [...]}."""
    report = {"accepted": [], "rejected": [], "skipped": []}
    lock = repo / "dist" / "rule-ids.lock"
    retired = repo / "rules" / "RETIRED.txt"
    taken = set(lock.read_text().split() if lock.exists() else []) | set(retired.read_text().split() if retired.exists() else [])
    if target is not None:
        taken = target_ids(target)
    seen = set()
    with tempfile.TemporaryDirectory() as td:
        for n, p in enumerate(patterns):
            pid = p.get("id") if isinstance(p, dict) and isinstance(p.get("id"), str) else f"#{n + 1}"
            if isinstance(p, dict) and isinstance(p.get("hits"), int) and not isinstance(p.get("hits"), bool) \
                    and p["hits"] < MIN_HITS:
                report["skipped"].append({"id": pid, "reason": f"{p['hits']} hits (needs {MIN_HITS})"})
                continue
            bad = check_pattern(p)
            if bad:
                report["rejected"].append({"id": pid, "reason": bad})
                continue
            area, _, ext, exts = STACKS[p["stack"]]
            rule_id = f"{'local' if target is not None else 'sast'}.{area}.{p['id']}"
            dest = repo / "rules" / "custom" / area if target is None else target / LOCAL_DIR
            fx_dest = dest if target is None else dest / "tests"
            if rule_id in taken or rule_id in seen or (dest / f"{p['id']}.yaml").exists() \
                    or (fx_dest / f"{p['id']}{ext}").exists() or (fx_dest / f"{p['id']}{ext}").is_symlink():
                report["skipped"].append({"id": pid, "reason": f"{rule_id} already exists, was shipped or retired"})
                continue
            seen.add(rule_id)
            train, held = split_examples(p["examples"])
            if len(train) + len(held) < MIN_EXAMPLES:
                report["skipped"].append({"id": pid, "reason": f"needs {MIN_EXAMPLES}+ distinct examples so one can be "
                                                               f"held out (has {len(train) + len(held)})"})
                continue
            if not clean_files(repo, exts):
                report["rejected"].append({"id": pid, "reason": f"no {p['stack']} code in this repo to prove the rule "
                                                                "stays silent on clean code"})
                continue
            feedback, reason = "", ""
            for attempt in range(1, attempts + 1):
                work = Path(td) / f"{p['id']}-{attempt}"
                work.mkdir()
                try:
                    rule_text, fixture = build_rule(p, drafter(p, train, rule_id, ext, feedback), rule_id)
                    evaluate(p, rule_text, fixture, train, held, repo, engines, work)
                except HeldOutMiss as e:
                    reason = f"attempt {attempt}: {e}"
                    break
                except Reject as e:
                    reason = feedback = f"attempt {attempt}: {e}"
                    continue
                fx_dest.mkdir(parents=True, exist_ok=True)
                (dest / f"{p['id']}.yaml").write_text(rule_text)
                (fx_dest / f"{p['id']}{ext}").write_text(fixture)
                report["accepted"].append({"id": pid, "rule_id": rule_id, "hits": p["hits"],
                                           "cwe": yaml.safe_load(rule_text)["rules"][0]["metadata"]["cwe"],
                                           "cwe_source": "pattern" if p["cwe"] else "drafted", "orgs": source_orgs(p),
                                           "severity": p["impact_band"], "blocking": SEVERITY[p["impact_band"]] == "ERROR",
                                           "held_out": len(held), "attempts": attempt,
                                           "files": [(dest / f"{p['id']}.yaml").relative_to(target or repo).as_posix(),
                                                     (fx_dest / f"{p['id']}{ext}").relative_to(target or repo).as_posix()]})
                reason = ""
                break
            if reason:
                report["rejected"].append({"id": pid, "reason": reason})
    return report


def build_dist(repo: Path, report: dict) -> str:
    """Rebuild dist/ (rule bundle + ID lock). On failure, remove this run's rules again and return the error."""
    r = subprocess.run([sys.executable, str(repo / "scripts" / "build_rules.py")], cwd=repo, capture_output=True, text=True)
    if r.returncode == 0:
        return ""
    for a in report["accepted"]:
        for f in a["files"]:
            (repo / f).unlink(missing_ok=True)
    report["accepted"] = []
    return (r.stderr or r.stdout).strip()[-400:]


def target_problem(target: Path) -> str:
    """Why TARGET cannot take rules ("" if it can): every folder on the way must be a real folder (a link
    would send writes outside the checkout), and its settings must keep the fixtures out of its own scans
    (they hold findings on purpose)."""
    for rel in (".sast-check", LOCAL_DIR, LOCAL_DIR + "/tests"):
        p = target / rel
        if p.is_symlink() or (p.exists() and not p.is_dir()):
            return f"{rel} in the target must be a folder, not a symlink or file"
    sys.path.insert(0, str(ROOT / "scripts"))
    import sast  # the scanner's own settings reader
    try:
        cfg = sast.load_config(sast.settings_file(target, None, ".sast-check.toml"))
    except (RuntimeError, ValueError) as e:
        return f"the target's .sast-check.toml is invalid: {e}"
    if not sast.glob_any(f"{LOCAL_DIR}/tests/x.py", cfg["paths"]["exclude"]):
        return (f"the target's .sast-check.toml must exclude the fixtures: add \"{LOCAL_DIR}/tests/**\" to "
                "[paths] exclude")
    return ""


def private_repo(target: Path) -> str:
    """owner/name of TARGET's origin, checked to be a private GitHub repo; raises ValueError otherwise. The rules
    come from private code, so nothing may be pushed or proposed to a public (or internal) repo. Every URL git
    would use for origin (the fetch URL and each push URL) must name that same private repo."""
    def git_urls(*args):
        r = subprocess.run(["git", "remote", "get-url", *args, "origin"], cwd=target, capture_output=True,
                           text=True, check=False)
        return r.stdout.split() if r.returncode == 0 else []

    urls = git_urls() + git_urls("--push", "--all")
    if not urls:
        raise ValueError("the target has no origin remote")
    names = set()
    for url in dict.fromkeys(urls):
        r = subprocess.run(["gh", "repo", "view", url, "--json", "nameWithOwner,visibility"], cwd=target,
                           capture_output=True, text=True, check=False, timeout=60)
        try:
            info = json.loads(r.stdout) if r.returncode == 0 else {}
        except ValueError:
            info = {}
        if info.get("visibility") != "PRIVATE" or not info.get("nameWithOwner"):
            raise ValueError(f"the target's origin URL {url} must be a private GitHub repo "
                             f"(got {info.get('visibility', 'unknown')})")
        names.add(info["nameWithOwner"])
    if len(names) != 1:
        raise ValueError(f"the target's origin fetch and push URLs name different repos: {', '.join(sorted(names))}")
    return names.pop()


def check_target(target: Path, report: dict, engine: str | None = None) -> str:
    """Check TARGET's rules exactly as sast-check will read them (ids, metadata, keys, Opengrep). On failure,
    remove this run's files again and return the error."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import sast  # the scanner's own reader, so a rule it would refuse never reaches a PR
    try:
        sast.validate_local_rules(sast.parse_local_rules(sast.local_rule_files(target, None)), engine)
        return ""
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        for a in report["accepted"]:
            for f in a["files"]:
                (target / f).unlink(missing_ok=True)
        report["accepted"] = []
        return str(e)[-400:]


def pr_body(report: dict, model: str) -> str:
    """The pull request description: ids, counts and reasons only (never example code)."""
    out = ["Rules drafted by `tools/learner_rules.py` from recurring review findings (learner P3).", "",
           f"Model: `{model}` (OpenRouter). Each rule matched every vulnerable example including held-out ones, "
           "none of the fixed examples, nothing in this repo's own code, passed its synthetic fixture with "
           "Opengrep, and had no surviving mutant. **A human reviews and merges; nothing here auto-merges.**",
           "", "## Accepted", "", "| rule | CWE | hits | severity | blocking | source orgs |", "|---|---|---|---|---|---|"]
    out += [f"| `{a['rule_id']}` | {a['cwe']}{' (drafted: check it)' if a.get('cwe_source') == 'drafted' else ''} "
            f"| {a['hits']} | {a['severity']} | {'yes' if a['blocking'] else 'warning'} "
            f"| {', '.join(a.get('orgs', ['unknown']))} |"
            for a in report["accepted"]]
    cross = [a for a in report["accepted"] if set(a.get("orgs", ["unknown"])) - {HOME_ORG}]
    if cross:
        out += ["", "## Owner approval needed: rules from another org's code", "",
                f"These rules were drafted from patterns seen outside {HOME_ORG}. Per the learning boundaries in "
                "SathiaAI/quality-gate `learner/DATA_DICTIONARY.md`, merging them needs the owner's approval recorded "
                "on this PR (or remove them first):", ""]
        out += [f"- `{a['rule_id']}` (from {', '.join(a.get('orgs', ['unknown']))})" for a in cross]
    if report["rejected"] or report["skipped"]:
        out += ["", "## Not turned into rules", ""]
        out += [f"- `{x['id']}`: rejected, {x['reason']}" for x in report["rejected"]]
        out += [f"- `{x['id']}`: skipped, {x['reason']}" for x in report["skipped"]]
    return "\n".join(out) + "\n"


def sh(cmd: list[str], repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=repo, capture_output=True, text=True, check=True, timeout=300)


def open_pr(repo: Path, report: dict, base: str, model: str, runner=sh, dist: bool = True, gh_repo: str = "") -> str:
    """Commit this run's rules on learner/rules-<date> and open one PR against base (in REPO: sast-check, or a
    private rules repo with dist=False). Never merges."""
    branch = f"learner/rules-{date.today().isoformat()}"
    files = [f for a in report["accepted"] for f in a["files"]] + (["dist/rules.yaml", "dist/rule-ids.lock"] if dist else [])
    runner(["git", "checkout", "-b", branch], repo)
    runner(["git", "add", "--"] + files, repo)
    runner(["git", "commit", "-m", f"feat(rules): {len(report['accepted'])} learner rule(s) from review patterns"], repo)
    runner(["git", "push", "-u", "origin", branch], repo)
    body = Path(tempfile.mkstemp(suffix=".md")[1])
    try:
        body.write_text(pr_body(report, model))
        r = runner(["gh", "pr", "create", *(["-R", gh_repo] if gh_repo else []), "--base", base, "--head", branch,
                    "--title", f"Learner rules {date.today().isoformat()}", "--body-file", str(body)], repo)
    finally:
        body.unlink(missing_ok=True)
    return r.stdout.strip()


def main() -> int:
    """Draft, check and (optionally) open a PR for rules from the learner's recurring patterns."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns", required=True, help="patterns.json from the quality-gate learner (learner-patterns/v1)")
    ap.add_argument("--engine", default=shutil.which("opengrep"), help="opengrep (the CI engine)")
    ap.add_argument("--model", default=os.environ.get("LEARNER_MODEL", DEFAULT_MODEL))
    ap.add_argument("--attempts", type=int, default=2, help="drafts per pattern (default 2)")
    ap.add_argument("--report", help="write the accept/reject report (JSON) here")
    ap.add_argument("--open-pr", action="store_true", help="commit on a new branch and open one PR (needs git + gh)")
    ap.add_argument("--base", default="main", help="base branch of the PR (default main)")
    ap.add_argument("--target", help="checkout of a private rules repo: write `local.` rules to its .sast-check/rules/ "
                                     "(and open the PR there) instead of this repo's rules/custom/")
    a = ap.parse_args()
    target = Path(a.target).resolve() if a.target else None
    if target is not None and (not (target / ".git").exists() or target == ROOT or target.is_relative_to(ROOT)):
        print("--target must be a separate git checkout (the private rules repo)", file=sys.stderr)
        return 2
    out_repo = target or ROOT
    gh_repo = ""
    if target is not None and (why := target_problem(target)):
        print(f"--target: {why}", file=sys.stderr)
        return 2
    if not a.engine or Path(a.engine).name != "opengrep":
        print("opengrep is required (the only supported engine)", file=sys.stderr)
        return 2
    if not os.environ.get("OPENROUTER_API_KEY"):
        print("OPENROUTER_API_KEY is not set", file=sys.stderr)
        return 2
    if a.attempts < 1:
        print("--attempts must be at least 1", file=sys.stderr)
        return 2
    # the report must never replace a file this run writes (dist/ or a rule/fixture under rules/)
    if a.report and any(Path(a.report).resolve().is_relative_to(ROOT / d) for d in ("dist", "rules")):
        print("--report must be outside dist/ and rules/", file=sys.stderr)
        return 2
    if a.report and target is not None and any(Path(a.report).resolve().is_relative_to(d) for d in (target, ROOT)):
        # inside the target it would be committed with the rules; inside this public checkout it could be pushed
        print("--report must be outside the --target checkout and this repo", file=sys.stderr)
        return 2
    try:
        patterns = load_patterns(Path(a.patterns))
    except (OSError, ValueError) as e:
        print(f"cannot read patterns: {e}", file=sys.stderr)
        return 2
    if a.open_pr:
        if subprocess.run(["git", "status", "--porcelain"], cwd=out_repo, capture_output=True, text=True).stdout.strip():
            print("--open-pr needs a clean working tree", file=sys.stderr)
            return 2
        branch = f"learner/rules-{date.today().isoformat()}"
        if subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=out_repo,
                          capture_output=True).returncode == 0:
            print(f"branch {branch} already exists in the checkout: remove it or review that work first", file=sys.stderr)
            return 2
        if target is not None:
            try:
                gh_repo = private_repo(target)
            except ValueError as e:
                print(f"--target: {e}", file=sys.stderr)
                return 2
        if subprocess.run(["git", "ls-remote", "--exit-code", "--heads", "origin", branch], cwd=out_repo,
                          capture_output=True).returncode != 2:   # 2 = no such branch; anything else stops the run
            print(f"branch {branch} already exists on origin (or origin is unreachable): review that PR first", file=sys.stderr)
            return 2

    def drafter(p, train, rule_id, ext, feedback):
        return draft_with_llm(p, train, rule_id, ext, feedback, a.model)

    report = run(patterns, ROOT, [a.engine], drafter, a.attempts, target)
    err = ((check_target(target, report, a.engine) if target is not None else build_dist(ROOT, report))
           if report["accepted"] else "")
    for x in report["accepted"]:
        print(f"ACCEPTED {x['rule_id']} ({x['cwe']}, {x['severity']}{', blocking' if x['blocking'] else ''})")
    for x in report["rejected"]:
        print(f"REJECTED {x['id']}: {x['reason']}")
    for x in report["skipped"]:
        print(f"SKIPPED  {x['id']}: {x['reason']}")
    if a.report:
        Path(a.report).write_text(json.dumps(report, indent=1) + "\n")
    if err:
        print(f"{'the rules check' if target is not None else 'scripts/build_rules.py'} failed, nothing kept: {err}",
              file=sys.stderr)
        return 2
    if a.open_pr and report["accepted"]:
        try:
            print(open_pr(out_repo, report, a.base, a.model, dist=target is None, gh_repo=gh_repo))
        except subprocess.CalledProcessError as e:
            print(f"opening the PR failed at `{' '.join(e.cmd[:3])}`: {(e.stderr or '').strip()[-300:]}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
