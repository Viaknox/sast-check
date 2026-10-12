#!/usr/bin/env python3
"""sast-check: run several open-source scanners, merge findings, apply one policy.

Stdlib only (Python 3.11+). Exit codes: 0 pass, 1 blocking findings, 2 scanner error.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEV_ORDER = ["low", "medium", "high", "critical"]

# Ruff S-rule severities (baseline from our coverage checklist; unlisted S codes -> low).
RUFF_SEVERITY = {
    "S301": "critical", "S302": "critical", "S307": "critical", "S506": "critical",
    "S413": "high", "S102": "high", "S602": "high", "S201": "high", "S701": "high",
    "S608": "high", "S507": "high", "S501": "high",
    "S605": "medium", "S314": "medium", "S317": "medium", "S318": "medium", "S320": "medium",
    "S306": "medium", "S321": "medium", "S202": "medium", "S610": "medium", "S611": "medium",
    "S324": "medium", "S502": "medium", "S503": "medium", "S504": "medium", "S323": "medium",
}
RUFF_LOW_SIGNAL_IN_TESTS = {"S101", "S105", "S106", "S107", "S108", "S311", "S603", "S607"}
ZIZMOR_OVERRIDE = {"known-vulnerable-actions": "critical"}

# CWE on every rule (learner-agent contract). Mappings are ours; unmapped codes fall back to CWE-710.
RUFF_CWE = {
    "S101": "CWE-703", "S102": "CWE-94", "S103": "CWE-732", "S104": "CWE-605", "S105": "CWE-259",
    "S106": "CWE-259", "S107": "CWE-259", "S108": "CWE-377", "S110": "CWE-703", "S112": "CWE-703",
    "S113": "CWE-400", "S201": "CWE-94", "S202": "CWE-22", "S301": "CWE-502", "S302": "CWE-502",
    "S303": "CWE-327", "S304": "CWE-327", "S305": "CWE-327", "S306": "CWE-377", "S307": "CWE-95",
    "S308": "CWE-79", "S310": "CWE-22", "S311": "CWE-330", "S312": "CWE-319", "S313": "CWE-611",
    "S314": "CWE-611", "S315": "CWE-611", "S316": "CWE-611", "S317": "CWE-611", "S318": "CWE-611",
    "S319": "CWE-611", "S320": "CWE-611", "S321": "CWE-319", "S323": "CWE-295", "S324": "CWE-327",
    "S401": "CWE-319", "S402": "CWE-319", "S403": "CWE-502", "S404": "CWE-78", "S405": "CWE-611",
    "S406": "CWE-611", "S407": "CWE-611", "S408": "CWE-611", "S409": "CWE-611", "S410": "CWE-611",
    "S411": "CWE-611", "S412": "CWE-807", "S413": "CWE-327", "S415": "CWE-319", "S501": "CWE-295",
    "S502": "CWE-327", "S503": "CWE-327", "S504": "CWE-327", "S505": "CWE-326", "S506": "CWE-502",
    "S507": "CWE-295", "S508": "CWE-319", "S509": "CWE-326", "S601": "CWE-78", "S602": "CWE-78",
    "S603": "CWE-78", "S604": "CWE-78", "S605": "CWE-78", "S606": "CWE-78", "S607": "CWE-78",
    "S608": "CWE-89", "S609": "CWE-155", "S610": "CWE-89", "S611": "CWE-89", "S612": "CWE-94",
    "S701": "CWE-79", "S702": "CWE-79", "S704": "CWE-79",
}
ZIZMOR_CWE = {
    "template-injection": "CWE-94", "github-env": "CWE-94", "insecure-commands": "CWE-77",
    "unpinned-uses": "CWE-829", "unpinned-images": "CWE-829", "unpinned-tools": "CWE-829",
    "impostor-commit": "CWE-829", "ref-confusion": "CWE-829", "typosquat-uses": "CWE-829",
    "stale-action-refs": "CWE-829", "adhoc-packages": "CWE-829", "forbidden-uses": "CWE-829",
    "dependabot-execution": "CWE-829", "dependabot-cooldown": "CWE-829",
    "known-vulnerable-actions": "CWE-1395", "archived-uses": "CWE-1104",
    "dangerous-triggers": "CWE-863", "bot-conditions": "CWE-290",
    "excessive-permissions": "CWE-250", "undocumented-permissions": "CWE-250",
    "overprovisioned-secrets": "CWE-250", "secrets-inherit": "CWE-250", "secrets-outside-env": "CWE-250",
    "self-hosted-runner": "CWE-250", "github-app": "CWE-250",
    "artipacked": "CWE-522", "use-trusted-publishing": "CWE-522",
    "hardcoded-container-credentials": "CWE-798", "unredacted-secrets": "CWE-532",
    "cache-poisoning": "CWE-349", "insecure-url-scheme": "CWE-319", "concurrency-limits": "CWE-400",
    "unsound-condition": "CWE-697", "unsound-contains": "CWE-697", "unsound-ternary": "CWE-697",
}
LOCKFILES = {  # every manifest osv-scanner v2 scans (google.github.io/osv-scanner/supported-languages-and-lockfiles)
    "conan.lock", "pubspec.lock", "mix.lock", "go.mod", "cabal.project.freeze", "stack.yaml.lock",
    "buildscript-gradle.lockfile", "gradle.lockfile", "verification-metadata.xml", "pom.xml",
    "bun.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "deps.json",
    "packages.config", "packages.lock.json", "composer.lock", "Pipfile.lock", "poetry.lock",
    "requirements.txt", "pdm.lock", "pylock.toml", "uv.lock", "renv.lock", "Gemfile.lock",
    "gems.locked", "Cargo.lock",
}
# only inside a comment: # (py/sh/yaml/tf/docker), // or /* (js/ts/tf), <!-- (html)
IGNORE_RE = re.compile(r"(?:#|//|/\*|<!--)\s*sast-ignore\[(?P<rule>[^\]]+)\]\s*:?\s*(?P<reason>.*?)\s*(?:\*/|-->)?\s*$")


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    confidence: str
    path: str
    line: int
    message: str
    fix: str = ""
    cwe: str = ""
    url: str = ""
    kind: str = "code"          # code | secret | dependency | config
    fingerprint: str = ""       # hash(rule ID + normalized code snippet); survives line moves
    in_diff: bool = True
    end_line: int = 0           # last line of a multi-line match (0 = same as line)
    suppressed: str = ""        # reason, if suppressed
    blocking: bool = False


@dataclass
class ToolRun:
    name: str
    status: str                 # ran | skipped | error
    detail: str = ""
    count: int = 0


@dataclass
class Ctx:
    repo: Path
    cfg: dict
    mode: str
    base: str | None
    changed_lines: dict[str, set[int]] = field(default_factory=dict)
    changed_files: list[str] = field(default_factory=list)
    runs: list[ToolRun] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- helpers
def sh(cmd: list[str], cwd: Path, ok_codes=(0,), env=None, timeout=900) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"{cmd[0]} timed out after {timeout}s") from e
    if p.returncode not in ok_codes:
        raise RuntimeError(f"{cmd[0]} exited {p.returncode}: {(p.stderr or p.stdout)[-800:]}")
    return p


def deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


# Settings files a PR must not be able to change for its own scan. With a base ref (a PR), each is read
# from the base branch; a PR's change to one takes effect once it is merged.
SETTINGS_FILES = (".sast-check.toml", ".gitleaks.toml", ".gitleaksignore", "zizmor.yml", ".github/zizmor.yml",
                  "osv-scanner.toml", "trivy.yaml", ".trivyignore")


def settings_file(repo: Path, base: str | None, name: str) -> str | None:
    """Text of a settings file: from the base branch when scanning a PR, else from the working tree."""
    if not base:
        f = repo / name
        return f.read_text(errors="replace") if f.is_file() else None
    v = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"], cwd=repo, capture_output=True)
    if v.returncode != 0:   # an unknown base must fail closed, not read as "no settings file"
        raise RuntimeError(f"base {base} is not a commit in this checkout")
    p = subprocess.run(["git", "show", f"{base}:{name}"], cwd=repo, capture_output=True, text=True)
    if p.returncode == 0:
        return p.stdout
    if "does not exist" in p.stderr or "exists on disk, but not in" in p.stderr:
        return None
    raise RuntimeError(f"cannot read {name} from base {base}: {p.stderr.strip()[:200]}")


def load_config(text: str | None) -> dict:
    cfg = tomllib.loads((ROOT / "config" / "default.toml").read_text())
    if text is not None:
        uc = tomllib.loads(text)
        defaults_excl = cfg["paths"]["exclude"]
        cfg = deep_merge(cfg, uc)
        # user excludes ADD to the defaults (never silently re-include node_modules etc.)
        cfg["paths"]["exclude"] = sorted(set(defaults_excl) | set(cfg["paths"]["exclude"]))
    block_on = cfg["policy"].get("block_on")
    # a typo ("criticial") would match no finding and silently turn the gate into report-only: fail closed
    if not isinstance(block_on, list) or any(s not in SEV_ORDER for s in block_on):
        raise RuntimeError(f"policy.block_on must be a list of {', '.join(SEV_ORDER)}; got {block_on!r}")
    return cfg


def glob_any(path: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch("/" + path, "*/" + g.lstrip("*/")) for g in globs)


def rel(repo: Path, p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(repo.resolve()))
    except ValueError:
        return p.lstrip("./")


def unquote_git_path(p: str) -> str:
    """Git C-quotes unusual paths ("b/sp\\303\\251c.py"). Decode octal escapes as UTF-8 bytes."""
    if not (p.startswith('"') and p.endswith('"')):
        return p
    raw, out, i = p[1:-1], bytearray(), 0
    simple = {"n": 10, "t": 9, "r": 13, '"': 34, "\\": 92, "a": 7, "b": 8, "f": 12, "v": 11}
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in "01234567" and i + 3 < len(raw) + 1:
                out.append(int(raw[i + 1:i + 4], 8))
                i += 4
                continue
            out.append(simple.get(nxt, ord(nxt)))
            i += 2
            continue
        out += c.encode()
        i += 1
    return out.decode("utf-8", errors="replace")


def changed_lines(repo: Path, base: str) -> dict[str, set[int]]:
    """Map repo-relative file -> added/modified line numbers (merge-base vs working tree)."""
    if sh(["git", "rev-parse", "--is-shallow-repository"], repo).stdout.strip() == "true":
        raise RuntimeError("shallow clone: check out with fetch-depth: 0 so the PR diff can be computed")
    out = sh(["git", "diff", "-U0", "--no-color", "--text", "--no-textconv", "--no-ext-diff",
               "--diff-filter=ACMRT", "--merge-base", base], repo).stdout
    files: dict[str, set[int]] = {}
    cur = None
    old_left = new_left = 0      # lines still to come in the current hunk: inside a hunk nothing is a header
    hunk = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    for ln in out.split("\n"):  # "\n" only: str.splitlines() also splits on \r, \f, \x1c... inside file content
        if old_left or new_left:
            if ln.startswith("-"):
                old_left -= 1
            elif ln.startswith("+"):
                new_left -= 1
            elif ln.startswith(" "):
                old_left, new_left = old_left - 1, new_left - 1
            continue                                      # "\ No newline at end of file" counts as neither
        if ln.startswith("+++ "):
            hdr = unquote_git_path(ln[4:])
            cur = None if hdr == "/dev/null" else hdr[2:] if hdr.startswith("b/") else hdr
            if cur:
                files.setdefault(cur, set())
        elif (m := hunk.match(ln)) and cur:
            old_left = int(m.group(1) or 1)
            start, new_left = int(m.group(2)), int(m.group(3) or 1)
            files[cur].update(range(start, start + new_left))
            if new_left == 0:
                # pure deletion ("+N,0": lines removed after new line N). Deleting a protective line (e.g.
                # `owners = [...]`) can create a finding with no added line, so the lines on both sides of
                # the cut count as changed; a finding spanning the cut then counts as new.
                files[cur].update(n for n in (start, start + 1) if n >= 1)
    # a file in the diff with no hunk (a 100% rename or copy, e.g. payload.txt -> payload.py) still changed
    # what gets scanned: count it as fully changed
    ns = sh(["git", "diff", "--name-status", "-z", "-M", "-C", "--diff-filter=ACMRT", "--merge-base", base],
            repo).stdout.split("\0")
    i = 0
    while i < len(ns) - 1:
        status, i = ns[i], i + 1
        if status[:1] in ("R", "C"):
            i += 1                                    # skip the source path; the next field is the destination
        path, i = ns[i], i + 1
        if path and path not in files and (repo / path).is_file():
            with open(repo / path, errors="ignore") as fh:
                files[path] = set(range(1, sum(1 for _ in fh) + 1))
    # untracked new files (local runs) count as fully changed
    untracked = sh(["git", "ls-files", "-z", "--others", "--exclude-standard"], repo).stdout.split("\0")
    for f in filter(None, untracked):
        try:
            n = sum(1 for _ in open(repo / f, errors="ignore"))
        except OSError:
            continue
        files[f] = set(range(1, n + 1))
    return files


# ---------------------------------------------------------------- scanners
def targets(ctx: Ctx, exts: tuple[str, ...] | None = None, names: tuple[str, ...] = ()) -> list[str]:
    excl = ctx.cfg["paths"]["exclude"]
    files = ctx.changed_files if ctx.mode == "diff" else None
    if files is None:
        return ["."]
    keep = []
    for f in files:
        if glob_any(f, excl) or not (ctx.repo / f).is_file():
            continue
        if exts is None or f.endswith(exts) or Path(f).name in names:
            keep.append(f)
    return keep


def run_opengrep(ctx: Ctx) -> list[Finding]:
    engine = shutil.which("opengrep") or shutil.which("semgrep")
    if not engine:
        raise FileNotFoundError("opengrep (or semgrep) not installed")
    rules = ROOT / "dist" / "rules.yaml"
    if not rules.exists():
        sh([sys.executable, str(HERE / "build_rules.py")], ROOT)
    tg = targets(ctx)
    if not tg:
        return []
    # --disable-nosem: a PR's `// nosemgrep` comment must not hide a finding (only sast-ignore with a reason)
    # --x-ignore-semgrepignore-files: a PR's .semgrepignore/.opengrepignore must not hide files (full scans pass ".")
    cmd = [engine, "scan", "--config", str(rules), "--json", "--quiet", "--disable-version-check", "--disable-nosem",
           "--x-ignore-semgrepignore-files"]
    if Path(engine).name == "opengrep":
        cmd.append("--taint-intrafile")
    else:
        cmd += ["--metrics=off"]
    for g in ctx.cfg["paths"]["exclude"]:
        cmd += ["--exclude", g]
    p = sh(cmd + ["--"] + tg, ctx.repo, ok_codes=(0, 1))   # "--": a PR file named "--x" is never an option
    data = json.loads(p.stdout or "{}")
    errs = [e for e in data.get("errors", []) if e.get("level") == "error" and "Syntax error" not in str(e.get("type"))]
    if errs:
        raise RuntimeError(f"{len(errs)} engine errors: {str(errs[0])[:300]}")
    out = []
    for r in data.get("results", []):
        md = r["extra"].get("metadata", {})
        rid = r["check_id"]
        rid = rid[rid.find("sast."):] if "sast." in rid else rid
        out.append(Finding(
            tool="opengrep", rule=rid, severity=md.get("sast_severity", "medium"),
            confidence=md.get("confidence", "medium"), path=rel(ctx.repo, r["path"]),
            line=r["start"]["line"], end_line=r["end"]["line"], message=" ".join(r["extra"]["message"].split()),
            fix=md.get("fix", ""), cwe=str(md.get("cwe", "")),
            url=(md.get("references") or [""])[0],
        ))
    return out


def py_call_end(path: Path, row: int, col: int, cache: dict) -> int:
    """End line of the call that starts at (row, col); Ruff anchors e.g. S602 on `subprocess.run(`
    only, so a changed argument further down must still count as part of the finding."""
    if path not in cache:
        try:
            src = path.read_text(errors="ignore")
            cache[path] = ([n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)], src.splitlines())
        except (OSError, SyntaxError, ValueError):
            cache[path] = ([], [])
    calls, lines = cache[path]
    # ast col_offset is a UTF-8 byte offset; Ruff's column counts characters
    if not 0 < row <= len(lines):
        return row
    byte_col = len(lines[row - 1][:col - 1].encode("utf-8"))
    ends = [n.end_lineno for n in calls if n.lineno == row and n.col_offset == byte_col and n.end_lineno]
    return max(ends, default=row)


def notebook_line(path: Path, cell: int, row: int) -> tuple[int, int]:
    """Map Ruff's (cell, row) in a .ipynb to (line, end_line) in the file on disk.

    Jupyter writes one JSON string per source line, so the n-th string of the cell's "source" list is
    its row. If the layout is anything else (e.g. minified JSON), return the whole file so that any
    change to the notebook counts the finding as new (fail safe)."""
    try:
        lines = path.read_text(errors="ignore").split("\n")
    except OSError:
        return 1, 1
    seen, in_source, n = 0, False, 0
    for i, ln in enumerate(lines, 1):
        t = ln.strip()
        if t.startswith('"cell_type"'):
            seen, in_source = seen + 1, False
        elif seen == cell and t.startswith('"source"'):
            if t.endswith("[]") or t.endswith("[],"):
                break
            in_source, n = True, 0
            if t.endswith('"') or t.endswith('",'):   # "source": "single string"
                return (i, i) if row == 1 else (1, len(lines))
        elif in_source:
            if t.startswith("]"):
                break
            n += 1
            if n == row:
                return i, i
    return 1, len(lines)


def run_ruff(ctx: Ctx) -> list[Finding]:
    if not shutil.which("ruff"):
        raise FileNotFoundError("ruff not installed")
    tg = targets(ctx, (".py", ".pyi", ".pyw", ".ipynb"))
    if not tg:
        return []
    # --ignore-noqa: a PR's noqa comments must not hide a finding (only sast-ignore with a reason)
    # --no-respect-gitignore: a PR's .gitignore must not hide a committed file from a full scan
    cmd = ["ruff", "check", "--isolated", "--no-cache", "--preview", "--ignore-noqa", "--no-respect-gitignore",
           "--select", "S",
           "--output-format", "json", "--exit-zero"]
    for g in ctx.cfg["paths"]["exclude"]:
        cmd += ["--extend-exclude", g]
    data = json.loads(sh(cmd + ["--"] + tg, ctx.repo).stdout or "[]")
    calls: dict = {}
    out = []
    for r in data:
        code = r["code"]
        path = rel(ctx.repo, r["filename"])
        if code in RUFF_LOW_SIGNAL_IN_TESTS and glob_any(path, ctx.cfg["paths"]["tests"]):
            continue
        end_row = (r.get("end_location") or r["location"])["row"]
        if r.get("cell"):              # notebook: Ruff counts rows within a cell; map to file lines
            line, end = notebook_line(ctx.repo / path, r["cell"], r["location"]["row"])
            end = max(end, notebook_line(ctx.repo / path, r["cell"], end_row)[1])
        else:
            line = r["location"]["row"]
            end = max(end_row, py_call_end(ctx.repo / path, line, r["location"]["column"], calls))
        out.append(Finding(
            tool="ruff", rule=f"ruff.{code}", severity=RUFF_SEVERITY.get(code, "low"),
            confidence="medium", path=path, line=line, end_line=end,
            message=r["message"], url=r.get("url") or "", cwe=RUFF_CWE.get(code, "CWE-710"),
        ))
    return out


def run_zizmor(ctx: Ctx) -> list[Finding]:
    if not shutil.which("zizmor"):
        raise FileNotFoundError("zizmor not installed")
    if ctx.mode == "diff":
        tg = [f for f in targets(ctx, (".yml", ".yaml"))
              if f.startswith(".github/workflows/") or Path(f).name in ("action.yml", "action.yaml")]
    else:
        specs = ["--", ".github/workflows/*.yml", ".github/workflows/*.yaml", ":(glob)**/action.yml", ":(glob)**/action.yaml"]
        tracked = (sh(["git", "ls-files", "-z"] + specs, ctx.repo).stdout.split("\0")            # committed
                   + sh(["git", "ls-files", "-z", "--others", "--exclude-standard"] + specs,       # new, local runs
                        ctx.repo).stdout.split("\0"))
        tg = sorted({f for f in tracked if f and not glob_any(f, ctx.cfg["paths"]["exclude"])})
    if not tg:
        return []
    online = bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    # --no-ignores: a PR's `# zizmor: ignore[...]` must not hide a finding (only sast-ignore with a reason)
    cmd = ["zizmor", "--format", "json", "--no-progress", "--no-ignores"] + ([] if online else ["--offline"])
    with tempfile.TemporaryDirectory() as td:
        if ctx.base:   # PR scans: the base branch's zizmor config only (a PR's could switch audits off)
            conf = (settings_file(ctx.repo, ctx.base, "zizmor.yml")
                    or settings_file(ctx.repo, ctx.base, ".github/zizmor.yml"))
            if conf is None:
                cmd.append("--no-config")
            else:
                (Path(td) / "zizmor.yml").write_text(conf)
                cmd += ["--config", str(Path(td) / "zizmor.yml")]
        return zizmor_scan(ctx, cmd, tg, online)


def zizmor_scan(ctx: Ctx, cmd: list[str], tg: list[str], online: bool) -> list[Finding]:
    """Run zizmor (online, falling back to offline) and turn its results into findings."""
    # zizmor exit codes 10-14 mean "findings present"
    ok = (0, 10, 11, 12, 13, 14)
    try:
        p = sh(cmd + ["--"] + tg, ctx.repo, ok_codes=ok)
    except RuntimeError as e:
        if not online:
            raise
        # GitHub API unavailable/unauthorized: keep the offline audits rather than lose all of them
        p = sh(cmd + ["--offline", "--"] + tg, ctx.repo, ok_codes=ok)   # same settings flags, offline
        why = next((l.strip() for l in str(e).splitlines() if re.search(r"status|unauthorized|timed? ?out|dns", l, re.I)),
                   "GitHub API error")
        ctx.runs.append(ToolRun("zizmor-online", "skipped", "online audits unavailable (" + why[:160] + ")"))
    out = []
    for r in json.loads(p.stdout or "[]"):   # "ignored" is not honored: suppress only via sast-ignore / [[ignore]]
        det = r["determinations"]
        loc = next((l for l in r["locations"] if l["symbolic"].get("kind") == "Primary"), r["locations"][0])
        sev = ZIZMOR_OVERRIDE.get(r["ident"], det["severity"].lower().replace("informational", "low").replace("unknown", "low"))
        path = loc["symbolic"]["key"].get("Local", {}).get("verbatim_path") or loc["symbolic"]["key"].get("Local", {}).get("given_path", "")
        if glob_any(rel(ctx.repo, path), ctx.cfg["paths"]["exclude"]):   # excluded paths are never scanned
            continue
        out.append(Finding(
            tool="zizmor", rule=f"zizmor.{r['ident']}", severity=sev,
            confidence=det["confidence"].lower().replace("unknown", "low"),
            path=rel(ctx.repo, path), line=loc["concrete"]["location"]["start_point"]["row"] + 1,
            message=f"{r['desc']}: {loc['symbolic'].get('annotation', '')}".strip(": "),
            url=r.get("url", ""), kind="config", cwe=ZIZMOR_CWE.get(r["ident"], "CWE-710"),
        ))
    return out


def run_gitleaks(ctx: Ctx) -> list[Finding]:
    if not shutil.which("gitleaks"):
        raise FileNotFoundError("gitleaks not installed")
    reports = []
    with tempfile.TemporaryDirectory() as td:
        runs = []
        if ctx.mode == "diff":
            mb = sh(["git", "merge-base", ctx.base, "HEAD"], ctx.repo).stdout.strip()
            runs.append(["gitleaks", "git", f"--log-opts={mb}..HEAD"])          # the PR's commits
            runs.append(["gitleaks", "git", "--pre-commit"])                    # unstaged (local runs)
            runs.append(["gitleaks", "git", "--pre-commit", "--staged"])        # staged (local runs)
            untracked = sh(["git", "ls-files", "-z", "--others", "--exclude-standard"], ctx.repo).stdout.split("\0")
            runs += [["gitleaks", "dir", "--", f] for f in untracked
                     if f and not glob_any(f, ctx.cfg["paths"]["exclude"])]     # new, never-added files
        else:
            runs.append(["gitleaks", "dir", "."])
            if ctx.base:   # a secret added then deleted in the PR is gone from the tree but not from history
                mb = sh(["git", "merge-base", ctx.base, "HEAD"], ctx.repo).stdout.strip()
                runs.append(["gitleaks", "git", f"--log-opts={mb}..HEAD"])
        # PR scans use the base branch's .gitleaks.toml / .gitleaksignore, never the PR's (a PR could
        # allow-list its own secret). gitleaks always also reads <repo>/.gitleaksignore, so the PR's copy
        # is moved aside for the scan and put back afterwards.
        settings, aside = [], None
        if ctx.base:
            conf = settings_file(ctx.repo, ctx.base, ".gitleaks.toml")
            (Path(td) / "gitleaks.toml").write_text(conf if conf is not None else
                                                    (ROOT / "config" / "gitleaks.toml").read_text())
            (Path(td) / ".gitleaksignore").write_text(settings_file(ctx.repo, ctx.base, ".gitleaksignore") or "")
            settings = ["--config", str(Path(td) / "gitleaks.toml"), "--gitleaks-ignore-path", td]
            if (ctx.repo / ".gitleaksignore").is_file():
                aside = Path(td) / "pr.gitleaksignore"
                shutil.move(ctx.repo / ".gitleaksignore", aside)
        try:
            reports += gitleaks_runs(ctx, runs, settings, td)
        finally:
            if aside:
                shutil.move(aside, ctx.repo / ".gitleaksignore")
    return gitleaks_findings(ctx, reports)


def gitleaks_runs(ctx: Ctx, runs: list[list[str]], settings: list[str], td: str) -> list[dict]:
    """Run each gitleaks command with the given settings flags; return the raw JSON findings."""
    reports = []
    for i, cmd in enumerate(runs):
        rp = Path(td) / f"g{i}.json"
        # --ignore-gitleaks-allow: a PR's `gitleaks:allow` must not hide a secret
        opts = settings + ["--ignore-gitleaks-allow", "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json",
                           "--report-path", str(rp)]
        sh(cmd[:2] + opts + cmd[2:], ctx.repo)                   # options before any "--" / target
        if rp.exists() and rp.stat().st_size:
            reports += json.loads(rp.read_text())
    return reports


def gitleaks_findings(ctx: Ctx, reports: list[dict]) -> list[Finding]:
    """Deduplicate gitleaks results and turn them into findings (secret values stay redacted)."""
    out, seen = [], set()
    for r in reports:
        key = (r["File"], r["StartLine"], r["RuleID"])
        if key in seen or glob_any(rel(ctx.repo, r["File"]), ctx.cfg["paths"]["exclude"]):
            continue
        seen.add(key)
        out.append(Finding(
            tool="gitleaks", rule=f"secret.{r['RuleID']}", severity="critical", confidence="high",
            path=rel(ctx.repo, r["File"]), line=r["StartLine"], kind="secret", cwe="CWE-798",
            message=f"Possible secret committed ({r['Description']}). Value redacted.",
            fix="Revoke/rotate the credential first, then remove it from the code and git history.",
        ))
    return out


def run_osv(ctx: Ctx) -> list[Finding]:
    if not shutil.which("osv-scanner"):
        raise FileNotFoundError("osv-scanner not installed")
    if ctx.mode == "diff" and not any(Path(f).name in LOCKFILES and not glob_any(f, ctx.cfg["paths"]["exclude"])
                                      for f in ctx.changed_files):
        return []
    # 0 = clean, 1 = vulns found, 128 = no packages found
    with tempfile.TemporaryDirectory() as td:
        # --no-ignore: a PR's .gitignore must not hide a committed lockfile
        cmd = ["osv-scanner", "scan", "source", "-r", "--no-ignore", "--format", "json"]
        if ctx.base:   # PR scans: --config replaces every osv-scanner.toml in the tree (a PR's could hide vulns)
            conf = Path(td) / "osv-scanner.toml"
            conf.write_text(settings_file(ctx.repo, ctx.base, "osv-scanner.toml") or "")
            cmd.append(f"--config={conf}")
        p = sh(cmd + ["."], ctx.repo, ok_codes=(0, 1, 128))
    if p.returncode == 128 and ctx.mode == "diff":
        # a dependency manifest changed but OSV found no packages: unparseable or unsupported -> not a pass
        raise RuntimeError("osv-scanner found no packages although a dependency manifest changed")
    data = json.loads(p.stdout or "{}")
    out = []
    for res in data.get("results", []):
        src = rel(ctx.repo, res["source"]["path"])
        if ctx.mode == "diff" and src not in ctx.changed_files:
            continue
        if glob_any(src, ctx.cfg["paths"]["exclude"]):   # excluded paths are never scanned
            continue
        for pkg in res.get("packages", []):
            info = pkg["package"]
            for grp in pkg.get("groups", []):
                try:
                    score = float(grp.get("max_severity") or 0)
                except ValueError:
                    score = 0.0
                sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                ids = grp["ids"]
                out.append(Finding(
                    tool="osv-scanner", rule=f"dep.{ids[0]}", severity=sev, confidence="high",
                    path=src, line=1, kind="dependency", cwe="CWE-1395",
                    message=f"{info['name']}@{info.get('version', '?')} has known vulnerability {', '.join(ids[:3])}",
                    fix="Upgrade to a fixed version (see advisory).", url=f"https://osv.dev/vulnerability/{ids[0]}",
                ))
    return out


TRIVY_INLINE_RE = re.compile(rb"(trivy|tfsec):ignore", re.IGNORECASE)


def run_trivy(ctx: Ctx) -> list[Finding]:
    if not shutil.which("trivy"):
        raise FileNotFoundError("trivy not installed")
    with tempfile.TemporaryDirectory() as td:
        # Trivy has no switch for inline `trivy:ignore` / `tfsec:ignore` comments, so it scans a copy of the
        # tree with those markers defused (same length, so line numbers hold). Symlinks are not copied.
        work = Path(td) / "src"
        for d, dirs, names in os.walk(ctx.repo):
            reld = Path(d).relative_to(ctx.repo).as_posix()
            dirs[:] = [x for x in dirs if x != ".git" and not os.path.islink(os.path.join(d, x))
                       and not glob_any(f"{x}/" if reld == "." else f"{reld}/{x}/", ctx.cfg["paths"]["exclude"])]
            for n in names:
                src = Path(d) / n
                r = src.relative_to(ctx.repo).as_posix()
                if src.is_symlink() or not src.is_file() or glob_any(r, ctx.cfg["paths"]["exclude"]):
                    continue
                (work / r).parent.mkdir(parents=True, exist_ok=True)
                (work / r).write_bytes(TRIVY_INLINE_RE.sub(rb"\1_ignore", src.read_bytes()))
        work.mkdir(exist_ok=True)
        cmd = ["trivy", "config", "--quiet", "--format", "json"]
        if ctx.base:   # PR scans: the base branch's trivy.yaml / .trivyignore, never the PR's
            conf, ign = Path(td) / "trivy.yaml", Path(td) / "trivyignore"
            conf.write_text(settings_file(ctx.repo, ctx.base, "trivy.yaml") or "")
            ign.write_text(settings_file(ctx.repo, ctx.base, ".trivyignore") or "")
            cmd += ["--config", str(conf), "--ignorefile", str(ign)]
        p = sh(cmd + ["."], work)
    out = []
    for res in json.loads(p.stdout or "{}").get("Results", []) or []:
        if glob_any(res["Target"], ctx.cfg["paths"]["exclude"]):   # excluded paths are never scanned
            continue
        for m in res.get("Misconfigurations", []) or []:
            cm = m.get("CauseMetadata") or {}
            out.append(Finding(
                tool="trivy", rule=f"trivy.{m['ID']}", severity=m["Severity"].lower().replace("unknown", "low"),
                confidence="medium", path=res["Target"],
                line=cm.get("StartLine") or 1, end_line=cm.get("EndLine") or 0, kind="config", cwe="CWE-710",
                message=m["Title"], fix=m.get("Resolution", ""), url=m.get("PrimaryURL", ""),
            ))
    return out


SCANNERS = {
    "opengrep": run_opengrep, "ruff": run_ruff, "zizmor": run_zizmor,
    "gitleaks": run_gitleaks, "osv": run_osv, "trivy": run_trivy,
}


# ---------------------------------------------------------------- policy
def comment_text(line: str) -> str | None:
    """The comment part of a source line: from the first comment opener (#, //, /*, <!--) outside a
    '...', "..." or `...` string, so a marker inside string data never suppresses. None if no comment.
    Line-local: a stray quote before the comment hides it (the finding then blocks: fails safe)."""
    quote, i = None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "#" or line.startswith(("//", "/*", "<!--"), i):
            return line[i:]
        i += 1
    return None


def inline_suppression(repo: Path, f: Finding) -> str:
    try:
        lines = (repo / f.path).read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    for idx in (f.line - 1, f.line - 2):          # same line or the line above
        if 0 <= idx < len(lines):
            c = comment_text(lines[idx])
            m = IGNORE_RE.search(c) if c else None
            if m and m.group("rule").strip() in (f.rule, "*") and m.group("reason").strip():
                return "inline: " + m.group("reason").strip()
    return ""


def config_suppression(cfg: dict, f: Finding, today: str) -> str:
    for ig in cfg.get("ignore", []):
        if ig.get("rule") not in (f.rule, "*"):
            continue
        if ig.get("path") and not glob_any(f.path, [ig["path"]]):
            continue
        if not ig.get("reason"):
            continue
        if ig.get("expires") and str(ig["expires"]) < today:
            continue
        return "config: " + ig["reason"]
    return ""


def fingerprint(repo: Path, findings: list[Finding]) -> None:
    """Learner contract: identity = sha256(rule ID + normalized code snippet), never the line number.
    Normalized = the flagged source line with all whitespace runs collapsed and trimmed.
    Secrets: the snippet would contain the secret, so we use rule ID + file path instead.
    Dependencies: rule ID (advisory) + package@version from the message."""
    import hashlib
    cache: dict[str, list[str]] = {}
    for f in findings:
        if f.kind == "secret":
            snippet = f.path
        elif f.kind == "dependency":
            snippet = f.message
        else:
            if f.path not in cache:
                try:
                    cache[f.path] = (repo / f.path).read_text(errors="ignore").splitlines()
                except OSError:
                    cache[f.path] = []
            lines = cache[f.path]
            snippet = " ".join(lines[f.line - 1].split()) if 0 < f.line <= len(lines) else ""
        f.fingerprint = hashlib.sha256(f"{f.rule}\n{snippet}".encode()).hexdigest()


def apply_policy(ctx: Ctx, findings: list[Finding]) -> None:
    from datetime import date
    today = date.today().isoformat()
    pol = ctx.cfg["policy"]
    block_on = set(pol["block_on"])
    for f in findings:
        if ctx.mode == "diff" and f.kind in ("code", "config"):
            changed = ctx.changed_lines.get(f.path, set())
            f.in_diff = any(n in changed for n in range(f.line, max(f.end_line, f.line) + 1))
        elif ctx.mode == "diff" and f.kind == "dependency":
            f.in_diff = f.path in ctx.changed_files
        f.suppressed = inline_suppression(ctx.repo, f) or config_suppression(ctx.cfg, f, today)
        f.blocking = (
            f.severity in block_on and f.in_diff and not f.suppressed
            and (f.confidence != "low" or pol.get("low_confidence_blocks", False))
            and (f.kind != "dependency" or ctx.cfg["deps"].get("block", False))
        )


# ---------------------------------------------------------------- report
def report_md(ctx: Ctx, findings: list[Finding], verdict: str) -> str:
    active = [f for f in findings if not f.suppressed]
    blocking = [f for f in active if f.blocking]
    new = [f for f in active if f.in_diff and not f.blocking]
    old = [f for f in active if not f.in_diff]
    icon = {"pass": "✅", "fail": "❌", "error": "⚠️"}[verdict]
    head = {"pass": "No blocking security issues", "fail": f"{len(blocking)} blocking security issue(s)",
            "error": "A scanner failed — result incomplete"}[verdict]
    L = [f"## {icon} SAST check: {head}", ""] + [f"> {n}" for n in ctx.notes] + ([""] if ctx.notes else [])
    counts = {s: sum(1 for f in active if f.in_diff and f.severity == s) for s in reversed(SEV_ORDER)}
    L += ["| Critical | High | Medium | Low | Pre-existing | Suppressed |", "|---|---|---|---|---|---|",
          f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {len(old)} | "
          f"{len(findings) - len(active)} |", ""]

    def row(f: Finding) -> str:
        fix = f" — **Fix:** {f.fix}" if f.fix else ""
        link = f" ([ref]({f.url}))" if f.url else ""
        return f"- **{f.severity.upper()}** `{f.path}:{f.line}` `{f.rule}` — {f.message}{fix}{link}"

    if blocking:
        L += ["### Must fix before merge", *[row(f) for f in sorted(blocking, key=lambda x: (x.path, x.line))], ""]
    if new:
        new.sort(key=lambda x: (-SEV_ORDER.index(x.severity), x.path, x.line))
        L += [f"<details><summary>Warnings in this change ({len(new)})</summary>", "",
              *[row(f) for f in new[:100]], "" if len(new) <= 100 else f"\n…and {len(new) - 100} more", "</details>", ""]
    if old and ctx.mode == "diff":
        L += [f"<sub>{len(old)} pre-existing finding(s) outside changed lines are not shown. "
              "Run with `--mode full` to see them.</sub>", ""]
    tools = ", ".join(f"{r.name} {'✓' if r.status == 'ran' else '⏭' if r.status == 'skipped' else '✗'}" for r in ctx.runs)
    L += [f"<sub>Scanners: {tools}. Block policy: {', '.join(ctx.cfg['policy']['block_on'])} "
          f"(scope: {ctx.mode}). Suppress with `sast-ignore[rule-id]: reason` on or above the line.</sub>"]
    for r in ctx.runs:
        if r.status != "ran":
            L.append(f"<sub>• {r.name} {r.status}: {r.detail}</sub>")
    return "\n".join(L) + "\n"


def to_sarif(findings: list[Finding]) -> dict:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "sast-check", "rules": [
                {"id": r, "shortDescription": {"text": r},
                 "properties": {"tags": ["security", cwe], "cwe": cwe}}
                for r, cwe in sorted({(f.rule, f.cwe or "CWE-710") for f in findings})]}},
            "results": [{
                "ruleId": f.rule, "level": lvl[f.severity], "message": {"text": f.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                    "region": {"startLine": max(f.line, 1)}}}],
                "partialFingerprints": {"sastCheck/v1": f.fingerprint},
                **({"suppressions": [{"kind": "inSource", "justification": f.suppressed}]} if f.suppressed else {}),
            } for f in findings],
        }],
    }


# ---------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the SAST check and apply the block policy.")
    ap.add_argument("--repo", default=".", help="repository root (default: .)")
    ap.add_argument("--mode", choices=["diff", "full"], help="override policy.scope")
    ap.add_argument("--base", help="base ref for diff mode, e.g. origin/main")
    ap.add_argument("--out", default="sast-results", help="output directory")
    ap.add_argument("--only", help="comma-separated scanners to run (overrides config)")
    a = ap.parse_args(argv)

    repo = Path(a.repo).resolve()
    settings_error = ""
    try:
        cfg = load_config(settings_file(repo, a.base, ".sast-check.toml"))
    except (RuntimeError, tomllib.TOMLDecodeError) as e:   # unreadable settings: report it, scan nothing (fail closed)
        settings_error, cfg = str(e)[:300], load_config(None)
    mode = a.mode or cfg["policy"]["scope"]
    if mode == "diff" and not a.base:
        print("diff mode needs --base (e.g. origin/main); falling back to full scan", file=sys.stderr)
        mode = "full"
    ctx = Ctx(repo=repo, cfg=cfg, mode=mode, base=a.base)
    if settings_error:
        ctx.runs.append(ToolRun("settings", "error", settings_error))
    elif a.base:
        try:
            edited = [n for n in SETTINGS_FILES if settings_file(repo, None, n) != settings_file(repo, a.base, n)]
        except RuntimeError as e:
            settings_error = str(e)[:300]
            ctx.runs.append(ToolRun("settings", "error", settings_error))
            edited = []
        if edited:
            ctx.notes.append("This change edits " + ", ".join(f"`{n}`" for n in edited) + ". The check used the "
                             "base branch's version; the new settings take effect after merge.")
    enabled = a.only.split(",") if a.only else [k for k, v in cfg["tools"].items() if v]
    if settings_error:
        enabled = []                           # cannot trust the settings: report the error (fail closed)
    unknown = [n for n in enabled if n not in SCANNERS]
    if unknown:
        print(f"unknown scanner(s): {', '.join(unknown)}; valid: {', '.join(SCANNERS)}", file=sys.stderr)
        return 2
    if mode == "diff":
        try:
            ctx.changed_lines = changed_lines(repo, a.base)
        except RuntimeError as e:
            ctx.runs.append(ToolRun("git-diff", "error", f"cannot diff against {a.base}: {str(e)[:300]}"))
            enabled = []                       # nothing can be scoped; report the error (fail closed)
        ctx.changed_files = sorted(ctx.changed_lines)
    findings: list[Finding] = []
    for name in enabled:
        try:
            res = SCANNERS[name](ctx)
            findings += res
            ctx.runs.append(ToolRun(name, "ran", count=len(res)))
        except FileNotFoundError as e:
            ctx.runs.append(ToolRun(name, "skipped", str(e)))
        except Exception as e:  # noqa: BLE001 - surface any scanner failure
            ctx.runs.append(ToolRun(name, "error", str(e)[:400]))

    fingerprint(repo, findings)
    apply_policy(ctx, findings)
    errored = any(r.status == "error" for r in ctx.runs) and cfg["policy"].get("fail_on_tool_error", True)
    verdict = "error" if errored else "fail" if any(f.blocking for f in findings) else "pass"

    out = Path(a.out)
    if not out.is_absolute():
        out = repo / out
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(
        {"verdict": verdict, "mode": mode, "runs": [asdict(r) for r in ctx.runs],
         "findings": [asdict(f) for f in findings]}, indent=1))
    (out / "report.md").write_text(report_md(ctx, findings, verdict))
    (out / "results.sarif").write_text(json.dumps(to_sarif(findings)))
    print((out / "report.md").read_text())
    return {"pass": 0, "fail": 1, "error": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
