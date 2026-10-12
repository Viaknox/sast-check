# sast-check

A security gate for every pull request. One step in CI, one skill for your AI coding agent.

It runs five open-source scanners, merges the results, and applies **one** policy:
**critical issues on lines you changed block the PR — everything else is a warning.**

| Scanner | Checks | License |
|---|---|---|
| **Opengrep** + 54 custom rules (this repo) | JS/TS, Python, HTML, GitHub Actions, Docker, K8s, Terraform | engine LGPL-2.1 (run as a tool) · rules MIT |
| **Ruff** `S` rules | Python | MIT |
| **zizmor** | GitHub Actions workflows | MIT |
| **gitleaks** | Secrets in the PR's commits | MIT |
| **osv-scanner** | Known-vulnerable dependencies | Apache-2.0 |

Full list: [docs/coverage.md](docs/coverage.md).

## Add it to a repo (2 minutes)

1. Copy [`templates/sast.yml`](templates/sast.yml) to `.github/workflows/sast.yml`.
2. Replace `OWNER/sast-check@REPLACE_WITH_COMMIT_SHA` with this repo and a **full commit SHA** — never `@main` or a tag: either can change under you, and this action runs with your PR's token.
3. In branch protection, make **`sast-check / scan`** a required check.

Each PR gets one sticky comment and a job summary. Fork PRs get the summary only (no write token).

## Tune it — `.sast-check.toml` in your repo root

Changes to this file take effect **after they are merged**. PRs are always checked with the base branch's settings.

```toml
[policy]
block_on = ["critical", "high"]   # default: ["critical"]
scope = "diff"                    # "full" = old findings can block too

[[ignore]]                        # every ignore needs a reason; add an expiry
rule = "sast.js.express-no-helmet"
path = "examples/**"
reason = "demo apps, never deployed"
expires = "2027-01-01"
```
Inline, on or above the line: `// sast-ignore[sast.js.code-eval]: <reason>` (no reason = not suppressed).
This is the **only** inline suppression. The scanners' own comments (`# noqa`, `// nosemgrep`, `gitleaks:allow`,
`# zizmor: ignore[...]`) are ignored, so every suppression has a written reason and shows up in the report.
All keys and defaults: [config/default.toml](config/default.toml).

## Run locally / with an AI agent

Install the scanners (any OS): `pip install ruff==0.16.8 zizmor==1.30.1`, then
[Opengrep](https://github.com/opengrep/opengrep#installation), [gitleaks](https://github.com/gitleaks/gitleaks#installing),
[osv-scanner](https://google.github.io/osv-scanner/installation/). Any missing scanner is reported as *skipped*, never silently passed.

```bash
python3 scripts/sast.py --mode diff --base origin/main     # exit 0 pass · 1 blocking · 2 scanner error
```

As a Claude Code skill: put this folder in `~/.claude/skills/sast-check/` — the agent runs the scan, fixes blocking
findings, and re-runs until it passes ([SKILL.md](SKILL.md)). It never adds ignores on its own and never merges.

## Contract with the learner agent

- **SARIF** on every run: `sast-results/results.sarif` locally; artifact `sast-check-sarif` in CI (90 days).
- **Rule IDs are permanent.** `dist/rule-ids.lock` lists every shipped ID; the build fails if one is renamed or removed. Retire one by listing it in `rules/RETIRED.txt` — a retired ID can **never** be reused (build fails).
- **Fingerprints:** every SARIF result has `partialFingerprints["sastCheck/v1"]` = sha256(rule ID + flagged line with whitespace collapsed). No line number, so a moved finding keeps its identity. Secrets use rule ID + file path (never the secret line); dependencies use rule ID + package@version.
- **Every rule has a CWE** (`properties.tags` + `properties.cwe` in SARIF). Custom rules must set `metadata.cwe` or the build fails.
- **Custom rules live in `rules/custom/<area>/`** — the learner opens PRs there (rule + fixture), a human merges.

## Design choices

- **Diff-only blocking** — legacy issues don't stop new work; run `--mode full` for a backlog.
- **Fail closed** — if an installed scanner crashes, the check fails (`fail_on_tool_error`).
- **Supply chain** — actions pinned by SHA; Opengrep binary verified with Sigstore/cosign; Go tools installed through the Go checksum database; Python tools pinned.
- **Low-confidence findings never block** (they're shown as warnings).
- **Settings come from the PR's base branch.** On a PR, `.sast-check.toml`, `.gitleaks.toml`, `.gitleaksignore` and zizmor's config are read from the base branch, never from the PR. A PR that edits them is scanned with the old settings, and the report says the change takes effect after merge. This stops a PR from switching off its own check.

## Known limits (v1)

- **Runners:** Linux x64 only (the action stops with a clear error elsewhere).
- **Languages:** JS/TS, Python, HTML (inline scripts and script sources), GitHub Actions, Dockerfiles, Kubernetes YAML, Terraform. Anything else is not scanned by custom rules.
- **Secrets** (gitleaks) are always critical and block when they appear in the PR's commits, staged or untracked files.
- **Dependencies** (osv-scanner) warn only by default; set `[deps] block = true` to let critical CVEs (CVSS ≥ 9) in changed lockfiles block.
- **Prototype pollution** through `Array.prototype.reduce` merge helpers is not caught: Semgrep and Opengrep disagree on that pattern, so it was left out rather than ship an engine-specific rule.
- **NoSQL injection** ignores callbacks passed to `.find()` / `.filter()`-style calls (e.g. `arr.find(x => x === req.body.id)`). Opengrep taints closures, so without this exclusion every array lookup on request data would be flagged. A real Mongo filter is an object, which is still checked.
- **JWT decode** counts a `verify()` of the **same token** anywhere in the same function, or earlier in the same block (class methods included), as verification. Verifying one token and decoding another is still flagged. `sast.js.jwt-verify-error-swallowed` catches a `verify()` whose error is swallowed (`catch` without `throw`/`return`) or that uses a callback, followed by `decode()`; it covers `jwt.verify` / `jwt.decode` (default or namespace import), not the named-import form.
- **Dependency settings:** on PRs, only the base branch's root `osv-scanner.toml` is used; per-directory `osv-scanner.toml` files are ignored.
- **zizmor exceptions** go in `[[ignore]]` in `.sast-check.toml` (zizmor ignore rules and comments are not honored).

## Develop

```bash
python3 scripts/build_rules.py      # rules/custom/** -> dist/rules.yaml (commit the result)
python3 tests/rules_test.py         # every rule vs its fixture (ruleid:/ok: annotations)
bash tests/e2e.sh                   # gate decisions on a throwaway repo
```
New rule = `rules/custom/<area>/<slug>.yaml` + a fixture with ≥3 true positives and ≥3 safe look-alikes. Spec: [docs/RULE_SPEC.md](docs/RULE_SPEC.md).

Supports Linux x64 runners in v1. License: MIT. Third-party tools: [THIRD_PARTY.md](THIRD_PARTY.md).
