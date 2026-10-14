# sast-check

A security gate for every pull request. One step in CI, one skill for your AI coding agent.

It runs five open-source scanners, merges the results, and applies **one** policy:
**By default, critical issues your change introduces block the PR — everything else is a warning** (`block_on` can add other severities). Code and config findings block when they are on a changed line or absent from the base version; secrets in the PR's commits always block; dependency CVEs warn unless `[deps] block = true`.

| Scanner | Checks | License |
|---|---|---|
| **Opengrep** + 56 custom rules (this repo) | JS/TS, Python, HTML, GitHub Actions, Docker, K8s, Terraform | engine LGPL-2.1 (run as a tool) · rules MIT |
| **Ruff** `S` rules | Python | MIT |
| **zizmor** | GitHub Actions workflows, Dependabot config | MIT |
| **gitleaks** | Secrets in the PR's commits | MIT |
| **osv-scanner** | Known-vulnerable dependencies | Apache-2.0 |

Full list: [docs/coverage.md](docs/coverage.md).

## Add it to a repo (2 minutes)

1. Copy [`templates/sast.yml`](templates/sast.yml) to `.github/workflows/sast.yml`.
2. Replace `OWNER/sast-check@REPLACE_WITH_COMMIT_SHA` with this repo and a **full commit SHA** — never `@main` or a tag: either can change under you, and this action runs with your PR's token.
3. In branch protection, make **`sast-check / scan`** a required check.
4. Protect the workflow itself: a PR runs its own copy of `.github/workflows/sast.yml`, so it could replace the scan step and still report `sast-check / scan` as passed. Add a `CODEOWNERS` entry for `.github/workflows/`, the settings files (`.sast-check.toml`, `.gitleaks*`, zizmor, OSV and Trivy configs) and `.github/CODEOWNERS` itself (otherwise a PR can first remove the protection), and turn on **Require review from Code Owners**. A check that runs from a trusted GitHub App is planned as the stronger fix.

Each PR gets one sticky comment and a job summary. Fork PRs get the summary only (no write token).

## Tune it — `.sast-check.toml` in your repo root

Changes to this file take effect **after they are merged**. PRs are always checked with the base branch's settings. A PR that changes this file must still leave it valid, or the check fails (an invalid file would otherwise break every later PR): unknown sections or keys (`[tools] opengrepp`), wrong value types and an unknown `scope` are errors. The other settings files a PR edits are checked by the scanner that reads them (zizmor, gitleaks, osv-scanner, Trivy), when it is installed. Settings files must be UTF-8. A settings error always fails the check, even with `fail_on_tool_error = false`.

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
`# zizmor: ignore[...]`, `trivy:ignore`) are ignored, so every suppression has a written reason and shows up in the report.
The marker counts only in a real comment: inside a string (`"# sast-ignore[...]"`) it does nothing.
Secrets cannot be suppressed either way: remove the secret from the PR's commits and rotate it.
A misspelled `block_on` severity is a settings error (the check fails) rather than a gate that never blocks.
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
- **Settings come from the PR's base branch.** On a PR, `.sast-check.toml`, `.gitleaks.toml`, `.gitleaksignore`, zizmor's config, `osv-scanner.toml`, `trivy.yaml` and `.trivyignore` are read from the base branch, never from the PR. A PR that edits them is scanned with the old settings, and the report says the change takes effect after merge. This stops a PR from switching off its own check.

## Known limits (v1)

- **Runners:** Linux x64 only (the action stops with a clear error elsewhere).
- **Languages:** JS/TS, Python, HTML (inline scripts and script sources), GitHub Actions, Dockerfiles, Kubernetes YAML, Terraform. Anything else is not scanned by custom rules.
- **Secrets** (gitleaks) are always critical and block when they appear in the PR's commits, staged files, or untracked files that are not git-ignored (a git-ignored file such as `.env` cannot be committed, so local runs leave it alone).
- **Dependencies** (osv-scanner) warn only by default; set `[deps] block = true` to let critical CVEs (CVSS ≥ 9) in changed lockfiles (including `*requirements*.txt`) or SBOMs (`bom.json`, `*.cdx.json`, `*.spdx.json`, ...) or OSV custom inventories (`osv-scanner-custom.json`) block.
- **Nunjucks `|safe`** is checked only in `.njk` / `.nunjucks` files: an `.html` template cannot be told apart from a Django or Jinja2 one, where `|safe` belongs to a different engine.
- **LDAP clients** are recognised when created in the same file (`ldapjs` `createClient`, `ldapts` `new Client`) or when the variable name contains `ldap`; a client from another module named only `client` or `conn` is not checked (those names matched too many non-LDAP APIs).
- **Puppeteer pages passed in as a parameter** are checked only in files that require or import `puppeteer` / `puppeteer-core`; in such a file any parameter used with `goto`, `setContent`, `evaluate` or `addScriptTag` is treated as a page.
- **Path basenames** (`os.path.basename`, `Path(...).name`) still count as safe when stored in a variable and later passed to a directory call (`os.listdir`, `shutil.rmtree`, ...); a basename of `..` reaches the parent folder. Written inline inside the directory call, they are flagged.
- **Django templates**: a literal `Template("...")` counts as escaping unless it contains `|safe` or `autoescape off` or is rendered with `autoescape=False` inline; a `Context` built earlier with `autoescape=False`, or a custom unsafe filter loaded with `{% load %}`, is not seen.
- **Fastify plugins**: a sink inside `fastify.<method>(...)` is exempt from the error-leak rule by the receiver's name alone, so plugin parameters (`async function (fastify) {...}`) stay quiet. An Express app that is itself named `fastify` is not checked.
- **Redirect checks** trust a variable that passed a validation test, even if it is reassigned inside the validated branch before the redirect.
- **Download-then-verify order**: in a `run` step or Dockerfile `RUN`, any extraction or execution between the download and its checksum counts as using the download, even when it touches a different file.
- **Vite config as a named function**: `export default function namedConfig(...)` is not treated as a Vite config; anonymous functions and arrows are.
- **Reassigned options and values**: a JWT options variable, a validated path, or a validated redirect target that is reassigned before use is judged by its first assignment. Choosing the last reaching assignment needs data-flow analysis.
- **Redirect bases in template literals**: `` `${BASE_URL}/items/${id}` `` trusts an upper-case base even when it is bound from request data. The `+` form checks where the base came from.
- **`var location` shadowing** counts only as the first statement of a function; `let`/`const` count anywhere.
- **Kubernetes images in block scalars** (`image: >-` with the value on the next line) are not matched.
- **Python `.name` sanitizing** needs `Path` to come from a `pathlib` import (direct or aliased).
- **Binding order**: an LDAP client or js-yaml binding must appear above the code that uses it. A helper function declared before `const client = ldap.createClient(...)` is not checked. The either-order form made those rules about 45x slower on large files, so they would time out and skip the file.
- **EJS reassignment** is seen only when it starts a `<% ... %>` tag; a reassignment inside a block (`<% if (c) { x = req.query.q } %>`) is not.
- **Prototype pollution** through `Array.prototype.reduce` merge helpers is not caught: Semgrep and Opengrep disagree on that pattern, so it was left out rather than ship an engine-specific rule.
- **NoSQL injection** ignores callbacks passed to `.find()` / `.filter()`-style calls (e.g. `arr.find(x => x === req.body.id)`). Opengrep taints closures, so without this exclusion every array lookup on request data would be flagged. A real Mongo filter is an object, which is still checked.
- **JWT decode** counts a `verify()` of the **same token** anywhere in the same function, or earlier in the same block (class methods included), as verification. Verifying one token and decoding another is still flagged. `sast.js.jwt-verify-error-swallowed` catches a `verify()` whose error is swallowed (`catch` without `throw`/`return`) or that uses a callback, followed by `decode()`; it covers `jwt.verify` / `jwt.decode` (default or namespace import), not the named-import form.
- **Dependency settings:** on PRs, only the base branch's root `osv-scanner.toml` is used; per-directory `osv-scanner.toml` files are ignored.
- **Inline markers** are found line by line: a quote earlier on the line (e.g. `msg: don't # sast-ignore[...]` in YAML) hides the marker, so the finding still blocks. Put the marker on its own line above instead. A line inside a multi-line string that starts with `# sast-ignore[...]` is read as a comment; every suppression is listed with its reason in the report, so reviewers see it.
- **Moved files:** a renamed, copied or symlinked file counts as fully changed, so moving a file can surface its old findings as new.
- **What counts as new (diff scope):** a finding on a changed line, or (Opengrep and Ruff) a finding that the base branch's version of the file does not have. The base version of every touched file is scanned with the same rules and a finding is old only if the base has the same finding on the line this line came from (the two versions are aligned line by line), so deleting a sanitizer several lines above an unchanged `eval()` still blocks. A line whose text occurs more than once in either version (two identical `eval(v)` sinks) is matched only when both versions have it equally often and every copy lines up; otherwise all its findings count as new, so touching a file with repeated flagged lines can surface them. For zizmor and Trivy, a deletion counts when the finding's lines span the cut (e.g. the `aws_ami` block that lost `owners`).
- **gitleaks `[extend] path`:** on PR scans a base `.gitleaks.toml` may use `[extend] useDefault = true` but not `[extend] path` (gitleaks would read that file from the PR's checkout); the check reports a settings error. Copy the extended rules into `.gitleaks.toml`.
- **Not scanned, named in the report:** a changed submodule pointer (its code is not checked out) and a changed Git LFS pointer file (the content is on the LFS server). Review those by hand.
- **Full scope** scans `.` plus every in-repo symlink under the link's name, so code behind an alias of an excluded path is scanned.
- **zizmor exceptions** go in `[[ignore]]` in `.sast-check.toml` (zizmor ignore rules and comments are not honored).

## Develop

```bash
python3 scripts/build_rules.py      # rules/custom/** -> dist/rules.yaml (commit the result)
python3 tests/rules_test.py         # every rule vs its fixture (ruleid:/ok: annotations)
bash tests/e2e.sh                   # gate decisions on a throwaway repo
```
New rule = `rules/custom/<area>/<slug>.yaml` + a fixture with ≥3 true positives and ≥3 safe look-alikes. Spec: [docs/RULE_SPEC.md](docs/RULE_SPEC.md).

Supports Linux x64 runners in v1. License: MIT. Third-party tools: [THIRD_PARTY.md](THIRD_PARTY.md).
