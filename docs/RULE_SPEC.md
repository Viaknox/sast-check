# Custom rule spec (Opengrep / Semgrep-syntax)

All custom rules are original work, licensed MIT. Never copy text, messages or rule
bodies from any other ruleset (semgrep-rules, Trail of Bits, commercial scanners, etc.). Write
messages in your own plain English.

## Layout
One rule per file, test fixture next to it with the SAME basename:

```
rules/custom/<area>/<slug>.yaml
rules/custom/<area>/<slug>.<ext>     # .js, .ts, .py, .html, .tf, .dockerfile; YAML fixtures: <slug>.test.yml or <slug>.test.yaml
```
`<area>` is one of: js, python, gha, docker, k8s, terraform, web.
Rule `id` is `sast.<area>.<slug>` (e.g. `sast.js.code-eval`). Fixture file for Dockerfiles:
name it `<slug>.dockerfile`.

## Stability (learner-agent contract)
- A rule `id` is permanent once merged. Never rename or reuse it; to retire, delete the rule and add its id to `rules/RETIRED.txt`. Retired IDs can never be reused (the build fails).
- `metadata.cwe` is required (`CWE-<n>`); the build fails without it.

## Rule file shape
```yaml
rules:
  - id: sast.js.code-eval
    languages: [javascript, typescript]
    severity: ERROR            # critical/high -> ERROR, medium -> WARNING, low -> INFO
    message: >-
      One or two plain sentences: what is wrong, why it matters, how to fix.
    metadata:
      sast_severity: critical  # critical | high | medium | low  (given to you per rule)
      confidence: high         # high | medium | low  (be honest)
      cwe: "CWE-95"
      category: security
      fix: "Short concrete fix, e.g. 'Use JSON.parse for data, never eval.'"
      references:
        - https://cwe.mitre.org/data/definitions/95.html   # only well-known stable URLs (cwe.mitre.org, owasp.org, MDN, official docs)
    # patterns / mode: taint ...
```
Use only standard features supported by both Semgrep CE and Opengrep: `pattern`, `patterns`,
`pattern-either`, `pattern-not`, `pattern-inside`, `pattern-not-inside`, `pattern-regex`,
`metavariable-regex`, `metavariable-pattern`, `focus-metavariable`, `mode: taint` with
`pattern-sources` / `pattern-sinks` / `pattern-sanitizers`. Do NOT use Pro-only features
(interfile, `taint_assume_safe_*` is fine, `languages: [generic]` is fine for Dockerfile/regex).

## Precision rules (we block PRs on critical — false positives cost trust)
- Prefer taint mode for "user input reaches X" checks. User-input sources for JS/TS:
  Express/Koa/Next style `req.query`, `req.body`, `req.params`, `req.headers`, `req.cookies`,
  `request.query|body|params|headers|cookies`, `ctx.query`, `ctx.request.body`, `ctx.params`,
  plus `new URL(...).searchParams.get(...)` and `location.search|hash` for browser code.
  Python: `flask.request.*` (args, form, json, values, cookies, headers, get_json()), Django
  `request.GET|POST|body|COOKIES|META`, FastAPI is out of scope for v1.
- Do not flag string literals / constants (pattern-not on literal arguments).
- Only flag config-style checks when the risky value is explicit in code.

## Tests (mandatory)
In the fixture, annotate lines with comments:
- `// ruleid: sast.js.code-eval` on the line BEFORE each line that must match (`# ruleid:` for py/yaml/tf/dockerfile, `<!-- ruleid: ... -->` for html)
- `// ok: sast.js.code-eval` before safe look-alike code that must NOT match.
Minimum per rule: 3 true positives and 3 realistic safe look-alikes (false-positive traps).

Verify with:
```
semgrep --test --metrics=off rules/custom/<area>/
semgrep --validate --metrics=off --config rules/custom/<area>/<slug>.yaml
```
Loop until every test passes and validate is clean. Do not weaken a test to make it pass —
fix the rule.
