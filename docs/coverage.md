# Coverage

What the gate checks in v1, and which open-source scanners it uses.

Severity is ours. Baseline: a commercial SAST checklist with 99 checks in these languages — **97 fully covered, 1 partly** (npm "staged publishing" is approximated by zizmor `use-trusted-publishing`), **1 deferred to v2** (Azure Pipelines template injection).
`block` = fails the PR under the default policy: critical, confidence not low, and new in this change (on a changed line, or absent from the base version). Exceptions: gitleaks secrets in the PR's commits always block; osv-scanner dependency findings warn unless `[deps] block = true`.

## Custom rules (Opengrep, MIT, this repo)

| Area | Rule | Severity | Confidence |
|---|---|---|---|
| Dockerfile | `sast.docker.remote-fetch-no-checksum` | medium | medium |
| GitHub Actions | `sast.gha.ai-prompt-injection` | high | medium |
| GitHub Actions | `sast.gha.compromised-action` | critical | high |
| GitHub Actions | `sast.gha.remote-fetch-no-checksum` | medium | medium |
| JavaScript / TypeScript | `sast.js.angular-bypass-trust` | medium | medium |
| JavaScript / TypeScript | `sast.js.code-eval` | critical | high |
| JavaScript / TypeScript | `sast.js.command-injection` | high | high |
| JavaScript / TypeScript | `sast.js.dom-xss-sink` | high | medium |
| JavaScript / TypeScript | `sast.js.ejs-unescaped` | high | medium |
| JavaScript / TypeScript | `sast.js.electron-node-integration` | high | high |
| JavaScript / TypeScript | `sast.js.express-error-leak` | high | medium |
| JavaScript / TypeScript | `sast.js.express-no-helmet` | medium | low |
| JavaScript / TypeScript | `sast.js.express-render-ssti` | high | medium |
| JavaScript / TypeScript | `sast.js.grpc-insecure` | medium | medium |
| JavaScript / TypeScript | `sast.js.handlebars-noescape` | high | high |
| JavaScript / TypeScript | `sast.js.handlebars-unescaped` | high | medium |
| JavaScript / TypeScript | `sast.js.jquery-xss` | high | medium |
| JavaScript / TypeScript | `sast.js.jwt-decode-unverified` | high | medium |
| JavaScript / TypeScript | `sast.js.jwt-verify-error-swallowed` | high | medium |
| JavaScript / TypeScript | `sast.js.ldap-injection` | critical | high |
| JavaScript / TypeScript | `sast.js.libxml-noent` | medium | high |
| JavaScript / TypeScript | `sast.js.location-xss` | high | medium |
| JavaScript / TypeScript | `sast.js.nosql-injection` | high | medium |
| JavaScript / TypeScript | `sast.js.nunjucks-autoescape-off` | high | high |
| JavaScript / TypeScript | `sast.js.open-redirect` | high | medium |
| JavaScript / TypeScript | `sast.js.path-traversal` | high | high |
| JavaScript / TypeScript | `sast.js.prototype-pollution` | high | medium |
| JavaScript / TypeScript | `sast.js.puppeteer-ssrf` | critical | medium |
| JavaScript / TypeScript | `sast.js.react-dangerous-html` | high | medium |
| JavaScript / TypeScript | `sast.js.sequelize-no-tls` | high | medium |
| JavaScript / TypeScript | `sast.js.sql-injection` | high | high |
| JavaScript / TypeScript | `sast.js.ssrf` | medium | medium |
| JavaScript / TypeScript | `sast.js.template-safe-filter` | high | low |
| JavaScript / TypeScript | `sast.js.timing-unsafe-compare` | medium | medium |
| JavaScript / TypeScript | `sast.js.tls-reject-unauthorized-off` | low | high |
| JavaScript / TypeScript | `sast.js.unsafe-yaml-load` | critical | high |
| JavaScript / TypeScript | `sast.js.vite-define-process-env` | medium | high |
| JavaScript / TypeScript | `sast.js.vite-loadenv-all-vars` | critical | high |
| JavaScript / TypeScript | `sast.js.vue-dynamic-href` | medium | low |
| JavaScript / TypeScript | `sast.js.vue-v-html` | high | medium |
| JavaScript / TypeScript | `sast.js.websocket-cleartext` | low | high |
| Kubernetes / Helm | `sast.k8s.ingress-nginx-vulnerable` | critical | medium |
| Python | `sast.python.django-httpresponse-xss` | high | high |
| Python | `sast.python.httpx-verify-false` | low | high |
| Python | `sast.python.jwt-unverified` | high | high |
| Python | `sast.python.jwt-unverified-claims` | high | medium |
| Python | `sast.python.langchain-hub-unpinned` | medium | medium |
| Python | `sast.python.path-traversal` | medium | medium |
| Python | `sast.python.requests-cleartext` | low | medium |
| Python | `sast.python.ssrf` | medium | medium |
| Python | `sast.python.torch-load-unsafe` | high | high |
| Terraform | `sast.terraform.aws-ami-no-owner` | critical | high |
| HTML / any file | `sast.web.inline-script-dom-xss` | high | medium |
| HTML / any file | `sast.web.malicious-cdn-domain` | critical | high |

## Python — Ruff `S` rules (MIT)

All `S` rules run. Severity overrides (others default to low):

| Severity | Ruff codes |
|---|---|
| critical | S301 pickle, S302 marshal, S307 eval, S506 unsafe yaml.load |
| high | S102 exec, S201 Flask debug, S413 pycrypto, S501 requests verify=False, S507 SSH host key, S602 shell=True, S608 SQL string, S701 Jinja2 autoescape off |
| medium | S202 tarfile, S306 mktemp, S314/S317/S318/S320 XML parsers, S321 FTP, S323/S502-S504 TLS, S324 weak hash, S605 shell, S610/S611 Django raw SQL |

## GitHub Actions — zizmor (MIT)

All default audits run; severity = zizmor's own, except `known-vulnerable-actions` → critical. Key ones: `template-injection`, `unpinned-uses`, `dangerous-triggers`, `excessive-permissions`, `artipacked`, `use-trusted-publishing`, `known-vulnerable-actions` (online, uses the job token). Also audits `.github/dependabot.yml` (e.g. `dependabot-execution`). On PRs the base branch's zizmor config is used (`.github/zizmor.yml`, `.github/zizmor.yaml`, `zizmor.yml`, `zizmor.yaml`, in zizmor's own order); a workflow zizmor cannot parse fails the check. Workflows are the `.yml`/`.yaml` files directly in `.github/workflows`; GitHub never runs one in a subdirectory, so those are not scanned (an `action.yml` is scanned wherever it is).

## Secrets — gitleaks (MIT)

Every secret found in the PR's commits is **critical** (blocks). Rotate first, then remove.

## Dependencies — osv-scanner (Apache-2.0)

Runs when a lockfile changes. Severity from CVSS (≥9 critical, ≥7 high, ≥4 medium). Reported, **not blocking** by default (`[deps] block = true` to change).

## Optional — Trivy (Apache-2.0)

`[tools] trivy = true` adds deep Docker/Terraform/K8s misconfiguration checks (install trivy yourself).
On PRs it uses the base branch's `trivy.yaml` and `.trivyignore`; inline `trivy:ignore` / `tfsec:ignore` rules are not honored (use `sast-ignore` or `[[ignore]]`). Trivy reads such a rule from any space-separated word starting with `trivy:` or `tfsec:`, even inside a string, so Trivy scans a copy where exactly those words are defused (`trivy_...`); a string value that is one of them is scanned in that changed form. Findings carry Trivy's full-line range, so a change inside a resource counts. On PRs Trivy runs from a snapshot of the base tree, so files the base `trivy.yaml` points to (custom checks, data) are the base's, not the PR's. Terraform variable files (`*.tfvars`, `*.tfvars.json`) are scan inputs and come from the PR; a vars file the PR deletes is scanned as empty (defaults apply). When a PR changes or deletes one, a finding counts as new unless the base tree (with its own vars) has the same rule on the matching line, even though no `.tf` line changed. Helm values files named in `trivy.yaml` are still read from the base.

## Not in v1

Java, C#/VB, PHP, Ruby, Go, Rust, Kotlin, Swift, Dart, Scala, Elixir, Clojure, C, Apex, Azure Pipelines — planned for v2.
