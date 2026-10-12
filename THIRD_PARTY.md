# Third-party tools

sast-check **downloads and runs** these tools; it does not copy or modify their code or rules.
All custom rules in `rules/` are original work under this repo's MIT license.

| Tool | Version pinned | License | How it is obtained |
|---|---|---|---|
| [Opengrep](https://github.com/opengrep/opengrep) | v1.30.2 | LGPL-2.1 | release binary, Sigstore signature verified |
| [Ruff](https://github.com/astral-sh/ruff) | 0.16.8 | MIT | PyPI |
| [zizmor](https://github.com/zizmorcore/zizmor) | 1.30.1 | MIT | PyPI |
| [gitleaks](https://github.com/gitleaks/gitleaks) | v8.30.1 | MIT | `go install` (Go checksum DB) |
| [osv-scanner](https://github.com/google/osv-scanner) | v2.7.0 | Apache-2.0 | `go install` (Go checksum DB) |
| [Semgrep CE](https://github.com/semgrep/semgrep) | 1.180.0 | LGPL-2.1 | dev/test only (rule tests); local fallback engine |
| [Trivy](https://github.com/aquasecurity/trivy) (optional) | user-installed | Apache-2.0 | off by default |

## Deliberately NOT used

| Source | Why |
|---|---|
| semgrep/semgrep-rules | Semgrep Rules License v1.0: internal business use only, no redistribution |
| opengrep/opengrep-rules | Archived (2025-11-28); Commons Clause |
| trailofbits/semgrep-rules | AGPL-3.0 |
| CodeQL CLI | Not licensed for private, non-GHAS repositories |
| Brakeman | Non-commercial license |
| trufflehog | AGPL-3.0 |
| hadolint | GPL-3.0 |

Notes: gitleaks is in maintenance mode (author's successor project: Betterleaks, MIT) — revisit for v2.
The `ingress-nginx` project was retired by Kubernetes; the ingress-nginx rule also flags that.
