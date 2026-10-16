# Third-party tools

sast-check **downloads and runs** these tools; it does not copy or modify their code or rules.
All custom rules in `rules/` are original work under this repo's MIT license.

**LGPL-2.1 (Opengrep):** this repo ships no Opengrep code or binaries. The action fetches the unmodified upstream release at run time and calls it as a separate program, so nothing here is a derivative work and there is nothing to redistribute. If you ever vendor or bundle the binary, include its license text and offer its source as LGPL-2.1 §6 requires.

| Tool | Version pinned | License | How it is obtained |
|---|---|---|---|
| [Opengrep](https://github.com/opengrep/opengrep) | v1.30.2 | LGPL-2.1 | release binary, Sigstore signature verified |
| [Ruff](https://github.com/astral-sh/ruff) | 0.16.8 | MIT | PyPI |
| [zizmor](https://github.com/zizmorcore/zizmor) | 1.30.1 | MIT | PyPI |
| [gitleaks](https://github.com/gitleaks/gitleaks) | v8.30.1 | MIT | `go install` (Go checksum DB) |
| [osv-scanner](https://github.com/google/osv-scanner) | v2.7.0 | Apache-2.0 | `go install` (Go checksum DB) |
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
