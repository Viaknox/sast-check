# Security policy

sast-check is a security gate, so a flaw in it can let unsafe code through. Thank you for reporting one.

## Report a vulnerability privately

Use GitHub's private reporting: open this repository's **Security** tab and choose **Report a vulnerability**.
Please do **not** open a public issue, pull request or discussion for a security problem.

Useful to include:

- what an attacker can do (for example: get a blocking finding past the gate, read a secret, run code in CI);
- the smallest repo, file or workflow that shows it, and the sast-check commit SHA you used;
- the scanner output or report, with any real secrets removed.

We aim to acknowledge a report within 7 days and to agree a fix and disclosure date with you. Please give us a
reasonable time to ship a fix before you publish details.

## What is in scope

- `scripts/sast.py`, `action.yml`, the rules in `rules/` and `dist/`, and `scripts/workflow_guard.py`.
- Ways to make the gate pass when it should block, to make it use settings from a pull request instead of the
  base branch, or to leak data from the CI run.

Problems in the scanners sast-check runs (Opengrep, Ruff, zizmor, gitleaks, osv-scanner, Trivy) belong with
their own projects; see [THIRD_PARTY.md](THIRD_PARTY.md). If you are unsure, report it here and we will route it.

## Supported versions

This is an early release with no versioned releases yet. Fixes land on `main`; pin the action to a full commit
SHA and move the pin forward to pick up a fix.
