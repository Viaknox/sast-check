---
name: sast-check
description: Security gate for code changes. Run before opening or updating a pull request (or when asked for a security check, SAST scan, or "is this PR safe"). Scans the change (blocking only what it introduces) with Opengrep custom rules, Ruff security rules, zizmor, gitleaks and osv-scanner, then fixes blocking findings in a loop until the gate passes.
---

# sast-check

The same check runs in CI on every PR (`action.yml`). Running it locally first means the PR is green on the first push.

## 1. Run

```bash
python3 "<this skill's folder>/scripts/sast.py" --mode diff --base origin/main
```
- Use the PR's real base branch for `--base` (`git merge-base` is computed for you).
- Output: `sast-results/report.md` (human summary) and `sast-results/findings.json` (machine-readable).
- Exit code: `0` pass, `1` blocking findings, `2` a scanner crashed (result incomplete — treat as not passed).
- A missing Opengrep fails the check (it is required); install it first. Other report lines marked `⏭ skipped` mean that scanner is not installed. Tell the user which one and the install line from README → "Run locally / with an AI agent". Do not claim a pass while a scanner is skipped without saying so.
- A `✗` line (for example `zizmor-online error`) means a scanner ran but failed or ran only partly; the check fails. Report the error detail and fix its cause; do not suggest installing anything.

## 2. Fix loop (only blocking findings are mandatory)

For each finding in `findings.json` where `"blocking": true`:
1. Read the code around `path:line`. Confirm it is real. If you are not sure, say so — do not guess.
2. Explain it to the user in one plain sentence: what an attacker could do.
3. Make the smallest fix that removes the risk (the `fix` field is a hint). Do not refactor unrelated code.
4. **Secrets (`secret.*`)**: tell the user to revoke/rotate the credential FIRST. Removing it from the file is not enough — it is in git history.

Re-run the scan after the fixes. Repeat until the verdict is `pass`. Stop after 3 rounds and report what is left.

Warnings (`"blocking": false`, in the change) — list them briefly; fix the cheap ones if the user agrees.

## 3. Rules you must follow

- **Never** add a `sast-ignore[...]` comment, an `[[ignore]]` entry, or loosen `.sast-check.toml` on your own. If you believe a finding is a false positive, show the evidence and ask the user. If they approve, the suppression must carry their reason: `// sast-ignore[sast.js.code-eval]: <reason>`.
- **Never** disable a scanner or switch to `--mode diff` with a fake base to make the gate pass.
- Do not merge, approve, or resolve the PR. A human approves every PR.
- Cheap work (reading many findings, drafting explanations) can go to a lower-cost sub-agent tier; the fix and the final verdict are checked by you by re-running the scan.

## 4. Report back (keep it short)

| Verdict | Blocking fixed | Warnings left | Skipped scanners |
|---|---|---|---|

Then one line: the next action for the user (e.g. "rotate the AWS key", or "push — gate will pass").
