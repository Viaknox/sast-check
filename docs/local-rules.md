# Repository rules (`.sast-check/rules/`)

A repo can keep its own Opengrep rules next to its code. They run with the built-in rules on every scan.
Use them for rules that belong to one codebase only, such as rules learned from its own review comments.
Rules derived from private code belong here, never in the public sast-check rule set.

## Layout

```
.sast-check/
  rules/
    payments.yaml        # rule files: *.yaml or *.yml directly in this folder
    tests/               # subfolders are not read (keep test fixtures here)
```

Each file holds `rules:` with a list of rules:

```yaml
rules:
  - id: local.payments.raw-amount        # must start with local.
    message: Pass amounts through Money(), never a raw float.
    severity: ERROR
    languages: [python]
    pattern: charge(amount=float(...))
    metadata:
      sast_severity: high                # low, medium, high or critical (decides blocking)
      cwe: CWE-681
      confidence: medium                 # optional: low, medium, high
```

## Rules for the rules

- **Taken from the base branch.** A PR is scanned with the rules already merged. A PR that adds, edits or deletes a rule changes nothing for its own scan; the change applies after merge.
- **Checked before merge.** When a PR edits the folder, its rules must be valid now, or the check fails. Otherwise one bad rule, once merged, would fail every later PR.
- **Allowed keys only:** `id`, `message`, `severity`, `languages`, `metadata`, `mode` (`search` or `taint`), `options`, `paths`, `fix`, `fix-regex`, the `pattern*` keys, `min-version`, `max-version`. Keys such as `join` or `extract`, which read other files or change how targets are read, are refused.
- **Ids** start with `local.` and use only `a-z 0-9 _ -` and dots. They must be unique across the folder.
- **Limits:** 100 files, 500 rules, 1 MiB in total.
- **Regular files only:** a symlink (the folder, `.sast-check`, or a rule file) is an error.
- Opengrep must accept every rule (`opengrep scan --validate`). The action installs PyYAML to read the files; a local run needs `pip install pyyaml`.
- Any problem with the folder is a settings error: the check fails even with `fail_on_tool_error = false`.

Waive a repository rule like any other, with `[[ignore]]` in `.sast-check.toml` or an inline `sast-ignore[local.…]: reason`.

## When the merged rules break

A rule can stop working after merge, for example when a new Opengrep version rejects it. Every PR then fails.
To recover, open a PR that changes **only** rule files directly in `.sast-check/rules/` (fix or delete the rule). If its rules are valid, that PR is scanned with them, so it can pass and be merged. A PR that also changes anything else gets no exception.

## Test fixtures

Put fixtures for these rules in `.sast-check/rules/tests/` and add that path to `paths.exclude` in `.sast-check.toml`. The fixtures contain the code the rules flag on purpose.
