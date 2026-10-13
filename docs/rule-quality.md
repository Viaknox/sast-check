# Rule quality: test strength and noise

Two tools measure every custom rule. Both run only rules and public code; neither generates vulnerable code.

## Test strength: `tools/rule_mutation.py`

Each rule is a set of pattern elements (sources, sinks, sanitizers, `pattern-either` branches, `pattern-not`,
`pattern-inside`, `metavariable-regex`, …). The tool deletes one element at a time and reruns the rule's
fixture with `tests/rules_test.py`:

| Outcome | Meaning | What to do |
|---|---|---|
| killed | the fixture now fails: some `ruleid:` or `ok:` line depends on that element | nothing |
| survived | the fixture still passes: no test exercises that element | add a fixture line that needs it, or justify it in the baseline |
| invalid | the engine rejects the mutated rule | nothing (not scored) |

Score = killed / (killed + survived). Mutant ids are `<rule id>:<path>:<hash of the element>`, so they stay
stable when other parts of the rule change.

**How to kill a survivor.** Deleting a source or sink survives when no `ruleid:` line reaches the sink through
that element alone (often because a broader pattern also matches). Add a `ruleid:` line that only that element
catches. Deleting a sanitizer, `pattern-not` or `pattern-not-inside` survives when no `ok:` line depends on it.
Add an `ok:` line that the rule would flag without it.

**CI.** On every pull request, changed rules are mutated, and a survivor not listed in
`tests/mutation-baseline.json` fails the check. The baseline records the survivors that existed when the tool
was introduced, each with a `why`. Shrink it over time; a new entry needs a reason a reviewer accepts (for
example, two equivalent patterns kept for readability).

```
python tools/rule_mutation.py --rules js/ssrf.yaml          # one rule
python tools/rule_mutation.py --json out.json               # all rules
```

## Noise: `tools/fp_sweep.py`

Runs all rules in full mode over a pinned corpus of well-maintained open-source repositories
(`tools/fp-corpus.json`, one exact commit per repository so scores are comparable run to run). Each finding is
labelled `fp` (safe code, the rule is wrong), `tp` (a real weakness), `tp_test` (the rule is right, but the code
is a test, example or docs) or `unclear`. Noise = fp / (fp + tp + tp_test).

- A confirmed false positive becomes a hand-written `ok:` fixture line, never code copied from the repository.
- A true positive in someone else's project is never published (no issue, no PR, no fixture copied from it).
  Raw findings stay in the scratch `--work` directory; the committed report has only rule, repository, counts
  and labels.

```
python tools/fp_sweep.py --work /tmp/fp                                   # clone + scan
python tools/fp_sweep.py --work /tmp/fp --labels labels.json --report docs/fp-report.json
```
