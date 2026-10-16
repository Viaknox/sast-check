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

Score = killed / (killed + survived). Mutant ids are `<rule id>:<keys to the list>:<hash of the element>` with no
list positions, so they stay stable when other parts of the rule change or branches are added or reordered.
A run where the engine crashes, times out or prints no JSON is an error (exit 2), never a kill or a pass.

**How to kill a survivor.** Deleting a source or sink survives when no `ruleid:` line reaches the sink through
that element alone (often because a broader pattern also matches). Add a `ruleid:` line that only that element
catches. Deleting a sanitizer, `pattern-not` or `pattern-not-inside` survives when no `ok:` line depends on it.
Add an `ok:` line that the rule would flag without it.

**CI.** On every pull request, changed rules are mutated, and a survivor not listed in
`tests/mutation-baseline.json` fails the check. The baseline records the survivors that existed when the tool
was introduced, each with a `why`. An entry counts only with a written `why`: `{}`, a blank reason or a `TODO` from
`--write-baseline` fails the check. A partial `--write-baseline` (`--rules`, `--changed-*`) rewrites only the rules it ran. For the rules that ran, a baseline entry that no longer survives fails the check (`STALE BASELINE`):
remove it, so a later loss of that fixture line cannot pass silently. Shrink it over time; a new entry needs a reason a reviewer accepts (for
example, two equivalent patterns kept for readability).

```
python tools/rule_mutation.py --rules js/ssrf.yaml          # one rule
python tools/rule_mutation.py --json out.json               # all rules
python tools/rule_mutation.py --report docs/mutation-report.json   # the committed summary (full run)
```

## Speed: `tools/rule_perf.py`

The gate scans with no per-file timeout, so a slow rule makes every PR scan slow. CI times each rule a PR
changes against the base branch's version of the same rule, on a file built by repeating the rule's fixture to
about 2,000 lines, with the gate's own engine flags. It fails when the changed rule is both 1.5x and 3 seconds
slower (a second run of each confirms it first). A new rule, or one whose base version's paths or languages skip
the generated file, has nothing to compare with and fails only over 60 seconds. A renamed rule is compared with its
base version under the old name. A scan that fails or reports an engine error fails the check. It catches large
slowdowns, like the 30-45x ones PR #11 found by hand; a slowdown that shows only on a different shape of code
(PR #11's Django rule was 1.5x slower on a big handler file but 1.2x on its repeated fixture) can still pass.

```
python tools/rule_perf.py --base-dir BASE --rules js/ssrf.yaml   # BASE holds the old rule at rules/custom/js/ssrf.yaml
```

## Noise: `tools/fp_sweep.py`

Runs all rules in full mode over a pinned corpus of well-maintained open-source repositories
(`tools/fp-corpus.json`, one exact commit per repository so scores are comparable run to run). Each finding is
labelled `fp` (safe code, the rule is wrong), `tp` (a real weakness), `tp_test` (the rule is right, but the code
is a test, example or docs) or `unclear`. Noise = fp / (fp + tp + tp_test).

- The sweep needs Opengrep (the CI engine) and rebuilds `dist/rules.yaml` first. Every finding is tagged with the commit
  and rule bundle it came from; the report counts only findings from the pinned commit and the current bundle
  (`stale_findings_excluded` says how many were left out), and labels must match those findings one to one.
- A rule with a single scalar pattern has nothing to delete: the mutation tool prints `NOT MUTATION-TESTED` for it.
- A confirmed false positive becomes a hand-written `ok:` fixture line, never code copied from the repository.
- A true positive in someone else's project is never published (no issue, no PR, no fixture copied from it).
  Raw findings stay in the scratch `--work` directory; the committed report has only rule, repository, counts
  and labels.

```
python tools/fp_sweep.py --work /tmp/fp                                   # clone + scan
python tools/fp_sweep.py --work /tmp/fp --labels labels.json --report docs/fp-report.json
```
