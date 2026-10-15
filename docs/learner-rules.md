# Learner rules (P3): from review patterns to custom rules

`tools/learner_rules.py` reads `patterns.json` from the quality-gate learner (`learner-patterns/v1`) and, for each
pattern with at least 3 hits and at least 3 distinct examples (so one can be held out), asks a cheap model on OpenRouter (default `qwen/qwen3-coder-30b-a3b-instruct`,
override with `--model` or `LEARNER_MODEL`) for a rule and a synthetic fixture. The key comes from
`OPENROUTER_API_KEY` and is never printed. The pattern's examples are sent to OpenRouter.

```
python tools/learner_rules.py --patterns patterns.json --report run.json            # write accepted rules locally
python tools/learner_rules.py --patterns patterns.json --report run.json --open-pr  # and open one PR
```

## When a draft is accepted

Every check runs with Opengrep and Semgrep CE (CI tests rules with both). The first failure rejects the draft.

| Check | Why |
|---|---|
| matches every `before` example | the rule finds the weakness it was learned from |
| matches the held-out `before` examples (every third example, never shown to the model) | the rule generalises instead of memorising |
| matches no `after` example | the fix makes the finding go away |
| no finding in this repo's own code of that language (fixtures, `dist/` and `tests/fixtures/` excluded) | a cheap proxy for noise on clean code |
| fixture: >= 3 `ruleid:` and >= 3 `ok:` lines, passes `tests/rules_test.py` | the contract in [RULE_SPEC.md](RULE_SPEC.md) |
| no fixture line repeats an example line | examples may be private code; fixtures are new synthetic code |
| `tools/rule_mutation.py` finds no surviving mutant | every pattern element is tested ([rule-quality.md](rule-quality.md)) |
| `scripts/build_rules.py` passes (rule-ID lock, retired IDs, `metadata.cwe`) | if it fails, nothing from the run is kept |

A draft that fails a check other than a held-out miss is retried once (`--attempts`), with the reason. A held-out
miss is never retried, so the model never learns about the held-out examples. A rejected draft is never written
to `rules/custom/`; the reason is printed and written to `--report`.

## What lands

- `rules/custom/<area>/<pattern id>.yaml` (rule id `sast.<area>.<pattern id>`) and its fixture. The id is permanent
  once merged: a pattern whose rule id is already shipped or retired is skipped.
- `metadata.cwe` from the pattern. When the pattern's `cwe` is null (P2 sets one only when a scanner tagged the
  finding), the model proposes it with the rule; it must be `CWE-<n>`, and the PR marks it "drafted: check it".
  A CWE the pattern gives always wins over the model's.
- `metadata.learner_pattern_id` = the pattern id, `confidence: medium`.
- The PR lists each rule's source orgs (from the pattern's `repos`). A rule from outside SathiaAI, or from unknown
  repos, is listed under "Owner approval needed": the learning boundaries in quality-gate's `learner/DATA_DICTIONARY.md`
  require the owner's approval on the PR for cross-org use.
- Severity from `impact_band`: critical and high are `ERROR` (blocking under `block_on`; the default blocks
  critical only), medium is `WARNING`, low is `INFO`.
- `--open-pr` commits only those files and `dist/` on `learner/rules-<date>` and opens one PR. It stops if the
  working tree is dirty or the branch already exists. It never merges and never enables auto-merge.

## Limits

- Stacks: `python`, `javascript`/`node`, `typescript`. This repo has no JavaScript of its own, so JS patterns are
  rejected (nothing to prove the rule is quiet on clean code) until a clean JS sample is added.
- The clean-code check uses this repo only; the fuller noise check is `tools/fp_sweep.py`.

Tests: `python tests/learner_rules_test.py` (offline: canned drafts in `tests/fixtures/learner/drafts.json` stand in
for the model; needs opengrep and semgrep).
