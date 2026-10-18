# `opengrep.not-parsed`: code the scanner could not read

## What it means

Opengrep reads code with a parser. When it hits syntax it does not know, it skips that part, reports a
`PartialParsing` error, and keeps scanning the rest of the file. **Nothing inside the skipped part is checked.**
A dangerous call there (for example `eval(req.query.code)`) is invisible to every rule.

sast-check turns each skipped span into a finding:

| | |
|---|---|
| Rule id | `opengrep.not-parsed` |
| Severity | critical (blocks like any critical finding, under your `policy.block_on`) |
| One finding per | file: the range from the first unreadable line to the last (a whole-file parse error covers the whole file) |

## Why it blocks

A gate that silently skips code it cannot read is a gate with a hole in it. "No findings" must mean "looked and
found nothing", not "could not look". Fix the code so the scanner can read it.

## Diff mode and full mode

- **Diff mode (PRs):** a gap blocks only if a line you changed falls inside its range (a whole-file parse error:
  if the file changed). Gaps on lines you did not touch do not block; the report lists them under **Not scanned**.
- **Full mode:** every gap blocks.

## Why the whole range, not just the marked tokens

Opengrep marks only the tokens it could not read (for example the `{` that opens a `static` block and the `}`
that closes the class), not the code between them, and that code is skipped too. So sast-check takes the range
from the **first** unreadable line to the **last** one in the file as one unscanned region and reports it as one
finding. Editing only the body of an existing unreadable block therefore blocks, and a suppression goes on the
range's first line. The range can include some code Opengrep did read; that is the safe side. Rewriting the
construct into a form Opengrep can read removes the finding.

## How to fix: rewrite into a form Opengrep can read

Keep behaviour identical. Each pair below was checked with Opengrep 1.30.2: the "before" is reported, the
"after" is not.

**Class static block** (JavaScript / TypeScript)

```js
// before
class A { static { eval(req.query.code); } }
// after: same code, same `this`
class A {}
(function () { "use strict"; eval(req.query.code); }).call(A);
```

Class bodies, static blocks included, are always strict mode code, so the replacement function must start with
`"use strict"`; otherwise a direct `eval` inside it would run as sloppy code and behave differently. It is still not identical in every case: inside the function, `arguments` exists (a static block rejects it),
and `super` and the class's private names (`#x`) are not available. If the block uses those, or evaluates code
that might, use a reasoned suppression instead.

**`using` declaration** (TypeScript)

```ts
// before
using res = getRes();
// after: read the disposer once, when the resource is acquired; null and undefined are allowed
const res = getRes();
const dispose = res == null ? undefined : res[Symbol.dispose];
if (res != null && typeof dispose !== "function") throw new TypeError("not disposable");
try { /* code that used res */ } finally { dispose?.call(res); }
```

This matches `using` for one resource. It is not identical when the body and the disposer both throw (`using`
reports both in a `SuppressedError`) or when several `using` declarations share a scope (nest one `try` per
resource, in reverse order). If that matters, use a reasoned suppression instead.

**`accessor` field**

```js
// before
class A { accessor x = 1; }
// after
class A { #x = 1; get x() { return this.#x; } set x(v) { this.#x = v; } }
```

**`#priv in obj` check**

```js
// before
class A { #p = 1; static has(o) { return #p in o; } }
// after
class A {
  #p = 1;
  static has(o) {
    if (o === null || (typeof o !== "object" && typeof o !== "function")) throw new TypeError("not an object");
    try { o.#p; return true; } catch { return false; }
  }
}
```

Per the ECMAScript private-identifier `in` semantics, `#p in o` throws a `TypeError` when `o` is not an object, so the
rewrite throws it too instead of returning `false`.

**`const` type parameter** (TypeScript)

```ts
// before
const f = <const T,>(x: T) => x;
// after: drop `const`; pass `x as const` at call sites that relied on it
const f = <T,>(x: T) => x;
```

This changes the inferred type. `x as const` only works on simple literals (not, for example, on a conditional
expression), so for an exported function or a caller passing a complex expression, keep the signature and use a
reasoned suppression instead.

**`unique symbol` type**

```ts
// before (runtime code)
const s: unique symbol = Symbol("s");
// after: let TypeScript infer the unique symbol type
const s = Symbol("s");
```

For an ambient or `.d.ts` declaration (`declare const s: unique symbol;`) there is no equivalent rewrite:
`symbol` is a weaker type and changes what the declaration promises. Use a reasoned suppression, or move the
declaration to a path a human lists in `paths.exclude` (a declaration holds no executable code). AI agents must not make that change.

**Interface member named `new`**

```ts
// before
interface I { new: string; }
// after
interface I { "new": string; }
```

Other constructs can trigger the same finding. The report shows the lines Opengrep could not read; rewrite them
in an older or plainer form.

## Waivers

Only if a rewrite is impossible. There are two ways, and both approve **exactly** the lines in the finding:

**1. In the PR itself: a comment with a reason.** Put it on the range's first line or the line above it:

```js
// sast-ignore[opengrep.not-parsed]: generated parser output, reviewed by hand in PR 123
class A { static { /* ... */ } }
```

**2. Owner-approved, merged first: an `[[ignore]]` entry pinned to the code.** The finding and the report give
the entry ready to paste, including the range's fingerprint (`range_sha`):

```toml
[[ignore]]
rule = "opengrep.not-parsed"
path = "src/legacy/parser.js"        # one exact file, no globs
range_sha = "47fb4daf1a06158d5ca8c40e9bc5ab75f99ac59a5de9b50973252e5b3d0122ac"
reason = "generated parser, reviewed by hand in PR 123"
expires = "2027-01-01"
```

- A reason is required. Without one nothing is suppressed.
- Only `opengrep.not-parsed` is suppressed, never another rule on the same lines. `sast-ignore[*]` and
  `rule = "*"` do **not** cover it; the rule must be named.
- An `[[ignore]]` entry for this rule must have an exact `path` and a valid `range_sha`, or the settings are
  rejected (exit code 2). An older entry with only a `path` is rejected too: it could cover any unreadable code
  added to that file later. Run the check without it, then copy the entry from the finding.
- `range_sha` is a SHA-256 of the range's lines: line endings (CRLF), a leading byte-order mark and trailing
  spaces are ignored, so do line numbers. Moving the code down the file keeps the waiver. **Any other change in
  the range** — new unreadable code that makes the range grow, an edit inside it, even a spacing change inside a
  string — makes it stop matching, and the PR blocks until someone looks at the new lines. The finding then says
  why the old entry no longer applies.
- To change waived code in one step: merge the new entry first, keeping the old one next to it; merge the code
  change; then delete the old entry. Or waive the new code in the PR with a comment (way 1).
- In a PR, a comment that was already there does **not** waive unreadable lines that the PR adds or edits: the
  comment must be added or edited in the same PR, so the reviewer sees it. A comment reached through a symlink
  never counts.
- Suppressed gaps stay listed in the report with their reason, with a separate count of coverage-gap
  suppressions. Code under a suppressed gap is still **not scanned**: review it by hand.
- sast-check reads the comment and the fingerprint from the source file, so both work even though Opengrep
  skipped those lines. To get a `range_sha` without CI, run `python3 scripts/sast.py --mode full --only opengrep`
  locally: it is in `sast-results/findings.json` and the report.

## Why the range is never made smaller

Opengrep 1.30.2 reports only the tokens it could not read. It never says which code between them it did read,
so sast-check cannot prove any of that code was scanned, and keeps the whole range. A smaller range would need
that proof from Opengrep's own output; until an Opengrep release gives it, the range stays as it is.

## Who decides what (trust boundary)

- **Settings come from the base branch.** A PR cannot add, widen or extend its own `[[ignore]]` entry; the owner
  merges it first, and a PR that changes `.sast-check.toml` is checked with the old one.
- **Waivers are reviewed by a person.** An inline comment shows in the PR diff; a config entry is a separate,
  owner-merged change. Both carry a reason, and both are listed in every report.
- **The "Prompt for AI agents" block is guidance, not enforcement.** It tells an agent to rewrite and never to
  suppress. What actually stops a bad suppression is the gate: settings from the base branch, the fresh-comment
  rule and the `range_sha` pin.

## If the check errors instead

A parse error with missing or malformed spans, or an error type sast-check does not know, fails the check
(exit code 2). It is never ignored. Report it as a bug if your code is valid.

**Opengrep upgrades.** sast-check pins Opengrep (currently 1.30.2) and lists every error type it knows in
`scripts/sast.py` (`WHOLE_FILE_ERRORS`, `KNOWN_TOOL_ERRORS`). A new release can add error types; until one is
inspected, it stays exit code 2. To upgrade: bump the pin in `action.yml` and `.github/workflows/test.yml`, run
the tests in CI, and for each new error type, look at what it means, add it to the right list only if it is
truly a parse gap or a tool error, and add a test fixture that produces it. Never add a type to make the check
pass without that inspection. A new Opengrep can also read more or less of a file, so an unread range can start
or end on different lines: every `[[ignore]]` entry whose `range_sha` stops matching after the upgrade must be
looked at and re-approved (the finding shows the new value), never copied over blindly.
