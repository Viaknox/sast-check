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
(function () { eval(req.query.code); }).call(A);
```

**`using` declaration** (TypeScript)

```ts
// before
using res = getRes();
// after
const res = getRes();
try { /* code that used res */ } finally { res[Symbol.dispose](); }
```

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
class A { #p = 1; static has(o) { try { o.#p; return true; } catch { return false; } } }
```

**`const` type parameter** (TypeScript)

```ts
// before
const f = <const T,>(x: T) => x;
// after: drop `const`; pass `x as const` at call sites that relied on it
const f = <T,>(x: T) => x;
```

**`unique symbol` type**

```ts
// before
declare const s: unique symbol;
// after: let TypeScript infer the unique symbol type
const s = Symbol("s");
```

**Interface member named `new`**

```ts
// before
interface I { new: string; }
// after
interface I { "new": string; }
```

Other constructs can trigger the same finding. The report shows the lines Opengrep could not read; rewrite them
in an older or plainer form.

## Last resort: suppress with a reason

Only if a rewrite is impossible. Put this on the span's first line or the line above it:

```js
// sast-ignore[opengrep.not-parsed]: generated parser output, reviewed by hand in PR 123
class A { static { /* ... */ } }
```

- A reason is required. Without one the finding is not suppressed.
- It suppresses only `opengrep.not-parsed`, never another rule on the same line. `sast-ignore[*]` does **not**
  cover it; the rule must be named. The same holds for an `[[ignore]]` entry in `.sast-check.toml`.
- Suppressed gaps stay listed in the report with their reason, and the summary shows a separate count of
  coverage-gap suppressions. Code under a suppressed gap is still **not scanned**: review it by hand.
- sast-check reads the comment from the source file, so it works even though Opengrep skipped those lines.

## If the check errors instead

A parse error with missing or malformed spans, or an error type sast-check does not know, fails the check
(exit code 2). It is never ignored. Report it as a bug if your code is valid.
