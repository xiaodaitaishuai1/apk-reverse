# JS AST pre-deobfuscation — the pipeline layer before `jsvmp-recovery.md` reads anything

**Load this when** the JavaScript in front of you (pulled from a WebView, an embedded engine, a
mini-program bundle, `assets/www/`) is unreadable through *structure*, not just minification —
string tables, self-executing decoder wrappers, flattened control flow, if-chain dispatch — and
`jsvmp-recovery.md` §3's step 1 ("AST pre-deobfuscation") is the instruction you are executing.
This file owns **how that step is run as a pipeline**; the VM work after it stays in
`jsvmp-recovery.md`, and this file deliberately does not repeat it.

**What this answers:** which family the sample belongs to, in what order the rewrite passes run,
when a rewrite is *safe to apply at all*, and how you prove the batch helped. Contents:
§1 the three layers · §2 detection · §3 the pass library and order · §4 safe-rewrite rules ·
§5 string tables and minimal bootstrap eval · §6 residue and proof · §7 extending the library.

**The fence — this skill ships detection and order, not the rewriter.** The passes need a real JS
parser: node + `@babel/parser` + `@babel/traverse` + `@babel/generator`. That stack is one
`npm install` away, but this repository does not carry it; every *rewrite* below is a documented
route (`unverified` as end-to-end), while the **detector and its fixtures are `observed`**
(`scripts/js_obf_detect.py --selftest`). Re-parse after every batch — output that does not re-parse
is corruption, not progress.

**Provenance.** Absorbed 2026-10-20 from `lwjjike/xbsReverseSkill` (MIT), its `ast-deobfuscation`
skill — the pipeline-config step library with per-family ordering and weighted detection, and the
safe-rewrite-rules, string-array-and-minimal-eval, control-flow-and-opcode-patterns and
pattern-layering notes. No code or pattern corpus was copied; the architecture and the rules are
the absorption. The absorbed pipeline's own measured caveat
(late literal-inlining stalls on large VM-heavy samples, so that family skips it) is carried in §3.

## 1. Three layers, and the rule that keeps them honest

1. **Generic transform layer** — stable, low-risk rewrites that hold across unrelated samples.
2. **Detection / pipeline-selection layer** — score the sample, pick the pass order.
3. **Family adapter layer** — narrow passes for one vendor's reproducible quirk.

The rule (the reason the absorbed library stayed usable): **a family rule does not move into the
generic layer until it has recurred in at least two unrelated samples** with its safety boundary
still clear. The failure this prevents is generic passes accreting site-specific heuristics until
every run needs per-sample exemptions — at which point the pipeline is unmaintainable *and*
unreviewable, and mis-rewrites become undebuggable.

## 2. Detection — score before you choose the order

`scripts/js_obf_detect.py <file.js> [--hint TEXT] [--json]` implements the absorbed scoring model:

- a **hint** token matched against your `--hint` text or the file path scores **10** — a human
  saying "this is the delivery platform's sign SDK" outranks any regex;
- each **content** regex hit scores **3** — `_0x` identifiers and a top-level string array
  (string-array lineage), `while(!![]){switch(...)}` with `"3|1|2".split('|')` order tables
  (flattening), a huge hex/base64 literal plus a `[Object, Math, …]` dependency array (jsvmp
  entry — cross-check against `jsvmp-recovery.md` §2's table, which is the authoritative
  recognition step), long literal-vs-variable if-chains (opcode dispatch).

Any score > 0 is a detection; the top scorer sets the pipeline; nothing scored means the generic
ladder, which is also where you fall back when family residue stays stable after two batches.
The huge-literal threshold is `--min-literal` (default 1500) — a parameter, not a boundary: lower
it for small samples, and say so in your record.

## 3. The pass library and the order that matters

Generic ladder (absorbed order): **normalize → prune fake branches → inline dispatchers → flatten
array-driven control flow → if-chain to switch → prune → normalize**, with identifier renaming
**last**, and a `string_array_pass` **first** when detection says the lineage uses one — every
later pass reads strings through the decoder, so metrics and rewrites on undecoded text are noise.

Per-order rules, each paid for by someone's stall:

- **Decode the string array before any control-flow work** (§5).
- **Never jump to full beautification because the code is ugly.** The stop condition is "the main
  dispatcher is readable and the key cases are individually analysable", not "the file is pretty".
  `jsvmp-recovery.md` §3's ladder decides how much deeper than that you ever go.
- **VM-heavy families skip late literal-inlining** — the absorbed architecture's own measured
  example of a pass order that hangs a large sample; re-ordering per family is the point of the
  detection layer, not a hack.
- **A pass that finds no match must exit clean**, not "best effort" — a visitor that half-applies
  leaves the tree in a state no later pass expects. Structure mismatch ⇒ skip and report.

## 4. Safe-rewrite rules — when a node is *certainly* foldable

Replace **only when the answer to "is this certainly recoverable" is yes**; anything less is a
corruption lottery.

Certainly replaceable: array-literal indexing with a numeric literal and stable contents · calls
whose arguments are all literals **after** the minimal decoder environment exists (§5) · pure
expressions (`['a','b'].join('')`, `String.fromCharCode(...)`, `split/reverse/join` chains) ·
verified alias chains (`var a='x'; var b=a;`) · statically-true/false comparisons.

Never fold: anything depending on `this`/global/closure-external bindings or the host environment ·
getters/setters/Proxy objects/dynamic property access/side-effecting calls · alias chains whose
binding stability is unproven · comma/logical expressions where order matters · anything needing
cross-scope execution reasoning.

Judgement order: (1) does the result depend only on literals and stable local bindings?
(2) does evaluation have side effects? (3) does it depend on execution order, host state, or
environment? — **any unknown at any step ⇒ do not replace**; leave the region for runtime evidence.
And never re-fold an already-folded literal: putting `StringLiteral`s back through the evaluator is
how output destabilizes.

## 5. String tables and minimal bootstrap eval

The string-array family: the file's first statements build a decoder — a top-level IIFE rotating an
array, or 2–5 statements initialising one. Order:

1. Locate the array literal, the decoder function, and the alias chain.
2. **Static first**: array indexing, literal concatenation, numeric-argument calls.
3. Only when static stops: **minimal bootstrap eval** — execute *only* the first few statements
   that construct the decoder, never the file; never in an environment with DOM/timers/network;
   with the narrowest goal ("resolve numeric-argument calls to strings").
4. Delete the consumed bootstrap declarations, **re-parse**, then enter control-flow work.

Stop when the main table is restored and the decoder entry is clear; string tables beyond that are
low-value residue. For a jsvmp sample this is `jsvmp-recovery.md` §3 step 1, which halved the
write-up's sample before any VM reading.

## 6. Residue and proof — a batch helped, or it did not

Measure **before and after each batch** with `js_obf_detect.py`'s residue metrics (mangled-identifier
count, hex-literal density, comma-expression count, switch/case counts, longest line). They are
*textual proxies*, honest for same-file before/after comparison and for nothing finer — do not
quote them as AST counts. Two rules:

- **Compare against a reference where one exists.** If you hold the vendor's decoded output or a
  known-good decode of one function, diff against it; residue dropping while diverging from the
  reference is a loss.
- **A batch that did not move the metrics is a signal to stop**, not to re-run it louder — the same
  two-strike shape as `SKILL.md` §Stop conditions, at pass granularity.

## 7. Extending the pattern library — the three-piece rule

Adding a family adapter means adding **all three, in the same change**: the rule document
(a `patterns/<family>.md` note — shape, safety boundary, measured caveats; the directory starts
empty and fills only when a real family is absorbed), the detector entries (hint tokens + content
regexes in `scripts/js_obf_detect.py`), and the pipeline entry (pass order in its `FAMILIES`
record). An adapter that exists in only one of the three places is invisible,
undetectable, or unmaintainable — and §1's promotion rule still governs what may reach the generic
layer.
