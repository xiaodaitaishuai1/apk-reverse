# JS VMP recovery — when the protected logic is JavaScript (jsvmp)

Load this when the value you need — a sign, a token, a device fingerprint, a risk parameter — is
produced inside **JavaScript the app controls** (a WebView page, a JS engine embedded behind JNI, a
mini-program container, a hot-updated bundle), and the JS is not merely minified: one entry call
receives a **giant literal** — thousands of hex characters or a base64 blob — plus an array of
globals, and everything behind it is one closed interpreter. That shape is **jsvmp**: the original
logic compiled to a private opcode stream and executed by a virtual machine shipped with the script.
This file owns reading it. The neighbouring layers own the rest: `references/emulation-and-rpc.md`
owns **calling** the routine instead of reading it, `references/js-ast-deobfuscation.md` owns the
**pre-deobfuscation pipeline** (detection, pass order, safe-rewrite rules — the step §3.1 names),
`references/vmp-differential-analysis.md` the dex-layer VMP, `references/native-vm-recovery.md` the
native interpreter loop, and `references/framework-runtimes.md` deciding that the logic lives in JS
at all.

**Claim strength.** Absorbed from three public write-ups of one reverse-engineering series
(2024-03..2024-09; titles and authors anonymized in this record). One builds a minimal JS VM to
expose the shape; one reverses a **stack-machine** jsvmp (a short-video platform's web sign SDK);
one reverses a **register-machine** jsvmp (a messaging giant's refreshed risk-control VMP, which
migrated from stack to register and grew from ~60 to 91 instructions). The write-ups are `observed`
by their authors; this repository has executed **none** of these steps on a real target — every
procedure below is `inferred`. The one shipped tool, `scripts/jsvmp_loader_decode.py`, is
host-measured against its own round trip (`--selftest`). The JS-engine details (QuickJS,
JavaScriptCore, V8-in-WebView) were never exercised here either.

## 1. Why this shape exists, and what it changes about your plan

jsvmp compiles the original JS to a private instruction stream and interprets it, exactly like a
native VM does for machine code — but the interpreter itself is JS you can **read, run, instrument
and re-run in a REPL**. That is the structural advantage over `native-vm-recovery.md`: no trace
hardware, no arm64 semantics, and a wrong hypothesis is a one-line probe away from a correction.

Two facts about the shape drive the plan:

- **The literal is the program.** Every character (stack machine) or decoded integer (register
  machine) is an opcode or operand byte. Its length is a lower bound on program size, and its
  format names the loader you must undo first (§2).
- **The dependency array is an import table and an environment probe at once.** The write-ups' entry
  calls pass `[Object, Math, setTimeout, ..., void 0 !== x ? x : void 0, false, entryFn, arg]` — the
  VM reads its globals through this array, and the `typeof`/`void 0` guards double as an environment
  fingerprint check. Hostile values here are how a harness is detected.

Why the vendor did not use wasm: wasm cannot touch JS objects directly without a bridge, and the
crossing cost plus the bridge code outweigh the protection. Which tells you the **whole point of the
JS-layer VM is environment access** — expect fingerprint collection (canvas, screen, fonts) woven
into the guest program, not only crypto.

## 2. Recognition — decide "jsvmp" before committing

| Signal | What it looks like | Confidence |
|---|---|---|
| Entry shape | `global['_$webrt_<epoch>'](hugeString, [deps...], this)` — one call, one huge constant, one globals array | near-certain with the other two |
| Interpreter shape | a `while`/`for` loop containing a large `switch` or if-chain; the **deepest indentation** in the file (loops nested in flow control) | strong |
| Opcode fetch | `parseInt(s[i] + s[i+1], 16); i += 2` (two hex chars = one byte), or `opcode[++PC]` cascades inside each `case` | strong |
| State | an array plus an index used as stack (`stack[++sp] = v` push, `v = stack[sp--]` pop), or an array indexed by fetched operands as a register file | decides stack vs register (§5, §6) |
| Loader fingerprint | base64 charset ops, 7-bit masking with high-bit continuation (varint), or the ZigZag formula `(A >> 1) ^ -(1 & A)` | the program is encoded, not encrypted — decode it, don't cryptanalyse it |

Two cautions. A big `switch` alone proves nothing (a state machine looks the same); the loop must
**read a cursor from a data buffer, dispatch on the value, and write the cursor back**. And the
presence of a readable interpreter does not mean you must read it — §3 first.

**A parameter-name index for the families this repository has on record** (`unverified` —
absorbed 2026-10-20 from a public JS-reverse case corpus; wire-level parameter names are kept as
the recognition signal, vendors anonymised per this repository's desensitization convention; none
of these was met on a real target here). Recognition aid only — confirm by §2's structural signals
before routing on it:

| Wire parameter / marker | Family shape | Typical carrier |
|---|---|---|
| `a_bogus`, `X-Bogus` | layered sign params, heavy env probing | short-video platforms, web + app |
| `mtgsig` | mini-program VMP with native assist | delivery/local-services apps |
| `sensor_data` | device-fingerprint collection + packing | risk-control SDKs (app-embedded) |
| `blackbox` | fingerprint blob, env-sensitivity | risk-control SDKs (app-embedded) |
| `h5st` | staged params with time windows | large e-commerce clients |
| `x-s`, `x-t` pair | jsvmp-generated sign pair | lifestyle-community platforms |
| `__zse_ck` | JS + wasm nested obfuscation | Q&A communities |
| `acw_sc__v2` | JS-computed cookie on first visit | e-commerce/ACW-fronted sites |
| `F14B3CEF*`-prefixed cookies, `$_ts` | 4/5/6-generation dynamic JS ("RS") | ticketing/airline/gov sites in WebView |
| `armorToken`, `Anti-in` | request-header token pair | fashion e-commerce |
| `aws-waf-token` | JS challenge token | AWS-WAF-fronted endpoints |
| `Reese84`, `___utmvc` | obfuscator.io-lineage challenge | airline/CDN-fronted sites |
| `hexin-v` | sign with heavy obfuscation | stock-data platforms |
| `ssxmod_itna` | multi-cookie interdependent chain | travel/booking sites |

A hit in this table says "expect a known shape, budget accordingly" — it does **not** say the
algorithm is known, and it never overrides a structural check. Two or three of these families show
up inside APKs as embedded WebView/H5 risk pages and mini-program containers rather than as the
app's own code — which is exactly why they surface here and not in `detection-and-anti-analysis.md`.

**Provenance note.** The A/B/C ladder at the end of §3 and this table are the only parts of this
file absorbed from outside the three write-ups the rest cites: both come from
`715494637/reverse-skill` (`jsr-reverse` skill; the repository ships no license, so methodology
only was absorbed, no text), retrieved 2026-10-20.

## 3. The cheaper question first: restore, fill the environment, call it

The stack-machine write-up's outcome, in its own order, and the step most skip:

1. **AST pre-deobfuscation.** String-array restoration, folding self-executing wrappers, constant
   propagation. This halved the sample (~9,600 lines → roughly half) and made every later step
   debuggable in an IDE instead of a browser's obfuscated view (the same function was 3,000+
   unreadable lines in devtools). Debugging un-restored code in the browser is the slow path; do
   not attempt VM analysis inside it. **Run as a pipeline, not ad hoc:**
   `references/js-ast-deobfuscation.md` owns the family detection, pass order and safe-rewrite
   rules, and `scripts/js_obf_detect.py` scores the sample.
2. **Fill the environment** ("补环境"): give the script the `window`/`document`/`navigator`/canvas
   surface it probes. Canvas fingerprints are **hardware-linked** — vendors have collected real
   device fingerprints to reject forged ones; a random canvas value may still be accepted (the
   write-up's target did not server-validate it *at that time*), which is `unverified` as a
   general rule. Treat every environment patch as a variable that can fail server-side later.
3. **Export the target function and call it.** In the write-up this already produced the parameter
   the task needed — **before any VM analysis at all**.

This is `references/emulation-and-rpc.md`'s call-don't-read route, and it is the correct first
deliverable: a harness that runs the guest in your controlled environment. Read the VM only when
you must understand or alter the algorithm itself, or when the environment the VM demands is more
expensive to fake than the VM is to read.

### How deep to go — the A/B/C ladder (absorbed; `inferred`)

"Call it first" is level **A**, and most tasks never leave it. The ladder below makes the upgrade
a *decision with evidence*, not a mood — its shapes come from a public JS-reverse recovery-strategy
note (see provenance above), and they match what the three write-ups actually did:

| Level | What you recover | You are here when… | You leave when… |
|---|---|---|---|
| **A — call the guest, extract only the opcodes that touch the target field** | the harness + a handful of critical-opcode semantics | the write-back boundary is known and a few opcodes explain the field | — (the deliverable is the harness) |
| **B — recover the dispatcher plus the critical state carriers** | the dispatcher loop, register/stack/context carriers, opcode families with state flow | a critical opcode cannot be interpreted without dispatcher semantics; the field explanation depends on register/stack flow; key branches cannot be judged without the carriers | never jump here because the code is *ugly* — ugliness is not an evidence type |
| **C — minimal decompilation / minimal re-interpreter** | a smallest verifiable re-execution of the needed path | multiple paths must be re-played, or batch/protocol rebuild requires an executable fragment, and A+B demonstrably cannot support it | — |

**Hard rules.** Start at A; never jump to C for aesthetics. A→B requires a *proven* dispatcher or
state-carrier dependency, not a suspicion. B→C requires a named downstream need (replay, batch,
protocol rebuild) — "the write-up rebuilt the whole ISA" is not that need until your task has one.
And the **black-box reuse boundary** decides whether reading is needed at all: reuse the module
whole when its input/output boundaries are known and the difficulty is the container or bridge
rather than the operator; recover deeper when the module rides heavy implicit shared state, replays
are unstable without the state carrier, or the module is *itself* another jsvmp. Write the decision
down in four lines — reuse mode / known inputs / known outputs / still-dependent state carriers —
so "we stopped at A" reads as a conclusion rather than a shortcut.

## 4. Locating the interpreter and clearing the porch

- **Find the entry by the literal, not by names.** Search for the huge constant being passed; follow
  the call stack one frame to the VM entry (`_$webrt_`-style name). Entry is ~900 lines even after
  de-obfuscation in the stack-machine sample.
- **Copy it to a new file and use an IDE outline.** The entry decomposes into a handful of closures;
  the outline view names them and the reference view tells you which are dead. The write-up's entry
  was seven closures, one of them the interpreter.
- **Simplify the guard closures before touching the interpreter.** Two measured reductions from the
  write-up, both anti-hook scaffolding rather than VM logic:
  - a `Reflect.construct` availability probe + a bind-based construct fallback + a
    `setPrototypeOf`/`__proto__` fallback — three functions whose only role is preventing
    reflection hooks; after checking references, replace with `const construct = Reflect.construct;`
  - an iterable-to-array spread helper (`Array.isArray` copy / `Symbol.iterator` / Arguments check,
    throwing `TypeError("Invalid attempt to spread non-iterable instance")`) — replace with
    `Array.from`.
- **Do not delete "fake" branches on aesthetics.** The write-up marked a suspicious dual-`if` flow
  as probably-dead, instrumented the condition variables, and found the second branch **did** fire
  (values almost always 0, occasionally 1). Probe before cutting; a deleted live branch fails
  silently pages later.

## 5. Reading a stack-machine jsvmp

The operands live on an explicit stack; instructions pop and push. Recognition: `stack[++sp] = v`
and `v = stack[sp--]` pairs, binary results written back in place — `stack[sp] = stack[sp] OP reg`
after one pop. Rename first, everything becomes readable:

| Original idiom | Rename to |
|---|---|
| `_0xcc6308 = []` | `stack` — the operand stack |
| `_0x2e1055 = 0` | `stackPointer` |
| the fetch index, initialised from an argument | `PC` (start index), with `endIndex` computed from the program length |
| `_0x3f0f70` — `parseInt(s[i]+s[i+1],16)` | `operationCode` (0x00..0xFF by construction) |
| first popped operand in binary cases | `operandReg`; longer cases: `regA`, `regB` |
| the pushed `this`/global at call boundaries | `context` — the scope object the VM executes inside |

The dispatch value is *computed*, not read directly — in the sample:
`dispatch = 3 & ((13 * operationCode) % 241)`, giving an initial class 0..3 that then varies during
execution. Derive such ranges from the arithmetic, never from secondary prose: the write-up caught
a whole lineage of copy-paste articles asserting "the loop variable is 0..255" — that is the *byte*
range, not the dispatch sequence. (This is the label discipline of `SKILL.md` §Coverage applied to
someone else's blog.)

After renaming, rewrite the if-chain dispatch into a real `switch` via AST — the case bodies are the
instruction semantics, and the set of cases is the ISA.

## 6. Reading a register-machine jsvmp

The newer shape (91 instructions in the sample): no stack. Each `case` fetches its own operands
inline — `case 3: h[opcode[++PC]] = opcode[++PC];` is `MOV reg, imm` — and `h` is the
register/context file. Verify by instrumenting: log `h`'s indices at one binary op; fixed indices
for operand/operand/result (`h[17]`, `h[22]`, `h[26]` in the sample) prove register addressing.

**Undo the loader before anything else.** The program arrives encoded; the write-up's chain, each
stage recognisable by its fingerprint (§2), and shipped as `scripts/jsvmp_loader_decode.py`
(corroboration, `observed`: the write-up's own sample literal decodes end to end under it — no
truncation error, values in a plausible opcode range):

1. **base64** string → unsigned byte array (strip `=`, map chars to indices, recombine bits);
2. **varint** — per byte, `o |= (b & 0x7F) << shift; shift += 7` while the high bit continues;
3. **ZigZag** decode each accumulated integer: `(n >> 1) ^ -(n & 1)` maps unsigned back to signed.

A flattened loader loop reads as 4 `if`s each ending in `continue` — treat every later block as the
`else` of the earlier one and it reduces to the three-stage pipeline above. In an APK, the same
chain may sit behind JNI or load from `assets/`; the recognition problem is identical.

**Expect twins.** The sample carried **two executors** selected by a condition that constant-folds
to one side — but the twins call each other, so both must be accounted for. Text-diffing the two
interpreters showed them byte-identical except `"use strict"`. Strict-mode code runs in non-strict
too, so deleting the non-strict twin is safe *if you verify by running* — the write-up replaced the
response through a proxy rewriter and confirmed the output unchanged. Two executors also means two
places a patch must land; a patch that "had no effect" may have edited the dead twin.

**The exception path is the call stack.** The `catch` saves the exception, and if a callback stack
is non-empty returns to the previous frame, else rethrows (optionally through a handler argument
that was `void 0` in the sample — probably a vendor debugger/log hook). The VM's **PC save across
nested guest calls rides on JS closures** — each invocation carries its own PC, and returning from
the inner function restores the outer one. There is no explicit restore instruction, so any
executor you build must not leak scope state across guest calls (§8).

## 7. Instruction extraction — from switch cases to an ISA table

Extract mechanically with AST, not by hand:

1. Pull each `case` body into its own function (drop the `break`s); the write-up used a
   `SwitchStatement` visitor that renames each to `op_<code>` and lifts it to a declaration.
2. **Type every operand** as it is used: an operand read as `h[...]` is a **register** (`R0`,
   `R1`, …); an operand consumed directly as a value is an **immediate** (`imm`) — and an immediate
   is a **constant by construction**, because it comes from the program text. That single property
   powers constant folding later (§9).
3. Record `argnums` per opcode — the operand count — and let a loader (`loadOP`) fetch exactly that
   many before dispatch. Instructions whose operand count is data-dependent (varargs calls, the
   sample's ops 18/19) stay unparameterised until understood.
4. Name what you understand (`MOV`, `ADD`, `JMP`, `STOSB`…), reuse one name for ops that differ
   only in operand width, and name the rest `unknown_<code>` rather than guessing. The sample
   reached ~91 instructions with 8 `unknown` — resolved later by running.
5. Watch for **semantic disguises**: the sample's op 10 is `h[r] = h[r] - 0` — not arithmetic but
   `ToNumber` coercion. Name intent, not syntax.

An operand may have **two possible widths** under one opcode — the sample's conditional jump reads
one operand when the condition is true and two when false (`PC += h[op1] ? op2 : op3`). Encode that
in the table; a disassembler that assumes one width desynchronises from that instruction onward.

## 8. Four JS-language traps with no native counterpart

Rewriting an interpreter's cases into clean functions breaks in ways native VM work never meets.
All four cost the write-up a day or more; all four are now checkable in minutes.

1. **Expression evaluation is strictly left-to-right.** In
   `h[opcode[++PC]][h[opcode[++PC]]] = h[opcode[++PC]]`, the object index is `args[0]`, the member
   index `args[1]`, the RHS `args[2]` — *not* the Python order (RHS first, then outer-then-inner on
   the left). Verifiable with side-effect logging: JS prints 0,1,2,3. Reconstructing operand order
   "by execution priority" inverts it.
2. **`PC += opcode[++PC]` is not `arg = opcode[++PC]; PC += arg`.** Compound assignment reads the
   LHS value *before* evaluating the RHS (`PC=1`: first form → 3, second → 4). The V8 bytecode shows
   it — the slot is loaded into the accumulator before `AddSmi`. For any PC-accumulating
   instruction, either keep the original expression verbatim in the extracted function or
   compensate by hand; a wrapped `jmp` that off-by-ones PC executes the wrong opcode and dies
   silently pages later.
3. **`this` pollution.** Calling the extracted op functions with the caller's `this` leaks
   `undefined` (strict) or `globalThis` (sloppy) into the VM's environment. Call with
   `opFn.apply(undefined, args)` or spread — and remember the strict/sloppy difference is exactly
   why the vendor shipped twin interpreters (§6).
4. **A `RET` may legitimately return `undefined`.** An executor's `if (result !== undefined) return
   result;` therefore never exits. Branch on the opcode (`if (bytecode === RET) return result;`),
   not on the value.

The acceptance test for any rebuilt executor is the write-up's: run the **real captured program**
end to end (the sample took ~880,000 guest instructions) and compare outputs — a clean exit after
the fixes is the only proof the extraction preserved semantics.

## 9. Disassembly, constant folding, control-flow recovery

With a loader and an ISA table you have a static disassembler. Pipeline the artefacts as files —
`program.b64` (input) → `program.bin` (decoded integer stream) → `program.asm` (disassembled) →
`program.ir` (lifted) — so each stage is diffable and re-runnable. In the sample: ~48,000 decoded
integers → ~14,000 instructions, with constants visible as bulk stores into fixed program space
(the same layout discipline as a real binary's `.rodata`).

- **Fold constant-building idioms with pattern matching, not by reading.** The sample's dominant
  idiom — `SETEMP [r]` then a run of `STOSB [r, imm]` then a member store — *is* a string
  declaration: `locals[r] = String.fromCharCode(imm, imm, …)` (there: `"__lastWatirConfirm"`).
  `STOSB` alone was 5,300 of 14,000 instructions; folding collapsed a third of the program. Match
  instruction sequences like regexes (the write-up used an NFA over the instruction stream) and
  emit **extended pseudo-instructions** from a reserved opcode range (999+) for each folded idiom.
- **Control flow falls out of compare-and-branch pairs.** `EQ` + `JNZ` with two targets → `if/else`;
  `LT` + `JNZ` back-edge → `while`; `GETMEMBERIMM` + `GTIMM` + `JNZ` → `for`. This is
  `native-vm-recovery.md` §10's reading discipline with an easier instruction set — and the honest
  limit is the same: what you can recover is bounded by how much of the ISA you have named.
- **Know what your disassembly does not give you.** The write-up's own list: register roles not
  analysed (still `locals[n]`, not variable names); constants foldable but not yet folded; no
  re-assembler, so asm edits cannot round-trip into runnable bytecode. Say which of these your
  output suffers from before treating it as source.

## 10. Where this plugs into this skill

| Need | Tool / file |
|---|---|
| decode a jsvmp program literal (base64 → varint → ZigZag) | `scripts/jsvmp_loader_decode.py` (`--selftest` proves the round trip) |
| classify an obfuscated JS sample and get its pass order | `scripts/js_obf_detect.py`, then `references/js-ast-deobfuscation.md` |
| decide the logic lives in JS at all | `references/framework-runtimes.md` (runtime table; zero-hit Java hooks) |
| call the routine instead of reading it (the §3 route) | `references/emulation-and-rpc.md`; Frida RPC over a WebView/engine boundary |
| reach a JS engine behind JNI from the device | `references/dynamic-frida.md`; the JS bridge inputs are in `references/system-ipc-audit.md` |
| the same VM problem, one layer down (native interpreter) | `references/native-vm-recovery.md` |
| the same VM problem, one layer up (dex private opcodes) | `references/vmp-differential-analysis.md` |

Deliverable shape: a jsvmp target almost never ends in a repack — the artifact is a **harness that
calls the guest program** (G1's third form) or an **analysis report with a stated boundary**. Write
the G1 sentence accordingly before sinking days into the ISA.

## Checklist

- [ ] entry recognised by the literal + dependency-array shape, not by a big `switch` alone
- [ ] §3 executed in order — AST restore, environment fill, call the function — before any VM reading
- [ ] the A/B/C stop depth stated with its evidence (which field-explanation or replay need forced the level) and the reuse boundary written down
- [ ] environment patches labelled: each one can fail server-side later (canvas especially)
- [ ] guard closures simplified with reference-checked replacements; "dead" branches probed, not cut
- [ ] stack vs register decided by the state idiom (§2 table), then the naming map applied
- [ ] loader undone before semantics; range claims derived from arithmetic, not from secondary prose
- [ ] twins diffed; patches proven against the live twin by running, not by reading the selector
- [ ] operand typing R/imm recorded per opcode; unknown opcodes named `unknown_<code>`, not guessed
- [ ] the four §8 traps checked in any rebuilt executor; real program run end to end as acceptance
- [ ] labels: procedures `inferred` (absorbed write-ups), shipped decoder `observed` (round trip only)
