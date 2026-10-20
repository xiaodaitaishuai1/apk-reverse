# Extension verification — sampling, crash forensics, symbolization, de-virtualization

Covers the second hardware-layer pass: `references/hardware-sampling-and-crash.md`,
`scripts/trace_addr2sym.py`, `scripts/vm_handler_slice.py`, and the source-reading
corrections to the flattening recipes. Strength labels as this directory's README defines
them.

Reference environment: Linux container host, Python 3.13, cross `gcc 16.2.0` targeting
`aarch64-linux-gnu` (the toolchain that makes the symbolizer's "real ELF" half testable).
Network access was used once, read-only, to fetch the two public obfuscator implementations
the calibration cites (below). No Android device, no coresight/SPE/BRBE hardware.

**Headline: the address→symbol loop is measured against a real cross-compiled library; the
de-virtualization slicer is measured on synthetic traces AND end to end on a real
IR-virtualized + flattened binary (built by the completed toolchain, host-traced, sliced,
and fully opcode-named); the SPE/BRBE producer side remains documented-and-gated. The
flattening-recipe corrections are read from public source, and that source is named.**

---

## 1. `trace_addr2sym.py` against a real library — observed

```
$ gcc -shared -fPIC -O2 -o libtlib.so tlib.c      # cross gcc -> aarch64 ELF64
$ readelf --syms -W libtlib.so
... 00000000000005e0  132 FUNC GLOBAL DEFAULT 9 encrypt_block
... 0000000000000664    4 FUNC GLOBAL DEFAULT 9 decrypt_block
$ python skills/apk-reverse/scripts/trace_addr2sym.py --elf libtlib.so --offs 0x610
  0x610              -> encrypt_block+0x30  [vaddr 0x610 file 0x610 .text+0x130]
```

The resolution agrees with `readelf` exactly (0x610 − 0x5e0 = 0x30, inside the sized symbol);
a point outside any function falls to the nearest-below symbol with its section shown
(`0x700 -> _fini+0x98 [.eh_frame+0x40]`), which is GNU-addr2line-shaped behaviour and is
pinned by unit test together with the PT_LOAD `vaddr≠offset` conversion on a hand-built
minimal ELF. That minimal-ELF fixture also covers the stripped-library fallback
(section+offset, no symbols).

## 2. `vm_handler_slice.py` on the calibrated shape — observed

A synthetic interpreter trace in the shape the public IR virtualizer emits
(dispatcher D, handler blocks, one const-materialization segment, an unclosed tail):

```
$ python skills/apk-reverse/scripts/vm_handler_slice.py --log vm.log --opcode-map map.json
dispatcher: libvm.so+0x1000  (41.7% of 24 blocks, 10 hits)
segments: 10 total, 7 unique, avg len 2.00   [last segment UNCLOSED: exit path or truncated window]
opcode trajectory (first 20): OP_LOAD OP_LOAD OP_STORE OP_BR OP_LOAD OP_LOAD OP_BR OP_CALL OP_LOAD OP_RET
```

What the output pins, and why each part is the part a de-virtualization needs: the
**dispatcher share** (with the diagnostic that separates a real dispatch loop from a spin
loop), the **segment table** (one row per handler chain, first block = handler entry =
the `--opcode-map` key), the **trajectory** (the guest program, one signature per executed
guest opcode), the **OP_CALL materialization segment** appearing as its own signature (the
virtualizer's const dispatch — the second observation point the calibration names), and the
**UNCLOSED tail** flagged rather than silently dropped. The auto-detection rule is
top-of-histogram **plus predecessor diversity** (≥3 distinct predecessors), not a naive
count margin: in a stack-shaped VM the hottest handler executes on every guest instruction,
exactly as often as the dispatcher. That refusal-to-accept is the load-bearing part of the
auto rule. Section 6 measures all of this against a real hardened binary.

## 3. The flattening-recipe corrections — observed source, inferred runtime

Fetched read-only from the public implementations the user supplied
(github.com/dpkg123/ollvm-aosp-toolchain: branch `ollvm-r614150-clang23-rebase+omp`
[Hikari family] and `ollvm-r614150-clang23+omp` [Pluto family]; commits 63fec41f and
9b7cf75e for the IR virtualizer; 2026-10):

- **Hikari `Flattening.cpp`**: `switchVar` is an entry-block **alloca** written through a
  `switchVarAddr` double pointer (indirect store per transition); case values are
  `scramble32`-permuted; EH-bearing functions are skipped.
- **Pluto `Flattening.cpp`**: two allocas (`switchVar`, `switchXor`) with a **rolling XOR**
  (`enc^=delta; key^=delta; cond=enc^key` per dispatch); case values fully random; the true
  case exists only in the `switchCond` register for one instruction; EH/`callbr`/`indirectbr`
  functions skipped.
- **Hikari `AntiDebugging.cpp`**: on Darwin/AArch64 it injects **inline-assembly raw `svc`**
  with a randomized register-setup order and a **randomized svc immediate**; elsewhere it
  links precompiled anti-debug IR. Consequence recorded in the reference: byte signatures
  cannot survive the randomization; semantic site-location (`svc_scan.py`) and hardware
  observation do not care.
- **The IR virtualizer**: `vm_exec(code, size, vm_args, num)` stubs, boxed-argument array,
  11 one-byte opcodes + 19 arithmetic sub-ops, const/call materialization dispatch,
  switch-to-if lowering.

These corrected `hardware-watchpoints.md`'s state-variable recipe (the old text assumed a
global and a readable value — wrong for both families as shipped) and added the
family-difference table to `ete-diff-tracing.md` §5. The fetches live under
`tools/_work/refs/` (git-ignored); **runtime behaviour of these passes is `inferred` from
source** — except the IR virtualizer's runtime, which this pass built, executed and
measured (§5–§6).

## 4. What this pass deliberately did not do

- No SPE capture, no BRBE record read, no `perf -j any` on any device: those routes ship as
  documented-and-gated, and the reference's §5 failure modes say exactly how each gate
  fails silently.
- No hardened *closed-source* VM was sliced: the fixture in §6 is an open, self-built
  virtualizer; against a closed VMP the same slicing yields the trajectory, and the
  opcode map becomes a manual labelling task over the (usually few dozen) unique segments —
  which is exactly the workflow the script documents.

## 5. The xvmp toolchain, completed and verified — observed (workbench clone)

The public tree ships the compiler half of its IR virtualizer only, and that half was
never compiled: no TU includes the virtualizer headers, and on dev trees they do not build.
Three facts to keep when working with that tree:

- `getOrCreateVMExec` emits a **weak stub with no implementation** when `vm_exec` is absent
  — a build from that tree as-is links and then falls into the empty stub at runtime.
- Unsupported IR is **skipped with an `errs()` line and no failure** — "compiled clean" is
  not "every function was rewritten": read stderr for `[irvm] skip` lines, or a silently
  skipped function stays native and quietly skews a trace pair.
- The companion write-up (vmp.md) describes a **different, earlier prototype** — 32-bit
  fixed-width ISA, thunk bridges, an LVMP container — none of which is in the tree. Trust
  the code, not the article.

This repository completed the missing half. On the workbench clone of that tree (SSH
environment, 64-core), all four `omp` branches now carry:

- **Pass wiring**: `IRVM.cpp/.h` (new-PM pass beside the obfuscation manager, enabled by
  `-mllvm -irobf-irvm`, functions opt in via `section(".irvm")`) — the first TU that ever
  compiled the virtualizer headers, which required fixing per-tree upstream breakage (the
  revived `ADT/Optional.h` lacks `NoneType`; `DataLayout(Module*)` removed; `Br` split into
  `UncondBr`/`CondBr` on newer trees; `CastOps` renumbered — `FPExt` moved 17→47; the
  Hikari `compat/CallSite.h` called `DenseMapInfo` members dev-main deleted). One branch
  additionally had an **ungated** `IRVMModuleTool` call at the top of
  `Obfuscation::runOnModule` — plain native builds rewrote `.irvm` functions into thunks
  over the weak stub (and native -O1/-O2 escaped only because small functions get inlined
  away); removing it made IRVM strictly flag-gated.
- **FORMAT v3 bytecode**: 8-byte aligned zero-extended slot words; explicit
  `OP_LOAD/OP_STORE` access widths; src/dst bit widths plus a **stable CC_ kind enum** for
  `OP_CAST` (raw LLVM opcode numbers break across trees); operand width for `OP_CMP`;
  **per-index byte scales** for `OP_GEP` (a single element size mis-addresses the
  multi-index GEPs `-O0` emits verbatim). The branch condition is operand 0, never the
  last operand (that is the false-successor label).
- **Runtime**: `vm_exec.c` strong-symbol interpreter (23 hand-packed bytecode unit checks
  on host) and `VMP.h` user header (`IRVM_SECTION`, weak `handle_call` fallback,
  `VMP_TRACE=1` per-step interpreter trace).
- **Verification** (`test_irvm.c`: loops, globals, arrays via GEP, fpu, casts, external
  printf): virtualized vs native output **identical at -O0/-O1/-O2 on all four `omp`
  branches** (upstream commits `9b7cf75..ee23d66`, `cb1e2c1..63f100d`, `8a85cce..ee23d66`,
  `b6b6578..7929a03`).

## 6. The fixture, built, traced, sliced, and named — measured (host)

End to end on the workbench clone with the §5 toolchain:

- **Sample** (`tools/_work/irvm_fixture/fixture_sample.c`): three `.irvm` functions —
  `checksum` (fnv1a loop over 32 bytes), `stats` (fpu + branches), `mix` (byte-shuffle
  casts) — each called 200× from main. `stats` stays native: at -O1 the optimizer's
  if-conversion produces a `select` before the IRVM pass sees it (the documented skip
  hazard; a `volatile` interlock does not survive either). The fixture ships 2/3
  virtualized — as-is, since that is the real workflow.
- **Hardened build**: `-O1 -mllvm -irobf-irvm -mllvm -enable-fco -mllvm -enable-bcfobf
  -mllvm -enable-subobf` plus `runtime/vm_exec.c`; output **identical to native**.
  This tree's Hikari flag is `-enable-fco` (not `-enable-fla`). `handle_call` needs no
  user-side bridge — the pass emits the real const-materialization dispatch into the
  module — but only when at least one function was rewritten: with all candidates inlined
  away (-O1 + single call site) the link fails on the weak `vm_exec` reference chain.
  `noinline` on the `.irvm` functions keeps candidates (and the emitted `handle_call`)
  alive.
- **Guest ground truth**: `VMP_TRACE=1` → 17,961 `[vm] step=` lines (this build traces
  CAST/ARITH/CMP/RET steps only).
- **Host capture**: frida stalker does not work in these containers (measured on both a
  Docker host and an Android-kernel sandbox, frida 16.7.19 and 17.23.3): execution
  primitives pass (anonymous RWX mmap, W^X flip, memfd), the agent loads and runs the
  script, a ptrace syscall-error tracer around the injection tree shows **zero** denied
  syscalls — the failure is inside the injected agent's hook/trampoline machinery, past
  the syscall layer. Two operational notes: an outer ptrace tracer conflicts with frida
  spawn (frida ptrace-attaches the child it spawns → NotSupportedError — do not nest this
  repo's ptrace tooling and frida against the same tree); and the working host capture is
  a 33-line **ptrace single-stepper** (`stepper.c`): 24,582,699 `0x<rip>` lines in 36 s,
  filtered to the main image (23.97 M lines). On Android devices the stalker route keeps
  its own verification status per the skill's evidence rules.
- **Slicing**: `vm_handler_slice.py --dispatcher 0x55b98249c470` (manual — with an
  instruction-per-line stream the dispatcher block's instructions tie in count, so `auto`
  correctly refuses) → **95,184 segments, 18 unique signatures**, `RESULT=ok`. The
  diagnostics fire as designed: the tail stays open (exit path), and the nested-dispatch
  warning marks the outer fla state machine — one guest step crosses the chosen dispatcher
  ~5.3× (95,184 / 17,961), and the len-20 segment (83,286 hits) is the flat state-machine
  shuttle, not a handler.
- **Per-level separation and naming**: the 18 signatures split into the shuttle class and
  16 handler segments (~59 per round). No single host block fires once per guest step
  (fla scattered the switch into per-state entries), so the 200-count round-boundary
  segments split the trajectory into per-call rounds, and each round's signature sequence
  aligns positionally against the VMP_TRACE guest sequence. Result (round 2, all 59
  handler segments named):
  `loop1 x8: [ARITH_OR_SHL, OP_CAST, ARITH_ADD_CMP_latch]` →
  `LOOP_BOUNDARY_BR LOOP2_ENTRY_BR LOOP2_PROLOGUE` →
  `loop2 x8: [ARITH_OR, ARITH_SUB_INDEX, OP_CAST, ARITH11_ADD_CMP_latch]` → `OP_RET` —
  positionally isomorphic to the guest ops (`[or, shl, CAST, add, cmp]` / `[or, sub,
  CAST(zext), arith11, add, cmp]`, many ops per segment under fla), with the latch firing
  7/8 times (the last iteration exits via the boundary segments) and the segment counts
  matching the guest histograms exactly (3232/1600/1400/200). `--opcode-map` yields a
  fully named trajectory, zero unmapped (map at `tools/_work/irvm_fixture/opcode_map.json`).
- **Two findings that carry beyond this fixture**:
  1. `-O1` LICM **hoisted the pure virtualized call** out of the 200× driver loop —
     `checksum` executed once (`c == h*200 mod 2^32`). A virtualized function is not
     protected against being treated as pure by the optimizer that virtualized it; defeat
     hoisting with per-round argument changes when designing fixtures.
  2. `apply_map` originally keyed handler names by the segment's *first block* — under an
     instruction stream (or an outer flattening pass) every segment shares the
     dispatch-successor block, and only the signature distinguishes handlers. Signature
     keys are tried first; first-block keys remain supported.

Artifacts under `tools/_work/irvm_fixture/` (git-ignored): sample, stepper, the frida
attempt, guest trace, host excerpt, opcode map. The full host trace stays on the workbench
clone.
