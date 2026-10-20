# Extension verification — absorption pass: four public write-ups (Kanxue, 2026)

Covers the absorption of four public reverse-engineering write-ups the user supplied
(2026-08/09 postings; titles, authors and every sample identity anonymized in this record —
the write-ups themselves were already anonymized by their authors). Following the
absorption-pass convention (`EXTENSION-desensitization.md`): **only phase, checklist and
command patterns cross over**, nothing target-shaped, and each absorbed claim carries its own
strength label.

**Headline: two write-ups produced a new reference (`references/native-vm-recovery.md`, every
step `inferred`), one produced four pitfalls (P43–P46) and one tool fix; one write-up's
dispatcher-margin lesson was already absorbed in the previous pass. The sources are public
postings; no sample, tool output or target fact from them entered the repository.**

---

## 1. What was read

| Source (anonymized) | Shape | Absorbed into |
|---|---|---|
| W1: full arm64 custom-VM recovery (long-form) | 0x00–0x1A method narrative | `references/native-vm-recovery.md` (existence signals, dispatcher separation, partial deflattening, relocation tables, PC proofs, descriptor/ISA cautions, clean-re-VM loop) |
| W2: VMP interpreter recovery with trace-driven IR lifting | anchor/trace/lifting narrative | `references/native-vm-recovery.md` (register anchoring + triple verification, nested segment stacks, STORE-backward slicing, byte provenance, IR shape), `vm_handler_slice.py` nested-loop diagnostic |
| W3: login-capture war story (packed + MADP/Weex + gomobile) | route-by-route复盘 | `references/pitfalls.md` P43–P46; the stack-ABI note in `references/hardware-watchpoints.md` |
| W4: manual OLLVM deflattening | predicate algebra + IDA scripting | cross-checked against existing content; its MOV/MOVK constant-propagation state mapping is referenced as the static counterpart in `native-vm-recovery.md` §11 — no new file |

## 2. The one code change, and why — observed

`vm_handler_slice.py` gained `nested_loop_segments()`: a block repeating 4+ times **inside one
segment** flags a nested dispatch loop. Reasoning absorbed from W2: handler chains repeat
across segments, never within one — a within-segment repeat is a second dispatcher running
under the first, and W2 measured 45-of-46 entries nested with 57–1997 instructions lost per
nesting under a flat accumulator. Host-tested on a synthetic nested fixture:

```
$ python vm_handler_slice.py --log nested.log --dispatcher libvm.so+0x1000
  note: segments 2 contain a block repeating 4+ times inside one segment: a nested dispatch
  loop ... slice per level; the segment-stack fix is documented in
  references/native-vm-recovery.md
```

The same edit fixed a latent bug this pass's review found: `diagnostics()` had been measuring
`len()` of `(run, closed)` tuples (always 2) since the open-tail change, quietly disabling the
spin-loop note on the real code path. Both regressions are now pinned by tests.

## 3. The judgement calls — what did NOT cross over

- W1/W2's Ghidra/SLEIGH-specific mechanics (p-code slicing internals, seed definitions bound to
  their toolchain): only the **method** crossed (store-backward, provenance-over-value); the
  repository ships no Ghidra script and none is implied.
- W3's working exploit details (hook source, injection directory, SELinux labels of the
  delivery mechanism): the delivery route already has its own file
  (`references/lsposed-and-modules.md`, `kernel-event-injection.md`); what crossed is the
  **layer-identification discipline** (each dead end names the next layer; prefer the highest
  plaintext boundary; a RegisterNative inventory is one run for a full method table).
- W4's full IDA script: the technique is named (state-register MOV/MOVK constant propagation,
  CMP-site collection, predecessor walk past blocks with no CMP on the state register) and
  pointed at from `native-vm-recovery.md` §11; writing an IDA-independent implementation is a
  future pass, not an absorbed claim.
- Every sample identity in all four sources: anonymized by the authors, kept anonymized here;
  `.ref/` (the local copies) is untracked and git-ignored in effect (never added).

## 4. Strength accounting

- `native-vm-recovery.md`: every method step `inferred` (absorbed, not executed here) — stated
  in the file's own header, mirrored in `evidence-summary.md` and the capability matrix.
- `vm_handler_slice.py` nested diagnostic: `observed` on the host fixture (this pass).
- Pitfalls P43–P46: absorbed as `inferred` lessons with their mechanism stated; each names the
  check that would have caught it, per this repository's pitfall format.
- No claim from the write-ups was upgraded to `observed` by absorption. That is the point of
  the convention: a method someone else paid for is a lead, not a measurement.
