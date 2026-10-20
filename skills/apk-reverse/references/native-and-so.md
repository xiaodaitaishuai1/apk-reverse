# Native & SO Layer

Load this when the Java/dex layer is blocked or unsuitable, when you need code to run **before** the app's
own code, or when a native library is the only editable place left.

If instead the problem is that the app **dies on its own** — hangs, restarts, or crashes natively at a
roughly constant time after launch — that is a terminate mechanism, not a hooking problem, and the
methods differ: read `native-tamper-and-suicide.md` before this file.

The Java layer is usually the right choice. Go native when you need one of these:

- execution **earlier than any app code** (before `Application.onCreate`, before static initialisers),
- a change that survives the app re-loading or re-initialising its Java state,
- a host the integrity checks do not cover while the dex is covered.

## Picking a host library

A library is usable only if all three hold. Verify each; do not assume.

1. **Loaded in your scenario** — confirm in `/proc/<pid>/maps`, not by inspecting the APK.
2. **Editable** — per the boundary map you built in `packers.md`.
3. **Has a call the runtime makes for you** — an exported `JNI_OnLoad` is ideal, because the runtime
   invokes it automatically when the library is loaded by the app, with no trigger of your own.

Prefer a host whose exported JNI entry point exists *and* which appears in `maps`.

## The auto-load trap: `DT_NEEDED` does not call `JNI_OnLoad`

Adding a `DT_NEEDED` entry so one library drags in another is a natural idea. It maps the second library,
but **`JNI_OnLoad` is not invoked for it** — that callback only fires when the runtime loads a library
through the normal library-load API. A dependency loaded purely by the dynamic linker is mapped, not
initialised.

If you rely on `DT_NEEDED`, your entry point must be an **ELF constructor** or a `DT_INIT` entry, not
`JNI_OnLoad`. Conversely, if your host exports `JNI_OnLoad` and you control when the app loads it, that is
the simplest reliable trigger.

Related: a constructor/`DT_INIT` runs so early that the VM may not exist yet. Retry, and treat failure as
non-fatal — a library that logs nothing must never take the process down.

## Relocations and page permissions

This is where most hand-built native payloads fail, and the failure looks like a crash **inside the
dynamic linker**, not inside your code.

Rules that follow from how Android maps libraries:

- **A relocation target must be writable at load time.** The linker writes the computed address into the
  target slot. If the slot lives in a section that is mapped read-only, the write faults
  (`SEGV_ACCERR` in `plain_relocate_impl`).
- **Modern Android refuses W+X segments.** Adding a read/write/execute segment to get both properties is
  rejected; the loader will not give you one.
- Together these mean: relative relocations cannot heal pointer slots that sit in an executable-only page.

### Bootstrapping when relocations cannot work

If your payload's internal pointers all live in the same page as the code that reads them, and that page
must be executable, you cannot use relocations. Do the fixup at runtime instead:

1. derive the runtime page base (a PC-relative instruction gives you this without any relocation),
2. make the page writable/executable via a direct `mprotect` **syscall** (do not depend on the libc
   symbol being imported; a syscall needs no linkage),
3. write the pointer slots yourself, computed from the runtime base,
4. restore the page to read+execute,
5. then branch into your entry point.

Every pointer you need is `runtime_base + fixed_offset`. No relocation is added, so the segment
properties never have to change.

Do **not** try to make a page writable by re-mapping it over itself with an anonymous fixed mapping:
that severs the file mapping, and any other thread executing code on that page faults immediately. Use a
permission change, not a re-map.

## Replacing a Java method from native code

You can redirect a Java method's implementation without touching dex:

- Look up the method id, walk to the `ArtMethod` structure, and rewrite its **quick entry point**.
- Emit a short stub: load a target address from a literal pool and branch to it; return values follow the
  normal calling convention (arguments are already in place, return in the usual register).
- **Always preserve the original code you overwrote.** If the method can be entered through its own
  entry point, a naive redirect makes it jump into your stub, which jumps back into the same entry —
  infinite recursion. Copy the overwritten instructions into a trampoline and branch back after them.
- **Do not patch a method whose entry still points at a shared interpreter bridge.** Methods that have
  not been compiled by JIT/AOT share an entry; rewriting it breaks every method that shares it.
  A practical guard: if two unrelated target methods report the identical entry address, both are still
  on the bridge — refuse to patch rather than corrupting the process.
- Also refuse when the first instruction at the entry is PC-relative (address computed from the current
  program counter): copying it elsewhere silently changes what it points to.

Make installation **fail-safe**: if any precondition is not met, skip the patch and let the app run
unmodified. A hook that silently does not apply is survivable; a hook that corrupts a shared entry is not.

## Finding call sites without symbols

Stripped and obfuscated libraries still expose structure:

- Scan the code section for the pattern that reaches your target (a PC-relative address computation
  followed by an indirect branch through a table slot). A method reached through a **cached table slot**
  will ignore a rewrite of its own entry point, because callers never read that field — another reason
  the entry-point rewrite must be validated per call site.
- Dump the executable range and disassemble around candidate offsets instead of trusting symbol names.
- The JNI calls themselves have a fixed reading shape — in a stripped library this is often the
  fastest way to find where Java objects are touched. The first argument of an exported or
  registered JNI function is the `JNIEnv*`; every JNI call through it compiles to
  `ldr x8, [x0]` (load the vtable) → `ldr x8, [x8, #imm]` (slot) → `blr x8` (call), with `x0`
  holding the env and later slots taking the jobject/jstring. Offsets differ per JNI version and
  per call, so read the offset from a *known* JNI call in an unstripped library of the same
  target ABI before trusting a number. *(The shape is `inferred` from the JNIEnv table layout;
  absorbed from milksu.org notes, retrieved 2026-10-19.)*
- The width/type map for reading those calls: `jboolean` u8, `jbyte` i8, `jchar` u16,
  `jshort`/`jint` i32, `jlong` i64, `jfloat`/`jdouble` 32/64-bit float;
  `jobject`/`jstring`/`j*Array` are pointers, not values. *(inferred from `jni.h`; same
  source, same date.)*
- When a payload was produced by a just-in-time compiler on the target, the displacement between its
  pages is often zero, which is exactly why relocation-free bootstrapping is required (above).

## Reading AArch64 — registers, addressing, frames

The layer under every recipe above: what the disassembly itself means when a Ghidra listing is
open and the question is what a function does with its arguments. *(Unverified as workflow —
absorbed from milksu.org ARM64 essentials 00–02, retrieved 2026-10-19; the ISA facts are
`inferred` from the ARM ARM and AAPCS64 those notes cite.)*

**Registers.**

| Register | Role | Saved by |
|---|---|---|
| `X0`–`X7` | arguments 1–8, return value (`X0`) | caller |
| `X8` | indirect-return address; syscall number at `svc` sites | caller |
| `X9`–`X15` | scratch | caller |
| `X16`–`X17` | intra-procedure scratch — PLT stubs land here | caller |
| `X18` | platform register — on Android it points at TLS | special |
| `X19`–`X28` | locals that survive calls | callee |
| `X29` / `X30` | frame pointer / link register (return address) | callee |
| `SP`, `XZR`/`WZR` | stack pointer; zero register (reads 0, writes discard) | — |

`Wn` is the low-32-bit view of `Xn`, and **writing `Wn` zeroes the high half** — the usual reason
a pointer read through a 32-bit path came back truncated.

**Calls.** First eight integer arguments in `X0`–`X7`, the rest on the stack; return in `X0`
(128-bit in `X0:X1`, large structs through an `X8`-provided buffer). Floating point travels its own
channel (`V0`–`V7` / `D0`–`D7`), so `mix(int, double, int, double)` puts its integers in `W0`/`W1`
and its doubles in `D0`/`D1` — argument *position* is not register *position*. JNI follows from
this: `env` in `X0`, `thiz`/class in `X1`, user arguments from `X2` — which is why the vtable shape
above starts by loading from `X0`, and why a Frida `onEnter(args)` reads them in exactly that
order.

**The frame pattern** every non-leaf function wears:

```asm
stp x29, x30, [sp, #-32]!   // save FP/LR, allocate 32 bytes (SP stays 16-byte aligned)
mov x29, sp                  // new frame pointer
stp x19, x20, [sp, #16]      // callee-saved locals
...                          // body
ldp x19, x20, [sp, #16]
ldp x29, x30, [sp], #32      // restore, release
ret                          // branch to X30
```

Leaf functions skip all of it (`add x0, x0, x1; ret`). The `X29` chain is what any backtrace —
tombstone frames, GDB `bt`, Frida `Thread.backtrace` — is walking.

**Addressing**, the shapes worth recognizing on sight:

| Shape | Meaning |
|---|---|
| `ldr x0, [x1]` / `[x1, #8]` | struct field at offset |
| `ldr x0, [x1, x2, lsl #3]` | `array[i]` with 8-byte elements |
| `ldr x0, [x1, #16]!` | pre-index: bump base, then load — the stack-push shape |
| `ldr x0, [x1], #8` | post-index: load, then walk — the array/list-loop shape |
| `ldr x0, [x1, w2, SXTW]` | sign-extended 32-bit index; a negative `int` index must go here, `UXTW` would turn it huge |
| `adrp x0, #page` + `add x0, x0, #…` | how PIC code references strings and GOT entries — page base plus offset. *(inferred — standard AArch64 codegen; the source notes omit this one, but it is the pattern every string xref in a `.so` actually wears)* |

**Immediates and branches.** A single instruction encodes only a 16-bit immediate, so large
constants arrive as `movz` + `movk` pairs — a 64-bit constant is several instructions long in the
listing, which is why byte-patching "the constant" garbles it unless every piece is edited.
`cbz`/`cbnz` (compare-with-zero branch) and `tbz`/`tbnz` (test-bit branch) are the compact
conditionals; `blr` is the indirect call the vtable shape ends with. The other half of the branch
population is `cmp` + a flag-tested suffix — `cmp x0, x1` is really `subs xzr, x0, x1`, and which
suffix follows decides the comparison kind: `b.eq`/`b.ne` (equal/not), `b.gt`/`b.lt`/`b.ge`/`b.le`
(**signed**, N/V flag logic), `b.hi`/`b.lo`/`b.hs`/`b.ls` (**unsigned**). Signed-vs-unsigned is the
reading error that flips which side of a licence/VIP check you think you are on: a length compared
with `b.hi` is unsigned, so the same branch with `b.gt` means the author expected negatives.

**PAC/BTI**, on armv8.3+/armv9 targets: a function bracketed by `paciasp`/`autiasp` (sign/verify
the return address in LR) or starting with a `bti` landing pad is normal modern codegen — but a
byte patch that **drops** the `paciasp`, or a redirect that lands **past** the `bti`, dies with
`SIGILL` when the branch arrives. Recognition only; presence is probeable from `/proc/cpuinfo`
features. *(inferred — standard ARM semantics, absorbed from milksu.org notes 2026-10-19; see
also `references/native-dbi-and-deobfuscation.md` on translator interactions)*

**Syscall sites**, for reading what `scripts/svc_scan.py` (see
`references/detection-and-anti-analysis.md`) finds: the number is loaded into `X8` and the call
is `svc #0` —

```asm
mov x8, #0x40        // 64-bit table: write 64, ioctl 29, exit 93, clone 220, execve 221
svc #0
cmn x0, #0x1, lsl #12 // bionic wrapper epilogue: is x0 in [-4096, -1]?
b.cs done             // yes → it is an errno, not a return value
```

so a termination site reads as an immediate into `X8` followed by `svc`, with the argument
registers holding fd/status — and bionic's own wrappers wear that `cmn x0, #0x1, lsl #12` +
`b.cs` epilogue (the negative-errno range check), which separates **libc's own** svc sites from a
protector's **inline** ones in a `svc_scan` histogram. A byte scan that reports an `svc` with no
nearby instruction setting `X8` to a resolvable immediate is most likely reading data — the
measured false-positive case — with the exception of a runtime-computed or table-loaded number,
which `svc_scan` reports as `nr=?`: an unreadable site, not a non-site. *(Correction note: the
source article's "real libc fragment" labels `mov x8, #0x47` as `<write>` — 0x47 is 71, sendfile;
the real write wrapper loads 0x40. Its own GDB trace and decimal table were right.)* And the same
immediate-reading applies to a protector's mapping stub: `x2 = #3` is
`PROT_READ|PROT_WRITE`, `x3 = #0x22` is `MAP_PRIVATE|MAP_ANONYMOUS` — an anonymous-private mapping
is where runtime-materialized libraries come from, so the payload never exists in the APK file
and only a live dump can reach it (`references/advanced-unpacking.md`).

## Cross-architecture notes

Architecture is not background information here — it decides **which artifact you must edit** and
**whether your hook can observe anything at all**. Get it from the runtime, not from the manifest.

### What the device claims vs what is executing

Three different answers, and they disagree more often than people expect:

| Source | Answers | Command |
|---|---|---|
| The device | which ABIs the system supports | `getprop ro.product.cpu.abi` and `ro.product.cpu.abilist` |
| The package manager | **which ABI it chose for this app on this device** | `dumpsys package <pkg> \| grep primaryCpuAbi` |
| The live process | **what is actually mapped right now** | `scripts/lib_map.py --pkg <pkg>` |

Only the third is ground truth. The first two are predictions, and they are wrong exactly when it
matters: an emulator whose primary ABI is `x86_64` can be running an `arm64-v8a`-only app through a
translator, and a fat APK can have the package manager pick an ABI you did not assume.

**Consequence: if the library you patched does not appear in the live mapping, your change cannot
matter.** That is a plan problem, and no amount of re-patching will fix it.

### Translation layers change what you are observing

When an ARM-only app runs on an x86 host, a translator (Intel Houdini, `libndk_translation`, a
`native_bridge` in general) is executing the guest code. Detect it from the maps — look for
translator marker libraries and for app libraries whose architecture differs from the host's
primary ABI (`lib_map.py` reports both).

What it changes:

- **Timing.** Translation is slower and less predictable. Anything you measured about latency is
  about the translator, not the code.
- **Native integrity and anti-tamper checks can behave differently** under translation, in either
  direction — a check that fails on hardware may pass here, and vice versa. A pass under translation
  is not evidence of a pass on hardware.
- **Hook behaviour.** Intercepting translated code is not the same as intercepting native code:
  address spaces, calling conventions, and what the host sees at a syscall boundary all differ. If a
  native hook reports nothing while the feature plainly runs, suspect translation before suspecting
  your script.
- **Syscall-level observation shows the host's view.** A file or network call made from the guest
  may look different on the host side than it would natively.

**Rule: verify the artifact on the ABI the user will actually run.** An emulator-only result is a
mid-task checkpoint, never the final claim (`verification.md`).

### Fat APKs: patching the ABI that never loads

An APK can ship `lib/arm64-v8a/`, `lib/armeabi-v7a/`, `lib/x86_64/`… The package manager extracts
**one** of them into the install-time native library directory, and only that one is loaded.

- Check `primaryCpuAbi` and the live maps before editing a `.so`. Editing `arm64-v8a` while the
  device loads `armeabi-v7a` produces a build that is byte-different and behaviorally identical.
- If the deliverable must work for an unknown user, remember their device may select a different
  ABI than yours. Either patch every ABI present, or state which ABI your artifact targets.
- If the app's own libraries are written at *runtime* rather than extracted from the APK, the live
  paths will not be inside the APK at all (`lib_map.py` marks these `materialized`). Those belong to
  whatever produced them, and a repacked APK will not carry them in that location.

### Payloads and tooling are per-ABI too

- A native payload, an injected library, or a shellcode blob built for one ABI **will not load** on
  another. The failure usually surfaces as a *missing library* or a generic linker error rather than
  a clean "wrong architecture" message — do not read it as "my payload is broken".
- **Pointer size differs** between 32- and 64-bit targets. A script or struct layout that assumes
  8-byte words misbehaves silently on a 32-bit target.
- Keep build artifacts per-ABI and label them with the ABI in the filename. Mixing them up is a
  reliable source of "it crashed for no reason" when the same APK behaves differently on an emulator
  and on a device.

### Quick decision list

1. `scripts/lib_map.py --pkg <pkg> --app-only` → which app libraries are loaded, from where, and at
   what architecture.
2. If a translator is present and the task needs reliable native behaviour, move to a matching
   device.
3. If the library you meant to patch is absent, stop — pick the right library first.
4. Only then start editing.

## Verification

A native patch earns no credit until the behaviour changes **and** the app stays healthy:

- log a marker from your entry point so you know it ran at all;
- confirm the library is in `maps`;
- confirm the app reaches its normal UI afterwards;
- keep the original library so you can produce an unmodified control build.

Never conclude "the hook works" from the absence of a crash. Absence of effect is the normal outcome of a
hook that never installed.
