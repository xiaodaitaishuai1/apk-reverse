# Extension verification — hardware watchpoints (ptrace route, helper, encoders)

Covers the hardware-layer pass that added `scripts/hw_watch.py` and
`references/hardware-watchpoints.md`. Strength labels as this directory's README defines them.

Reference environment: Linux container host, Python 3.13, cross `gcc 16.2.0` targeting
`aarch64-linux-gnu`. No Android device was attached during this pass; `adb` exists on PATH but
reports no devices (`adb: no devices/emulators found`, observed).

**Headline: the encoders, the plan/emit/decode paths and the helper's build are measured on the
host — including a clean static aarch64 compile of the emitted C. No watchpoint was armed on any
device by this pass; the device-side behaviour is `unverified` by this record.**

---

## 1. Encoder acceptance and refusal — observed

```
$ python skills/apk-reverse/scripts/hw_watch.py plan --addr 0x1004 --len 4 --access w --json
{"status": "ok", "specs": [{"kind": "watch", "addr": 4100, "len": 4, "access": "w", "vr": 4096,
 "cr": 7701, "cr_fields": "BAS=0xf0 LSC=store PAC=EL0 E=1"}]}
```

WCR `0x1E15` = BAS `0xf0` (bytes 4–7 of the aligned window) | store | EL0 | enabled — the bit
fields decompose back to the inputs exactly. Refusals measured with exit 2 and a reason:

- `--addr 0x7b2000123456 --len 8` (addr&7=6, 6+8>8): *"crosses its aligned 8-byte window"*
- `plan --break 0x1002`: *"breakpoint PC 0x1002 is not 4-byte aligned"*

The canonical values are pinned by unit test (`tests/unit/test_hw_watch.py`): 8-byte rw watch
`WCR=0x1FFD`, address-match EL0 breakpoint `BCR=0x3F05`.

## 2. The emitted helper compiles as a static aarch64 ELF — observed

```
$ python skills/apk-reverse/scripts/hw_watch.py emit --out work/hwwatch
$ gcc -static -O2 -o hwwatch work/hwwatch/hwwatch_helper.c
$ file hwwatch
hwwatch: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked
```

Zero errors, zero warnings after one fix (a `TRAP_HWBKPT` redefinition against glibc's
`signal.h` needed an `#ifndef` guard; bionic defines the same macro). The compiler here is a
cross glibc toolchain, not the NDK — the binary was not run, and the runtime behaviour of the
ptrace loop (seize/interrupt per tid, `PTRACE_O_TRACECLONE` arming, `TRAP_HWBKPT` siginfo
handling, the disable-step-rearm breakpoint dance, group-stop `PTRACE_LISTEN`) remains
**`unverified`** until a device runs the control procedure in the reference's §3.

## 3. What this pass deliberately did not do

- No device was attached: no `READY watch_slots=N` probe, no slot-capacity read, no control
  run, no hit. Every device-behaviour claim in `hardware-watchpoints.md` carries `unverified`.
- `decode` was exercised on synthetic `HIT` lines only (unit test); a real `/proc/<pid>/maps`
  pull was not available to feed it.
- `run` (build+push+stream) was exercised to its argument-validation and no-adb exits only;
  its `exit 3` on missing adb was measured before a device was ever contacted.

## 4. Facts this pass pinned for the next one

- `slot_capacity` reads `dbg_info & 0xff` from the `NT_ARM_HW_WATCH`/`NT_ARM_HW_BREAK`
  regsets — the ABI gdb uses for the same purpose; on a masked kernel this returns 0 and the
  helper prints `READY ... watch_slots=0`, which the reference file treats as a **closed
  gate**, not a tuning problem.
- The helper's output grammar (`READY`/`ARM`/`HIT`/`EXIT`/`DONE`) is load-bearing: `decode`
  and the reference's control procedure both parse it. Changing the helper means regenerating
  both ends.
- The honesty ledger (ptrace route leaves `TracerPid` visible) is stated in three places on
  purpose — script header, reference §1, evidence summary — because the tempting wrong claim
  ("invisible") is exactly what a reader under pressure wants to believe.
