# Extension verification — kernel-side instrumentation scaffold (templates, gates, verify)

Covers the hardware-layer pass that added `scripts/kernel_instrument_scaffold.py` and
`references/kernel-event-injection.md`. Strength labels as this directory's README defines
them. This pass follows `EXTENSION-kernel-weapons.md`'s shape deliberately: a generator whose
host behaviour is measured, kernel-side templates that have never been compiled or loaded
anywhere, and the gate table that says so.

Reference environment: Linux container host, Python 3.13, no `aarch64-none-elf-gcc`
(`gates` reports NOT FOUND — observed), no APatch/KernelPatch boot image, no device.

**Headline: `gates`/`generate`/`verify` are measured on the host. Every generated kernel-side
file carries a `NOT COMPILED AND NOT LOADED` banner that `verify` enforces. The
register-rewrite action is labelled experimental in the template itself — it was never run
anywhere, by anyone in this repository.**

---

## 1. Generate + verify round trip — observed

```
$ python skills/apk-reverse/scripts/kernel_instrument_scaffold.py generate \
    --out work/kwatch --pid 12345 --watch w:0x7b2000123450:8:w --break b:0x7b20001234c0 --set-reg x0=0x1
wrote work/kwatch
  kpm/src/kwatch.c  kpm/Makefile  lkm/kwatch.c  lkm/Makefile
  module.prop  README.md  post-fs-data.sh  config/instrument.json
RESULT=ok
$ python skills/apk-reverse/scripts/kernel_instrument_scaffold.py verify --dir work/kwatch
verified 4 kernel-side file(s), 0 problem(s)
RESULT=ok
```

Spec validation reuses the hardware rules and refuses at generation, before any file is
written: a watch crossing its 8-byte window and a misaligned breakpoint PC both exit 2 with
the reason (`observed`, same refusal strings as `hw_watch.py plan` — one rule, one copy in
each tool, both unit-tested).

The generated KPM template embeds: `kfunc_def(...)` declarations **without** `extern` (the
loader-rejection lesson recorded in `EXTENSION-kernel-weapons.md`, restated in the template's
own header), a callback whose first statements are the cheap filter, and the watch config as
generated constants with *"regenerate rather than hand-edit"* in the config JSON.

## 2. The honesty devices this pass ships

- **The primitive map is a capability table, not a wishlist.** Each cell names what the route
  can do, and the `no` cells (eBPF cannot create perf breakpoint events; a userspace module
  cannot arm anything) are the rows that stop a reader from spending a day on a route that
  cannot express the need.
- **The experimental action is fenced three times**: template comment, script header, and the
  reference's stop table ("the first run is a measurement"). Rewriting `pt_regs` in a perf
  overflow callback is mechanically what a ptrace stop does, and that is exactly as far as
  the claim goes.
- **The userspace carrier cannot arm watchpoints and says so in its own README** — the same
  structural correction `EXTENSION-kernel-weapons.md` made for syscall masking, applied
  before anyone could misread this module the same way.

## 3. What this pass deliberately did not do

- Nothing was compiled: no `aarch64-none-elf-gcc` exists here, no KernelPatch image exists on
  any reference device, and the LKM route has no matching kernel source. All three kernel
  files are `unverified` templates and are labelled so in the files themselves.
- No claim about whether `register_hw_breakpoint` can be resolved from a KPM on any specific
  KernelPatch revision is made; the template says to verify symbol names against the
  revision's `kpmodule.h`, which is the same instruction the syscall-mask template gives.

## 4. Facts this pass pinned for the next one

- The kernel's **perf breakpoint layer owning the debug registers** is a gate in its own
  right: if `CONFIG_HW_PERF_EVENTS` is out, both templates close regardless of root scheme.
  Probe: `ls /sys/bus/event_source/devices/breakpoint` on the device.
- `verify` exists so the banner survives edits: someone will adapt a template on a real
  device, strip the banner, and the next reader must be able to tell an adapted-unverified
  file from a measured one. A banner replaced by a real measurement is the intended
  outcome, and `kernel-event-injection.md`'s checklist says so.
