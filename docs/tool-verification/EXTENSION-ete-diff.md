# Extension verification — ETE differential tracing (gates, reducer, differ)

Covers the hardware-layer pass that added `scripts/ete_capture.py`, `scripts/trace_diff.py` and
`references/ete-diff-tracing.md`. Strength labels as this directory's README defines them.

Reference environment: Linux container host, Python 3.13, adb present with no device. No
coresight-capable hardware exists in this environment at all; the reference device of the
earlier passes (kernel 4.14.186) has the ETE gate closed permanently (`observed` there).

**Headline: the gate table, the recipe and the capture wrapper are host-measured; the
differential reducer is host-measured on synthetic flattened-dispatcher fixtures. No ETE trace
was captured or decoded anywhere in this pass — the producer side is `unverified` and the
`--control` run exists precisely so the next device says so in one command.**

---

## 1. The differ, measured on a synthetic OLLVM shape — observed

Two fixture logs built to the flattened-dispatcher rhythm `D R1 D R2 …` — run A taking
`R5/R7` (wrong password), run B taking `R3/R4` (right password), one log in raw
`stalker_trace.js` grammar, one wrapped by `run_probe.py` (`[ts] [ts] TRACE BLK …`) to prove
the parser survives both:

```
$ python skills/apk-reverse/scripts/trace_diff.py diff --a a.log --b b.log
run A: 8 events, 5 distinct blocks
run B: 8 events, 5 distinct blocks
shared block executions: 6   divergent regions: 2
first divergence: after run #5 (A) / #5 (B), 5/5 events in, last common block liba.so+0x1000
region 1 (replace)
  A: liba.so+0x6000        B: liba.so+0x4000
blocks unique to A ...: 0x6000, 0x8000      blocks unique to B ...: 0x4000, 0x5000
```

What the output pins, and why each number is the one the method needs:

- **the identical prefix** (`D R1 D R2`, 5 events) is the shared machinery — exactly where
  parsing ends and the input-dependent path begins;
- **first divergence** names the dispatcher entry whose state constant differed;
- **unique-to-each-side** lists are the input-dependent block set, which is the deliverable
  the reference file's §4 interprets per obfuscation.

`reduce` on one side prints the histogram with the dispatcher as the wide-margin top
(4 hits vs 1 for every real block) — the same shape `stalker_report.py` documents for Stalker
logs, reached from a different producer.

## 2. Gate and capture plumbing — observed (to the no-device boundary)

`gates` prints the five-gate table; `gates --device` with adb present but no device degrades
to five `OPEN` rows and `RESULT=partial` rather than a traceback — measured. `capture --pid 1`
without a device exits through the pull failure with `RESULT=blocked` and exit code 3
(no-device capability refusal, per the CLI contract) — measured. `recipe` prints the
Termux and cross build paths for perf-with-CORESIGHT — `inferred` from the kernel's
tools/perf CoreSight documentation and the OpenCSD project, not from a build performed here.

## 3. What this pass deliberately did not do

- No perf-with-CORESIGHT was built (host or device): the recipe is a documented path, and a
  reader who builds it owes the control record (`capture --control`) before any real capture.
- No decoded cs_etm stream was fed to `trace_diff.py`; the `plain` parser accepts the
  address-bearing lines `perf script` emits, but that exact pairing is `unverified`.
- No claim about ETE's runtime overhead or its visibility to targets was measured. The
  reference states the mechanism (no code modification, no ptrace) and refuses to go further.

## 4. Facts this pass pinned for the next one

- The differ is **producer-agnostic by design**: the same command answers Stalker logs today
  and cs_etm decode output tomorrow. That is why the diff subcommand ships now, not after the
  first ETE capture — it is useful the day a Stalker pair exists.
- The five gates each fail **silently** downstream; the reference's table says which silence
  each gate produces. The one-instruction control record is the only gate that exercises the
  whole pipe, which is why `capture` refuses to continue when it fails.
- Run design is part of the tool contract, not user care: `trace_diff.py` refuses empty logs
  with a message that points at the zero-event diagnostics, because an empty trace is a
  capture failure wearing an analysis result's clothes.
