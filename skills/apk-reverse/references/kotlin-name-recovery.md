# Kotlin name recovery — original class names survive R8 inside annotations

**Load this when** you are reading a decompiled Kotlin app and the class names are meaningless
(`nq.e`, `a`, `C0123x`) — before you conclude the code is "unreadable" and before you sink hours
into cross-referencing by shape. One pass over the export recovers the *original* names for a
large share of the classes you actually want to read.

**What this answers:** which original class each obfuscated class was — from data R8 cannot strip,
not from guessing. What it does **not** answer: method names and field names (never recovered —
see Limits).

Contents: §1 why the leak exists · §2 the three sources · §3 the shipped script · §4 what you
typically get · §5 how it plugs into this kit's index-first discipline · §6 limits.

**Provenance.** Absorbed 2026-10-20 from `SimoneAvogadro/android-reverse-engineering-skill`
(Apache-2.0), its `recover-kotlin-names.sh` and `references/kotlin-name-recovery.md`; re-implemented
here as a dependency-free Python script. The recovery-rate numbers in §4 are the upstream author's
claims — `unverified` here. The script's parsing is `observed` against its own embedded fixtures
only (`--selftest`); no real obfuscated app was run through it in this repository.

## 1. Why the names survive

R8/ProGuard rename JVM symbols, but the Kotlin runtime needs metadata at runtime — for reflection,
coroutines (`@DebugMetadata` drives coroutine stack-trace recovery), and `data class` / serialization
behaviour (`@Metadata`). The annotations are **values the runtime reads**, so obfuscators keep them,
and the values contain the original fully-qualified names. This is a leak by necessity, the same
class of fact as "R8 cannot rename what the manifest references" (`recon.md` §5's anchor idea).

## 2. The three sources, in trust order

1. **`@DebugMetadata(c = "...")`** — emitted for nearly every `suspend` function's `SuspendLambda`
   subclass. The `c` value is the original FQN **with `$`-suffix scope**:
   `com.example.account.AccountRepositoryImpl$fetch$1` means the declaring class is everything
   before the first `$`. Highest precision: a true declaring-class name, one per coroutine lambda —
   and modern Kotlin apps are full of them.
2. **`@Metadata(d2 = {...})`** — every Kotlin class carries it. The `d2` array lists the file's
   internal class references as JVM descriptors (`Lcom/example/Foo;`); the **first non-stdlib,
   non-framework descriptor** is usually the file's primary class. A hint, not a declaration.
3. **jadx `/* renamed from: X */`** — jadx's own rename bookkeeping, emitted when `--deobf` or a
   mapping renamed the class. Weakest: it records what *jadx* renamed from, which for an R8 target
   is the obfuscated name — useful mainly for jadx-generated names (`C0123x`).

## 3. The shipped script

```bash
python scripts/kotlin_name_recovery.py <jadx-export>/sources          # build the map
python scripts/kotlin_name_recovery.py --map <map-dir> -o nq.e        # resolve one name
python scripts/kotlin_name_recovery.py --map <map-dir> -p com.example.feature   # list a package
python scripts/kotlin_name_recovery.py --map <map-dir> --grep '"api/' <jadx-export>/sources
```

Outputs: `mapping.tsv` (`obf_fqn  real_fqn  source  file`), `mapping.json`, and `by_package/`
(one file per original package). The `--grep` mode is the everyday one: it greps the export and
annotates **every hit with the real owning class**, so the export becomes navigable without opening
files one by one. Third-party trees (`kotlin.*`, `androidx.*`, `okhttp3.*`, …) are skipped — their
names are already real.

Resolving `-o nq.e` also prints **siblings** under the same short prefix (`nq.d`, `nq.f`): they are
frequently one original class's split lambdas/inner classes, which is often the context you wanted.

## 4. What you typically get — upstream's claims, `unverified`

| Class kind | Recovery |
|---|---|
| `*Repository` / `*Impl` / `*ViewModel` / `*UseCase` | ~100 % |
| plain `data class` DTOs | ~80 % |
| share of all classes in a real app | 30–50 % |

The shape is the point: the classes a *reading* task targets are exactly the annotated ones, so the
effective recovery on "the classes you came for" is much higher than the global share. Treat the
numbers as directional; this repository has not measured them.

## 5. How it plugs into this kit's order of work

This is a **reading aid for the export tier**, not a replacement for the index tier
(`SKILL.md` §Tooling — orient with an indexer, not an export): locate first with `rasc findrefs` /
`dexsql query`, then read the located class in the export with names restored. Two combinations that pay:

- **Mapping onto query results:** the index hands you `nq.e`; `-o nq.e` tells you it is
  `com.example.feature.account.AccountRepositoryImpl` — which usually *is* the layer answer
  (`recon.md` §3's "where does the behaviour live" becomes a lookup instead of an inference).
- **Endpoint hunting:** `--grep '"/' <export>` over the app's own packages gives every path literal
  with its real owning class attached — a cheap first pass for `server-api.md`'s surface list.

## 6. Limits — say them before trusting a mapping

- **Method and field names are never recovered.** Metadata preserves class-level FQNs and some
  signatures, not members. For members you still need call-site evidence (`find_refs.py`,
  `dexsql` callers) or jadx-gui's interactive rename.
- **Pure-Java classes carry no `@Metadata`** and stay obfuscated; the fallbacks do not see them.
- **Heavily inlined shapes** (`@JvmInline value class`, top-level functions compiled into shared
  `*Kt` classes) can surface under a wrong primary class; every mapping row is a hint, and §5's
  cross-checks are the antidote.
- The script reads **decompiled sources**, not the dex: annotations are read as jadx printed them,
  so a decompiler that drops annotations removes the source entirely. (The raw dex annotation
  sections carry the same strings — `dexsql`'s annotation tables — as a cross-check when in doubt.)
