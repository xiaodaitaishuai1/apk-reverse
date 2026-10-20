# Extension verification — dexsql, the SQL query layer (parity, decode, cache, MCP)

Covers the pass that adopted `dexsql` as a third indexer beside `rasc`/`droidasc`/`ddc` and
registered it as the `dex_query_sql` capability. Strength labels as this directory's README defines
them.

Reference environment: Windows 10.0.26100, PowerShell 7, Python 3.14.0, no device attached. The tool
is a release download (`dexsql-windows-amd64.exe`, v0.1.0, 21,365,760 B, sha256
`f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448`) — no build step, no Python, no
JVM, no Android SDK.

**Headline: the class-definition parity check passes on all four archives — identical to `rasc`,
`droidasc` and `ddc`, zero differences either way — and the string cross-reference agrees site for
site. Three claims came back *smaller* than they could have been sold: the persistent cache is not a
speed switch, `decode` emits smali rather than Java, and the SQL match semantics are not `findrefs`'s.
The MCP surface was exercised to a tool listing, not end to end from a client.**

---

## 1. Class-definition parity — observed

The check that decides whether a new indexer may be trusted for location questions at all, and the
same comparison `rasc_build.py --verify` performs between `rasc` and `droidasc`. Each tool prints
class identity in its own shape, so each output is parsed per format and normalised to a DEX
descriptor before comparing — a single regex over all four outputs measures the regex, not the tools
(this pass's own first defect: an unescaped `$` in a descriptor pattern silently dropped classes whose
names contain `$` or non-ASCII characters, and reported `droidasc` as 38 classes where it returns 647).

| Archive | dexsql | rasc | droidasc | ddc | verdict |
|---|---|---|---|---|---|
| 1.4 MB MASTG challenge | 1,396 | 1,396 | 1,396 | 1,396 | identical |
| 4.3 MB hardened | 647 | 647 | 647 | 647 | identical |
| 38.7 MB hardened | 4 | 4 | 4 | 4 | identical |
| 34.8 MB app | 30,768 | 30,768 | 30,768 | 30,768 | identical |

Zero differences in either direction on every row. The two small counts are the hardened targets, not
the tools: the business dex is encrypted inside a shell and is in no DEX any of the four can read.

Full class listing, best of 3, stdout redirected to a file — the same shape for all four tools:

| Archive | dexsql | rasc | droidasc | ddc |
|---|---|---|---|---|
| 1.4 MB / 1,396 classes | 0.035 s | 0.028 s | 0.149 s | 0.109 s |
| 4.3 MB / 647 classes | 0.031 s | 0.025 s | 0.139 s | 0.099 s |
| 38.7 MB / 4 classes | 0.040 s | 0.021 s | 0.156 s | 0.092 s |
| 34.8 MB / 30,768 classes | 0.136 s | 0.055 s | 0.200 s | 0.156 s |

The `rasc` and `droidasc` columns reproduce this repository's earlier figures for the same 34.8 MB
archive (0.048 s / 0.190 s), which is what makes the new column comparable rather than merely new.
`dexsql` is 1.5× faster than the Python indexer and 2.5× slower than the Rust one, so **it does not
replace `rasc` for a plain class list** — it answers questions the other two cannot express.

## 2. Cross-reference parity, and the semantics that differ — observed

```
$ dexsql query --input <1.4 MB challenge> --sql \
    "SELECT DISTINCT method_class, method_name FROM method_strings WHERE value LIKE '%http%'"
Landroid/support/v4/content/res/TypedArrayUtils; | hasAttribute
Landroid/support/v4/text/util/LinkifyCompat;     | addLinks
Landroid/support/v4/util/PatternsCompat;         | <clinit>
```

`rasc findrefs … string http` and `droidasc findrefs … string http` return exactly those three sites,
and `ddc findrefs` agrees. **The matching semantics differ, and the difference is a trap worth
recording:** `findrefs` matches a *substring*, while SQL needs `LIKE '%…%'`. `WHERE value = 'http'`
returns **zero rows** and is not a broken query — no method in that archive holds a literal that *is*
`http`. A first pass read that empty result as a tool defect; the control was the same query with
`LIKE`, which reproduced ASC's answer exactly.

## 3. `decode` against `ddc disasm` — observed

```
$ dexsql decode --input <challenge> --method 'Lsg/vantagepoint/uncrackable3/MainActivity;->verifyLibs()V'
.method private verifyLibs()V
    .registers 14
    const-string v0, "UnCrackable3"
    new-instance v1, Ljava/util/HashMap;
    ...
```

The instruction sequence matches `ddc disasm <challenge> sg.vantagepoint.uncrackable3.MainActivity.verify`
line for line on that method. `decode` emits **smali, not Java** — that is a feature for the
bytecode-level decision `dex-patching.md` requires, and a limitation when the question is Java-level,
where `ddc getclass` still owns it. A missing class exits 1 with `Error: not_found: selected file,
method, or class not found`.

## 4. The persistent cache is not a speed switch — observed

```
$ dexsql prepare-cache --input <34.8 MB app> --output cache     # 0.196 s, writes cache.dxc2 34,481,119 B
$ dexsql query --input <app> --full --sql "SELECT count(*) FROM method_calls"      # 0.121 s
$ dexsql query-cache --cache-file cache/cache.dxc2 --sql "SELECT count(*) FROM method_calls"   # 0.098 s
$ dexsql query --input <app> --full --sql "<top-20 GROUP BY over method_calls>"    # 0.470 s
$ dexsql query-cache --cache-file cache/cache.dxc2 --sql "<same aggregate>"        # 0.458 s
```

**Under 20%, not an order of magnitude**, because parse-and-build is already 0.12 s on that archive.
On the 38.7 MB sample the cache is a net *loss* (0.071 s from cache against 0.042 s direct). The
honest claim is "hold one dataset across many queries in a long session", not "queries get fast" —
and the cache file is roughly the size of the source archive.

## 5. Error surface and read-only enforcement — observed

Every failure exits 1 with a named cause, and writes are refused:

| Input | Result |
|---|---|
| missing class | `Error: not_found: selected file, method, or class not found` |
| missing file, or a non-dex file | `Error: load_failed at load_inputs: failed to prepare native input cache` |
| unknown column | `Error: invalid_query at execute_sql: unknown column `nope`` |
| unknown relation | `Error: invalid_query at execute_sql: unknown relation `nope`` |
| `DELETE FROM classes` | `Error: SQL statement 1 failed` — the statement is rejected |

## 6. The MCP surface, exercised to its boundary — observed (listing), unverified (client)

`dexsql mcp` speaks JSON-RPC over stdio; an `initialize` + `tools/list` handshake returns 13 tools:
`open_dataset`, `list_datasets`, `close_dataset`, `list_tables`, `describe_table`, `query`, `decode`,
`get_manifest`, `get_manifest_components`, `list_resource_files`, `read_resource`, `query_resources`,
plus an embedded English documentation catalog on `resources/list`. Every list-shaped result carries
`next_offset`, and the resource tools read `resources.arsc` and archive entries without extracting
them to disk. Quotas are explicit (`--max-datasets`, `--max-input-bytes`, `--max-dex-bytes`,
`--max-output-bytes`, `--timeout-ms`), and the server's own instructions say a running timeout closes
the affected dataset. **No client session was driven against it in this pass** — the tool list and the
schemas are what is measured.

## 7. What this pass deliberately did not do

- No Linux or macOS asset was downloaded or run: the release publishes `linux-amd64`, `linux-arm64`
  and `darwin-arm64` binaries and none was exercised.
- No MCP client session: the handshake and tool inventory were read, the tools were not called.
- No patching through `dexsql`: it has no write path, and nothing here claims one.
- No claim about a packed target beyond the parity row: on both hardened archives it returns the same
  class count as the other three tools, and the payload is not in any readable DEX.

## 8. Facts this pass pinned for the next one

- **A new indexer earns trust by the class-set comparison, not by its feature list.** The parity check
  is cheap (four tools, four archives, seconds) and it is the only evidence that separates "answers
  location questions correctly" from "parses most of the file". Do it before adopting the next one.
- **Parse each tool's own output format.** The first pass compared four differently-shaped outputs
  with one regex and produced two false verdicts — one an unescaped `$`, one a dotted-vs-descriptor
  mismatch. A comparison harness is itself a tool that needs a control.
- **`doctor.py` is the registration surface.** Adding `tool:dexsql` plus a `dex_query_sql` capability
  makes G2 report the tool instead of guessing, and `INSTALL_HINTS` is where a release download or a
  from-source build declares the location this kit's own install step produces, so a machine that
  followed the instructions is not reported BLOCKED.
- **The three indexers now have a stated division of labour:** `rasc` locates fastest, `droidasc` is
  the Python cross-check, `dexsql` answers joins and aggregates (and carries the resource model).
  Writing that down is what keeps the next pass from re-deriving it.
