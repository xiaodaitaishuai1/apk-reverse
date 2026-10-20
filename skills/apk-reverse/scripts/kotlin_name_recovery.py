#!/usr/bin/env python3
"""Rebuild an (obfuscated -> original) Kotlin class-name map from decompiled sources.

R8/ProGuard rename JVM symbols but cannot strip the Kotlin metadata the Kotlin runtime
itself needs for reflection and coroutines, so two annotations survive into any decompiled
Java and still carry the *original* fully-qualified names:

  * ``@DebugMetadata(c = "com.example.Foo$bar$1", ...)`` -- emitted for nearly every
    ``suspend`` function's SuspendLambda; everything after the first ``$`` is inner/lambda
    scope, so the prefix is the declaring class.
  * ``@Metadata(d2 = {"...", "Lcom/example/Foo;", ...})`` -- every Kotlin class; the first
    non-stdlib ``L...;`` descriptor in ``d2`` is usually the file's primary class.
  * jadx's ``/* renamed from: X */`` comments as a last-resort fallback.

This is a *reading aid*, not ground truth: it feeds names back into a jadx export you are
already navigating, and every mapping is a hint. Method and field names are NOT recovered --
metadata preserves class-level FQNs only.

Provenance: absorbed 2026-10-20 from SimoneAvogadro/android-reverse-engineering-skill
(Apache-2.0), its ``recover-kotlin-names.sh`` + ``references/kotlin-name-recovery.md``;
re-implemented here as a dependency-free Python script. The upstream recovery-rate claims
("30-50% of classes, ~100% of *Repository/*ViewModel/*Impl") are the upstream author's and
are ``unverified`` in this repository. The script itself is measured only by ``--selftest``
on embedded fixtures (``observed`` for the parsing, nothing more).

Examples:
    python scripts/kotlin_name_recovery.py <jadx-export>/sources            # build the map
    python scripts/kotlin_name_recovery.py --map <map-dir> -o nq.e          # obf -> real
    python scripts/kotlin_name_recovery.py --map <map-dir> -p com.example   # list a package
    python scripts/kotlin_name_recovery.py --map <map-dir> --grep '"api/' <jadx-export>/sources
    python scripts/kotlin_name_recovery.py --selftest
"""
import argparse
import json
import os
import re
import sys
import tempfile
from collections import defaultdict

# @DebugMetadata(c = "com.foo.Bar$Inner$1", ...) -- `c` carries the original outer FQN.
RE_DEBUG = re.compile(r'@DebugMetadata\([^)]*?c\s*=\s*"([^"]+)"', re.S)
# @Metadata(... d2 = { "...", "Lcom/foo/Bar;", ... } ...) -- internal class refs of the file.
RE_DTWO = re.compile(r'@Metadata\([^)]*?d2\s*=\s*\{([^}]*)\}', re.S)
# A JVM class descriptor inside d2: Lcom/foo/Bar;
RE_LCLASS = re.compile(r'L([A-Za-z][\w/$]+);')
# jadx emits this comment above classes it renamed during deobfuscation.
RE_RENAMED = re.compile(r'/\*\s*renamed from:\s*([\w.$]+)\s*\*/')

# Third-party / framework trees whose names are already real, so a "recovery" there is noise.
SKIP_PREFIXES = (
    "kotlin.", "kotlinx.", "androidx.", "android.", "java.", "javax.",
    "com.google.", "com.facebook.", "com.appsflyer.", "com.datadog.",
    "io.ktor.", "io.sentry.", "io.realm.", "okhttp3.", "okio.",
    "com.squareup.", "com.bumptech.", "com.airbnb.",
    "com.amplitude.", "com.segment.", "com.mixpanel.", "com.onesignal.",
    "com.stripe.", "retrofit2.", "dagger.", "javax.inject.", "org.jetbrains.",
)

MAP_TSV = "mapping.tsv"
MAP_JSON = "mapping.json"
BY_PACKAGE = "by_package"


def recover_real_name(text):
    """Return (real_fqn, source) for one decompiled file's text, or (None, None).

    Order is deliberate: @DebugMetadata is the most precise (a true declaring-class FQN),
    d2 descriptors are a strong hint, jadx's rename comment is the weakest.
    """
    m = RE_DEBUG.search(text)
    if m:
        # Everything after the first `$` is inner/lambda scope of the original source tree.
        return m.group(1).split("$", 1)[0], "debug_metadata"
    m = RE_DTWO.search(text)
    if m:
        for lm in RE_LCLASS.finditer(m.group(1)):
            cand = lm.group(1).replace("/", ".").split("$", 1)[0]
            # A real package has at least one dot and is not a stdlib/framework ref.
            if "." in cand and not cand.startswith(SKIP_PREFIXES):
                return cand, "metadata_d2"
    m = RE_RENAMED.search(text)
    if m:
        return m.group(1).split("$", 1)[0], "renamed_comment"
    return None, None


def mine_tree(sources_dir):
    """Walk every *.java under sources_dir; return {obf_fqn: {real, file, source}}."""
    mapping = {}
    counts = defaultdict(int)
    for dirpath, _dirs, files in os.walk(sources_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, sources_dir)
            obf = rel[:-len(".java")].replace(os.sep, ".")
            if obf.startswith(SKIP_PREFIXES):
                continue
            try:
                with open(path, "r", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            real, source = recover_real_name(text)
            if real:
                mapping[obf] = {"real": real, "file": path, "source": source}
                counts[source] += 1
    return mapping, dict(counts)


def default_map_dir(sources_dir):
    """The mapping lands next to the sources tree, matching an export-then-query flow."""
    return os.path.join(os.path.dirname(os.path.abspath(sources_dir)), "kotlin-name-map")


def write_map(mapping, counts, out_dir):
    os.makedirs(os.path.join(out_dir, BY_PACKAGE), exist_ok=True)
    with open(os.path.join(out_dir, MAP_TSV), "w") as fh:
        fh.write("obf_fqn\treal_fqn\tsource\tfile\n")
        for obf in sorted(mapping):
            entry = mapping[obf]
            fh.write("%s\t%s\t%s\t%s\n" % (obf, entry["real"], entry["source"], entry["file"]))
    with open(os.path.join(out_dir, MAP_JSON), "w") as fh:
        json.dump({"counts": counts, "mapping": mapping}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    by_pkg = defaultdict(list)
    for obf, entry in mapping.items():
        by_pkg[entry["real"].rsplit(".", 1)[0]].append((entry["real"], obf, entry["file"]))
    for pkg, rows in by_pkg.items():
        safe = pkg.replace(".", "_")
        with open(os.path.join(out_dir, BY_PACKAGE, safe + ".tsv"), "w") as fh:
            fh.write("real_fqn\tobf_fqn\tfile\n")
            for row in sorted(rows):
                fh.write("%s\t%s\t%s\n" % row)
    return len(by_pkg)


def load_map(map_dir):
    with open(os.path.join(map_dir, MAP_JSON), "r") as fh:
        return json.load(fh)["mapping"]


def resolve_query(args, mapping):
    """Run one query mode against a loaded mapping; returns the lines to print."""
    lines = []
    if args.obf:
        if args.obf in mapping:
            lines.append("%s -> %s (%s)" % (args.obf, mapping[args.obf]["real"],
                                            mapping[args.obf]["source"]))
        else:
            # Sibling classes under the same short prefix are useful context: they are
            # frequently the same original class's split lambdas/inner classes.
            prefix = args.obf.rsplit(".", 1)[0] + "."
            siblings = sorted(k for k in mapping if k.startswith(prefix))
            for sib in siblings:
                lines.append("%s -> %s (%s)" % (sib, mapping[sib]["real"],
                                                mapping[sib]["source"]))
            if not siblings:
                lines.append("not in mapping: %s" % args.obf)
    elif args.package:
        for obf in sorted(mapping):
            real = mapping[obf]["real"]
            if real == args.package or real.startswith(args.package + "."):
                lines.append("%s\t%s" % (real, obf))
    return lines


def grep_with_map(pattern, sources_dir, mapping):
    """Grep sources, annotating each hit with the real owning class when known."""
    rx = re.compile(pattern)
    hits = 0
    for dirpath, _dirs, files in os.walk(sources_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, sources_dir)
            obf = rel[:-len(".java")].replace(os.sep, ".")
            try:
                with open(path, "r", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if rx.search(line):
                            real = mapping.get(obf, {}).get("real", "?")
                            print("%s:%d: %s  // %s" % (rel, lineno, line.rstrip(), real))
                            hits += 1
            except OSError:
                continue
    if not hits:
        print("(no hits for %r under %s)" % (pattern, sources_dir))


FIXTURE_DEBUG = '''package nq;

@DebugMetadata(
    c = "com.example.feature.account.AccountRepositoryImpl$fetch$1",
    f = "AccountRepositoryImpl.kt",
    l = {42, 51},
    m = "invokeSuspend"
)
public final class a extends kotlin.coroutines.jvm.internal.SuspendLambda {
}
'''

FIXTURE_METADATA = '''package p0.q;

@Metadata(
    mvp = 1,
    d1 = {"..." },
    d2 = {"", "", "Lcom/example/feature/login/LoginViewModel;", "", "", ""}
)
public final class b {
}
'''

FIXTURE_RENAMED = '''package z;

/* renamed from: com.example.core.network.ApiClient */
public class C0123x {
}
'''

FIXTURE_PLAIN = '''package z;

public class Untouched {
}
'''


def selftest():
    """Parse the three recovery sources plus a negative fixture; assert each outcome.

    The fixtures pin the *shapes* (annotation layout, `$`-suffix scope, d2 descriptor list,
    rename comment), so a regex regression fails here rather than on a real export.
    """
    real, source = recover_real_name(FIXTURE_DEBUG)
    assert real == "com.example.feature.account.AccountRepositoryImpl", real
    assert source == "debug_metadata"
    real, source = recover_real_name(FIXTURE_METADATA)
    assert real == "com.example.feature.login.LoginViewModel", real
    assert source == "metadata_d2"
    real, source = recover_real_name(FIXTURE_RENAMED)
    assert real == "com.example.core.network.ApiClient", real
    assert source == "renamed_comment"
    real, source = recover_real_name(FIXTURE_PLAIN)
    assert real is None and source is None

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "sources")
        for rel, body in (("nq/a.java", FIXTURE_DEBUG),
                          ("p0/q/b.java", FIXTURE_METADATA),
                          ("z/C0123x.java", FIXTURE_RENAMED),
                          ("z/Untouched.java", FIXTURE_PLAIN),
                          ("kotlin/x/Keep.java", FIXTURE_DEBUG)):
            path = os.path.join(src, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(body)
        mapping, counts = mine_tree(src)
        # kotlin.* is skipped as already-real: exactly three mappings must come back.
        assert len(mapping) == 3, mapping
        assert counts == {"debug_metadata": 1, "metadata_d2": 1, "renamed_comment": 1}, counts
        out = os.path.join(tmp, "map")
        packages = write_map(mapping, counts, out)
        assert packages == 3, packages
        assert load_map(out)["nq.a"]["real"] == "com.example.feature.account.AccountRepositoryImpl"
    print("selftest: 3 recovery sources + skip-list + round trip through the map files: ok")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sources", nargs="?", help="decompiled sources root (build mode)")
    ap.add_argument("--out", help="map output dir (default: next to the sources dir)")
    ap.add_argument("--map", dest="map_dir", help="map dir for query modes (-o/-p)")
    ap.add_argument("-o", "--obf", help="resolve one obfuscated FQN (siblings listed as context)")
    ap.add_argument("-p", "--package", help="list real classes under one original package")
    ap.add_argument("--grep", help="regex; grep sources with the real class annotated per hit")
    ap.add_argument("--selftest", action="store_true", help="run the embedded fixture tests")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.obf or args.package:
        if not args.map_dir:
            ap.error("-o/-p need --map <dir> (build it first with: script <sources-dir>)")
        for line in resolve_query(args, load_map(args.map_dir)):
            print(line)
        return 0
    if args.grep:
        if not (args.map_dir and args.sources):
            ap.error("--grep needs --map <dir> and a sources dir")
        grep_with_map(args.grep, args.sources, load_map(args.map_dir))
        return 0
    if not args.sources:
        ap.print_usage()
        print("build: script <sources-dir> [--out DIR]   query: --map DIR -o nq.e / -p com.pkg / --grep")
        return 2
    if not os.path.isdir(args.sources):
        print("not a directory: %s" % args.sources, file=sys.stderr)
        return 1
    out_dir = args.out or default_map_dir(args.sources)
    mapping, counts = mine_tree(args.sources)
    packages = write_map(mapping, counts, out_dir)
    total = 0
    for dirpath, _dirs, files in os.walk(args.sources):
        total += sum(1 for f in files if f.endswith(".java"))
    print("mapped %d of %d .java files (%d original packages) -> %s" %
          (len(mapping), total, packages, out_dir))
    print("by source: %s" % json.dumps(counts, sort_keys=True))
    print("next: --map %s -o <obf.Fqn> | -p <com.example.pkg> | --grep <pattern> <sources-dir>" % out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
