#!/usr/bin/env python3
"""Detect which obfuscation family a JS bundle belongs to, by weighted content probes.

This is the detection layer of the JS AST pre-deobfuscation route documented in
`references/js-ast-deobfuscation.md`: before running any rewrite pass you want to know
*which family* you face, because the pass order differs per family (a wrong order stalls
or corrupts -- the absorbed architecture's own measured example: late literal-inlining
hangs on large VM-heavy samples, so that family skips it).

Design (absorbed, see the reference for provenance): every family carries

  * ``hint`` tokens -- matched against the file path and the user-supplied ``--hint``
    text; a hit scores 10, because a human saying "this is the delivery platform's SDK"
    is stronger evidence than any content regex;
  * ``content`` regexes -- matched against the source text; each hit scores 3.

Any family scoring > 0 is a detection; the top scorer is the recommended pipeline. No
hit means the generic pipeline, which is also the escalation target when residue stays
stable after the family passes.

What this script deliberately does NOT do: rewrite anything. The passes need a real JS
parser (node + @babel/parser + traverse + generator); this skill ships the detector and
the pass order, not the rewriting engine -- the fence is stated in the reference.

The residue metrics are *textual proxies* (identifier shapes, literal densities, chain
counts), not AST counts; they are honest for comparing before/after a pass batch on the
same file and for nothing finer.

Evidence: `observed` only for `--selftest` against embedded fixtures. No real obfuscated
target was ever run through this detector here; every threshold is a starting point, not
a boundary.

Examples:
    python scripts/js_obf_detect.py bundle.js
    python scripts/js_obf_detect.py bundle.js --hint 'delivery-platform sign sdk' --json
    python scripts/js_obf_detect.py --selftest
"""
import argparse
import json
import os
import re
import sys

FAMILIES = [
    {
        "id": "ob_string_array",
        "display": "string-array / obfuscator.io lineage",
        "hint": ["obfuscator", "javascript-obfuscator", "ob.io"],
        "pipeline": ["normalize", "prune_fake_branches", "string_array_pass",
                     "inline_dispatchers", "flatten_array_cff", "prune_fake_branches",
                     "normalize"],
        "content": [
            (r'\b_0x[a-f0-9]{3,}\b', "hex-mangled identifiers"),
            (r'var\s+_0x[a-f0-9]+\s*=\s*\[', "top-level string array"),
            (r'\b(?:push\s*\(\s*(?:shift|pop)\s*\(\s*\)\s*\)|shift\s*\(\s*\)\s*\))', "rotate/pull decoder idiom"),
            (r'String\s*\.\s*fromCharCode', "charCode decoder"),
            (r'\bparseInt\s*\(\s*[A-Za-z_$][\w$]*\s*\+\s*[^)]*?,\s*16\s*\)', "radix-16 decoder math"),
        ],
        "notes": "Decode the string array before any control-flow work: every later pass "
                 "reads strings through it, and residue metrics on undecoded samples are noise.",
    },
    {
        "id": "control_flow_flattening",
        "display": "control-flow flattening (switch dispatch)",
        "hint": ["flatten", "cff", "ollvm-js"],
        "pipeline": ["normalize", "prune_fake_branches", "inline_dispatchers",
                     "flatten_array_cff", "if_chain_to_switch", "prune_fake_branches",
                     "normalize"],
        "content": [
            (r'while\s*\(\s*(?:!!\[\]|\(?!!\[\]\)?|!0|0x1|1)\s*\)\s*\{', "infinite-loop driver"),
            (r'["\'][0-9]+\|[0-9|]+["\']\s*\.\s*split\s*\(\s*["\']\|["\']\s*\)', "sequence-string order table"),
            (r'switch\s*\(\s*_?0x[a-f0-9]+', "switch on mangled var"),
        ],
        "notes": "Recover the real block order from the state variable's assignment chain; "
                 "the dispatcher block is noise, not structure.",
    },
    {
        "id": "jsvmp_entry",
        "display": "jsvmp entry (opcode literal + interpreter)",
        "hint": ["jsvmp", "js vmp", "sign", "risk"],
        "pipeline": ["string_array_pass", "normalize", "prune_fake_branches",
                     "inline_dispatchers", "if_chain_to_switch"],
        "content": [
            (r'[_$][\w$]{0,12}\'?\]?\s*\(\s*[\'"][0-9a-fA-F]{%d,}[\'"]', "huge hex opcode literal"),
            (r'[_$][\w$]{0,12}\'?\]?\s*\(\s*[\'"][A-Za-z0-9+/=]{%d,}[\'"]', "huge base64 opcode literal"),
            (r'\[\s*(?:Object|Function|Math)\s*,', "globals dependency array"),
            (r'_\$\w+', "_$-prefixed vendor identifiers"),
        ],
        "notes": "Do NOT beautify the interpreter into 'readable' form before reading the "
                 "dispatcher: the pass order here stops at making the dispatch readable. "
                 "See references/jsvmp-recovery.md for the VM work itself.",
        # The huge-literal thresholds are parameters, not constants: a selftest or a small
        # sample legitimately lowers them.
        "literal_min": 1500,
    },
    {
        "id": "opcode_if_chain",
        "display": "opcode if-chain dispatch",
        "hint": ["if chain", "opcode chain"],
        "pipeline": ["normalize", "prune_fake_branches", "if_chain_to_switch",
                     "prune_fake_branches", "normalize"],
        "content": [
            (r'if\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*[=!]==?\s*[A-Za-z_$][\w$]*', "literal-vs-var comparison"),
            (r'else\s+if\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*[=!]==?\s*[A-Za-z_$][\w$]*', "chained else-if"),
        ],
        "notes": "Rewrite to switch ONLY when the whole chain tests one discriminant against "
                 "literals; a mixed chain left as-is beats a mangled rewrite.",
    },
]


def score_families(source_text, hint_text, path_text, literal_min):
    """Return [detection dicts] sorted by score desc then id; every family with score > 0."""
    detections = []
    haystack = " ".join(filter(None, [hint_text, path_text])).lower()
    for fam in FAMILIES:
        score = 0
        reasons = []
        for token in fam.get("hint", []):
            if token.lower() and token.lower() in haystack:
                score += 10
                reasons.append("hint:" + token)
        for rx_src, what in fam["content"]:
            rx_src = _bind_literal_min(rx_src, literal_min)
            if re.search(rx_src, source_text):
                score += 3
                reasons.append("content:" + what)
        if score > 0:
            detections.append({"id": fam["id"], "score": score, "reasons": reasons})
    detections.sort(key=lambda d: (-d["score"], d["id"]))
    return detections


def _bind_literal_min(rx_src, literal_min):
    """Families declare huge-literal thresholds with %d so callers can lower them."""
    return rx_src % literal_min if "%d" in rx_src else rx_src


def residue_metrics(source_text):
    """Textual proxies for 'how obfuscated does this still look'. Compare same-file only."""
    lines = source_text.splitlines()
    identifiers = set(re.findall(r'\b_0x[a-f0-9]{3,}\b', source_text))
    hex_lits = re.findall(r'\b0x[a-fA-F0-9]{2,}\b', source_text)
    comma_expr = re.findall(r'(?<=[;{}])\s*[^;{}()]{1,80},[^;{}]{1,80}\s*(?=[;{}])', source_text)
    switches = len(re.findall(r'\bswitch\s*\(', source_text))
    cases = len(re.findall(r'\bcase\s+', source_text))
    longest = max((len(ln) for ln in lines), default=0)
    evals = len(re.findall(r'\beval\s*\(', source_text))
    return {
        "lines": len(lines),
        "mangled_identifiers": len(identifiers),
        "hex_literals": len(hex_lits),
        "comma_expressions": len(comma_expr),
        "switches": switches,
        "cases": cases,
        "longest_line": longest,
        "eval_calls": evals,
    }


def pipeline_for(family_id):
    """The ordered pass list for a family (or the generic ladder when nothing scored)."""
    fam = next((f for f in FAMILIES if f["id"] == family_id), None)
    if fam is None:
        return ["normalize", "prune_fake_branches", "inline_dispatchers",
                "flatten_array_cff", "if_chain_to_switch", "prune_fake_branches", "normalize"]
    return list(fam["pipeline"])


def notes_for(family_id):
    fam = next((f for f in FAMILIES if f["id"] == family_id), None)
    if fam is None:
        return "Generic ladder only. Escalate to a family adapter when residue is stable and reproducible."
    return fam["notes"]


FIXTURES = {
    "ob_string_array": (
        "var _0x4ab1 = ['\\x68\\x65\\x6c\\x6c\\x6f', 'push', 'shift'];\n"
        "(function (_0x1, _0x2) { var _0x3 = function (_0x4) { while (--_0x4) { _0x1.push(_0x1.shift()); } }; _0x3(++_0x2); }(_0x4ab1, 0x1a4));\n"
        "var _0x9f = function (_0x1, _0x2) { _0x1 = _0x1 - 0x0; var _0x3 = _0x4ab1[_0x1]; return _0x3; };\n"
        "console[_0x9f('0x0')](_0x9f('0x1'));\n"
    ),
    "control_flow_flattening": (
        "function f(_0x1, _0x2) { var _0x3 = '3|1|2'.split('|'), _0x4 = 0; "
        "while (!![]) { switch (_0x3[_0x4++]) { case '1': var _0x5 = _0x1 + _0x2; continue; "
        "case '2': return _0x5; case '3': _0x1 = _0x1 | 0; continue; } break; } }\n"
    ),
    "opcode_if_chain": (
        "function d(o) { if (0x31 === o) { return 1; } else if (0x32 === o) { return 2; } "
        "else if (0x33 === o) { return 3; } else if (0x34 === o) { return 4; } return 0; }\n"
    ),
}


def _jsvmp_fixture(literal_min):
    literal = "ab" * (literal_min // 2 + 10)
    return "global['_$webrt_%s']('%s', [Object, Math, setTimeout, void 0, false, entry]);\n" % ("d2a1", literal)


def selftest(literal_min):
    """Each embedded fixture must select its own family as the TOP pick.

    Exclusivity is NOT asserted: families genuinely overlap by design (hex-mangled
    identifiers appear in the CFF fixture too), so the test pins the winner, not the
    loser list. The hint-beats-content rule (10 vs 3) and the plain-code-is-generic
    case are pinned as well, because both decide real routing.
    """
    for fam_id, body in FIXTURES.items():
        detections = score_families(body, "", "", literal_min)
        assert detections, "no detection for %s" % fam_id
        assert detections[0]["id"] == fam_id, (fam_id, detections)
    jsvmp_body = _jsvmp_fixture(literal_min)
    detections = score_families(jsvmp_body, "", "", literal_min)
    assert detections and detections[0]["id"] == "jsvmp_entry", detections
    # A hint alone is worth 10 and must beat a single content hit (3).
    hinted = score_families("plain text, nothing obfuscated", "delivery-platform obfuscator", "x.js", literal_min)
    assert hinted and hinted[0]["id"] == "ob_string_array" and hinted[0]["score"] == 10, hinted
    # Plain code selects nothing: generic ladder.
    plain = score_families("function add(a, b) { return a + b; }\n", "", "", literal_min)
    assert plain == [], plain
    residues = residue_metrics(FIXTURES["ob_string_array"])
    # The 3+ hex-char filter counts _0x4ab1 but not short names (_0x1, _0x9f) -- pinned so
    # the filter does not silently loosen to counting every _0x-prefixed token.
    assert residues["mangled_identifiers"] == 1 and residues["eval_calls"] == 0, residues
    print("selftest: 4 family fixtures + hint-beats-content + plain-is-generic + residues: ok")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("input", nargs="?", help="JS source file to classify")
    ap.add_argument("--hint", default="", help="free text: target name, vendor, parameter name")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-literal", type=int, default=1500,
                    help="char length that makes a literal 'huge' (default 1500; lower for small samples)")
    ap.add_argument("--selftest", action="store_true", help="run the embedded fixture tests")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.min_literal)
    if not args.input:
        ap.print_usage()
        print("classify: script bundle.js [--hint TEXT]   families: %s" %
              ", ".join(f["id"] for f in FAMILIES))
        return 2
    if not os.path.isfile(args.input):
        print("not a file: %s" % args.input, file=sys.stderr)
        return 1
    with open(args.input, "r", errors="replace") as fh:
        text = fh.read()

    detections = score_families(text, args.hint, args.input, args.min_literal)
    best = detections[0]["id"] if detections else "generic"
    result = {
        "input": os.path.abspath(args.input),
        "best": best,
        "detections": detections,
        "pipeline": pipeline_for(best),
        "notes": notes_for(best),
        "residues": residue_metrics(text),
    }
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print("family: %s" % best)
        for d in detections:
            print("  %-3d %-22s %s" % (d["score"], d["id"], ", ".join(d["reasons"])))
        if not detections:
            print("  (no family scored; generic ladder)")
        print("pipeline order: %s" % " -> ".join(result["pipeline"]))
        print("note: %s" % result["notes"])
        print("residues: %s" % json.dumps(result["residues"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
