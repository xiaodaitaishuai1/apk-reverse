"""Unit tests for trace_diff.py: parsers, run-length, and the differential.

The fixtures are synthetic flattened-dispatcher traces (D R1 D R2 ...), because
that is the shape the differ exists to answer: same machinery, different
input-dependent blocks. One fixture is in raw stalker_trace.js grammar, the
other wrapped by run_probe.py, so the parser's tolerance is under test too.
"""
import json

import pytest

from conftest import load_script, run_script

td = load_script("trace_diff.py")

DISP = {"D": 0x1000, "R1": 0x2000, "R2": 0x3000, "R3": 0x4000,
        "R4": 0x5000, "R5": 0x6000, "R7": 0x8000}


def stalker_log(seq, wrap=False):
    """Render a synthetic stalker log from a block sequence."""
    lines = []
    for i, k in enumerate(seq.split()):
        body = "BLK %d liba.so+0x%x" % (i, DISP[k])
        lines.append(("[123.4] [56.7] TRACE %s" % body) if wrap else body)
    lines.append("DONE reason=stop-rpc blocks=8 blk=8 calls=0 truncated=0")
    return "\n".join(lines) + "\n"


RUN_A = "D R1 D R2 D R5 D R7"    # wrong password: rejects after two extra blocks
RUN_B = "D R1 D R2 D R3 D R4"    # right password: accepts


@pytest.fixture
def pair(tmp_path):
    """Two synthetic trace logs: unwrapped and run_probe-wrapped."""
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text(stalker_log(RUN_A), encoding="utf-8")
    b.write_text(stalker_log(RUN_B, wrap=True), encoding="utf-8")
    return a, b


class TestParsers:
    def test_stalker_unwrapped_and_wrapped(self, pair):
        """Stalker unwrapped and wrapped."""
        a, b = pair
        blocks = td.read_blocks(str(a))
        assert blocks == ["liba.so+0x%x" % DISP[k] for k in RUN_A.split()]

    def test_wrapped_log_parses_identically(self, pair):
        """Wrapped log parses identically."""
        a, b = pair
        assert td.parse_line_stalker("[h] [d] TRACE BLK 7 liba.so+0x8000") == "liba.so+0x8000"

    def test_plain_format_keeps_module_keys_and_hex(self, tmp_path):
        """Plain format keeps module keys and hex."""
        p = tmp_path / "plain.log"
        p.write_text("0x7f0000001000\n7f0000002000 x\nlibb.so+0x9f6c0\nnoise line\n",
                     encoding="utf-8")
        blocks = td.read_blocks(str(p), "plain")
        # keys are kept verbatim (lowercased), so 0x-less and 0x-full forms stay distinct
        assert blocks == ["0x7f0000001000", "7f0000002000", "libb.so+0x9f6c0"]

    def test_plain_format_refuses_ambiguous_decimal_tokens(self, tmp_path):
        """Bare runs under 8 hex digits are PIDs, counts and timestamp
        fragments; an all-digit 8+ run is indistinguishable from a date --
        taking either as a block key adds noise, and a log with no real
        addresses must stay refused (an empty trace is a capture failure,
        not a result)."""
        p = tmp_path / "pids.log"
        p.write_text("app 1234 567\nsample count 99\ndead\n", encoding="utf-8")
        with pytest.raises(td.TraceError, match="capture"):
            td.read_blocks(str(p), "plain")
        d = tmp_path / "date.log"
        d.write_text("20261015\n", encoding="utf-8")
        with pytest.raises(td.TraceError, match="capture"):
            td.read_blocks(str(d), "plain")
        p2 = tmp_path / "mixed.log"
        p2.write_text("app 1234\n7f0000002000 x\n", encoding="utf-8")
        assert td.read_blocks(str(p2), "plain") == ["7f0000002000"]

    def test_empty_log_is_a_capture_failure_not_a_result(self, tmp_path):
        """Empty log is a capture failure not a result."""
        p = tmp_path / "empty.log"
        p.write_text("READY ...\nDONE reason=timeout blocks=0 blk=0 calls=0\n",
                     encoding="utf-8")
        with pytest.raises(td.TraceError, match="capture"):
            td.read_blocks(str(p))

    def test_auto_detection_prefers_stalker_then_plain(self, tmp_path):
        """Auto detection prefers stalker then plain."""
        p = tmp_path / "mixed.log"
        p.write_text("BLK 1 liba.so+0x1000\n0x7f0000002000\n", encoding="utf-8")
        assert td.read_blocks(str(p)) == ["liba.so+0x1000", "0x7f0000002000"]


class TestReduce:
    def test_histogram_names_the_dispatcher(self, pair):
        """Histogram names the dispatcher."""
        a, _ = pair
        rep = td.reduce_trace(td.read_blocks(str(a)))
        assert rep["events"] == 8
        assert rep["top"][0] == ("liba.so+0x1000", 4)   # D: the wide-margin top
        assert rep["runs"] == 8

    def test_run_length_collapses_repeats(self):
        """Run length collapses repeats."""
        assert td.run_length(["D", "D", "D", "R1", "R1"]) == \
            [("D", 3), ("R1", 2)]


class TestDiff:
    def test_first_divergence_after_the_shared_prefix(self, pair):
        """First divergence after the shared prefix."""
        a, b = pair
        d = td.diff_traces(td.read_blocks(str(a)), td.read_blocks(str(b)))
        fd = d["first_divergence"]
        assert fd is not None
        # shared prefix D R1 D R2 = 5 events on both sides
        assert fd["event_index_a"] == 5 and fd["event_index_b"] == 5
        assert fd["last_common_block"] == "liba.so+0x1000"   # the dispatcher
        # shared span = prefix D,R1,D,R2,D (5 runs) + trailing D (1) = 6 runs
        assert d["identical_run_span"] == 6

    def test_unique_sets_are_the_input_dependent_blocks(self, pair):
        """Unique sets are the input dependent blocks."""
        a, b = pair
        d = td.diff_traces(td.read_blocks(str(a)), td.read_blocks(str(b)))
        only_a = {k for k, _ in d["unique_to_a"]}
        only_b = {k for k, _ in d["unique_to_b"]}
        assert only_a == {"liba.so+0x6000", "liba.so+0x8000"}   # R5, R7
        assert only_b == {"liba.so+0x4000", "liba.so+0x5000"}   # R3, R4

    def test_identical_traces_report_no_divergence(self, pair):
        """Identical traces report no divergence."""
        a, _ = pair
        blocks = td.read_blocks(str(a))
        d = td.diff_traces(blocks, blocks)
        assert d["first_divergence"] is None
        assert d["divergent_regions"] == 0
        assert "NO DIVERGENCE" in td.render_diff(d)

    def test_render_names_every_part(self, pair):
        """Render names every part."""
        a, b = pair
        d = td.diff_traces(td.read_blocks(str(a)), td.read_blocks(str(b)))
        text = td.render_diff(d, top=5)
        for marker in ("first divergence", "region 1", "unique to A", "unique to B"):
            assert marker in text


class TestCli:
    def test_reduce_cli(self, pair):
        """Reduce cli."""
        a, _ = pair
        r = run_script("trace_diff.py", ["reduce", "--log", str(a), "--top", "3"])
        assert r.returncode == 0 and "RESULT=ok" in r.output
        assert "liba.so+0x1000" in r.output

    def test_diff_cli_json(self, pair):
        """Diff cli json."""
        a, b = pair
        r = run_script("trace_diff.py", ["diff", "--a", str(a), "--b", str(b), "--json"])
        assert r.returncode == 0, r.output
        doc = json.loads(r.stdout)   # --json stdout is one pure document
        assert doc["status"] == "ok"
        assert doc["first_divergence"]["event_index_a"] == 5
        assert {k for k, _ in doc["unique_to_b"]} == \
            {"liba.so+0x4000", "liba.so+0x5000"}

    def test_missing_file_is_usage_error(self):
        """Missing file is usage error."""
        r = run_script("trace_diff.py", ["diff", "--a", "nope.log", "--b", "nada.log"])
        assert r.returncode == 2

    def test_empty_file_refused_with_the_lesson(self, tmp_path):
        """Empty file refused with the lesson."""
        p = tmp_path / "e.log"
        p.write_text("DONE reason=timeout blocks=0 blk=0\n", encoding="utf-8")
        r = run_script("trace_diff.py", ["reduce", "--log", str(p)])
        assert r.returncode == 2
        assert "capture failure" in r.output or "zero-event" in r.output
