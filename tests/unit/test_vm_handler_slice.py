"""Unit tests for vm_handler_slice.py: dispatcher detection, slicing, clustering,
the open tail, and the opcode-map trajectory.

The fixture is a synthetic interpreter trace in the calibrated shape (dispatcher
loop + handler chains + one const-materialization segment + unclosed tail), per
docs/tool-verification/EXTENSION-sampling-crash.md.
"""
import json

import pytest

from conftest import load_script, run_script

vs = load_script("vm_handler_slice.py")

H = {"D": 0x1000, "load": 0x2000, "arith": 0x3000, "store": 0x4000,
     "br": 0x5000, "ret": 0x6000, "mat": 0x7000, "spin": 0x8000}

RUN = "D load D load arith D store D br D load D load arith store D br D mat D load arith D ret"

MAP = {"libvm.so+0x2000": "OP_LOAD", "libvm.so+0x3000": "OP_ARITH",
       "libvm.so+0x4000": "OP_STORE", "libvm.so+0x5000": "OP_BR",
       "libvm.so+0x6000": "OP_RET", "libvm.so+0x7000": "OP_CALL"}


@pytest.fixture
def vm_log(tmp_path):
    """Vm log."""
    p = tmp_path / "vm.log"
    p.write_text("\n".join("BLK %d libvm.so+0x%x" % (i, H[k])
                           for i, k in enumerate(RUN.split())) + "\n",
                 encoding="utf-8")
    return p


class TestPickDispatcher:
    def test_top_plus_predecessor_diversity(self):
        """Top plus predecessor diversity."""
        blocks = ["libvm.so+0x%x" % H[k] for k in RUN.split()]
        assert vs.pick_dispatcher(blocks) == "libvm.so+0x1000"

    def test_hottest_handler_may_tie_with_dispatcher(self):
        """A stack-shaped VM runs OP_LOAD on every guest instruction: D and the
        hottest handler occur equally often, and when that handler is a single
        block the pair is a genuine 2-cycle (each has one predecessor -- the
        other). That is ambiguity, not a dispatcher: refuse and demand an
        explicit --dispatcher."""
        seq = "D load D load D load D load D load D load"
        blocks = ["libvm.so+0x%x" % H[k] for k in seq.split()]
        assert vs.pick_dispatcher(blocks) is None

    def test_tie_with_multiblock_handler_resolves(self):
        """Same tie, but the hot handler is two blocks: its tail block is a
        predecessor of D that the handler's own head never is, and other
        handlers join -- predecessor diversity decides for D."""
        seq = ("D load arith D load arith D load arith "
               "D store D load arith D br D load arith")
        blocks = ["libvm.so+0x%x" % H[k] for k in seq.split()]
        assert vs.pick_dispatcher(blocks) == "libvm.so+0x1000"

    def test_no_loop_refused(self):
        """No loop refused."""
        blocks = ["a.so+0x1", "a.so+0x2", "a.so+0x3"]
        assert vs.pick_dispatcher(blocks) is None

    def test_frequency_margin_cannot_substitute_for_predecessor_diversity(self):
        """A block 3x hotter than the runner-up but entered from one
        predecessor is a plain hot loop, not a dispatch loop: the docstring's
        rule is top + many distinct predecessors, so no frequency fallback
        may rescue it."""
        blocks = ["hot+0x1"] + ["foo+0x2", "hot+0x1"] * 4 + ["bar+0x3", "hot+0x1"]
        assert vs.pick_dispatcher(blocks) is None

    def test_single_entry_histogram_is_accepted(self):
        """Only one distinct block: nothing to be diverse against."""
        assert vs.pick_dispatcher(["a+0x1"] * 8) == "a+0x1"


class TestSlicing:
    def test_segments_preamble_tail(self):
        """Segments preamble tail."""
        blocks = ["libvm.so+0x%x" % H[k] for k in RUN.split()]
        segments, preamble, tail = vs.slice_segments(blocks, "libvm.so+0x1000")
        runs = [r for r, _closed in segments]
        assert runs[0] == ["libvm.so+0x2000"]                       # load
        assert runs[1] == ["libvm.so+0x2000", "libvm.so+0x3000"]    # load arith
        assert ["libvm.so+0x7000"] in runs                          # const materialization
        assert segments[-1] == (["libvm.so+0x6000"], False)         # ret: unclosed
        assert preamble == [] and tail == ["libvm.so+0x6000"]

    def test_preamble_kept_separate(self):
        """Preamble kept separate."""
        blocks = ["entry+0x1", "D", "h+0x2", "D", "h+0x3"]
        segments, preamble, tail = vs.slice_segments(blocks, "D")
        assert preamble == ["entry+0x1"]
        assert [r for r, _ in segments] == [["h+0x2"], ["h+0x3"]]


class TestCluster:
    def test_signatures_and_counts(self):
        """Signatures and counts."""
        blocks = ["libvm.so+0x%x" % H[k] for k in RUN.split()]
        segments, _, _ = vs.slice_segments(blocks, "libvm.so+0x1000")
        trajectory, stats = vs.cluster(segments)
        assert len(trajectory) == len(segments)
        # the load-only segment occurs twice (positions 0 and 4)
        load_sig = vs.signature(["libvm.so+0x2000"])
        assert stats[load_sig]["count"] == 2
        # every trajectory entry is a known signature
        assert set(trajectory) <= set(stats)

    def test_spin_loop_diagnostic(self):
        """Spin loop diagnostic."""
        blocks = ["a+0x1"] * 20
        segments, _, _ = vs.slice_segments(blocks, "a+0x1")
        segments = [(["b+0x2"], True)] * 20 if not segments else segments
        trajectory, stats = vs.cluster(segments)
        diag = vs.diagnostics(blocks, "a+0x1", [r for r, _ in segments], stats)
        assert any("spin" in n for n in diag["notes"])


class TestCli:
    def test_full_run_with_opcode_map(self, vm_log, tmp_path):
        """Full run with opcode map."""
        mp = tmp_path / "map.json"
        mp.write_text(json.dumps(MAP), encoding="utf-8")
        r = run_script("vm_handler_slice.py", ["--log", str(vm_log),
                                               "--opcode-map", str(mp)])
        assert r.returncode == 0, r.output
        assert "dispatcher: libvm.so+0x1000" in r.output
        assert "UNCLOSED" in r.output
        assert "OP_CALL" in r.output                       # const materialization named
        assert r.output.rstrip().endswith("RESULT=ok")

    def test_json_shape(self, vm_log, tmp_path):
        """Json shape."""
        mp = tmp_path / "map.json"
        mp.write_text(json.dumps(MAP), encoding="utf-8")
        r = run_script("vm_handler_slice.py", ["--log", str(vm_log),
                                               "--opcode-map", str(mp), "--json"])
        doc = json.loads(r.stdout)   # --json stdout is one pure document
        assert doc["status"] == "ok"
        assert doc["opcode_trajectory"][-1] == "OP_RET"
        assert all("sig" in s for s in doc["segments"])

    def test_explicit_dispatcher(self, vm_log):
        """Explicit dispatcher."""
        r = run_script("vm_handler_slice.py", ["--log", str(vm_log),
                                               "--dispatcher", "libvm.so+0x1000"])
        assert r.returncode == 0 and "segments: 10 total" in r.output

    def test_non_vm_trace_refused(self, tmp_path):
        """Non vm trace refused."""
        p = tmp_path / "flat.log"
        p.write_text("BLK 0 a+0x1\nBLK 1 a+0x2\nBLK 2 a+0x3\n", encoding="utf-8")
        r = run_script("vm_handler_slice.py", ["--log", str(p)])
        assert r.returncode == 2
        assert "interpreter" in r.output or "dispatcher" in r.output

    def test_unmapped_handler_blocks_reported(self, vm_log, tmp_path):
        """Unmapped handler blocks reported."""
        mp = tmp_path / "map.json"
        mp.write_text(json.dumps({"libvm.so+0x2000": "OP_LOAD"}), encoding="utf-8")
        r = run_script("vm_handler_slice.py", ["--log", str(vm_log),
                                               "--opcode-map", str(mp)])
        assert r.returncode == 0
        assert "unmapped handler blocks" in r.output


class TestNestedLoopDiagnostic:
    """A block repeating inside ONE segment is a second dispatcher under the
    first (a VM entered from VM code) -- the absorbed write-up measured 45-of-46
    entries nested, 57-1997 instructions lost per nesting under a flat slice."""

    def _nested_log(self, tmp_path):
        H = {"D": 0x1000, "h": 0x2000, "i": 0x3000, "j": 0x4000}
        seq = "D h D h D " + " ".join(["i"] * 6 + ["j"] + ["i"] * 6) + " D h D h"
        p = tmp_path / "nested.log"
        p.write_text("\n".join("BLK %d libvm.so+0x%x" % (i, H[k])
                               for i, k in enumerate(seq.split())) + "\n",
                     encoding="utf-8")
        return p

    def test_nested_segment_flagged_with_explicit_outer_dispatcher(self, tmp_path):
        r = run_script("vm_handler_slice.py", ["--log", str(self._nested_log(tmp_path)),
                                               "--dispatcher", "libvm.so+0x1000"])
        assert r.returncode == 0, r.output
        assert "nested dispatch loop" in r.output
        assert "native-vm-recovery.md" in r.output

    def test_short_segments_do_not_trigger(self, vm_log):
        r = run_script("vm_handler_slice.py", ["--log", str(vm_log)])
        assert r.returncode == 0
        assert "nested dispatch loop" not in r.output

    def test_nested_helper_shape(self):
        segs = [(["a"] * 6 + ["b"] + ["a"] * 6, True), (["c"], True)]
        assert vs.nested_loop_segments(segs) == [0]
        assert vs.nested_loop_segments([(["a", "b", "a"], True)]) == []

    def test_diagnostics_accepts_tuple_and_bare_run_segments(self):
        """(run, closed) since the open-tail fix; a bare run still measures."""
        d1 = vs.diagnostics(["D", "a", "D", "a"], "D", [(["a"], True)] * 2, {})
        d2 = vs.diagnostics(["D", "a", "D", "a"], "D", [["a"]] * 2, {})
        assert d1["avg_segment_len"] == d2["avg_segment_len"] == 1.0


class TestSigKeyMaps:
    """Signature-keyed opcode maps: on an instruction stream (or under an outer
    flattening pass) segments share one entry block, so only the signature
    distinguishes handlers. Measured on the SS6 fixture run."""

    def test_sig_key_wins_when_first_blocks_collide(self, tmp_path):
        """Two segments starting at the same block, named via signature keys."""
        run = "D load arith D store D br D ret".split()
        p = tmp_path / "vm2.log"
        p.write_text("\n".join("BLK %d libvm.so+0x%x" % (i, H[k])
                               for i, k in enumerate(run)) + "\n",
                     encoding="utf-8")
        blocks = vs.trace_diff.read_blocks(str(p))
        segs, pre, tail = vs.slice_segments(blocks, "libvm.so+0x1000")
        # both segments start right after D at 0x2000; only one exists per
        # entry -- craft the collision by slicing at the handler block itself:
        # segments then begin at 0x3000 / 0x4000 -- distinct. To force a true
        # collision, slice at a block the segments share:
        run3 = "D arith D arith store D ret".split()
        p3 = tmp_path / "vm3.log"
        p3.write_text("\n".join("BLK %d libvm.so+0x%x" % (i, H[k])
                                for i, k in enumerate(run3)) + "\n",
                      encoding="utf-8")
        b3 = vs.trace_diff.read_blocks(str(p3))
        segs3, _, _ = vs.slice_segments(b3, "libvm.so+0x1000")
        # dispatcher-sliced segments here are [arith] and [arith, store]:
        # different content, and the first segment's run == second's prefix,
        # which is the fixture shape (shared entry prefix).
        assert len(segs3) == 3          # two closed + the open tail
        sig_a, sig_b = (vs.signature(r) for r, _ in segs3[:2])
        assert sig_a != sig_b
        mp = tmp_path / "map.json"
        mp.write_text(json.dumps({sig_a: "ARITH_OR_SHL", sig_b: "ARITH_LATCH"}),
                      encoding="utf-8")
        _traj, stats = vs.cluster(segs3)
        named, unmapped = vs.apply_map([sig_a, sig_b], stats, str(mp))
        assert named == ["ARITH_OR_SHL", "ARITH_LATCH"]
        assert unmapped == []

    def test_first_block_key_still_supported(self, tmp_path):
        """Legacy first-block keys keep working when no signature key matches."""
        run = "D load arith D ret".split()
        p = tmp_path / "vm4.log"
        p.write_text("\n".join("BLK %d libvm.so+0x%x" % (i, H[k])
                               for i, k in enumerate(run)) + "\n",
                     encoding="utf-8")
        blocks = vs.trace_diff.read_blocks(str(p))
        segs, _, _ = vs.slice_segments(blocks, "libvm.so+0x1000")
        _traj, stats = vs.cluster(segs)
        mp = tmp_path / "map4.json"
        mp.write_text(json.dumps({"libvm.so+0x2000": "OP_LOAD"}), encoding="utf-8")
        named, unmapped = vs.apply_map([vs.signature(segs[0][0])], stats, str(mp))
        assert named == ["OP_LOAD"] and unmapped == []
