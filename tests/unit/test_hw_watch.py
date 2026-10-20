"""Unit tests for hw_watch.py: encoders, refusals, emit, hit decoding.

What is asserted here is the **host-measured half** of the watchpoint route: the
WCR/BCR bit encodings against the ARM DDI 0487 field map, the alignment rules
that refuse impossible specs locally instead of on the device, the emitted
helper's shape, and the hit-log decoder. Device behaviour (seize/arm/trap) is
deliberately not simulated -- see docs/tool-verification/EXTENSION-hw-watchpoints.md.
"""
import json
import shutil
import subprocess

import pytest

from conftest import load_script, run_script

hw = load_script("hw_watch.py")


# ---------------------------------------------------------------------------
# encoders -- the two canonical values plus the variations
# ---------------------------------------------------------------------------
class TestWatchEncoders:
    def test_canonical_8byte_rw(self):
        # BAS=0xff, LSC=both(0b11), PAC=EL0(0b10), E=1
        """Canonical 8byte rw."""
        assert hw.encode_watch(0x7b2000000000, 8, "rw") == (0x7b2000000000, 0x1FFD)

    def test_load_only_and_store_only(self):
        """Load only and store only."""
        wvr, wcr_r = hw.encode_watch(0x1000, 8, "r")
        wvr, wcr_w = hw.encode_watch(0x1000, 8, "w")
        assert wcr_r == 0x1FED   # LSC=01 (load)
        assert wcr_w == 0x1FF5   # LSC=10 (store)

    def test_unaligned_start_shifts_bas(self):
        # bytes 4..7 of the window: BAS = 0xf0 << 5 = 0x1E00
        """Unaligned start shifts bas."""
        wvr, wcr = hw.encode_watch(0x1004, 4, "w")
        assert wvr == 0x1000     # WVR canonicalised to the aligned window
        assert wcr & 0x1FE0 == 0x1E00
        assert wcr == 0x1E15     # | store | PAC | E

    def test_len_1_at_offset_7(self):
        """Len 1 at offset 7."""
        wvr, wcr = hw.encode_watch(0x1007, 1, "rw")
        assert wcr & 0x1FE0 == (0x80 << 5)

    def test_window_crossing_refused(self):
        """Window crossing refused."""
        with pytest.raises(hw.PlanError, match="crosses"):
            hw.encode_watch(0x1006, 8, "rw")
        with pytest.raises(hw.PlanError, match="crosses"):
            hw.encode_watch(0x1004, 8, "r")

    def test_length_bounds(self):
        """Length bounds."""
        with pytest.raises(hw.PlanError):
            hw.encode_watch(0x1000, 0, "rw")
        with pytest.raises(hw.PlanError):
            hw.encode_watch(0x1000, 9, "rw")

    def test_access_vocabulary(self):
        """Access vocabulary."""
        with pytest.raises(hw.PlanError):
            hw.encode_watch(0x1000, 8, "x")


class TestBreakEncoders:
    def test_canonical_address_match(self):
        # BAS all-ones (0x3F << 8), PMC=EL0 (0b10 << 1), BT=0, E=1
        """Canonical address match."""
        assert hw.encode_break(0x7b20001234c0) == (0x7b20001234c0, 0x3F05)

    def test_misaligned_pc_refused(self):
        """Misaligned pc refused."""
        with pytest.raises(hw.PlanError, match="4-byte aligned"):
            hw.encode_break(0x1002)
        with pytest.raises(hw.PlanError):
            hw.encode_break(0x1001)


def test_kernel_abi_constants_are_the_uapi_values():
    """Pinned because a drifted constant compiles fine and arms nothing."""
    assert hw.PTRACE_GETREGSET == 0x4204
    assert hw.PTRACE_SETREGSET == 0x4205
    assert hw.PTRACE_SEIZE == 0x4206
    assert hw.NT_ARM_HW_BREAK == 0x402
    assert hw.NT_ARM_HW_WATCH == 0x403
    assert hw.TRAP_HWBKPT == 4
    assert hw.USER_PT_REGS_BYTES == 272
    assert hw.REG_OFFSETS["pc"] == 256 and hw.REG_OFFSETS["sp"] == 248


# ---------------------------------------------------------------------------
# emit -- the helper's shape and buildability
# ---------------------------------------------------------------------------
def test_emit_writes_helper_and_readme(tmp_path):
    """Emit writes helper and readme."""
    out = tmp_path / "hww"
    r = run_script("hw_watch.py", ["emit", "--out", str(out)])
    assert r.returncode == 0, r.output
    c = (out / "hwwatch_helper.c").read_text(encoding="utf-8")
    readme = (out / "README.md").read_text(encoding="utf-8")
    # the ABI surface the encoders promised
    for marker in ("NT_ARM_HW_WATCH", "NT_ARM_HW_BREAK", "TRAP_HWBKPT",
                   "PTRACE_SEIZE", "PTRACE_O_TRACECLONE", "PTRACE_SINGLESTEP",
                   "PTRACE_LISTEN", "0x3Fu << 8"):
        assert marker in c, marker
    # the honesty devices
    assert "TracerPid" in c
    assert "TEMPLATE" in c
    assert "aarch64-linux-android24-clang" in readme


def test_emitted_helper_compiles_when_a_cross_toolchain_exists(tmp_path):
    """When gcc targets aarch64 here (it does on this CI image), the emitted
    helper must build as a static ELF. Skipped where no compiler is present:
    the compile is evidence, not a portability promise."""
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on this host")
    probe = subprocess.run([cc, "-dumpmachine"], capture_output=True, text=True)
    if "aarch64" not in (probe.stdout or ""):
        pytest.skip("host gcc does not target aarch64 (%r)" % probe.stdout.strip())
    out = tmp_path / "hww"
    run_script("hw_watch.py", ["emit", "--out", str(out)])
    exe = tmp_path / "hwwatch"
    built = subprocess.run([cc, "-static", "-O2", "-o", str(exe),
                            str(out / "hwwatch_helper.c")],
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    assert exe.stat().st_size > 10000


# ---------------------------------------------------------------------------
# decode -- hits in, module+offset out
# ---------------------------------------------------------------------------
HIT_LOG = """READY pid=1234 watch_slots=4 break_slots=6
ARM tid=1234 watch=1 break=0
ARM tid=1240 watch=1 break=0
HIT tid=1240 kind=watch pc=0x7b20001234c0 addr=0x7b2000feedd0 sp=0x7fc000123000 lr=0x7b2000120000 x0=0x1 x1=0x2 x2=0x3 x3=0x4 x4=0x5 x5=0x6 x6=0x7 x7=0x8
ARMFAIL tid=1250 slot=watch1 capacity=0
HIT tid=1234 kind=break pc=0x7b2000129000 addr=0x7b2000129000 sp=0x7fc000124000 lr=0x0 x0=0x0 x1=0x0 x2=0x0 x3=0x0 x4=0x0 x5=0x0 x6=0x0 x7=0x0
DONE hits=2 reason=seconds
"""

MAPS = """7b2000000000-7b2000200000 r--p 00000000 fd:01 100  /data/app/liba.so
7b2000200000-7b2000400000 r-xp 00200000 fd:01 100  /data/app/liba.so
7b2000400000-7b2000420000 rw-p 00400000 fd:01 100  /data/app/liba.so
"""


def test_parse_hits_tolerates_interleaved_lines(tmp_path):
    """Parse hits tolerates interleaved lines."""
    log = tmp_path / "hits.log"
    log.write_text(HIT_LOG, encoding="utf-8")
    rows = hw.parse_hits(str(log))
    assert len(rows) == 2
    assert rows[0]["kind"] == "watch" and rows[0]["pc"] == "0x7b20001234c0"
    assert rows[1]["kind"] == "break"


def test_decode_resolves_module_offset(tmp_path):
    """Decode resolves module offset."""
    log = tmp_path / "hits.log"
    log.write_text(HIT_LOG, encoding="utf-8")
    maps = tmp_path / "maps.txt"
    maps.write_text(MAPS, encoding="utf-8")
    r = run_script("hw_watch.py", ["decode", "--hits", str(log), "--maps", str(maps)])
    assert r.returncode == 0, r.output
    assert "+0x1234c0" in r.output            # pc lands in the first r--p range
    assert "unresolved_pc=0" in r.output
    rj = run_script("hw_watch.py", ["decode", "--hits", str(log), "--maps", str(maps),
                                    "--json"])
    doc = json.loads(rj.stdout)               # --json stdout is one pure document
    assert doc["status"] == "ok" and doc["hits"] == 2
    assert doc["rows"][0]["site"].endswith("liba.so+0x1234c0")


def test_decode_offsets_come_from_the_module_base_not_the_mapping(tmp_path):
    """A PC in a library's r-xp mapping (its second mapping) must report the
    offset from the MODULE base -- the number IDA/Ghidra expects -- not from
    that mapping's own start, which resets the offset at each boundary."""
    log = tmp_path / "hits.log"
    log.write_text("HIT tid=1 kind=break pc=0x7b2000212345 addr=0x7b2000212345 "
                   "sp=0x0 lr=0x0 x0=0x0\n", encoding="utf-8")
    maps = tmp_path / "maps.txt"
    maps.write_text(MAPS, encoding="utf-8")
    r = run_script("hw_watch.py", ["decode", "--hits", str(log), "--maps", str(maps)])
    assert r.returncode == 0, r.output
    assert "liba.so+0x212345" in r.output     # not +0x12345 (mapping-relative)


def test_decode_without_maps_leaves_pcs_raw(tmp_path):
    """Decode without maps leaves pcs raw."""
    log = tmp_path / "hits.log"
    log.write_text(HIT_LOG, encoding="utf-8")
    r = run_script("hw_watch.py", ["decode", "--hits", str(log)])
    assert r.returncode == 0
    assert "unresolved" in r.output and "no --maps" in r.output


def test_plan_json_and_refusal_exit_codes():
    """Plan json and refusal exit codes."""
    r = run_script("hw_watch.py", ["plan", "--addr", "0x1000", "--len", "8",
                                   "--access", "rw", "--json"])
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert doc["specs"][0]["cr"] == 0x1FFD
    r = run_script("hw_watch.py", ["plan", "--addr", "0x1004", "--len", "8"])
    assert r.returncode == 2
    assert "crosses" in r.output


# ---------------------------------------------------------------------------
# the emitted helper: kernel-ABI regressions pinned in the C source
# ---------------------------------------------------------------------------
def emitted_helper(tmp_path):
    """Emit the on-device helper; return its C source."""
    out = tmp_path / "hww"
    run_script("hw_watch.py", ["emit", "--out", str(out)])
    return (out / "hwwatch_helper.c").read_text(encoding="utf-8")


def test_helper_slot_layout_matches_the_kernel_abi(tmp_path):
    """user_hwdebug_state carries the 64-bit address register FIRST and the
    32-bit control register SECOND (arch/arm64 uapi); swapping them arms
    every slot with the ctrl bits as the address."""
    c = emitted_helper(tmp_path)
    assert "struct hwslot { uint64_t wvr; uint32_t wcr; uint32_t pad; };" in c


def test_helper_error_paths_release_seized_threads(tmp_path):
    """PTRACE_O_EXITKILL turns an exit-without-detach into a SIGKILL of the
    target: every post-seize failure must route through release_all()."""
    c = emitted_helper(tmp_path)
    assert "static void release_all(void)" in c
    # capacity probe failure and arming failure both detach instead of return
    assert c.count("release_all();") >= 3      # cap fail, arm fail, clean exit
    # partial seize failure detaches the threads seized so far
    assert "EXITKILLed when we exit" in c


def test_helper_forwards_genuine_sigtrap(tmp_path):
    """Only our TRAP_HWBKPT hits and ptrace event stops are consumed; a
    target-generated SIGTRAP (raise/tgkill/int3) must be forwarded or the
    app's handler never runs."""
    c = emitted_helper(tmp_path)
    assert "if (event != 0) {" in c                    # event stops: consumed
    assert "genuine" in c and "pt(PTRACE_CONT, tid, 0, sig);" in c
