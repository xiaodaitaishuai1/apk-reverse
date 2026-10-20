"""Unit tests for trace_addr2sym.py: the zero-dependency ELF64 walker, both offset
spaces, and the input adapters.

Two evidence layers, matching docs/tool-verification/EXTENSION-sampling-crash.md:
a hand-built minimal ELF (always runs, covers vaddr!=offset and the stripped
fallback) and a real cross-compiled aarch64 .so (runs where the toolchain exists,
cross-checked against readelf).
"""
import json
import shutil
import struct
import subprocess

import pytest

from conftest import load_script, run_script

tas = load_script("trace_addr2sym.py")


# ---------------------------------------------------------------------------
# a hand-built minimal ELF64: one PT_LOAD with vaddr != offset, one dynsym
# ---------------------------------------------------------------------------
def build_minimal_elf(path, vaddr_delta=0x1000, with_gap=False):
    """Two-symbol dynsym; one PT_LOAD, or two with an unmapped gap.

    Symbols: sym_a @ 0x2000 (size 0x100), sym_b @ 0x2400 (size 0x10).
    The load segment maps file [0x0,0x4000) at vaddr 0x1000..0x5000, so
    file offset F <-> vaddr F + vaddr_delta for the segment, while the symbols
    live at vaddr 0x2000/0x2400 regardless (they sit inside the segment).

    with_gap=True shrinks segment 1 to vaddr 0x1000..0x3000 and adds a second
    PT_LOAD at vaddr 0x4000..0x5000: the span [0x3000,0x4000) is loaded by
    NEITHER segment, the shape real shared objects have between PT_LOADs.
    """
    assert vaddr_delta == 0x1000
    data = bytearray(b"\x00" * 0x4000)
    # ELF header
    data[0:4] = b"\x7fELF"
    struct.pack_into("<B", data, 4, 2)      # ELFCLASS64
    struct.pack_into("<B", data, 5, 1)      # little-endian
    struct.pack_into("<H", data, 16, 3)     # e_type = ET_DYN
    struct.pack_into("<H", data, 18, 0xB7)  # e_machine = AArch64
    e_phoff, e_shoff = 0x40, 0x3000
    struct.pack_into("<Q", data, 0x20, e_phoff)
    struct.pack_into("<Q", data, 0x28, e_shoff)
    struct.pack_into("<H", data, 0x36, 56)  # e_phentsize
    struct.pack_into("<H", data, 0x38, 1)   # e_phnum
    struct.pack_into("<H", data, 0x3A, 64)  # e_shentsize
    struct.pack_into("<H", data, 0x3C, 3)   # e_shnum: null, dynsym, dynstr
    struct.pack_into("<H", data, 0x3E, 2)   # e_shstrndx (unused: names empty)
    if with_gap:
        struct.pack_into("<H", data, 0x38, 2)   # e_phnum: two PT_LOADs
        struct.pack_into("<IIQQQQQQ", data, e_phoff,
                         1, 5, 0, 0x1000, 0, 0x2000, 0x2000, 0x1000)
        struct.pack_into("<IIQQQQQQ", data, e_phoff + 56,
                         1, 5, 0x2500, 0x4000, 0, 0x1000, 0x1000, 0x1000)
    else:
        # PT_LOAD file[0,0x4000) @ vaddr 0x1000 (8 fields, Elf64_Phdr:
        # p_paddr included -- a 7-field pack silently shifts p_memsz onto p_align)
        struct.pack_into("<IIQQQQQQ", data, e_phoff,
                         1, 5, 0, 0x1000, 0, 0x4000, 0x4000, 0x1000)
    # dynstr @ 0x200, dynsym @ 0x400
    strtab = b"\x00sym_a\x00sym_b\x00"
    data[0x200:0x200 + len(strtab)] = strtab
    # Elf64_Sym is 24B: st_name, st_info, st_other/shndx, st_value, st_size

    def sym(name_off, info, value, size):
        """Sym."""
        return struct.pack("<IBBHQQ", name_off, info, 0, 1, value, size)

    syms = sym(1, (1 << 4) | 2, 0x2000, 0x100) + sym(7, (1 << 4) | 2, 0x2400, 0x10)
    data[0x400:0x400 + len(syms)] = syms
    # section headers @ 0x3000: null, dynsym(link=dynstr idx 2), dynstr

    def shdr(sh_type, sh_offset, sh_size, sh_link=0, sh_entsize=24):
        """Shdr."""
        return struct.pack("<IIQQQQIIQQ", 0, sh_type, 0, 0, sh_offset, sh_size,
                           sh_link, 0, 0, sh_entsize)

    sh = (shdr(0, 0, 0)
          + shdr(11, 0x400, len(syms), sh_link=2)
          + shdr(3, 0x200, len(strtab), 0, 0))
    data[e_shoff:e_shoff + len(sh)] = sh
    with open(path, "wb") as fh:
        fh.write(bytes(data))


def test_minimal_elf_roundtrip(tmp_path):
    """Minimal elf roundtrip."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    elf = tas.Elf64(str(p))
    assert [s["name"] for s in elf.symbols] == ["sym_a", "sym_b"]
    # vaddr -> file: the segment adds 0x1000 going file->vaddr
    assert elf.vaddr_to_file(0x2000) == 0x1000          # 0x2000 - 0x1000
    assert elf.file_to_vaddr(0x1000) == 0x2000
    sym, off = elf.resolve(0x2042)
    assert (sym, off) == ("sym_a", 0x42)
    sym, off = elf.resolve(0x2405)
    assert (sym, off) == ("sym_b", 5)
    # past every symbol but still inside the load segment: nearest-below
    # fallback (addr2line-style, gaps included) -- a PC OUTSIDE the segment is
    # refused by describe(), not folded onto the last symbol (see below)
    sym, off = elf.resolve(0x3f00)
    assert (sym, off) == ("sym_b", 0x1b00)
    # the span gate: a PC from another module must not be attributed here
    assert elf.contains_vaddr(0x3f00) and not elf.contains_vaddr(0xdead0000)
    assert "outside-elf" in tas.describe(elf, 0xdead0000)


def test_offs_are_file_flag_and_vaddr_space(tmp_path):
    """file offset input and vaddr input must not be conflated."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    r1 = run_script("trace_addr2sym.py", ["--elf", str(p), "--offs", "0x2042"])
    assert r1.returncode == 0 and "sym_a+0x42" in r1.output
    r2 = run_script("trace_addr2sym.py", ["--elf", str(p), "--offs", "0x2042",
                                          "--offs-are-file"])
    assert r2.returncode == 0
    # file 0x2042 -> vaddr 0x3042: past sym_a's 0x100-size, nearest-below is sym_b
    assert "sym_b+0xc42" in r2.output


def test_absolute_addrs_need_a_base(tmp_path):
    """Absolute addrs need a base."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    r = run_script("trace_addr2sym.py", ["--elf", str(p), "--addrs", "0x7b2000002042"])
    assert r.returncode == 2
    assert "load base" in r.output       # ASLR: refuse rather than guess
    r = run_script("trace_addr2sym.py", ["--elf", str(p), "--addrs", "0x7b2000002042",
                                         "--base", "0x7b2000000000"])
    assert r.returncode == 0 and "sym_a+0x42" in r.output


# ---------------------------------------------------------------------------
# real cross-compiled library (skipped where no aarch64 gcc exists)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def real_so(tmp_path_factory):
    """Real so."""
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on this host")
    probe = subprocess.run([cc, "-dumpmachine"], capture_output=True, text=True)
    if "aarch64" not in (probe.stdout or ""):
        pytest.skip("host gcc does not target aarch64 (%r)" % probe.stdout.strip())
    d = tmp_path_factory.mktemp("so")
    src = d / "tlib.c"
    src.write_text("int encrypt_block(unsigned char *b,int n){for(int i=0;i<n;i++)"
                   "b[i]^=0x5A;return n;}\n"
                   "int decrypt_block(unsigned char *b,int n){return encrypt_block(b,n);}\n",
                   encoding="utf-8")
    so = d / "libtlib.so"
    built = subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", str(so), str(src)],
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    return so


def test_real_so_symbols_agree_with_readelf(real_so):
    """Real so symbols agree with readelf."""
    syms = subprocess.run(["readelf", "--syms", "-W", str(real_so)],
                          capture_output=True, text=True).stdout
    addr = None
    for line in syms.splitlines():
        parts = line.split()
        if len(parts) > 7 and parts[7] == "encrypt_block" and parts[3] == "FUNC":
            addr = int(parts[1], 16)
            break
    assert addr is not None
    r = run_script("trace_addr2sym.py", ["--elf", str(real_so), "--offs",
                                         "0x%x" % (addr + 0x30), "--json"])
    assert r.returncode == 0
    doc = json.loads(r.stdout)   # --json stdout is a pure JSON document
    assert doc["resolved"][0]["where"].startswith("encrypt_block+0x30")


def test_real_so_stripped_fallback(real_so, tmp_path):
    """Real so stripped fallback."""
    stripped = tmp_path / "stripped.so"
    shutil.copy(real_so, stripped)
    if shutil.which("strip"):
        subprocess.run(["strip", str(stripped)], capture_output=True)
    r = run_script("trace_addr2sym.py", ["--elf", str(stripped), "--offs", "0x610"])
    assert r.returncode == 0
    assert ".text+" in r.output           # section+offset fallback, no crash


def test_hits_and_trace_adapters(tmp_path):
    """Hits and trace adapters."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    hits = tmp_path / "hits.log"
    hits.write_text("HIT tid=1 kind=watch pc=0x7b2000002042 addr=0x7b200000feedd0 "
                    "sp=0x0 lr=0x0 x0=0x0 x1=0x0 x2=0x0 x3=0x0 x4=0x0 x5=0x0 x6=0x0 x7=0x0\n",
                    encoding="utf-8")
    maps = tmp_path / "maps.txt"
    # physically correct for this ELF: the segment (p_offset 0, p_vaddr 0x1000)
    # is mapped at 0x7b2000001000, so the load bias is 0x7b2000001000 - 0x1000
    maps.write_text("7b2000001000-7b2000005000 r--p 00000000 fd:01 1  "
                    "/data/app/min.so\n", encoding="utf-8")
    r = run_script("trace_addr2sym.py", ["--hits", str(hits), "--maps", str(maps),
                                         "--elf", str(p)])
    assert r.returncode == 0, r.output
    assert "sym_a+0x42" in r.output
    # a neighbour whose name merely CONTAINS the hint must not be matched
    maps.write_text("7b3000001000-7b3000005000 r--p 00000000 fd:01 1  "
                    "/data/app/min.so.v2\n", encoding="utf-8")
    r = run_script("trace_addr2sym.py", ["--hits", str(hits), "--maps", str(maps),
                                         "--elf", str(p)])
    assert r.returncode == 2 and "no load bias" in r.output
    trace = tmp_path / "t.log"
    trace.write_text("BLK 0 min.so+0x2042\nBLK 1 xmin.so+0x2405\n", encoding="utf-8")
    r = run_script("trace_addr2sym.py", ["--trace", str(trace), "--mod", "min.so",
                                         "--elf", str(p)])
    assert r.returncode == 0
    assert "sym_a+0x42" in r.output and "sym_b+0x5" not in r.output


def test_load_bias_subtracts_segment_vaddr(tmp_path):
    """p_vaddr != 0: the bias is map_start - (foff - p_offset) - p_vaddr,
    not the mapping start."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    elf = tas.Elf64(str(p))
    maps = tmp_path / "maps.txt"
    maps.write_text("7b2000001000-7b2000005000 r--p 00000000 fd:01 1  /data/app/min.so\n",
                    encoding="utf-8")
    assert tas.load_bias_from_maps(str(maps), "min.so", elf) == 0x7b2000000000
    # full-path hint matches too; a mere-substring neighbour does not
    maps.write_text("7b2000001000-7b2000005000 r--p 00000000 fd:01 1  /data/app/min.so\n"
                    "7b3000000000-7b3000004000 r--p 00000000 fd:01 1  /data/app/min.so.v2\n",
                    encoding="utf-8")
    assert tas.load_bias_from_maps(str(maps), "min.so", elf) == 0x7b2000000000
    assert tas.load_bias_from_maps(str(maps), "/data/app/min.so", elf) == 0x7b2000000000


def test_pcs_in_the_gap_between_segments_are_refused(tmp_path):
    """Real shared objects leave unmapped gaps between PT_LOADs: a PC in a
    gap is outside every segment and must be refused, not named after the
    nearest symbol below it."""
    p = tmp_path / "gap.so"
    build_minimal_elf(p, with_gap=True)
    elf = tas.Elf64(str(p))
    assert elf.contains_vaddr(0x2000)            # segment 1
    assert elf.contains_vaddr(0x4500)            # segment 2
    assert not elf.contains_vaddr(0x3800)        # the gap
    assert "outside-elf" in tas.describe(elf, 0x3800)


def test_json_stdout_is_pure(tmp_path):
    """--json mode must be parseable as one document (no trailing RESULT=)."""
    p = tmp_path / "min.so"
    build_minimal_elf(p)
    r = run_script("trace_addr2sym.py", ["--elf", str(p), "--offs", "0x2042", "--json"])
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert doc["status"] == "ok" and "RESULT" not in r.stdout
