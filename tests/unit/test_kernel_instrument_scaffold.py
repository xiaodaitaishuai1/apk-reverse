"""Unit tests for kernel_instrument_scaffold.py: spec validation, generate,
verify, and the honesty devices (the unverified banner, the carrier that
cannot arm anything, the experimental action fence)."""
import json

import pytest

from conftest import load_script, run_script

ks = load_script("kernel_instrument_scaffold.py")


class TestSpecValidation:
    def test_watch_spec_roundtrip(self):
        """Watch spec roundtrip."""
        row = ks.parse_spec_watch("w:0x7b2000123450:8:w")
        assert row == {"addr": "0x7b2000123450", "len": 8, "access": "w"}

    def test_window_rule_shared_with_hw_watch(self):
        """Window rule shared with hw watch."""
        with pytest.raises(ValueError, match="crosses"):
            ks.parse_spec_watch("w:0x7b2000123456:8:w")

    def test_break_alignment(self):
        """Break alignment."""
        assert ks.parse_spec_break("b:0x1234c0")["pc"] == "0x1234c0"
        with pytest.raises(ValueError, match="4-byte aligned"):
            ks.parse_spec_break("b:0x1234c2")

    def test_set_reg_shape(self):
        """Set reg shape."""
        row = ks.parse_spec_break("b:0x1234c0", set_reg="x0=0x1")
        assert row["set_reg"] == "x0" and row["set_value"] == "0x1"
        with pytest.raises(ValueError):
            ks.parse_spec_break("b:0x1234c0", set_reg="x0")

    def test_set_reg_rejects_registers_the_template_cannot_write(self):
        """x31 is sp's slot in user_pt_regs and the array ends at x30: an
        index past 30 writes sp/pc/pstate or off the frame."""
        for bad in ("x31=0x1", "x99=0x1", "ax5=0x1", "x0", "y0=0x1"):
            with pytest.raises(ValueError):
                ks.parse_spec_break("b:0x1234c0", set_reg=bad)
        for good in ("x0=0x1", "x30=0x2", "x30=5"):
            ks.parse_spec_break("b:0x1234c0", set_reg=good)


def generate(tmp_path, extra=()):
    """Generate the standard scaffold; return its output directory."""
    out = tmp_path / "kwatch"
    argv = ["generate", "--out", str(out), "--pid", "12345",
            "--watch", "w:0x7b2000123450:8:w", "--break", "b:0x7b20001234c0",
            "--set-reg", "x0=0x1"] + list(extra)
    r = run_script("kernel_instrument_scaffold.py", argv)
    assert r.returncode == 0, r.output
    return out


class TestGenerate:
    def test_layout_and_config(self, tmp_path):
        """Layout and config."""
        out = generate(tmp_path)
        expected = ["config/instrument.json", "kpm/src/kwatch.c", "kpm/Makefile",
                    "lkm/kwatch.c", "lkm/Makefile", "module.prop", "README.md",
                    "post-fs-data.sh"]
        for rel in expected:
            assert (out / rel).is_file(), rel
        cfg = json.loads((out / "config" / "instrument.json").read_text(encoding="utf-8"))
        assert cfg["pid"] == 12345
        assert cfg["watches"][0]["addr"] == "0x7b2000123450"
        assert cfg["breaks"][0]["set_reg"] == "x0"

    def test_kernel_files_carry_the_banner_and_the_kpm_lessons(self, tmp_path):
        """Kernel files carry the banner and the kpm lessons."""
        out = generate(tmp_path)
        kpm = (out / "kpm" / "src" / "kwatch.c").read_text(encoding="utf-8")
        lkm = (out / "lkm" / "kwatch.c").read_text(encoding="utf-8")
        for body in (kpm, lkm):
            assert "NOT COMPILED AND NOT LOADED" in body
            assert "EXPERIMENTAL" in body            # the set-reg fence
        assert "kfunc_def" in kpm
        # the banner text mentions the generator, so a stripped banner is traceable
        assert "kernel_instrument_scaffold.py" in kpm
        # the user-task breakpoint API: four arguments, task last (the per-cpu
        # register_wide_* family cannot arm on one target task)
        assert "register_user_hw_breakpoint" in lkm
        assert "&attr, wp_hit, NULL, task)" in lkm
        # the task pointer is pinned past the RCU section and released after
        # registration: registration can sleep, an unpinned task can be freed
        assert "get_task_struct(task)" in lkm and "put_task_struct(task)" in lkm
        # the execution breakpoint row initializes fields wp_cfg declares
        # (.addr/.len/.bp_type) -- there is no .pc member to initialize
        for body in (kpm, lkm):
            assert ".pc = " not in body
        assert ".addr = 0x7b20001234c0, .len = 8, .bp_type = 4" in kpm

    def test_breakpoint_rows_initialize_declared_fields(self, tmp_path):
        """Breakpoint rows initialize declared fields."""
        out = generate(tmp_path)
        for body in ((out / "kpm" / "src" / "kwatch.c").read_text(encoding="utf-8"),
                     (out / "lkm" / "kwatch.c").read_text(encoding="utf-8")):
            assert ".pc = " not in body                     # no such member
            assert ".addr = 0x7b20001234c0, .len = 8, .bp_type = 4" in body

    def test_events_carry_a_sampling_period(self, tmp_path):
        """A zero sample_period is a non-sampling event: perf arms it, the
        overflow callback (wp_hit) never runs, and the module reports armed
        events that stay silent forever."""
        out = generate(tmp_path)
        kpm = (out / "kpm" / "src" / "kwatch.c").read_text(encoding="utf-8")
        lkm = (out / "lkm" / "kwatch.c").read_text(encoding="utf-8")
        assert "attr.sample_period = 1;" in kpm       # hw_breakpoint_init, spelled out
        assert "hw_breakpoint_init(&attr);" in lkm

    def test_set_reg_rewrite_is_gated_to_its_breakpoint_event(self, tmp_path):
        """wp_hit fires for every registered event (watch and break alike), so
        the rewrite must check it landed on its own breakpoint."""
        out = generate(tmp_path)
        for body in ((out / "kpm" / "src" / "kwatch.c").read_text(encoding="utf-8"),
                     (out / "lkm" / "kwatch.c").read_text(encoding="utf-8")):
            assert "event->attr.bp_addr == 0x7b20001234c0" in body
            assert body.count("regs->regs[0] = 0x1;") == 1
            # the write sits inside the guard, not at callback top level
            guarded = body.split("regs->regs[0] = 0x1;")[0]
            assert "event->attr.bp_type & 4" in guarded

    def test_id_is_restricted_to_a_module_identifier(self, tmp_path):
        """--id becomes paths, Makefile targets and module.prop entries: a
        path separator or leading dot would write outside --out."""
        for bad in ("../evil", "a/b", ".hidden", "", "a b"):
            argv = ["generate", "--out", str(tmp_path / "x"), "--pid", "1",
                    "--watch", "w:0x1000:8:w", "--id", bad]
            r = run_script("kernel_instrument_scaffold.py", argv)
            assert r.returncode == 2, bad
        argv = ["generate", "--out", str(tmp_path / "ok"), "--pid", "1",
                "--watch", "w:0x1000:8:w", "--id", "kwatch.v2-x"]
        r = run_script("kernel_instrument_scaffold.py", argv)
        assert r.returncode == 0, r.output

    def test_carrier_says_what_it_cannot_do(self, tmp_path):
        """Carrier says what it cannot do."""
        out = generate(tmp_path)
        readme = (out / "README.md").read_text(encoding="utf-8")
        assert "cannot arm a watchpoint" in readme

    def test_no_specs_is_refused(self, tmp_path):
        """No specs is refused."""
        r = run_script("kernel_instrument_scaffold.py",
                       ["generate", "--out", str(tmp_path / "x"), "--pid", "1"])
        assert r.returncode == 2


class TestVerify:
    def test_clean_generation_verifies(self, tmp_path):
        """Clean generation verifies."""
        out = generate(tmp_path)
        r = run_script("kernel_instrument_scaffold.py", ["verify", "--dir", str(out)])
        assert r.returncode == 0, r.output
        assert "RESULT=ok" in r.output

    def test_stripped_banner_is_a_problem(self, tmp_path):
        """Stripped banner is a problem."""
        out = generate(tmp_path)
        target = out / "kpm" / "src" / "kwatch.c"
        body = target.read_text(encoding="utf-8").replace(
            "NOT COMPILED AND NOT LOADED", "COMPILED SOMEWHERE, TRUST ME")
        target.write_text(body, encoding="utf-8")
        r = run_script("kernel_instrument_scaffold.py", ["verify", "--dir", str(out)])
        assert r.returncode == 1
        assert "banner" in r.output

    def test_missing_config_is_a_problem(self, tmp_path):
        """Missing config is a problem."""
        out = generate(tmp_path)
        (out / "config" / "instrument.json").unlink()
        r = run_script("kernel_instrument_scaffold.py", ["verify", "--dir", str(out)])
        assert r.returncode == 1
        assert "missing" in r.output


class TestGates:
    def test_gate_table_includes_the_perf_breakpoint_layer(self):
        """Gate table includes the perf breakpoint layer."""
        routes = {g["route"] for g in ks.GATES}
        assert "perf hw-breakpoint slots" in routes
        assert "KernelPatch / APatch KPM" in routes
        r = run_script("kernel_instrument_scaffold.py", ["gates", "--json"])
        assert r.returncode == 0
        doc = json.loads(r.stdout)   # --json stdout is one pure document
        assert doc["status"] == "ok" and len(doc["gates"]) == len(ks.GATES)
