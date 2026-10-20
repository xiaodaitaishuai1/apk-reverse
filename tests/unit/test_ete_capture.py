"""Unit tests for ete_capture.py: the command construction the review broke.

The capture path needs a device, so what is host-testable is exactly what the
review found wrong before: where `-o` sits relative to the `--` workload
separator, how values are quoted on their way into one `su -c '...'` string,
and that the control record is held to a decode check, not just an exit code
(the decode gate itself is asserted by construction: the control command and
the decode command are what `capture --control` runs, in that order).
"""
import shlex

from conftest import load_script

ec = load_script("ete_capture.py")


class Args:
    """The argparse namespace shape cmd_capture/perf_record_command read."""

    def __init__(self, pid=None, cmd=None, seconds=10, event="cs_etm//u",
                 out="perf.data", control=False, serial=None):
        """The argparse namespace shape cmd_capture reads."""
        self.pid = pid
        self.cmd = cmd
        self.seconds = seconds
        self.event = event
        self.out = out
        self.control = control
        self.serial = serial


def split_device_shell(perf_cmd):
    """What the device shell sees: strip the trailing 2>&1 and split su args."""
    assert perf_cmd.endswith(" 2>&1"), perf_cmd
    return shlex.split(perf_cmd[:-len(" 2>&1")])


def test_output_option_precedes_the_workload_separator():
    """`perf record` hands everything after `--` to the target command, so a
    trailing `-o` is argv for the workload and perf writes to its default
    path (the pull then fetches a stale file)."""
    cmd = ec.perf_record_command(Args(cmd="app --flag"))
    toks = split_device_shell(cmd)
    assert toks[:2] == ["su", "-c"]
    inner = toks[2]
    sep = inner.index(" -- ")                 # the workload separator, not --per-thread
    out_at = inner.index("-o ")
    assert out_at < sep, "-o must come before the workload separator"
    assert inner[sep:].startswith(" -- app --flag")


def test_pid_mode_quotes_the_pid_and_keeps_o_before_target():
    """Pid mode quotes the pid and keeps o before target."""
    cmd = ec.perf_record_command(Args(pid="1234"))
    inner = " ".join(split_device_shell(cmd)[2:])
    assert "-p 1234" in inner
    assert inner.index("-o ") < inner.index("-p 1234")


def test_values_with_quotes_cannot_break_out_of_su_c():
    """Every interpolated value travels inside one su -c string: an unquoted
    single quote would close it and run the rest in the outer device shell."""
    evil = "x'; rm -rf /data/local/tmp/*; '"
    cmd = ec.perf_record_command(Args(cmd='sh -c "%s"' % evil,
                                      event="cs_etm/@tmc_etr0/u"))
    toks = split_device_shell(cmd)
    assert toks[:2] == ["su", "-c"]
    # the su argument is ONE token: the device shell never sees the payload
    # as separate commands, whatever it contains
    assert len(toks) == 3
    inner = toks[2]
    assert "perf record" in inner and "-o /data/local/tmp/perf.data" in inner


def test_out_filename_and_event_are_quoted():
    """Out filename and event are quoted."""
    cmd = ec.perf_record_command(Args(pid="7", event="my event",
                                      out="dir/my perf.data"))
    toks = split_device_shell(cmd)
    inner = toks[2]
    assert "perf record -e 'my event'" in inner
    assert "-o '/data/local/tmp/my perf.data'" in inner


def test_control_commands_exist_and_decode_runs_the_recorded_file():
    """The --control guarantee is that the record DECODES: the decode command
    must point perf script at the control recording's file."""
    rec = ec.control_record_command("a.ctl.data")
    dec = ec.control_decode_command("a.ctl.data")
    assert "perf record" in rec and "-- true" in rec and "-o a.ctl.data" in rec
    assert "perf script" in dec and "-i a.ctl.data" in dec


def test_control_commands_quote_across_both_device_shell_layers():
    """A spaced output name travels inside one su -c string: quote it inside
    the inner command, then quote the whole command for su -c -- a splice of
    literal single quotes would run in the outer device shell."""
    for cmd in (ec.control_record_command("my ctl.data"),
                ec.control_decode_command("my ctl.data")):
        assert cmd.endswith(" 2>&1")
        toks = shlex.split(cmd[:-len(" 2>&1")])
        assert toks[:2] == ["su", "-c"] and len(toks) == 3   # one su argument
        assert "my ctl.data" in toks[2]


def test_seconds_must_be_a_positive_window():
    """`timeout 0` disables the timer (or kills instantly): the CLI would
    wait on a record that never ends. Refused before any adb check."""
    from conftest import run_script
    for bad in ("0", "-5"):
        r = run_script("ete_capture.py", ["capture", "--pid", "1", "--seconds", bad])
        assert r.returncode == 2, (bad, r.output)
        assert "--seconds" in r.output and "RESULT=refused" in r.output
