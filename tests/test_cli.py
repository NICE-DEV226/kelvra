"""The command line, and the exit codes CI depends on.

The contract matters more than the output: a warning must never break a
build by surprise, and an error must always break it. Anything else and
people either ignore the tool or take it out of their pipeline.
"""

import json
import textwrap
from pathlib import Path

import pytest

from kelvra.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "support_agent" / "policy.klv"

CLEAN = """
policy Clean
principal alice
source src
    confidential(alice)
    integrity trusted
sink out
    accepts confidential(alice)
"""

DEAD_SINK = """
policy Dead
principal alice, bob
source src
    confidential(alice)
sink out
    accepts confidential(bob)
"""

EXPOSED = """
policy Exposed
principal alice
source web
    public
    integrity untrusted
sink act
    accepts public
"""

BROKEN = """
policy Broken
principal alice
source src
    confidential(ghost)
"""


@pytest.fixture
def write(tmp_path):
    def _write(body: str, name: str = "p.klv") -> Path:
        path = tmp_path / name
        path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        return path

    return _write


def run(*argv: str) -> int:
    return main(list(argv))


# -- exit codes -------------------------------------------------------------


def test_a_clean_policy_exits_zero(write, capsys):
    assert run("check", str(write(CLEAN))) == EXIT_OK
    assert "no findings" in capsys.readouterr().out


def test_an_error_exits_one(write):
    assert run("check", str(write(DEAD_SINK))) == EXIT_FINDINGS


def test_warnings_alone_exit_zero(write):
    """A warning must never break a build by surprise."""
    assert run("check", str(write(EXPOSED))) == EXIT_OK


def test_strict_turns_warnings_into_failure(write):
    assert run("check", "--strict", str(write(EXPOSED))) == EXIT_FINDINGS


def test_a_file_that_will_not_parse_exits_one(write, capsys):
    assert run("check", str(write(BROKEN))) == EXIT_FINDINGS
    assert "ghost" in capsys.readouterr().err


def test_a_missing_file_exits_one_rather_than_raising(capsys):
    assert run("check", "no/such/file.klv") == EXIT_FINDINGS
    assert "cannot read" in capsys.readouterr().err


def test_the_shipped_example_passes_check():
    assert run("check", str(EXAMPLE)) == EXIT_OK


def test_the_shipped_example_fails_strict():
    """It has a real injection surface, and --strict is meant to catch that."""
    assert run("check", "--strict", str(EXAMPLE)) == EXIT_FINDINGS


# -- several files ----------------------------------------------------------


def test_one_bad_file_among_several_fails_the_run(write):
    good = write(CLEAN, "good.klv")
    bad = write(DEAD_SINK, "bad.klv")
    assert run("check", str(good), str(bad)) == EXIT_FINDINGS


def test_a_broken_file_does_not_stop_the_others_being_checked(write, capsys):
    broken = write(BROKEN, "broken.klv")
    good = write(CLEAN, "good.klv")
    assert run("check", str(broken), str(good)) == EXIT_FINDINGS
    assert "no findings" in capsys.readouterr().out, "the good file was still checked"


# -- json output ------------------------------------------------------------


def test_json_output_is_machine_readable(write, capsys):
    run("check", "--json", str(write(DEAD_SINK)))
    [payload] = json.loads(capsys.readouterr().out)

    assert payload["policy"] == "Dead" and payload["error"] is None
    assert payload["fingerprint"].startswith("sha256:")
    codes = {f["code"] for f in payload["findings"]}
    assert "unsatisfiable-sink" in codes
    assert all(set(f) >= {"code", "severity", "subject", "message"} for f in payload["findings"])


def test_json_is_always_one_array_with_one_entry_per_file_in_order(write, capsys):
    broken = write("policy P\nbogus\n", "broken.klv")
    good = write(CLEAN, "good.klv")
    missing = broken.parent / "missing.klv"
    code = run("check", "--json", str(broken), str(good), str(missing))
    entries = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert [e["file"] for e in entries] == [str(broken), str(good), str(missing)]
    assert entries[0]["error"] == {
        "kind": "parse",
        "line": 2,
        "message": "unknown keyword 'bogus' at top level",
        "hint": "expected version, principal, purpose, or one of: "
        "source, sink, declassify, endorse",
    }
    assert entries[1]["error"] is None and entries[1]["policy"] == "Clean"
    assert entries[2]["error"]["kind"] == "read" and entries[2]["error"]["line"] is None
    assert "policy" not in entries[0] and "findings" not in entries[2]


def test_json_for_one_unreadable_file_is_still_json_and_the_text_still_goes_to_stderr(
    write, capsys
):
    bad = write("policy P\nbogus\n", "bad.klv")
    assert run("check", "--json", str(bad)) == EXIT_FINDINGS
    captured = capsys.readouterr()
    [entry] = json.loads(captured.out)
    assert entry["error"]["kind"] == "parse"
    assert "unknown keyword 'bogus'" in captured.err  # the human message is unchanged


def test_json_for_a_binary_file_names_the_encoding_problem(write, capsys):
    binary = write("", "bin.klv")
    binary.write_bytes(b"\xff\xfe\x00 not utf-8 \xe5")
    assert run("check", "--json", str(binary)) == EXIT_FINDINGS
    [entry] = json.loads(capsys.readouterr().out)
    assert entry["error"]["kind"] == "read" and "codec" in entry["error"]["message"]


# -- explain ----------------------------------------------------------------


def test_explain_reports_reachability(capsys):
    assert run("explain", str(EXAMPLE)) == EXIT_OK
    out = capsys.readouterr().out
    assert "reachability:" in out
    assert "via declassification" in out


def test_explain_names_the_declassifiers_as_the_leak_points(capsys):
    run("explain", str(EXAMPLE))
    out = capsys.readouterr().out
    assert "the only places a leak is possible" in out
    assert "pii_redaction" in out


def test_explain_on_an_unparseable_file_fails_cleanly(write, capsys):
    assert run("explain", str(write(BROKEN))) == EXIT_FINDINGS
    assert "ghost" in capsys.readouterr().err


# -- argument handling ------------------------------------------------------


def test_no_subcommand_is_a_usage_error():
    assert run() == EXIT_USAGE


def test_version_is_reported(capsys):
    from kelvra import __version__

    assert run("--version") == EXIT_OK
    assert __version__ in capsys.readouterr().out


def test_help_exits_zero(capsys):
    """`--help` and `--version` succeed; only a real misuse exits non-zero.

    This asserts the exit code, not the output. An earlier version of this
    test checked only what was printed, and missed that both exited 2 --
    argparse raises SystemExit(0) for these, and `code or EXIT_USAGE`
    silently turned that into a failure because zero is falsy.
    """
    assert run("--help") == EXIT_OK
    assert "check" in capsys.readouterr().out


def test_an_unknown_subcommand_is_a_usage_error():
    assert run("frobnicate") == EXIT_USAGE


def test_check_without_a_file_is_a_usage_error():
    assert run("check") == EXIT_USAGE
