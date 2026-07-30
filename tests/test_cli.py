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
    payload = json.loads(capsys.readouterr().out)

    assert payload["policy"] == "Dead"
    assert payload["fingerprint"].startswith("sha256:")
    codes = {f["code"] for f in payload["findings"]}
    assert "unsatisfiable-sink" in codes
    assert all(set(f) >= {"code", "severity", "subject", "message"} for f in payload["findings"])


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
