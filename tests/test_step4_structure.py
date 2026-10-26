"""Structured results where the code used to read its own messages back."""

import re
from pathlib import Path

from kelvra import FORMAT_VERSION, Kelvra, Label, PrincipalSet, Sink, __version__, parse
from kelvra.analysis import analyse
from kelvra.klv import parse_detailed
from kelvra.lsp import diagnostics_for
from kelvra.policy import check_flow

ROOT = Path(__file__).resolve().parents[1]


def test_a_decision_names_every_failed_axis_without_parsing_its_reasons():
    label = Label(PrincipalSet.of("a"), PrincipalSet.none(), PrincipalSet.of("x"))
    sink = Sink("s", PrincipalSet.of("z"), PrincipalSet.of("rev"), purpose="y")
    decision = check_flow(label, sink)
    assert decision.axes == ("audience", "endorsement", "purpose")
    assert len(decision.axes) == len(decision.reasons)


def test_a_permitted_decision_has_no_failed_axes():
    assert check_flow(Label(), Sink("s", PrincipalSet.of("a"))).axes == ()


def test_the_hint_of_an_unsatisfiable_sink_survives_reworded_reasons():
    """The hint used to depend on substrings of the reason text; now on the axes."""
    policy = parse(
        "policy P\nprincipal a, b\nsource s\n    confidential(a)\n    integrity trusted\n"
        "sink out\n    accepts confidential(b)\n"
    )
    (finding,) = [f for f in analyse(policy) if f.code == "unsatisfiable-sink"]
    assert "audience" in finding.hint and finding.name == "out"


def test_every_finding_carries_the_bare_name_it_is_about():
    policy = parse(
        "policy P\nprincipal a, b\nsource s\n    confidential(a)\n    integrity untrusted\n"
        "source lonely\n    confidential(b)\n    integrity trusted\n"
        "sink out\n    accepts public\n"
        "endorse e\n    to endorsed(a)\n"
    )
    names = {f.code: f.name for f in analyse(policy)}
    assert names["unguarded-endorsement"] == "e"
    assert all(name for name in names.values())


def test_parser_warnings_come_with_their_line_numbers():
    result = parse_detailed("policy P\nprincipal a, a\nsource s\n    confidential(a)\n")
    assert (2, "principal 'a' declared more than once") in result.warning_lines
    assert [f"line {n}: {m}" for n, m in result.warning_lines] == result.warnings


def test_editor_warnings_land_on_the_declaring_line():
    text = "policy P\nprincipal a\nsource s\n    confidential(a)\n"
    by_line = {d.line: d.message for d in diagnostics_for(text) if d.code == "policy"}
    assert "defaults to trusted" in by_line[3]


def test_findings_land_on_the_declaring_line_in_the_editor():
    text = (
        "policy P\nprincipal a, b\nsource s\n    confidential(a)\n    integrity trusted\n"
        "sink out\n    accepts confidential(b)\n"
    )
    assert [d.line for d in diagnostics_for(text) if d.code == "unsatisfiable-sink"] == [6]


def test_the_package_version_is_the_one_pyproject_declares():
    declared = re.search(
        r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M
    )
    assert declared and declared.group(1) == __version__


def test_the_record_declares_the_format_not_the_package():
    record = Kelvra(parse("policy P\nprincipal a\n")).record()
    assert record["kelvra_version"] == FORMAT_VERSION
    assert FORMAT_VERSION != __version__
