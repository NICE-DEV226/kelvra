"""The static analysis reports every finding it owes, in the form it promises.

Mutation testing of ``analysis.py`` (368 mutants, 106 survivors) showed the suite checking that
a finding *exists* for a policy built to have exactly one, and little else. What survived:

* an early ``continue`` turned into ``break``, which silently stops the analysis at the first
  item that has nothing to report, so a later sink, source or declassifier goes unexamined. The
  analysis is allowed to miss problems; it is not allowed to miss them *because of the order the
  author happened to write things in*;
* findings of different kinds not accumulating (``=`` for ``+=``);
* severities, subjects and names, which tooling reads;
* the rendering of a finding, with and without its hint, and ``worst_severity``.

Each policy below puts the item that has nothing to report *before* the one that does.
"""

from __future__ import annotations

import pytest

from kelvra import parse
from kelvra.analysis import Finding, analyse, describe_reachability, worst_severity


def findings(text: str) -> list[Finding]:
    return analyse(parse(text))


def pairs(text: str) -> list[tuple[str, str]]:
    return [(f.code, f.name) for f in findings(text)]


# -- one policy with something of every kind ---------------------------------------------------

EVERYTHING = """\
policy Everything
principal a, b, c, rev
purpose p
source s_ok
    confidential(a)
    integrity trusted
source s_untrusted
    confidential(a)
    integrity untrusted
source s_trapped
    confidential(c)
    integrity trusted
sink z_open
    accepts confidential(a)
sink a_never
    accepts confidential(b)
declassify extra
    from confidential(a)
    to confidential(c)
    requires consent(rev)
    audit always
declassify rubber_stamp
    from untrusted
    to endorsed(rev)
    audit always
"""


def test_every_kind_of_finding_is_reported_together_in_the_order_they_are_documented():
    assert pairs(EVERYTHING) == [
        ("unsatisfiable-sink", "a_never"),
        ("untrusted-reaches-sink", "z_open"),
        ("trapped-source", "s_trapped"),
        ("unused-declassifier", "extra"),
        ("unused-declassifier", "rubber_stamp"),
        ("unguarded-endorsement", "rubber_stamp"),
    ]


# -- severities, subjects and names are what tooling reads -------------------------------------


def test_each_kind_has_its_documented_severity_subject_and_message():
    by_code = {f.code: f for f in findings(EVERYTHING)}
    unsat = by_code["unsatisfiable-sink"]
    assert (unsat.severity, unsat.subject, unsat.name) == ("error", "sink 'a_never'", "a_never")
    assert unsat.message == (
        "no declared source can reach this sink, even after applying every declassifier"
    )
    inj = by_code["untrusted-reaches-sink"]
    assert (inj.severity, inj.subject, inj.name) == ("warning", "sink 'z_open'", "z_open")
    assert inj.message == (
        "reachable by untrusted data from 's_untrusted', with no endorsement or consent required"
    )
    assert inj.hint.endswith("Add 'requires endorsed(...)' or 'requires consent(...)'")
    guard = by_code["unguarded-endorsement"]
    assert (guard.severity, guard.subject) == ("error", "declassifier 'rubber_stamp'")
    assert guard.name == "rubber_stamp"
    assert "turns untrusted data into endorsed data automatically" in guard.message
    assert guard.hint.startswith("add 'requires consent(<principal>)'")
    [public] = [
        f
        for f in findings(
            """\
policy P
principal a
source s
    confidential(a)
    integrity trusted
sink out
    accepts public
declassify to_the_world
    from confidential(a)
    to public
    audit always
"""
        )
        if f.code == "unguarded-public-declassification"
    ]
    assert (public.severity, public.subject) == ("error", "declassifier 'to_the_world'")
    assert public.name == "to_the_world"
    assert public.message == "makes data readable by everyone with no consent required"
    assert public.hint.startswith("publishing is irreversible")


def test_trapped_and_unused_findings_have_their_documented_text():
    trapped = analyse(
        parse(
            """\
policy T
principal a, c
source s_ok
    confidential(a)
    integrity trusted
source s_trapped
    confidential(c)
    integrity trusted
sink out
    accepts confidential(a)
"""
        )
    )
    [finding] = trapped
    assert finding.code == "trapped-source" and finding.severity == "warning"
    assert (finding.subject, finding.name) == ("source 's_trapped'", "s_trapped")
    assert finding.message == "data from this source can reach no declared sink"
    assert finding.hint.startswith("this is safe but probably not intended")
    unused = [f for f in findings(EVERYTHING) if f.code == "unused-declassifier"]
    assert unused and all(f.severity == "warning" for f in unused)
    assert unused[0].message == "no source-to-sink flow requires this declassification"
    assert unused[0].subject == f"declassifier '{unused[0].name}'"


# -- an item with nothing to report must not hide the ones after it ----------------------------


def test_a_satisfiable_sink_before_an_unsatisfiable_one_does_not_hide_it():
    assert pairs(
        """\
policy P
principal a, b
source s
    confidential(a)
    integrity trusted
sink a_fine
    accepts confidential(a)
sink b_never
    accepts confidential(b)
sink c_never
    accepts confidential(b)
"""
    ) == [("unsatisfiable-sink", "b_never"), ("unsatisfiable-sink", "c_never")]


def test_a_policy_without_sources_has_no_unsatisfiable_sinks_to_report():
    assert (
        findings(
            """\
policy P
principal a
sink one
    accepts confidential(a)
sink two
    accepts confidential(a)
"""
        )
        == []
    )


def test_sinks_that_demand_a_vouch_or_a_human_are_skipped_but_later_ones_are_not():
    text = """\
policy P
principal a, rev
source s_bad
    confidential(a)
    integrity untrusted
sink a_endorsed
    accepts confidential(a)
    requires endorsed(rev)
sink b_human
    accepts confidential(a)
    requires consent(rev)
sink c_plain
    accepts confidential(a)
"""
    got = [f for f in findings(text) if f.code == "untrusted-reaches-sink"]
    assert [f.name for f in got] == ["c_plain"]


def test_an_unreachable_sink_before_a_reachable_one_does_not_hide_it():
    text = """\
policy P
principal a, b
source s_bad
    confidential(a)
    integrity untrusted
sink a_other_audience
    accepts confidential(b)
sink b_plain
    accepts confidential(a)
"""
    got = [f for f in findings(text) if f.code == "untrusted-reaches-sink"]
    assert [f.name for f in got] == ["b_plain"]


def test_with_no_untrusted_source_there_is_no_injection_surface():
    text = """\
policy P
principal a
source s
    confidential(a)
    integrity trusted
sink out
    accepts confidential(a)
"""
    assert findings(text) == []


def test_a_source_that_reaches_a_sink_before_a_trapped_one_does_not_hide_it():
    text = """\
policy P
principal a, c, d
source a_ok
    confidential(a)
    integrity trusted
source b_trapped
    confidential(c)
    integrity trusted
source c_trapped
    confidential(d)
    integrity trusted
sink out
    accepts confidential(a)
"""
    assert pairs(text) == [("trapped-source", "b_trapped"), ("trapped-source", "c_trapped")]


def test_a_policy_with_no_sinks_has_no_trapped_sources_and_no_unused_declassifiers():
    text = """\
policy P
principal a, rev
source s
    confidential(a)
    integrity trusted
declassify d
    from confidential(a)
    to public
    requires consent(rev)
    audit always
"""
    assert findings(text) == []


def test_a_policy_with_no_sources_has_no_unused_declassifiers_to_report():
    text = """\
policy P
principal a, rev
sink out
    accepts confidential(a)
declassify d
    from confidential(a)
    to public
    requires consent(rev)
    audit always
"""
    assert findings(text) == []


def test_two_declassifiers_that_grant_the_same_thing_are_each_unnecessary_on_their_own():
    """Excluding the first must still count the second; excluding either leaves the other."""
    text = """\
policy P
principal a, b, rev
source s
    confidential(a)
    integrity trusted
sink out
    accepts confidential(a, b)
declassify first
    from confidential(a)
    to confidential(a, b)
    requires consent(rev)
    audit always
declassify second
    from confidential(a)
    to confidential(a, b)
    requires consent(rev)
    audit always
"""
    assert pairs(text) == [("unused-declassifier", "first"), ("unused-declassifier", "second")]


def test_a_declassifier_that_is_needed_is_not_reported_even_when_others_are_not():
    text = """\
policy P
principal a, b, c, rev
source s
    confidential(a)
    integrity trusted
sink out
    accepts confidential(a, b)
declassify a_useless
    from confidential(a)
    to confidential(c)
    requires consent(rev)
    audit always
declassify b_needed
    from confidential(a)
    to confidential(a, b)
    requires consent(rev)
    audit always
declassify c_useless
    from confidential(a)
    to confidential(c)
    requires consent(rev)
    audit always
"""
    assert pairs(text) == [
        ("unused-declassifier", "a_useless"),
        ("unused-declassifier", "c_useless"),
    ]


def test_a_guarded_declassifier_before_an_unguarded_one_does_not_hide_it():
    text = """\
policy P
principal a, rev
source s
    confidential(a)
    integrity untrusted
sink out
    accepts confidential(a)
    requires endorsed(rev)
declassify a_guarded
    from untrusted
    to endorsed(rev)
    requires consent(rev)
    audit always
declassify b_unguarded
    from untrusted
    to endorsed(rev)
    audit always
declassify c_public
    from confidential(a)
    to public
    audit always
"""
    got = [(f.code, f.name) for f in findings(text) if f.code.startswith("unguarded")]
    assert got == [
        ("unguarded-endorsement", "b_unguarded"),
        ("unguarded-public-declassification", "c_public"),
    ]


def test_one_declaration_can_be_unguarded_in_both_ways_and_is_reported_for_each():
    text = """\
policy P
principal a, rev
source s
    confidential(a)
    integrity untrusted
sink out
    accepts public
declassify both
    from untrusted
    to endorsed(rev)
    to public
    audit always
"""
    got = [f.code for f in findings(text) if f.code.startswith("unguarded")]
    assert got == ["unguarded-endorsement", "unguarded-public-declassification"]


# -- the reasons given for a sink nothing can reach --------------------------------------------


@pytest.mark.parametrize(
    "sink,hint",
    [
        (
            "accepts confidential(b)",
            "the audience b is never permitted to read; either widen a declassifier's 'to', "
            "or check the audience for a typo",
        ),
        (
            "accepts confidential(a)\n    requires endorsed(rev)",
            "nothing grants endorsement by rev; add an 'endorse' declaration that grants it",
        ),
    ],
)
def test_the_hint_names_the_axis_that_blocks_every_source(sink, hint):
    text = f"""\
policy P
principal a, b, rev
source s
    confidential(a)
    integrity untrusted
sink out
    {sink}
"""
    [finding] = [f for f in findings(text) if f.code == "unsatisfiable-sink"]
    assert finding.hint == hint


def test_the_hint_for_a_purpose_nobody_permits_says_so():
    text = """\
policy P
principal a
purpose billing, support
source s
    confidential(a) for support
    integrity trusted
sink out
    accepts confidential(a)
    for billing
"""
    [finding] = [f for f in findings(text) if f.code == "unsatisfiable-sink"]
    assert finding.hint == "no source permits the purpose 'billing'"


def test_the_hint_lists_every_blocking_axis_when_they_differ():
    text = """\
policy P
principal a, b, rev
source s
    confidential(a)
    integrity untrusted
sink out
    accepts confidential(b)
    requires endorsed(rev)
"""
    [finding] = [f for f in findings(text) if f.code == "unsatisfiable-sink"]
    assert finding.hint == "blocked on: audience, endorsement"


# -- how a finding is shown and how bad a set of them is ---------------------------------------


def test_a_finding_is_shown_with_its_hint_on_a_second_line_only_when_it_has_one():
    with_hint = Finding("c", "error", "sink 'x'", "it is wrong", hint="do this")
    without = Finding("c", "warning", "sink 'x'", "it is odd")
    assert str(with_hint) == "error[c] sink 'x': it is wrong\n  hint: do this"
    assert str(without) == "warning[c] sink 'x': it is odd"


def test_worst_severity_is_the_worst_present_and_none_for_nothing():
    warning = Finding("w", "warning", "s", "m")
    error = Finding("e", "error", "s", "m")
    assert worst_severity([]) is None
    assert worst_severity([warning]) == "warning"
    assert worst_severity([warning, warning]) == "warning"
    assert worst_severity([error]) == "error"
    assert worst_severity([warning, error]) == "error"
    assert worst_severity([error, warning]) == "error"


# -- the reachability table --------------------------------------------------------------------


def test_the_reachability_table_lists_every_sink_whatever_the_order():
    text = """\
policy P
principal a, b, rev
source s_a
    confidential(a)
    integrity trusted
sink a_never
    accepts confidential(b)
sink b_direct
    accepts confidential(a)
sink c_via
    accepts confidential(a, b)
declassify widen
    from confidential(a)
    to confidential(a, b)
    requires consent(rev)
    audit always
"""
    assert describe_reachability(parse(text)) == [
        "a_never: s_a (via declassification)",
        "b_direct: s_a (direct)",
        "c_via: s_a (via declassification)",
    ]


def test_a_sink_nothing_reaches_is_shown_as_unreachable_and_the_next_one_still_is_shown():
    text = """\
policy P
principal a, b
source s_a
    confidential(a)
    integrity trusted
sink a_never
    accepts confidential(b)
sink b_direct
    accepts confidential(a)
"""
    assert describe_reachability(parse(text)) == ["a_never: unreachable", "b_direct: s_a (direct)"]
