"""Every worked example in spec/labels.md, executed.

A specification whose examples are wrong is worse than none: it teaches the
wrong model to whoever implements against it. These tests exist so that the
document cannot drift away from the code without CI noticing.

Each test names the section of spec/labels.md it pins.
"""

import pytest

from kelvra import Label, PrincipalSet, Sink
from kelvra.policy import check_flow

# spec/labels.md section 5, "Worked examples"
L = Label(
    readers=PrincipalSet.of("customer", "support_team"),
    endorsers=PrincipalSet.all(),
    purposes=PrincipalSet.of("support"),
)

SINKS = {
    "slack.support": Sink("slack.support", audience=PrincipalSet.of("support_team")),
    "llm.openai": Sink("llm.openai", audience=PrincipalSet.all()),
    "crm.write": Sink(
        "crm.write",
        audience=PrincipalSet.of("customer", "support_team"),
        requires_endorsement=PrincipalSet.of("reviewer"),
    ),
    "marketing.export": Sink(
        "marketing.export",
        audience=PrincipalSet.of("marketing"),
        purpose="marketing",
    ),
}


@pytest.mark.parametrize(
    "sink_name,expected",
    [
        ("slack.support", True),
        ("llm.openai", False),
        ("crm.write", True),
        ("marketing.export", False),
    ],
)
def test_worked_examples_table(sink_name, expected):
    assert check_flow(L, SINKS[sink_name]).allowed is expected


def test_marketing_export_fails_on_two_axes_not_one():
    """The spec claims two failures. Report every failing check, not the first."""
    decision = check_flow(L, SINKS["marketing.export"])
    assert len(decision.reasons) == 2
    joined = " ".join(decision.reasons)
    assert "read" in joined and "purpose" in joined


def test_untrusted_variant_is_refused_by_the_privileged_sink():
    """spec/labels.md section 5: the last row, the injection defence."""
    untrusted = L.untrusted()
    decision = check_flow(untrusted, SINKS["crm.write"])
    assert not decision.allowed
    assert any("endorsement" in r for r in decision.reasons)


def test_untrusted_variant_still_passes_the_confidentiality_check():
    """The axes are independent: losing integrity must not change readers."""
    untrusted = L.untrusted()
    assert untrusted.readers == L.readers
    assert check_flow(untrusted, SINKS["slack.support"]).allowed


# spec/labels.md section 2, "Independence of the axes"


@pytest.mark.parametrize(
    "label,is_public,is_untrusted",
    [
        (Label.public(), True, False),
        (Label.public().untrusted(), True, True),
        (Label.confidential("a"), False, False),
        (Label.confidential("a").untrusted(), False, True),
    ],
)
def test_all_four_quadrants_are_distinguishable(label, is_public, is_untrusted):
    assert label.is_public is is_public
    assert label.is_untrusted is is_untrusted


# spec/labels.md section 1, principal set operations


def test_universe_is_neutral_for_intersection_and_absorbing_for_union():
    a = PrincipalSet.of("x")
    assert (PrincipalSet.all() & a) == a
    assert (a & PrincipalSet.all()) == a
    assert (PrincipalSet.all() | a).is_all
    assert (a | PrincipalSet.all()).is_all


# spec/labels.md section 5, "Default deny"


def test_undeclared_sink_raises_rather_than_defaulting():
    from kelvra import Kelvra, Policy, Source

    p = Policy(name="conformance")
    p.add_source(Source("s", Label.public()))
    k = Kelvra(p)
    value = k.read("s", "x")

    with pytest.raises(LookupError):
        k.emit("never.declared", value)
