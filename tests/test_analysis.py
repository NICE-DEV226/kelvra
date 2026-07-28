"""Static analysis, and the soundness contract it promises.

The contract is that every finding is definite: the analysis reports a
problem only when no execution can avoid it. A checker that cries wolf gets
switched off, and a switched-off checker protects nothing -- so the tests
that matter most here are the ones asserting *silence*.
"""

from pathlib import Path

import pytest

from kelvra import Label, Policy, PrincipalSet, Sink, Source, declassify_to, endorse_as
from kelvra.analysis import analyse, describe_reachability, worst_severity
from kelvra.klv import parse_file

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "support_agent" / "policy.klv"


def codes(policy: Policy) -> set[str]:
    return {f.code for f in analyse(policy)}


def sound_policy() -> Policy:
    p = Policy(name="Sound")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a")))
    return p


# -- no false positives -----------------------------------------------------


def test_a_sound_policy_produces_nothing():
    assert analyse(sound_policy()) == []
    assert worst_severity([]) is None


def test_a_sink_reachable_only_after_declassification_is_not_flagged():
    """The analysis must apply declassifiers before declaring a sink dead."""
    p = Policy(name="ViaDeclass")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a", "b")))
    p.add_declassifier(declassify_to("widen", "b"))
    assert "unsatisfiable-sink" not in codes(p)


def test_a_sink_reachable_only_after_endorsement_is_not_flagged():
    p = Policy(name="ViaEndorse")
    p.add_source(Source("src", Label.confidential("a").untrusted()))
    p.add_sink(
        Sink("out", audience=PrincipalSet.of("a"), requires_endorsement=PrincipalSet.of("r"))
    )
    p.add_declassifier(endorse_as("review", "r"))
    assert "unsatisfiable-sink" not in codes(p)


def test_an_empty_policy_says_nothing():
    assert analyse(Policy(name="Empty")) == []


def test_a_policy_with_no_sinks_does_not_report_trapped_sources():
    p = Policy(name="NoSinks")
    p.add_source(Source("src", Label.confidential("a")))
    assert analyse(p) == []


# -- unsatisfiable sinks ----------------------------------------------------


def test_a_sink_no_source_can_reach_is_an_error():
    p = Policy(name="Dead")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("b")))

    finding = next(f for f in analyse(p) if f.code == "unsatisfiable-sink")
    assert finding.severity == "error"
    assert "out" in finding.subject
    assert "typo" in finding.hint, "the usual cause is a misspelled audience"


def test_a_sink_demanding_an_endorsement_nothing_grants_is_an_error():
    p = Policy(name="NoEndorser")
    p.add_source(Source("src", Label.confidential("a").untrusted()))
    p.add_sink(
        Sink("out", audience=PrincipalSet.of("a"), requires_endorsement=PrincipalSet.of("ghost"))
    )
    finding = next(f for f in analyse(p) if f.code == "unsatisfiable-sink")
    assert "endorse" in finding.hint


def test_a_sink_demanding_an_unreachable_purpose_is_an_error():
    p = Policy(name="WrongPurpose")
    p.add_source(Source("src", Label.confidential("a", for_purpose="support")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a"), purpose="marketing"))
    finding = next(f for f in analyse(p) if f.code == "unsatisfiable-sink")
    assert "marketing" in finding.hint


def test_accepts_public_with_no_public_source_is_caught():
    """The finding that first appeared against the project's own example."""
    p = Policy(name="PublicSink")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.all()))
    assert "unsatisfiable-sink" in codes(p)


# -- injection surface ------------------------------------------------------


def test_untrusted_data_reaching_an_unguarded_sink_warns():
    p = Policy(name="Exposed")
    p.add_source(Source("web", Label.public().untrusted()))
    p.add_sink(Sink("shell.exec", audience=PrincipalSet.all()))

    finding = next(f for f in analyse(p) if f.code == "untrusted-reaches-sink")
    assert finding.severity == "warning"
    assert "web" in finding.message
    assert "injected content can drive it" in finding.hint


def test_requiring_endorsement_removes_the_exposure():
    p = Policy(name="Guarded")
    p.add_source(Source("web", Label.public().untrusted()))
    p.add_sink(
        Sink("shell.exec", audience=PrincipalSet.all(), requires_endorsement=PrincipalSet.of("r"))
    )
    assert "untrusted-reaches-sink" not in codes(p)


def test_requiring_consent_also_removes_the_exposure():
    """A human in the way is a defence even without an endorser."""
    p = Policy(name="Consented")
    p.add_source(Source("web", Label.public().untrusted()))
    p.add_sink(
        Sink("shell.exec", audience=PrincipalSet.all(), requires_consent_from="operator")
    )
    assert "untrusted-reaches-sink" not in codes(p)


def test_a_policy_with_no_untrusted_source_reports_no_exposure():
    p = Policy(name="AllTrusted")
    p.add_source(Source("db", Label.public()))
    p.add_sink(Sink("out", audience=PrincipalSet.all()))
    assert "untrusted-reaches-sink" not in codes(p)


# -- trapped sources and unused declassifiers -------------------------------


def test_a_source_that_reaches_nothing_warns():
    p = Policy(name="Trapped")
    p.add_source(Source("locked", Label.confidential("nobody_else")))
    p.add_source(Source("fine", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a")))

    trapped = [f for f in analyse(p) if f.code == "trapped-source"]
    assert [f.subject for f in trapped] == ["source 'locked'"]


def test_a_declassifier_nothing_needs_warns():
    p = Policy(name="Spare")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a")))
    p.add_declassifier(declassify_to("never_needed", "z"))

    finding = next(f for f in analyse(p) if f.code == "unused-declassifier")
    assert "never_needed" in finding.subject
    assert "attack surface" in finding.hint


def test_a_declassifier_that_is_needed_is_not_flagged():
    p = Policy(name="Needed")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("a", "b")))
    p.add_declassifier(declassify_to("widen", "b"))
    assert "unused-declassifier" not in codes(p)


# -- the shipped example ----------------------------------------------------


def test_the_example_policy_has_no_errors():
    findings = analyse(parse_file(EXAMPLE))
    assert [f for f in findings if f.severity == "error"] == []


def test_the_example_policy_reports_its_real_injection_surface():
    """These warnings are accurate and the example keeps them.

    A support agent that acts on inbound email genuinely has untrusted data
    reaching sinks. Naming that is the analysis working, not the example
    misbehaving.
    """
    exposed = {
        f.subject for f in analyse(parse_file(EXAMPLE)) if f.code == "untrusted-reaches-sink"
    }
    assert exposed == {"sink 'llm.openai'", "sink 'slack.support_channel'"}


def test_the_example_has_no_dead_sinks_or_spare_declassifiers():
    codes_found = codes(parse_file(EXAMPLE))
    assert "trapped-source" not in codes_found
    assert "unused-declassifier" not in codes_found


def test_the_crm_sink_is_not_flagged_because_it_demands_review_and_consent():
    exposed = {
        f.subject for f in analyse(parse_file(EXAMPLE)) if f.code == "untrusted-reaches-sink"
    }
    assert "sink 'crm.write'" not in exposed


# -- reachability report ----------------------------------------------------


def test_reachability_distinguishes_direct_from_declassified():
    lines = describe_reachability(parse_file(EXAMPLE))
    joined = "\n".join(lines)
    assert "crm.customer_record (direct)" in joined
    assert "inbox.imap (via declassification)" in joined


def test_reachability_names_unreachable_sinks():
    p = Policy(name="Dead")
    p.add_source(Source("src", Label.confidential("a")))
    p.add_sink(Sink("out", audience=PrincipalSet.of("b")))
    assert describe_reachability(p) == ["out: unreachable"]


# -- severity ---------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_factory,expected",
    [
        (sound_policy, None),
        (
            lambda: _with(Policy(name="W"), untrusted_exposure=True),
            "warning",
        ),
    ],
)
def test_worst_severity(policy_factory, expected):
    assert worst_severity(analyse(policy_factory())) == expected


def _with(p: Policy, *, untrusted_exposure: bool) -> Policy:
    p.add_source(Source("web", Label.public().untrusted()))
    p.add_sink(Sink("out", audience=PrincipalSet.all()))
    return p
