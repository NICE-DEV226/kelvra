"""Behaviour that other things depend on, pinned to exact values.

Found by mutation testing: a tool changed the code in 271 small ways, and 72 of those
changes were not noticed by the suite. Most were the same few things: nothing checked
the *exact* text of a refusal, nothing checked that the fingerprint of a policy stays the
same from one release to the next, and a method (``Policy.__delattr__``) had no test at
all. These are those tests.
"""

from pathlib import Path

import pytest

from kelvra import (
    PUBLIC,
    SECRET,
    Declassifier,
    Label,
    Policy,
    PrincipalSet,
    Sink,
    Source,
    check_flow,
    parse,
)
from kelvra.policy import PolicySealed

ROOT = Path(__file__).resolve().parents[1]


# -- the fingerprint is an audit artifact: it must not change by accident -------------------


def _tiny() -> Policy:
    p = Policy(name="Tiny", version=2)
    p.add_source(Source("s", Label.confidential("a", for_purpose="x").untrusted()))
    p.add_sink(Sink("k", PrincipalSet.of("a", "b"), PrincipalSet.of("r"), "x", "a"))
    p.add_declassifier(
        Declassifier(
            "d",
            PrincipalSet.of("c"),
            PrincipalSet.of("r"),
            PrincipalSet.of("y"),
            "a",
            Label.confidential("a"),
        )
    )
    return p


@pytest.mark.parametrize(
    "policy,expected",
    [
        (
            lambda: parse((ROOT / "examples/support_agent/policy.klv").read_text(encoding="utf-8")),
            "sha256:c5551701fe426ec8f95af12c8c0344a968eb76a736a87fd680d4db2993118fae",
        ),
        (
            lambda: parse((ROOT / "evaluation/policy.klv").read_text(encoding="utf-8")),
            "sha256:bc3ff430cc6dbc89ae02f8a49e8878e5c1435eba0178bf1b07295d4f695b5a4f",
        ),
        (_tiny, "sha256:959089f2d1058f875a2ee951501e59267a32c88e2ea66f31158995d2a4466572"),
    ],
)
def test_the_fingerprint_of_a_known_policy_is_a_known_value(policy, expected):
    """A record names the policy it ran under by this hash. If the way it is computed drifts,
    every old record stops matching the policy it was about, with no error anywhere. Changing
    the serialisation is allowed; doing it without updating these values, the specification
    (provenance.md section 3) and the record format version is not."""
    assert policy().fingerprint() == expected


def test_the_fingerprint_does_not_depend_on_the_order_things_were_declared():
    forward, backward = Policy(name="P"), Policy(name="P")
    sources = [Source(f"s{i}", Label.confidential(f"p{i}")) for i in range(4)]
    for s in sources:
        forward.add_source(s)
    for s in reversed(sources):
        backward.add_source(s)
    assert forward.fingerprint() == backward.fingerprint()


# -- every field of a policy is covered by its fingerprint -----------------------------------


def _changes(policy: Policy):
    """Yield a description and a copy of ``policy`` with exactly one thing changed."""
    import dataclasses

    other = PrincipalSet.of("zz-other")

    def copy_with(**tables):
        p = Policy(name=policy.name, version=policy.version)
        p.sources.update(policy.sources)
        p.sinks.update(policy.sinks)
        p.declassifiers.update(policy.declassifiers)
        for key, value in tables.items():
            if key in ("name", "version"):
                setattr(p, key, value)
            else:
                getattr(p, key).update(value)
        return p

    yield "policy name", copy_with(name=policy.name + "x")
    yield "policy version", copy_with(version=policy.version + 1)
    for name, s in policy.sources.items():
        for axis in ("readers", "endorsers", "purposes"):
            label = dataclasses.replace(s.label, **{axis: other})
            yield f"source {axis}", copy_with(sources={name: Source(name, label)})
    for name, k in policy.sinks.items():
        yield "sink audience", copy_with(sinks={name: dataclasses.replace(k, audience=other)})
        yield (
            "sink endorsement",
            copy_with(sinks={name: dataclasses.replace(k, requires_endorsement=other)}),
        )
        yield "sink purpose", copy_with(sinks={name: dataclasses.replace(k, purpose="zz")})
        yield (
            "sink consent",
            copy_with(sinks={name: dataclasses.replace(k, requires_consent_from="zz")}),
        )
    for name, d in policy.declassifiers.items():
        for field in ("grants_readers", "grants_endorsement", "grants_purposes"):
            yield (
                f"declassifier {field}",
                copy_with(declassifiers={name: dataclasses.replace(d, **{field: other})}),
            )
        yield (
            "declassifier consent",
            copy_with(declassifiers={name: dataclasses.replace(d, requires_consent_from="zz")}),
        )
        yield (
            "declassifier from",
            copy_with(
                declassifiers={name: dataclasses.replace(d, expects=Label.confidential("zz"))}
            ),
        )
    # a declaration renamed
    only = next(iter(policy.sources))
    renamed = copy_with()
    renamed.sources[only + "x"] = policy.sources[only]
    del renamed.sources[only]
    yield "source name", renamed


def test_changing_any_single_field_of_a_policy_changes_its_fingerprint():
    policy = _tiny()
    base = policy.fingerprint()
    seen = set()
    for what, changed in _changes(policy):
        seen.add(what)
        assert changed.fingerprint() != base, f"the fingerprint ignores: {what}"
    assert len(seen) >= 14  # every field above was actually exercised


# -- the exact text of a refusal (it goes into audit records and into people's terminals) ------


def test_a_refusal_names_each_failing_check_in_the_words_the_specification_shows():
    label = Label(PrincipalSet.of("a"), PrincipalSet.none(), PrincipalSet.of("x"))
    sink = Sink("out", PrincipalSet.of("z"), PrincipalSet.of("rev"), purpose="y")
    decision = check_flow(label, sink)
    assert decision.reasons == (
        "audience z is not permitted to read data readable by a",
        "sink requires endorsement by rev but got untrusted data",
        "sink serves purpose 'y', not permitted by x",
    )
    assert decision.axes == ("audience", "endorsement", "purpose")
    assert decision.reason == "; ".join(decision.reasons)


def test_an_endorsement_failure_names_who_did_vouch_when_somebody_did():
    label = Label(PrincipalSet.all(), PrincipalSet.of("s", "t"), PrincipalSet.all())
    decision = check_flow(label, Sink("out", requires_endorsement=PrincipalSet.of("rev")))
    assert decision.reasons == ("sink requires endorsement by rev but got endorsers s,t",)


def test_a_decision_remembers_which_sink_and_which_label_it_was_about():
    label = Label.confidential("a")
    sink = Sink("the-sink", PrincipalSet.of("b"))
    decision = check_flow(label, sink)
    assert decision.sink == "the-sink" and decision.label is label
    assert not decision and bool(check_flow(PUBLIC, Sink("x", PrincipalSet.of("b"))))
    assert check_flow(PUBLIC, Sink("x")).reason == "permitted"


# -- how labels and sets are shown ---------------------------------------------------------------


def test_principal_sets_show_the_way_the_documentation_says():
    assert repr(PrincipalSet.all()) == "*"
    assert repr(PrincipalSet.none()) == "-"
    assert repr(PrincipalSet.of("b", "a")) == "a,b"
    assert list(PrincipalSet.of("b", "a", "c")) == ["a", "b", "c"]
    with pytest.raises(TypeError, match="universe"):
        list(PrincipalSet.all())
    assert "anything" in PrincipalSet.all() and "x" not in PrincipalSet.none()


@pytest.mark.parametrize(
    "label,described,shown",
    [
        (PUBLIC, "public", "Label(readers=* endorsers=* purposes=*)"),
        (SECRET, "confidential(-) untrusted for -", "Label(readers=- endorsers=- purposes=-)"),
        (
            Label.confidential("a", "b"),
            "confidential(a,b)",
            "Label(readers=a,b endorsers=* purposes=*)",
        ),
        (
            Label.confidential("a").untrusted(),
            "confidential(a) untrusted",
            "Label(readers=a endorsers=- purposes=*)",
        ),
        (
            Label.confidential("a", for_purpose="p").endorsed_by("r"),
            "confidential(a) endorsed(r) for p",
            "Label(readers=a endorsers=r purposes=p)",
        ),
    ],
)
def test_labels_describe_and_show_themselves_exactly(label, described, shown):
    assert label.describe() == described
    assert repr(label) == shown


def test_the_label_helpers_set_the_axis_they_are_named_for_and_no_other():
    base = Label.confidential("a", for_purpose="p")
    assert (base.readers, base.endorsers, base.purposes) == (
        PrincipalSet.of("a"),
        PrincipalSet.all(),
        PrincipalSet.of("p"),
    )
    untrusted = base.untrusted()
    assert (untrusted.readers, untrusted.endorsers, untrusted.purposes) == (
        base.readers,
        PrincipalSet.none(),
        base.purposes,
    )
    endorsed = base.endorsed_by("r", "s")
    assert (endorsed.readers, endorsed.endorsers, endorsed.purposes) == (
        base.readers,
        PrincipalSet.of("r", "s"),
        base.purposes,
    )
    purposed = base.for_purposes("q")
    assert (purposed.readers, purposed.endorsers, purposed.purposes) == (
        base.readers,
        base.endorsers,
        PrincipalSet.of("q"),
    )
    assert Label.confidential("a").purposes.is_all
    assert Label.public() is PUBLIC
    a, b = Label.confidential("a", "b"), Label.confidential("b", "c").untrusted()
    assert a | b == a.join(b)
    assert (PUBLIC.is_public, Label.confidential("a").is_public) == (True, False)
    assert (Label.confidential("a").untrusted().is_untrusted, PUBLIC.is_untrusted) == (True, False)


@pytest.mark.parametrize("member", ["*", "", 5, None])
def test_a_principal_set_refuses_members_that_are_not_names(member):
    with pytest.raises(ValueError, match="non-empty name"):
        PrincipalSet(frozenset({member}))


# -- a sealed policy -----------------------------------------------------------------------------


def test_a_sealed_policy_cannot_lose_an_attribute_either():
    sealed = _tiny().seal()
    for name in ("sinks", "name", "sealed", "version"):
        with pytest.raises(PolicySealed, match="sealed"):
            delattr(sealed, name)
    assert sealed.name == "Tiny" and sealed.sealed  # nothing was removed


def test_an_unsealed_policy_can_still_be_edited_and_trimmed():
    p = _tiny()
    p.version = 9
    assert p.version == 9
    del p.version  # falls back to the class default, as a dataclass attribute does


def test_the_message_for_editing_a_sealed_policy_says_which_policy_and_why():
    sealed = _tiny().seal()
    with pytest.raises(PolicySealed) as excinfo:
        sealed.add_sink(Sink("late"))
    text = str(excinfo.value)
    assert "'Tiny'" in text and "sealed" in text and "run" in text
    with pytest.raises(PolicySealed) as excinfo:
        sealed.name = "other"
    assert "'Tiny'" in str(excinfo.value) and "name" in str(excinfo.value)
    with pytest.raises(PolicySealed, match="delete"):
        del sealed.sinks
    for add, thing in (
        (sealed.add_source, Source("n", PUBLIC)),
        (sealed.add_declassifier, Declassifier("n")),
    ):
        with pytest.raises(PolicySealed):
            add(thing)
