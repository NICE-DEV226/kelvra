"""Behaviour added by the first hardening step, beyond the audit regressions.

The audit tests (``test_audit_regressions.py``) state each property from the
specifications. These cover what the fixes introduced and could get wrong.
"""

import pytest

from kelvra import (
    ConsentDecision,
    ConsentRefused,
    Kelvra,
    KlvError,
    Label,
    Policy,
    PolicyIntegrityError,
    PrincipalSet,
    Sink,
    Source,
    parse,
)
from kelvra.policy import PolicySealed

BASE = """\
policy P
principal a, rev
source s
    confidential(a)
    integrity untrusted
sink out
    accepts confidential(a)
"""


# -- line terminators -------------------------------------------------------


@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r"])
def test_the_three_specified_terminators_all_work(eol):
    assert parse(BASE.replace("\n", eol)).name == "P"


def test_a_leading_byte_order_mark_is_tolerated_once():
    assert parse("\ufeff" + BASE).name == "P"
    with pytest.raises(KlvError):
        parse("\ufeff\ufeff" + BASE)


def test_a_bom_in_the_middle_of_the_file_is_rejected():
    with pytest.raises(KlvError) as excinfo:
        parse(BASE + "# x\ufeffy\n")
    assert excinfo.value.line == BASE.count("\n") + 1


def test_a_tab_is_still_allowed_as_indentation():
    assert "out" in parse(BASE.replace("    ", "\t")).sinks


def test_the_forbidden_character_is_named_in_the_message():
    with pytest.raises(KlvError) as excinfo:
        parse(BASE + "# x\u202ey\n")
    assert "U+202E" in excinfo.value.message


# -- the seal ---------------------------------------------------------------


def _session() -> Kelvra:
    return Kelvra(parse(BASE), signing_key=b"k" * 32)


@pytest.mark.parametrize("table", ["sources", "sinks", "declassifiers"])
def test_the_sealed_tables_are_read_only(table):
    k = _session()
    with pytest.raises(TypeError):
        getattr(k.policy, table)["x"] = object()


@pytest.mark.parametrize("attribute", ["sealed", "name", "version", "sinks"])
def test_a_sealed_policy_rejects_attribute_assignment(attribute):
    k = _session()
    with pytest.raises(PolicySealed):
        setattr(k.policy, attribute, False)


def test_the_callers_own_policy_stays_editable():
    p = parse(BASE)
    Kelvra(p)
    p.add_sink(Sink("later", audience=PrincipalSet.all()))
    assert "later" in p.sinks


def test_a_record_is_refused_if_the_policy_was_swapped_around_the_seal():
    """object.__setattr__ defeats any in-process guard; the record must still not lie."""
    k = _session()
    object.__setattr__(k.policy, "sinks", {"out": Sink("out", audience=PrincipalSet.none())})
    with pytest.raises(PolicyIntegrityError):
        k.record()


def test_an_untouched_session_still_records():
    assert _session().record()["policy"]["fingerprint"].startswith("sha256:")


# -- consent ----------------------------------------------------------------

CONSENT_SRC = BASE + "sink gated\n    accepts confidential(a)\n    requires consent(a)\n"


def _gated(provider):
    k = Kelvra(parse(CONSENT_SRC), consent=provider)
    return k, k.read("s", "x")


def test_true_grants():
    k, data = _gated(lambda p, c: ConsentDecision(True, "dr-test"))
    assert k.emit("gated", data) == "x"


@pytest.mark.parametrize("answer", [False, None])
def test_false_and_none_refuse(answer):
    k, data = _gated(lambda p, c: answer)
    with pytest.raises(ConsentRefused):
        k.emit("gated", data)


@pytest.mark.parametrize("answer", ["yes", 1, [0], object()])
def test_any_other_value_is_an_error_and_a_recorded_refusal(answer):
    k, data = _gated(lambda p, c: answer)
    with pytest.raises(TypeError):
        k.emit("gated", data)
    consent = k.ledger.of_kind("consent")[0]
    assert consent.detail["granted"] is False


def test_an_async_provider_is_an_error_not_a_grant():
    async def provider(principal, context):
        return True

    k, data = _gated(provider)
    with pytest.raises(TypeError, match="awaitable"):
        k.emit("gated", data)


# -- the agent surface ------------------------------------------------------


def test_the_agent_session_can_do_what_an_agent_needs():
    k = _session()
    agent = k.agent_session()
    data = agent.read("s", "hello")
    out = agent.model_call("m", data, produce=lambda v: v.upper())
    assert agent.would_allow("out", out)
    assert agent.emit("out", out) == "HELLO"
    assert agent.combine("c", data, out) == data.label.join(out.label)


@pytest.mark.parametrize(
    "name", ["declassify", "endorse", "policy", "ledger", "record", "report", "signing_key"]
)
def test_the_agent_session_exposes_no_privileged_operation(name):
    assert not hasattr(_session().agent_session(), name)


def test_the_agent_session_cannot_grow_attributes():
    agent = _session().agent_session()
    with pytest.raises(AttributeError):
        agent.declassify = lambda *a: None


# -- analysis ---------------------------------------------------------------


def _codes(src):
    from kelvra.analysis import analyse

    return {f.code for f in analyse(parse(src))}


def test_a_declassifier_naming_nobody_is_not_flagged_when_it_only_widens_to_a_group():
    src = BASE + "declassify d\n    to confidential(a)\n"
    assert not _codes(src) & {"unguarded-endorsement", "unguarded-public-declassification"}


def test_endorse_without_consent_is_an_error():
    assert "unguarded-endorsement" in _codes(BASE + "endorse e\n    to endorsed(rev)\n")


def test_endorse_with_consent_is_accepted():
    src = BASE + "endorse e\n    to endorsed(rev)\n    requires consent(rev)\n"
    assert "unguarded-endorsement" not in _codes(src)


def test_public_declassification_without_consent_is_an_error():
    assert "unguarded-public-declassification" in _codes(BASE + "declassify d\n    to public\n")


def test_programmatic_policies_are_covered_too():
    from kelvra import endorse_as
    from kelvra.analysis import analyse

    p = Policy(name="X")
    p.add_source(Source("s", Label.confidential("a").untrusted()))
    p.add_declassifier(endorse_as("e", "rev"))
    assert any(f.code == "unguarded-endorsement" for f in analyse(p))


# -- parser robustness ------------------------------------------------------


@pytest.mark.parametrize("version", ["²", "٣", "1" * 10, "-1", "1.5"])
def test_odd_versions_are_located_errors(version):
    with pytest.raises(KlvError) as excinfo:
        parse(f"policy P\nversion {version}\n")
    assert excinfo.value.line == 2


def test_policy_keyword_needs_a_word_boundary():
    with pytest.raises(KlvError):
        parse("policyX P\n")
