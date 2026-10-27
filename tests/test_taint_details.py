"""What the enforcement layer does with what it is handed, beyond allow and deny.

Mutation testing of ``taint.py`` (371 mutants, 61 survivors) found the decisions themselves
well covered and the plumbing around them not: that a ``transform`` is actually applied, that the
consent provider is told *who* is asked and *about what*, which origin and site the ledger
receives, that ``signer`` and ``signing_key`` together are refused, where the unsigned-record
warning points, and the exact edges of a usable identity. None of these changes an allow into a
deny, which is why nothing noticed; each changes what an auditor reads or what an integrator
gets.
"""

from __future__ import annotations

import warnings

import pytest

from kelvra import (
    ConsentDecision,
    ConsentRefused,
    Denied,
    Kelvra,
    UnsignedRecordWarning,
    parse,
    verify_record,
)
from kelvra.provenance import MIN_KEY_BYTES

KEY = b"k" * MIN_KEY_BYTES

POLICY = """\
policy P
principal a, b, rev
source s_a
    confidential(a)
    integrity trusted
sink out_a
    accepts confidential(a)
sink out_ab
    accepts confidential(a, b)
sink gated
    accepts confidential(a)
    requires consent(rev)
declassify widen
    from confidential(a)
    to confidential(a, b)
    requires consent(rev)
    audit always
declassify widen_free
    from confidential(a)
    to confidential(a, b)
    audit always
"""


def make(**kwargs) -> Kelvra:
    kwargs.setdefault("signing_key", KEY)
    return Kelvra(parse(POLICY), **kwargs)


class Recorder:
    """A consent provider that remembers what it was asked."""

    def __init__(self, answer):
        self.answer = answer
        self.calls: list[tuple[object, object]] = []

    def __call__(self, principal, context):
        self.calls.append((principal, context))
        return self.answer


def events(k: Kelvra, kind: str):
    return [e.to_json() for e in k.ledger.of_kind(kind)]


# -- the transform is applied, and only when the declassification is taken ---------------------


def test_declassify_applies_the_transform_to_the_value_and_not_otherwise():
    k = make()
    out = k.declassify("widen_free", k.read("s_a", "secret"), lambda v: v.upper())
    assert out.unsafe_value == "SECRET"
    unchanged = k.declassify("widen_free", k.read("s_a", "secret"))
    assert unchanged.unsafe_value == "secret"


def test_a_transform_is_not_run_when_the_declassification_is_refused():
    k = make(consent=Recorder(False))
    ran = []
    with pytest.raises(ConsentRefused):
        k.declassify("widen", k.read("s_a", "x"), lambda v: ran.append(v))
    assert ran == []


def test_declassify_hands_the_transform_the_raw_value_and_returns_what_it_returns():
    k = make()
    seen = []

    def transform(value):
        seen.append(value)
        return {"redacted": True}

    out = k.declassify("widen_free", k.read("s_a", ["a", "b"]), transform)
    assert seen == [["a", "b"]] and out.unsafe_value == {"redacted": True}


# -- the origin an auditor follows -------------------------------------------------------------


def test_the_origin_of_a_derived_value_names_each_step_that_made_it():
    k = make()
    base = k.read("s_a", 1)
    assert base.origin == "s_a"
    assert base.map(lambda v: v + 1).origin == "s_a|map"
    assert base.map(lambda v: v + 1, note="double").origin == "s_a|double"
    assert k.declassify("widen_free", base).origin == "s_a|widen_free"
    assert k.model_call("plan", base).origin == "plan"
    assert repr(base) == f"Tainted(s_a: {base.label.describe()})"


def test_mapping_keeps_the_label_and_the_issuer_so_the_value_is_still_this_sessions():
    k = make()
    base = k.read("s_a", 1)
    mapped = base.map(str)
    assert mapped.label == base.label and mapped.unsafe_value == "1"
    assert k.emit("out_a", mapped) == "1"  # still accepted by this session


def test_a_model_call_records_its_site_and_the_origins_it_joined():
    k = make()
    a, b = k.read("s_a", 1), k.read("s_a", 2)
    k.model_call("agent.plan", a, b.map(str, note="text"))
    [join] = events(k, "join")
    assert join["site"] == "agent.plan"
    assert join["inputs"] == ["s_a", "s_a|text"]
    assert join["result"] == a.label.join(b.label).to_json()


def test_combine_records_its_site_and_inputs_and_returns_the_joined_label():
    k = make()
    a = k.read("s_a", 1)
    label = k.combine("merge.step", a, a.map(str))
    assert label == a.label
    [join] = events(k, "join")
    assert join["site"] == "merge.step" and join["inputs"] == ["s_a", "s_a|map"]


def test_the_session_forwards_the_site_and_the_provider_unchanged():
    k = make()
    session = k.agent_session()
    a = session.read("s_a", 1)
    out = session.model_call("site.one", a, produce=lambda v: v + 1, via="out_a")
    assert out.unsafe_value == 2 and out.origin == "site.one"
    session.combine("site.two", a)
    assert [e["site"] for e in events(k, "join")] == ["site.one", "site.two"]
    assert [e["sink"] for e in events(k, "allow")] == ["out_a"]
    assert session.would_allow("out_a", a) is True


def test_a_model_call_without_produce_hands_back_the_raw_inputs_as_a_tuple():
    k = make()
    out = k.model_call("echo", k.read("s_a", 1), k.read("s_a", 2))
    assert out.unsafe_value == (1, 2)


# -- the declassification event says who must agree and whether the source matched -------------


def test_the_declassify_event_names_the_principal_whose_consent_was_required():
    k = make(consent=Recorder(ConsentDecision(True, "dr.martin")))
    k.declassify("widen", k.read("s_a", "x"))
    [event] = events(k, "declassify")
    assert event["declassifier"] == "widen" and event["consent_from"] == "rev"
    k2 = make()
    k2.declassify("widen_free", k2.read("s_a", "x"))
    assert events(k2, "declassify")[0]["consent_from"] is None


# -- what the consent provider is told ---------------------------------------------------------


def test_the_consent_provider_is_told_who_is_asked_and_what_for():
    provider = Recorder(ConsentDecision(True, "dr.martin"))
    k = make(consent=provider)
    k.declassify("widen", k.read("s_a", "x"))
    k.emit("gated", k.read("s_a", "y"))
    assert provider.calls == [("rev", "declassify:widen"), ("rev", "emit:gated")]
    assert [e["context"] for e in events(k, "consent")] == ["declassify:widen", "emit:gated"]
    assert [e["principal"] for e in events(k, "consent")] == ["rev", "rev"]


def test_an_async_provider_is_refused_and_never_leaves_an_unawaited_coroutine(recwarn):
    async def provider(principal, context):
        return ConsentDecision(True, "someone")

    k = make(consent=provider)
    with pytest.raises(TypeError, match="returned an awaitable; consent providers must be sync"):
        k.emit("gated", k.read("s_a", "x"))
    assert not [w for w in recwarn if "never awaited" in str(w.message)]
    assert events(k, "consent")[0]["granted"] is False


def test_an_awaitable_that_is_not_a_coroutine_is_refused_too():
    class Later:
        def __await__(self):
            yield

    k = make(consent=lambda principal, context: Later())
    with pytest.raises(TypeError, match="returned an awaitable"):
        k.emit("gated", k.read("s_a", "x"))


@pytest.mark.parametrize(
    "answer,message",
    [
        (True, "returned a bare True, which names nobody"),
        ("yes", "returned str, expected ConsentDecision or bool"),
        ([0], "returned list, expected ConsentDecision or bool"),
        (1, "returned int, expected ConsentDecision or bool"),
        (ConsentDecision("yes", "dr.martin"), "returned granted=str, expected bool"),
        (ConsentDecision(1, "dr.martin"), "returned granted=int, expected bool"),
        (ConsentDecision(True, ""), "returned a grant without a usable decided_by identity"),
        (ConsentDecision(True, None), "returned a grant without a usable decided_by identity"),
        (ConsentDecision(True, "x" * 129), "returned a grant without a usable decided_by"),
    ],
)
def test_a_provider_that_answers_wrongly_is_an_error_that_says_how(answer, message):
    k = make(consent=lambda principal, context: answer)
    with pytest.raises(TypeError, match=message) as excinfo:
        k.emit("gated", k.read("s_a", "x"))
    assert "'rev'" in str(excinfo.value) and "treated as refused" in str(excinfo.value)
    assert [e["granted"] for e in events(k, "consent")] == [False]
    assert events(k, "allow") == []


def test_an_identity_is_usable_from_one_character_to_the_documented_maximum():
    for identity, usable in (("x", True), ("x" * 128, True), ("", False), ("x" * 129, False)):
        k = make(consent=lambda principal, context, who=identity: ConsentDecision(True, who))
        if usable:
            k.emit("gated", k.read("s_a", "x"))
            assert events(k, "consent")[0]["granted_by"] == identity
        else:
            with pytest.raises(TypeError, match="usable decided_by identity"):
                k.emit("gated", k.read("s_a", "x"))


def test_an_identity_that_is_not_a_clean_string_is_not_usable():
    for identity in (None, 5, b"bytes", "line\nbreak", "tab\there", chr(0x202E) + "evil", " "):
        k = make(consent=lambda principal, context, who=identity: ConsentDecision(True, who))
        with pytest.raises((TypeError, ConsentRefused)):
            k.emit("gated", k.read("s_a", "x"))
        assert events(k, "allow") == []


def test_a_refusal_by_a_named_person_records_who_refused():
    k = make(consent=lambda principal, context: ConsentDecision(False, "dr.martin"))
    with pytest.raises(ConsentRefused, match=r"consent from 'rev' refused for emit:gated$"):
        k.emit("gated", k.read("s_a", "x"))
    [event] = events(k, "consent")
    assert event["granted"] is False and event["granted_by"] == "dr.martin"


def test_a_refusal_by_nobody_records_nobody():
    for answer in (False, None, ConsentDecision(False, "")):
        k = make(consent=lambda principal, context, a=answer: a)
        with pytest.raises(ConsentRefused):
            k.emit("gated", k.read("s_a", "x"))
        assert events(k, "consent")[0]["granted_by"] is None


def test_a_service_identity_cannot_approve_and_the_refusal_names_it():
    k = make(
        consent=lambda principal, context: ConsentDecision(True, "svc-agent"),
        service_identities=["svc-agent"],
    )
    with pytest.raises(ConsentRefused, match=r"'svc-agent', a service identity \(self-approval\)"):
        k.emit("gated", k.read("s_a", "x"))
    [event] = events(k, "consent")
    assert event["granted"] is False and event["granted_by"] == "svc-agent"


# -- keys and signers --------------------------------------------------------------------------


def test_giving_both_a_signer_and_a_key_is_refused():
    pytest.importorskip("cryptography")
    from kelvra.signing import Ed25519Signer, generate_ed25519_keypair

    private, _ = generate_ed25519_keypair()
    signer = Ed25519Signer(private)
    with pytest.raises(ValueError, match="give signing_key or signer, not both"):
        Kelvra(parse(POLICY), signing_key=KEY, signer=signer)
    k = Kelvra(parse(POLICY), signer=signer)
    assert k.signer is signer and k.signing_key is None
    assert Kelvra(parse(POLICY), signing_key=KEY).signer is None


def test_a_key_given_explicitly_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("KELVRA_SIGNING_KEY", "e" * 32)
    assert Kelvra(parse(POLICY), signing_key=KEY).signing_key == KEY
    assert Kelvra(parse(POLICY)).signing_key == b"e" * 32
    monkeypatch.delenv("KELVRA_SIGNING_KEY")
    assert Kelvra(parse(POLICY)).signing_key is None


def test_an_unsigned_record_warns_at_the_caller_and_says_how_to_fix_it(monkeypatch):
    monkeypatch.delenv("KELVRA_SIGNING_KEY", raising=False)
    k = Kelvra(parse(POLICY))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        record = k.record()
    [warning] = caught
    assert issubclass(warning.category, UnsignedRecordWarning)
    assert "pass signing_key= or set KELVRA_SIGNING_KEY" in str(warning.message)
    assert "nothing vouches for it" in str(warning.message)
    assert warning.filename == __file__  # reported where record() was called, not inside kelvra
    assert "signature" not in record


def test_a_signed_record_does_not_warn_and_verifies():
    k = make()
    k.emit("out_a", k.read("s_a", "x"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        record = k.record()
    assert verify_record(record, KEY).signed is True


def test_a_signer_is_used_for_the_record_instead_of_the_key():
    pytest.importorskip("cryptography")
    from kelvra.signing import Ed25519Signer, generate_ed25519_keypair

    private, public = generate_ed25519_keypair()
    k = Kelvra(parse(POLICY), signer=Ed25519Signer(private))
    record = k.record()
    assert record["signature"].startswith("ed25519:")
    assert verify_record(record, public_key=public).signed is True


# -- the journal options reach the journal -----------------------------------------------------


def test_the_journal_is_not_durable_unless_asked_and_is_when_asked(tmp_path):
    lazy = make(journal_path=tmp_path / "lazy.jsonl")
    assert lazy.ledger.journal.durable is False
    durable = make(journal_path=tmp_path / "durable.jsonl", durable_journal=True)
    assert durable.ledger.journal.durable is True
    assert make().ledger.journal is None


# -- what is said when something is not declared -----------------------------------------------


def test_each_undeclared_name_is_refused_with_the_name_and_the_policy():
    k = make()
    a = k.read("s_a", 1)
    with pytest.raises(LookupError, match=r"source 'nope' is not declared in policy 'P'"):
        k.read("nope", 1)
    with pytest.raises(LookupError, match=r"declassifier 'nope' is not declared in policy 'P'"):
        k.declassify("nope", a)
    with pytest.raises(LookupError, match=r"sink 'nope' is not declared in policy 'P'"):
        k.emit("nope", a)
    assert [(e["operation"], e["name"]) for e in events(k, "refuse")] == [
        ("read", "nope"),
        ("declassify", "nope"),
    ]
    assert [e["sink"] for e in events(k, "deny")] == ["nope"]


def test_a_denied_emit_carries_the_decision_and_nothing_leaves():
    k = make()
    with pytest.raises(Denied) as excinfo:
        k.emit("out_ab", k.read("s_a", "x"))  # readable by a only, sink would show it to b
    assert excinfo.value.decision.allowed is False
    assert events(k, "allow") == [] and len(events(k, "deny")) == 1


# -- closing the record ------------------------------------------------------------------------


def test_a_record_that_no_longer_describes_the_policy_is_refused_with_the_reason():
    k = make()
    k.ledger.policy_fingerprint = "sha256:" + "0" * 64
    with pytest.raises(Exception, match="no longer matches the fingerprint recorded at session"):
        k.record()
