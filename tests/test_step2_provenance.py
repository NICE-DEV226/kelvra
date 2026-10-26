"""Format 0.2 of the provenance record: chain, closing, verification, consent identity.

Written from the falsification cases the audit lists for a log: deletion,
reordering, duplication, truncation, replay between runs, and a verifier fed
hostile input.
"""

import copy
import random
import threading

import pytest

from kelvra import (
    FORMAT_VERSION,
    ConsentDecision,
    ConsentRefused,
    Denied,
    Kelvra,
    LedgerClosed,
    approved_by,
    parse,
    verify,
    verify_record,
)
from kelvra.provenance import sign

KEY = b"0123456789abcdef0123456789abcdef"

POLICY = """\
policy P
principal a, b, rev
source s_a
    confidential(a)
source s_b
    confidential(b)
sink out_a
    accepts confidential(a)
sink gated
    accepts confidential(a)
    requires consent(a)
"""


def run(consent=None, **kw) -> Kelvra:
    return Kelvra(parse(POLICY), signing_key=KEY, consent=consent or approved_by("dr-test"), **kw)


def busy_record() -> dict:
    k = run()
    a = k.read("s_a", "x")
    b = k.read("s_b", "y")
    k.emit("out_a", a)
    k.emit("gated", a)
    with pytest.raises(Denied):
        k.emit("out_a", b)
    with pytest.raises(LookupError):
        k.emit("mail.attacker", a)
    return k.record()


# -- the chain --------------------------------------------------------------


def test_a_fresh_record_verifies_keyless_and_keyed():
    rec = busy_record()
    assert rec["kelvra_version"] == FORMAT_VERSION
    assert verify_record(rec).ok
    keyed = verify_record(rec, KEY)
    assert keyed.ok and keyed.signed and not keyed.legacy
    assert verify(rec, KEY)


def test_events_carry_a_sequence_and_the_hash_of_their_predecessor():
    events = busy_record()["events"]
    assert [e["seq"] for e in events] == list(range(len(events)))
    assert len({e["prev"] for e in events}) == len(events)


@pytest.mark.parametrize("victim", [0, 2, -1])
def test_deleting_an_event_is_detected_without_the_key(victim):
    rec = busy_record()
    del rec["events"][victim]
    assert not verify_record(rec).ok


def test_reordering_is_detected_without_the_key():
    rec = busy_record()
    rec["events"][1], rec["events"][2] = rec["events"][2], rec["events"][1]
    assert not verify_record(rec).ok


def test_duplicating_an_event_is_detected_without_the_key():
    rec = busy_record()
    rec["events"].insert(2, copy.deepcopy(rec["events"][1]))
    assert not verify_record(rec).ok


def test_truncating_the_tail_is_detected_without_the_key():
    rec = busy_record()
    rec["events"] = rec["events"][:-2]
    assert not verify_record(rec).ok


def test_editing_an_event_in_place_is_detected_without_the_key():
    rec = busy_record()
    rec["events"][0]["source"] = "somewhere.innocent"
    assert not verify_record(rec).ok


def test_a_record_spliced_into_another_run_is_detected():
    one, two = busy_record(), busy_record()
    two["events"] = one["events"]
    two["chain_head"] = one["chain_head"]
    assert not verify_record(two).ok


def test_a_consistent_rewrite_without_the_key_still_fails_the_signature():
    """Recomputing the whole chain defeats the chain; only the key stops it."""
    rec = busy_record()
    forged = copy.deepcopy(rec)
    forged["events"] = [e for e in forged["events"] if e["kind"] != "deny"]
    assert not verify(forged, KEY)


# -- closing ----------------------------------------------------------------


def test_one_run_has_one_record():
    k = run()
    k.emit("out_a", k.read("s_a", "x"))
    assert k.record() == k.record()


def test_nothing_can_be_recorded_after_the_record_is_produced():
    k = run()
    a = k.read("s_a", "x")
    k.record()
    for action in (
        lambda: k.read("s_a", "y"),
        lambda: k.emit("out_a", a),
        lambda: k.model_call("m", a),
        lambda: k.combine("c", a),
    ):
        with pytest.raises(LedgerClosed):
            action()


def test_a_closed_ledger_does_not_ask_for_consent_first():
    asked = []
    k = run(consent=lambda p, c: asked.append(c) or ConsentDecision(True, "dr-test"))
    a = k.read("s_a", "x")
    k.record()
    with pytest.raises(LedgerClosed):
        k.emit("gated", a)
    assert asked == []


def test_events_cannot_be_edited_through_the_ledger():
    k = run()
    k.read("s_a", "x")
    events = k.ledger.events
    assert isinstance(events, tuple)
    events[0].detail["source"] = "other"  # edits a copy
    assert k.ledger.events[0].detail["source"] == "s_a"
    with pytest.raises(AttributeError):
        events[0].kind = "deny"  # type: ignore[misc]
    k.record()
    assert verify(k.record(), KEY)


# -- verification of hostile input -------------------------------------------


def test_verify_never_raises_on_arbitrary_json_shapes():
    rng = random.Random(4)
    base = busy_record()

    def mutate(value, depth=0):
        r = rng.random()
        if r < 0.15:
            return rng.choice([None, 0, -1, 1.5, "", "é", [], {}, True, "x" * 50, float("nan")])
        if isinstance(value, dict) and depth < 4:
            out = {k: mutate(v, depth + 1) if rng.random() < 0.3 else v for k, v in value.items()}
            if rng.random() < 0.1 and out:
                out.pop(rng.choice(list(out)))
            return out
        if isinstance(value, list) and depth < 4:
            return [mutate(v, depth + 1) if rng.random() < 0.3 else v for v in value]
        return value

    for _ in range(3000):
        rec = mutate(copy.deepcopy(base))
        verify_record(rec, KEY)
        verify_record(rec)
        assert verify(rec, KEY) in (True, False)


@pytest.mark.parametrize("key", ["text", None, b"", 12, object()])
def test_verify_with_an_unusable_key_is_false_not_an_exception(key):
    assert verify(busy_record(), key) is False


def test_a_lying_summary_is_rejected_even_when_resigned():
    rec = busy_record()
    rec["summary"]["denied"] = 0
    rec["signature"] = sign(rec, KEY)
    result = verify_record(rec, KEY)
    assert not result.ok and any("summary.denied" in p for p in result.problems)


def test_a_missing_signature_is_not_a_verified_one():
    rec = busy_record()
    del rec["signature"]
    assert verify_record(rec).ok  # structurally sound
    assert not verify(rec, KEY)  # but nobody vouches for it


# -- format 0.1 --------------------------------------------------------------


def legacy_record() -> dict:
    rec = {
        "kelvra_version": "0.1.0",
        "policy": {"name": "P", "version": 1, "fingerprint": "sha256:" + "0" * 64},
        "run_id": "r",
        "started_at": "2026-01-01T00:00:00.000+00:00",
        "ended_at": "2026-01-01T00:00:01.000+00:00",
        "summary": {
            "sources_read": 1,
            "declassifications": 0,
            "consents": 0,
            "allowed": 0,
            "denied": 0,
        },
        "events": [
            {
                "kind": "read",
                "at": "2026-01-01T00:00:00.500+00:00",
                "source": "s_a",
                "label": {"readers": ["a"], "endorsers": "*", "purposes": "*"},
            }
        ],
    }
    rec["signature"] = sign(rec, KEY)
    return rec


def test_a_format_0_1_record_is_accepted_and_marked_legacy():
    result = verify_record(legacy_record(), KEY)
    assert result.ok and result.signed and result.legacy


def test_a_legacy_record_is_still_checked_for_summary_and_signature():
    rec = legacy_record()
    rec["summary"]["sources_read"] = 5
    assert not verify_record(rec, KEY).ok
    rec = legacy_record()
    rec["events"][0]["source"] = "x"
    assert not verify(rec, KEY)


def test_a_0_2_record_cannot_pass_as_legacy_to_skip_the_chain():
    rec = busy_record()
    rec["kelvra_version"] = "0.1.0"
    assert not verify_record(rec).ok  # summary has 'refused' that 0.1 does not


# -- refusals are recorded ---------------------------------------------------


def test_an_undeclared_sink_leaves_a_deny_event_with_the_label():
    k = run()
    with pytest.raises(LookupError):
        k.emit("mail.evil@example.com", k.read("s_a", "x"))
    deny = k.ledger.of_kind("deny")[0].detail
    assert deny["sink"] == "mail.evil@example.com"
    assert deny["label"]["readers"] == ["a"]
    assert "not declared" in deny["reasons"][0]


def test_undeclared_source_and_declassifier_leave_refuse_events():
    k = run()
    with pytest.raises(LookupError):
        k.read("nope", "x")
    with pytest.raises(LookupError):
        k.declassify("nope", k.read("s_a", "x"))
    ops = [(e.detail["operation"], e.detail["name"]) for e in k.ledger.of_kind("refuse")]
    assert ops == [("read", "nope"), ("declassify", "nope")]
    assert k.record()["summary"]["refused"] == 2


def test_an_undeclared_name_cannot_smuggle_a_payload_into_the_record():
    k = run()
    secret = "S" * 5000
    with pytest.raises(LookupError):
        k.emit("mail." + secret, k.read("s_a", "x"))
    recorded = k.ledger.of_kind("deny")[0].detail["sink"]
    assert len(recorded) < 130 and secret not in recorded


def test_the_summary_report_mentions_refusals():
    k = run()
    with pytest.raises(LookupError):
        k.read("nope", "x")
    assert "REFUSED" in k.report()


# -- model_call(via=...) ------------------------------------------------------


def test_a_model_call_is_authorised_once_for_its_joined_inputs():
    asked = []
    src = POLICY + "sink llm\n    accepts confidential(a)\n    requires consent(a)\n"
    k = Kelvra(
        parse(src),
        consent=lambda p, c: asked.append(c) or ConsentDecision(True, "dr-test"),
    )
    ins = [k.read("s_a", i) for i in range(3)]
    k.model_call("agent", *ins, via="llm")
    assert len(asked) == 1
    assert len(k.ledger.of_kind("allow")) == 1


def test_a_refused_model_call_records_one_deny_and_no_allow():
    src = POLICY + "sink llm\n    accepts confidential(a)\n"
    k = Kelvra(parse(src))
    sent = []
    with pytest.raises(Denied):
        k.model_call(
            "agent",
            k.read("s_a", 1),
            k.read("s_b", 2),
            produce=lambda *a: sent.append(a),
            via="llm",
        )
    assert not sent
    assert len(k.ledger.of_kind("deny")) == 1 and not k.ledger.of_kind("allow")


# -- consent identity ---------------------------------------------------------


def test_the_decider_is_recorded_with_the_data_label():
    k = run()
    k.emit("gated", k.read("s_a", "x"))
    consent = k.ledger.of_kind("consent")[0].detail
    assert consent["granted_by"] == "dr-test" and consent["granted"] is True
    assert consent["label"]["readers"] == ["a"]


def test_a_grant_without_an_identity_is_not_a_grant():
    for decision in (
        True,
        ConsentDecision(True, ""),
        ConsentDecision(True, " x "),
        ConsentDecision(True, "a\nb"),
        ConsentDecision(True, "x" * 200),
    ):
        k = run(consent=lambda p, c, d=decision: d)
        with pytest.raises(TypeError):
            k.emit("gated", k.read("s_a", "x"))
        assert k.ledger.of_kind("consent")[0].detail["granted"] is False


def test_an_agent_service_account_cannot_approve_its_own_output():
    k = run(consent=approved_by("svc-agent"), service_identities={"svc-agent"})
    with pytest.raises(ConsentRefused, match="self-approval"):
        k.emit("gated", k.read("s_a", "x"))
    consent = k.ledger.of_kind("consent")[0].detail
    assert consent["granted"] is False and consent["granted_by"] == "svc-agent"


def test_a_named_refusal_keeps_the_refusers_identity():
    k = run(consent=lambda p, c: ConsentDecision(False, "dr-no"))
    with pytest.raises(ConsentRefused):
        k.emit("gated", k.read("s_a", "x"))
    assert k.ledger.of_kind("consent")[0].detail["granted_by"] == "dr-no"


# -- concurrency --------------------------------------------------------------


def test_concurrent_writers_produce_one_consistent_chain():
    k = run()
    a = k.read("s_a", "x")

    def worker():
        for _ in range(300):
            k.emit("out_a", a)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rec = k.record()
    assert rec["summary"]["allowed"] == 1800
    assert verify(rec, KEY)


def test_records_taken_while_another_thread_appends_are_always_consistent():
    k = run()
    stop = threading.Event()
    a = k.read("s_a", "x")

    def writer():
        n = 0
        while not stop.is_set() and n < 20_000:
            try:
                k.emit("out_a", a)
            except LedgerClosed:
                return
            n += 1

    t = threading.Thread(target=writer)
    t.start()
    try:
        rec = k.record()  # closes the ledger while the writer is mid-flight
    finally:
        stop.set()
        t.join()
    assert verify(rec, KEY)
    assert k.record() == rec
