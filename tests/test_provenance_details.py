"""What the record's verifier and journal say, and exactly how the chain is computed.

Mutation testing changed ``provenance.py`` in 928 small ways and the suite noticed 653. The
rest fell into a few groups, and they are the ones that matter most in a module whose whole job
is to be believed by someone else:

* the verifier was tested for *failing*, never for *why*: ``problems.append(None)`` went
  unnoticed, though the explanation is what an auditor reads;
* nothing pinned how the hash chain and the signature are computed, so a different
  serialisation would verify against itself and against nothing else;
* the journal reader had one test per outcome, not one per way a file can be wrong;
* the one-page report had no test of its text at all.

``spec/provenance.vector.json`` is a complete signed record with a published test key. A second
implementation of the verifier can check itself against it, and so does this one, with the chain
recomputed here from ``hashlib`` and ``json`` alone, not through the code under test.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

import kelvra.provenance as provenance
from kelvra import (
    Journal,
    JournalError,
    Label,
    Ledger,
    LedgerClosed,
    PrincipalSet,
    journal_to_record,
    read_journal,
    verify,
    verify_record,
)
from kelvra.provenance import check_key, sign

ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILE = ROOT / "spec" / "provenance.vector.json"
VECTOR_KEY = b"kelvra-test-vector-key-0123456789"
RUN_ID = "00000000-0000-4000-8000-000000000001"
FINGERPRINT = "sha256:" + "ab" * 32


# -- a record that is the same on every run ----------------------------------------------------


def _fixed_clock(monkeypatch):
    ticks = iter(f"2026-01-01T00:00:{i:02d}.000+00:00" for i in range(60))
    monkeypatch.setattr(provenance, "_now", lambda: next(ticks))


def build_ledger(monkeypatch, journal: Journal | None = None) -> Ledger:
    _fixed_clock(monkeypatch)
    ledger = Ledger(
        "VectorPolicy",
        1,
        FINGERPRINT,
        run_id=RUN_ID,
        started_at="2026-01-01T00:00:00.000+00:00",
        journal=journal,
    )
    untrusted = Label.confidential("customer", for_purpose="support").untrusted()
    both = Label.confidential("customer", "support_team", for_purpose="support")
    joined = untrusted.join(both)
    reviewed = Label(untrusted.readers, PrincipalSet.of("reviewer"), untrusted.purposes)
    ledger.read("inbox.imap", untrusted)
    ledger.read("crm.record", both)
    ledger.join("agent.plan", ["inbox.imap", "crm.record"], joined)
    ledger.deny(
        "crm.write",
        joined,
        (
            "audience customer,support_team is not permitted to read data readable by customer",
            "sink requires endorsement by reviewer but got untrusted data",
        ),
    )
    ledger.declassify("human_review", untrusted, reviewed, "reviewer", "within")
    ledger.consent("reviewer", True, "dr.martin", "declassify:human_review", untrusted)
    ledger.allow("slack.support_channel", both)
    ledger.refuse("read", "inbox.imap2")
    return ledger


@pytest.fixture
def vector(monkeypatch) -> dict:
    return build_ledger(monkeypatch).to_record(VECTOR_KEY)


def test_the_published_test_vector_is_what_the_code_produces(vector):
    on_disk = json.loads(VECTOR_FILE.read_text(encoding="utf-8"))
    assert on_disk == vector, "regenerate spec/provenance.vector.json and say why in the CHANGELOG"


def test_the_vector_verifies_with_its_published_key_and_not_with_another(vector):
    result = verify_record(vector, VECTOR_KEY)
    assert result.ok is True and result.signed is True and result.legacy is False
    assert result.problems == ()
    assert verify(vector, VECTOR_KEY) is True
    assert verify(vector, b"another-key-0123456789abcdef") is False


def _digest(obj) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def test_the_chain_is_what_the_specification_says_recomputed_without_the_code(vector):
    """provenance.md section 6.1, written out with hashlib and json and nothing of ours."""
    genesis = _digest(
        {
            "genesis": True,
            "policy": vector["policy"]["fingerprint"],
            "run_id": vector["run_id"],
            "started_at": vector["started_at"],
        }
    )
    previous = genesis
    for index, event in enumerate(vector["events"]):
        assert event["seq"] == index
        assert event["prev"] == previous
        previous = _digest(event)
    assert vector["chain_head"] == previous
    assert vector["events"][0]["prev"] == genesis


def test_the_signature_is_what_the_specification_says_recomputed_without_the_code(vector):
    body = {k: v for k, v in vector.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expected = "hmac-sha256:" + hmac.new(VECTOR_KEY, canonical, hashlib.sha256).hexdigest()
    assert vector["signature"] == expected
    assert sign(body, VECTOR_KEY) == expected == sign(vector, VECTOR_KEY)  # signature excluded


def test_the_summary_counts_each_kind_of_event(vector):
    assert vector["summary"] == {
        "sources_read": 2,
        "declassifications": 1,
        "consents": 1,
        "allowed": 1,
        "denied": 1,
        "refused": 1,
    }
    assert [e["kind"] for e in vector["events"]] == [
        "read", "read", "join", "deny", "declassify", "consent", "allow", "refuse",
    ]  # fmt: skip


# -- why a record is rejected, in the words an auditor reads -----------------------------------


def _break(record: dict, how: str) -> dict:
    r = copy.deepcopy(record)
    if how == "no run_id":
        del r["run_id"]
    elif how == "policy":
        r["policy"] = {"name": "x"}
    elif how == "summary not object":
        r["summary"] = []
    elif how == "events not list":
        r["events"] = {}
    elif how == "bad kind":
        r["events"][3]["kind"] = "teleport"
    elif how == "event not object":
        r["events"][2] = 5
    elif how == "summary count":
        r["summary"]["denied"] = 9
    elif how == "summary bool":
        r["summary"]["denied"] = True
    elif how == "summary field set":
        del r["summary"]["refused"]
    elif how == "out of sequence":
        r["events"][4]["seq"] = 9
    elif how == "wrong prev":
        r["events"][5]["prev"] = "sha256:" + "0" * 64
    elif how == "chain head":
        r["chain_head"] = "sha256:" + "0" * 64
    elif how == "no signature":
        del r["signature"]
    elif how == "bad signature":
        r["signature"] = "hmac-sha256:" + "0" * 64
    elif how == "non-ascii signature":
        r["signature"] = "hmac-sha256:" + chr(0xE9)
    return r


@pytest.mark.parametrize(
    "how,fragment",
    [
        ("no run_id", "run_id is missing or not a string"),
        ("policy", "policy is missing or malformed"),
        ("summary not object", "summary is missing or not an object"),
        ("events not list", "events is missing or not a list"),
        ("bad kind", "event 3 is malformed or of an unknown kind"),
        ("event not object", "event 2 is malformed or of an unknown kind"),
        ("summary count", "summary.denied disagrees with the events"),
        ("summary bool", "summary.denied disagrees with the events"),
        ("summary field set", "summary does not have the fields of its format version"),
        ("out of sequence", "event 4 is out of sequence (event removed, added or moved)"),
        ("wrong prev", "event 5 does not follow the previous event's hash"),
        ("chain head", "chain_head does not match the last event (record truncated or extended)"),
        ("no signature", "signature is missing or malformed"),
        ("bad signature", "signature does not match"),
        ("non-ascii signature", "signature is missing or malformed"),
    ],
)
def test_a_rejection_says_what_is_wrong(vector, how, fragment):
    result = verify_record(_break(vector, how), VECTOR_KEY)
    assert result.ok is False and result.signed is False
    assert fragment in result.problems, result.problems
    assert all(isinstance(p, str) and p for p in result.problems)


def test_a_record_that_is_not_an_object_is_refused_with_its_reason():
    for value in ([], "text", None, 5, 1.5):
        result = verify_record(value)
        assert result.ok is False and result.problems == ("record is not an object",)
        assert result.signed is False and result.legacy is False


@pytest.mark.parametrize("key", ["text", b"", None, 5])
def test_an_unusable_verification_key_is_named_as_the_problem(vector, key):
    result = verify_record(vector, key if key is not None else b"")
    assert result.ok is False
    assert "the verification key must be non-empty bytes" in result.problems


def test_asking_for_both_kinds_of_check_is_refused_in_so_many_words(vector):
    result = verify_record(vector, VECTOR_KEY, public_key=b"p" * 32)
    assert result.ok is False and result.signed is False
    assert result.problems == ("give an HMAC key or an Ed25519 public key, not both",)


def test_without_a_key_a_good_record_is_ok_but_not_signed(vector):
    result = verify_record(vector)
    assert result.ok is True and result.signed is False and result.problems == ()
    assert bool(result) is True


def test_a_signature_that_matches_a_record_that_is_otherwise_wrong_is_not_signed(vector):
    broken = _break(vector, "summary count")
    broken["signature"] = sign(broken, VECTOR_KEY)  # the signer vouches for a lie
    result = verify_record(broken, VECTOR_KEY)
    assert result.ok is False and result.signed is False
    assert result.problems == ("summary.denied disagrees with the events",)


def test_the_legacy_format_is_recognised_by_its_version_and_only_that(vector):
    legacy = copy.deepcopy(vector)
    legacy["kelvra_version"] = "0.1.9"
    result = verify_record(legacy)
    assert result.legacy is True and result.ok is False  # the 0.2 fields do not belong in 0.1
    assert verify_record(vector).legacy is False
    assert verify_record({"kelvra_version": 1}).legacy is False


def test_a_record_that_makes_the_verifier_itself_fail_is_reported_not_raised():
    class Hostile(dict):
        def get(self, *args):
            raise RuntimeError("boom")

    result = verify_record(Hostile())
    assert result.ok is False and result.problems == ("record could not be checked: RuntimeError",)


# -- keys --------------------------------------------------------------------------------------


def test_a_signing_key_is_checked_with_a_message_that_says_what_to_change():
    with pytest.raises(TypeError, match=r"signing_key must be bytes, not str"):
        check_key("text")
    with pytest.raises(ValueError, match=r"signing_key is 15 bytes; at least 16 are required"):
        check_key(b"x" * 15)
    with pytest.raises(ValueError, match=r"\$KELVRA is 3 bytes"):
        check_key(b"abc", "$KELVRA")
    assert check_key(b"x" * 16) == b"x" * 16
    assert check_key(bytearray(b"y" * 16)) == b"y" * 16 and isinstance(
        check_key(bytearray(b"y" * 16)), bytes
    )


def test_signing_refuses_a_key_that_is_not_bytes_or_is_empty():
    for key in ("text", b"", None, 5):
        with pytest.raises(TypeError, match="the signing key must be non-empty bytes"):
            sign({"a": 1}, key)
    assert sign({"a": 1}, bytearray(b"k" * 16)).startswith("hmac-sha256:")


# -- the one-page report -----------------------------------------------------------------------


def test_the_report_an_auditor_reads_is_exactly_this(monkeypatch):
    lines = build_ledger(monkeypatch).summary_lines()
    assert lines == [
        "policy   VectorPolicy v1",
        f"run      {RUN_ID}",
        "sources  2 read",
        "declassified via:",
        "           - human_review",
        "DENIED   1 flow(s):",
        "           x crm.write: audience customer,support_team is not permitted to read data "
        "readable by customer",
        "REFUSED  1 use(s) of something undeclared:",
        "           x read 'inbox.imap2'",
    ]


def test_a_quiet_run_says_so_in_plain_words():
    ledger = Ledger("P", 3, FINGERPRINT, run_id="r")
    assert ledger.summary_lines() == [
        "policy   P v3",
        "run      r",
        "sources  0 read",
        "declassified: none",
        "denied   none",
    ]


# -- what each kind of event holds -------------------------------------------------------------


def test_every_kind_of_event_holds_exactly_the_fields_the_schema_names(vector):
    by_kind = {e["kind"]: e for e in vector["events"]}
    common = {"kind", "at", "seq", "prev"}
    assert set(by_kind["read"]) == common | {"source", "label"}
    assert set(by_kind["join"]) == common | {"site", "inputs", "result"}
    assert set(by_kind["deny"]) == common | {"sink", "label", "reasons"}
    assert set(by_kind["allow"]) == common | {"sink", "label"}
    assert set(by_kind["declassify"]) == common | {
        "declassifier", "before", "after", "consent_from", "from_check",
    }  # fmt: skip
    assert set(by_kind["consent"]) == common | {
        "principal", "granted", "granted_by", "context", "label",
    }  # fmt: skip
    assert by_kind["refuse"]["operation"] == "read" and by_kind["refuse"]["reason"] == "undeclared"
    assert by_kind["consent"]["granted_by"] == "dr.martin" and by_kind["consent"]["granted"] is True
    assert by_kind["declassify"]["consent_from"] == "reviewer"
    assert by_kind["declassify"]["from_check"] == "within"


def test_a_name_that_was_never_declared_is_cut_at_a_hundred_and_twenty_characters(monkeypatch):
    _fixed_clock(monkeypatch)
    ledger = Ledger("P", 1, FINGERPRINT, run_id="r")
    ledger.refuse("read", "x" * 500)
    ledger.deny("y" * 500, Label(), ("no",))
    refuse, deny = (e.detail for e in ledger.events)
    assert refuse["name"] == "x" * 120 + "..."
    assert deny["sink"] == "y" * 120 + "..."
    ledger.refuse("read", "z" * 120)  # exactly the limit is kept whole
    assert ledger.events[-1].detail["name"] == "z" * 120


def test_closing_the_record_closes_the_ledger_and_says_which_run(monkeypatch):
    ledger = build_ledger(monkeypatch)
    first = ledger.to_record(VECTOR_KEY)
    for action in (lambda: ledger.read("s", Label()), ledger.ensure_open):
        with pytest.raises(LedgerClosed, match=RUN_ID):
            action()
    assert ledger.to_record(VECTOR_KEY) == first
    assert json.loads(ledger.to_json(VECTOR_KEY)) == first
    assert ledger.ended_at == first["ended_at"]


def test_an_event_hands_out_copies_so_nobody_can_edit_what_will_be_signed(monkeypatch):
    ledger = build_ledger(monkeypatch)
    event = ledger.events[0]
    event.detail["source"] = "edited"
    event.to_json()["label"]["readers"].append("edited")
    assert ledger.events[0].detail["source"] == "inbox.imap"
    assert "edited" not in ledger.events[0].to_json()["label"]["readers"]
    assert ledger.of_kind("deny")[0].seq == 3
    assert ledger.declassification_count == 1 and ledger.denial_count == 1


# -- the journal: every way a file can be wrong ------------------------------------------------


def write_journal(tmp_path: Path, monkeypatch, *, finish=True) -> Path:
    path = tmp_path / "run.jsonl"
    ledger = build_ledger(monkeypatch, Journal(path))
    if finish:
        ledger.to_record(VECTOR_KEY)
    return path


def _lines(path: Path) -> list[str]:
    return path.read_bytes().decode("utf-8").split("\n")


def _put(path: Path, lines: list[str]) -> None:
    path.write_bytes("\n".join(lines).encode("utf-8"))


def test_a_finished_journal_reads_back_as_exactly_what_was_written(tmp_path, monkeypatch):
    path = write_journal(tmp_path, monkeypatch)
    contents = read_journal(path)
    assert contents.ok is True and contents.complete is True and contents.problems == ()
    assert contents.header["kelvra_journal"] == "0.2.0" and contents.header["run_id"] == RUN_ID
    assert contents.header["policy"] == {
        "name": "VectorPolicy", "version": 1, "fingerprint": FINGERPRINT,
    }  # fmt: skip
    assert contents.header["started_at"] == "2026-01-01T00:00:00.000+00:00"
    assert len(contents.events) == 8 and isinstance(contents.events, tuple)
    assert contents.footer == {
        "ended_at": "2026-01-01T00:00:08.000+00:00",
        "chain_head": contents.events and _digest(contents.events[-1]),
        "events": 8,
    }


def test_the_record_rebuilt_from_a_journal_is_the_published_vector(tmp_path, monkeypatch):
    path = write_journal(tmp_path, monkeypatch)
    assert journal_to_record(path, VECTOR_KEY) == json.loads(VECTOR_FILE.read_text("utf-8"))
    unsigned = journal_to_record(path)
    assert "signature" not in unsigned and verify_record(unsigned).ok is True


@pytest.mark.parametrize(
    "damage,problem,ok",
    [
        ("missing", "cannot read journal:", False),
        ("not json", "line 3 is not valid JSON", False),
        ("not object", "line 2 is not an object", False),
        ("no header", "the header line is missing", False),
        ("empty", "the header line is missing", False),
        ("torn", "the last line is incomplete (the process stopped mid-write)", False),
        ("chain", "event 1 breaks the chain", False),
        ("genesis", "the header's genesis value does not match its run", False),
        ("no end", "no end line: the run did not finish (crash, or still running)", True),
        ("end disagrees", "the end line does not agree with the events", False),
        ("bad header", "the header is malformed:", False),
    ],
)
def test_each_way_a_journal_can_be_wrong_is_named(tmp_path, monkeypatch, damage, problem, ok):
    path = write_journal(tmp_path, monkeypatch)
    lines = _lines(path)
    if damage == "missing":
        path = tmp_path / "does-not-exist.jsonl"
    elif damage == "not json":
        lines[2] = "{not json"
        _put(path, lines)
    elif damage == "not object":
        lines[1] = "[1,2]"
        _put(path, lines)
    elif damage == "no header":
        _put(path, lines[1:])
    elif damage == "empty":
        path.write_bytes(b"")
    elif damage == "torn":
        path.write_bytes(path.read_bytes()[:-10])
    elif damage == "chain":
        lines[2], lines[3] = lines[3], lines[2]
        _put(path, lines)
    elif damage == "genesis":
        header = json.loads(lines[0])
        header["genesis"] = "sha256:" + "0" * 64
        lines[0] = json.dumps(header)
        _put(path, lines)
    elif damage == "no end":
        _put(path, [*lines[:-2], ""])
    elif damage == "end disagrees":
        footer = json.loads(lines[-2])
        footer["end"]["events"] = 99
        lines[-2] = json.dumps(footer)
        _put(path, lines)
    elif damage == "bad header":
        lines[0] = json.dumps({"kelvra_journal": "0.2.0"})
        _put(path, lines)
    contents = read_journal(path)
    assert contents.ok is ok and contents.complete is False
    assert any(p.startswith(problem) for p in contents.problems), contents.problems
    assert isinstance(contents.header, dict) and isinstance(contents.events, tuple)
    if not ok:
        with pytest.raises(JournalError, match="not a complete, intact run"):
            journal_to_record(path)


def test_a_torn_last_line_leaves_the_events_before_it_readable(tmp_path, monkeypatch):
    path = write_journal(tmp_path, monkeypatch, finish=False)
    path.write_bytes(path.read_bytes()[:-7])
    contents = read_journal(path)
    assert contents.ok is False and len(contents.events) == 7
    assert contents.footer is None and contents.header["run_id"] == RUN_ID


def test_a_complete_journal_names_what_is_missing_when_asked_for_a_record(tmp_path, monkeypatch):
    path = write_journal(tmp_path, monkeypatch, finish=False)
    with pytest.raises(JournalError) as excinfo:
        journal_to_record(path)
    assert "no end line" in str(excinfo.value)


# -- the journal: how it writes ----------------------------------------------------------------


def test_the_journal_file_is_one_header_one_line_per_event_and_an_end(tmp_path, monkeypatch):
    path = write_journal(tmp_path, monkeypatch)
    lines = [ln for ln in _lines(path) if ln]
    assert len(lines) == 1 + 8 + 1
    header, *events, footer = [json.loads(ln) for ln in lines]
    assert list(header) == sorted(header)  # canonical, sorted keys
    assert set(header) == {"genesis", "kelvra_journal", "policy", "run_id", "started_at"}
    assert set(footer) == {"end"} and set(footer["end"]) == {"ended_at", "chain_head", "events"}
    assert [e["seq"] for e in events] == list(range(8))
    canonical = (json.dumps(json.loads(ln), sort_keys=True, separators=(",", ":")) for ln in lines)
    assert list(canonical) == lines


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_journal_is_created_private_to_its_owner(tmp_path):
    path = tmp_path / "j.jsonl"
    Journal(path).begin({"kelvra_journal": "0.2.0"})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_partial_write_is_finished_not_lost(tmp_path):
    path = tmp_path / "j.jsonl"
    journal = Journal(path)
    journal.begin({"kelvra_journal": "0.2.0", "padding": "x" * 50})
    real = os.write
    calls = []

    def stingy(fd, data):
        calls.append(len(data))
        return real(fd, data[:5] if fd == journal._fd else data)

    with mock.patch.object(provenance.os, "write", stingy):
        journal.append({"kind": "read", "n": "y" * 40})
    assert len(calls) > 3  # it took several writes
    last = [ln for ln in _lines(path) if ln][-1]
    assert json.loads(last) == {"kind": "read", "n": "y" * 40}


def test_a_failed_write_is_a_journal_error_that_names_the_file(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    journal.begin({"kelvra_journal": "0.2.0"})
    with mock.patch.object(provenance.os, "write", side_effect=OSError("disk full")):
        with pytest.raises(JournalError, match=r"cannot write journal .*j\.jsonl.*disk full"):
            journal.append({"x": 1})


def test_a_journal_that_cannot_be_created_says_where_and_why(tmp_path):
    with pytest.raises(JournalError, match=r"cannot create journal .*nope.*j\.jsonl"):
        Journal(tmp_path / "nope" / "j.jsonl").begin({"x": 1})
    existing = tmp_path / "there.jsonl"
    existing.write_text("keep me", encoding="utf-8")
    with pytest.raises(JournalError, match="cannot create journal"):
        Journal(existing).begin({"x": 1})
    assert existing.read_text(encoding="utf-8") == "keep me"


def test_a_journal_that_has_ended_or_never_begun_refuses_writes(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    with pytest.raises(JournalError, match=r"journal .*j\.jsonl.* is closed"):
        journal.append({"x": 1})
    journal.begin({"x": 1})
    journal.end({"done": True})
    with pytest.raises(JournalError, match="is closed"):
        journal.append({"x": 2})


def test_a_durable_journal_asks_the_operating_system_to_flush_each_line(tmp_path):
    synced = []
    journal = Journal(tmp_path / "d.jsonl", durable=True)
    with mock.patch.object(provenance.os, "fsync", lambda fd: synced.append(fd)):
        journal.begin({"x": 1})
        journal.append({"y": 2})
        journal.end({"z": 3})
    assert len(synced) == 3
    lazy = Journal(tmp_path / "l.jsonl")
    with mock.patch.object(provenance.os, "fsync", lambda fd: synced.append(fd)):
        lazy.begin({"x": 1})
        lazy.append({"y": 2})
    assert len(synced) == 3  # a journal that was not asked to be durable did not sync
    assert journal.durable is True and lazy.durable is False


def test_an_event_that_cannot_be_journalled_is_not_recorded(tmp_path, monkeypatch):
    ledger = build_ledger(monkeypatch, Journal(tmp_path / "j.jsonl"))
    before = (len(ledger.events), ledger._head)
    with mock.patch.object(provenance.os, "write", side_effect=OSError("gone")):
        with pytest.raises(JournalError):
            ledger.allow("late", Label())
    assert (len(ledger.events), ledger._head) == before
