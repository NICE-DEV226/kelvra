"""The on-disk journal: written as the run happens, readable after a crash."""

import json
import os
import stat
import sys

import pytest

from kelvra import (
    Denied,
    JournalError,
    Kelvra,
    approved_by,
    journal_to_record,
    parse,
    read_journal,
    verify,
    verify_record,
)

KEY = b"journal-test-key-0123456789abcdef"

POLICY = """\
policy P
principal a, b
source s_a
    confidential(a)
    integrity trusted
source s_b
    confidential(b)
    integrity trusted
sink out
    accepts confidential(a)
sink gated
    accepts confidential(a)
    requires consent(a)
"""


def session(path, **kw) -> Kelvra:
    return Kelvra(
        parse(POLICY), signing_key=KEY, consent=approved_by("dr-test"), journal_path=path, **kw
    )


def busy(k: Kelvra) -> None:
    a = k.read("s_a", "x")
    b = k.read("s_b", "y")
    k.emit("out", a)
    k.emit("gated", a)
    with pytest.raises(Denied):
        k.emit("out", b)
    with pytest.raises(LookupError):
        k.emit("nowhere", a)


def test_a_finished_run_leaves_a_complete_verified_journal(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    k.record()
    contents = read_journal(path)
    assert contents.ok and contents.complete and not contents.problems
    assert len(contents.events) == len(k.ledger.events)


def test_the_record_rebuilt_from_the_journal_is_the_record_the_session_produced(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    live = k.record()
    rebuilt = journal_to_record(path, KEY)
    assert rebuilt == live
    assert verify(rebuilt, KEY)


def test_events_reach_the_file_before_the_run_ends(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    k.read("s_a", "x")
    lines = path.read_bytes().splitlines()
    assert len(lines) == 2  # header + the read
    assert json.loads(lines[1])["kind"] == "read"


def test_a_crashed_run_is_incomplete_but_its_events_are_intact(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)  # no record(): the process "died" here
    contents = read_journal(path)
    assert contents.ok and not contents.complete
    assert any("did not finish" in p for p in contents.problems)
    assert len(contents.events) == len(k.ledger.events)
    with pytest.raises(JournalError, match="not a complete"):
        journal_to_record(path)


def test_a_torn_last_line_is_reported_and_earlier_lines_still_count(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    data = path.read_bytes()
    path.write_bytes(data[:-15])  # cut the last event mid-line
    contents = read_journal(path)
    assert not contents.ok and not contents.complete
    assert any("incomplete" in p for p in contents.problems)
    assert len(contents.events) == len(k.ledger.events) - 1


@pytest.mark.parametrize("damage", ["delete", "reorder", "duplicate", "edit", "truncate-end"])
def test_tampering_with_a_journal_is_detected(tmp_path, damage):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    k.record()
    lines = path.read_bytes().split(b"\n")[:-1]
    body = lines[1:-1]
    if damage == "delete":
        del body[2]
    elif damage == "reorder":
        body[1], body[2] = body[2], body[1]
    elif damage == "duplicate":
        body.insert(2, body[1])
    elif damage == "edit":
        body[0] = body[0].replace(b'"s_a"', b'"s_z"')
    elif damage == "truncate-end":
        del body[-1]
    path.write_bytes(b"\n".join([lines[0], *body, lines[-1]]) + b"\n")
    assert not read_journal(path).complete
    with pytest.raises(JournalError):
        journal_to_record(path)


def test_a_journal_that_lost_its_end_line_cannot_pose_as_finished(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    k.record()
    lines = path.read_bytes().split(b"\n")[:-2]
    path.write_bytes(b"\n".join(lines) + b"\n")
    assert not read_journal(path).complete


def test_an_existing_file_is_never_appended_to(tmp_path):
    path = tmp_path / "run.jsonl"
    path.write_text("precious\n", encoding="utf-8")
    with pytest.raises(JournalError, match="cannot create"):
        session(path)
    assert path.read_text(encoding="utf-8") == "precious\n"


def test_a_run_that_cannot_be_journalled_does_not_start(tmp_path):
    with pytest.raises(JournalError):
        session(tmp_path / "missing-dir" / "run.jsonl")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_journal_is_private_to_its_owner(tmp_path):
    path = tmp_path / "run.jsonl"
    session(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_failed_write_fails_the_operation_instead_of_running_it_unlogged(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    a = k.read("s_a", "x")
    os.close(k.ledger.journal._fd)  # the disk "goes away"
    with pytest.raises(JournalError):
        k.emit("out", a)
    assert not k.ledger.of_kind("allow")  # nothing is recorded as sent


def test_nothing_is_written_after_the_run_ends(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    k.record()
    size = path.stat().st_size
    with pytest.raises(Exception):  # noqa: B017 - LedgerClosed; the point is the file
        k.read("s_a", "late")
    assert path.stat().st_size == size


def test_the_journal_holds_no_payload(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    k.emit("out", k.read("s_a", "SECRET-PAYLOAD-0123"))
    k.record()
    assert b"SECRET-PAYLOAD" not in path.read_bytes()


def test_the_durable_option_runs(tmp_path):
    k = session(tmp_path / "run.jsonl", durable_journal=True)
    busy(k)
    k.record()
    assert read_journal(tmp_path / "run.jsonl").complete


def test_a_missing_or_garbage_file_is_a_report_not_an_exception(tmp_path):
    assert not read_journal(tmp_path / "nope").ok
    garbage = tmp_path / "g.jsonl"
    garbage.write_bytes(b"\xff\xfe not json\n")
    assert not read_journal(garbage).ok
    notjournal = tmp_path / "n.jsonl"
    notjournal.write_text('{"a":1}\n', encoding="utf-8")
    assert not read_journal(notjournal).ok


def test_the_rebuilt_record_passes_the_same_verifier_as_the_live_one(tmp_path):
    path = tmp_path / "run.jsonl"
    k = session(path)
    busy(k)
    k.record()
    assert verify_record(journal_to_record(path, KEY), KEY).signed
