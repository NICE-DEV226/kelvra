"""The provenance record -- the artifact that has value outside engineering.

Every run produces an append-only ledger of what actually happened: which
sources were read, where labels were joined, which declassifications were
taken, which consents were granted, and -- importantly -- which flows were
*denied*. For an auditor, proof that a system refused a flow is worth as
much as the trace of the ones it permitted.

The record is signed so that alteration is detectable (property P4 in
spec/threat-model.md). Format 0.2 adds what a signature at the end of a run
cannot give on its own:

* every event carries a sequence number and the hash of the event before it, so
  a deleted, reordered, duplicated or truncated event breaks the chain even in
  an unsigned record, and ``chain_head`` pins the last one;
* the ledger is encapsulated and closes when the record is produced, so one run
  has one record and nothing can be appended after ``ended_at``;
* ``verify_record`` checks structure, the summary against the events, the chain
  and the signature, and never raises on hostile input.

On signing: this module uses HMAC-SHA256 from the standard library, which
keeps the core dependency-free. HMAC proves the record was produced by a
holder of the key -- it does not prove it to a third party who does not
hold that key. A deployment that needs an auditor to verify independently
wants asymmetric signatures instead. Stated here rather than glossed over.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from .labels import Label

if TYPE_CHECKING:
    from .signing import Signer

FORMAT_VERSION = "0.2.0"
"""Version of the record format (the specification), not of the package."""

_LEGACY_PREFIX = "0.1."
"""Records of this format have no chain and no ``refused`` count."""

EventKind = Literal["read", "join", "declassify", "consent", "allow", "deny", "refuse"]

_KINDS_V02 = ("read", "join", "declassify", "consent", "allow", "deny", "refuse")
_KINDS_V01 = _KINDS_V02[:-1]

_SUMMARY_V02 = {
    "sources_read": "read",
    "declassifications": "declassify",
    "consents": "consent",
    "allowed": "allow",
    "denied": "deny",
    "refused": "refuse",
}

MAX_NAME = 120
"""Longest caller-supplied name kept in an event.

A name that was never declared is whatever the caller (or an attacker steering
it) typed. The record must not become a channel for data, so it is bounded.
"""


MIN_KEY_BYTES = 16
"""A shorter HMAC key is guessable; refuse it rather than sign with it."""


class UnsignedRecordWarning(UserWarning):
    """A record was produced with no signing key, so nothing vouches for it."""


class JournalError(OSError):
    """The on-disk journal could not be written or read back soundly."""


class LedgerClosed(RuntimeError):
    """The record for this run has been produced; nothing more may be recorded."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _bounded(name: object) -> str:
    text = str(name)
    return text if len(text) <= MAX_NAME else text[:MAX_NAME] + "..."


def _digest(obj: object) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class Event:
    """One recorded fact. Its content is frozen as JSON text at creation.

    ``detail`` hands out a fresh copy each time, so nobody holding an event can
    change what the ledger will later hash and sign by editing a nested dict.
    """

    kind: EventKind
    at: str
    seq: int
    prev: str
    _payload: str

    @staticmethod
    def make(kind: EventKind, at: str, detail: dict[str, Any], seq: int, prev: str) -> Event:
        return Event(kind, at, seq, prev, json.dumps(detail, sort_keys=True))

    @property
    def detail(self) -> dict[str, Any]:
        return json.loads(self._payload)

    def to_json(self) -> dict:
        return {"kind": self.kind, "at": self.at, "seq": self.seq, "prev": self.prev, **self.detail}


@dataclass
class Ledger:
    """Append-only, thread-safe record of one agent run.

    ``events`` is an immutable snapshot. The only way to add to the ledger is
    through the recording methods, and once :meth:`to_record` has produced the
    record they all raise :class:`LedgerClosed`.
    """

    policy_name: str
    policy_version: int
    policy_fingerprint: str
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now)
    ended_at: str | None = None
    journal: Journal | None = field(default=None, repr=False, compare=False)
    _events: list[Event] = field(default_factory=list, init=False, repr=False)
    _head: str = field(default="", init=False, repr=False)
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._head = self._genesis()
        if self.journal is not None:
            self.journal.begin(
                {
                    "kelvra_journal": FORMAT_VERSION,
                    "run_id": self.run_id,
                    "policy": {
                        "name": self.policy_name,
                        "version": self.policy_version,
                        "fingerprint": self.policy_fingerprint,
                    },
                    "started_at": self.started_at,
                    "genesis": self._head,
                }
            )

    def _genesis(self) -> str:
        return _genesis(self.run_id, self.policy_fingerprint, self.started_at)

    # -- recording -------------------------------------------------------

    def ensure_open(self) -> None:
        """Raise :class:`LedgerClosed` before doing anything that would need recording."""
        with self._lock:
            if self.ended_at is not None:
                raise LedgerClosed(
                    f"the record for run {self.run_id} has been produced; "
                    "start a new session to continue"
                )

    def _record(self, kind: EventKind, **detail: Any) -> Event:
        with self._lock:
            if self.ended_at is not None:
                raise LedgerClosed(
                    f"the record for run {self.run_id} has been produced; "
                    "start a new session to record more"
                )
            event = Event.make(kind, _now(), detail, seq=len(self._events), prev=self._head)
            as_json = event.to_json()
            # Write ahead: an event that cannot be made durable is not recorded, so
            # the operation that needed recording fails with it instead of running
            # unlogged.
            if self.journal is not None:
                self.journal.append(as_json)
            self._head = _digest(as_json)
            self._events.append(event)
            return event

    def read(self, source: str, label: Label) -> None:
        self._record("read", source=source, label=label.to_json())

    def join(self, at: str, inputs: list[str], result: Label) -> None:
        self._record("join", site=at, inputs=inputs, result=result.to_json())

    def declassify(
        self,
        name: str,
        before: Label,
        after: Label,
        consent_from: str | None = None,
        from_check: str = "undeclared",
    ) -> None:
        """``from_check`` says whether the input matched the declarator's ``from``.

        ``from`` is documentation, not a restriction (spec/policy-language.md
        section 3), so a mismatch is not refused -- but a reader of the policy
        believed the crossing was for that kind of data, and the auditor should
        be able to see when it was used on another.
        """
        self._record(
            "declassify",
            declassifier=name,
            before=before.to_json(),
            after=after.to_json(),
            consent_from=consent_from,
            from_check=from_check,
        )

    def consent(
        self,
        principal: str,
        granted: bool,
        decided_by: str | None,
        context: str,
        label: Label,
    ) -> None:
        """A human decision, bound to the label of the data it concerned."""
        self._record(
            "consent",
            principal=principal,
            granted=granted,
            granted_by=decided_by,
            context=context,
            label=label.to_json(),
        )

    def allow(self, sink: str, label: Label) -> None:
        self._record("allow", sink=sink, label=label.to_json())

    def deny(self, sink: str, label: Label, reasons: tuple[str, ...]) -> None:
        self._record("deny", sink=_bounded(sink), label=label.to_json(), reasons=list(reasons))

    def refuse(self, operation: str, name: str) -> None:
        """An attempt to use something the policy never declared."""
        self._record("refuse", operation=operation, name=_bounded(name), reason="undeclared")

    # -- querying --------------------------------------------------------

    @property
    def events(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def of_kind(self, kind: EventKind) -> list[Event]:
        return [e for e in self.events if e.kind == kind]

    @property
    def declassification_count(self) -> int:
        return len(self.of_kind("declassify"))

    @property
    def denial_count(self) -> int:
        return len(self.of_kind("deny"))

    # -- output ----------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self.ended_at is None:
                self.ended_at = _now()
                if self.journal is not None:
                    self.journal.end(
                        {
                            "ended_at": self.ended_at,
                            "chain_head": self._head,
                            "events": len(self._events),
                        }
                    )

    def to_record(self, key: bytes | None = None, signer: Signer | None = None) -> dict:
        """Build the provenance record, signed if a key is supplied.

        Closes the ledger. Calling it again returns the same record, because
        the events can no longer change: one run, one record.
        """
        with self._lock:
            self.close()
            events = list(self._events)
            head = self._head
        record = {
            "kelvra_version": FORMAT_VERSION,
            "policy": {
                "name": self.policy_name,
                "version": self.policy_version,
                "fingerprint": self.policy_fingerprint,
            },
            "run_id": self.run_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "summary": _summarise(events),
            "chain_head": head,
            "events": [e.to_json() for e in events],
        }
        if signer is not None:
            record["signature"] = signer.sign(record)
        elif key is not None:
            record["signature"] = sign(record, key)
        return record

    def to_json(self, key: bytes | None = None, indent: int = 2) -> str:
        return json.dumps(self.to_record(key), indent=indent, sort_keys=False)

    def summary_lines(self) -> list[str]:
        """One-screen summary. This is what a human actually reads."""
        events = self.events
        lines = [
            f"policy   {self.policy_name} v{self.policy_version}",
            f"run      {self.run_id}",
            f"sources  {sum(e.kind == 'read' for e in events)} read",
        ]
        declass = [e for e in events if e.kind == "declassify"]
        if declass:
            lines.append("declassified via:")
            for e in declass:
                lines.append(f"           - {e.detail['declassifier']}")
        else:
            lines.append("declassified: none")
        denied = [e for e in events if e.kind == "deny"]
        if denied:
            lines.append(f"DENIED   {len(denied)} flow(s):")
            for e in denied:
                lines.append(f"           x {e.detail['sink']}: {e.detail['reasons'][0]}")
        else:
            lines.append("denied   none")
        refused = [e for e in events if e.kind == "refuse"]
        if refused:
            lines.append(f"REFUSED  {len(refused)} use(s) of something undeclared:")
            for e in refused:
                lines.append(f"           x {e.detail['operation']} {e.detail['name']!r}")
        return lines


def _genesis(run_id: str, fingerprint: str, started_at: str) -> str:
    return _digest(
        {"genesis": True, "run_id": run_id, "policy": fingerprint, "started_at": started_at}
    )


def _summarise(events: list[Event]) -> dict[str, int]:
    return {name: sum(1 for e in events if e.kind == kind) for name, kind in _SUMMARY_V02.items()}


# -- the journal ------------------------------------------------------------


class Journal:
    """Append-only JSON Lines file, written as the run happens.

    The record in memory is lost if the process dies, and a long-running agent
    that crashes is the run an auditor most wants to see. The journal keeps the
    same hash-chained events on disk, one line each, written *before* the event
    counts as recorded: line 1 is a header, then one line per event, and a final
    ``end`` line is written when the record is produced. A journal without that
    line is an incomplete run, and says so; it never reads as a finished one.

    It holds exactly what the record holds (names, labels, decisions, times) and
    no payloads. The file is created exclusively, mode 0600 where the platform
    honours it, and an existing file is never appended to: one run, one file.
    ``durable=True`` fsyncs after every line, trading throughput for the
    guarantee that an acknowledged event survives a power cut.
    """

    def __init__(self, path: str | os.PathLike[str], *, durable: bool = False) -> None:
        self.path = os.fspath(path)
        self.durable = durable
        self._fd: int | None = None
        self._lock = threading.Lock()

    def begin(self, header: dict) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_BINARY", 0)
        try:
            self._fd = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise JournalError(f"cannot create journal {self.path!r}: {error}") from error
        self._write(header)

    def append(self, event: dict) -> None:
        self._write(event)

    def end(self, footer: dict) -> None:
        self._write({"end": footer})
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def _write(self, obj: dict) -> None:
        line = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self._lock:
            if self._fd is None:
                raise JournalError(f"journal {self.path!r} is closed")
            try:
                written = 0
                while written < len(line):  # os.write may be partial
                    written += os.write(self._fd, line[written:])
                if self.durable:
                    os.fsync(self._fd)
            except OSError as error:
                raise JournalError(f"cannot write journal {self.path!r}: {error}") from error


@dataclass(frozen=True)
class JournalContents:
    """What a journal file holds, and whether it can be trusted."""

    ok: bool
    complete: bool
    """The ``end`` line is present and agrees with the events."""

    header: dict
    events: tuple[dict, ...]
    footer: dict | None
    problems: tuple[str, ...] = ()


def read_journal(path: str | os.PathLike[str]) -> JournalContents:
    """Read a journal back and check its chain. Never raises on a bad file.

    ``ok`` means every line is well formed and the chain holds, up to a torn
    final line (a crash mid-write), which is reported but does not invalidate the
    lines before it. ``complete`` additionally needs the ``end`` line.
    """
    problems: list[str] = []
    header: dict = {}
    events: list[dict] = []
    footer: dict | None = None
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        return JournalContents(False, False, {}, (), None, (f"cannot read journal: {error}",))

    lines = raw.split(b"\n")
    tail = lines.pop()  # what follows the last newline: empty if the file ends cleanly
    torn = tail if tail else None
    if torn is not None:
        problems.append("the last line is incomplete (the process stopped mid-write)")
    parsed: list[dict] = []
    for index, line in enumerate(lines):
        try:
            value = json.loads(line.decode("utf-8"))
        except ValueError:
            problems.append(f"line {index + 1} is not valid JSON")
            return JournalContents(False, False, header, tuple(events), footer, tuple(problems))
        if not isinstance(value, dict):
            problems.append(f"line {index + 1} is not an object")
            return JournalContents(False, False, header, tuple(events), footer, tuple(problems))
        parsed.append(value)

    if not parsed or "kelvra_journal" not in parsed[0]:
        problems.append("the header line is missing")
        return JournalContents(False, False, header, (), None, tuple(problems))
    header = parsed[0]
    body = parsed[1:]
    if body and "end" in body[-1]:
        footer = body[-1]["end"]
        body = body[:-1]
    chain_ok = True
    try:
        policy = header["policy"]
        prev = _genesis(header["run_id"], policy["fingerprint"], header["started_at"])
        if header.get("genesis") != prev:
            problems.append("the header's genesis value does not match its run")
            chain_ok = False
        for index, event in enumerate(body):
            if "end" in event or event.get("seq") != index or event.get("prev") != prev:
                problems.append(f"event {index} breaks the chain")
                chain_ok = False
                break
            events.append(event)
            prev = _digest(event)
    except (KeyError, TypeError) as error:
        problems.append(f"the header is malformed: {error!r}")
        return JournalContents(False, False, header, tuple(events), footer, tuple(problems))

    complete = False
    if footer is not None and chain_ok:
        complete = (
            isinstance(footer, dict)
            and footer.get("chain_head") == prev
            and footer.get("events") == len(events)
        )
        if not complete:
            problems.append("the end line does not agree with the events")
            chain_ok = False
    elif footer is None:
        problems.append("no end line: the run did not finish (crash, or still running)")
    ok = chain_ok and torn is None
    return JournalContents(ok, complete and ok, header, tuple(events), footer, tuple(problems))


def journal_to_record(path: str | os.PathLike[str], key: bytes | None = None) -> dict:
    """Rebuild the provenance record of a *complete* journal, signed if a key is given.

    The result is identical to the record the live session produced, so a run
    whose process died after its last event but before anyone saved the record
    can still be attested to -- by whoever holds the key. An incomplete journal
    is refused: a record built from it would claim an end the run never had.
    """
    contents = read_journal(path)
    if not contents.complete:
        raise JournalError(
            "journal is not a complete, intact run: " + "; ".join(contents.problems or ("?",))
        )
    events = list(contents.events)
    record = {
        "kelvra_version": FORMAT_VERSION,
        "policy": contents.header["policy"],
        "run_id": contents.header["run_id"],
        "started_at": contents.header["started_at"],
        "ended_at": contents.footer["ended_at"],  # type: ignore[index]
        "summary": {
            name: sum(1 for e in events if e["kind"] == kind) for name, kind in _SUMMARY_V02.items()
        },
        "chain_head": contents.footer["chain_head"],  # type: ignore[index]
        "events": events,
    }
    if key is not None:
        record["signature"] = sign(record, key)
    return record


# -- signing and verification ---------------------------------------------


def _canonical(record: dict) -> bytes:
    """Serialise deterministically, excluding any existing signature."""
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(record: dict, key: bytes) -> str:
    if not isinstance(key, bytes | bytearray) or not key:
        raise TypeError("the signing key must be non-empty bytes")
    return "hmac-sha256:" + hmac.new(bytes(key), _canonical(record), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Verification:
    """The outcome of checking a record. Truthy when nothing is wrong."""

    ok: bool
    problems: tuple[str, ...] = ()
    signed: bool = False
    """A signature was present and matched the key."""

    legacy: bool = False
    """Format 0.1: no hash chain, so omissions cannot be ruled out."""

    def __bool__(self) -> bool:
        return self.ok


def verify_record(
    record: object, key: bytes | None = None, *, public_key: bytes | None = None
) -> Verification:
    """Check a record that may be hostile. Never raises.

    Without a key this checks structure, the summary against the events and the
    hash chain. With a key it also checks the signature. A format 0.1 record has
    no chain; it is accepted on the other checks and reported ``legacy``.

    ``public_key`` checks an Ed25519 signature instead (see ``kelvra.signing``);
    give a ``key`` or a ``public_key``, not both.
    """
    problems: list[str] = []
    signed = False
    legacy = False
    try:
        if not isinstance(record, dict):
            return Verification(False, ("record is not an object",))
        legacy = str(record.get("kelvra_version", "")).startswith(_LEGACY_PREFIX)
        _check_structure(record, legacy, problems)
        if not problems:
            events = record["events"]
            _check_summary(record, events, legacy, problems)
            if not legacy:
                _check_chain(record, events, problems)
        if key is not None and public_key is not None:
            problems.append("give an HMAC key or an Ed25519 public key, not both")
        elif key is not None:
            signed = _check_signature(record, key, problems)
        elif public_key is not None:
            from .signing import check_ed25519

            signed = check_ed25519(record, public_key, problems)
    except Exception as error:
        problems.append(f"record could not be checked: {type(error).__name__}")
    return Verification(not problems, tuple(problems), signed and not problems, legacy)


def verify(record: object, key: bytes) -> bool:
    """True only for a well-formed, consistent, chained record whose signature matches."""
    result = verify_record(record, key)
    return result.ok and result.signed


def _check_structure(record: dict, legacy: bool, problems: list[str]) -> None:
    for name in ("kelvra_version", "run_id", "started_at", "ended_at"):
        if not isinstance(record.get(name), str):
            problems.append(f"{name} is missing or not a string")
    policy = record.get("policy")
    if not isinstance(policy, dict) or not all(
        isinstance(policy.get(n), str) for n in ("name", "fingerprint")
    ):
        problems.append("policy is missing or malformed")
    if not isinstance(record.get("summary"), dict):
        problems.append("summary is missing or not an object")
    events = record.get("events")
    if not isinstance(events, list):
        problems.append("events is missing or not a list")
        return
    kinds = _KINDS_V01 if legacy else _KINDS_V02
    for index, event in enumerate(events):
        if not isinstance(event, dict) or event.get("kind") not in kinds:
            problems.append(f"event {index} is malformed or of an unknown kind")
            return


def _check_summary(record: dict, events: list, legacy: bool, problems: list[str]) -> None:
    expected = {
        name: sum(1 for e in events if e["kind"] == kind) for name, kind in _SUMMARY_V02.items()
    }
    if legacy:
        expected.pop("refused")
    summary = record["summary"]
    if set(summary) != set(expected):
        problems.append("summary does not have the fields of its format version")
        return
    for name, count in expected.items():
        value = summary[name]
        if isinstance(value, bool) or not isinstance(value, int) or value != count:
            problems.append(f"summary.{name} disagrees with the events")


def _check_chain(record: dict, events: list, problems: list[str]) -> None:
    prev = _genesis(record["run_id"], record["policy"]["fingerprint"], record["started_at"])
    for index, event in enumerate(events):
        if event.get("seq") != index or isinstance(event.get("seq"), bool):
            problems.append(f"event {index} is out of sequence (event removed, added or moved)")
            return
        if event.get("prev") != prev:
            problems.append(f"event {index} does not follow the previous event's hash")
            return
        prev = _digest(event)
    if record.get("chain_head") != prev:
        problems.append("chain_head does not match the last event (record truncated or extended)")


def _check_signature(record: dict, key: object, problems: list[str]) -> bool:
    if not isinstance(key, bytes | bytearray) or not key:
        problems.append("the verification key must be non-empty bytes")
        return False
    claimed = record.get("signature")
    if not isinstance(claimed, str) or not claimed.isascii():
        problems.append("signature is missing or malformed")
        return False
    expected = sign(record, bytes(key))
    if not hmac.compare_digest(claimed.encode("ascii"), expected.encode("ascii")):
        problems.append("signature does not match")
        return False
    return True


def check_key(key: object, origin: str = "signing_key") -> bytes:
    """Return ``key`` as bytes, or raise. Called when a session starts, not when it ends.

    A key rejected at the end of a run costs the run's audit record; rejected at
    the start it costs nothing.
    """
    if not isinstance(key, bytes | bytearray):
        raise TypeError(f"{origin} must be bytes, not {type(key).__name__}")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"{origin} is {len(key)} bytes; at least {MIN_KEY_BYTES} are required")
    return bytes(key)


def key_from_env(var: str = "KELVRA_SIGNING_KEY") -> bytes | None:
    value = os.environ.get(var)
    return check_key(value.encode(), f"${var}") if value else None
