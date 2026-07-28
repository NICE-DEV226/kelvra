"""The provenance record -- the artifact that has value outside engineering.

Every run produces an append-only ledger of what actually happened: which
sources were read, where labels were joined, which declassifications were
taken, which consents were granted, and -- importantly -- which flows were
*denied*. For an auditor, proof that a system refused a flow is worth as
much as the trace of the ones it permitted.

The record is signed so that alteration is detectable (property P4 in
spec/threat-model.md).

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
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .labels import Label

EventKind = Literal[
    "read", "join", "declassify", "consent", "allow", "deny"
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class Event:
    kind: EventKind
    at: str
    detail: dict[str, Any]

    def to_json(self) -> dict:
        return {"kind": self.kind, "at": self.at, **self.detail}


@dataclass
class Ledger:
    """Append-only record of one agent run."""

    policy_name: str
    policy_version: int
    policy_fingerprint: str
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now)
    ended_at: str | None = None
    events: list[Event] = field(default_factory=list)

    # -- recording -------------------------------------------------------

    def _record(self, kind: EventKind, **detail: Any) -> Event:
        event = Event(kind=kind, at=_now(), detail=detail)
        self.events.append(event)
        return event

    def read(self, source: str, label: Label) -> None:
        self._record("read", source=source, label=label.to_json())

    def join(self, at: str, inputs: list[str], result: Label) -> None:
        self._record("join", site=at, inputs=inputs, result=result.to_json())

    def declassify(
        self, name: str, before: Label, after: Label, consent_from: str | None = None
    ) -> None:
        self._record(
            "declassify",
            declassifier=name,
            before=before.to_json(),
            after=after.to_json(),
            consent_from=consent_from,
        )

    def consent(self, principal: str, granted: bool, granted_by: str | None, context: str) -> None:
        self._record(
            "consent",
            principal=principal,
            granted=granted,
            granted_by=granted_by,
            context=context,
        )

    def allow(self, sink: str, label: Label) -> None:
        self._record("allow", sink=sink, label=label.to_json())

    def deny(self, sink: str, label: Label, reasons: tuple[str, ...]) -> None:
        self._record("deny", sink=sink, label=label.to_json(), reasons=list(reasons))

    # -- querying --------------------------------------------------------

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
        if self.ended_at is None:
            self.ended_at = _now()

    def to_record(self, key: bytes | None = None) -> dict:
        """Build the provenance record, signed if a key is supplied."""
        self.close()
        record = {
            "kelvra_version": "0.1.0",
            "policy": {
                "name": self.policy_name,
                "version": self.policy_version,
                "fingerprint": self.policy_fingerprint,
            },
            "run_id": self.run_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "summary": {
                "sources_read": len(self.of_kind("read")),
                "declassifications": self.declassification_count,
                "consents": len(self.of_kind("consent")),
                "allowed": len(self.of_kind("allow")),
                "denied": self.denial_count,
            },
            "events": [e.to_json() for e in self.events],
        }
        if key is not None:
            record["signature"] = sign(record, key)
        return record

    def to_json(self, key: bytes | None = None, indent: int = 2) -> str:
        return json.dumps(self.to_record(key), indent=indent, sort_keys=False)

    def summary_lines(self) -> list[str]:
        """One-screen summary. This is what a human actually reads."""
        lines = [
            f"policy   {self.policy_name} v{self.policy_version}",
            f"run      {self.run_id}",
            f"sources  {len(self.of_kind('read'))} read",
        ]
        declass = self.of_kind("declassify")
        if declass:
            lines.append("declassified via:")
            for e in declass:
                lines.append(f"           - {e.detail['declassifier']}")
        else:
            lines.append("declassified: none")
        denied = self.of_kind("deny")
        if denied:
            lines.append(f"DENIED   {len(denied)} flow(s):")
            for e in denied:
                lines.append(f"           x {e.detail['sink']}: {e.detail['reasons'][0]}")
        else:
            lines.append("denied   none")
        return lines


def _canonical(record: dict) -> bytes:
    """Serialise deterministically, excluding any existing signature."""
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(record: dict, key: bytes) -> str:
    return "hmac-sha256:" + hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def verify(record: dict, key: bytes) -> bool:
    """Constant-time check that a record has not been altered."""
    claimed = record.get("signature")
    if not isinstance(claimed, str):
        return False
    return hmac.compare_digest(claimed, sign(record, key))


def key_from_env(var: str = "KELVRA_SIGNING_KEY") -> bytes | None:
    value = os.environ.get(var)
    return value.encode() if value else None
