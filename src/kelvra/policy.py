"""Sources, sinks, declassifiers -- the policy objects.

This is the programmatic form of what a ``.klv`` file will eventually
declare. The parser comes later, deliberately: the language should be
designed against flows we have observed, not flows we imagined. See the
roadmap in README.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .labels import Label, PrincipalSet


@dataclass(frozen=True)
class Source:
    """Where data enters the agent, and what it carries when it does.

    Source labelling is declarative, and that makes it the weakest link in
    the trust base: nothing verifies that a source declared public really
    is. This is a process problem, not a technical one, and it is stated
    rather than hidden. See spec/threat-model.md section 6.
    """

    name: str
    label: Label

    def __repr__(self) -> str:
        return f"Source({self.name}: {self.label.describe()})"


@dataclass(frozen=True)
class Sink:
    """Where data becomes observable outside the agent's boundary."""

    name: str
    audience: PrincipalSet = field(default_factory=PrincipalSet.all)
    """Who will see data that reaches here. ``ALL`` means the whole world."""

    requires_endorsement: PrincipalSet = field(default_factory=PrincipalSet.none)
    """Minimum set of principals that must vouch for the data."""

    purpose: str | None = None
    """If set, data must permit this purpose."""

    requires_consent_from: str | None = None
    """If set, a human decision from this principal is needed per use."""

    def __repr__(self) -> str:
        return f"Sink({self.name}: audience={self.audience!r})"


@dataclass(frozen=True)
class Decision:
    """The outcome of checking one flow against one sink."""

    allowed: bool
    sink: str
    label: Label
    reasons: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "permitted"


def check_flow(label: Label, sink: Sink) -> Decision:
    """May data carrying ``label`` reach ``sink``?

    Three independent subset checks, one per axis:

      confidentiality  everyone who will see it is permitted to read it
      integrity        everyone the sink demands a vouch from has vouched
      purpose          the sink's purpose is among the permitted ones
    """
    reasons: list[str] = []

    if not (sink.audience <= label.readers):
        reasons.append(
            f"audience {sink.audience!r} is not permitted to read "
            f"data readable by {label.readers!r}"
        )

    if not (sink.requires_endorsement <= label.endorsers):
        missing = "untrusted data" if label.endorsers.is_empty else f"endorsers {label.endorsers!r}"
        reasons.append(
            f"sink requires endorsement by {sink.requires_endorsement!r} but got {missing}"
        )

    if sink.purpose is not None and sink.purpose not in label.purposes:
        reasons.append(
            f"sink serves purpose {sink.purpose!r}, not permitted by {label.purposes!r}"
        )

    return Decision(
        allowed=not reasons, sink=sink.name, label=label, reasons=tuple(reasons)
    )


@dataclass(frozen=True)
class Declassifier:
    """An explicitly declared relaxation of a label.

    This is the only construct permitted to make a label less restrictive,
    and it is the only place in a Kelvra pipeline where a leak is possible.
    Which is precisely why every use produces an audit entry.

    Kelvra makes no claim that a declassifier is semantically correct. If
    your redactor does not redact, data leaks -- it merely leaks on the
    record, at a named point. See LIMITATIONS.md.
    """

    name: str
    grants_readers: PrincipalSet = field(default_factory=PrincipalSet.none)
    """Readers to add. Lowers confidentiality."""

    grants_endorsement: PrincipalSet = field(default_factory=PrincipalSet.none)
    """Endorsers to add. Raises integrity -- an ``endorse`` in .klv terms."""

    grants_purposes: PrincipalSet = field(default_factory=PrincipalSet.none)

    requires_consent_from: str | None = None

    def apply(self, label: Label) -> Label:
        return Label(
            readers=label.readers | self.grants_readers,
            endorsers=label.endorsers | self.grants_endorsement,
            purposes=label.purposes | self.grants_purposes,
        )


def declassify_to(name: str, *readers: str) -> Declassifier:
    """Shorthand: a declassifier that widens the reader set."""
    return Declassifier(name=name, grants_readers=PrincipalSet.of(*readers))


def endorse_as(name: str, *endorsers: str, consent_from: str | None = None) -> Declassifier:
    """Shorthand: a declassifier that raises integrity."""
    return Declassifier(
        name=name,
        grants_endorsement=PrincipalSet.of(*endorsers),
        requires_consent_from=consent_from,
    )


class PolicySealed(Exception):
    """Raised on an attempt to modify a policy that is governing a run."""


@dataclass
class Policy:
    """A named collection of sources, sinks and declassifiers."""

    name: str
    version: int = 1
    sources: dict[str, Source] = field(default_factory=dict)
    sinks: dict[str, Sink] = field(default_factory=dict)
    declassifiers: dict[str, Declassifier] = field(default_factory=dict)
    sealed: bool = False
    """A sealed policy cannot be modified. See :meth:`seal`."""

    def _check_mutable(self) -> None:
        if self.sealed:
            raise PolicySealed(
                f"policy {self.name!r} is sealed and governing a run. "
                "Build the policy before starting the session -- a run whose policy "
                "changed underneath it cannot be honestly attested to."
            )

    def add_source(self, source: Source) -> Source:
        self._check_mutable()
        self.sources[source.name] = source
        return source

    def add_sink(self, sink: Sink) -> Sink:
        self._check_mutable()
        self.sinks[sink.name] = sink
        return sink

    def add_declassifier(self, d: Declassifier) -> Declassifier:
        self._check_mutable()
        self.declassifiers[d.name] = d
        return d

    def seal(self) -> Policy:
        """Return an immutable snapshot, for a session to enforce against.

        The provenance record carries a fingerprint of the policy that was in
        force. If the policy could change mid-run, that fingerprint would
        attest to something other than what was actually enforced -- and it
        would do so under a signature, which makes a misleading record look
        authoritative. Sealing removes the possibility rather than detecting
        it afterwards.

        The caller's policy object is untouched and stays mutable; the
        session holds this copy.
        """
        return Policy(
            name=self.name,
            version=self.version,
            sources=dict(self.sources),
            sinks=dict(self.sinks),
            declassifiers=dict(self.declassifiers),
            sealed=True,
        )

    def fingerprint(self) -> str:
        """Stable hash of the effective policy, recorded in every run.

        Lets an auditor confirm which policy was in force. Computed over the
        effective content rather than any source text, so two differently
        written policies with identical semantics fingerprint the same.
        Excludes :attr:`sealed`, which is a lifecycle flag and not part of
        what the policy means.
        """
        import hashlib
        import json

        payload = {
            "name": self.name,
            "version": self.version,
            "sources": {
                n: s.label.to_json() for n, s in sorted(self.sources.items())
            },
            "sinks": {
                n: {
                    "audience": s.audience.to_json(),
                    "requires_endorsement": s.requires_endorsement.to_json(),
                    "purpose": s.purpose,
                    "requires_consent_from": s.requires_consent_from,
                }
                for n, s in sorted(self.sinks.items())
            },
            "declassifiers": {
                n: {
                    "grants_readers": d.grants_readers.to_json(),
                    "grants_endorsement": d.grants_endorsement.to_json(),
                    "grants_purposes": d.grants_purposes.to_json(),
                    "requires_consent_from": d.requires_consent_from,
                }
                for n, d in sorted(self.declassifiers.items())
            },
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
