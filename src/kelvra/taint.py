"""Labelled values, and the session that moves them around.

The central modelling decision lives here, in :meth:`Kelvra.model_call`.

A language model is opaque. Anything placed in its context window can
influence anything it emits -- there is no reliable privilege boundary
inside a token sequence, which is precisely why indirect prompt injection
remains unsolved at the model level. So Kelvra treats a model call as a
**total join**: the output carries the join of every input label, with no
exception.

This is coarse and it is sound. It is coarse because a summary of one
public document and one secret document is marked secret even if the model
only used the public one -- we cannot know that it didn't. It is sound
because it never under-labels, and under-labelling is the failure that
leaks data.

The cost is label creep: keep joining and eventually everything is secret
and nothing is permitted. That is the standard practical failure of dynamic
IFC and Kelvra does not solve it -- see LIMITATIONS.md. The mitigation is
structural, not clever: keep tainted data out of context windows whose
output must stay clean, by splitting the work across separate calls.
"""

from __future__ import annotations

import inspect
import os
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from .labels import Label, join_all
from .policy import Declassifier, Policy, Sink, check_flow
from .provenance import Journal, Ledger, UnsignedRecordWarning, check_key, key_from_env

if TYPE_CHECKING:
    from .sealing import MasterKey, Sealer
    from .signing import Signer

T = TypeVar("T")


class Denied(Exception):
    """A flow was refused. Carries the decision so callers can inspect why."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(f"flow to {decision.sink!r} denied: {decision.reason}")


class ConsentRefused(Exception):
    pass


class PolicyIntegrityError(RuntimeError):
    """The policy in force differs from the one the run started under."""


_MINT = object()
"""Proof of issue. Only this module passes it, so only a session can create a value."""


class Tainted(Generic[T]):
    """A value together with what it carries.

    Deliberately not transparent: it does not forward attribute access or
    arithmetic to the wrapped value. The only way to get the payload back out
    is :meth:`Kelvra.emit` or :attr:`unsafe_value`, so that losing a label is
    something you had to type -- and ``unsafe_value`` is the *only* spelling, so
    grepping for it finds every hole.

    A value cannot be constructed by hand: ``Tainted(secret, PUBLIC, "x")``
    raises. Sessions issue them (``read``, ``model_call``, ``declassify``,
    ``map``), each remembers who issued it, and a session refuses a value that
    another session -- or nobody -- issued. That stops the ordinary ways of
    attaching a flattering label to data; it is not a defence against code that
    reaches into private attributes (see ``AgentSession``).
    """

    __slots__ = ("_issuer", "_value", "label", "origin")

    def __init__(
        self, value: T, label: Label, origin: str, *, _mint: object = None, _issuer: object = None
    ) -> None:
        if _mint is not _MINT:
            raise TypeError(
                "Tainted values are issued by a Kelvra session (read, model_call, "
                "declassify, map); they cannot be constructed directly"
            )
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "_issuer", _issuer)

    @classmethod
    def _issue(cls, value: T, label: Label, origin: str, issuer: object) -> Tainted[T]:
        return cls(value, label, origin, _mint=_MINT, _issuer=issuer)

    def __setattr__(self, key: str, value: object) -> None:
        raise AttributeError(f"Tainted is immutable; cannot set {key!r}")

    def __delattr__(self, key: str) -> None:
        raise AttributeError(f"Tainted is immutable; cannot delete {key!r}")

    @property
    def unsafe_value(self) -> T:
        """Escape hatch. Every use is a hole in the model; grep for it."""
        return self._value

    def map(self, fn: Callable[[T], object], *, note: str = "map") -> Tainted:
        """Transform the value, keeping the label. Never relaxes anything."""
        return Tainted._issue(fn(self._value), self.label, f"{self.origin}|{note}", self._issuer)

    def __repr__(self) -> str:
        return f"Tainted({self.origin}: {self.label.describe()})"


@dataclass(frozen=True)
class ConsentDecision:
    """A human decision, with the identity of whoever took it.

    ``granted=True`` without ``decided_by`` is not consent: an audit record that
    says "someone agreed" cannot be answered for. The identity is what an
    auditor reads in ``consent.granted_by``.
    """

    granted: bool
    decided_by: str


ConsentProvider = Callable[[str, str], "ConsentDecision | bool | None"]
"""Called as ``(principal, context)``.

Return ``ConsentDecision(True, "<who>")`` to grant. ``False`` or ``None`` refuse.
A bare ``True`` is refused: it carries no identity.
"""


def deny_all_consent(principal: str, context: str) -> bool:
    return False


def approved_by(identity: str) -> ConsentProvider:
    """A provider that approves everything as ``identity``. For tests and demos only."""

    def provider(principal: str, context: str) -> ConsentDecision:
        return ConsentDecision(True, identity)

    return provider


_MAX_IDENTITY = 128


class Kelvra:
    """A policy, a ledger, and the operations that connect them."""

    def __init__(
        self,
        policy: Policy,
        *,
        signing_key: bytes | None = None,
        consent: ConsentProvider = deny_all_consent,
        service_identities: Iterable[str] = (),
        signer: Signer | None = None,
        journal_path: str | os.PathLike[str] | None = None,
        durable_journal: bool = False,
        master_key: MasterKey | None = None,
    ) -> None:
        """``service_identities`` names the accounts that run the agent itself.

        Consent decided by one of them is refused: an approval the agent (or
        its service account) gave to itself is not an approval.

        ``signer`` (for example :class:`~kelvra.signing.Ed25519Signer`) signs the
        record instead of the HMAC ``signing_key``; give one or the other.

        ``journal_path`` also writes every event to that file as it happens
        (see :class:`~kelvra.provenance.Journal`): the file must not exist yet,
        and a run that cannot be journalled does not start.

        ``master_key`` enables :meth:`seal` and :meth:`emit_text` (see
        :mod:`kelvra.sealing`). It stays here, in the authority: an
        :class:`AgentSession` has no way to reach it.
        """
        # Sealed, not referenced. A run whose policy changed underneath it
        # cannot be honestly attested to, and the signature would make the
        # misleading record look authoritative. See Policy.seal.
        self.policy = policy.seal()
        if signer is not None and signing_key is not None:
            raise ValueError("give signing_key or signer, not both")
        self.signer = signer
        if signer is not None:
            self.signing_key = None
        elif signing_key is not None:
            self.signing_key = check_key(signing_key)
        else:
            self.signing_key = key_from_env()
        self.consent_provider = consent
        self._issuer = object()
        self.service_identities = frozenset(service_identities)
        self.ledger = Ledger(
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            policy_fingerprint=self.policy.fingerprint(),
            journal=(
                Journal(journal_path, durable=durable_journal) if journal_path is not None else None
            ),
        )
        self._sealer: Sealer | None = None
        if master_key is not None:
            from .sealing import Sealer

            self._sealer = Sealer(master_key, self.ledger.policy_fingerprint, self.ledger.run_id)

    # -- entry -----------------------------------------------------------

    def read(self, source_name: str, value: T) -> Tainted[T]:
        """Bring a value in, labelled by its declared source."""
        self.ledger.ensure_open()
        try:
            source = self.policy.sources[source_name]
        except KeyError:
            self.ledger.refuse("read", source_name)
            raise LookupError(
                f"source {source_name!r} is not declared in policy {self.policy.name!r}"
            ) from None
        self.ledger.read(source.name, source.label)
        return Tainted._issue(value, source.label, source.name, self._issuer)

    # -- propagation -----------------------------------------------------

    def model_call(
        self,
        site: str,
        *inputs: Tainted,
        produce: Callable[..., object] | None = None,
        via: str | None = None,
    ) -> Tainted:
        """Run a model call. The output carries the join of every input.

        ``produce`` receives the raw values and returns the model's output.
        If omitted, the inputs are returned as a tuple, which is useful for
        testing propagation without spending tokens.

        ``via`` names the model provider as a declared sink. The joined label of
        the inputs is checked against it once, before the call happens: a
        refusal is one ``deny`` event, a grant is one ``allow`` and one consent
        prompt, and nothing is recorded as sent that was not. Passing it matters:
        sending data to a remote model is sending it outside the boundary,
        and without this the provider is the one destination that receives
        everything and is checked for nothing. It is optional only because a
        local model is not a sink at all.
        """
        self.ledger.ensure_open()
        self._own(*inputs)
        label = join_all(t.label for t in inputs)
        if via is not None:
            self._authorize(via, label)
        self.ledger.join(site, [t.origin for t in inputs], label)
        raw = tuple(t._value for t in inputs)
        out = produce(*raw) if produce is not None else raw
        return Tainted._issue(out, label, site, self._issuer)

    def combine(self, site: str, *inputs: Tainted) -> Label:
        """Join labels without producing a value."""
        self.ledger.ensure_open()
        self._own(*inputs)
        label = join_all(t.label for t in inputs)
        self.ledger.join(site, [t.origin for t in inputs], label)
        return label

    # -- declassification ------------------------------------------------

    def declassify(
        self,
        name: str,
        tainted: Tainted,
        transform: Callable[[object], object] | None = None,
    ) -> Tainted:
        """Take a declared declassification. The only way a label relaxes.

        Kelvra does not and cannot check that ``transform`` actually does
        what its name claims. It records that this crossing was taken.
        (:meth:`seal` is the one declassification whose transformation Kelvra
        performs itself, and so the one whose effect it can vouch for.)
        """
        after = self._cross(name, tainted)
        value = transform(tainted._value) if transform is not None else tainted._value
        return Tainted._issue(value, after, f"{tainted.origin}|{name}", self._issuer)

    def _cross(self, name: str, tainted: Tainted) -> Label:
        """Look up, consent to and record one declassification; return the new label."""
        self.ledger.ensure_open()
        self._own(tainted)
        try:
            d: Declassifier = self.policy.declassifiers[name]
        except KeyError:
            self.ledger.refuse("declassify", name)
            raise LookupError(
                f"declassifier {name!r} is not declared in policy {self.policy.name!r}"
            ) from None

        if d.requires_consent_from is not None:
            self._require_consent(d.requires_consent_from, f"declassify:{name}", tainted.label)

        after = d.apply(tainted.label)
        self.ledger.declassify(
            name, tainted.label, after, d.requires_consent_from, d.matches_from(tainted.label)
        )
        return after

    # -- sealing ---------------------------------------------------------

    def seal(self, name: str, tainted: Tainted[str], kind: str = "value") -> Tainted[str]:
        """Replace a value by an authenticated ciphertext, under a declared declassification.

        ``name`` must be a declassifier of the policy; the crossing it describes is exactly
        what happens: the *token* carries the relaxed label (for example one that lets the
        model provider read it), because the token is all that crosses. The plaintext and
        its original label stay recoverable only through :meth:`emit_text`, which asks the
        flow rule about the original label, not the relaxed one.

        Unlike :meth:`declassify`, the transformation is Kelvra's, not the caller's, so the
        policy's claim ("this crossing sends ciphertext") is one Kelvra can keep.
        """
        if self._sealer is None:
            raise TypeError("sealing needs Kelvra(..., master_key=MasterKey(...))")
        self.ledger.ensure_open()
        self._own(tainted)
        if not isinstance(tainted._value, str):
            raise TypeError(f"only text can be sealed, not {type(tainted._value).__name__}")
        # Seal first, record second: a value that cannot be sealed (too long, bad kind)
        # must not leave a declassification in the record that never produced a token.
        token = self._sealer.seal(tainted._value, kind, tainted.label)
        after = self._cross(name, tainted)
        return Tainted._issue(token, after, f"{tainted.origin}|{name}", self._issuer)

    def emit_text(self, sink_name: str, tainted: Tainted[str]) -> str:
        """Send text to a sink, opening the sealed tokens in it if, and only if, allowed.

        The decision is one flow: the text's own label joined with the *original* label of
        every token inside it. If the sink refuses that, nothing is opened and the refusal is
        recorded like any other. A token that does not authenticate (forged, altered, cut,
        from another run) is refused and recorded, never passed through.
        """
        self.ledger.ensure_open()
        self._own(tainted)
        if not isinstance(tainted._value, str):
            raise TypeError(f"emit_text takes text, not {type(tainted._value).__name__}")
        if self._sealer is None:
            return self.emit(sink_name, tainted)

        from .sealing import SealError

        def decide(originals: list[Label]) -> None:
            self._authorize(sink_name, join_all([tainted.label, *originals]))

        try:
            text, _ = self._sealer.resolve(tainted._value, decide)
        except SealError as error:
            if sink_name in self.policy.sinks:
                self.ledger.deny(sink_name, tainted.label, (f"sealed content refused: {error}",))
            else:
                self.ledger.deny(sink_name, tainted.label, ("sink is not declared in the policy",))
            raise
        return text

    # -- exit ------------------------------------------------------------

    def emit(self, sink_name: str, tainted: Tainted[T]) -> T:
        """Send a value to a sink. Raises :class:`Denied` if the policy refuses.

        This is the enforcement point. Returning the unwrapped value on
        success is intentional: past this line the data has left Kelvra's
        boundary and there is nothing further to track.
        """
        self._own(tainted)
        self._authorize(sink_name, tainted.label)
        return tainted._value

    def _authorize(self, sink_name: str, label: Label) -> None:
        """Decide one flow, and record the decision. The single enforcement path."""
        self.ledger.ensure_open()
        try:
            sink: Sink = self.policy.sinks[sink_name]
        except KeyError:
            # An attempt to reach an undeclared destination is a refused flow.
            # It used to leave no trace, though it is exactly what an auditor
            # asks about ("what was refused?").
            self.ledger.deny(sink_name, label, ("sink is not declared in the policy",))
            raise LookupError(
                f"sink {sink_name!r} is not declared in policy {self.policy.name!r}"
            ) from None

        decision = check_flow(label, sink)
        if not decision.allowed:
            self.ledger.deny(sink.name, label, decision.reasons)
            raise Denied(decision)

        if sink.requires_consent_from is not None:
            self._require_consent(sink.requires_consent_from, f"emit:{sink_name}", label)

        self.ledger.allow(sink.name, label)

    def _own(self, *values: object) -> None:
        """Refuse anything this session did not issue.

        A value built by hand, or carried over from another session, has a
        label nobody here vouched for. Refusing is the only safe reading.
        """
        for value in values:
            if not isinstance(value, Tainted) or value._issuer is not self._issuer:
                raise TypeError(
                    "this value was not issued by this session; labels cannot be "
                    "carried in from outside (build it with read/model_call/declassify)"
                )

    def would_allow(self, sink_name: str, tainted: Tainted) -> bool:
        """Check without recording or raising. For dry runs and tests."""
        self._own(tainted)
        return check_flow(tainted.label, self.policy.sinks[sink_name]).allowed

    # -- consent ---------------------------------------------------------

    def _require_consent(self, principal: str, context: str, label: Label) -> None:
        """Ask the provider; grant only on ``ConsentDecision(True, <identity>)``.

        Truthiness is not consent. An ``async def`` provider returns a
        coroutine object, which is truthy; a provider returning ``"no"`` or
        ``[0]`` is truthy too; a bare ``True`` names nobody. All of those used
        to be recorded and treated as a grant. ``None`` and ``False`` are a
        refusal; every other value is an integration error, recorded as a
        refusal and raised loudly so that it is fixed rather than papered over.
        A grant by an identity listed in ``service_identities`` is refused as
        self-approval. The decision is recorded with the label of the data.
        """
        decision = self.consent_provider(principal, context)
        problem: str | None = None
        refusal: str | None = None
        granted = False
        decided_by: str | None = None

        if inspect.isawaitable(decision):
            if inspect.iscoroutine(decision):
                decision.close()  # never awaited; avoid the "never awaited" warning
            problem = "returned an awaitable; consent providers must be synchronous"
        elif isinstance(decision, ConsentDecision):
            if not isinstance(decision.granted, bool):
                problem = f"returned granted={type(decision.granted).__name__}, expected bool"
            elif decision.granted:
                who = decision.decided_by
                if not _valid_identity(who):
                    problem = "returned a grant without a usable decided_by identity"
                elif who in self.service_identities:
                    decided_by = who
                    refusal = f"consent decided by {who!r}, a service identity (self-approval)"
                else:
                    granted, decided_by = True, who
            elif _valid_identity(decision.decided_by):
                decided_by = decision.decided_by
        elif decision is True:
            problem = "returned a bare True, which names nobody; return ConsentDecision(True, who)"
        elif decision is not False and decision is not None:
            problem = f"returned {type(decision).__name__}, expected ConsentDecision or bool"

        self.ledger.consent(principal, granted, decided_by, context, label)
        if problem is not None:
            raise TypeError(f"consent provider for {principal!r} {problem}; treated as refused")
        if refusal is not None:
            raise ConsentRefused(f"consent from {principal!r} refused for {context}: {refusal}")
        if not granted:
            raise ConsentRefused(f"consent from {principal!r} refused for {context}")

    # -- output ----------------------------------------------------------

    def record(self) -> dict:
        """Close and sign the record, provided it still describes this run.

        The fingerprint in the ledger was taken when the session started. If
        the policy in force no longer hashes to it, something replaced part
        of it, and signing would attest to a policy that was not the one
        enforced -- the misleading-but-authoritative record the seal exists to
        prevent. Refuse instead.
        """
        enforced = self.policy.fingerprint()
        if enforced != self.ledger.policy_fingerprint:
            raise PolicyIntegrityError(
                "the policy in force no longer matches the fingerprint recorded at "
                "session start; refusing to produce a record that would misattest it"
            )
        if self.signing_key is None and self.signer is None:
            warnings.warn(
                "no signing key: this record is unsigned and nothing vouches for it; "
                "pass signing_key= or set KELVRA_SIGNING_KEY",
                UnsignedRecordWarning,
                stacklevel=2,
            )
        return self.ledger.to_record(self.signing_key, self.signer)

    # -- capability separation -------------------------------------------

    def agent_session(self) -> AgentSession:
        """The only surface to hand to model-driven code.

        ``declassify`` and ``endorse`` are privileged: they are the one place
        a label is relaxed, and an untrusted-integrity input that can reach
        them can launder itself. Whoever builds the pipeline holds this
        object; the agent, its tools and its adapter get the session.
        """
        return AgentSession(self)

    def report(self) -> str:
        return "\n".join(self.ledger.summary_lines())


def _valid_identity(identity: object) -> bool:
    return (
        isinstance(identity, str)
        and 0 < len(identity) <= _MAX_IDENTITY
        and identity.isprintable()
        and identity == identity.strip()
    )


class AgentSession:
    """What model-driven code is allowed to touch: read, join, emit. Nothing else.

    The privileged operations -- ``declassify`` (which also covers ``endorse``),
    the policy, the ledger and ``record`` -- are deliberately absent. An agent
    steered by injected content can still *try* to send data somewhere, and
    the flow rule decides; it cannot widen a label or vouch for its own input.

    This is a capability boundary inside one process, not a sandbox: code that
    reaches for private attributes can get back to the :class:`Kelvra` object.
    Real isolation is a process boundary, which is what an adapter is for. What
    this does give is that the privileged path is no longer an *ordinary*
    method on the object an agent is handed, so it cannot be called by accident
    or by a tool wrapper that forwards arbitrary method names.
    """

    __slots__ = ("_kelvra",)

    def __init__(self, kelvra: Kelvra) -> None:
        self._kelvra = kelvra

    def read(self, source_name: str, value: T) -> Tainted[T]:
        return self._kelvra.read(source_name, value)

    def model_call(
        self,
        site: str,
        *inputs: Tainted,
        produce: Callable[..., object] | None = None,
        via: str | None = None,
    ) -> Tainted:
        return self._kelvra.model_call(site, *inputs, produce=produce, via=via)

    def combine(self, site: str, *inputs: Tainted) -> Label:
        return self._kelvra.combine(site, *inputs)

    def emit(self, sink_name: str, tainted: Tainted[T]) -> T:
        return self._kelvra.emit(sink_name, tainted)

    def emit_text(self, sink_name: str, tainted: Tainted[str]) -> str:
        return self._kelvra.emit_text(sink_name, tainted)

    def would_allow(self, sink_name: str, tainted: Tainted) -> bool:
        return self._kelvra.would_allow(sink_name, tainted)
