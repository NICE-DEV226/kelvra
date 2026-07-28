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

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from .labels import Label, join_all
from .policy import Declassifier, Policy, Sink, check_flow
from .provenance import Ledger, key_from_env

T = TypeVar("T")


class Denied(Exception):
    """A flow was refused. Carries the decision so callers can inspect why."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(f"flow to {decision.sink!r} denied: {decision.reason}")


class ConsentRefused(Exception):
    pass


@dataclass(frozen=True)
class Tainted(Generic[T]):
    """A value together with what it carries.

    Deliberately not transparent: it does not forward attribute access or
    arithmetic to the wrapped value. Unwrapping is explicit, via
    :meth:`Kelvra.emit` or :attr:`unsafe_value`, so that losing a label is
    something you had to type rather than something that happened to you.
    """

    value: T
    label: Label
    origin: str

    @property
    def unsafe_value(self) -> T:
        """Escape hatch. Every use is a hole in the model; grep for it."""
        return self.value

    def map(self, fn: Callable[[T], object], *, note: str = "map") -> Tainted:
        """Transform the value, keeping the label. Never relaxes anything."""
        return Tainted(fn(self.value), self.label, f"{self.origin}|{note}")

    def __repr__(self) -> str:
        return f"Tainted({self.origin}: {self.label.describe()})"


ConsentProvider = Callable[[str, str], bool]
"""Called as ``(principal, context) -> granted``."""


def deny_all_consent(principal: str, context: str) -> bool:
    return False


class Kelvra:
    """A policy, a ledger, and the operations that connect them."""

    def __init__(
        self,
        policy: Policy,
        *,
        signing_key: bytes | None = None,
        consent: ConsentProvider = deny_all_consent,
    ) -> None:
        self.policy = policy
        self.signing_key = signing_key if signing_key is not None else key_from_env()
        self.consent_provider = consent
        self.ledger = Ledger(
            policy_name=policy.name,
            policy_version=policy.version,
            policy_fingerprint=policy.fingerprint(),
        )

    # -- entry -----------------------------------------------------------

    def read(self, source_name: str, value: T) -> Tainted[T]:
        """Bring a value in, labelled by its declared source."""
        try:
            source = self.policy.sources[source_name]
        except KeyError:
            raise LookupError(
                f"source {source_name!r} is not declared in policy {self.policy.name!r}"
            ) from None
        self.ledger.read(source.name, source.label)
        return Tainted(value, source.label, source.name)

    # -- propagation -----------------------------------------------------

    def model_call(
        self, site: str, *inputs: Tainted, produce: Callable[..., object] | None = None
    ) -> Tainted:
        """Run a model call. The output carries the join of every input.

        ``produce`` receives the raw values and returns the model's output.
        If omitted, the inputs are returned as a tuple, which is useful for
        testing propagation without spending tokens.
        """
        label = join_all(t.label for t in inputs)
        self.ledger.join(site, [t.origin for t in inputs], label)
        raw = tuple(t.value for t in inputs)
        out = produce(*raw) if produce is not None else raw
        return Tainted(out, label, site)

    def combine(self, site: str, *inputs: Tainted) -> Label:
        """Join labels without producing a value."""
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
        """
        try:
            d: Declassifier = self.policy.declassifiers[name]
        except KeyError:
            raise LookupError(
                f"declassifier {name!r} is not declared in policy {self.policy.name!r}"
            ) from None

        if d.requires_consent_from is not None:
            self._require_consent(d.requires_consent_from, f"declassify:{name}")

        after = d.apply(tainted.label)
        self.ledger.declassify(name, tainted.label, after, d.requires_consent_from)
        value = transform(tainted.value) if transform is not None else tainted.value
        return Tainted(value, after, f"{tainted.origin}|{name}")

    # -- exit ------------------------------------------------------------

    def emit(self, sink_name: str, tainted: Tainted[T]) -> T:
        """Send a value to a sink. Raises :class:`Denied` if the policy refuses.

        This is the enforcement point. Returning the unwrapped value on
        success is intentional: past this line the data has left Kelvra's
        boundary and there is nothing further to track.
        """
        try:
            sink: Sink = self.policy.sinks[sink_name]
        except KeyError:
            raise LookupError(
                f"sink {sink_name!r} is not declared in policy {self.policy.name!r}"
            ) from None

        decision = check_flow(tainted.label, sink)
        if not decision.allowed:
            self.ledger.deny(sink.name, tainted.label, decision.reasons)
            raise Denied(decision)

        if sink.requires_consent_from is not None:
            self._require_consent(sink.requires_consent_from, f"emit:{sink_name}")

        self.ledger.allow(sink.name, tainted.label)
        return tainted.value

    def would_allow(self, sink_name: str, tainted: Tainted) -> bool:
        """Check without recording or raising. For dry runs and tests."""
        return check_flow(tainted.label, self.policy.sinks[sink_name]).allowed

    # -- consent ---------------------------------------------------------

    def _require_consent(self, principal: str, context: str) -> None:
        granted = self.consent_provider(principal, context)
        self.ledger.consent(principal, granted, principal if granted else None, context)
        if not granted:
            raise ConsentRefused(f"consent from {principal!r} refused for {context}")

    # -- output ----------------------------------------------------------

    def record(self) -> dict:
        return self.ledger.to_record(self.signing_key)

    def report(self) -> str:
        return "\n".join(self.ledger.summary_lines())
