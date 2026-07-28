"""Static analysis of a policy, before anything runs.

This is where Kelvra's value arrives earliest. Telling someone at authoring
time that a sink can never receive data, or that an injected email can drive
a privileged write, is worth more than catching it at runtime -- and far more
than catching it in an incident review.

Soundness contract
------------------
Every finding here is **definite**. The analysis reports a problem only when
no execution can avoid it, and stays silent otherwise.

That direction is deliberate. A policy check that cries wolf gets switched
off, and a check that is switched off protects nothing. So the analysis is
allowed to miss problems; it is not allowed to invent them.

Concretely: labels only ever get *more* restrictive as data flows, because
propagation joins and join is intersection (see spec/labels.md section 3).
The only thing that relaxes a label is a declared declassifier. So for any
source, the most permissive label it can ever carry is its own label with
every declassifier's grants unioned onto it. If a sink cannot accept even
that, no execution can reach it -- which is a fact, not a guess.

The converse does not hold. A sink that accepts the optimistic label may
still be unreachable in practice, because a real pipeline joins several
sources together and drives the label back down. The analysis therefore
never claims a sink *is* reachable, only that it is not provably unreachable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .labels import Label
from .policy import Policy, Sink, check_flow

Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Finding:
    """One thing wrong with a policy."""

    code: str
    severity: Severity
    subject: str
    message: str
    hint: str = ""

    def __str__(self) -> str:
        out = f"{self.severity}[{self.code}] {self.subject}: {self.message}"
        if self.hint:
            out += f"\n  hint: {self.hint}"
        return out


def _most_permissive(label: Label, policy: Policy) -> Label:
    """The label after every declassifier has been applied.

    Declassifiers only ever union in grants, and union is commutative and
    idempotent, so applying all of them gives the upper bound directly. There
    is no need to search subsets.
    """
    readers = label.readers
    endorsers = label.endorsers
    purposes = label.purposes
    for d in policy.declassifiers.values():
        readers = readers | d.grants_readers
        endorsers = endorsers | d.grants_endorsement
        purposes = purposes | d.grants_purposes
    return Label(readers, endorsers, purposes)


def _reaches(label: Label, sink: Sink, policy: Policy) -> bool:
    return check_flow(_most_permissive(label, policy), sink).allowed


def analyse(policy: Policy) -> list[Finding]:
    """Check a policy for definite problems. Empty list means none found."""
    findings: list[Finding] = []
    findings += _unsatisfiable_sinks(policy)
    findings += _injection_surface(policy)
    findings += _trapped_sources(policy)
    findings += _unused_declassifiers(policy)
    return findings


# -- the findings -----------------------------------------------------------


def _unsatisfiable_sinks(policy: Policy) -> list[Finding]:
    """A sink no source can ever satisfy.

    The highest-value diagnostic in the language. It means the author wrote a
    flow that cannot happen -- usually a typo in an audience, or a required
    endorsement that nothing grants. Left alone it surfaces in production as
    an agent that mysteriously never does one of its jobs.
    """
    findings = []
    for name, sink in sorted(policy.sinks.items()):
        if any(_reaches(s.label, sink, policy) for s in policy.sources.values()):
            continue

        if not policy.sources:
            continue  # nothing to say about a policy with no sources

        reasons = _why_unsatisfiable(policy, sink)
        findings.append(
            Finding(
                code="unsatisfiable-sink",
                severity="error",
                subject=f"sink {name!r}",
                message=(
                    "no declared source can reach this sink, even after applying "
                    "every declassifier"
                ),
                hint=reasons,
            )
        )
    return findings


def _why_unsatisfiable(policy: Policy, sink: Sink) -> str:
    """Name the axis that blocks every source, when they all agree."""
    blocking: set[str] = set()
    for source in policy.sources.values():
        decision = check_flow(_most_permissive(source.label, policy), sink)
        for reason in decision.reasons:
            if "permitted to read" in reason:
                blocking.add("audience")
            elif "endorsement" in reason:
                blocking.add("endorsement")
            elif "purpose" in reason:
                blocking.add("purpose")

    if blocking == {"audience"}:
        return (
            f"the audience {sink.audience!r} is never permitted to read; either "
            "widen a declassifier's 'to', or check the audience for a typo"
        )
    if blocking == {"endorsement"}:
        return (
            f"nothing grants endorsement by {sink.requires_endorsement!r}; add an "
            "'endorse' declaration that grants it"
        )
    if blocking == {"purpose"}:
        return f"no source permits the purpose {sink.purpose!r}"
    return f"blocked on: {', '.join(sorted(blocking))}"


def _injection_surface(policy: Policy) -> list[Finding]:
    """A sink that untrusted data can reach without any endorsement.

    This is the shape of the attack the project exists for: content an
    attacker controls reaches an action. Kelvra cannot tell whether the sink
    is dangerous -- posting to a log is not writing to a bank -- so this is a
    warning that names the exposure rather than an error.
    """
    findings = []
    untrusted = {
        name: source
        for name, source in policy.sources.items()
        if source.label.is_untrusted
    }
    if not untrusted:
        return findings

    for sink_name, sink in sorted(policy.sinks.items()):
        if not sink.requires_endorsement.is_empty:
            continue  # the sink demands a vouch; injection cannot supply one
        if sink.requires_consent_from is not None:
            continue  # a human stands in the way

        reachable = sorted(
            name for name, source in untrusted.items() if _reaches(source.label, sink, policy)
        )
        if not reachable:
            continue

        findings.append(
            Finding(
                code="untrusted-reaches-sink",
                severity="warning",
                subject=f"sink {sink_name!r}",
                message=(
                    "reachable by untrusted data from "
                    + ", ".join(repr(n) for n in reachable)
                    + ", with no endorsement or consent required"
                ),
                hint=(
                    "if this sink takes an action rather than just recording one, "
                    "injected content can drive it. Add 'requires endorsed(...)' "
                    "or 'requires consent(...)'"
                ),
            )
        )
    return findings


def _trapped_sources(policy: Policy) -> list[Finding]:
    """A source whose data can reach no sink at all.

    Either the source is dead weight, or a declassifier is missing. Both are
    worth knowing; neither is definitely a bug, so it is a warning.
    """
    findings = []
    if not policy.sinks:
        return findings

    for name, source in sorted(policy.sources.items()):
        if any(_reaches(source.label, sink, policy) for sink in policy.sinks.values()):
            continue
        findings.append(
            Finding(
                code="trapped-source",
                severity="warning",
                subject=f"source {name!r}",
                message="data from this source can reach no declared sink",
                hint=(
                    "this is safe but probably not intended -- the source is either "
                    "unused, or a declassifier that would let it out is missing"
                ),
            )
        )
    return findings


def _unused_declassifiers(policy: Policy) -> list[Finding]:
    """A declassifier no source→sink pair needs.

    Declassifiers are the only places a leak is possible, so an unnecessary
    one is pure attack surface. Removing it costs nothing and shrinks what an
    auditor has to reason about.
    """
    findings = []
    if not policy.sources or not policy.sinks:
        return findings

    for name in sorted(policy.declassifiers):
        without = Policy(
            name=policy.name,
            version=policy.version,
            sources=dict(policy.sources),
            sinks=dict(policy.sinks),
            declassifiers={k: v for k, v in policy.declassifiers.items() if k != name},
        )

        needed = False
        for source in policy.sources.values():
            for sink in policy.sinks.values():
                if _reaches(source.label, sink, policy) and not _reaches(
                    source.label, sink, without
                ):
                    needed = True
                    break
            if needed:
                break

        if not needed:
            findings.append(
                Finding(
                    code="unused-declassifier",
                    severity="warning",
                    subject=f"declassifier {name!r}",
                    message="no source-to-sink flow requires this declassification",
                    hint=(
                        "a declassifier is the only place a leak can happen, so an "
                        "unnecessary one is attack surface an auditor must review "
                        "for nothing"
                    ),
                )
            )
    return findings


# -- reporting --------------------------------------------------------------


def worst_severity(findings: list[Finding]) -> Severity | None:
    if any(f.severity == "error" for f in findings):
        return "error"
    if findings:
        return "warning"
    return None


def describe_reachability(policy: Policy) -> list[str]:
    """A human-readable reachability table.

    Not a check -- this is what someone reviewing a policy actually wants to
    see, and it is the same computation the findings run on.
    """
    lines = []
    for sink_name, sink in sorted(policy.sinks.items()):
        reachable = sorted(
            name
            for name, source in policy.sources.items()
            if _reaches(source.label, sink, policy)
        )
        direct = sorted(
            name
            for name, source in policy.sources.items()
            if check_flow(source.label, sink).allowed
        )
        if not reachable:
            lines.append(f"{sink_name}: unreachable")
            continue
        detail = ", ".join(
            f"{n} (direct)" if n in direct else f"{n} (via declassification)"
            for n in reachable
        )
        lines.append(f"{sink_name}: {detail}")
    return lines


__all__ = [
    "Finding",
    "Severity",
    "analyse",
    "describe_reachability",
    "worst_severity",
]
