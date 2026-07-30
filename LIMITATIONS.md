# Kelvra — Known limitations

Kept public and current on purpose. A security project that hides what it hasn't solved is worth less than one that doesn't exist.

For what Kelvra does not *defend against*, see the [threat model](spec/threat-model.md). This document covers what is unbuilt, untested, or unresolved.

---

## The big one

**There is no implementation.** No instrumentation, no parser, no emitted record, not one line of working code. The design has more documents than it has functions. Treat every claim here as intent, not as a description of software.

## Unresolved design problems

**Label creep.** Any label propagation drifts: keep joining labels and eventually everything is confidential and nothing is permitted. This is the standard practical failure mode of dynamic IFC, and Kelvra has no strategy for it. If you have seen this solved well in production, please open an issue.

**Propagation granularity is undecided.** Per value, per message, per tool call? Each choice trades precision against overhead, and the answer should come from observing real pipelines rather than from reasoning.

**Persistent memory is unaddressed.** An agent that keeps state across runs carries labels across runs too. Recent work identifies cross-session persistence as a major axis. Kelvra says nothing about it.

**Multi-agent systems are unaddressed.** When one agent delegates to another, labels must cross the boundary. Not designed.

**Compiling to third-party engines is untested.** The positioning depends on being able to translate a `.klv` policy into the input of an existing engine (OPA/Rego, or a FIDES-style system). Nothing has been attempted. If this turns out to be impractical, the positioning needs rethinking.

**No performance budget.** Commercial guardrails advertise sub-50ms. Nothing indicates label propagation fits in that envelope, and no measurement exists.

**Format versioning is unspecified.** The provenance record carries a version field. There is no compatibility policy behind it.

## Unvalidated assumptions

**No user has ever been asked.** No conversation with a developer building agents, a CISO, a DPO, or an auditor. The claim that a provenance record is the artifact compliance teams want is a hypothesis held by people who have never sold to a compliance team.

**"A spec beats an engine" is a bet, not a result.** It rests on historical analogies — SQL, TypeScript, OpenTelemetry, SPIFFE. Analogies are reassuring and prove nothing.

**A standard cannot be declared unilaterally.** Formats that win emerge from consortia, not from individual repositories. No institutional home has been sought. If none is found, Phase 3 fails and Kelvra becomes one more tool.

**No legal review.** The reading that a flow-provenance record satisfies a traceability obligation is a reasonable interpretation by non-lawyers. No counsel, DPO, or authority has confirmed it.

## Regulatory dependency

Part of the case for Kelvra rests on traceability obligations for high-risk AI systems under the EU AI Act. Two caveats:

- A delay of parts of the Act has been proposed and was still under negotiation as of mid-2026. If it passes, the commercial urgency thins considerably.
- Two logging standards were in draft (prEN 18229-1, ISO/IEC DIS 24970) and neither had been finalized. If they land first and land well, the gap Kelvra targets closes without us.

Both are perishable facts. If you are reading this well after mid-2026, verify them rather than trusting this file.

## Corrections to earlier versions of this project

Recorded rather than deleted, because the reasoning errors are more instructive than the conclusions.

**"No structural competitor occupies this intersection."** This was published here and it was false. [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind, March 2025) and [FIDES](https://arxiv.org/abs/2505.23643) (Microsoft Research, May 2025) already implemented the core thesis. The claim rested on names encountered incidentally while checking whether a project name was available — never on a dedicated search.
*Lesson: absence of results in a search run for another purpose is not evidence of absence.*

**"The regulatory argument is an extrapolation with no specific text behind it."** The opposite error, and it cost more. The article existed, the date was known, and the standards gap was publicly documented. The project spent months underrating its strongest argument for want of a ten-minute search.
*Lesson: epistemic humility is only useful when it triggers verification. Otherwise it is just well-phrased ignorance.*

**The corrected competitive map was still incomplete.** After the first entry above was fixed, the survey still missed [AgentArmor](https://arxiv.org/abs/2508.01249) — a type system over agent execution traces with control and data flow graphs, and the closest neighbour this project has — along with [IPIGuard](https://arxiv.org/abs/2508.15310) and several behavioural defences.

The uncomfortable part: every one of them was already cited in a state-of-the-art document the same author had written a month earlier for an adjacent project. The best-placed source was one directory away and was never consulted.
*Lesson: a literature search that only looks outward misses what you already know. Read your own notes before searching the web.*

**A published figure went stale.** The README claimed the best result in this space cleared "roughly two thirds" of a benchmark's attacks. That was accurate for CaMeL and obsolete once AgentArmor reported 3% attack success on AgentDojo for a 1% utility cost.
*Lesson: a number quoted to bound someone else's work needs a date attached, or a plan to re-check it.*
