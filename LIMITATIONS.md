# Kelvra — Known limitations

Kept public and current on purpose. A security project that hides what it hasn't solved is worth less than one that doesn't exist.

For what Kelvra does not *defend against*, see the [threat model](spec/threat-model.md). This document covers what is unbuilt, untested, or unresolved.

---

## The big one

**There is a reference implementation and no integration.** The parser, analysis, label algebra, in-process runtime, provenance record and language server exist and are tested. What exists beyond the library is one enforcement point: a stdio proxy for MCP servers ([gateway](spec/gateway.md)), which checks tool calls against the *conversation's* label and not against each argument. It has been run against the official MCP SDK's client and server (versions 1.30.0 and 2.3.0), not against any MCP application. There is no framework binding, no HTTP transport, and nothing that stops an agent which can reach its tools without going through the proxy. In-process use is therefore *cooperative*: it holds for code that goes through the session and does not reach into its internals (an `AgentSession` is a capability boundary inside one process, not a sandbox). Treat the guarantees as properties of the library, not of an agent running with it.

## Unresolved design problems

**Label creep.** Any label propagation drifts: keep joining labels and eventually everything is confidential and nothing is permitted. This is the standard practical failure mode of dynamic IFC. It is now measured for one concrete form ([evaluation/README.md](evaluation/README.md#label-creep-with-a-number)): an agent that reads six documents in one model call can hand each result only to someone who may read all six, so about 98% of legitimate deliveries are refused, against none when each document gets its own call. That is the one mitigation Kelvra has, and it is a discipline for whoever writes the pipeline, not something the library does for them. The labels in that measurement are random, and how often a real pipeline can be split is not known. If you have seen this solved well in production, please open an issue.

**Propagation granularity is undecided.** Per value, per message, per tool call? Each choice trades precision against overhead, and the answer should come from observing real pipelines rather than from reasoning.

**Persistent memory is unaddressed.** An agent that keeps state across runs carries labels across runs too. Recent work identifies cross-session persistence as a major axis. Kelvra says nothing about it.

**Multi-agent systems are unaddressed.** When one agent delegates to another, labels must cross the boundary. Not designed.

**Compiling to third-party engines is untested.** The positioning depends on being able to translate a `.klv` policy into the input of an existing engine (OPA/Rego, or a FIDES-style system). Nothing has been attempted. If this turns out to be impractical, the positioning needs rethinking.

**No performance budget.** Commercial guardrails advertise sub-50ms. Nothing indicates label propagation fits in that envelope, and no measurement exists.

**Format versioning is unspecified.** The provenance record carries a version field. There is no compatibility policy behind it.

## What sealing does not do

`Kelvra.seal` and `Kelvra.emit_text` ([design](spec/sealing-cryptographic-design.md),
[threat model](spec/sealing-threat-model.md)) put ciphertext in front of the model. They do not:

- **let the model use the value.** A model cannot reason about a ciphertext. It can copy a token into
  its reply; it cannot read it, compare it, or compute on it. This is not homomorphic encryption.
- **protect against code in the same process.** The `AgentSession` omits the privileged methods; it
  is a capability boundary, not a sandbox. A test asserts that `session._kelvra` is reachable.
- **hide everything from the provider.** It still sees the clear parts of the prompt, each token's
  label (principal names) and kind, the plaintext length to within a 64-byte bucket, and timing.
- **make a mangled token usable.** A model that alters a token gets an error and loses the reply;
  nothing is repaired.
- **rotate keys, or keep the key somewhere better than process memory.** There is no rotation, no key
  registry, and no secret-manager or HSM integration. A key read from an environment variable is
  visible to the user's other processes. The seal count per key is capped at 2^24 to stay far under
  the AES-GCM random-nonce limit; across runs it is not tracked.
- **say in the record which token was opened.** An opened token is an ordinary `allow` with the
  joined label; there is no separate event.
- **resist side channels,** or guarantee that a key leaves no copy in memory.
- **replace external review.** The construction is a composition of standard primitives, tested and
  reviewed by its author, not formally analysed or audited. It has not been run against a live
  provider.

## Unvalidated assumptions

**The adversarial evaluation is a floor, not a measurement.** There is one now
([evaluation/](evaluation/)) — six attacks from a real corpus, five of them
expressible as a data flow and all five contained, no false positives on three
benign controls. But the agent in it is modelled as fully compromised rather
than driven by a real model, so it measures containment and not utility under
attack. It produces no AgentDojo-comparable number, and it will not until there
is a real integration to measure. The policy and the harness were also written
by the same person.

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
