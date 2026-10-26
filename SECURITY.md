# Security policy

## Current scope

Kelvra is pre-alpha. It has a small reference implementation (`src/kelvra/`: parser, analysis, runtime, provenance, language server) and **no deployment anyone should rely on**, so both implementation bugs and design flaws are in scope.

An *implementation* vulnerability is a case where the code does not do what the specification says, or where a safeguard can be bypassed by an input or caller the specification covers. A *design flaw* is a case where the model in the [threat model](spec/threat-model.md) would fail to hold even if implemented exactly as specified.

Examples of what is in scope:

- a policy file whose enforced meaning differs from what a reviewer reads;
- a way to obtain a label, an endorsement or a consent that the specification says cannot be obtained;
- a provenance record that verifies but misdescribes the run;
- an input that makes the parser, analysis or verifier raise, hang or crash;

- a flow that satisfies the label rules as written but still leaks;
- an adversary in [section 2](spec/threat-model.md#2-adversaries-in-scope) that the design does not actually cover, contrary to what is claimed;
- a property among P1–P5 that is unachievable as stated;
- a component missing from the declared trust base.

## Reporting

Use **GitHub private vulnerability reporting** on this repository (Security → Report a vulnerability). If that is unavailable to you, open a normal issue **without** operational detail and ask for a private channel.

Please include: the property you believe is broken, a concrete scenario, and where in the spec the gap sits.

## What to expect

This is a solo, early-stage project with no funding and no SLA. Realistically: an acknowledgement within a week, and a substantive answer when there is one. There is no bug bounty.

Reports that identify a genuine design flaw will be credited in the repository unless you prefer otherwise.

## Out of scope

- Prompt injection against language models in general. That is the problem the project exists to mitigate the *consequences* of, not a vulnerability in Kelvra.
- Anything listed as a non-property in [section 5 of the threat model](spec/threat-model.md#5-non-properties). Those are documented, deliberate limits — reporting them as vulnerabilities is welcome as *discussion*, but they are not defects.
- Vulnerabilities in third-party engines, frameworks, or MCP servers. Report those upstream.
