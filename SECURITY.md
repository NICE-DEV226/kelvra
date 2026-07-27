# Security policy

## Current scope

Kelvra is at the specification stage. **There is no code, therefore no vulnerabilities in code.**

What can meaningfully be reported today is a **design flaw**: a case where the model described in the [threat model](spec/threat-model.md) or the [architecture](README.md#a-first-look) would fail to hold even if implemented exactly as specified.

Examples of what is in scope right now:

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
