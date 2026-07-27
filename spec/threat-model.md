# Kelvra — Threat model

**Status: draft. Nothing here has been validated against an implementation, because there is no implementation.**

This document exists because a security mechanism without a named adversary cannot be evaluated. If you take one thing from it, take [section 3](#3-what-kelvra-does-not-defend-against) — what Kelvra explicitly does *not* defend against.

---

## 1. The system under consideration

An LLM-based agent that:

1. reads data from **sources** — mailbox, document store, CRM, API, files, RAG index;
2. passes it through one or more model calls;
3. calls **tools**, typically over MCP;
4. writes to **sinks** — sending a message, writing to a database, calling an outbound API, replying to a user;
5. optionally retains **memory** across runs.

Kelvra sits between these. It is not the model, not the framework, not the tools.

### Vocabulary

- **Source** — where data enters the agent.
- **Sink** — where data becomes observable outside the agent's boundary.
- **Label** — what a piece of data carries: confidentiality, integrity, purpose.
- **Declassification** — an explicitly declared operation that lowers a confidentiality label (e.g. anonymization) or raises an integrity label (e.g. human review).
- **Trust base (TCB)** — components whose correctness is assumed. If one is compromised, the guarantees fall.

## 2. Adversaries in scope

### A1 — The careless developer *(low value)*

A competent, well-intentioned developer who lets sensitive data reach a sink it shouldn't — logging a whole object during debugging, and with it customer data.

Low value because linters and code review already catch some of this. It is nonetheless the adversary most privacy tooling implicitly targets.

### A2 — Hostile injected content *(primary adversary)*

An attacker who controls neither code nor infrastructure, but controls **data the agent will read**: an inbound email, a fetched web page, a document dropped into a RAG index, a support ticket, a repository comment. They place instructions there to redirect the agent.

Typical goals: exfiltrate data the agent legitimately holds, trigger a privileged action, or poison memory for subsequent runs.

This is indirect prompt injection — OWASP LLM01, publicly unresolved at the model level. It is the only adversary against which a structural approach offers something no heuristic does.

**This is an *integrity* violation, not a confidentiality one.** Untrusted data travels up to influence a control decision. A confidentiality-only label model is structurally incapable of describing this attack. That is why Kelvra requires two axes.

### A3 — The malicious tool or MCP server *(partially in scope)*

A tool the agent can call that lies — a misleading description to get itself invoked (tool poisoning), or falsified return data to steer subsequent reasoning.

**Covered:** a tool is declared as both sink and source with its labels; an undeclared tool is not callable, and a declared one cannot receive more than its declaration permits.
**Not covered:** detecting that a tool lies about what it does.

## 3. What Kelvra does not defend against

### A4 — The hostile developer *(out of scope)*

Someone on the inside who deliberately wants to exfiltrate data.

**No mechanism of this kind stops them, and saying otherwise would be the easiest oversell to dismantle.** They can simply not use Kelvra, or declare a declassifier that lets everything through.

What Kelvra still offers is not nothing: an abusive declassification is **visible in plain text in a short policy file** rather than buried in three thousand lines of Python. That moves the problem from technical detection to human review and audit. That is real progress. It is not a security guarantee.

### A5 — The model provider *(out of scope)*

An inference provider that retains or exploits transmitted data. Once data is sent to a remote model, it has left the boundary. Kelvra can *declare* a remote model call as a sink and require data to arrive already declassified. Beyond that, nothing.

### A6 — Side channels *(out of scope, for now)*

Exfiltration through execution time, call counts, output length, or steganographic encoding inside otherwise-authorized text.

A real and well-documented problem in classical IFC. Explicitly out of scope: addressing it needs resources unrelated to this project's. To be revisited if Kelvra reaches industrial maturity.

## 4. Security properties targeted

**P1 — Declared confinement.** No data carrying confidentiality label `L` reaches a sink that does not accept `L`, except through a declassification declared in the policy file.

**P2 — Complete traceability.** Every declassification actually taken during a run appears in that run's provenance record.

**P3 — Integrity barrier.** No low-integrity data influences a privileged action without passing a declared integrity upgrade — programmatic validation, or human consent.

**P4 — Tamper-evident proof.** The provenance record is signed, and alteration is detectable after the fact.

**P5 — Data-bound consent.** An action marked `requires_consent` does not execute without explicit human agreement, and that agreement is recorded alongside the labels of the data involved.

## 5. Non-properties

Kelvra does **not**:

- **N1** — guarantee a model won't disclose sensitive data *inside an authorized channel*. If an authorized summary contains something it shouldn't, Kelvra does not see it.
- **N2** — guarantee a declassifier is semantically correct. A bad anonymizer leaks; the leak is merely recorded.
- **N3** — detect side channels (A6).
- **N4** — stop a hostile developer (A4).
- **N5** — protect data past the process boundary (A5).
- **N6** — detect that a tool lies about its function (A3, partial).

## 6. Trust base

P1–P5 assume the following components are correct. **This list is the system's real attack surface.**

| Component | Why it's in the TCB | If compromised |
|---|---|---|
| Instrumentation runtime | Propagates labels, blocks flows | All properties fall |
| Source label declarations | Nothing verifies a source declared `public` really is | Silent leak, invisible to audit |
| Declassifier implementations | They do the actual anonymization | N2 |
| Provenance signing key | It underpins P4 | Audit proof becomes forgeable |
| Enforcement point (MCP gateway or interpreter) | It applies decisions | Complete bypass |

**The weakest link is the second one.** Initial source labeling is declarative: someone asserts that a given source holds confidential data. If that assertion is wrong or forgotten, everything else works correctly and accomplishes nothing.

There is no technical fix for this. It is an organizational process problem, and it should be stated rather than hidden.

## 7. What this document still lacks

- None of these scenarios has been reviewed by a practitioner in post — no CISO, DPO, or working security engineer. This is desk analysis.
- No formal modeling (STRIDE, LINDDUN, or equivalent) has been performed.
- P1–P5 are not stated formally enough to be proved. They are stated precisely enough to be tested, which is the useful step today.
- No explicit mapping to the OWASP Top 10 for LLM Applications has been produced.

Pushback on any of the above — particularly on the out-of-scope decisions — is the most valuable contribution this project can receive right now.
