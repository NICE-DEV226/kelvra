# Kelvra provenance record

**Version 0.1 — draft. Status: unstable.**

The provenance record is what a Kelvra run produces for someone who was not
in the room: an auditor, a data protection officer, a regulator. It is the
artifact with value outside engineering, and it is specified here so that it
can be produced without reading the reference implementation.

Label semantics are in [labels.md](labels.md). What the system defends
against is in [threat-model.md](threat-model.md).

RFC 2119 keywords apply.

---

## 1. What the record is for

Three questions, answerable from the record alone:

1. **What policy was in force?** — name, version, and a fingerprint that
   proves which text of it ran.
2. **Where did sensitive data go, and through what?** — every declassification
   taken, every flow permitted.
3. **What was refused?** — every flow denied, and why.

The third is not a bonus. For an auditor, evidence that a system refused a
flow is worth as much as evidence of the ones it allowed. An implementation
that records only successes has not implemented this specification.

## 2. The payload rule

> **A provenance record MUST NOT contain the data it describes.**

No message bodies, no tool arguments, no model outputs, no retrieved
documents. Only names, labels, decisions and timestamps.

This is the single most important rule in this document. A record of who
touched confidential data, which itself contains the confidential data, is a
new copy of the problem — one that gets shipped to auditors, stored for
years under a retention obligation, and read by people with no need to see
it. An implementation that embeds payloads is not conforming, however
convenient the debugging.

Implementations MAY record a cryptographic hash of a payload where linking
matters. They MUST NOT record the payload.

## 3. Structure

```jsonc
{
  "kelvra_version": "0.1.0",
  "policy":  { "name": "...", "version": 1, "fingerprint": "sha256:..." },
  "run_id":  "...",
  "started_at": "...", "ended_at": "...",
  "summary": { "...": 0 },
  "events":  [ /* ordered, append-only */ ],
  "signature": "hmac-sha256:..."
}
```

### Top level

| Field | Type | Required | Notes |
|---|---|---|---|
| `kelvra_version` | string | yes | Version of *this specification* the record claims to follow |
| `policy` | object | yes | See below |
| `run_id` | string | yes | Unique per run. UUIDv4 RECOMMENDED |
| `started_at` | RFC 3339 timestamp | yes | MUST include a timezone offset |
| `ended_at` | RFC 3339 timestamp | yes | |
| `summary` | object | yes | Derivable from `events`; present so a reader need not compute it |
| `events` | array | yes | Ordered oldest-first. MUST NOT be reordered after the fact |
| `signature` | string | no | Absent means unsigned, not "signature omitted" |

### `policy`

| Field | Type | Notes |
|---|---|---|
| `name` | string | |
| `version` | integer | |
| `fingerprint` | string | `sha256:` + hex of a canonical serialisation of the policy |

The fingerprint is what makes the record auditable. Without it, a record
attests to "policy SupportAgent v1" — a label anyone can reuse over changed
content. Implementations MUST compute it over the effective policy, not over
the source file, so that two textually different files with identical
semantics produce the same fingerprint.

> **The policy MUST NOT change during a run.** An implementation MUST either
> reject a mid-run modification or enforce against a snapshot taken at the
> start; it MUST NOT allow enforcement to follow a policy the fingerprint no
> longer describes.
>
> Without this, a record can attest to policy *A* while some flows were
> checked against policy *B* — and it does so under a signature, which is
> what makes it dangerous rather than merely wrong. A misleading record that
> looks authoritative is worse than no record. The reference implementation
> seals the policy when a session is created; the caller's own object stays
> mutable and simply no longer reaches the run.

### `summary`

| Field | Meaning |
|---|---|
| `sources_read` | count of `read` events |
| `declassifications` | count of `declassify` events |
| `consents` | count of `consent` events |
| `allowed` | count of `allow` events |
| `denied` | count of `deny` events |

A consumer MUST be able to recompute every field from `events`. A record
whose summary disagrees with its events is malformed, and a verifier SHOULD
reject it rather than trusting either.

## 4. Events

Every event carries `kind` and `at`. Labels are serialised as in §5.

### `read` — data entered

```json
{ "kind": "read", "at": "...", "source": "inbox.imap", "label": { ... } }
```

### `join` — labels combined

```json
{ "kind": "join", "at": "...", "site": "agent.plan",
  "inputs": ["inbox.imap", "crm.customer_record"], "result": { ... } }
```

Emitted for model calls and any other combination point. `inputs` holds
origin identifiers, not values. Because a model call is a total join
([labels.md](labels.md) §7), `result` is the join of every input label.

### `declassify` — a label was relaxed

```json
{ "kind": "declassify", "at": "...", "declassifier": "pii_redaction",
  "before": { ... }, "after": { ... }, "consent_from": null }
```

MUST be emitted on every use, including uses whose resulting flow is later
denied. An attempt to declassify is itself information an auditor wants.

### `consent` — a human decision

```json
{ "kind": "consent", "at": "...", "principal": "customer",
  "granted": false, "granted_by": null, "context": "emit:crm.write" }
```

MUST be emitted whether granted or refused. `granted_by` identifies who
actually decided, which is not always the principal whose consent was
required.

### `allow` / `deny` — a flow reached a sink

```json
{ "kind": "allow", "at": "...", "sink": "slack.support_channel", "label": { ... } }

{ "kind": "deny",  "at": "...", "sink": "crm.write", "label": { ... },
  "reasons": ["audience ... is not permitted to read ...",
              "sink requires endorsement by ... but got untrusted data"] }
```

`reasons` MUST list every failing check, not the first. An auditor needs to
know whether one axis failed or three — a flow that fails only on integrity
is a different situation from one that fails on everything.

## 5. Label serialisation

```json
{ "readers": ["customer", "support_team"], "endorsers": "*", "purposes": ["support"] }
```

Each axis is either an array of names or the string `"*"` for the universe.
Arrays MUST be sorted, so that two records describing the same label compare
equal byte for byte.

`"*"` and `["*"]` are different: the first is the universe, the second is a
one-element set containing a principal literally named `*`. Implementations
SHOULD reject `*` as a principal name to remove the ambiguity.

## 6. Signing

Canonical form for signing: the record with `signature` removed, serialised
as JSON with sorted keys and no insignificant whitespace, UTF-8 encoded.

The reference implementation uses HMAC-SHA256, giving
`"hmac-sha256:<hex>"`.

> **HMAC is a compromise and its limits belong in the open.** It proves the
> record was produced by a holder of the key. It proves nothing to a third
> party who does not hold that key — and an auditor who holds the key could
> have forged the record. For an audit artifact whose purpose is to convince
> someone outside the organisation, that is the wrong shape.
>
> A deployment that needs independent verification MUST use asymmetric
> signatures. The reference implementation does not, because the core carries
> no third-party dependencies, and this trade is stated rather than hidden.
> Future versions SHOULD define an Ed25519 form as `"ed25519:<...>"`.

Verification MUST be constant-time.

## 7. Mapping to OpenTelemetry

Kelvra does not invent a transport. The record above is the self-contained
audit artifact; for live telemetry, implementations SHOULD also emit
OpenTelemetry spans using the GenAI semantic conventions.

Those conventions are **pre-stable** — as of semantic-conventions v1.42.0
(June 2026) all `gen_ai.*` attributes moved to a dedicated repository and
there is no 1.0. Names below may change. That instability is also the
opportunity: a label extension has a real chance of being adopted upstream
while the conventions are still in development, which is a far better
outcome than a schema published alone.

### Span shape

| Kelvra concept | OTel span | `gen_ai.operation.name` |
|---|---|---|
| a run | one span | `invoke_agent` |
| a model call (`join`) | child span | `chat` |
| a tool call (`read` / `allow` / `deny`) | child span | `execute_tool` |

Relevant existing attributes, used unchanged: `gen_ai.provider.name` (note:
`gen_ai.system` is deprecated in its favour), `gen_ai.agent.name`,
`gen_ai.agent.id`, `gen_ai.tool.name`, `gen_ai.tool.call.id`,
`gen_ai.tool.type`, `gen_ai.conversation.id`.

### Proposed `kelvra.*` attributes

| Attribute | Type | On |
|---|---|---|
| `kelvra.policy.name` | string | `invoke_agent` |
| `kelvra.policy.version` | int | `invoke_agent` |
| `kelvra.policy.fingerprint` | string | `invoke_agent` |
| `kelvra.run.id` | string | `invoke_agent` |
| `kelvra.label.readers` | string[] | any |
| `kelvra.label.endorsers` | string[] | any |
| `kelvra.label.purposes` | string[] | any |
| `kelvra.flow.decision` | string | `execute_tool` — `allow` or `deny` |
| `kelvra.flow.sink` | string | `execute_tool` |
| `kelvra.flow.denial_reasons` | string[] | `execute_tool` when denied |
| `kelvra.declassifier.name` | string | span event |
| `kelvra.consent.principal` | string | span event |
| `kelvra.consent.granted` | boolean | span event |

A denied flow SHOULD set the span status to `ERROR` with the first denial
reason as the description. Denials are the signal most worth alerting on.

**The payload rule of §2 applies to spans without exception.** GenAI
conventions permit capturing prompt and completion content behind an opt-in;
Kelvra attributes MUST NOT be used to carry any of it.

## 8. Retention

Not specified here, because it is a legal question rather than a technical
one and the answer differs by jurisdiction and by system. Two things follow
from §2 and are worth stating anyway: a record containing no payloads is far
cheaper to retain for years than one that does, and it can be shared with an
auditor without a second review of what is inside it. That is most of the
argument for the payload rule.

## 9. Conformance

An implementation conforms if it:

1. emits every field marked required in §3;
2. never embeds payload data (§2);
3. prevents the governing policy from changing during a run (§3);
4. emits `declassify` on every use, including ones whose flow is later
   denied;
5. emits `consent` on refusal as well as grant;
6. records every failing check in `deny.reasons`, not only the first;
7. sorts label arrays and distinguishes `"*"` from `["*"]`;
8. produces a summary that a consumer can recompute from the events;
9. signs over the canonical form of §6, or omits `signature` entirely.

## 10. Open questions

- **No streaming form.** The record is built in memory and emitted at the
  end. A long-running or crashed agent produces nothing. An append-only
  on-disk form is needed and is not designed.
- **No redaction story for the record itself.** Source and sink names can
  themselves be sensitive — `crm.oncology_patients` leaks by existing.
- **Ed25519 signing is described but not specified.**
- **Cross-run linking is undefined.** An agent with persistent memory carries
  labels between runs; nothing here connects two records.
- **Multi-agent runs are undefined.** Whether delegation produces one record
  or several, and how they reference each other, is unresolved.

## Changelog

- **0.1** — first draft, extracted from the reference implementation. The
  payload rule and the OTel mapping are new here rather than derived from
  code.
