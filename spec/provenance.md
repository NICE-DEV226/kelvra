# Kelvra provenance record

**Version 0.2 — draft. Status: unstable.** Format 0.1 is described under *Compatibility* below.

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
  "chain_head": "sha256:...",
  "events":  [ /* ordered, append-only, hash-chained */ ],
  "signature": "hmac-sha256:..."
}
```

### Top level

| Field | Type | Required | Notes |
|---|---|---|---|
| `kelvra_version` | string | yes | Version of *this specification* the record claims to follow (`0.2.0`). Not the version of the software that wrote it |
| `policy` | object | yes | See below |
| `run_id` | string | yes | Unique per run. UUIDv4 RECOMMENDED |
| `started_at` | RFC 3339 timestamp | yes | MUST include a timezone offset |
| `ended_at` | RFC 3339 timestamp | yes | |
| `summary` | object | yes | Derivable from `events`; present so a reader need not compute it |
| `chain_head` | string | yes | `sha256:` hash of the last event, or of the genesis value when there are none (§6.1) |
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
| `refused` | count of `refuse` events |

A consumer MUST be able to recompute every field from `events`. A record
whose summary disagrees with its events is malformed, and a verifier SHOULD
reject it rather than trusting either.

## 4. Events

Every event carries `kind`, `at`, `seq` and `prev` (§6.1). Labels are serialised as in §5.

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
  "before": { ... }, "after": { ... }, "consent_from": null,
  "from_check": "within" }
```

`from_check` is `within` when the input label is at least as restrictive as the
declassifier's `from`, `outside` when it is not, and `undeclared` when the
declassifier has no `from`. `from` documents intent and is not enforced
([policy-language.md](policy-language.md) §3), so `outside` is recorded, not
refused: it is how an auditor sees a crossing used on data it was not written for.

MUST be emitted on every use, including uses whose resulting flow is later
denied. An attempt to declassify is itself information an auditor wants.

### `consent` — a human decision

```json
{ "kind": "consent", "at": "...", "principal": "customer",
  "granted": true, "granted_by": "dr.martin", "context": "emit:crm.write",
  "label": { ... } }
```

MUST be emitted whether granted or refused, and MUST carry the label of the data
the decision concerned. `granted_by` is the identity of whoever actually
decided, supplied by the consent mechanism; it is not inferred from `principal`
and is `null` only on a refusal that named nobody. A grant without an identity
MUST NOT be accepted: "someone agreed" is not something an auditor can answer
for. A grant by an identity the deployment lists as the agent's own service
account MUST be refused as self-approval.

### `allow` / `deny` — a flow reached a sink

```json
{ "kind": "allow", "at": "...", "sink": "slack.support_channel", "label": { ... } }

{ "kind": "deny",  "at": "...", "sink": "crm.write", "label": { ... },
  "reasons": ["audience ... is not permitted to read ...",
              "sink requires endorsement by ... but got untrusted data"] }
```

A flow to a sink the policy does not declare is a denied flow and MUST be
recorded as a `deny` (its reason says the sink is not declared). The sink name
is caller-controlled, so it MUST be truncated; it is the one place a record
could be made to carry data.

`reasons` MUST list every failing check, not the first. An auditor needs to
know whether one axis failed or three — a flow that fails only on integrity
is a different situation from one that fails on everything.

### `refuse` — something undeclared was used

```json
{ "kind": "refuse", "at": "...", "operation": "read", "name": "inbox.imap2",
  "reason": "undeclared" }
```

Emitted when a source is read or a declassifier is taken that the policy never
declared. `operation` is `read` or `declassify`; `name` is truncated for the
reason given under `deny`.

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

### 6.1 The chain, and closing the record

`seq` is the event's index, from 0. `prev` is `sha256:` of the canonical JSON of
the previous event (sorted keys, no insignificant whitespace), or, for the first
event, of `{"genesis":true,"policy":<fingerprint>,"run_id":<id>,"started_at":<ts>}`.
`chain_head` is the same hash taken over the last event. Deleting, inserting,
duplicating, reordering or truncating events therefore breaks the chain **even in
an unsigned record**; only a party who can recompute the whole chain *and* sign
can forge one, which is what the key is for.

Producing the record closes the run. A conforming implementation MUST refuse to
record anything afterwards, and MUST return the same record if asked again: one
run, one record. Recording MUST be safe under concurrent callers, and the
summary MUST be computed from the same snapshot of events as the events list.

### 6.2 Verification

A verifier MUST NOT raise on malformed input. It MUST check, in this order:
structure; that every summary field equals the count recomputed from the events;
the chain and `chain_head`; and, when it holds a key, that `signature` matches.
A record that fails any check is rejected, however valid its signature.

### 6.3 Asymmetric signatures

Where the record must convince someone outside the organisation, the verifier
holds only a public key. A signature is `"ed25519:"` followed by the lowercase hex
of the 64-byte Ed25519 (RFC 8032) signature over the same canonical bytes as §6.
The verifier holds the 32-byte public key. Distributing that key, and keeping the
private key out of the agent's reach, are deployment questions this document does
not settle: a key in the agent's own process is the agent's key. A verifier asked
for an HMAC key MUST NOT accept an Ed25519 signature, and the reverse.

### 6.4 The journal

The record exists only in memory until it is produced, and the run an auditor most
wants is the one that crashed. An implementation SHOULD therefore offer a journal:
a file of JSON Lines, written as the run happens, holding the same hash-chained
events.

* Line 1 is a header: `kelvra_journal` (the format version), `run_id`, `policy`
  (`name`, `version`, `fingerprint`), `started_at` and `genesis` (§6.1).
* Each following line is one event, exactly as it appears in `events`.
* When the record is produced, a last line `{"end": {"ended_at", "chain_head", "events"}}`.

An event MUST be written *before* it counts as recorded: if it cannot be made
durable, the operation that needed recording fails. The file MUST be created
exclusively and never appended to by a later run. A journal without the `end` line
is an **incomplete run** and MUST NOT be presented as a finished one; a final line
cut mid-write is reported, and the events before it still count. The record of a
*complete* journal is rebuilt byte for byte (and signed by whoever holds the key);
nothing is rebuilt from an incomplete one.

### 6.5 Compatibility

Format 0.1 records (`kelvra_version` `0.1.x`) have no `seq`, `prev`, `chain_head`
or `refused`. A verifier accepts them on structure, summary and signature, and
MUST report them as *legacy*: without a chain, omissions cannot be ruled out. A
`0.2` record cannot be passed off as `0.1` to skip the chain, because the summary
then carries a field `0.1` does not have. The 0.1 schema is kept in
`provenance.v0.1.schema.json`.

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
9. signs over the canonical form of §6, or omits `signature` entirely;
10. chains events and sets `chain_head` (§6.1), and closes the record (§6.1);
11. records a refusal for an undeclared sink, source or declassifier;
12. records consent with the data's label and a decider identity, and accepts no
    grant without one;
13. verifies without raising (§6.2).

## 10. Open questions

- **Chain anchoring.** The chain proves internal consistency, not that the head was not replaced wholesale by someone holding the key. Publishing the head to a party the agent cannot write to would add that; it is not designed.
- **The journal is not tamper-proof against its writer.** It is hash-chained, so partial edits and truncation are caught, but whoever can rewrite the whole file can rewrite the chain; anchoring the head outside the agent's reach is not designed.
- **No redaction story for the record itself.** Source and sink names can
  themselves be sensitive — `crm.oncology_patients` leaks by existing.
- **Cross-run linking is undefined.** An agent with persistent memory carries
  labels between runs; nothing here connects two records.
- **Multi-agent runs are undefined.** Whether delegation produces one record
  or several, and how they reference each other, is unresolved.

## Changelog

- **0.1** — first draft, extracted from the reference implementation. The
  payload rule and the OTel mapping are new here rather than derived from
  code.
