# Kelvra label model

**Version 0.1 — draft. Status: unstable.**

This document defines the label algebra and the flow rule. It is written to
be implementable without reading the reference implementation. Where the two
disagree, this document is wrong and should be corrected — but say so in an
issue rather than assuming.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

---

## 1. Principals

A **principal** is an opaque name: `customer`, `support_team`, `reviewer`.
Kelvra assigns no meaning to it. Whether `support_team` corresponds to an
LDAP group, a role, or a person is the deployment's business.

A **principal set** is either a finite set of principals or the distinguished
value `*`, the universe.

`*` does not mean "every principal currently named". It means "any principal,
including ones not yet named". The distinction matters: data readable by `*`
stays readable when a new principal appears; data readable by an enumerated
set does not.

### Operations

For principal sets `A` and `B`:

| Operation | Notation | Definition |
|---|---|---|
| Intersection | `A ∩ B` | `* ∩ B = B`; `A ∩ * = A`; otherwise set intersection |
| Union | `A ∪ B` | `* ∪ B = *`; `A ∪ * = *`; otherwise set union |
| Inclusion | `A ⊆ B` | true if `B = *`; false if `A = *` and `B ≠ *`; otherwise set inclusion |

Implementations MUST treat `*` as absorbing for union and neutral for
intersection.

## 2. Labels

A **label** is a triple:

```
Label = (readers, endorsers, purposes)
```

all three of which are principal sets.

| Component | Axis | Reads as |
|---|---|---|
| `readers` | confidentiality | who is permitted to read this data |
| `endorsers` | integrity | who vouches for this data |
| `purposes` | purpose limitation | what this data may be used for |

`purposes` holds purpose names rather than principal names. It is the same
type because it needs the same operations, not because the values are
interchangeable.

### Distinguished labels

```
PUBLIC = (*, *, *)      readable by anyone, fully endorsed, any purpose
SECRET = (∅, ∅, ∅)      nobody may read it, nobody vouches, no purpose
```

`PUBLIC` is the identity of join. `SECRET` is its absorbing element.

### Independence of the axes

Confidentiality and integrity are **independent**. All four combinations are
meaningful and occur in practice:

| | endorsed | untrusted |
|---|---|---|
| **public** | a signed public advisory | a fetched web page |
| **confidential** | a record from your own database | an inbound customer email |

`public` is not a synonym for `trusted`. An implementation that conflates
them cannot express indirect prompt injection, which is the attack this
model exists for. See [threat-model.md](threat-model.md) §2.

## 3. Join

```
join((r₁, e₁, p₁), (r₂, e₂, p₂)) = (r₁ ∩ r₂, e₁ ∩ e₂, p₁ ∩ p₂)
```

Intersection on all three axes. Combining data yields something only the
readers of both may see, only the endorsers of both vouch for, and that may
serve only the purposes of both.

Join MUST satisfy, for all labels `a`, `b`, `c`:

- **commutativity** — `join(a,b) = join(b,a)`
- **associativity** — `join(join(a,b),c) = join(a,join(b,c))`
- **idempotence** — `join(a,a) = a`
- **identity** — `join(a, PUBLIC) = a`
- **absorption** — `join(a, SECRET) = SECRET`
- **monotonicity** — `join(a,b)` is at least as restrictive as `a` and as `b`
  on every axis

The reference implementation checks all six exhaustively over a sample of
labels; a conforming implementation SHOULD do the same.

Join is the **only** operation propagation may use. Propagation MUST NOT
relax a label under any circumstance. Relaxing requires declassification
(§6), which is an explicit, declared, recorded act.

## 4. Sources

A **source** binds an entry point to the label its data carries:

```
source inbox.imap
    confidential(customer) for support
    integrity untrusted
```

> **Source labelling is declarative and unverified.** Nothing checks that a
> source declared `public` really is. This is the weakest link in the trust
> base and it has no technical fix — it is an organizational process
> problem. See [threat-model.md](threat-model.md) §6. Stated here because an
> implementer needs to know it, not buried in a footnote.

## 5. Sinks and the flow rule

A **sink** declares three things:

| Field | Type | Meaning |
|---|---|---|
| `audience` | principal set | who will see data that reaches here |
| `requires_endorsement` | principal set | who must have vouched for it |
| `purpose` | purpose or none | what this sink uses data for |

Data carrying label `L` MAY flow to sink `S` if and only if **all three**
hold:

```
1. confidentiality   S.audience ⊆ L.readers
2. integrity         S.requires_endorsement ⊆ L.endorsers
3. purpose           S.purpose = none  OR  S.purpose ∈ L.purposes
```

Read them in words:

1. everyone who will see it is permitted to read it;
2. everyone the sink demands a vouch from has vouched;
3. the sink's purpose is among the permitted ones.

An implementation MUST evaluate all three and MUST report every failing
check, not merely the first. An auditor reading a denial needs to know
whether one axis failed or three.

### Worked examples

Let `L = ({customer, support_team}, *, {support})`.

| Sink | audience | requires | purpose | Result |
|---|---|---|---|---|
| `slack.support` | `{support_team}` | `∅` | none | **allowed** — `{support_team} ⊆ {customer, support_team}` |
| `llm.openai` | `*` | `∅` | none | **denied** — `* ⊄ {customer, support_team}` |
| `crm.write` | `{customer, support_team}` | `{reviewer}` | none | **allowed** — `{reviewer} ⊆ *`, since `*` endorses everything |
| `marketing.export` | `{marketing}` | `∅` | `marketing` | **denied** — two failures: audience and purpose |

Now let `L' = L` but untrusted, i.e. `endorsers = ∅`:

| Sink | Result |
|---|---|
| `crm.write` (`requires {reviewer}`) | **denied** — `{reviewer} ⊄ ∅` |

That last row is the injection defence. Nothing inspected the content.

### Default deny

An undeclared sink MUST raise an error. It MUST NOT default to permitting
the flow, and it MUST NOT default to denying it silently — an undeclared
sink is a bug in the policy, and it should surface as one.

## 6. Declassification

A **declassifier** is the only construct permitted to make a label less
restrictive. It declares what it grants:

```
declassify(name, L) = (L.readers ∪ grants_readers,
                       L.endorsers ∪ grants_endorsement,
                       L.purposes ∪ grants_purposes)
```

Two conventional forms, which the `.klv` surface names separately because
they mean different things to a reader:

- **`declassify`** — grants readers. Lowers confidentiality. *"This summary
  may now be seen by the support team."*
- **`endorse`** — grants endorsement. Raises integrity. *"A reviewer has
  checked this and vouches for it."*

Both MUST produce an entry in the provenance record on every use, whether or
not the resulting flow is ultimately permitted.

> Kelvra makes **no claim** that a declassifier is semantically correct. If a
> function named `pii_redaction` does not redact PII, data leaks. What the
> model guarantees is that the leak happened at a **named, declared,
> recorded** point, and that no undeclared path exists. That is the whole of
> the claim, and overstating it is how this project would lose credibility.

An implementation MUST NOT provide a general-purpose "set this label to X"
operation. Every relaxation goes through a declared declassifier.

## 7. Propagation through a model call

A language model is opaque. Anything in its context window can influence
anything it emits; there is no reliable privilege boundary inside a token
sequence. Therefore:

> **A model call MUST be treated as a total join.** The output carries
> `join` of every input label, with no exception.

This is deliberately coarse. A summary of one public and one secret document
is labelled secret even if the model only drew on the public one — we cannot
know that it didn't.

It is coarse in the safe direction. It never under-labels, and
under-labelling is the failure that leaks data.

### The known cost

Repeated joining drives every label toward `SECRET`, at which point nothing
is permitted and the system is useless. This is **label creep**, the standard
practical failure of dynamic information flow control, and this specification
does not solve it.

The mitigation is structural rather than clever: keep tainted data out of
context windows whose output must stay clean, by splitting work across
separate model calls. An implementation MAY offer helpers for this; it MUST
NOT achieve the same effect by weakening the join rule.

## 8. Consent

A sink or a declassifier MAY require consent from a named principal. When it
does:

- the consent decision MUST be obtained before the flow or the
  declassification takes effect;
- the decision MUST be recorded with the labels of the data involved,
  whether granted or refused;
- absence of a configured consent mechanism MUST be treated as refusal, never
  as approval.

That last rule matters more than it looks. A system that treats "no consent
provider configured" as implicit consent fails open, which for this class of
tool is the worst possible default.

## 9. Conformance

An implementation conforms to this document if it:

1. implements the three-axis label with `*` semantics as in §1;
2. satisfies all six join laws in §3;
3. evaluates all three flow checks in §5 and reports every failure;
4. raises on undeclared sinks and declassifiers;
5. relaxes labels only through declared declassifiers (§6);
6. treats model calls as total joins (§7);
7. defaults consent to refusal (§8);
8. emits a provenance record containing every declassification taken and
   every flow denied.

## 10. Open questions

These are unresolved and an implementer will hit them. They are listed rather
than hidden.

- **Granularity.** Per value, per message, or per tool call? This
  specification is written per value; a gateway implementation may only have
  per-call visibility, and the consequences are not worked out.
- **Persistent memory.** An agent that retains state across runs carries
  labels across runs. Nothing here says how.
- **Multi-agent delegation.** Labels must cross an agent boundary. Not
  specified.
- **Label creep mitigation.** §7 describes the problem and gestures at a
  discipline. That is not a solution.
- **Purpose semantics.** Purposes are opaque names that intersect. Real
  purpose limitation involves hierarchy — is `billing_support` a sub-purpose
  of `support`? Undecided.

## Changelog

- **0.1** — first draft. Extracted from the reference implementation rather
  than the reverse, which is the wrong order and is being corrected.
