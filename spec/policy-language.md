# The `.klv` policy language

**Version 0.1 — draft. Status: unstable.**

The surface syntax. Label semantics are in [labels.md](labels.md); this
document defines only how a policy is written down and what each construct
maps to.

The language is deliberately small. It has no expressions, no control flow,
no user-defined functions and no arithmetic. It is a declaration format, and
its primary reader is someone who does not write code — a data protection
officer, an auditor, a security reviewer. Every design choice below serves
that reader over the one writing it.

RFC 2119 keywords apply.

---

## 1. Lexical structure

- Files are UTF-8. Implementations MUST accept both LF and CRLF.
- `#` begins a comment that runs to end of line. There are no block comments.
- Blank lines and comment-only lines are ignored everywhere.
- **Indentation is significant**: a declaration header sits at column 0, and
  its clauses are indented. Any consistent indent is accepted; implementations
  MUST NOT require a specific width.
- Tabs and spaces MUST NOT be mixed within one file. An implementation MUST
  reject a file that mixes them rather than guessing.

### Identifiers

```
identifier ::= [A-Za-z_] [A-Za-z0-9_.-]*
```

Dots are permitted so that sources and sinks can carry their natural names
(`inbox.imap`, `crm.customer_record`). `*` MUST NOT be an identifier — it is
reserved for the universe in [labels.md](labels.md) §1, and allowing it as a
principal name would make a label ambiguous.

## 2. Grammar

```ebnf
policy_file  ::= header declaration*

header       ::= "policy" identifier NEWLINE
                 [ "version" INTEGER NEWLINE ]
                 declare*

declare      ::= ( "principal" | "purpose" ) name_list NEWLINE
name_list    ::= identifier ( "," identifier )*

declaration  ::= source | sink | declassifier

source       ::= "source" identifier NEWLINE INDENT source_clause+ DEDENT
source_clause ::= confidentiality | integrity

sink         ::= "sink" identifier NEWLINE INDENT sink_clause+ DEDENT
sink_clause  ::= "accepts" audience
               | "requires" requirement
               | "for" identifier

declassifier ::= ( "declassify" | "endorse" ) identifier NEWLINE
                 INDENT declass_clause+ DEDENT
declass_clause ::= "from" label_expr
                 | "to" label_expr
                 | "audit" ( "always" )

confidentiality ::= ( "public" | "confidential" "(" name_list ")" )
                    [ "for" identifier ]
integrity    ::= "integrity" ( "trusted" | "untrusted" )
audience     ::= "public" | "confidential" "(" name_list ")"
requirement  ::= "endorsed" "(" name_list ")" | "consent" "(" identifier ")"
label_expr   ::= "public" | "untrusted"
               | "confidential" "(" name_list ")"
               | "endorsed" "(" name_list ")"
```

## 3. Semantics

### `policy` and `version`

`policy` names the policy; `version` is an integer, defaulting to `1`. Both
appear in every provenance record ([provenance.md](provenance.md) §3).

### `principal` and `purpose`

Declare the names the rest of the file may use. **Every principal and purpose
referenced elsewhere MUST have been declared**, and an implementation MUST
reject a file that references an undeclared one.

This is the language's most valuable check and the reason declarations are
mandatory rather than inferred. A typo in a principal name silently creates a
new principal that nothing else mentions — which produces a label nobody can
read and a policy that denies everything, or worse, a sink audience that
matches nothing and therefore never constrains. Requiring declaration turns a
silent misconfiguration into a parse error with a line number.

### `source`

```klv
source inbox.imap
    confidential(customer) for support
    integrity untrusted
```

| Clause | Maps to |
|---|---|
| `public` | `readers = *` |
| `confidential(a, b)` | `readers = {a, b}` |
| `for p` | `purposes = {p}` |
| `integrity trusted` | `endorsers = *` |
| `integrity untrusted` | `endorsers = ∅` |

A source MUST declare exactly one confidentiality clause. `integrity` is
optional and defaults to `trusted`.

> Source labels are declarative and unverified. Nothing checks that a source
> declared `public` really is — the weakest link in the trust base, with no
> technical fix. See [threat-model.md](threat-model.md) §6.

### `sink`

```klv
sink crm.write
    accepts confidential(customer, support_team)
    requires endorsed(reviewer)
    requires consent(customer)
```

| Clause | Maps to |
|---|---|
| `accepts public` | `audience = *` |
| `accepts confidential(a, b)` | `audience = {a, b}` |
| `requires endorsed(r)` | `requires_endorsement = {r}` |
| `requires consent(p)` | consent from `p` per use |
| `for p` | the sink's purpose |

A sink MUST declare exactly one `accepts`. Multiple `requires` clauses are
permitted and accumulate.

There is no `requires integrity trusted`. "Trusted" alone does not say *by
whom*, and an audience-facing file should not contain that ambiguity — name
the endorser.

### `declassify` and `endorse`

```klv
declassify pii_redaction
    from confidential(customer)
    to   confidential(customer, support_team)
    audit always

endorse human_review
    from untrusted
    to   endorsed(reviewer)
    audit always
```

`to` is normative: it declares what the construct **grants**, unioned onto
the incoming label. `from` is documentation — it records the author's intent
about what this crossing is for, and an implementation MAY warn when a
declassification is applied to a label that does not match, but MUST NOT
refuse it. Enforcing `from` would require knowing every label that can reach
the construct, which is exactly the whole-program analysis this design avoids.

`declassify` and `endorse` are the same construct with different names.
Keeping both is a readability decision, not a semantic one: lowering
confidentiality and raising integrity are different acts to a human reviewer
and should not share a keyword. An implementation MAY warn when `declassify`
grants only endorsement, or `endorse` grants only readers.

`audit always` is the only accepted audit mode. Every use produces a record
entry regardless ([provenance.md](provenance.md) §4), so the clause is
documentation. `audit never` MUST be rejected rather than silently ignored —
accepting a word that promises something the system will not do is worse than
not having the word.

## 4. Diagnostics

Because the errors are the point, an implementation MUST report:

| Condition | |
|---|---|
| undeclared principal or purpose | with the line and the name |
| a source with no confidentiality clause | |
| a source with more than one | |
| a sink with no `accepts` | |
| a duplicate declaration name | with both lines |
| `audit never` | |
| mixed tabs and spaces | |
| an unknown keyword | with the enclosing block's type |

Every diagnostic MUST carry a line number. A message without one is not a
diagnostic, it is a complaint.

Implementations SHOULD additionally warn — without failing — on:

- a declared principal or purpose that nothing uses;
- a declassifier that no flow can reach;
- a sink whose audience no declared source can satisfy, even after every
  declared declassification. That last one is the highest-value warning in the
  language: it says *this flow can never work*, at authoring time.

## 5. Canonical JSON form

`.klv` is the human surface. Implementations SHOULD also accept and emit an
equivalent JSON document, so that tooling which does not parse `.klv` can
still consume a policy. The JSON form is normative for interchange; `.klv` is
normative for people. Neither is a subset of the other in expressiveness.

The JSON form is not yet specified. It should mirror the structures in
[provenance.md](provenance.md) §5 for labels.

## 6. Open questions

- **No imports.** An organisation with twenty agents will want a shared base
  policy. Nothing here supports that, and bolting it on later is harder than
  designing it now.
- **No JSON form yet**, though §5 commits to one.
- **No versioning of the language itself**, distinct from the policy's
  `version` field.
- **`from` is unenforced**, which means it can drift from reality and mislead
  the reader it exists for.
- **No way to express a sink that is also a source**, which a read-write tool
  actually is.

## Changelog

- **0.1** — first draft. Resolves a divergence in which the README wrote
  `requires integrity trusted` while the example wrote `requires endorsed(...)`;
  the latter wins, and the former is removed from the language.
