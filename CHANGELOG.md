# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

**Pre-1.0: the specification is unstable and the label model may change in
breaking ways between minor versions.** Anything depending on it should pin
an exact version.

## [Unreleased]

### Added

- **`spec/labels.md`** — the label algebra and flow rule, written to be
  implemented without reading the code. Includes a conformance checklist and
  an explicit list of open questions.
- **Whole-policy analysis and a `kelvra` command line.** Four findings:
  `unsatisfiable-sink` (error), `untrusted-reaches-sink`, `trapped-source`
  and `unused-declassifier`. Built before a language server on purpose — an
  LSP is plumbing around an analysis, and a CLI puts the analysis in someone's
  CI today rather than in their editor next quarter. The eventual language
  server wraps the same module and adds no checks of its own.

  Every finding is definite: the analysis reports a problem only when no
  execution can avoid it. It may miss things; it may not invent them. Warnings
  exit 0 so they never break a build by surprise.
- **`spec/policy-language.md`** and a parser for `.klv`. Hand-written and
  dependency-free: the grammar is line-oriented with no expressions, and the
  diagnostics are the product — a generic "unexpected token" would fail
  exactly the non-programmer this language exists for. Every error carries a
  line, the offending text, and where possible what to do instead.
  `examples/support_agent/demo.py` now parses `policy.klv` instead of
  rebuilding the same policy in Python, so the advertised syntax and the
  enforced policy are one artifact rather than two kept in step by hand.
- **`spec/provenance.md`** and **`spec/provenance.schema.json`** — the audit
  record, specified so it can be produced without reading the code. Adds two
  rules that were not in the implementation: a record must never embed the
  data it describes, and the governing policy must not change during a run.
  Includes a mapping onto OpenTelemetry GenAI spans and a proposed `kelvra.*`
  attribute set.
- **`spec/threat-model.md`** — six adversaries, three of them explicitly out
  of scope, five target properties, six non-properties, and the trust base
  including its weakest link.
- Reference implementation of the label lattice, taint propagation and the
  provenance record. No third-party dependencies.
- `examples/support_agent/` — a hostile injected email defeating the model
  and being refused at all three sinks anyway.
- CI on Python 3.10 and 3.13, running tests, lint, the demo, and a guard
  against publishing the private `docs/` directory.
- `LIMITATIONS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CITATION.cff`.

### Changed

- **Repositioned from a programming language to a policy language and audit
  format.** Kelvra no longer aims to be an enforcement engine. That space is
  occupied by [CaMeL](https://arxiv.org/abs/2503.18813) and
  [FIDES](https://arxiv.org/abs/2505.23643); what is unoccupied is the label
  vocabulary, the readable policy surface, and the audit artifact above them.
- **Promise narrowed.** From "an agent structurally cannot leak" to a finite,
  enumerated set of declassification points, each logged. The absolute claim
  was indefensible.
- **Label model replaced.** `restricted(low|medium|high)` gave way to a
  lattice over confidentiality × integrity × purpose. The scale had no
  specifiable semantics; the integrity axis is required to express indirect
  prompt injection at all.
- Licence now matches the documented intent: `LICENSE` split into
  `LICENSE-MIT` and `LICENSE-APACHE`.

### Fixed

- **A model call sent data outside the boundary without any check.**
  `model_call` joined labels and passed the values to the model, so the one
  destination that receives everything was the one destination checked for
  nothing. The threat model already described declaring a remote model as a
  sink; the mechanism was written and never wired. `model_call(..., via=...)`
  now enforces the sink before the call. Found by running the new analysis
  against this project's own example, which reported the model sink as
  unreachable — the symptom of a policy that described a flow the code was
  bypassing.
- **A run could be attested to under a policy that was not the one enforced.**
  The provenance fingerprint was captured when a session started, but the
  policy stayed mutable, so a mid-run amendment produced a signed record
  describing something other than what ran. Sessions now seal the policy they
  govern; the caller's object stays mutable and simply no longer reaches the
  run. Found by writing the specification, not by reading the code.
- **The README and the example disagreed on the language.** The README wrote
  `requires integrity trusted`, the example wrote `requires endorsed(...)`.
  The latter wins and the former is removed: "trusted" alone does not say
  trusted *by whom*, and an audience-facing file should not carry that
  ambiguity. The parser rejects it with the replacement in the hint.
- The `.klv` example in the README did not type-check.
  `declassify pii_redaction from confidential(customer) to
  confidential(support_team)` moves sideways rather than widening under
  reader-set semantics; corrected to `confidential(customer, support_team)`.
- README claimed no implementation existed after one had been committed.

### Removed

- `assets/.klv`, an empty file committed by accident.

---

## Corrections to claims this project published

Kept visible rather than quietly edited out. The reasoning errors are more
instructive than the conclusions.

- **"No structural competitor occupies this intersection."** False when
  published, and false for over a year. It rested on names encountered
  incidentally while checking name availability, never on a dedicated search.
- **"The regulatory argument is an extrapolation with no specific text."**
  The opposite error. The article, the date and the standards gap were all
  public and documented; the project underrated its strongest argument for
  want of a short search.
