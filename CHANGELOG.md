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
