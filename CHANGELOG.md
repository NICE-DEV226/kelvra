# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

**Pre-1.0: the specification is unstable and the label model may change in
breaking ways between minor versions.** Anything depending on it should pin
an exact version.

## [Unreleased]

### Added (sealing)

- **`kelvra.sealing`, `Kelvra.seal`, `Kelvra.emit_text`, `MasterKey`.** A value the policy keeps from
  the model provider can be put in the prompt as an AES-256-GCM token (key from HKDF-SHA256, both
  from the `cryptography` package; new optional extra `seal`). The token is authenticated together
  with the run, the policy fingerprint, its kind and its original label. `emit_text` opens the tokens
  in a text only after the flow rule accepts `join(text label, each original label)` for the sink,
  and refuses anything that does not authenticate. The master key lives in the authority; an
  `AgentSession` has no way to reach it (`emit_text` is added to the session). Design and limits:
  `spec/sealing-*.md`.
- **`examples/sealed_support_agent/`**: policy, pipeline, scripted honest and injected models, an
  OpenAI-compatible adapter (tested against a local server only) and a terminal demo.
- `spec/sealing-*.md`: threat model, properties, attack scenarios, cryptographic design and
  verification results for sealing.
- `examples/sealed_support_agent/ui.py`: a page on the loopback interface that runs the same pipeline
  (Host and Origin checked, strict content security policy, model text drawn as text only).

### Fixed (tests)

- The Go peer of the differential test compiled a 4 MB binary into a fresh temporary directory and
  never removed it; hundreds of runs filled the disk quota and made unrelated tests fail
  intermittently. It is removed when the process ends.

### Resolved after the feature-by-feature analysis

- **Callbacks see plaintext, and closures are not tracked (N-01).** `Tainted`'s docstring said `unsafe_value` was the
  only way a payload leaves the label model and that grepping for it finds every hole. `map(fn)`,
  `model_call(produce=fn)` and `declassify(transform=fn)` also hand the raw payload to a function, and a function that
  closes over another value yields a result labelled only with its inputs: a public value emitted a secret to a public
  sink. The docstrings and LIMITATIONS now say so and tests pin it (`tests/test_callbacks_known_limit.py`). Nothing in
  the code changed; the claim did.
- **Changed (breaking, pre-1.0): `kelvra check --json` always prints one array** with one entry per file in the order
  given, and a file that cannot be read or parsed gets an entry with `error` (`kind`, `line`, `message`, `hint`) instead of
  nothing. It used to print an object for one file, an array for several, and no JSON at all for a file that failed.
  Entries for good files gain `"error": null`. Exit codes and the text on stderr are unchanged (N-03).
- **The package is type-checked** (N-04). mypy found 26 errors, nearly all because `Tainted` declared its attributes
  only in `__slots__`; they are declared, a few lists are typed, and the gateway config narrows a `None`. `py.typed` and
  `Typing :: Typed` ship, mypy is pinned (`mypy==2.4.0`) and runs in CI from the lockfile, which grows by five packages.
  A test checks that `CITATION.cff` and the editor manifest carry the package version.
- **The unused-declassifier analysis no longer takes seconds on a large policy, and the language server no longer
  analyses on every keystroke** (N-02). The analysis compared every source with every sink for every declassifier:
  800 x 800 x 10 useless ones took 35 s, 400 x 400 x 10 relevant-but-useless ones 8.9 s. Sources with the same label and
  sinks with the same signature are now compared once, a declassifier the others already cover is skipped, and one is
  only compared with the sinks that ask for something it grants: 141 ms and 125 ms. The answers are unchanged, shown
  against the previous algorithm kept as the reference on 24,000 random policies (and a sabotaged version fails the
  comparison on 773 of 1,500). A policy whose every source and sink is different, with every declassifier relevant to every
  sink, still costs the full product. The server waits 250 ms after the last edit (`KELVRA_LSP_DEBOUNCE_MS`, 0 to
  turn it off) before analysing, drops an analysis a newer edit has made stale, and still answers opening and saving
  at once; five quick edits give one answer.
- **Performance is measured, and what a run holds is stated (N-05).** `evaluation/scale.py` reports parse, analysis,
  labelling, record, verification and gateway cost, and the memory a run keeps: about 454 bytes per event, held until
  `record()` (a million events is about 454 MB). `LIMITATIONS.md` said no measurement existed; it now carries the table and
  says plainly that a long-lived agent would need the record cut into segments, which is not built. Nothing in the code
  changed for this one: it was a claim to measure, and the answer is that ordinary runs are small.
- **`.klv` is displayed and coloured properly** (the editor, GitHub, the tests). Running VS Code's own TextMate
  engine on the shipped policies showed 17 words of 240 with no colour: every name after the first in a
  `principal` or `purpose` list, and every purpose after `for`. The grammar now covers them, and the names the parser
  accepts with `-` and `.` (a randomly generated policy found `A-A`). `editors/highlight.py` applies that same grammar
  with a small TextMate engine of its own, checked character by character against VS Code's on 152 files (40,803
  characters, no difference), and draws `assets/policy.svg`, the coloured policy now at the top of the README's first
  look (GitHub colours neither `klv` nor `kelvra` fences; the text stays underneath for copying). The extension gains
  the alias `kelvra` (so fences colour in VS Code's Markdown preview), whole-name word selection for `inbox.imap`,
  indentation that no longer treats `policy` as a block, snippets for `source`, `sink`, `declassify` and `endorse`, and a
  description that no longer says there is no parser. `tests/test_klv_highlighting.py` checks all of it, including that
  every word of every generated policy has a colour and that the picture is what the grammar produces.
- **README and the editor extension's README no longer describe a project that does not exist** (N-06, N-07): the stdio
  gateway exists, the parser and a language server exist, and the grammar no longer colours `never`, an audit mode the
  parser refuses. `tests/test_docs_match_the_code.py` checks those sentences against the code.

### Fixed

- **A refusal owed to the server could be lost when the client left.** After the
  client disconnected the gateway closed the server's input as soon as nothing
  was pending, which on a slow scheduler (seen on Windows, Python 3.14) was
  before it had read and refused a request the server had just made. It now
  also waits for the server to fall quiet (`quiet_seconds`, 0.25 s, still bounded
  by `drain_seconds`). Nothing was ever forwarded wrongly; the refusal was only
  not delivered. A server that speaks late is in the test suite now.

### Tests (mutation gaps in `provenance.py`)

- `spec/provenance.vector.json` is a complete record signed with a published
  test key, built with a fixed clock and run id. A second implementation of the
  verifier can check itself against it, and a test fails if the code stops
  producing it byte for byte.
- `tests/test_provenance_details.py` pins what mutation testing found unasserted:
  the exact reason `verify_record` gives for each way a record is wrong, the
  hash chain and the signature recomputed with `hashlib` alone, the text of the
  one-page report, each way a journal file can be wrong, and how the journal
  writes (private file mode, partial writes, flushing, failure messages).
- `tests/test_taint_details.py` does the same for `taint.py`: the transform of a
  declassification is applied, the consent provider is told whom it is asked and
  for what, origins and sites reach the ledger, `signer` with `signing_key` is
  refused, the unsigned-record warning points at the caller, and the identity
  length limits are exact.

### Security

Findings of the independent audit (`kelvra-audit/`), first hardening step.

- **A comment could hide a declaration (F-02).** The parser split lines with
  `str.splitlines()` before stripping comments, so U+2028, U+2029, U+0085, VT,
  FF and FS/GS/RS ended a comment early for the parser while most viewers show
  one line. Lines now end only at LF, CRLF or CR, and control, format and
  line-separator characters are rejected everywhere, comments included. A
  leading BOM is tolerated.
- **A sealed policy could be edited in place (F-01).** The seal copied the
  dictionaries but did not freeze them. They are now read-only views, attribute
  assignment on a sealed policy raises, and `Kelvra.record()` refuses to sign if
  the policy no longer hashes to the fingerprint taken at session start.
- **Any truthy value was consent (F-05).** An `async def` provider, `"no"` or
  `[0]` granted. Only `True` grants; `None`/`False` refuse; anything else is
  recorded as a refusal and raises `TypeError`.
- **Clauses accepted and ignored (F-03).** A repeated `integrity`, `for` or
  `requires consent`, and `requires endorsed(...)` inside a declassifier, are
  now parse errors instead of silently overwriting or doing nothing.
- **An endorsement nobody answered for (F-04).** New errors
  `unguarded-endorsement` and `unguarded-public-declassification`. The agent now
  holds an `AgentSession` with no `declassify`; the evaluation and the demo use
  it. The demo's reviewer refuses the hostile plan instead of approving
  everything.
- `version ²` and 5000-digit versions raised `ValueError` through the CLI and
  language server; the CLI no longer aborts on a binary or missing file.

### Dependencies

An audit of the locked dependencies (`uv audit`, advisory database OSV) found 47
advisories (24 distinct) in 44 packages. 46 of the 47 came through the `mcp` and
`otel` extras, which nothing imported. Kelvra's core has no dependencies and was
never exposed; what changed:

- The `mcp` and `otel` extras are removed, and the lockfile shrinks from 44
  packages to 22. An extra returns with the code that uses it.
- `pytest` is now `>=9.0.3,<10` (GHSA-6w46-j5rx-g56g, tmpdir handling, fixed in
  9.0.3); tests that parametrised over iterators, deprecated in pytest 9 and
  removed in 10, now pass lists.
- `cryptography`, used only for Ed25519 signing, is locked at 50.0.2
  (GHSA-g6cj-pr64-35w5 concerned PKCS#7 decryption, which Kelvra does not use).
- Re-audit: 22 packages, 0 advisories.
- A weekly workflow (`.github/workflows/audit.yml`) and one on lockfile changes
  repeat the audit, separate from CI so that a new advisory does not turn an
  unrelated pull request red.

### Supply chain of the repository itself

- **Every GitHub Action is pinned to a full commit SHA**, with its release in a comment
  (`actions/checkout` v7.0.1, `actions/setup-python` v7.1.0). A tag can be moved after
  the fact; a SHA cannot. Pinning means nothing updates by itself, so
  `.github/dependabot.yml` opens a weekly pull request per outdated action for a person
  to read and merge; delete it to turn that off.
- **CI installs from `uv.lock`** (`uv sync --frozen`, uv itself pinned) and prints what it
  installed. Until now it installed whatever pip resolved from the ranges in
  `pyproject.toml`, so the dependency audit and the tests could be about different
  versions. A separate, non-blocking job still installs the unlocked ranges, to see an
  upstream release that breaks the project before a user does.

### Tests

- **Properties, not only examples** (`tests/test_properties.py`, 21 of them, via
  `hypothesis`, now a dev dependency): the label algebra and the flow rule against an
  independent oracle; taint tracking over arbitrary programs of reads, model calls and maps (a
  derived value is exactly the join of its sources, and joining never lets a flow through
  that either side alone would be refused); a policy written as text and parsed back is the
  policy written, however it is indented, commented or terminated; no text makes the parser
  or the language server raise anything but a located error; every single change to a record
  is detected without a key; the analysis says "unreachable" exactly when no execution
  reaches the sink.
- **Mutation testing found 72 changes to `labels.py` and `policy.py` that the suite did not
  notice**, and 10 that no test reached. They were: the exact text of a refusal, the
  `Decision`'s sink and label, `Policy.__delattr__` (untested), how labels and sets display,
  and above all that nothing pinned the **fingerprint of a policy** across releases. Now the
  fingerprints of the shipped policies are known values, every field of a policy is shown to
  change the fingerprint, and the rest is pinned (`tests/test_pinned_behaviour.py`). 189 of
  271 changes were noticed before, 260 after.

### Evaluation

- **`evaluation/matrix.py`: the result is a pair, so here is the table.** The same attacks
  under the shipped policy and four plausible mistakes (an endorser nobody answers for, a
  refund sink with no consent, sources that default to trusted, a public declassifier left
  open), with an agent that holds a session or, through a careless integration, the whole
  authority (where it tries every order of every declared crossing), and with consent that
  refuses, approves anything, or reads what it approves. It shows what the earlier evaluation
  could not: a session is enough to stop everything under the shipped policy, but the authority
  with rubber-stamped consent launders its own output; trusting sources by default lets a
  session through on consent alone, and `kelvra check` only warns; a clean `check` is not a safe
  policy. It also exercises, for the first time, the legitimate use of the integrity upgrade
  (a refund after a person reviews the ticket). The README embeds the generated table and a
  test keeps it equal to what the code produces.
- **`evaluation/creep.py`: label creep, with a number.** One model call over six documents
  refuses about 98% of legitimate deliveries; one call per document refuses none. Synthetic
  labels, one form of the problem.

### Extensions (step 6)

- **A tool-call gateway** (`kelvra.gateway`, `kelvra gateway`, [spec/gateway.md](spec/gateway.md)):
  an MCP stdio proxy that checks each `tools/call` against the conversation's label
  before it reaches the server, labels results before they reach the client, refuses
  unnamed tools, batches, unsolicited responses and server-initiated sampling, and
  needs no SDK. Coarse by construction; stdio only.
- **Interoperability, found by using the real SDK.** Running the official MCP
  Python SDK's client and server through the gateway (1.30.0 and 2.3.0) found two
  defects the fake-server tests could not: refusals lacked the `resultType` field
  the 2026-07-28 revision requires, so the client saw a protocol error instead of a
  tool error; and a server dying mid-call left the client waiting forever, the
  gateway now answering every request in flight and exiting with the server's code.
  Also fixed: reading the client through a buffered `stdin` could abort the
  interpreter at shutdown. `tests/test_interop_mcp_sdk.py` keeps all of it (skipped
  unless `mcp` is installed) and CI runs it against both SDK generations.
- A differential test replaces waiting for the next review. It feeds the gateway
  thousands of generated, awkward lines and asks real decoders (Python, Node, Ruby,
  PHP, Perl, jq, Go) what they see in whatever was forwarded; the answer must be what
  the gateway checked. It found a defect on its first run: a number such as `1e999`
  was read as infinity and forwarded as `Infinity`, which is not JSON. That is now a
  parse error. A control with a lenient gateway shows the harness can see
  disagreements, and reintroducing past defects makes it fail. CI requires Go, Node
  and jq on Linux so the test cannot quietly skip.
- Case folding is not a list to complete. Rather than adding foldings one report at a
  time, the gateway refuses any non-ASCII key in an object it reads by name and any
  non-ASCII or differently-cased spelling of a method it handles, closing the class.
  `Tools/Call` had passed as an unremarkable request, and `Sampling/CreateMessage`
  from a server reached the client. Argument values stay unrestricted; tools with
  non-ASCII argument names are refused. Found by an automated review; reproduced first.
- The gateway no longer trusts exact key matching against peers that ignore case:
  `{"Method":"tools/call"}` was no method to it and a tool call to a Go server, and
  `name` beside `Name` let the checked tool differ from the executed one. Keys that
  fold together (Unicode NFKC and casefold, which covers the long s and the Kelvin
  sign) are refused, variant spellings of the members it reads are refused, and
  only JSON-RPC's six top-level members are forwarded. Found by an automated review
  of the commits; reproduced first.
- The gateway refuses a message that is both a request and a response, in both
  directions: forwarded as a request, `{"id":3,"method":"x","result":{...}}` let a
  result reach the client unlabelled while the call stayed pending, as a lenient
  client would read it as the answer. Found by an automated security review of the
  commits; reproduced before it was fixed.
- **A journal** (`Journal`, `Kelvra(journal_path=...)`, `read_journal`,
  `journal_to_record`): events written to disk as they happen, before they count as
  recorded; incomplete runs are reported as such; complete ones are rebuilt exactly.
- **Ed25519 signatures** (`kelvra.signing`, extra `kelvra[sign]`): the one optional
  dependency, imported only when used; the core still has none.
- Step 4: `Decision.axes`, `Finding.name` and `ParseResult.warning_lines` replace
  places that read the project's own messages back.

### Security, step 3

- **Labels cannot be attached by hand (F-10).** `Tainted` is issued by a session
  and cannot be constructed; each remembers its issuer, and a session refuses a
  value it did not issue (a hand-built one, a raw value, another session's). The
  payload has one public name, `unsafe_value`; `.value` is gone. `PrincipalSet`
  refuses `'*'` as a member. This stops the ordinary ways of attaching a
  flattering label; it is not a defence against code that reaches into private
  attributes.
- **Signing keys are checked when the session starts (F-11).** Non-bytes keys
  raise `TypeError`, keys under 16 bytes raise `ValueError` (also for
  `KELVRA_SIGNING_KEY`, which used to be accepted at any length), and a record
  produced with no key raises `UnsignedRecordWarning`.
- **`from` is read and its use recorded (F-12).** It is parsed as an upper bound
  (`public`, `untrusted`, `confidential(...)`, `endorsed(...)`), a typo in it is
  an error, it is part of the fingerprint, and every `declassify` event carries
  `from_check` (`within`, `outside`, `undeclared`). Still not enforced.
- **A source with no `integrity` clause warns (F-13)** that it defaults to trusted.
- `kelvra check --json` on several files prints one JSON array (one file still
  prints the object).
- CI runs on Linux, macOS and Windows. README, SECURITY, LIMITATIONS and the
  threat model no longer say there is no code; the README policy is the shipped
  example, and a test keeps it so.

### Added (format 0.2, step 2)

- **Provenance format 0.2.** Every event carries `seq` and the hash of the
  previous event; `chain_head` pins the last. A deleted, inserted, duplicated,
  reordered or truncated event now breaks the record even without a key. The
  ledger is encapsulated and thread-safe, closes when `record()` is called, and
  returns the same record afterwards (F-08). `Event` content is frozen.
- **`verify_record`** checks structure, the summary against the events, the
  chain and the signature, and never raises; `verify` is its boolean form
  (F-07). Format 0.1 records are accepted and reported `legacy`.
- **Refusals are recorded (F-09).** An undeclared sink is a `deny`; an undeclared
  source or declassifier is a `refuse`. Names are truncated so the record cannot
  carry data.
- **`model_call(via=...)`** authorises the joined label once: one consent, one
  `allow` or one `deny`, and nothing recorded as sent that was not.
- **Consent carries who decided and what about (F-09).** `ConsentDecision(granted,
  decided_by)`; a bare `True` no longer grants; `service_identities` forbids
  self-approval; the `consent` event now holds the data's label.
- `provenance.v0.1.schema.json` keeps the old schema; `provenance.schema.json`
  is format 0.2.

### Changed

- `consent=lambda ...: True` no longer grants anywhere: tests, the demo and the
  evaluation now use `approved_by(...)` or `ConsentDecision`.
- `examples/support_agent/policy.klv` and `evaluation/policy.klv`: `human_review`
  now `requires consent(reviewer)`, as the new analysis demands.
- `tests/test_provenance_spec.py::test_fingerprint_covers_the_effective_policy`
  edited a sealed policy in place, which is the hole closed above; it now
  builds an unsealed copy. The assertion is unchanged.

### Added

- **`spec/labels.md`** — the label algebra and flow rule, written to be
  implemented without reading the code. Includes a conformance checklist and
  an explicit list of open questions.
- **An adversarial evaluation** (`evaluation/`), against a corpus of real
  indirect prompt injections. Six attacks: five expressible as a data flow and
  all five contained, by three different mechanisms — default deny on an
  undeclared sink, the confidentiality axis, the integrity axis. No false
  positives on three benign controls. One attack, system prompt disclosure,
  gets through and cannot be stopped: it reaches no tool, so nothing observes
  it. That is non-property N1, written before the evaluation existed.

  The agent is modelled as fully compromised — it does exactly what each
  injection asked. That isolates the structural guarantee from anything about
  the model, and it is the hardest case; it also means this measures
  containment and not utility, so it produces no AgentDojo-comparable number.

  Notable: the obfuscated attack, which needed a whole normalisation stage to
  catch in the corpus's original project, requires nothing here. Kelvra never
  reads the text.
- **A language server (`kelvra lsp`).** Diagnostics under the offending
  line as you type, hover that answers *who can reach this sink*, a document
  outline, and completion of declared principals. One protocol, every editor
  — the alternative is a plugin per editor.

  Everything below the protocol boundary is a pure function of text and
  imports nothing, so the interesting half is tested without a client; the
  pygls handlers are adapters with no logic. pygls is an optional extra
  (`kelvra[lsp]`) and the core still has no dependencies. Reimplementing the
  protocol by hand would have been work spent away from the part with value,
  which is the same argument that put the analysis before the server.
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
