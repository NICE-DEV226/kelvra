# Contributing to Kelvra

Kelvra is early. That changes what is useful — right now, being argued with
is worth more than being coded for.

## What helps most

**Prior art we have missed.** This project already published one claim that
was false: that nobody occupied this space. [CaMeL](https://arxiv.org/abs/2503.18813)
(Google DeepMind) and [FIDES](https://arxiv.org/abs/2505.23643) (Microsoft
Research) had implemented the core thesis for months. If you know of work
that closes the gap described in the README — an interoperable label
vocabulary, a policy surface non-programmers can read, an audit artifact
built for a regulator — say so in an issue. That is the single most valuable
contribution available, and it may well end the project, which is fine.

**Pushback on the threat model.** Particularly on [what is placed out of
scope](spec/threat-model.md#3-what-kelvra-does-not-defend-against). If an
adversary we excluded is one you actually face, we have drawn the boundary
in the wrong place.

**Does the label model survive your pipeline?** Take
[spec/labels.md](spec/labels.md) and try to express a real agent you have
built. Where it cannot, that is a finding. Label creep, persistent memory
and multi-agent delegation are known gaps — reports that they bite in
practice are still useful, because knowing a gap exists is different from
knowing how badly it hurts.

**If you work in compliance, audit, or as a DPO:** is the provenance record
the artifact you would actually want? Nobody in that role has been asked
yet, and the whole product thesis rests on the answer.

## What is premature

Feature PRs against the specification. It is unstable by design and moving;
opening an issue first will save you the work.

Optimisation. On one development machine (Python 3.14, Linux, not a
benchmark suite) the flow check itself takes about 1 µs, and a recorded
`declassify` plus `emit` -- ledger entry, hash chain and all -- about 60 µs.
Both are orders of magnitude below the LLM call they sit beside, so it is not
the bottleneck; if you find a case where it is, a reproducible number is more
useful than a patch.

Adding dependencies to the core. It has none on purpose, and that is a
constraint rather than an oversight. Optional extras (`lsp`, `sign`) have to
earn their place the same way, and one with no code behind it does not stay:
the `mcp` and `otel` extras that once did pulled 40 packages, and almost every
advisory a dependency audit found, into the lockfile for nothing that ran.

## Working on the code

```bash
git clone https://github.com/NICE-DEV226/kelvra.git
cd kelvra
pip install -e ".[dev,lsp]"   # lsp: otherwise the language-server protocol test skips
pytest
python examples/support_agent/demo.py
```

Before opening a PR:

```bash
pytest && ruff check src tests examples evaluation
```

CI runs both on Linux, macOS and Windows with Python 3.10, 3.13 and 3.14, plus
the demo, the adversarial evaluation, `kelvra check` on every policy in the
repository, and a check that the private `docs/` directory has not been
committed. Text files are read and written as UTF-8 with an explicit
`encoding=`; a test fails if one is not.

### Where things live

| You want to change | Look in | Its tests |
|---|---|---|
| The label algebra and flow rule | `src/kelvra/labels.py`, `policy.py` (`check_flow`) | `test_labels.py`, `test_spec_conformance.py` |
| The `.klv` grammar or its errors | `src/kelvra/klv.py`, `spec/policy-language.md` | `test_klv.py`, `test_step1_hardening.py` |
| What `kelvra check` finds | `src/kelvra/analysis.py` | `test_analysis.py` |
| Enforcement, consent, declassification | `src/kelvra/taint.py` | `test_flow.py`, `test_step*_*.py` |
| The audit record and `verify_record` | `src/kelvra/provenance.py`, `spec/provenance.md`, `spec/provenance.schema.json` | `test_provenance_spec.py`, `test_step2_provenance.py` |
| Editor support | `src/kelvra/lsp.py`, `editors/vscode/` | `test_lsp.py`, `test_editor_grammar.py` |

`tests/test_audit_regressions.py` holds the properties an independent audit
found violated, each stated from the specification rather than from the code.
Treat a failure there as a regression of a known defect, not as a flaky test.

### House rules

**The specification is the product.** A change to enforcement behaviour that
does not update [spec/labels.md](spec/labels.md) is incomplete. Where the two
disagree, the specification is the one that is wrong, and both get fixed.

**Worked examples in the spec are executed.** `tests/test_spec_conformance.py`
runs every example table in `spec/labels.md`. Add examples there and they
become tests.

**A safeguard that does nothing must be an error, not a no-op.** A clause that
parses and then has no effect (a repeated `integrity`, a `requires` that the
runtime ignores) lets a reader believe in a control that is not there. Reject
it, with a line number.

**What a reviewer reads must be what is enforced.** Anything that lets the
parsed text differ from the displayed text -- control characters, invisible or
bidirectional characters, non-standard line separators -- is rejected, comments
included.

**Never weaken the join rule to make something pass.** If a label is too
restrictive to be useful, the answer is a declared declassifier or a
restructured pipeline, never a relaxed propagation rule. This is the one
invariant the whole model rests on.

**Under-labelling is the failure that matters.** Over-labelling is annoying;
under-labelling leaks data. When a design choice is ambiguous, take the more
restrictive reading.

**Say what you did not verify.** Comments and docs in this project mark
unverified claims as unverified. That is a deliberate habit, not an
affectation — it is how the false claim above got caught, eventually.

## Commits and PRs

Explain *why*, not what — the diff already shows what. If a test failure
changed your mind about the design, say so; that is the most useful sentence
in any PR.

## Security

Do not open a public issue for a design flaw that would let data leak. See
[SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the same dual **MIT OR Apache-2.0** terms as
the project. By opening a PR you agree to that. There is no CLA.
