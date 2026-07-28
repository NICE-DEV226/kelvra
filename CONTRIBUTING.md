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

Optimisation. The enforcement path costs about 4.5 µs per check, roughly
four orders of magnitude below the LLM call it sits beside. It is not the
bottleneck and will not become one soon.

Adding dependencies to the core. It has none on purpose, and that is a
constraint rather than an oversight.

## Working on the code

```bash
git clone https://github.com/NICE-DEV226/kelvra.git
cd kelvra
pip install -e ".[dev]"
pytest
python examples/support_agent/demo.py
```

Before opening a PR:

```bash
pytest && ruff check src tests examples
```

CI runs both on Python 3.10 and 3.13, plus the demo, plus a check that the
private `docs/` directory has not been committed.

### House rules

**The specification is the product.** A change to enforcement behaviour that
does not update [spec/labels.md](spec/labels.md) is incomplete. Where the two
disagree, the specification is the one that is wrong, and both get fixed.

**Worked examples in the spec are executed.** `tests/test_spec_conformance.py`
runs every example table in `spec/labels.md`. Add examples there and they
become tests.

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
