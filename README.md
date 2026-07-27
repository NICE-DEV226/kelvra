<p align="center">
  <img src="./assets/kelvra-mascot.svg" width="180" alt="Kelvra mascot" />
</p>

<h1 align="center">Kelvra</h1>

<p align="center">
  <strong>Privacy-by-construction for autonomous agents.</strong>
</p>

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#why-kelvra">Why Kelvra</a> ·
  <a href="#a-first-look">A first look</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-early%20design-orange">
  <img alt="license" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue">
  <img alt="language" src="https://img.shields.io/badge/built%20on-Python-3776AB">
</p>

---

## Status

**Kelvra is in the design and specification stage.** There is no working compiler or interpreter yet. This repository currently exists to:

- publish the language design and the reasoning behind it,
- collect early feedback before implementation choices are locked in,
- track progress toward a first working prototype (see [Roadmap](#roadmap)).

If you are looking for something to `pip install` today, it isn't ready yet. If you're interested in the *why* and the *how it will work*, read on.

## Why Kelvra

Autonomous agents built on LLMs are increasingly trusted with sensitive data: customer records, medical information, financial history. Today, nothing structurally prevents an agent from leaking that data — developers rely on discipline, code review, and hoping the model doesn't do something unexpected with a piece of context it wasn't supposed to touch.

Existing tools address parts of this problem in isolation:

- **Privacy-preserving ML frameworks** (federated learning, differential privacy libraries) protect data used to *train* models, not data flowing through an *agent's* runtime decisions.
- **Agent orchestration frameworks** (LangChain, AutoGen, and similar) are excellent at chaining steps and tools, but treat data access as an implementation detail left entirely to the developer.

Kelvra's premise: **confidentiality should be a property of the program's structure, not a discipline the developer has to maintain by hand.** A value marked sensitive should be traceable through every step of an agent's execution, and the language should refuse — at definition time, not at incident-response time — to let that value reach an unauthorized output.

This is not a claim that Kelvra will formally verify an LLM's output. It can't; language models are non-deterministic. What Kelvra verifies is the *pipeline* around the model: what each step is allowed to read, transform, and emit.

## A first look

This is illustrative syntax, not yet implemented. It shows the shape of the language, not a working example.

```kelvra
data CustomerEmails: private from "inbox.imap"

agent SupportAgent:
    read(CustomerEmails) -> raw
    analyze(raw, model="gpt4") -> masked_summary
    decide(masked_summary) -> action
    act(action) requires_consent
```

`raw` inherits the `private` marker from its source. Any step that would export it — directly, or through a transformation that doesn't explicitly declare itself as privacy-preserving — is rejected before the program runs.

## Architecture

Kelvra is being built in two deliberate phases rather than committing upfront to a standalone compiler:

**Phase 1 — Python-embedded DSL.** Kelvra starts as a library and static checker on top of Python, the language the vast majority of ML and agent tooling already uses (PyTorch, LangChain, Hugging Face). This keeps the barrier to trying it at zero and lets the core ideas — sensitivity tracking, flow constraints — get tested against real usage before investing in a full compiler.

**Phase 2 — Standalone compiler.** If Phase 1 demonstrates real demand and the type system proves itself in practice, a dedicated compiler (likely implemented in Rust, following the path taken by tools like Deno and Bun) will provide stronger, structurally-enforced guarantees for contexts that need them — healthcare, finance, defense.

This mirrors the trajectory of TypeScript (never needed to leave JavaScript) and Mojo (started Python-compatible before building a native compiler).

## Roadmap

- [ ] Finalize core grammar (data sensitivity levels, control flow, permissions) — EBNF spec
- [ ] Build first parser prototype (Lark)
- [ ] Static checker for the `private` → unauthorized-export rule
- [ ] First runnable example end-to-end
- [ ] Public alpha release
- [ ] Gather real usage feedback
- [ ] Evaluate case for a standalone compiler (Phase 2)

No dates are attached yet. This is a solo/early-stage project moving in public rather than a funded roadmap with commitments.

## Contributing

Kelvra is not yet at a stage where code contributions make sense — there's no implementation to contribute to. What's genuinely useful right now:

- feedback on the language design and the examples above,
- pointers to prior art we should be aware of,
- honest pushback on whether the two-phase approach makes sense.

Open an issue if you have thoughts. Please don't open PRs against the design docs without discussing first — this is still moving fast and things will be restructured.

## License

Kelvra will be released under a dual **MIT OR Apache-2.0** license, following the convention used by most of the Rust ecosystem. This isn't finalized until the first code lands, but it's the intended direction.

---

<p align="center">
  <sub>Kelvra is an independent, early-stage project. Not affiliated with any existing product or company of a similar name.</sub>
</p>
