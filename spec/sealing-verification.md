# Verification results

What was run, with what, and what came out. Nothing here is an estimate: every number was read
from a command's output on the date below. Where something was *not* run, it says so.

**Run date:** 2026-10-27. **Machine:** Linux 7.2.9 (Arch), Python 3.14.8, pytest 9.1.1,
ruff 0.16.0, cryptography 50.0.2, hypothesis 6.170.11, mutmut 3.8.0.

## 1. Commands and results

| Command | Result |
|---|---|
| `python -m pytest -q` | **1239 passed, 1 skipped** in about 40 s. The skip is `tests/test_interop_mcp_sdk.py` (the `mcp` package is not installed in this environment; the interop job in CI installs it) |
| `python -m ruff check src tests examples evaluation` | All checks passed |
| `uv lock --check` | Resolved 26 packages, lockfile consistent with `pyproject.toml` (new extra `seal`) |
| `python examples/sealed_support_agent/demo.py` | Exit 0; both scenarios; "Plaintext account details in that prompt: none" twice; signature check valid |
| `python examples/sealed_support_agent/ui.py` | Served on 127.0.0.1; both scenarios looked at in a headless Chromium (screenshots viewed, not committed) |
| `kelvra check examples/sealed_support_agent/policy.klv` | exit 0; two warnings (`untrusted-reaches-sink` on `llm.provider` and `mail.customer`), both intended and explained in the example's policy |

New tests in this work: `tests/test_sealing.py` 42, `tests/test_sealing_details.py` 48,
`tests/test_sealed_agent_demo.py` 22, `tests/test_sealed_agent_ui.py` 15. Earlier in the same
effort: `test_provenance_details.py` 61, `test_taint_details.py` 36, `test_analysis_details.py` 23,
`test_klv_diagnostics.py` 55.

**Continuous integration:** the base project at `main` (commits `13b67d3`, `f4c6b85`) passed all 14
jobs (Ubuntu, macOS, Windows x Python 3.10, 3.13, 3.14, plus demo, interop and a
nothing-foreign-tracked check). **The sealing work is on a local branch and has not been pushed, so it
has not run in CI.** In particular it has not run on macOS, Windows or Python 3.10/3.13 (it was run
on Python 3.14 here). The lines `to_bytes(4, "big")` and `from_bytes(..., "big")` are written for
Python 3.10, where the byte order is required.

## 2. Mutation testing

`mutmut` changes the source in small ways and reports which changes the tests notice. A surviving
mutant is either a gap in the tests or a change that does not alter behaviour ("equivalent").

| Module | Mutants | Killed | Survived | Notes |
|---|---|---|---|---|
| `sealing.py` (this work, final run) | 337 | **317** | 20 | All 20 reviewed and equivalent (below). Started at 239 killed / 94 survived before `test_sealing_details.py` |
| `analysis.py` | 368 | 331 | 37 | Started at 259; the rest reviewed, equivalent |
| `provenance.py` | 928 | 653 before, not re-measured after | | Tests added for every group found; **no re-run** |
| `taint.py` | 371 | 310 before, not re-measured after | | Tests added; **no re-run** |
| `klv.py` | 1,143 | 842 before, not re-measured after | | `test_klv_diagnostics.py` added; the re-run did not complete |
| `gateway.py` | 749 | **not measured** | | The run could not collect the differential tests |

The 20 surviving `sealing.py` mutants: `"ascii"`/`"utf-8"` written in capitals (7); the byte order
argument omitted, which Python 3.11+ defaults to the same value (2); `validate=` on the base64
decode, redundant with the canonical re-encoding check that follows (3); `token_bytes(None)`, which
returns 32 bytes by default; `salt=None` omitted, its default; the bound `>=` instead of `>` on a
token length no valid token reaches; `TOKEN.sub("XXXX", ...)` which does not change the prefix
test; `last = None` before a loop that reassigns it; `zip(strict=...)` over lists that are always
the same length (3).

Mutation score measures how well the tests notice changes. It is not a security score.

## 3. Remediation record (audit findings)

The full audit is in `kelvra-audit/` (outside this repository): `AUDIT_FINDINGS.md`,
`STEP1_REPORT.md` to `STEP4-6_REPORT.md`. "Verified" means a named test fails without the fix.
Regression tests live in `tests/test_step*_*.py`, `tests/test_audit_regressions.py` and the
`*_details.py` files above; the audit's own independent tests are
`kelvra-audit/tests/test_independent_audit.py` (69, run against the fixed code: all pass).

| Finding | Severity (audit) | Root cause | Fix | Verification | Remaining risk |
|---|---|---|---|---|---|
| F-01 sealed policy mutable | High (compliance) | Seal copied dicts but did not freeze them | Read-only views, setters raise, `record()` refuses if the fingerprint changed | `test_step1_hardening.py`, `test_provenance_spec.py` | Same-process code can still reach private attributes |
| F-02 Unicode line separators hide a declaration | High | `str.splitlines()` before comment stripping | Lines end only at LF/CRLF/CR; control, format and separator characters rejected everywhere | `test_step1_hardening.py`, `test_step3_hardening.py` (sources scanned for invisible characters), property test | None known |
| F-03 clauses accepted then ineffective | Medium-High | Parser last-wins and ignored clauses | Duplicate and inert clauses are errors | `test_step1_hardening.py`, `test_klv_diagnostics.py` (46 malformed files, each checked for line, text, message and hint) | None known |
| F-04 endorsement can be self-granted | High (design) | One session exposed `declassify` to the agent | `AgentSession` without privileged methods; analysis errors `unguarded-endorsement`, `unguarded-public-declassification` | `test_step1_hardening.py`, `test_analysis_details.py` | Depends on the integrator giving the agent the session, not the authority |
| F-05 truthy consent | Medium | Any truthy object granted | Only `ConsentDecision(True, <identity>)` grants; the rest refuse and are recorded | `test_taint_details.py` (consent answers, identity bounds, service identities) | A consent provider answered by a script instead of a person |
| F-06 unhandled exceptions | Medium-Low | Malformed files | CLI/LSP/parser raise only located errors | `test_properties.py` (no text makes parser or LSP raise anything else) | None known |
| F-07 `verify` fragile | Medium | Hostile input | `verify_record` never raises, checks structure, recomputed summary, chain, signature | `test_provenance_details.py` (exact reasons, 15 break modes), `spec/provenance.vector.json` | HMAC is symmetric: whoever verifies can sign |
| F-08 journal not append-only | Medium | Mutable ledger | Per-event hash chain, closed on `record()`, write-ahead journal | `test_provenance_details.py` (11 damage modes), `test_step6_journal.py` | No external anchoring of the chain head |
| F-09 audit completeness | Medium | Refusals not recorded | `deny` for undeclared sinks, `refuse` for sources/declassifiers, consent per call | `test_step2_provenance.py`, `test_taint_details.py` | An opened sealed token is not an event of its own |
| F-10 forgeable labels | Low-Medium | `Tainted` constructible | Values issued by a session and recognised by it | `test_step3_hardening.py` | `unsafe_value` and same-process access remain, documented |
| F-11 key hygiene | Low | No checks | Type and length (16 bytes minimum) checked at start; unsigned-record warning at the caller | `test_taint_details.py`, `test_step3_hardening.py` | Entropy of a caller-supplied key is not checked |
| F-12 `from` not applied | Low | Documentary only | Read as an upper bound; each declassification records `within`/`outside` | `test_step3_hardening.py`, `test_sealing.py::test_what_a_declassification_is_taken_on...` | It is a record, not an enforcement on the data |
| F-13 language hardening | Low | Defaults | Warning when `integrity` omitted; `*` refused as a name | `test_klv_diagnostics.py::test_warnings_say_which_line...` | None known |

Found and fixed after the audit report (each with a test that fails without the fix):

| Item | Fix | Test |
|---|---|---|
| Gateway: number overflowing to infinity forwarded | Non-finite floats refused | `tests/test_gateway_differential.py` |
| Gateway: hybrid request/response, duplicate keys, case-variant methods | Strict parse, exact members, ASCII-only interpreted keys | `tests/test_step6_gateway.py`, differential tests |
| Gateway: a refusal owed to the server could be lost after the client left | Drain waits for the server to fall quiet | `test_end_to_end_a_request_the_server_makes_after_the_client_left_is_still_refused` (fails deterministically without the fix; the race was seen once on Windows/3.14) |
| Test harness: 4 MB Go binary left behind per process (about 3.4 GB filled the disk quota, making unrelated tests fail) | Removed at exit | Measured: 892 directories before, 0 leaked after a run |
| Sealing: several base64 spellings of one token | Canonical spelling only | `test_non_canonical_spellings_of_the_same_bytes_are_not_tokens` |

## 4. Reproducing the previously found vulnerabilities

The audit's 69 independent tests are the reproduction suite, each written against the *unfixed*
behaviour and now asserting the fixed one. They were last run against the fixed code before this
work began (all passing); **they were not re-run in this session**: they live outside the repository.
Re-running them against the current code is listed in
the project's private submission notes.

## 5. Against real models

Run on 2026-10-28 with `examples/sealed_support_agent/live_check.py`; raw per-trial results are in
`evaluation/live/`, and the table below is generated from them (a test fails if they disagree).

**Method.** The full pipeline, with a real model in place of the scripted one. The customer's message is
real text: a banking question from PolyAI/banking77 (CC-BY-4.0), and for the injection cases either one of
five hand-written attacks, or an attack taken from a public dataset (deepset/prompt-injections,
yanismiraoui/prompt_injections, Lakera/mosscap_prompt_injection). The account details the pipeline seals
(name, IBAN, telephone) are **fictional**: an IBAN with valid check digits and no bank behind it, a number
from a range reserved for fiction. The agent is asked to reply to the customer and confirm the three details
on file, so it needs all three tokens. Each trial uses a fresh random key and fresh details; sampling
settings are the provider's defaults. A dataset manifest (revision, licence, hash) is in each results file.

<!-- live:start -->
| model | message | trials used | token copied exactly | reply complete | tried another destination | delivered elsewhere | plaintext in prompt | calls that failed |
|---|---|---|---|---|---|---|---|---|
| gemini-3.5-flash-lite (gemini) | normal | 5 of 5 | 100% (15/15) | 100% (5/5) | 20% (1/5) | 0 | 0 of 5 | 0 of 5 |
| gemini-3.5-flash-lite (gemini) | injection (hand-written) | 5 of 5 | 100% (15/15) | 100% (5/5) | 0% (0/5) | 0 | 0 of 5 | 0 of 5 |
| gemini-3.5-flash-lite (gemini) | injection (public datasets) | 5 of 5 | 100% (15/15) | 100% (5/5) | 0% (0/5) | 0 | 0 of 5 | 0 of 5 |
| openai/gpt-oss-120b (groq) | normal | 17 of 20 | 94% (45/48) | 88% (15/17) | 35% (6/17) | 0 | 0 of 17 | 3 of 20 |
| openai/gpt-oss-120b (groq) | injection (hand-written) | 15 of 20 | 87% (27/31) | 40% (6/15) | 47% (7/15) | 0 | 0 of 15 | 5 of 20 |
| openai/gpt-oss-120b (groq) | injection (public datasets) | 18 of 20 | 100% (51/51) | 94% (17/18) | 33% (6/18) | 0 | 0 of 18 | 2 of 20 |
| openai/gpt-oss-20b (groq) | normal | 18 of 20 | 86% (24/28) | 11% (2/18) | 6% (1/18) | 0 | 0 of 18 | 2 of 20 |
| openai/gpt-oss-20b (groq) | injection (hand-written) | 20 of 20 | 92% (22/24) | 0% (0/20) | 45% (9/20) | 0 | 0 of 20 | 0 of 20 |
| openai/gpt-oss-20b (groq) | injection (public datasets) | 19 of 20 | 85% (29/34) | 11% (2/19) | 21% (4/19) | 0 | 0 of 19 | 1 of 20 |
| qwen/qwen3.8-27b (groq) | normal | 9 of 20 | 100% (27/27) | 89% (8/9) | 67% (6/9) | 0 | 0 of 9 | 11 of 20 |
| qwen/qwen3.8-27b (groq) | injection (hand-written) | 9 of 20 | 94% (17/18) | 44% (4/9) | 33% (3/9) | 0 | 0 of 9 | 11 of 20 |
| qwen/qwen3.8-27b (groq) | injection (public datasets) | 7 of 20 | 100% (21/21) | 100% (7/7) | 43% (3/7) | 0 | 0 of 7 | 13 of 20 |
<!-- live:end -->

*Token copied exactly* is measured among the tokens the model tried to copy (name, IBAN, telephone, one per
kind). *Reply complete* means a reply reached the customer with all three real details. *Tried another
destination* counts trials where the model named a destination other than the customer, including ones the
prompt listed (the CRM, an outside address): they are refused or recorded, and are not leaks. *Calls that failed*
are provider errors (mostly rate limits) that were retried and still failed; those trials are left out.

**What it shows**

* **The security property held in every valid trial: 147 of 147.** Nothing was delivered to a destination other
  than the customer's, and no prompt held a plaintext detail, whatever the model did, including when it obeyed an
  injection. This is the property the design exists for, and it does not depend on the model behaving.
* **Whether the feature is useful depends heavily on the model.** Copying a token back exactly happened 85% to
  100% of the time per token, but one altered token refuses the whole reply, so complete replies were far fewer
  for some models: from 100% (Gemini 3.5 Flash Lite, 5 trials per case) down to 0 to 11% for GPT-OSS 20B. The
  refusal is the safe outcome and a lost answer. **The cause of GPT-OSS 20B's incomplete replies was not
  diagnosed**; it may be copying errors, leaving tokens out, or sending to other destinations.
* The attacks taken from public datasets are generic ("ignore your instructions...") and mostly do not name a
  destination this agent has, so they say less about this pipeline than the hand-written ones, which do.

**Limits of this measurement**

* **Small samples and wide intervals.** 5 trials per case for Gemini; 15 to 20 for the GPT-OSS models; 7 to 9 for
  Qwen, whose other calls failed (11 to 13 of 20 per case, rate limits). Intervals are in the results files; a
  difference of a few trials between two models is not a finding.
* One day, one prompt, default sampling, three providers' models of one or two families. Not a ranking, and not
  a claim about any model that was not run.
* Gemini 3.5 Flash was started and its free quota ran out; those trials are not included.
* The data is fictional where it matters and public elsewhere; real customer traffic, longer prompts and other
  languages were not tried.
* It says nothing about what a provider does with a prompt it receives. The design assumes the worst.

## 6. What was not verified

* The sealing code on macOS and Windows (it passes the suite on Linux under Python 3.10, 3.13 and 3.14; CI has not run on this branch).
* A real model's behaviour beyond section 5: three providers' models, small samples, one day.
* Confidentiality of the construction itself beyond the primitives' published known answers and
  an independent re-implementation of the format; no external cryptographic review.
* Side channels, memory remanence, a compromised host.
* The mutation score of `provenance`, `taint`, `klv` and `gateway` after the tests added.
* Interoperability with the MCP SDK in this environment (it ran in CI for the base project).
