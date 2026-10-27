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

## 5. What was not verified

* The sealing code on macOS, Windows, Python 3.10 and 3.13 (CI would).
* Any behaviour against a live model provider: no request left this machine.
* A real model's behaviour with a token in its prompt.
* Confidentiality of the construction itself beyond the primitives' published known answers and
  an independent re-implementation of the format; no external cryptographic review.
* Side channels, memory remanence, a compromised host.
* The mutation score of `provenance`, `taint`, `klv` and `gateway` after the tests added.
* Interoperability with the MCP SDK in this environment (it ran in CI for the base project).
