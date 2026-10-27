# Security properties of sealing

Each property names the kind of guarantee it is (confidentiality, integrity, authenticity,
authorization, auditability or availability: they are not interchangeable), the adversary it is
stated against ([sealing-threat-model.md](sealing-threat-model.md)), what enforces it, which tests exercise it,
and what is *not* covered. A passing test is evidence for the tested scope, not a proof.

Test names are in `tests/test_sealing.py` unless a file is given.

## S1. Confidentiality of a sealed value against the provider and the model

> Given the ciphertext token, the key id, the clear label and the kind, an adversary without
> the master key learns nothing about the plaintext beyond its length to within a 64-byte
> bucket.

* **Kind:** confidentiality (of the value). It does **not** cover the label, the kind or the
  bucket, which are sent in the clear on purpose.
* **Rests on:** the AEAD security of AES-256-GCM with a unique 96-bit nonce per message
  (NIST SP 800-38D), and HKDF-SHA256 producing independent keys. Kelvra adds a random nonce
  per seal, length padding to 64 bytes and a cap of 2^24 seals per key. The chance of any
  nonce repeating among q random 96-bit nonces is at most q^2 / 2^97; for q = 2^24 that is
  at most 2^-49.
* **Enforced by:** `Sealer.seal` (`src/kelvra/sealing.py`).
* **Evidence:** `test_aes_256_gcm_matches_the_published_known_answer`,
  `test_hkdf_sha256_matches_rfc_5869_test_case_1` (the primitives behave as published);
  `test_sealing_the_same_value_twice_gives_two_different_tokens` (300 seals, 300 distinct);
  `test_the_ciphertext_hides_the_exact_length_within_a_64_byte_bucket`;
  `test_concurrent_sealing_and_opening_stay_correct_and_never_reuse_a_nonce`.
* **Status:** partially confirmed. The primitives and the construction are tested; the
  security argument is the standard one for AES-GCM and is **not re-proved here**. No test can
  show confidentiality; the tests show that no tested surface contains the plaintext (S6).
* **Not covered:** side channels; a key leaked from process memory; a weak key (the
  constructor only checks length, not entropy); an adversary who also controls the application.

## S2. Integrity and authenticity of a token

> Any change to a token, to its label, its kind, or the run or policy it is opened under, is
> detected, and the token is then refused, never repaired.

* **Kind:** integrity of the token and authenticity of its origin (it was produced by an
  authority holding the key). Not non-repudiation: the key is symmetric.
* **Enforced by:** the GCM tag over the ciphertext with additional authenticated data
  `"kelvra-seal-v1" | run id | policy fingerprint | kind | canonical label`
  (`Sealer._aad`); strict whole-token parsing; canonical base64 and canonical label encoding
  (`Sealer.unseal`, `_unb64`).
* **Evidence:** `test_any_single_character_change_to_a_token_is_refused` (every position,
  seven substitutes, about 1,700 mutated tokens, none accepted);
  `test_truncated_extended_or_spliced_tokens_are_refused`;
  `test_the_label_in_a_token_cannot_be_swapped_for_a_more_permissive_one`;
  `test_the_kind_cannot_be_changed_after_sealing`;
  `test_non_canonical_spellings_of_the_same_bytes_are_not_tokens`;
  `test_a_token_under_another_key_or_another_policy_is_refused`;
  `test_a_token_from_another_run_is_refused_even_under_the_same_key_and_policy`;
  `test_whatever_is_sealed_comes_back_exactly_with_its_label` (150 generated cases).
* **Status:** confirmed within the tested scope.
* **Not covered:** a token is valid for the whole run, so it can be opened more than once and
  by any sink the label allows; there is no single-use or expiry.

## S3. Authorization: plaintext appears only where the original label allows

> `emit_text(sink, text)` returns plaintext for a token only if the flow rule accepts
> `join(label of text, original label of every token in it)` for that sink, and, where the sink
> requires consent, only after consent.

* **Kind:** authorization (access control by information-flow label). It is the same rule that
  governs every other flow in Kelvra, applied to the label the token was sealed with, not the
  relaxed label the token travels under.
* **Enforced by:** `Kelvra.emit_text` calling `_authorize` once with the joined label, before
  substituting anything (`src/kelvra/taint.py`).
* **Evidence:** `test_the_model_sees_the_token_and_the_customer_gets_the_value`;
  `test_the_same_reply_is_refused_at_a_sink_the_original_label_does_not_allow`;
  `test_one_customers_token_cannot_be_delivered_to_another_customers_sink`;
  `test_a_refusal_opens_nothing_and_a_mixed_message_is_all_or_nothing`;
  `test_a_sink_that_wants_consent_asks_and_nothing_is_delivered_when_it_is_refused`;
  `test_untrusted_content_that_reaches_a_sink_needing_an_endorsement_is_still_refused`;
  `test_an_undeclared_sink_is_refused_and_recorded_even_when_the_text_has_tokens`;
  `tests/test_sealed_agent_demo.py::test_an_injected_model_delivers_nothing_anywhere`.
* **Status:** confirmed within the tested scope (the scenarios named).
* **Not covered:** a sink the policy *allows* receives the plaintext: if `crm.write` is
  declared to accept the customer's data, an injected model can send the IBAN there (the test
  suite shows this and treats it as correct). The policy, not sealing, decides what a
  destination is allowed to hold.

## S4. Integrity (trust) is not laundered by sealing

> Sealing relaxes confidentiality only. The integrity of the data (who vouched for it) is
> unchanged, so untrusted content still cannot drive a sink that requires an endorsement.

* **Kind:** integrity (provenance of trust).
* **Enforced by:** `Declassifier.apply` unions readers only for a `declassify`; the seal keeps
  the endorser set (`taint.py` `_cross`).
* **Evidence:** `test_untrusted_content_that_reaches_a_sink_needing_an_endorsement_is_still_refused`;
  `examples` demo: the `crm.note` attempt.
* **Status:** confirmed within the tested scope.

## S5. Key containment

> The master key is not reachable through any method of an `AgentSession`, is never printed,
> pickled, copied or compared by value, and its derived keys are not recorded.

* **Kind:** confidentiality of the key, against the model-driven side of the program.
* **Enforced by:** `MasterKey` (`__slots__`, redacted `repr`/`str`, `__reduce__` and
  `__getstate__` raise, identity equality) and the `AgentSession` surface.
* **Evidence:** `test_a_master_key_refuses_to_be_shown_pickled_copied_or_compared_by_value`;
  `test_the_agent_session_has_no_way_to_seal_unseal_or_reach_the_key`;
  `test_a_key_from_the_environment_is_hex_and_a_bad_value_is_never_echoed`;
  `test_destroying_a_key_overwrites_it`.
* **Status:** confirmed for the model-driven side. **Refuted for code in the same process**,
  by `test_known_limit_code_in_the_same_process_can_reach_the_authority`, which asserts the
  limit rather than hiding it.

## S6. No plaintext or key on any observable surface

> Across the prompt, the model's reply, the signed record, the journal file, the report,
> `repr` of every object, error messages and tracebacks and captured logs, neither the plaintext
> nor the master key (hex, base64, base64url, raw) nor the derived key appears.

* **Kind:** confidentiality, against A1 and A6.
* **Evidence:** `test_neither_the_plaintext_nor_the_key_appears_anywhere_a_model_or_an_auditor_can_look`
  (11 surfaces, 8 needles including fragments);
  `test_a_key_in_a_traceback_is_not_a_thing_because_it_is_never_a_local_argument`;
  `tests/test_sealed_agent_demo.py::test_no_plaintext_and_no_key_anywhere_a_provider_or_an_auditor_can_look`
  and `..._journal_of_a_run_is_as_free_of_plaintext_as_the_record`;
  `..._the_adapter_never_shows_the_key_in_what_it_prints_or_raises` (API key).
* **Status:** confirmed for the surfaces enumerated. Absence of a string from named surfaces is
  not absence from every possible one (core dumps, swap, a debugger).

## S7. Auditability

> A run that seals and opens values yields a signed, hash-chained record that verifies, that
> states how many crossings, allows, denials and refusals occurred and for which sinks, and that
> contains no value.

* **Kind:** auditability (and integrity of the record, S2 of the base model).
* **Evidence:** `test_the_signed_record_of_a_sealed_run_still_verifies_and_says_what_was_refused`;
  `tests/test_sealed_agent_demo.py::test_the_record_says_what_was_sealed_and_what_was_refused_without_saying_what_it_held`;
  the base format's own tests (`tests/test_provenance_details.py`,
  `spec/provenance.vector.json`).
* **Status:** partially confirmed. **Gap:** an opened token is not individually recorded; the
  `allow` event carries only the joined label. An auditor can see that a flow with a customer
  label was allowed to a sink, not which token it was.

## S8. Fail closed

> Any error while sealing or opening produces an exception and a recorded refusal; no partial
> output, no pass-through of the token or of an altered value.

* **Evidence:** `test_a_token_the_model_invented_or_mangled_is_refused_and_recorded`;
  `test_sealing_what_cannot_be_sealed_is_refused_and_leaves_no_trace_in_the_record`;
  `test_a_refusal_opens_nothing_and_a_mixed_message_is_all_or_nothing`.
* **Status:** confirmed within the tested scope.
* **Availability cost:** a model that copies a token imperfectly loses the whole reply. That
  is the chosen side of the trade-off.

## S9. Availability

Not a goal. A malicious model can make every reply fail by mangling a token. Nothing here
defends against denial of service, and the per-key seal cap is an availability limit by design.

## Summary

| Property | Status |
|---|---|
| S1 Confidentiality of a sealed value | Partially confirmed (primitives and construction tested; security argument is the standard one) |
| S2 Token integrity and authenticity | Confirmed within the tested scope |
| S3 Authorization at the sink | Confirmed within the tested scope |
| S4 Integrity not laundered | Confirmed within the tested scope |
| S5 Key containment | Confirmed against the model side; refuted against same-process code |
| S6 No plaintext or key on observable surfaces | Confirmed for the enumerated surfaces |
| S7 Auditability | Partially confirmed (no per-token open event) |
| S8 Fail closed | Confirmed within the tested scope |
| S9 Availability | Not a goal |
