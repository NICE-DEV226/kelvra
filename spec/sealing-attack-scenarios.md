# Attack scenarios and how they were tested

Every scenario below is a test that runs in CI. For each: the attacker's capabilities, the
invariant that must hold, the procedure, the result observed on the run recorded in
[sealing-verification.md](sealing-verification.md), and what the test cannot tell you. Tests
live in `tests/test_sealing.py` (`S:`), `tests/test_sealing_details.py` (`D:`) and
`tests/test_sealed_agent_demo.py` (`E:`).

"Observed: passes" means the assertion held on that run. It is a statement about the cases
written, not a proof about all inputs.

| ID | Scenario | Test |
|---|---|---|
| AS-01 | Model sends sealed data to an outsider | `S:test_the_same_reply_is_refused_at_a_sink_the_original_label_does_not_allow` |
| AS-02 | Prompt injection drives every action it can | `E:test_an_injected_model_delivers_nothing_anywhere`, `S:test_an_injected_model_gets_nowhere_with_the_token_it_was_given` |
| AS-03 | One character of a token is changed | `S:test_any_single_character_change_to_a_token_is_refused` |
| AS-04 | Token truncated, extended, split or re-cased | `S:test_truncated_extended_or_spliced_tokens_are_refused`, `S:test_a_token_the_model_invented_or_mangled_is_refused_and_recorded` |
| AS-05 | Model relabels a token as public | `S:test_the_label_in_a_token_cannot_be_swapped_for_a_more_permissive_one` |
| AS-06 | Model changes what kind of field a token is | `S:test_the_kind_cannot_be_changed_after_sealing` |
| AS-07 | Token replayed from an earlier run | `S:test_a_token_from_another_run_is_refused_...`, `E:test_a_second_run_cannot_use_the_first_runs_tokens` |
| AS-08 | Token presented under another key or policy | `S:test_a_token_under_another_key_or_another_policy_is_refused` |
| AS-09 | One customer's token sent to another customer | `S:test_one_customers_token_cannot_be_delivered_to_another_customers_sink` |
| AS-10 | Untrusted content drives a write that needs a human's endorsement | `S:test_untrusted_content_that_reaches_a_sink_needing_an_endorsement_is_still_refused` |
| AS-11 | Consent-gated sink without consent | `S:test_a_sink_that_wants_consent_asks_and_nothing_is_delivered_when_it_is_refused` |
| AS-12 | Mixed message: one allowed token, one forbidden | `S:test_a_refusal_opens_nothing_and_a_mixed_message_is_all_or_nothing` |
| AS-13 | Plaintext or key in logs, errors, repr, record, journal | `S:test_neither_the_plaintext_nor_the_key_appears_anywhere_...`, `E:test_no_plaintext_and_no_key_anywhere_...` |
| AS-14 | Key obtained through the agent's interface | `S:test_the_agent_session_has_no_way_to_seal_unseal_or_reach_the_key` |
| AS-15 | Key printed, pickled or copied | `S:test_a_master_key_refuses_to_be_shown_pickled_copied_or_compared_by_value`, `D:test_the_key_says_exactly_what_it_refuses_to_do` |
| AS-16 | Malformed or hostile token structure | `D:test_each_way_a_token_is_refused_says_which_kind_of_wrong_it_is`, `D:test_a_label_that_is_not_exactly_a_label_is_refused` |
| AS-17 | Authentic token with a corrupt inner frame | `D:test_a_token_whose_inner_length_is_wrong_or_not_text_is_refused_even_though_it_authenticates` |
| AS-18 | Concurrent sealing | `S:test_concurrent_sealing_and_opening_stay_correct_and_never_reuse_a_nonce` |
| AS-19 | Nonce budget exhausted | `S:test_the_seal_cap_...`, `D:test_the_seal_cap_message_and_the_count_it_applies_at` |
| AS-20 | API key of the real provider leaks | `E:test_the_adapter_never_shows_the_key_in_what_it_prints_or_raises` |
| AS-21 | Fail-open on error | `S:test_sealing_what_cannot_be_sealed_is_refused_and_leaves_no_trace_in_the_record`, `S:test_an_undeclared_sink_is_refused_...` |
| AS-22 | Code in the same process | `S:test_known_limit_code_in_the_same_process_can_reach_the_authority` (documents a limit) |

## Details

### AS-01, AS-02: the injected model

* **Attacker:** a model that has obeyed the instructions hidden in the customer's message. It can
  name any sink, declared or not, and put any text, including every token it was given, in any
  action.
* **Invariant:** plaintext reaches a sink only if the flow rule accepts the original label there.
* **Procedure:** `InjectedModel` returns six actions: two to the public outbound channel, one to the
  CRM, a made-up token, an altered token, and an undeclared sink. The pipeline executes each
  through the agent session's `emit_text`.
* **Observed:** passes. 0 delivered; 3 denied by the flow rule (audience, audience, missing
  endorsement); 3 refused (wrong key id, failed authentication, undeclared sink); the signed
  record verifies and counts 6 denials.
* **Limits:** the actions are scripted. A real model may do something else, and the test does not
  say what a real model does with a token.

### AS-03: exhaustive single-character tampering

* **Attacker:** can edit one character of a token anywhere.
* **Invariant:** the edited token is never accepted.
* **Procedure:** for every one of the 227 positions of a token, substitute each of 8 characters
  chosen from the base64url alphabet and `-`/`_`; call `unseal`.
* **Observed:** passes. 1,791 mutated tokens, 1,791 refused, 0 accepted. (Designing this test exposed a defect before it was run: base64 allows several spellings of the same
  bytes, so changing the last character could still decode. Tokens are now accepted only in their
  canonical spelling; `D:test_non_canonical_spellings_of_the_same_bytes_are_not_tokens`.)
* **Limits:** one token, one-character edits, one alphabet. Multi-character edits and structured
  edits are covered by AS-04 and AS-16 rather than exhaustively.

### AS-05, AS-06, AS-07, AS-08: moving a token somewhere it was not issued

* **Attacker:** holds a valid token and can rewrite any part of it, or carry it to another run,
  policy or key.
* **Invariant:** the label, kind, run and policy a token is opened under are the ones it was
  sealed under; anything else fails authentication.
* **Observed:** passes. Label swapped for another token's label or a hand-written public one:
  "failed authentication". Kind changed: same. Different run, same key and same policy: same.
  Different policy: "sealed under a different key or policy". Different key: refused.
* **Limits:** within one run a token is reusable by any sink the label allows (no single-use).

### AS-10: sealing does not launder integrity

* **Attacker:** controls the customer's message (untrusted) and wants the model's output to cause
  a CRM write that needs a human's endorsement.
* **Procedure:** a model call joins a sealed token with the untrusted message; the reply is emitted
  to `crm.write`, which requires `endorsed(reviewer)`.
* **Observed:** passes. Denied, reason mentions the missing endorsement, no plaintext in the message.
* **Limits:** the endorsement path (`human_review`) is exercised by the base suite, not here.

### AS-13, AS-20: leaks through the side doors

* **Attacker:** a reader of any artefact the system produces.
* **Procedure:** run a full pipeline (seal, model call, deliver, three refusals, two forgeries,
  record, journal) and search 11 surfaces for 8 needles: the plaintext, a fragment of it, the digits of
  the IBAN, the master key as hex, raw bytes, base64 and base64url, and the derived encryption
  key. For the adapter, search for the API key in `repr`, `vars`, and the exception raised on
  HTTP 401 whose body echoes the key.
* **Observed:** passes. No needle on any surface. The one place the plaintext appears is the
  delivery to the customer, asserted separately.
* **Limits:** named surfaces only. Memory, swap, core dumps and the network between the
  application and its sinks are not searched.

### AS-22: a limit, written as a test

`AgentSession` removes the privileged methods; it does not stop code that reaches for
`session._kelvra`. The test asserts that this is possible. It is there so the limit stays visible
and so that any future change that closes it has to update a test.

## Cases considered and not tested

* A model that behaves differently across many runs (statistical behaviour).
* A real provider's treatment of the prompt (logging, retention, training). Unknown; the
  design assumes the worst.
* Timing differences between the refusal paths. No claim is made about them.
* Resource exhaustion: a very large text with many tokens (tokens are bounded individually; the
  text is not).
