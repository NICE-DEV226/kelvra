# Threat model: sealing values for an external model

This document covers what was added for sealing (`kelvra.sealing`, `Kelvra.seal`,
`Kelvra.emit_text`). The model of the rest of Kelvra, labels, flows and the record, is
[spec/threat-model.md](threat-model.md); nothing here replaces it.

Statuses used throughout: **confirmed within the tested scope**, **partially confirmed**,
**not demonstrated**, **refuted by a counter-example**, **not evaluated**. They are
statements about evidence, not percentages.

## 1. The problem, stated narrowly

A pipeline that calls an external model has to put something in the prompt. If that something
is a customer's account number, the provider receives it in plaintext, the model can repeat it
anywhere its output goes, and a prompt injection in any other input can ask it to.

Kelvra already stops the *output* from reaching a destination the policy forbids. It did not
stop the *input* from reaching the provider except by refusing the call. Sealing adds the
middle path: the value goes in as ciphertext, and comes back as plaintext only at a sink that
the value's own label allows.

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Labelled values (account number, name, phone) | The data the policy exists to protect | Application memory as `Tainted`; plaintext at a sink after `emit_text` |
| Master key (`MasterKey`) | Everything sealed depends on it | The authority (`Kelvra`) only: a `bytearray` in process memory; from an environment variable if the operator chose that |
| Derived sealing key | Encrypts and authenticates tokens | Inside `Sealer`, one per policy fingerprint |
| The policy | Defines what each label may do | Sealed, hashed; fingerprint is in every record and in every token's authenticated data |
| The record and journal | The audit trail | Signed (HMAC or Ed25519); contain labels, never values |
| Signing key | Authenticity of the record | Separate from the master key (different variable, different class) |

## 3. Trust boundaries and who is trusted

```
 untrusted                          trusted (one process)                       untrusted
 ---------                          ---------------------                       ---------
 customer message  --read-->  [ application / Kelvra authority ]  --prompt-->  model provider
 (any author)                  holds: master key, plaintext,                    (stores the prompt,
                               policy, ledger, signing key                       runs the model)
                                       |                                               |
                          AgentSession: read, model_call,                              |
                          combine, emit, emit_text, would_allow  <---- model output ----+
                                       |
                              emit_text(sink, text)
                                       v
                        sink: customer mail, CRM, outsider
```

| Party | Trusted to | Not trusted to |
|---|---|---|
| Application and Kelvra authority (one process) | Hold plaintext and the key; decide flows | Nothing further is claimed: a bug or compromise here is out of scope |
| Policy author | Declare labels, sinks and declassifiers correctly | Kelvra does not verify that a source's label is true |
| Operator | Generate, store and rotate the master key; wire the consent provider to a person | |
| Human consent provider | Answer for an endorsement or a use | Not to be a service identity: refused as self-approval |
| Sinks | Handle the plaintext they are allowed to receive | |
| **Model provider** | **Nothing.** Receives only ciphertext, labels and the clear parts of the prompt | Anything |
| **The model's output** | **Nothing.** Treated as untrusted-integrity text that may contain any token or any invented token | Anything |
| Authors of untrusted inputs | Nothing | Anything: they can write instructions into the prompt |

## 4. Adversaries and their capabilities

| ID | Adversary | Can | Cannot |
|---|---|---|---|
| A1 | The provider (or anyone who later reads its logs) | See every prompt: clear text, tokens, their key id and the token's label; keep them forever | Read a sealed value, forge or alter a token, learn the key |
| A2 | A model steered by an injection (A3 below) | Write any text: copy, alter, truncate, split, invent or reorder tokens; name any sink, declared or not | Make the boundary open a token for a sink the original label forbids |
| A3 | The author of untrusted content | Put instructions in the message the model reads | Reach the application process |
| A4 | A confused deputy: tokens of one customer, a sink of another | Route a token to a different destination | Pass the flow rule for the token's original label |
| A5 | Someone with a token from an earlier run | Replay it in a new run | Have it opened there |
| A6 | Someone who reads the signed record, the journal, logs or error messages | Learn labels, sink names, counts, key id, timing | Learn a value or the key from them |

## 5. Explicit assumptions

1. AES-256-GCM and HKDF-SHA256 as implemented by the `cryptography` package (OpenSSL) are
   secure, used with unique nonces. Kelvra does not re-prove them.
2. `os.urandom` and `secrets` are a CSPRNG.
3. The master key was generated with enough entropy and has not leaked. `MasterKey.generate`
   does the first; the second is the operator's.
4. The application process is not compromised. Code in the same process can reach the key
   (see [sealing-attack-scenarios.md](sealing-attack-scenarios.md), "known limit").
5. The declared labels are true. Declaring an account number `public` makes it public.
6. The consent provider is answered by a person, not by the agent.

## 6. Entry points and sensitive flows

| Entry point | What crosses | Check | Where |
|---|---|---|---|
| `Kelvra.read` | A value, labelled by its declared source | Source is declared | `taint.py` `read` |
| `Kelvra.seal` | Plaintext in; token out | Declassifier declared; consent if required; length and kind valid; sealed **before** the crossing is recorded | `taint.py` `seal`, `sealing.py` `Sealer.seal` |
| `AgentSession.model_call(..., via=provider)` | The prompt, including tokens | Flow rule on the joined label against the provider sink | `taint.py` `model_call`, `_authorize` |
| `AgentSession.emit_text` | Model text out; plaintext in the result | Every token authenticates; flow rule on `join(text label, every original label)`; consent if the sink requires it | `taint.py` `emit_text`, `sealing.py` `Sealer.resolve` |
| Ledger and journal | Events | Labels only, never values | `provenance.py` |

## 7. Attack scenarios and mitigations

Each is exercised by a named test; see [sealing-attack-scenarios.md](sealing-attack-scenarios.md) for the
procedure and the observed result.

| Scenario | Mitigation | Status |
|---|---|---|
| Model sends the token to an outsider | `emit_text` checks the original label against the sink | Confirmed within the tested scope |
| Model alters a token (one character, truncation, glue, split) | Authentication tag; whole-token regex; residual prefix refused | Confirmed (exhaustive single-character test) |
| Model invents a token | Key id and tag do not match | Confirmed |
| Model swaps the label for a more permissive one | Label is in the authenticated data | Confirmed |
| Model changes the token's kind | Kind is in the authenticated data | Confirmed |
| Token replayed from another run | Run id is in the authenticated data | Confirmed |
| Token opened under another policy or key | Key id differs; fingerprint is in the authenticated data | Confirmed |
| Untrusted content drives a write that needs an endorsement | Integrity axis is unchanged by sealing | Confirmed |
| Customer A's token to customer B's sink | Original label's readers do not include B | Confirmed |
| Plaintext or key in logs, errors, traces, repr, record, journal | Values are never recorded; the key refuses `repr`, pickling and copying | Confirmed for the surfaces listed in the test |
| Fail-open when something raises | Every error path in `emit_text` raises; nothing is substituted before the decision | Confirmed |
| Concurrent use | Counter under a lock; nonces unique across 1,200 concurrent seals | Confirmed (one test, 8 threads) |

## 8. What is not protected (residual risks and out of scope)

* **The application process.** Anything running in it can read the key and plaintext. The
  `AgentSession` removes privileged methods, it is not a sandbox. Real isolation is a process
  boundary (for example the MCP gateway in a separate process holding the authority).
* **What the provider can still learn.** The clear parts of the prompt; the *label* of each
  token (principal names); the token's *kind*; the plaintext length to within a 64-byte
  bucket; how many tokens and when.
* **Utility.** A model cannot reason about a ciphertext. Sealing does not give computation on
  encrypted data. It lets the model carry a value it cannot read.
* **A model that mangles tokens** produces an error, never a repair. The reply is lost.
* **Side channels.** No claim. Python offers no constant-time or memory-scrubbing guarantee;
  `MasterKey.destroy` is best effort.
* **Key lifecycle.** Generation and destruction exist; rotation and a key id registry do not.
  The seal count is capped at 2^24 per key to stay far under the AES-GCM random-nonce limit.
* **Key storage.** The master key can come from an environment variable, visible to the same
  user's other processes and to crash dumps. A secret manager or HSM behind `MasterKey` is the
  deployment answer and is not built.
* **Wrong labels, wrong policy, a sink that mishandles plaintext, a compromised host,
  denial of service, post-quantum threats.** Out of scope.
* **Audit completeness for sealing.** Opening a token is recorded as an ordinary `allow`
  with the joined label; there is no separate `unseal` event, so the record cannot say which
  token was opened, only that a flow with that label was allowed.
