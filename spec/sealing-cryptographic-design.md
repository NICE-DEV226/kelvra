# Cryptographic design of sealing

Kelvra does not define a cryptographic primitive. It composes two established ones, from one
maintained library, and binds the result to its information-flow label. This document says
what is built, why each choice was made, and, as importantly, what is **not** claimed.

Source: [`src/kelvra/sealing.py`](../src/kelvra/sealing.py). Optional dependency:
`pip install "kelvra[seal]"` (`cryptography >= 43`). The core of Kelvra stays dependency-free.

## 1. Primitives

| Job | Primitive | Standard | Library call |
|---|---|---|---|
| Key derivation | HKDF with SHA-256, no salt | RFC 5869 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| Encryption and authentication | AES-256-GCM, 96-bit nonce, 128-bit tag | NIST SP 800-38D | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| Randomness | Operating system CSPRNG | n/a | `os.urandom`, `secrets.token_bytes` |

Nothing else. No hash is used on its own, nothing is hand-rolled, there is no custom mode,
padding scheme, or MAC. The one construction of Kelvra's own is the **binding** (section 3).

The tests check that the library behaves as published (`test_aes_256_gcm_matches_the_published_known_answer`:
GCM test case 16; `test_hkdf_sha256_matches_rfc_5869_test_case_1`), and that a token opens with
the construction below re-implemented from this document with `cryptography` alone
(`tests/test_sealing_details.py::test_a_token_opens_with_the_documented_construction_and_nothing_else`
and the reverse direction).

## 2. Key hierarchy and lifecycle

```
MasterKey (>= 32 bytes, held by the authority only)
   |  HKDF-SHA256, info = "kelvra/seal/v1/aes-256-gcm|" + policy fingerprint
   +--> encryption key (32 bytes)  -> AES-256-GCM
   |  HKDF-SHA256, info = "kelvra/seal/v1/key-id|" + policy fingerprint, 4 bytes
   +--> key id (8 hex characters, shown in every token)
```

* **One key per purpose.** The key that encrypts and the value that names it are independent
  HKDF outputs; the key id reveals nothing about the encryption key (it is an independent
  output of a PRF, truncated to 32 bits). Signing keys (HMAC or Ed25519) are separate objects
  with separate variables: nothing derives one from the other.
* **One key per policy.** The policy fingerprint is in the HKDF context and in the authenticated
  data, so a token cannot be opened under a different policy even with the same master key.
* **Generation.** `MasterKey.generate()`: 32 bytes from `secrets.token_bytes`. A key given by the
  caller must be at least 32 bytes; its entropy is the caller's responsibility and is not
  checked.
* **Storage.** In process memory as a `bytearray` in the authority. `MasterKey.from_hex_env`
  reads a hex key from an environment variable, which is visible to the user's other processes and
  to crash dumps; it exists for demonstrations. A secret manager or HSM behind the same class is the
  deployment answer and is **not implemented**.
* **Use.** Only by `Sealer`, only through `derive`. The class has no accessor, a redacted
  `repr`, and refuses pickling, copying and value comparison.
* **Rotation.** Not implemented. A new key means new tokens; old tokens fail with
  "sealed under a different key or policy". There is no key registry and no re-sealing.
* **Destruction.** `MasterKey.destroy()` overwrites the bytearray. Best effort: Python may
  have made copies (the derivation reads `bytes(self._key)`), and the interpreter gives no
  guarantee about memory.

## 3. The token

```
kelvra-seal.v1.<kind>.<key id>.<label>.<body>

  kind   1-24 characters [a-z][a-z0-9_]*       what the value is ("iban"); chosen by the caller
  key id 8 hex characters                     names the key without revealing it
  label  base64url(canonical JSON)            the ORIGINAL label of the value, in clear
  body   base64url( nonce(12) || AES-GCM( framed ) || tag(16) )

  framed = length(4 bytes, big endian) || plaintext(UTF-8) || zero padding to a multiple of 64
  additional authenticated data = "kelvra-seal-v1" 0x00 run id 0x00 policy fingerprint
                                  0x00 kind 0x00 canonical label JSON
  canonical label JSON = {"endorsers":..,"purposes":..,"readers":..}, sorted keys, no spaces
```

**What the authenticated data buys.** The label is not secret and travels in clear, but it is
authenticated: changing it fails the tag. That is what makes the token carry its own label, so the
boundary can decide on the *original* label without a database and without trusting the model's
copy. The run id means a token is only valid in the run that sealed it. The kind prevents a token
for one field from being presented as another.

**Why the label is in clear.** The boundary must read the label before it can decide, and it can
only trust the label after authenticating it. Hiding it would add nothing against the provider
that the policy does not already say (the provider is told, by the policy, which principals exist);
it would cost a second key and a harder-to-audit format.

**Length.** The plaintext is padded to a 64-byte multiple and the length is framed inside the
ciphertext, so the token length reveals only which 64-byte bucket the value falls in.

**Canonical encoding.** A token has exactly one valid spelling: base64url without padding whose
re-encoding matches, canonical JSON for the label. Several spellings of the same bytes would be
several tokens for one value, which makes "is this the token I issued" a question about bytes
instead of meaning.

## 4. Nonces and the limit that comes with them

A fresh 96-bit nonce is drawn from the OS for every seal. With random nonces, the probability that
any two of `q` seals under one key share a nonce is at most `q^2 / 2^97`. NIST SP 800-38D limits
random-nonce invocations to 2^32 per key. Kelvra refuses past **2^24 seals per key**
(`MAX_SEALS_PER_KEY`), which bounds that probability by `2^-49`, and says so in the error
("rotate it"). The counter is per `Sealer`, that is per run; a long-lived master key across many
runs is not tracked and its rotation is the operator's.

A nonce collision under GCM is catastrophic (it reveals the XOR of two plaintexts and allows
forgery); that is why the cap is far below the limit rather than at it.

## 5. Failure handling

Every failure raises `SealError` (or the flow rule's `Denied`) and is recorded as a refusal by
`emit_text`; nothing is substituted, nothing is passed through. The error says *which kind of
wrong*: malformed (the shape), "different key or policy" (the key id), or "failed authentication"
(the tag, the label, the run, the kind or the inner framing). It does **not** distinguish
inside "failed authentication": which of label, run or bytes was wrong is what someone probing the
boundary would want to know. Messages carry no plaintext and no key material
(`test_a_key_in_a_traceback_is_not_a_thing_because_it_is_never_a_local_argument`).

## 6. What is claimed, and what is not

**Claimed**, each with the evidence in [sealing-properties.md](sealing-properties.md):

* Given a token, an adversary without the master key learns nothing about the plaintext beyond its
  64-byte length bucket, *if AES-256-GCM is secure and nonces do not repeat*. That is the
  standard AEAD guarantee, restated, not re-derived.
* A token cannot be altered, relabelled, re-kinded, moved to another run or policy, or opened
  under another key without detection (the tag covers all of them).

**Not claimed:**

* **Side-channel resistance.** None. No constant-time claim for anything written in Python; the
  library's constant-time properties are the library's. There is no attacker model for timing,
  cache, power, or memory-remanence attacks, so there is no claim.
* **Computation on ciphertext.** A model cannot work with a sealed value. This is encryption of a
  value in transit through an untrusted party, not homomorphic encryption and not secure
  multi-party computation.
* **Protection against a provider that receives plaintext.** Encryption in transit (TLS) does
  not do this and neither does sealing the *wrong* fields: only fields the policy marks as not
  readable by the provider are sealed, and the rest, such as the customer's question, are sent in
  clear on purpose.
* **Any property of ordinary hashing, redaction or prompt instructions.** None of them is used as
  a security mechanism.
* **Security against a compromised application,** key extraction from process memory, or a weak
  caller-supplied key.
* **Post-quantum security.** AES-256 is considered adequate against known quantum attacks on
  symmetric keys; nothing else here has been analysed against them.
* **Formal verification** of this construction. It is a straightforward composition, reviewed by
  the author and tested, not formally analysed or externally audited.

## 7. Shamir secret sharing, and why it is not here

The hackathon permits secret sharing. Splitting the master key (for example 2-of-3 between the
operator, a hardware token and a recovery holder) would reduce the chance that one leak exposes
everything, and is a reasonable extension. It would be an addition to *key storage*, not to what
the model or provider can learn: they never hold the key either way. It is left out, rather than
included untested, because it needs its own known-answer tests and a decision on who the
holders are.
