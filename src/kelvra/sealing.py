"""Sealing: the model gets ciphertext, plaintext appears only at a sink the original label allows.

What this is for
----------------
A pipeline that calls an external model has to put *something* in the prompt. Sealing lets
it put an authenticated ciphertext where a confidential value would have been, so the
provider (and anything the model is talked into doing) holds data it cannot read and a key
it never had. The plaintext comes back only when the model's output reaches a sink, and
only if the flow rule accepts the value's *original* label for that sink.

What this is not
----------------
It is not a new cryptographic construction. Every primitive here is established and comes
from the ``cryptography`` package: HKDF-SHA256 (RFC 5869) to derive a key per purpose, and
AES-256-GCM (NIST SP 800-38D) to encrypt and authenticate. What is Kelvra's own is the
*binding*: the token's authenticated data carries the run, the policy fingerprint, the kind
and the original label, so a token cannot be re-labelled, moved to another run, or opened
under another policy.

It is not computation on encrypted data. A model cannot reason about a ciphertext, so what
it can do with a sealed value is carry it: route it, quote it, put it in a reply. See
LIMITATIONS.md ("What sealing does not do").

The master key
--------------
:class:`MasterKey` lives in the authority (:class:`~kelvra.taint.Kelvra`), never in an
:class:`~kelvra.taint.AgentSession`. It has no accessor, refuses to be printed, pickled or
copied, and derives purpose keys instead of being used directly. Python cannot promise that
a key leaves no copy in memory or that no side channel exists; this is a capability
boundary inside one process, not a hardware one (spec/threat-model.md).

Failure is always closed: a token that is malformed, truncated, altered, from another run,
or under another key is an error and is never replaced by anything.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import threading
from typing import TYPE_CHECKING

from .labels import Label, PrincipalSet

if TYPE_CHECKING:
    from collections.abc import Callable

MIN_MASTER_KEY_BYTES = 32
MAX_PLAINTEXT_BYTES = 4096
MAX_SEALS_PER_KEY = 1 << 24
"""AES-GCM with random 96-bit nonces must stay far below 2**32 messages per key (NIST SP
800-38D section 8.3). A run is refused well before that; a new run derives nothing new from
this counter, so a long-lived master key is rotated by the operator, not by this module."""

_BUCKET = 64
_NONCE_BYTES = 12
_VERSION = "v1"
_PREFIX = f"kelvra-seal.{_VERSION}."
_KIND = re.compile(r"[a-z][a-z0-9_]{0,23}")
_B64 = r"[A-Za-z0-9_-]"
TOKEN = re.compile(
    rf"kelvra-seal\.{_VERSION}\.([a-z][a-z0-9_]{{0,23}})\.([0-9a-f]{{8}})\.({_B64}{{1,2048}})\.({_B64}{{16,12000}})"
)
"""A sealed token inside arbitrary text. Greedy on purpose: a token with characters glued on
the end is a different token, fails authentication, and is refused."""

MAX_TOKEN_CHARS = 14_500


class SealError(Exception):
    """A token could not be sealed or opened. Carries no plaintext and no key material."""


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as error:  # pragma: no cover - exercised only without the extra
        raise SealError(
            "sealing needs the 'cryptography' package: pip install 'kelvra[seal]'"
        ) from error
    return hashes, AESGCM, HKDF


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        data = base64.b64decode(text + pad, altchars=b"-_", validate=True)
    except ValueError as error:
        raise SealError("malformed sealed token") from error
    # Several spellings can decode to the same bytes (the unused low bits of the last
    # character). Only the canonical one is a token: one thing, one spelling.
    if _b64(data) != text:
        raise SealError("malformed sealed token")
    return data


class MasterKey:
    """The one secret everything sealed depends on. Held by the authority, never handed out."""

    __slots__ = ("_key",)

    def __init__(self, material: bytes | bytearray) -> None:
        if not isinstance(material, (bytes, bytearray)):
            raise TypeError(f"a master key is bytes, not {type(material).__name__}")
        if len(material) < MIN_MASTER_KEY_BYTES:
            raise ValueError(
                f"a master key is at least {MIN_MASTER_KEY_BYTES} bytes; got {len(material)}"
            )
        self._key = bytearray(material)

    @classmethod
    def generate(cls) -> MasterKey:
        """A fresh 256-bit key from the operating system's CSPRNG."""
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_hex_env(cls, var: str = "KELVRA_MASTER_KEY") -> MasterKey | None:
        """Read a hex-encoded key from the environment; ``None`` if the variable is unset.

        An environment variable is visible to every process of the same user and to a crash
        dump. It is here because a demonstration needs somewhere to put a key; a deployment
        wants a secret manager or an HSM behind the same class.
        """
        value = os.environ.get(var)
        if value is None:
            return None
        try:
            return cls(bytes.fromhex(value.strip()))
        except ValueError as error:
            # Never echo the value: it is the secret, or close enough to one.
            raise ValueError(f"${var} is not a hex-encoded key of at least 32 bytes") from error

    def derive(self, purpose: bytes, length: int = 32) -> bytes:
        """HKDF-SHA256 (RFC 5869) with ``purpose`` as the context: one key per use."""
        hashes, _, hkdf = _crypto()
        return hkdf(algorithm=hashes.SHA256(), length=length, salt=None, info=purpose).derive(
            bytes(self._key)
        )

    def destroy(self) -> None:
        """Overwrite the key in place. Best effort: copies made earlier are not reachable."""
        for index in range(len(self._key)):
            self._key[index] = 0

    @property
    def destroyed(self) -> bool:
        return not any(self._key)

    def __repr__(self) -> str:
        return "MasterKey(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("a MasterKey cannot be pickled or copied")

    def __getstate__(self):
        raise TypeError("a MasterKey cannot be pickled or copied")

    def __eq__(self, other: object) -> bool:
        return self is other

    __hash__ = object.__hash__


def _label_from_json(data: object) -> Label:
    def members(value: object) -> PrincipalSet:
        if value == "*":
            return PrincipalSet.all()
        if isinstance(value, list) and all(isinstance(m, str) and m and m != "*" for m in value):
            return PrincipalSet.from_iterable(value)
        raise SealError("malformed sealed token")

    if not isinstance(data, dict) or set(data) != {"readers", "endorsers", "purposes"}:
        raise SealError("malformed sealed token")
    return Label(members(data["readers"]), members(data["endorsers"]), members(data["purposes"]))


def _label_bytes(label: Label) -> bytes:
    return json.dumps(label.to_json(), sort_keys=True, separators=(",", ":")).encode("ascii")


class Sealer:
    """Seals and opens tokens for one run of one policy under one master key."""

    def __init__(self, key: MasterKey, policy_fingerprint: str, run_id: str) -> None:
        if not isinstance(key, MasterKey):
            raise TypeError("a Sealer needs a MasterKey")
        _, aesgcm, _ = _crypto()
        self._fingerprint = policy_fingerprint.encode("ascii")
        self._run = run_id.encode("ascii")
        # Separate keys for separate jobs: what encrypts is not what names the key.
        scope = b"|" + self._fingerprint
        self._aead = aesgcm(key.derive(b"kelvra/seal/v1/aes-256-gcm" + scope))
        self._kid = key.derive(b"kelvra/seal/v1/key-id" + scope, 4).hex()
        self._count = 0
        self._lock = threading.Lock()

    @property
    def key_id(self) -> str:
        """Names the key without revealing it (an independent HKDF output)."""
        return self._kid

    def _aad(self, kind: str, label: bytes) -> bytes:
        return b"\0".join((b"kelvra-seal-v1", self._run, self._fingerprint, kind.encode(), label))

    def seal(self, plaintext: str, kind: str, label: Label) -> str:
        if not isinstance(plaintext, str):
            raise SealError(f"only text can be sealed, not {type(plaintext).__name__}")
        if not _KIND.fullmatch(kind):
            raise SealError("a kind is 1 to 24 characters: a lowercase letter, then a-z 0-9 _")
        data = plaintext.encode("utf-8")
        if len(data) > MAX_PLAINTEXT_BYTES:
            raise SealError(f"a sealed value is at most {MAX_PLAINTEXT_BYTES} bytes")
        with self._lock:
            if self._count >= MAX_SEALS_PER_KEY:
                raise SealError("this key has sealed as much as one key should; rotate it")
            self._count += 1
        # Length is framed and padded to a bucket so the ciphertext does not give away the
        # exact length of the plaintext (only which 64-byte bucket it falls in).
        framed = len(data).to_bytes(4, "big") + data
        framed += bytes(-len(framed) % _BUCKET)
        nonce = os.urandom(_NONCE_BYTES)
        label_bytes = _label_bytes(label)
        ciphertext = self._aead.encrypt(nonce, framed, self._aad(kind, label_bytes))
        return f"{_PREFIX}{kind}.{self._kid}.{_b64(label_bytes)}.{_b64(nonce + ciphertext)}"

    def unseal(self, token: str) -> tuple[str, Label, str]:
        """Authenticate and decrypt. Returns ``(plaintext, original label, kind)``."""
        if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
            raise SealError("malformed sealed token")
        match = TOKEN.fullmatch(token)
        if match is None:
            raise SealError("malformed sealed token")
        kind, kid, label_part, body_part = match.groups()
        if kid != self._kid:
            raise SealError("sealed under a different key or policy")
        label_bytes = _unb64(label_part)
        try:
            label = _label_from_json(json.loads(label_bytes.decode("ascii")))
        except (UnicodeDecodeError, ValueError) as error:
            raise SealError("malformed sealed token") from error
        if _label_bytes(label) != label_bytes:
            raise SealError("malformed sealed token")  # not the canonical encoding
        body = _unb64(body_part)
        if len(body) < _NONCE_BYTES + 16:
            raise SealError("malformed sealed token")
        try:
            framed = self._aead.decrypt(
                body[:_NONCE_BYTES], body[_NONCE_BYTES:], self._aad(kind, label_bytes)
            )
        except Exception as error:
            # One message for every authentication failure: which part was wrong (label,
            # run, key, bytes) is exactly what an attacker probing the boundary would want.
            raise SealError("sealed token failed authentication") from error
        length = int.from_bytes(framed[:4], "big")
        if length > len(framed) - 4:
            raise SealError("sealed token failed authentication")
        try:
            return framed[4 : 4 + length].decode("utf-8"), label, kind
        except UnicodeDecodeError as error:
            raise SealError("sealed token failed authentication") from error

    def resolve(self, text: str, decide: Callable[[list[Label]], None]) -> tuple[str, list[Label]]:
        """Open every token in ``text``; ``decide`` is asked once, with every original label.

        ``decide`` raises to refuse. Nothing is substituted until it returns, so a refusal
        leaves no partial result. Text that mentions the token prefix without being a whole
        token is refused rather than passed through.
        """
        matches = list(TOKEN.finditer(text))
        stripped = TOKEN.sub("", text)
        if "kelvra-seal." in stripped:
            raise SealError("malformed sealed token")
        opened = [self.unseal(m.group(0)) for m in matches]
        labels = [label for _, label, _ in opened]
        decide(labels)
        out: list[str] = []
        last = 0
        for match, (plaintext, _, _) in zip(matches, opened, strict=True):
            out.append(text[last : match.start()])
            out.append(plaintext)
            last = match.end()
        out.append(text[last:])
        return "".join(out), labels
