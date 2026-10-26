"""Asymmetric signatures for the provenance record (Ed25519).

HMAC proves a record came from a holder of the key, and proves nothing to a
party who does not hold it -- an auditor who holds the key could have forged
the record. Where the point of the record is to convince someone *outside* the
organisation, the verifier must hold only a public key. That is what this
module is for (spec/provenance.md section 6).

It is the one place the project needs a third-party library: the standard
library has no Ed25519, and implementing a signature scheme by hand is exactly
the work this project should not do. So it is an optional extra
(``pip install "kelvra[sign]"``) imported only when used; the core is still
dependency-free.

What it adds, and what it does not. A private key held *only* by the process
that signs lets anyone with the public key check the record without being able
to forge one. It does not authenticate the process: if the agent shares the
signer's memory, the key is the agent's. Keeping the signer in a separate
process or HSM is deployment, not something a library can promise.
"""

from __future__ import annotations

from typing import Any, Protocol

from .provenance import _canonical, verify_record


class SigningUnavailable(ImportError):
    """The optional ``cryptography`` package is not installed."""


class Signer(Protocol):
    """Anything that turns a record into a signature string."""

    def sign(self, record: dict) -> str: ...


def _ed25519() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as error:
        raise SigningUnavailable(
            'Ed25519 signatures need the optional dependency: pip install "kelvra[sign]"'
        ) from error
    return ed25519


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """A fresh ``(private, public)`` pair, each 32 raw bytes."""
    from cryptography.hazmat.primitives import serialization

    ed25519 = _ed25519()
    private = ed25519.Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    return (
        private.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        private.public_key().public_bytes(raw, serialization.PublicFormat.Raw),
    )


class Ed25519Signer:
    """Signs records with a 32-byte Ed25519 private key."""

    def __init__(self, private_key: bytes) -> None:
        if not isinstance(private_key, bytes | bytearray) or len(private_key) != 32:
            raise ValueError("an Ed25519 private key is exactly 32 bytes")
        self._key = _ed25519().Ed25519PrivateKey.from_private_bytes(bytes(private_key))

    @property
    def public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, record: dict) -> str:
        return "ed25519:" + self._key.sign(_canonical(record)).hex()


def check_ed25519(record: dict, public_key: object, problems: list[str]) -> bool:
    """Check ``record['signature']`` against a public key; append why not to ``problems``."""
    if not isinstance(public_key, bytes | bytearray) or len(public_key) != 32:
        problems.append("an Ed25519 public key is exactly 32 bytes")
        return False
    claimed = record.get("signature")
    if not isinstance(claimed, str) or not claimed.startswith("ed25519:"):
        problems.append("the record carries no Ed25519 signature")
        return False
    try:
        signature = bytes.fromhex(claimed.removeprefix("ed25519:"))
        ed25519 = _ed25519()
        ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            signature, _canonical(record)
        )
    except SigningUnavailable:
        raise
    except Exception:
        problems.append("signature does not match")
        return False
    return True


def verify_ed25519(record: object, public_key: bytes) -> bool:
    """True only for a well-formed, consistent, chained record signed by this key's owner."""
    result = verify_record(record, public_key=public_key)
    return result.ok and result.signed
