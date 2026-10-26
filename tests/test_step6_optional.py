"""The core must work without the optional signing dependency."""

import importlib
import sys

import pytest

from kelvra import Kelvra, parse, verify_record


def test_the_core_imports_and_signs_with_hmac_without_cryptography(monkeypatch):
    for name in [m for m in sys.modules if m == "cryptography" or m.startswith("cryptography.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "cryptography", None)  # import now fails
    import kelvra.signing

    importlib.reload(kelvra.signing)
    k = Kelvra(parse("policy P\nprincipal a\n"), signing_key=b"k" * 32)
    assert verify_record(k.record(), b"k" * 32).ok


def test_asking_for_ed25519_without_the_dependency_says_how_to_get_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography", None)
    monkeypatch.setitem(sys.modules, "cryptography.hazmat", None)
    from kelvra.signing import Ed25519Signer, SigningUnavailable

    with pytest.raises(SigningUnavailable, match=r"kelvra\[sign\]"):
        Ed25519Signer(b"k" * 32)
