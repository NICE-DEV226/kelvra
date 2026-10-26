"""Ed25519 signatures: a verifier that holds only a public key."""

import copy

import pytest

pytest.importorskip("cryptography")

from kelvra import Denied, Kelvra, parse, verify, verify_record
from kelvra.signing import (
    Ed25519Signer,
    generate_ed25519_keypair,
    verify_ed25519,
)

POLICY = """\
policy P
principal a, b
source s_a
    confidential(a)
    integrity trusted
source s_b
    confidential(b)
    integrity trusted
sink out
    accepts confidential(a)
"""


def signed_run(signer):
    k = Kelvra(parse(POLICY), signer=signer)
    k.emit("out", k.read("s_a", "x"))
    with pytest.raises(Denied):
        k.emit("out", k.read("s_b", "y"))
    return k.record()


def test_rfc_8032_test_vector_1_through_the_library_we_use():
    """Known answer: the primitive behaves as the standard says (RFC 8032 section 7.1)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    assert key.sign(b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701c"
        "f9b46bd25bf5f0595bbe24655141438e7a100b"
    )


def test_a_record_signed_with_a_private_key_verifies_with_the_public_one_only():
    private, public = generate_ed25519_keypair()
    record = signed_run(Ed25519Signer(private))
    assert record["signature"].startswith("ed25519:")
    assert verify_ed25519(record, public)
    result = verify_record(record, public_key=public)
    assert result.ok and result.signed and not result.legacy


def test_the_public_key_cannot_forge():
    """Everything the verifier holds is public; signing needs the private half."""
    private, public = generate_ed25519_keypair()
    record = signed_run(Ed25519Signer(private))
    forged = copy.deepcopy(record)
    forged["events"] = [e for e in forged["events"] if e["kind"] != "deny"]
    assert not verify_ed25519(forged, public)


def test_another_issuers_key_does_not_verify():
    record = signed_run(Ed25519Signer(generate_ed25519_keypair()[0]))
    assert not verify_ed25519(record, generate_ed25519_keypair()[1])


def test_the_signer_exposes_its_public_key():
    private, public = generate_ed25519_keypair()
    assert Ed25519Signer(private).public_key == public


@pytest.mark.parametrize("key", [b"", b"x" * 31, b"x" * 33, "text", None])
def test_malformed_private_keys_are_refused(key):
    with pytest.raises(ValueError):
        Ed25519Signer(key)


@pytest.mark.parametrize("public", [b"", b"x" * 31, "text", None, 5])
def test_a_malformed_public_key_is_false_not_an_exception(public):
    record = signed_run(Ed25519Signer(generate_ed25519_keypair()[0]))
    assert verify_ed25519(record, public) is False


def test_hostile_signatures_are_false_not_exceptions():
    private, public = generate_ed25519_keypair()
    record = signed_run(Ed25519Signer(private))
    for bad in ("ed25519:", "ed25519:zz", "ed25519:" + "00" * 64, "hmac-sha256:ab", 5, None, "é"):
        tampered = dict(record, signature=bad)
        assert verify_ed25519(tampered, public) is False


def test_an_hmac_record_is_not_accepted_as_ed25519_and_vice_versa():
    private, public = generate_ed25519_keypair()
    key = b"hmac-key-0123456789abcdef0123"
    hmac_record = Kelvra(parse(POLICY), signing_key=key).record()
    assert not verify_ed25519(hmac_record, public)
    ed_record = signed_run(Ed25519Signer(private))
    assert not verify(ed_record, key)


def test_asking_for_both_kinds_of_check_at_once_is_refused():
    private, public = generate_ed25519_keypair()
    record = signed_run(Ed25519Signer(private))
    result = verify_record(record, b"k" * 32, public_key=public)
    assert not result.ok and any("not both" in p for p in result.problems)


def test_the_structure_checks_still_apply_under_a_valid_signature():
    private, public = generate_ed25519_keypair()
    signer = Ed25519Signer(private)
    record = signed_run(signer)
    record["summary"]["denied"] = 0
    record["signature"] = signer.sign(record)  # the signer is honest about a lying record
    assert not verify_ed25519(record, public)


def test_a_session_takes_a_key_or_a_signer_not_both():
    with pytest.raises(ValueError, match="not both"):
        Kelvra(
            parse(POLICY),
            signer=Ed25519Signer(generate_ed25519_keypair()[0]),
            signing_key=b"k" * 32,
        )


def test_a_signer_makes_the_unsigned_warning_go_away():
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Kelvra(parse(POLICY), signer=Ed25519Signer(generate_ed25519_keypair()[0])).record()


def test_the_journal_rebuilds_a_record_a_public_key_can_check(tmp_path):
    """Journal and signature together: a record an outsider can verify after a restart."""
    from kelvra import journal_to_record

    private, public = generate_ed25519_keypair()
    signer = Ed25519Signer(private)
    k = Kelvra(parse(POLICY), signer=signer, journal_path=tmp_path / "run.jsonl")
    k.emit("out", k.read("s_a", "x"))
    live = k.record()
    rebuilt = journal_to_record(tmp_path / "run.jsonl")
    rebuilt["signature"] = signer.sign(rebuilt)
    assert rebuilt == live and verify_ed25519(rebuilt, public)
