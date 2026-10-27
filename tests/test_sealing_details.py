"""The sealing construction, checked against its own description and at its edges.

Mutation testing of ``sealing.py`` (337 mutants, 94 survivors after ``test_sealing.py``) showed a
suite that proved a token *round-trips* and that tampering is refused, but never that the
construction is the one documented. A round trip passes for any key derivation. So this file does
what a second implementation would do: open a token with ``cryptography`` alone, following
spec/sealing-cryptographic-design.md, and let the code under test be the thing that is checked.

It also pins each way a token can be refused to its own message, because the messages are the
only thing an operator has to tell a forged token from a mangled one.
"""

from __future__ import annotations

import base64
import builtins
import copy
import json
import pickle

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hypothesis import given, settings
from hypothesis import strategies as st

import kelvra.sealing as sealing
from kelvra import Label, PrincipalSet, SealError
from kelvra.sealing import MAX_PLAINTEXT_BYTES, TOKEN, MasterKey, Sealer, _label_from_json

KEY = bytes(range(10, 42))
FINGERPRINT = "sha256:" + "5a" * 32
RUN = "11111111-2222-4333-8444-555555555555"


def sealer() -> Sealer:
    return Sealer(MasterKey(KEY), FINGERPRINT, RUN)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def label_text(label: Label) -> bytes:
    return json.dumps(label.to_json(), sort_keys=True, separators=(",", ":")).encode()


# -- the construction, re-implemented from its description -------------------------------------


def independent_open(token: str) -> tuple[str, Label]:
    """Open a token with nothing of Kelvra's but the documented format."""
    kind, kid, label_part, body_part = TOKEN.fullmatch(token).groups()
    scope = b"|" + FINGERPRINT.encode()
    derived = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"kelvra/seal/v1/aes-256-gcm" + scope
    ).derive(KEY)
    expected_kid = HKDF(
        algorithm=hashes.SHA256(), length=4, salt=None, info=b"kelvra/seal/v1/key-id" + scope
    ).derive(KEY)
    assert kid == expected_kid.hex()
    label_bytes = base64.urlsafe_b64decode(label_part + "=" * (-len(label_part) % 4))
    body = base64.urlsafe_b64decode(body_part + "=" * (-len(body_part) % 4))
    aad = b"\0".join(
        [b"kelvra-seal-v1", RUN.encode(), FINGERPRINT.encode(), kind.encode(), label_bytes]
    )
    framed = AESGCM(derived).decrypt(body[:12], body[12:], aad)
    length = int.from_bytes(framed[:4], "big")
    assert framed[4 + length :] == bytes(len(framed) - 4 - length)  # padding is zeros
    assert len(framed) % 64 == 0
    data = json.loads(label_bytes)
    readers = (
        PrincipalSet.all()
        if data["readers"] == "*"
        else PrincipalSet.from_iterable(data["readers"])
    )
    return framed[4 : 4 + length].decode(), (readers, data)


def test_a_token_opens_with_the_documented_construction_and_nothing_else():
    label = Label(
        PrincipalSet.of("customer"), PrincipalSet.of("reviewer"), PrincipalSet.of("support")
    )
    token = sealer().seal("FR76 canary", "iban", label)
    plaintext, (readers, data) = independent_open(token)
    assert plaintext == "FR76 canary"
    assert readers == PrincipalSet.of("customer")
    assert data == {"endorsers": ["reviewer"], "purposes": ["support"], "readers": ["customer"]}


def test_a_token_sealed_independently_is_opened_by_the_code_under_test():
    scope = b"|" + FINGERPRINT.encode()
    derived = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"kelvra/seal/v1/aes-256-gcm" + scope
    ).derive(KEY)
    kid = (
        HKDF(algorithm=hashes.SHA256(), length=4, salt=None, info=b"kelvra/seal/v1/key-id" + scope)
        .derive(KEY)
        .hex()
    )
    label = Label(PrincipalSet.of("a", "b"), PrincipalSet.all(), PrincipalSet.all())
    label_bytes = label_text(label)
    data = b"hand made"
    framed = len(data).to_bytes(4, "big") + data
    framed += bytes(-len(framed) % 64)
    nonce = bytes(range(12))
    aad = b"\0".join([b"kelvra-seal-v1", RUN.encode(), FINGERPRINT.encode(), b"note", label_bytes])
    body = nonce + AESGCM(derived).encrypt(nonce, framed, aad)
    token = f"kelvra-seal.v1.note.{kid}.{b64(label_bytes)}.{b64(body)}"
    assert sealer().unseal(token) == ("hand made", label, "note")


def test_different_policies_runs_and_keys_give_different_key_ids_and_different_keys():
    base = sealer().key_id
    assert Sealer(MasterKey(KEY), "sha256:" + "5b" * 32, RUN).key_id != base
    assert Sealer(MasterKey(bytes(reversed(KEY))), FINGERPRINT, RUN).key_id != base
    assert Sealer(MasterKey(KEY), FINGERPRINT, "another-run").key_id == base  # run is not in the id
    assert len(base) == 8 and int(base, 16) >= 0


def test_the_key_id_is_not_derived_from_the_encryption_key():
    kid_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"kelvra/seal/v1/key-id|" + FINGERPRINT.encode(),
    ).derive(KEY)
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"kelvra/seal/v1/aes-256-gcm|" + FINGERPRINT.encode(),
    ).derive(KEY)
    assert kid_key != enc_key and sealer().key_id == kid_key[:4].hex()


@given(
    text=st.text(max_size=200),
    purposes=st.lists(st.sampled_from(["support", "billing"]), unique=True, max_size=2),
    endorsers=st.lists(st.sampled_from(["reviewer", "lead"]), unique=True, max_size=2),
    everyone=st.booleans(),
)
@settings(max_examples=120, deadline=None)
def test_every_part_of_the_label_survives_the_round_trip(text, purposes, endorsers, everyone):
    label = Label(
        PrincipalSet.all() if everyone else PrincipalSet.of("customer"),
        PrincipalSet.from_iterable(endorsers),
        PrincipalSet.from_iterable(purposes),
    )
    assert sealer().unseal(sealer().seal(text, "note", label))[1:] == (label, "note")


# -- the edges ---------------------------------------------------------------------------------


def test_the_longest_allowed_value_seals_and_one_byte_more_does_not():
    longest = "x" * MAX_PLAINTEXT_BYTES
    assert sealer().unseal(sealer().seal(longest, "note", Label()))[0] == longest
    with pytest.raises(
        SealError, match=rf"^a sealed value is at most {MAX_PLAINTEXT_BYTES} bytes$"
    ):
        sealer().seal(longest + "x", "note", Label())
    multibyte = "\u00e9" * (MAX_PLAINTEXT_BYTES // 2)  # 2 bytes each: counts bytes, not characters
    assert len(multibyte.encode()) == MAX_PLAINTEXT_BYTES
    assert sealer().unseal(sealer().seal(multibyte, "note", Label()))[0] == multibyte
    with pytest.raises(SealError):
        sealer().seal(multibyte + "\u00e9", "note", Label())


@pytest.mark.parametrize("size", [0, 1, 59, 60, 61, 123, 124, 125, 4095, 4096])
def test_values_at_and_around_every_padding_boundary_come_back_exactly(size):
    s = sealer()
    text = "y" * size
    assert s.unseal(s.seal(text, "note", Label()))[0] == text


def test_the_empty_string_is_a_value_like_any_other():
    s = sealer()
    assert s.unseal(s.seal("", "note", Label()))[0] == ""


# -- every way a token is refused has its own words --------------------------------------------


def craft(
    framed: bytes | None = None, *, kind="note", label=None, kid=None, body=None, label_part=None
):
    """A token with a damaged inner structure that the real key still authenticates."""
    s = sealer()
    label_bytes = label_text(label or Label())
    if body is None:
        nonce = bytes(range(12))
        body = nonce + s._aead.encrypt(nonce, framed, s._aad(kind, label_bytes))
    return f"kelvra-seal.v1.{kind}.{kid or s.key_id}.{label_part or b64(label_bytes)}.{b64(body)}"


def refusal(token) -> str:
    with pytest.raises(SealError) as excinfo:
        sealer().unseal(token)
    return str(excinfo.value)


def test_each_way_a_token_is_refused_says_which_kind_of_wrong_it_is():
    good = sealer().seal("v", "note", Label())
    assert refusal(5) == "malformed sealed token"
    assert refusal(None) == "malformed sealed token"
    assert refusal(good + "x" * 20000) == "malformed sealed token"  # beyond any possible token
    assert refusal("not a token") == "malformed sealed token"
    assert refusal(craft(b"\x00" * 64, kid="00000000")) == "sealed under a different key or policy"
    assert (
        refusal(craft(b"\x00" * 64, label_part="A" * 5)) == "malformed sealed token"
    )  # not base64
    assert refusal(craft(b"\x00" * 64, label_part=b64(b"\xff\xfe"))) == "malformed sealed token"
    assert refusal(craft(b"\x00" * 64, label_part=b64(b"not json"))) == "malformed sealed token"
    assert refusal(craft(b"\x00" * 64, label_part=b64(b"[]"))) == "malformed sealed token"
    spaced = b'{"endorsers": "*", "purposes": "*", "readers": "*"}'  # right content, not canonical
    assert refusal(craft(b"\x00" * 64, label_part=b64(spaced))) == "malformed sealed token"
    assert refusal(craft(body=bytes(27))) == "malformed sealed token"  # shorter than nonce + tag
    assert refusal(craft(body=bytes(28))) == "sealed token failed authentication"  # long enough
    assert refusal(craft(body=bytes(40))) == "sealed token failed authentication"


def test_a_token_whose_inner_length_is_wrong_or_not_text_is_refused_even_though_it_authenticates():
    bad_length = (5000).to_bytes(4, "big") + b"abc" + bytes(57)
    assert refusal(craft(bad_length)) == "sealed token failed authentication"
    exact = (60).to_bytes(4, "big") + b"z" * 60 + bytes(60)  # length may be as large as the frame
    assert sealer().unseal(craft(exact))[0] == "z" * 60
    just_over = (61).to_bytes(4, "big") + b"z" * 60
    assert (
        refusal(craft(just_over + bytes(-len(just_over) % 64)))
        == "sealed token failed authentication"
    )
    not_utf8 = (2).to_bytes(4, "big") + b"\xff\xfe" + bytes(58)
    assert refusal(craft(not_utf8)) == "sealed token failed authentication"


def test_sealing_refuses_with_a_message_that_says_what_to_change():
    s = sealer()
    with pytest.raises(SealError, match=r"^only text can be sealed, not int$"):
        s.seal(5, "note", Label())
    with pytest.raises(SealError, match=r"^only text can be sealed, not bytes$"):
        s.seal(b"x", "note", Label())
    for kind in ("", "Note", "1note", "a b", "a" * 25, "a-b", "\u00e9"):
        with pytest.raises(SealError, match=r"^a kind is 1 to 24 characters: a lowercase letter"):
            s.seal("v", kind, Label())
    s.seal("v", "a" * 24, Label())  # exactly the limit


def test_a_sealer_wants_a_master_key_and_says_so():
    with pytest.raises(TypeError, match=r"^a Sealer needs a MasterKey$"):
        Sealer(KEY, FINGERPRINT, RUN)


def test_the_seal_cap_message_and_the_count_it_applies_at(monkeypatch):
    s = sealer()
    monkeypatch.setattr(sealing, "MAX_SEALS_PER_KEY", 2)
    s.seal("a", "note", Label())
    s.seal("b", "note", Label())
    with pytest.raises(
        SealError, match=r"^this key has sealed as much as one key should; rotate it$"
    ):
        s.seal("c", "note", Label())


# -- label decoding is strict ------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "x",
        {},
        {"readers": "*", "endorsers": "*"},
        {"readers": "*", "endorsers": "*", "purposes": "*", "extra": 1},
        {"readers": "x", "endorsers": "*", "purposes": "*"},
        {"readers": ["*"], "endorsers": "*", "purposes": "*"},
        {"readers": [""], "endorsers": "*", "purposes": "*"},
        {"readers": [1], "endorsers": "*", "purposes": "*"},
        {"readers": ["a", 1], "endorsers": "*", "purposes": "*"},
        {"readers": ["a", None], "endorsers": "*", "purposes": "*"},
        {"readers": ["a", "*"], "endorsers": "*", "purposes": "*"},
        {"readers": ["a", ""], "endorsers": "*", "purposes": "*"},
        {"readers": "*", "endorsers": 5, "purposes": "*"},
        {"readers": "*", "endorsers": "*", "purposes": {"a": 1}},
        {"readers": "*", "endorsers": "*", "purposes": [["a"]]},
    ],
)
def test_a_label_that_is_not_exactly_a_label_is_refused(bad):
    with pytest.raises(SealError, match=r"^malformed sealed token$"):
        _label_from_json(bad)


def test_a_well_formed_label_is_decoded_in_all_three_parts():
    label = _label_from_json({"readers": ["a"], "endorsers": [], "purposes": "*"})
    assert label == Label(PrincipalSet.of("a"), PrincipalSet.none(), PrincipalSet.all())
    both = _label_from_json({"readers": "*", "endorsers": ["r"], "purposes": ["p", "q"]})
    assert both == Label(PrincipalSet.all(), PrincipalSet.of("r"), PrincipalSet.of("p", "q"))


# -- text around tokens ------------------------------------------------------------------------


def test_text_that_mentions_the_prefix_without_being_a_token_is_refused_whole():
    s = sealer()
    good = s.seal("v", "note", Label())
    for text in (
        "kelvra-seal.",
        f"{good} and kelvra-seal.v1.",
        "see kelvra-seal.v1.note.deadbeef",
        f"{good[:30]}",
    ):
        with pytest.raises(SealError, match=r"^malformed sealed token$"):
            s.resolve(text, lambda labels: None)


def test_resolve_asks_once_with_every_original_label_and_replaces_in_order():
    s = sealer()
    a = s.seal("AAA", "note", Label.confidential("x"))
    b = s.seal("BBB", "note", Label.confidential("y"))
    asked = []
    text, labels = s.resolve(f"1 {a} 2 {b} 3 {a}", lambda ls: asked.append(list(ls)))
    assert text == "1 AAA 2 BBB 3 AAA"
    assert len(asked) == 1 and len(asked[0]) == 3
    assert labels == [Label.confidential("x"), Label.confidential("y"), Label.confidential("x")]
    assert s.resolve("no tokens", lambda ls: asked.append(ls))[0] == "no tokens"
    assert asked[-1] == []


def test_a_refusal_by_the_decision_leaves_no_partial_text():
    s = sealer()
    token = s.seal("SECRET", "note", Label())

    def refuse(labels):
        raise PermissionError("no")

    with pytest.raises(PermissionError):
        s.resolve(f"before {token} after", refuse)


# -- the master key, exactly -------------------------------------------------------------------


def test_a_generated_key_is_32_bytes_and_never_the_same_twice():
    first, second = MasterKey.generate(), MasterKey.generate()
    assert len(first._key) == 32 and len(second._key) == 32
    assert first._key != second._key


def test_the_key_says_exactly_what_it_refuses_to_do():
    key = MasterKey(KEY)
    for action in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError, match=r"^a MasterKey cannot be pickled or copied$"):
            action(key)
    with pytest.raises(TypeError, match=r"^a MasterKey cannot be pickled or copied$"):
        key.__getstate__()
    with pytest.raises(TypeError, match=r"^a master key is bytes, not list$"):
        MasterKey([1, 2, 3])
    with pytest.raises(ValueError, match=r"^a master key is at least 32 bytes; got 31$"):
        MasterKey(bytes(31))
    MasterKey(bytearray(32))  # a bytearray is bytes enough
    assert MasterKey(bytes(33)).derive(b"p") != MasterKey(bytes(32)).derive(b"p")


def test_derivation_depends_on_the_purpose_the_length_and_the_key_and_nothing_else():
    key = MasterKey(KEY)
    expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"p").derive(KEY)
    assert key.derive(b"p") == expected
    assert key.derive(b"p", 16) == HKDF(
        algorithm=hashes.SHA256(), length=16, salt=None, info=b"p"
    ).derive(KEY)
    # HKDF-Expand output is a prefix of a longer one: asking for fewer bytes truncates
    assert key.derive(b"p", 16) == key.derive(b"p")[:16]


def test_the_environment_key_reads_the_variable_it_is_told_to(monkeypatch):
    monkeypatch.setenv("ANOTHER_VARIABLE", KEY.hex())
    monkeypatch.delenv("KELVRA_MASTER_KEY", raising=False)
    assert MasterKey.from_hex_env() is None
    assert MasterKey.from_hex_env("ANOTHER_VARIABLE").derive(b"p") == MasterKey(KEY).derive(b"p")
    monkeypatch.setenv("ANOTHER_VARIABLE", "  " + KEY.hex() + " \n")
    assert MasterKey.from_hex_env("ANOTHER_VARIABLE").derive(b"p") == MasterKey(KEY).derive(b"p")
    monkeypatch.setenv("ANOTHER_VARIABLE", "nothex")
    with pytest.raises(
        ValueError, match=r"^\$ANOTHER_VARIABLE is not a hex-encoded key of at least 32 bytes$"
    ):
        MasterKey.from_hex_env("ANOTHER_VARIABLE")


def test_without_the_cryptography_package_the_error_says_how_to_get_it(monkeypatch):
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("no cryptography here")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    with pytest.raises(
        SealError, match=r"^sealing needs the 'cryptography' package: pip install 'kelvra\[seal\]'$"
    ):
        sealing._crypto()
