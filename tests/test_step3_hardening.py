"""Unforgeable values, key hygiene, ``from`` tracing, portability and documentation."""

import itertools
import random
import re
import warnings
from pathlib import Path

import pytest

from kelvra import (
    PUBLIC,
    Declassifier,
    Kelvra,
    KlvError,
    Label,
    Policy,
    PrincipalSet,
    Sink,
    Source,
    Tainted,
    UnsignedRecordWarning,
    check_flow,
    join_all,
    parse,
)
from kelvra.analysis import analyse
from kelvra.cli import main

ROOT = Path(__file__).resolve().parents[1]

POLICY = """\
policy P
principal customer, support_team, billing
source crm
    confidential(customer)
    integrity trusted
source finance
    confidential(billing)
    integrity trusted
sink slack
    accepts confidential(support_team)
sink pub
    accepts public
declassify pii_redaction
    from confidential(customer)
    to   confidential(support_team)
declassify anything
    to confidential(support_team)
"""


# -- values cannot be forged ------------------------------------------------


def test_a_tainted_cannot_be_constructed_by_hand():
    with pytest.raises(TypeError, match="issued by a Kelvra session"):
        Tainted("secret", PUBLIC, "x")


def test_the_mint_cannot_be_guessed_from_the_keyword_arguments():
    with pytest.raises(TypeError):
        Tainted("secret", PUBLIC, "x", _mint=object(), _issuer=object())


def test_dataclasses_replace_cannot_relabel_a_value():
    import dataclasses

    k = Kelvra(parse(POLICY))
    t = k.read("crm", "x")
    with pytest.raises(TypeError):
        dataclasses.replace(t, label=PUBLIC)  # not a dataclass any more


def test_a_tainted_is_immutable():
    t = Kelvra(parse(POLICY)).read("crm", "x")
    for attribute in ("label", "origin", "_value", "_issuer"):
        with pytest.raises(AttributeError):
            setattr(t, attribute, PUBLIC)
    with pytest.raises(AttributeError):
        del t.label


def test_the_payload_has_one_public_name():
    t = Kelvra(parse(POLICY)).read("crm", "x")
    assert [n for n in dir(t) if "value" in n and not n.startswith("_")] == ["unsafe_value"]
    assert t.unsafe_value == "x"


def test_a_value_from_another_session_is_refused_everywhere():
    pol = parse(POLICY)
    foreign = Kelvra(pol).read("crm", "x")
    k = Kelvra(pol)
    for action in (
        lambda: k.emit("slack", foreign),
        lambda: k.model_call("m", foreign),
        lambda: k.combine("c", foreign),
        lambda: k.declassify("pii_redaction", foreign),
        lambda: k.would_allow("slack", foreign),
    ):
        with pytest.raises(TypeError, match="not issued by this session"):
            action()


def test_a_raw_value_is_refused_rather_than_crashing_obscurely():
    k = Kelvra(parse(POLICY))
    with pytest.raises(TypeError, match="not issued by this session"):
        k.emit("pub", "just a string")


def test_a_refused_foreign_value_leaves_no_event():
    pol = parse(POLICY)
    foreign = Kelvra(pol).read("crm", "x")
    k = Kelvra(pol)
    with pytest.raises(TypeError):
        k.emit("pub", foreign)
    assert k.ledger.events == ()


def test_map_keeps_the_label_and_the_issuer():
    k = Kelvra(parse(POLICY))
    t = k.read("crm", "x")
    mapped = t.map(str.upper)
    assert mapped.label == t.label and mapped.unsafe_value == "X"
    assert not k.would_allow("pub", mapped)


def test_declassify_and_model_call_results_are_accepted_by_their_own_session():
    k = Kelvra(parse(POLICY))
    out = k.declassify("pii_redaction", k.model_call("m", k.read("crm", "x")))
    assert k.emit("slack", out) == ("x",)


def test_principal_sets_refuse_the_universe_marker_as_a_name():
    for build in (
        lambda: PrincipalSet.of("*"),
        lambda: PrincipalSet.from_iterable(["a", "*"]),
        lambda: PrincipalSet(frozenset({"*"})),
        lambda: PrincipalSet.of(""),
    ):
        with pytest.raises(ValueError):
            build()
    assert PrincipalSet.all() != PrincipalSet.of("a")


# -- signing keys -----------------------------------------------------------


@pytest.mark.parametrize("key", ["a-string-key-long-enough", 12345, object()])
def test_a_key_that_is_not_bytes_is_refused_at_the_start(key):
    with pytest.raises(TypeError):
        Kelvra(parse(POLICY), signing_key=key)


@pytest.mark.parametrize("key", [b"", b"a", b"x" * 15])
def test_a_short_key_is_refused_at_the_start(key):
    with pytest.raises(ValueError, match="at least 16"):
        Kelvra(parse(POLICY), signing_key=key)


def test_the_smallest_accepted_key_signs():
    k = Kelvra(parse(POLICY), signing_key=b"x" * 16)
    assert k.record()["signature"].startswith("hmac-sha256:")


def test_a_short_key_in_the_environment_is_refused_not_silently_ignored(monkeypatch):
    monkeypatch.setenv("KELVRA_SIGNING_KEY", "short")
    with pytest.raises(ValueError, match="KELVRA_SIGNING_KEY"):
        Kelvra(parse(POLICY))


def test_a_good_key_in_the_environment_signs(monkeypatch):
    monkeypatch.setenv("KELVRA_SIGNING_KEY", "e" * 32)
    assert "signature" in Kelvra(parse(POLICY)).record()


def test_an_unsigned_record_says_so(monkeypatch):
    monkeypatch.delenv("KELVRA_SIGNING_KEY", raising=False)
    with pytest.warns(UnsignedRecordWarning, match="unsigned"):
        record = Kelvra(parse(POLICY)).record()
    assert "signature" not in record


def test_a_signed_record_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Kelvra(parse(POLICY), signing_key=b"x" * 32).record()


# -- `from` is read, and its use is recorded --------------------------------


def _declassified(name, source):
    k = Kelvra(parse(POLICY))
    k.declassify(name, k.read(source, "x"))
    return k.ledger.of_kind("declassify")[0].detail["from_check"]


def test_use_within_from_is_recorded_as_within():
    assert _declassified("pii_redaction", "crm") == "within"


def test_use_outside_from_is_recorded_as_outside_and_not_refused():
    assert _declassified("pii_redaction", "finance") == "outside"


def test_a_declassifier_without_from_is_recorded_as_undeclared():
    assert _declassified("anything", "crm") == "undeclared"


@pytest.mark.parametrize(
    "clause,label,expected",
    [
        ("untrusted", Label.confidential("a").untrusted(), "within"),
        ("untrusted", Label.confidential("a"), "outside"),
        ("public", Label.confidential("a"), "within"),
        ("endorsed(rev)", Label.confidential("a").endorsed_by("rev"), "within"),
        ("endorsed(rev)", Label.confidential("a"), "outside"),
        ("confidential(a, b)", Label.confidential("a"), "within"),
        ("confidential(a, b)", Label.confidential("c"), "outside"),
    ],
)
def test_every_from_form_has_a_meaning(clause, label, expected):
    src = (
        "policy P\nprincipal a, b, c, rev\nsource s\n    public\n    integrity trusted\n"
        f"declassify d\n    from {clause}\n    to confidential(a)\n"
    )
    assert parse(src).declassifiers["d"].matches_from(label) == expected


def test_two_from_lines_combine_as_a_conjunction():
    src = (
        "policy P\nprincipal a, rev\nsource s\n    public\n    integrity trusted\n"
        "declassify d\n    from confidential(a)\n    from untrusted\n    to confidential(a)\n"
    )
    d = parse(src).declassifiers["d"]
    assert d.matches_from(Label.confidential("a").untrusted()) == "within"
    assert d.matches_from(Label.confidential("a")) == "outside"


def test_from_with_an_undeclared_principal_is_now_an_error():
    src = "policy P\nprincipal a\nsource s\n    public\n    integrity trusted\n"
    with pytest.raises(KlvError, match="not declared"):
        parse(src + "declassify d\n    from confidential(typo)\n    to confidential(a)\n")


def test_from_with_garbage_is_an_error():
    src = "policy P\nprincipal a\nsource s\n    public\n    integrity trusted\n"
    with pytest.raises(KlvError, match="'from' takes"):
        parse(src + "declassify d\n    from whatever\n    to confidential(a)\n")


def test_from_is_part_of_the_fingerprint():
    a = parse(POLICY).fingerprint()
    assert parse(POLICY.replace("from confidential(customer)", "from untrusted")).fingerprint() != a


# -- the integrity default ----------------------------------------------------


def test_a_source_without_integrity_warns():
    from kelvra.klv import parse_with_warnings

    _, warns = parse_with_warnings("policy P\nprincipal a\nsource s\n    confidential(a)\n")
    assert any("defaults to trusted" in w for w in warns)


def test_a_source_with_explicit_integrity_does_not_warn_about_it():
    from kelvra.klv import parse_with_warnings

    _, warns = parse_with_warnings(
        "policy P\nprincipal a\nsource s\n    confidential(a)\n    integrity trusted\n"
    )
    assert not any("integrity" in w for w in warns)


# -- the command line ---------------------------------------------------------


def test_json_is_an_array_for_one_file_and_for_several(tmp_path, capsys):
    """It used to be an object for one file; a pipeline should not have to branch on the count."""
    import json

    a, b = tmp_path / "a.klv", tmp_path / "b.klv"
    a.write_text(POLICY, encoding="utf-8")
    b.write_text(POLICY, encoding="utf-8")
    main(["check", "--json", str(a)])
    assert [r["file"] for r in json.loads(capsys.readouterr().out)] == [str(a)]
    main(["check", "--json", str(a), str(b)])
    assert [r["file"] for r in json.loads(capsys.readouterr().out)] == [str(a), str(b)]


def test_a_file_with_crlf_line_endings_gives_the_same_policy(tmp_path):
    lf = tmp_path / "lf.klv"
    crlf = tmp_path / "crlf.klv"
    lf.write_bytes(POLICY.encode())
    crlf.write_bytes(POLICY.replace("\n", "\r\n").encode())
    from kelvra import parse_file

    assert parse_file(lf).fingerprint() == parse_file(crlf).fingerprint()


def test_every_shipped_policy_checks_clean_of_errors():
    for path in ROOT.rglob("*.klv"):
        assert main(["check", "--no-colour", str(path)]) == 0, path


# -- the reachability finding really is definite ------------------------------


def _random_policy(rng) -> Policy:
    names = ["a", "b", "c"]
    pol = Policy(name="R")

    def pset():
        if rng.random() < 0.2:
            return PrincipalSet.all()
        return PrincipalSet.from_iterable(rng.sample(names, rng.randint(0, 3)))

    for i in range(3):
        endorsers = rng.choice([PrincipalSet.all(), PrincipalSet.none()])
        pol.add_source(Source(f"s{i}", Label(pset(), endorsers, pset())))
    for i in range(3):
        pol.add_sink(
            Sink(
                f"k{i}",
                audience=pset(),
                requires_endorsement=PrincipalSet.none(),
                purpose=rng.choice([None, "a", "b"]),
            )
        )
    for i in range(3):
        pol.add_declassifier(
            Declassifier(f"d{i}", grants_readers=rng.choice([PrincipalSet.none(), pset()]))
        )
    return pol


def _reachable_by(pol: Policy, source: Source, sink: Sink) -> bool:
    decs = list(pol.declassifiers.values())
    for count in range(len(decs) + 1):
        for order in itertools.permutations(decs, count):
            label = source.label
            for d in order:
                label = d.apply(label)
            if check_flow(label, sink).allowed:
                return True
    return False


def test_untrusted_reaches_sink_names_only_sources_that_really_reach_it():
    """Every source the finding names has an execution that reaches the sink.

    The finding says "reachable"; the specification forbids claiming that of a
    sink, so check it: for a single source and the declassifiers in any order
    (consent set aside), the claim must be true, and no source that does reach
    the sink may be left out.
    """
    rng = random.Random(11)
    seen = 0
    for _ in range(300):
        pol = _random_policy(rng)
        for finding in analyse(pol):
            if finding.code != "untrusted-reaches-sink":
                continue
            seen += 1
            sink = pol.sinks[re.search(r"'([^']+)'", finding.subject).group(1)]
            named = set(re.findall(r"'(s\d)'", finding.message))
            expected = {
                s.name
                for s in pol.sources.values()
                if s.label.is_untrusted and _reachable_by(pol, s, sink)
            }
            assert named == expected
    assert seen > 20, "the generator never produced the finding"


def test_joining_never_helps_reachability():
    """Why a single source is enough: a join only restricts (spec/labels.md section 3)."""
    rng = random.Random(3)
    for _ in range(300):
        pol = _random_policy(rng)
        sources = list(pol.sources.values())
        sink = next(iter(pol.sinks.values()))
        joined = join_all(s.label for s in sources)
        best_single = any(check_flow(s.label, sink).allowed for s in sources)
        if check_flow(joined, sink).allowed:
            assert best_single


# -- documentation says what the code does ------------------------------------


def _readme_policy() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return re.search(r"```kelvra\n(.*?)```", readme, re.S).group(1)


def test_the_readme_policy_parses_and_is_the_example():
    shown = parse(_readme_policy())
    shipped = parse((ROOT / "examples/support_agent/policy.klv").read_text(encoding="utf-8"))
    assert shown.fingerprint() == shipped.fingerprint()


def test_the_readme_policy_has_no_errors():
    assert not [f for f in analyse(parse(_readme_policy())) if f.severity == "error"]


@pytest.mark.parametrize("name", ["SECURITY.md", "LIMITATIONS.md", "README.md"])
def test_documents_do_not_deny_the_code_they_ship_with(name):
    text = (ROOT / name).read_text(encoding="utf-8").lower()
    assert "there is no code" not in text
    assert "there is no implementation" not in text
    assert "not one line of working code" not in text


def test_no_text_file_depends_on_the_platform_default_encoding():
    """open()/read_text() without encoding= reads cp1252 on Windows."""
    offenders = []
    pattern = re.compile(r"\.read_text\(\s*\)|\.write_text\([^,()]*\)|(?<![.\w])open\([^)]*\)")
    for base in ("src", "tests", "examples", "evaluation"):
        for path in (ROOT / base).rglob("*.py"):
            if path.name == Path(__file__).name:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line) and "encoding" not in line and 'b"' not in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, offenders


def _invisible_characters() -> set[str]:
    """Line/paragraph separators, zero-width and bidirectional controls, and the BOM.

    Built from code points, not typed, so this file contains none of them either.
    """
    code_points = [0x2028, 0x2029, *range(0x200B, 0x2010), *range(0x202A, 0x202F)]
    code_points += [*range(0x2060, 0x206A), 0xFEFF]
    return {chr(c) for c in code_points}


def test_no_python_source_contains_an_invisible_or_bidirectional_character():
    """The rule the .klv parser enforces on policies, applied to this project's own code.

    A string such as "\\ufeff" written as the character itself is invisible in a
    diff and in review, which is the failure the parser exists to reject. Escapes
    only. (The obfuscated corpus under evaluation/corpus is data, not code.)
    """
    forbidden = _invisible_characters()
    offenders = []
    for base in ("src", "tests", "examples", "evaluation"):
        for path in (ROOT / base).rglob("*.py"):
            if any(ch in forbidden for ch in path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, offenders
