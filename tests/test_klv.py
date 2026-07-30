"""The .klv parser, against spec/policy-language.md.

Section 4 of that document promises a specific diagnostic for each malformed
case. Those promises are the language's main value -- for Kelvra the errors
are the product, not a convenience -- so there is one test per promise, and
each asserts on the message rather than just on the exception type.
"""

import textwrap
from pathlib import Path

import pytest

from kelvra import PrincipalSet
from kelvra.klv import KlvError, parse, parse_file, parse_with_warnings

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "support_agent" / "policy.klv"

MINIMAL = """
policy Minimal
principal alice
source s
    confidential(alice)
sink out
    accepts confidential(alice)
"""


def klv(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def fails(body: str) -> KlvError:
    with pytest.raises(KlvError) as excinfo:
        parse(klv(body))
    return excinfo.value


# -- the example ------------------------------------------------------------


def test_the_example_policy_parses():
    policy = parse_file(EXAMPLE)
    assert policy.name == "SupportAgent"
    assert policy.version == 1
    assert set(policy.sources) == {"inbox.imap", "crm.customer_record"}
    assert set(policy.sinks) == {"llm.openai", "slack.support_channel", "crm.write"}
    assert set(policy.declassifiers) == {"pii_redaction", "human_review", "share_with_model"}


def test_the_example_policy_is_clean():
    """No warnings. The flagship example should not model bad practice."""
    _, warnings = parse_with_warnings(EXAMPLE.read_text(encoding="utf-8"))
    assert warnings == []


def test_the_example_is_what_the_demo_actually_runs():
    """demo.py parses this file rather than rebuilding it in Python."""
    source = (EXAMPLE.parent / "demo.py").read_text(encoding="utf-8")
    assert "parse_file" in source
    assert "policy.klv" in source


# -- semantics --------------------------------------------------------------


def test_labels_map_as_the_spec_says():
    policy = parse_file(EXAMPLE)

    inbox = policy.sources["inbox.imap"].label
    assert inbox.readers == PrincipalSet.of("customer")
    assert inbox.is_untrusted
    assert "support" in inbox.purposes

    crm = policy.sources["crm.customer_record"].label
    assert not crm.is_untrusted, "'integrity trusted' means endorsed by everyone"


def test_sink_clauses_map_as_the_spec_says():
    sinks = parse_file(EXAMPLE).sinks

    # The model provider is a named principal, not the world: sending data to
    # it is a sharing decision, and the policy says who is being shared with.
    assert sinks["llm.openai"].audience == PrincipalSet.of("model_provider")
    assert sinks["slack.support_channel"].audience == PrincipalSet.of("support_team")

    crm = sinks["crm.write"]
    assert crm.requires_endorsement == PrincipalSet.of("reviewer")
    assert crm.requires_consent_from == "customer"


def test_declassify_grants_readers_and_endorse_grants_endorsement():
    d = parse_file(EXAMPLE).declassifiers
    assert d["pii_redaction"].grants_readers == PrincipalSet.of("customer", "support_team")
    assert d["pii_redaction"].grants_endorsement.is_empty
    assert d["human_review"].grants_endorsement == PrincipalSet.of("reviewer")
    assert d["human_review"].grants_readers.is_empty


def test_version_defaults_to_one():
    assert parse(klv(MINIMAL)).version == 1


def test_multiple_requires_clauses_accumulate():
    policy = parse(
        klv("""
        policy Acc
        principal a, b, c
        source s
            confidential(a)
        sink out
            accepts confidential(a)
            requires endorsed(b)
            requires endorsed(c)
        """)
    )
    assert policy.sinks["out"].requires_endorsement == PrincipalSet.of("b", "c")


def test_comments_and_blank_lines_are_ignored_anywhere():
    policy = parse(
        klv("""
        # leading comment
        policy Commented

        principal alice   # trailing comment

        source s
            # comment inside a block

            confidential(alice)
        sink out
            accepts public
        """)
    )
    assert policy.name == "Commented"
    assert policy.sinks["out"].audience.is_all


def test_indent_width_is_not_prescribed():
    two = parse(klv("""
        policy W
        principal a
        source s
          confidential(a)
        sink o
          accepts public
        """))
    eight = parse(klv("""
        policy W
        principal a
        source s
                confidential(a)
        sink o
                accepts public
        """))
    assert two.fingerprint() == eight.fingerprint()


# -- diagnostics, one per promise in spec/policy-language.md section 4 -------


def test_undeclared_principal():
    error = fails("""
        policy P
        principal alice
        source s
            confidential(bob)
        """)
    assert "bob" in error.message and "not declared" in error.message
    assert error.line == 4
    assert "typo" in error.hint


def test_undeclared_purpose():
    error = fails("""
        policy P
        principal alice
        source s
            confidential(alice) for billing
        """)
    assert "billing" in error.message and "purpose" in error.message


def test_source_with_no_confidentiality():
    error = fails("""
        policy P
        principal alice
        source s
            integrity untrusted
        """)
    assert "no confidentiality" in error.message
    assert "unlabelled source" in error.hint


def test_source_with_two_confidentiality_clauses():
    error = fails("""
        policy P
        principal alice, bob
        source s
            confidential(alice)
            confidential(bob)
        """)
    assert "twice" in error.message


def test_sink_with_no_accepts():
    error = fails("""
        policy P
        principal alice
        source s
            confidential(alice)
        sink out
            requires endorsed(alice)
        """)
    assert "no 'accepts'" in error.message


def test_duplicate_declaration_names_report_both_lines():
    error = fails("""
        policy P
        principal alice
        source s
            confidential(alice)
        source s
            confidential(alice)
        """)
    assert "declared twice" in error.message
    assert "line 3" in error.hint


def test_audit_never_is_rejected_rather_than_ignored():
    error = fails("""
        policy P
        principal alice, r
        source s
            confidential(alice)
        endorse review
            to endorsed(r)
            audit never
        """)
    assert "audit" in error.message
    assert "lie in the file" in error.hint


def test_mixed_tabs_and_spaces():
    text = "policy P\nprincipal a\nsource s\n    confidential(a)\n\tintegrity untrusted\n"
    with pytest.raises(KlvError) as excinfo:
        parse(text)
    assert "tabs and spaces" in excinfo.value.message


def test_unknown_clause_names_the_enclosing_block():
    error = fails("""
        policy P
        principal alice
        source s
            confidential(alice)
            sparkles yes
        """)
    assert "sparkles" in error.message
    assert "source" in error.message


def test_unknown_top_level_declaration():
    error = fails("""
        policy P
        principal alice
        conduit c
        """)
    assert "conduit" in error.message


def test_requires_integrity_is_rejected_with_the_replacement():
    """The README once used this. The language does not have it."""
    error = fails("""
        policy P
        principal alice, r
        source s
            confidential(alice)
        sink out
            accepts public
            requires integrity trusted
        """)
    assert "not part of the language" in error.message
    assert "endorsed(reviewer)" in error.hint
    assert "trusted by whom" in error.hint


def test_star_is_not_a_valid_principal():
    error = fails("""
        policy P
        principal *
        """)
    assert "'*'" in error.message
    assert "ambiguous" in error.hint


def test_declassifier_without_to():
    error = fails("""
        policy P
        principal alice, r
        source s
            confidential(alice)
        declassify d
            from confidential(alice)
        """)
    assert "no 'to'" in error.message
    assert "grants nothing" in error.hint


def test_a_file_not_starting_with_policy():
    error = fails("""
        principal alice
        policy P
        """)
    assert "must begin with 'policy" in error.message


def test_empty_file():
    with pytest.raises(KlvError) as excinfo:
        parse("\n# just a comment\n\n")
    assert "empty policy file" in excinfo.value.message


def test_indented_line_outside_a_declaration():
    error = fails("""
        policy P
        principal alice
            confidential(alice)
        """)
    assert "outside a declaration" in error.message


def test_every_error_carries_a_line_number():
    """A diagnostic without a location is a complaint."""
    for body in [
        "policy P\nprincipal a\nsource s\n    confidential(nobody)\n",
        "policy P\nprincipal a\nsource s\n    integrity untrusted\n",
        "policy P\nprincipal a\nnonsense x\n",
    ]:
        with pytest.raises(KlvError) as excinfo:
            parse(body)
        assert excinfo.value.line >= 1


def test_errors_carry_the_filename_when_one_is_known():
    with pytest.raises(KlvError) as excinfo:
        parse("policy P\nprincipal a\nsource s\n    confidential(ghost)\n", filename="acme.klv")
    assert "acme.klv:4" in str(excinfo.value)


# -- warnings, which must not fail the parse --------------------------------


def test_unused_principal_warns_but_parses():
    policy, warnings = parse_with_warnings(
        klv("""
        policy P
        principal alice, unused_one
        source s
            confidential(alice)
        sink o
            accepts public
        """)
    )
    assert policy.name == "P"
    assert any("unused_one" in w and "never used" in w for w in warnings)


def test_declassify_that_grants_no_readers_warns():
    _, warnings = parse_with_warnings(
        klv("""
        policy P
        principal alice, r
        source s
            confidential(alice)
        declassify wrong_keyword
            to endorsed(r)
        """)
    )
    assert any("did you mean 'endorse'" in w for w in warnings)


def test_endorse_that_grants_no_endorsement_warns():
    _, warnings = parse_with_warnings(
        klv("""
        policy P
        principal alice, bob
        source s
            confidential(alice)
        endorse wrong_keyword
            to confidential(bob)
        """)
    )
    assert any("did you mean 'declassify'" in w for w in warnings)


# -- the parsed policy is a real policy -------------------------------------


def test_a_parsed_policy_enforces():
    """Parsing is only useful if the result behaves."""
    from kelvra import Denied, Kelvra

    k = Kelvra(parse_file(EXAMPLE), consent=lambda principal, ctx: True)
    email = k.read("inbox.imap", "hostile")
    plan = k.model_call("agent.plan", email, produce=lambda e: e)

    with pytest.raises(Denied):
        k.emit("crm.write", plan)


def test_a_parsed_policy_is_sealed_by_a_session():
    from kelvra import Kelvra
    from kelvra.policy import PolicySealed

    extra = parse_file(EXAMPLE).sources["inbox.imap"]
    k = Kelvra(parse_file(EXAMPLE))
    with pytest.raises(PolicySealed):
        k.policy.add_source(extra)
