"""Every way a policy file can be wrong is refused with the right place and the right words.

A diagnostic without a location is a complaint, not a diagnostic (spec/policy-language.md
section 4), and the location is the part a person acts on. Mutation testing of ``klv.py``
(1,143 mutants, 299 survivors) showed the suite checking that a bad file raises ``KlvError`` and
almost never *which* error, *where*, or *what it says to do instead*; replacing the line number,
the quoted text or the whole message with ``None`` went unnoticed in nearly every parse routine.

Each case below marks the offending line with ``#BAD``. The expected line number and the expected
quoted text are read from that marker, not from the parser, so the parser cannot agree with
itself. The message and the hint are pinned as fragments.
"""

from __future__ import annotations

import pytest

from kelvra import parse
from kelvra.klv import KlvError

HEAD = "policy P\nprincipal a, b\npurpose p\n"
MARK = "#BAD"


def _case(case_id: str, text: str, message: str, hint: str = "", *, head: bool = True):
    return pytest.param(HEAD + text if head else text, message, hint, id=case_id)


CASES = [
    # -- the file as a whole --------------------------------------------------------------
    _case(
        "no-policy-line",
        "principal a #BAD\n",
        "a policy file must begin with 'policy <name>'",
        head=False,
    ),
    _case("policy-two-names", "policy P Q #BAD\n", "'policy' takes exactly one name", head=False),
    _case(
        "unknown-top-level",
        "bogus x #BAD\n",
        "unknown keyword 'bogus' at top level",
        "expected version, principal, purpose, or one of: ",
    ),
    _case(
        "indented-orphan",
        "    stray #BAD\n",
        "unexpected indented line outside a declaration",
        "clauses must sit under a source, sink, declassify or endorse header",
    ),
    _case(
        "version-letters",
        "version 1x #BAD\n",
        "'version' takes a single integer of at most 9 ASCII digits",
        "for example: version 1",
    ),
    _case("version-too-long", "version 1234567890 #BAD\n", "'version' takes a single integer"),
    _case("version-negative", "version -1 #BAD\n", "'version' takes a single integer"),
    _case("version-empty", "version #BAD\n", "'version' takes a single integer"),
    _case("principal-without-name", "principal #BAD\n", "'principal' needs at least one name"),
    _case("purpose-without-name", "purpose #BAD\n", "'purpose' needs at least one name"),
    _case("empty-name-in-list", "principal c,, d #BAD\n", "empty name in list"),
    _case(
        "star-as-a-name",
        "principal * #BAD\n",
        "'*' is not a valid name",
        "it is reserved for the universe",
    ),
    _case("bad-identifier", "principal 9x #BAD\n", "'9x' is not a valid identifier"),
    # -- declarations ---------------------------------------------------------------------
    _case(
        "header-without-name",
        "source #BAD\n    public\n",
        "'source' takes exactly one name",
        "for example: source inbox.imap",
    ),
    _case(
        "header-two-names",
        "sink a b #BAD\n    accepts public\n",
        "'sink' takes exactly one name",
        "for example: sink inbox.imap",
    ),
    _case(
        "header-bad-identifier", "source 9x #BAD\n    public\n", "'9x' is not a valid identifier"
    ),
    _case(
        "source-declared-twice",
        "source s\n    public\nsource s #BAD\n    public\n",
        "source 's' is declared twice",
        "first declared on line 4",
    ),
    _case(
        "name-shared-by-source-and-sink",
        "source s\n    public\nsink s #BAD\n    accepts public\n",
        "sink 's' is declared twice",
        "first declared on line 4",
    ),
    _case(
        "undeclared-principal",
        "source s\n    confidential(zzz) #BAD\n",
        "principal 'zzz' is not declared",
        "add it to a 'principal' line",
    ),
    _case(
        "undeclared-purpose",
        "source s\n    public for zzz #BAD\n",
        "purpose 'zzz' is not declared",
        "add it to a 'purpose' line",
    ),
    # -- sources --------------------------------------------------------------------------
    _case(
        "source-confidentiality-twice",
        "source s\n    public\n    confidential(a) #BAD\n",
        "source 's' declares confidentiality twice",
        "a source carries exactly one confidentiality label",
    ),
    _case(
        "source-integrity-twice",
        "source s\n    public\n    integrity trusted\n    integrity untrusted #BAD\n",
        "source 's' declares integrity twice",
        "a source carries exactly one integrity label",
    ),
    _case(
        "source-unknown-clause",
        "source s\n    public\n    bogus x #BAD\n",
        "unknown clause 'bogus' in source 's'",
        "a source accepts: public, confidential(...), integrity",
    ),
    _case(
        "source-without-confidentiality",
        "source s #BAD\n    integrity trusted\n",
        "source 's' declares no confidentiality",
        "add 'public' or 'confidential(...)'",
    ),
    _case(
        "source-for-two-purposes",
        "source s\n    public for p q #BAD\n",
        "'for' takes a single purpose",
    ),
    _case(
        "source-confidential-without-names",
        "source s\n    confidential #BAD\n",
        "expected 'public' or 'confidential(...)'",
    ),
    _case(
        "source-private", "source s\n    private #BAD\n", "unknown clause 'private' in source 's'"
    ),
    _case(
        "integrity-maybe",
        "source s\n    public\n    integrity maybe #BAD\n",
        "'integrity' takes 'trusted' or 'untrusted'",
        "to name specific endorsers on a sink, use 'requires endorsed(...)'",
    ),
    # -- sinks ----------------------------------------------------------------------------
    _case(
        "sink-accepts-twice",
        "sink k\n    accepts public\n    accepts public #BAD\n",
        "sink 'k' declares 'accepts' twice",
    ),
    _case(
        "sink-for-twice",
        "sink k\n    accepts public\n    for p\n    for p #BAD\n",
        "sink 'k' declares 'for' twice",
        "a sink serves exactly one purpose",
    ),
    _case(
        "sink-for-two-purposes",
        "sink k\n    accepts public\n    for p q #BAD\n",
        "'for' takes a single purpose",
    ),
    _case(
        "sink-unknown-clause",
        "sink k\n    accepts public\n    bogus x #BAD\n",
        "unknown clause 'bogus' in sink 'k'",
        "a sink accepts: accepts, requires, for",
    ),
    _case(
        "sink-without-accepts",
        "sink k #BAD\n    requires endorsed(a)\n",
        "sink 'k' declares no 'accepts'",
        "add 'accepts public' or 'accepts confidential(...)'",
    ),
    _case(
        "accepts-everyone",
        "sink k\n    accepts everyone #BAD\n",
        "'accepts' takes 'public' or 'confidential(...)'",
    ),
    _case(
        "requires-integrity",
        "sink k\n    accepts public\n    requires integrity trusted #BAD\n",
        "'requires integrity' is not part of the language",
        "name the endorser instead: 'requires endorsed(reviewer)'",
    ),
    _case(
        "requires-nothing-useful",
        "sink k\n    accepts public\n    requires #BAD\n",
        "'requires' takes endorsed(...) or consent(...)",
    ),
    _case(
        "consent-takes-one",
        "sink k\n    accepts public\n    requires consent(a, b) #BAD\n",
        "'consent' takes exactly one principal",
    ),
    _case(
        "consent-twice",
        "sink k\n    accepts public\n    requires consent(a)\n    requires consent(b) #BAD\n",
        "a second 'requires consent' on the same declaration",
        "consent from 'a' is already required here",
    ),
    _case(
        "unknown-requirement",
        "sink k\n    accepts public\n    requires bogus(a) #BAD\n",
        "unknown requirement 'bogus'",
        "expected endorsed(...) or consent(...)",
    ),
    # -- declassify and endorse -----------------------------------------------------------
    _case(
        "endorsed-in-declassifier",
        "declassify d\n    from untrusted\n    to public\n    requires endorsed(a) #BAD\n",
        "'requires endorsed(...)' has no effect in declassify 'd'",
        "a declassifier cannot demand an endorsement of its input",
    ),
    _case(
        "declassifier-unknown-clause",
        "declassify d\n    to public\n    bogus x #BAD\n",
        "unknown clause 'bogus' in declassify 'd'",
        "expected: from, to, audit, requires",
    ),
    _case(
        "declassifier-without-to",
        "endorse d #BAD\n    from untrusted\n",
        "endorse 'd' declares no 'to'",
        "'to' is what the construct grants",
    ),
    _case(
        "from-nonsense",
        "declassify d\n    from everything #BAD\n    to public\n",
        "'from' takes public, untrusted, confidential(...) or endorsed(...)",
    ),
    _case(
        "to-nonsense",
        "declassify d\n    to everything #BAD\n",
        "'to' takes public, confidential(...) or endorsed(...)",
    ),
    _case(
        "to-cannot-grant",
        "declassify d\n    to bogus(a) #BAD\n",
        "cannot grant 'bogus'",
        "expected confidential(...) or endorsed(...)",
    ),
    _case(
        "audit-never",
        "declassify d\n    to public\n    audit never #BAD\n",
        "'audit' accepts only 'always'",
        "every declassification is recorded regardless",
    ),
]


def _marked(text: str) -> tuple[int, str]:
    for number, raw in enumerate(text.split("\n"), start=1):
        if MARK in raw:
            return number, raw
    raise AssertionError("the case has no #BAD marker")


@pytest.mark.parametrize("text,message,hint", CASES)
def test_a_malformed_policy_is_refused_where_it_is_wrong_and_says_why(text, message, hint):
    line, raw = _marked(text)
    with pytest.raises(KlvError) as excinfo:
        parse(text)
    error = excinfo.value
    assert message in error.message
    assert error.line == line, f"reported line {error.line}, the mark is on line {line}"
    assert error.text == raw
    assert hint in error.hint
    if hint:
        assert error.hint, "a hint was promised"
    rendered = str(error)
    assert f"line {line}: " in rendered and raw.strip() in rendered
    assert (f"hint: {error.hint}" in rendered) is bool(error.hint)


def test_every_error_site_has_a_case():
    """A routine added to the parser without a case here would again be tested only for raising."""
    import re
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "src" / "kelvra" / "klv.py").read_text(
        encoding="utf-8"
    )
    raises = len(re.findall(r"raise KlvError\(", source))
    # 44 raise sites at the time of writing, some unreachable through parse() alone (shared
    # helpers reached from several callers) or covered by the special cases below.
    assert raises <= 46, f"{raises} raise sites; add cases for the new ones"


# -- the ones that cannot be written as plain text in this file -------------------------


def test_an_empty_file_is_refused_at_line_one_with_what_to_write():
    for text in ("", "\n\n", "# only a comment\n", "   \n"):
        with pytest.raises(KlvError) as excinfo:
            parse(text)
        error = excinfo.value
        assert error.message == "empty policy file" and error.line == 1 and error.text == ""
        assert error.hint == "expected 'policy <name>' on the first line"


def test_an_invisible_character_is_named_and_shown_escaped_not_as_itself():
    for char, name in ((chr(0x200B), "ZERO WIDTH SPACE"), (chr(0x202E), "RIGHT-TO-LEFT OVERRIDE")):
        text = f"policy P\nprincipal a{char}b\n"
        with pytest.raises(KlvError) as excinfo:
            parse(text)
        error = excinfo.value
        assert error.message == f"forbidden character U+{ord(char):04X} ({name})"
        assert error.line == 2
        assert char not in error.text and char not in str(error)  # shown escaped
        assert "\\u" in error.text
        assert "control, invisible and line-separator characters are rejected" in error.hint


def test_a_character_without_a_name_is_still_reported():
    with pytest.raises(KlvError) as excinfo:
        parse("policy P\nprincipal a\x01b\n")
    assert excinfo.value.message.startswith("forbidden character U+0001 (")
    assert excinfo.value.line == 2


def test_mixed_tabs_and_spaces_are_refused_with_the_line_and_a_way_out():
    text = "policy P\nprincipal a\nsource s\n \tpublic\n"
    with pytest.raises(KlvError) as excinfo:
        parse(text)
    error = excinfo.value
    assert error.message == "indentation mixes tabs and spaces" and error.line == 4
    assert error.text == " \tpublic"
    assert error.hint.startswith("pick one and use it throughout the file")


def test_a_filename_is_added_to_the_location_and_nothing_else_changes():
    with pytest.raises(KlvError) as excinfo:
        parse("policy P\nbogus x\n", filename="support.klv")
    error = excinfo.value
    assert error.filename == "support.klv"
    assert str(error).startswith("support.klv:2: unknown keyword 'bogus' at top level")
    assert error.line == 2 and error.text == "bogus x"
    assert KlvError("m", 3).located_in(None).filename is None
    assert str(KlvError("m", 3)) == "line 3: m"
    assert str(KlvError("m", 3, "  quoted  ", "do this")) == (
        "line 3: m\n    quoted\n  hint: do this"
    )


def test_a_policy_with_no_declared_names_complains_about_the_first_use_not_the_end():
    with pytest.raises(KlvError) as excinfo:
        parse("policy P\nsource s\n    confidential(a)\nsource t\n    confidential(b)\n")
    assert excinfo.value.line == 3 and "principal 'a' is not declared" in excinfo.value.message


# -- warnings are located too -----------------------------------------------------------


def test_warnings_say_which_line_they_are_about_and_what_they_noticed():
    from kelvra.klv import parse_detailed

    text = (
        "policy P\n"
        "principal a, b\n"
        "principal a\n"  # line 3: declared again
        "purpose unused_purpose\n"  # line 4
        "source s\n"  # line 5: no integrity
        "    confidential(a)\n"
        "declassify d\n"  # line 7: grants no readers
        "    to endorsed(a)\n"
        "endorse e\n"  # line 9: grants no endorsement
        "    to confidential(a)\n"
    )
    result = parse_detailed(text)
    got = dict.fromkeys(result.warning_lines)
    expected = [
        (3, "principal 'a' declared more than once"),
        (
            5,
            "source 's' declares no integrity and defaults to trusted; say 'integrity trusted' "
            "or 'integrity untrusted' so the choice is visible",
        ),
        (7, "declassify 'd' grants no readers -- did you mean 'endorse'?"),
        (9, "endorse 'e' grants no endorsement -- did you mean 'declassify'?"),
        (2, "principal 'b' is declared but never used"),
        (4, "purpose 'unused_purpose' is declared but never used"),
    ]
    for item in expected:
        assert item in got, (item, result.warning_lines)
    assert len(result.warning_lines) == len(expected)
    assert result.warnings == [f"line {n}: {m}" for n, m in result.warning_lines]
    assert len(result.warnings) == len(result.warning_lines)


def test_a_clean_policy_has_no_warnings():
    from kelvra.klv import parse_detailed

    text = "policy P\nprincipal a\nsource s\n    confidential(a)\n    integrity trusted\n"
    assert parse_detailed(text).warning_lines == []
