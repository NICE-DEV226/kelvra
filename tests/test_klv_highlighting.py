"""A policy is shown and coloured the same way everywhere, and every word in it has a colour.

Four things draw ``.klv``: the VS Code extension, the README picture, the demo page and the tests.
They read one grammar (``editors/vscode/syntaxes/klv.tmLanguage.json``) through
``editors/highlight.py``.

What was compared against the real thing, by hand, when this was written, because CI cannot start
VS Code: the engine in ``highlight.py`` against ``vscode-textmate`` with ``vscode-oniguruma``, the
engine VS Code uses, on the three shipped policies and on 120 randomly generated policies with
comments, tabs and CRLF line endings. Every character got the same scope list from both. That
check is not repeated here; what is repeated here is that every word is coloured, which is the
property a person sees, and that the pictures and settings say what the code does.
"""

from __future__ import annotations

import json
import re
import sys
import warnings

# Only our own generator's output and a file in this repository are parsed here, never input from
# outside, so the XML entity attacks that defusedxml guards against do not apply.
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "editors"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import highlight  # noqa: E402

from kelvra import KlvError, parse  # noqa: E402

VSCODE = ROOT / "editors" / "vscode"
SHIPPED = [
    "examples/support_agent/policy.klv",
    "examples/sealed_support_agent/policy.klv",
    "evaluation/policy.klv",
]
WORD = re.compile(r"[A-Za-z0-9_]")


def words_without_colour(text: str) -> list[str]:
    missing = []
    for number, line in enumerate(highlight.classes(text), start=1):
        for name, piece in line:
            if not name and WORD.search(piece):
                missing.append(f"line {number}: {piece.strip()!r}")
    return missing


# -- what each kind of word looks like ----------------------------------------------------


def kinds(line: str) -> list[tuple[str, str]]:
    [row] = highlight.classes(line)
    return [(name, piece) for name, piece in row if piece.strip()]


def test_each_part_of_a_policy_has_its_own_colour_class():
    assert kinds("source inbox.imap") == [("keyword", "source"), ("name", "inbox.imap")]
    assert kinds("    accepts confidential(a, b)") == [
        ("directive", "accepts"),
        ("function", "confidential"),
        ("punctuation", "("),
        ("principal", "a"),
        ("punctuation", ","),
        ("principal", "b"),
        ("punctuation", ")"),
    ]
    assert kinds("    integrity untrusted  # arrives from outside") == [
        ("directive", "integrity"),
        ("constant", "untrusted"),
        ("comment", "# arrives from outside"),
    ]
    assert kinds("version 12") == [("keyword", "version"), ("number", "12")]
    assert kinds("    requires consent(reviewer)") == [
        ("directive", "requires"),
        ("function", "consent"),
        ("punctuation", "("),
        ("principal", "reviewer"),
        ("punctuation", ")"),
    ]


def test_names_may_contain_dots_and_hyphens_as_the_parser_allows_and_are_coloured_whole():
    """Found by a generated policy: the parser takes ``A-A``, the grammar stopped at ``-``."""
    assert kinds("source inbox-v2.imap") == [("keyword", "source"), ("name", "inbox-v2.imap")]
    assert kinds("principal a-b, c.d") == [
        ("keyword", "principal"),
        ("principal", "a-b"),
        ("punctuation", ","),
        ("principal", "c.d"),
    ]
    assert kinds("    for q-1") == [("directive", "for"), ("purpose", "q-1")]


def test_every_name_in_a_principal_or_purpose_list_is_coloured_not_only_the_first():
    """Found by running VS Code's own engine: only the first name in the list had a colour."""
    assert kinds("principal a, b, c") == [
        ("keyword", "principal"),
        ("principal", "a"),
        ("punctuation", ","),
        ("principal", "b"),
        ("punctuation", ","),
        ("principal", "c"),
    ]
    assert kinds("purpose support, research  # why") == [
        ("keyword", "purpose"),
        ("purpose", "support"),
        ("punctuation", ","),
        ("purpose", "research"),
        ("comment", "# why"),
    ]


def test_a_purpose_after_for_is_coloured_as_a_purpose_wherever_it_appears():
    assert kinds("    confidential(customer) for support") == [
        ("function", "confidential"),
        ("punctuation", "("),
        ("principal", "customer"),
        ("punctuation", ")"),
        ("directive", "for"),
        ("purpose", "support"),
    ]
    assert kinds("    for billing") == [("directive", "for"), ("purpose", "billing")]


def test_a_comment_is_a_comment_to_the_end_of_the_line_and_hides_what_is_in_it():
    [(name, piece)] = kinds("# source sink confidential(a) for x")
    assert name == "comment" and piece.startswith("# source")
    [row] = highlight.classes("source s # sink")
    assert row[-1] == ("comment", "# sink")


# -- every word in every policy -----------------------------------------------------------


@pytest.mark.parametrize("path", SHIPPED)
def test_every_word_of_a_shipped_policy_has_a_colour(path):
    file = ROOT / path
    if not file.exists():
        pytest.skip(f"{path} is not in this tree")
    assert words_without_colour(file.read_text(encoding="utf-8")) == []


def test_every_word_of_any_generated_policy_has_a_colour():
    from test_properties import policy_spec, render

    @settings(max_examples=150, deadline=None, suppress_health_check=list(HealthCheck))
    @given(policy_spec(), st.sampled_from(["    ", "  ", "\t"]), st.booleans())
    def check(spec, indent, noisy):
        text = render(spec, indent=indent, noisy=noisy)
        parse(text)  # a valid policy
        assert words_without_colour(text) == []

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        check()


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_whatever_text_it_is_given_the_tokenizer_covers_each_line_without_a_gap(text):
    for line, tokens in zip(re.split(r"\r\n|\n|\r", text), highlight.tokenize(text), strict=True):
        assert "".join(piece for piece, _ in tokens) == line


def test_a_construct_left_open_does_not_break_the_next_line():
    lines = highlight.tokenize("confidential(a,\nb)\nsource s")
    assert [piece for piece, _ in lines[2] if piece.strip()] == ["source", "s"]
    assert highlight.classify(lines[2][0][1]) == "keyword"


# -- the picture --------------------------------------------------------------------------


def policy_svg() -> str:
    text = (ROOT / "examples" / "support_agent" / "policy.klv").read_text(encoding="utf-8")
    excerpt = "\n".join(text.split("\n")[14:74])
    label = "The SupportAgent policy: sources, sinks and declassifiers, with syntax colouring"
    return highlight.to_svg(excerpt, label)


def test_the_picture_in_the_readme_is_what_the_policy_and_the_grammar_produce():
    assert (ROOT / "assets" / "policy.svg").read_text(encoding="utf-8") == policy_svg(), (
        "regenerate it: python editors/highlight.py examples/support_agent/policy.klv "
        "--svg assets/policy.svg --lines 15-74 --label '...' (see the label in this test)"
    )


def test_the_picture_is_well_formed_self_contained_and_uses_only_the_palette():
    svg = (ROOT / "assets" / "policy.svg").read_text(encoding="utf-8")
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg") and root.get("role") == "img" and root.get("aria-label")
    lowered = svg.lower()
    for forbidden in ("<script", "href=", "<image", "onload", "javascript:", "<foreignobject"):
        assert forbidden not in lowered
    used = set(re.findall(r'fill="(#[0-9a-f]{6})"', svg))
    assert used <= set(highlight.PALETTE.values()), used - set(highlight.PALETTE.values())
    assert len(used) >= 8  # the colours are actually used, not just defined


def test_the_picture_places_each_word_at_its_column_so_indentation_survives_any_renderer():
    root = ET.fromstring(highlight.to_svg("source s\n    confidential(a)  # why"))
    texts = [t for t in root.iter() if t.tag.endswith("text")]
    first, second = (
        [(float(s.get("x")), s.text) for s in t if s.tag.endswith("tspan")] for t in texts
    )
    assert first[0][0] == highlight.PAD and second[0][0] == pytest.approx(
        highlight.PAD + 4 * highlight.CHAR_WIDTH, abs=0.2
    )
    assert second[-1][1] == "# why" and second[-1][0] > second[-2][0] + 2 * highlight.CHAR_WIDTH


def test_markup_in_a_policys_text_cannot_break_out_of_the_picture():
    svg = highlight.to_svg('# </text><script>alert(1)</script> & "q"')
    ET.fromstring(svg)
    assert "<script" not in svg and "&lt;/text&gt;" in svg


def test_the_readme_shows_the_picture_and_keeps_the_policy_as_text_the_tests_read():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert '<img src="./assets/policy.svg"' in readme and "<details>" in readme
    assert re.search(r"```kelvra\npolicy SupportAgent", readme)
    assert 'alt="' in readme.split("assets/policy.svg", 1)[1].split(">", 1)[0]


# -- the extension's settings -------------------------------------------------------------


def test_the_extension_does_not_describe_itself_as_having_no_parser():
    package = json.loads((VSCODE / "package.json").read_text(encoding="utf-8"))
    assert "no parser" not in package["description"].lower()
    assert "kelvra check" in package["description"]
    language = package["contributes"]["languages"][0]
    assert {"klv", "kelvra"} <= set(language["aliases"])  # a ```kelvra fence is coloured too
    assert language["extensions"] == [".klv"]


def test_a_name_with_a_dot_is_one_word_for_the_editor():
    config = json.loads((VSCODE / "language-configuration.json").read_text(encoding="utf-8"))
    word = re.compile(config["wordPattern"])
    for name in (
        "inbox.imap",
        "crm.customer_record",
        "slack.support_channel",
        "llm.openai",
        "a-b.c",
    ):
        assert word.fullmatch(name), name
    assert word.match("1abc") is None


def test_only_block_headers_indent_and_a_policy_line_does_not():
    config = json.loads((VSCODE / "language-configuration.json").read_text(encoding="utf-8"))
    rule = re.compile(config["indentationRules"]["increaseIndentPattern"])
    for header in ("source inbox.imap", "sink crm.write", "declassify d", "  endorse e"):
        assert rule.match(header), header
    for other in (
        "policy SupportAgent",
        "version 1",
        "    accepts public",
        "# source a",
        "principal a",
    ):
        assert not rule.match(other), other
    [enter] = config["onEnterRules"]
    assert re.compile(enter["beforeText"]).match("sink s") and enter["action"] == {
        "indent": "indent"
    }


def test_snippets_are_registered_and_each_one_parses_as_a_policy():
    package = json.loads((VSCODE / "package.json").read_text(encoding="utf-8"))
    [entry] = package["contributes"]["snippets"]
    path = VSCODE / entry["path"].removeprefix("./")
    snippets = json.loads(path.read_text(encoding="utf-8"))
    assert {s["prefix"] for s in snippets.values()} >= {
        "source", "sink", "sinkguarded", "declassify", "endorse",
    }  # fmt: skip
    for name, snippet in snippets.items():
        body = "\n".join(snippet["body"])
        body = re.sub(r"\$\{\d+\|([^,}|]+)[^}]*\|\}", r"\1", body)  # choice: take the first
        body = re.sub(r"\$\{\d+:([^}]*)\}", r"\1", body)  # placeholder: its default
        assert "$" not in body, f"{name}: a tab stop was left unresolved"
        text = "policy P\nprincipal customer, support_team, reviewer\n" + body + "\n"
        try:
            parse(text)
        except KlvError as error:
            pytest.fail(f"snippet {name!r} does not parse: {error}")


def test_the_grammar_has_a_rule_for_every_scope_the_picture_and_the_page_colour():
    grammar = (VSCODE / "syntaxes" / "klv.tmLanguage.json").read_text(encoding="utf-8")
    for prefix, _ in highlight.CLASSES:
        assert prefix in grammar, f"nothing in the grammar produces {prefix}"
