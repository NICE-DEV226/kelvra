"""Keep the TextMate grammar from drifting away from the language.

The grammar in editors/vscode/ duplicates the keyword set by hand, because
there is no parser to generate it from yet. Hand-maintained duplicates rot.
These tests fail when the example policy uses a word the grammar does not
know, which is the drift that actually matters -- a keyword nobody
highlights reads as a typo.

Delete this file the day the grammar is generated from the parser's tokens.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VSCODE = ROOT / "editors" / "vscode"
GRAMMAR = VSCODE / "syntaxes" / "klv.tmLanguage.json"
KLV = ROOT / "examples" / "support_agent" / "policy.klv"


@pytest.fixture(scope="module")
def grammar() -> dict:
    return json.loads(GRAMMAR.read_text(encoding="utf-8"))


def _patterns(node) -> list[str]:
    """Every regex the grammar contains."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"match", "begin", "end"} and isinstance(value, str):
                found.append(value)
            found.extend(_patterns(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_patterns(item))
    return found


def grammar_vocabulary(grammar: dict) -> set[str]:
    """Words the grammar names explicitly, from its alternation groups."""
    words: set[str] = set()
    for pattern in _patterns(grammar):
        for group in re.findall(r"\(([a-z_]+(?:\|[a-z_]+)+)\)", pattern):
            words |= set(group.split("|"))
    return words


def policy_vocabulary() -> set[str]:
    """Lowercase words in the example policy, comments stripped."""
    code = "\n".join(line.split("#")[0] for line in KLV.read_text(encoding="utf-8").splitlines())
    identifiers = set(re.findall(r"\b[a-z_]{2,}\b", code))

    # Names the policy declares or references are not keywords.
    declared: set[str] = set()
    for name in re.findall(
        r"^\s*(?:policy|source|sink|declassify|endorse|principal|purpose)\s+(.+)$",
        code,
        re.MULTILINE,
    ):
        declared |= {w for w in re.split(r"[,.\s]+", name) if w}
    for inner in re.findall(r"\w+\(([^)]*)\)", code):
        declared |= {w.strip() for w in inner.split(",") if w.strip()}

    return {w for w in identifiers if w not in declared}


# -- the tests --------------------------------------------------------------


def test_grammar_is_valid_json(grammar):
    assert grammar["scopeName"] == "source.klv"
    assert grammar["fileTypes"] == ["klv"]


def test_every_regex_compiles(grammar):
    for pattern in _patterns(grammar):
        re.compile(pattern)


def test_grammar_knows_every_keyword_the_example_uses(grammar):
    unknown = policy_vocabulary() - grammar_vocabulary(grammar)
    assert not unknown, (
        f"policy.klv uses {sorted(unknown)}, which the grammar does not highlight. "
        "Either add them to editors/vscode/syntaxes/klv.tmLanguage.json or stop using them."
    )


def test_the_example_does_not_spell_one_concept_two_ways():
    """`endorsement(...)` and `endorsed(...)` once coexisted. Once was enough."""
    code = KLV.read_text(encoding="utf-8")
    constructors = set(re.findall(r"\b([a-z_]+)\(", code))
    assert "endorsement" not in constructors, "use endorsed(...), not endorsement(...)"


def test_grammar_knows_every_block_keyword_the_parser_accepts(grammar):
    """Closes the loop: the grammar is checked against the parser, not the example.

    Until the grammar is generated from the parser's tokens, this is what
    stops a keyword from being accepted by the parser and left grey in the
    editor -- which reads as a typo to whoever wrote it.
    """
    from kelvra.klv import BLOCK_KEYWORDS

    unknown = set(BLOCK_KEYWORDS) - grammar_vocabulary(grammar)
    assert not unknown, f"the parser accepts {sorted(unknown)}; the grammar does not colour them"


def test_extension_declares_the_grammar_it_ships(grammar):
    package = json.loads((VSCODE / "package.json").read_text(encoding="utf-8"))
    contributed = package["contributes"]["grammars"][0]
    assert contributed["scopeName"] == grammar["scopeName"]
    assert (VSCODE / contributed["path"]).exists()

    language = package["contributes"]["languages"][0]
    assert language["extensions"] == [".klv"]
    assert (VSCODE / language["configuration"]).exists()


def test_github_override_exists_while_linguist_does_not_know_klv():
    """The .gitattributes fallback is load-bearing for how the repo looks."""
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert re.search(r"^\*\.klv\s+linguist-language=", attributes, re.MULTILINE)
