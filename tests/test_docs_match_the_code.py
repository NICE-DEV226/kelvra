"""Statements the documentation makes about what exists, checked against what exists.

Two of them went stale unnoticed: the README said the MCP adapter did not exist after it did,
and the editor extension's README said there was no parser after there was. A sentence about
the project's own state is a claim like any other, so these check the sentences that were wrong.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from kelvra import KlvError, parse

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
EXTENSION = (ROOT / "editors" / "vscode" / "README.md").read_text(encoding="utf-8")


def sentence_after(text: str, start: str) -> str:
    return text[text.index(start) :].split("\n", 1)[0]


def test_the_readme_does_not_say_the_gateway_is_missing_while_it_exists():
    gateway = importlib.import_module("kelvra.gateway")
    assert hasattr(gateway, "run_stdio") and hasattr(gateway, "McpFilter")
    missing = sentence_after(README, "What does not exist:")
    assert "MCP adapter" not in missing
    assert "gateway" in missing  # what is still missing about it is said: HTTP, a real application
    assert (ROOT / "spec" / "gateway.md").exists()
    # and the roadmap no longer says enforcement at the MCP boundary is still to do
    assert "What remains is enforcement at the MCP boundary" not in README


def test_the_extension_readme_does_not_say_there_is_no_parser():
    assert "no parser" not in EXTENSION.lower()
    assert "kelvra lsp" in EXTENSION
    assert "does not start it" not in EXTENSION  # it does now: extension.js starts the server
    assert (ROOT / "editors" / "vscode" / "extension.js").is_file()
    assert "Not tested automatically: how it looks" in EXTENSION  # and what is not tested is said


def test_the_grammar_colours_only_audit_words_the_parser_accepts():
    grammar = (ROOT / "editors" / "vscode" / "syntaxes" / "klv.tmLanguage.json").read_text(
        encoding="utf-8"
    )
    constants = re.search(r'"match": "\\\\b\((public\|[^)]*)\)\\\\b"', grammar)
    assert constants, "the constants rule was not found"
    words = set(constants.group(1).split("|"))
    head = "policy P\nprincipal a\ndeclassify d\n    to public\n    audit {}\n"
    parse(head.format("always"))
    with pytest.raises(KlvError, match="accepts only 'always'"):
        parse(head.format("never"))
    assert "always" in words and "never" not in words
