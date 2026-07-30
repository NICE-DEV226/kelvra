"""The language server's logic, tested without a client.

Everything below the protocol boundary is a pure function of text, which is
why none of this needs pygls installed. If a test here needed a running
editor, the logic would be in the wrong place.
"""

import textwrap
from pathlib import Path

import pytest

from kelvra.lsp import (
    completions_for,
    diagnostics_for,
    hover_at,
    symbols_for,
    word_at,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "support_agent" / "policy.klv"


def klv(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


GOOD = klv("""
policy Good
principal alice, bob
source inbox
    confidential(alice)
    integrity untrusted
sink out
    accepts confidential(alice)
""")


@pytest.fixture(scope="module")
def example_text() -> str:
    return EXAMPLE.read_text(encoding="utf-8")


# -- diagnostics ------------------------------------------------------------


def test_a_syntax_error_lands_on_its_own_line():
    text = klv("""
    policy P
    principal alice
    source s
        confidential(ghost)
    """)
    diagnostic = diagnostics_for(text)[0]
    assert diagnostic.severity == "error"
    assert diagnostic.code == "syntax"
    assert diagnostic.line == 4
    assert "ghost" in diagnostic.message


def test_a_syntax_error_suppresses_the_analysis():
    """Findings against a half-parsed file would break the soundness contract."""
    text = klv("""
    policy P
    principal alice
    source s
        confidential(ghost)
    sink dead
        accepts confidential(alice)
    """)
    assert [d.code for d in diagnostics_for(text)] == ["syntax"]


def test_a_finding_is_attached_to_the_line_that_declared_its_subject():
    text = klv("""
    policy P
    principal alice, bob
    source src
        confidential(alice)
    sink unreachable
        accepts confidential(bob)
    """)
    diagnostic = next(d for d in diagnostics_for(text) if d.code == "unsatisfiable-sink")
    assert diagnostic.line == 5, "should point at the sink, not at line 1"
    assert diagnostic.severity == "error"


def test_the_hint_travels_with_the_message():
    text = klv("""
    policy P
    principal alice, bob
    source src
        confidential(alice)
    sink unreachable
        accepts confidential(bob)
    """)
    diagnostic = next(d for d in diagnostics_for(text) if d.code == "unsatisfiable-sink")
    assert "hint:" in diagnostic.full_message


def test_parser_warnings_keep_their_line():
    text = klv("""
    policy P
    principal alice, spare
    source src
        confidential(alice)
    sink out
        accepts confidential(alice)
    """)
    warnings = [d for d in diagnostics_for(text) if "spare" in d.message]
    assert warnings and warnings[0].severity == "warning"


def test_diagnostics_are_ordered_by_line(example_text):
    lines = [d.line for d in diagnostics_for(example_text)]
    assert lines == sorted(lines)


def test_the_example_reports_its_injection_surface(example_text):
    codes = {d.code for d in diagnostics_for(example_text)}
    assert "untrusted-reaches-sink" in codes
    assert "unsatisfiable-sink" not in codes


# -- word under the cursor --------------------------------------------------


@pytest.mark.parametrize(
    "character,expected",
    [(0, "sink"), (5, "crm.write"), (9, "crm.write"), (13, "crm.write")],
)
def test_word_at_finds_dotted_identifiers(character, expected):
    assert word_at("sink crm.write\n", 1, character) == expected


def test_word_at_returns_none_off_the_end():
    assert word_at("sink out\n", 1, 400) is None
    assert word_at("sink out\n", 99, 0) is None


# -- hover ------------------------------------------------------------------


def test_hovering_a_sink_answers_who_can_reach_it(example_text):
    line = next(
        n for n, text in enumerate(example_text.splitlines(), 1) if "sink crm.write" in text
    )
    markdown = hover_at(example_text, line, 6)

    assert "sink `crm.write`" in markdown
    assert "Reachable by" in markdown
    assert "inbox.imap" in markdown


def test_hovering_an_unreachable_sink_says_so():
    text = klv("""
    policy P
    principal alice, bob
    source src
        confidential(alice)
    sink nowhere
        accepts confidential(bob)
    """)
    assert "Unreachable" in hover_at(text, 5, 6)


def test_hovering_a_sink_warns_when_untrusted_data_reaches_it():
    text = klv("""
    policy P
    principal alice
    source web
        public
        integrity untrusted
    sink act
        accepts public
    """)
    markdown = hover_at(text, 6, 6)
    assert "Untrusted data reaches this sink" in markdown


def test_hovering_a_source_says_its_labels_are_unverified(example_text):
    line = next(
        n for n, t in enumerate(example_text.splitlines(), 1) if "source inbox.imap" in t
    )
    markdown = hover_at(example_text, line, 8)
    assert "untrusted" in markdown
    assert "declarative and unverified" in markdown


def test_hovering_a_declassifier_names_it_as_a_leak_point(example_text):
    line = next(
        n for n, t in enumerate(example_text.splitlines(), 1) if "declassify pii_redaction" in t
    )
    markdown = hover_at(example_text, line, 13)
    assert "only places a leak is possible" in markdown


def test_hovering_a_principal_reports_where_it_was_declared(example_text):
    line = next(n for n, t in enumerate(example_text.splitlines(), 1) if t.startswith("principal"))
    markdown = hover_at(example_text, line, 11)
    assert "principal `customer`" in markdown
    assert "declared on line" in markdown


def test_hovering_nothing_returns_nothing():
    assert hover_at(GOOD, 1, 0) is None  # the word "policy"
    assert hover_at("", 1, 0) is None


def test_hover_is_silent_on_an_unparseable_file():
    assert hover_at("policy P\nsource s\n    confidential(ghost)\n", 2, 8) is None


# -- symbols ----------------------------------------------------------------


def test_symbols_outline_the_declarations(example_text):
    symbols = symbols_for(example_text)
    assert {s.name for s in symbols} == {
        "inbox.imap",
        "crm.customer_record",
        "llm.openai",
        "slack.support_channel",
        "crm.write",
        "pii_redaction",
        "human_review",
        "share_with_model",
    }
    assert all(s.line >= 1 for s in symbols)


def test_symbols_survive_a_broken_file():
    """An outline that vanishes on a syntax error vanishes when most needed."""
    broken = "policy P\nsource s\n    confidential(ghost)\nsink out\n    accepts public\n"
    assert {s.name for s in symbols_for(broken)} == {"s", "out"}


def test_symbols_ignore_commented_declarations():
    symbols = symbols_for("# sink not.real\nsink real\n    accepts public\n")
    assert [(s.name, s.line) for s in symbols] == [("real", 2)]


# -- completion -------------------------------------------------------------


def test_completing_inside_confidential_offers_declared_principals():
    text = "policy P\nprincipal alice, bob\nsource s\n    confidential("
    labels = {label for label, _ in completions_for(text, 4, len("    confidential("))}
    assert {"alice", "bob"} <= labels


def test_completing_at_the_left_margin_offers_declarations():
    labels = {label for label, _ in completions_for(GOOD + "\n", 8, 0)}
    assert {"source", "sink", "declassify", "endorse"} <= labels


def test_completing_indented_offers_clauses():
    labels = {label for label, _ in completions_for(GOOD + "    ", 8, 4)}
    assert {"accepts", "requires", "integrity"} <= labels


def test_completion_still_works_on_an_unparseable_file():
    """Completion is most useful mid-edit, which is when a file does not parse."""
    text = (
        "policy P\nprincipal alice, bob\nsource s\n    confidential(ghost)\n"
        "sink o\n    accepts confidential("
    )
    labels = {label for label, _ in completions_for(text, 6, len("    accepts confidential("))}
    assert {"alice", "bob"} <= labels


# -- the optional dependency ------------------------------------------------


def test_the_pure_functions_need_no_pygls():
    """The core has no dependencies and this module must not change that."""
    import kelvra.lsp

    assert "pygls" not in dir(kelvra.lsp)
    assert diagnostics_for(GOOD) is not None


# -- the protocol itself ----------------------------------------------------


def test_the_server_speaks_lsp_over_stdio():
    """One real exchange, because the pure functions above prove nothing
    about the wiring: capability negotiation, framing and position
    conversion all live in the adapter layer and none of them are exercised
    by calling `diagnostics_for` directly.
    """
    pytest.importorskip("pygls")

    import json
    import subprocess
    import sys

    def frame(payload: dict) -> bytes:
        body = json.dumps(payload).encode()
        return b"Content-Length: %d\r\n\r\n%s" % (len(body), body)

    uri = "file:///policy.klv"
    text = EXAMPLE.read_text(encoding="utf-8")

    stdin = (
        frame(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"processId": None, "rootUri": None, "capabilities": {}},
            }
        )
        + frame({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        + frame(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "klv",
                        "version": 1,
                        "text": text,
                    }
                },
            }
        )
        + frame({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": None})
        + frame({"jsonrpc": "2.0", "method": "exit", "params": None})
    )

    result = subprocess.run(
        [sys.executable, "-m", "kelvra.cli", "lsp"],
        input=stdin,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")

    published = []
    for chunk in result.stdout.decode("utf-8", "replace").split("Content-Length:"):
        start = chunk.find("{")
        if start < 0:
            continue
        try:
            message = json.loads(chunk[start:])
        except json.JSONDecodeError:
            continue
        if message.get("method") == "textDocument/publishDiagnostics":
            published.extend(message["params"]["diagnostics"])

    assert published, "the server never published diagnostics"
    codes = {d["code"] for d in published}
    assert "untrusted-reaches-sink" in codes

    # Diagnostics must land on the sink they describe, not at the top of the
    # file. LSP lines are zero-based; the sink declarations are not on line 1.
    assert all(d["range"]["start"]["line"] > 0 for d in published)
