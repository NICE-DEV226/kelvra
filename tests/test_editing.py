"""Suggestions, jump to definition, references, rename and quick fixes in an editor.

All of it is a pure function of text, and all of it has to work on a file that does not parse,
because that is the state a file is in while someone is typing.
"""

from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kelvra import KlvError, parse
from kelvra.editing import (
    KEYWORDS,
    RenameError,
    declaration_edit,
    definition,
    occurrence_at,
    occurrences,
    references,
    rename,
    suggestions,
)
from kelvra.lsp import completions_for, quick_fix_for

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_properties import policy_spec, render


def klv(body: str) -> str:
    return textwrap.dedent(body).strip("\n") + "\n"


POLICY = klv("""
    policy P
    principal customer, support_team, reviewer
    purpose support
    source inbox.imap          # customer is mentioned in this comment
        confidential(customer) for support
        integrity untrusted
    sink slack.out
        accepts confidential(support_team)
        requires endorsed(reviewer)
    declassify widen
        from confidential(customer)
        to   confidential(customer, support_team)
        requires consent(reviewer)
        audit always
""")


def at(text: str, needle: str, nth: int = 0, inside: int = 1) -> tuple[int, int]:
    """(line, column) of the ``nth`` occurrence of ``needle``, ``inside`` characters into it."""
    seen = 0
    for number, line in enumerate(text.split("\n"), start=1):
        start = -1
        while (start := line.find(needle, start + 1)) >= 0:
            if seen == nth:
                return number, start + inside
            seen += 1
    raise AssertionError(f"{needle!r} #{nth} not found")


def labels(text: str, line: int, character: int) -> list[str]:
    return [item.label for item in suggestions(text, line, character)]


# -- what to suggest where ------------------------------------------------------------------


def test_after_each_clause_keyword_only_what_can_follow_it_is_offered():
    cases = {
        "    integrity ": ["trusted", "untrusted"],
        "    accepts ": ["public", "confidential"],
        "    requires ": ["endorsed", "consent"],
        "    from ": ["public", "untrusted", "confidential", "endorsed"],
        "    to ": ["public", "confidential", "endorsed"],
        "    audit ": ["always"],
    }
    for prefix, expected in cases.items():
        text = "policy P\nprincipal a\nsource s\n" + prefix
        assert labels(text, 4, len(prefix)) == expected, prefix


def test_inside_a_constructor_the_declared_principals_are_offered_and_only_them():
    text = "policy P\nprincipal b, a\npurpose p\nsink k\n    accepts confidential("
    items = suggestions(text, 5, len("    accepts confidential("))
    assert [(i.label, i.kind) for i in items] == [("a", "principal"), ("b", "principal")]
    assert labels(text + "a, ", 5, len("    accepts confidential(a, ")) == ["a", "b"]
    closed = text + "a) "
    assert "a" not in labels(closed, 5, len("    accepts confidential(a) "))


def test_after_for_the_declared_purposes_are_offered():
    text = "policy P\nprincipal a\npurpose billing, support\nsource s\n    confidential(a) for "
    items = suggestions(text, 5, len("    confidential(a) for "))
    assert [(i.label, i.kind) for i in items] == [("billing", "purpose"), ("support", "purpose")]


def test_each_block_offers_its_own_clauses_and_not_another_blocks():
    head = "policy P\nprincipal a\n"
    expected = {
        "source": {"confidential", "public", "integrity"},
        "sink": {"accepts", "requires", "for"},
        "declassify": {"from", "to", "requires", "audit"},
        "endorse": {"from", "to", "requires", "audit"},
    }
    for kind, wanted in expected.items():
        text = head + f"{kind} x\n    "
        assert set(labels(text, 4, 4)) == wanted, kind
    # the nearest header above decides, even after a blank line or a comment
    text = head + "source s\n    public\n\n    # note\nsink k\n    accepts public\n\n    "
    assert set(labels(text, 10, 4)) == {"accepts", "requires", "for"}


def test_at_the_left_margin_the_declarations_come_as_whole_blocks_that_parse():
    items = suggestions("policy P\n", 2, 0)
    assert [i.label for i in items] == [
        "source", "sink", "declassify", "endorse", "principal", "purpose",
    ]  # fmt: skip
    assert all(i.insert for i in items) and {i.kind for i in items} == {"snippet", "keyword"}
    # a word being typed at the margin still gets them: the editor filters by what is typed
    assert labels("policy P\nso", 2, 2) == labels("policy P\n", 2, 0)


def test_in_a_comment_and_when_inventing_a_name_nothing_is_offered():
    assert suggestions("policy P\nprincipal a  # accepts ", 2, 20) == []
    assert suggestions("policy P\nprincipal a, ", 2, len("principal a, ")) == []
    assert suggestions("policy P\npurpose ", 2, len("purpose ")) == []


def test_a_source_line_with_its_label_offers_for_to_limit_it_to_a_purpose():
    text = "policy P\nprincipal a\npurpose p\nsource s\n    confidential(a) "
    assert labels(text, 5, len("    confidential(a) ")) == ["for"]


def test_suggestions_work_in_a_file_that_does_not_parse():
    text = (
        "policy P\nprincipal a, b\nsource s\n    confidential(ghost)\n"
        "sink k\n    accepts confidential("
    )
    assert labels(text, 6, len("    accepts confidential(")) == ["a", "b"]


# -- every suggestion, filled in, is something the parser accepts ---------------------------


def expand(snippet: str) -> str:
    """LSP snippet syntax to text: a choice takes its first option, a placeholder its default."""
    previous = None
    while previous != snippet:
        previous = snippet
        snippet = re.sub(r"\$\{\d+\|([^,|}]+)(?:,[^|]*)?\|\}", r"\1", snippet)
        snippet = re.sub(r"\$\{\d+:([^${}]*)\}", r"\1", snippet)
    return snippet


def test_every_snippet_expands_to_text_without_leftover_tab_stops():
    items = list(suggestions("policy P\n", 2, 0))
    for kind in ("source", "sink", "declassify"):
        items += suggestions(f"policy P\n{kind} x\n    ", 3, 4)
    for after in ("integrity", "accepts", "requires", "from", "to", "audit"):
        items += suggestions(f"policy P\nsource s\n    {after} ", 3, len(after) + 5)
    for item in items:
        assert item.insert is None or "$" not in expand(item.insert), item.label


def test_each_block_a_snippet_creates_is_a_valid_policy_when_it_is_filled_in():
    """The drop-downs offer the names this policy declares, so the first choice is always valid."""
    head = "policy P\nprincipal customer, support_team, reviewer, model_provider\n"
    for item in suggestions(head, 3, 0):
        if item.kind != "snippet":
            continue
        assert "|customer," in item.insert or "inbox" in item.insert, item.label
        try:
            parse(head + expand(item.insert) + "\n")
        except KlvError as error:
            pytest.fail(f"the {item.label!r} snippet does not parse: {error}")


def test_with_nothing_declared_the_placeholder_stays_a_placeholder_not_an_invented_name():
    [source] = [i for i in suggestions("policy P\n", 2, 0) if i.label == "source"]
    assert "${2:principal}" in source.insert and "|" not in source.insert.split("integrity")[0]


@pytest.mark.parametrize("kind", ["source", "sink", "declassify", "endorse"])
def test_each_clause_a_block_offers_is_accepted_by_the_parser_in_that_block(kind):
    head = "policy P\nprincipal customer, support_team, reviewer\npurpose support\n"
    required = {
        "source": "    public\n",
        "sink": "    accepts public\n",
        "declassify": "    to public\n",
        "endorse": "    to endorsed(reviewer)\n",
    }[kind]
    alone = {
        "source": ("public", "confidential"),
        "sink": ("accepts",),
        "declassify": ("to",),
        "endorse": ("to",),
    }[kind]
    opened = head + f"{kind} x\n"
    checked = 0
    for item in suggestions(opened + "    ", 5, 4):
        if item.retrigger:  # accepted in two steps: the word, then what the editor offers next
            typed = "    " + (item.insert or item.label)
            follow = suggestions(opened + typed, 5, len(typed))
            assert follow, f"{kind}: nothing follows {item.label!r}"
            clauses = [typed + expand(f.insert or f.label) for f in follow]
        else:
            clauses = ["    " + expand(item.insert or item.label)]
        for clause in clauses:
            word = item.label
            body = clause + "\n" if word in alone else required + clause + "\n"
            if kind == "source" and word == "integrity":
                body = required + clause + "\n"
            try:
                parse(opened + body)
            except KlvError as error:
                pytest.fail(
                    f"{kind}: {item.label!r} gives {clause!r}, which does not parse: {error}"
                )
            checked += 1
    assert checked >= 3


# -- where a name is declared, and everything that mentions it ------------------------------


def test_occurrences_find_declarations_and_uses_and_ignore_comments():
    found = {(o.line, o.name, o.space, o.role) for o in occurrences(POLICY)}
    assert (2, "customer", "principal", "decl") in found
    assert (3, "support", "purpose", "decl") in found
    assert (4, "inbox.imap", "block", "decl") in found
    assert (5, "customer", "principal", "use") in found
    assert (5, "support", "purpose", "use") in found
    assert not any(o.line == 4 and o.name == "customer" for o in occurrences(POLICY))  # the comment


def test_the_definition_of_a_principal_or_purpose_is_its_declaration():
    line, col = at(POLICY, "customer", nth=2)  # the use in the source's label
    found = definition(POLICY, line, col)
    assert (found.line, found.role, found.space) == (2, "decl", "principal")
    line, col = at(POLICY, "confidential(support_team", inside=len("confidential(s"))
    found = definition(POLICY, line, col)
    assert (found.name, found.line) == ("support_team", 2)
    line, col = at(POLICY, "for support", inside=len("for s"))  # a purpose, after `for`
    found = definition(POLICY, line, col)
    assert (found.line, found.space, found.name) == (3, "purpose", "support")


def test_the_definition_of_a_name_that_is_not_declared_is_nothing():
    text = "policy P\nprincipal a\nsource s\n    confidential(ghost)\n"
    assert definition(text, 4, len("    confidential(g")) is None
    assert definition(text, 1, 3) is None  # not on a name at all


def test_references_list_the_declaration_and_every_use_and_can_leave_the_declaration_out():
    line, col = at(POLICY, "reviewer", nth=0)  # the declaration
    everything = references(POLICY, line, col)
    assert [(o.line, o.role) for o in everything] == [(2, "decl"), (9, "use"), (13, "use")]
    uses = references(POLICY, line, col, include_declaration=False)
    assert [(o.line, o.role) for o in uses] == [(9, "use"), (13, "use")]
    assert references(POLICY, 1, 0) == []


def test_a_block_name_has_its_declaration_and_nothing_else():
    line, col = at(POLICY, "slack.out")
    [only] = references(POLICY, line, col)
    assert (only.space, only.role) == ("block", "decl")


def test_a_principal_and_a_source_with_the_same_name_are_different_names():
    text = "policy P\nprincipal crm\nsource crm\n    confidential(crm)\n"
    principal = references(text, 2, len("principal c"))
    block = references(text, 3, len("source c"))
    assert [(o.space, o.line) for o in principal] == [("principal", 2), ("principal", 4)]
    assert [(o.space, o.line) for o in block] == [("block", 3)]


def test_names_with_dots_and_hyphens_are_one_name():
    text = "policy P\nprincipal team-a.b, other\nsink k\n    accepts confidential(team-a.b)\n"
    found = references(text, 2, len("principal team-"))
    assert [o.name for o in found] == ["team-a.b", "team-a.b"]


def test_the_cursor_at_either_edge_of_a_name_still_finds_it():
    start = at(POLICY, "reviewer", nth=0, inside=0)
    end = at(POLICY, "reviewer", nth=0, inside=len("reviewer"))
    assert occurrence_at(POLICY, *start).name == "reviewer"
    assert occurrence_at(POLICY, *end).name == "reviewer"
    assert occurrence_at(POLICY, start[0], start[1] - 1) is None  # the space before it: nothing


# -- rename ---------------------------------------------------------------------------------


def apply(text: str, edits, new: str) -> str:
    lines = text.split("\n")
    for edit in sorted(edits, key=lambda e: (e.line, e.start), reverse=True):
        row = lines[edit.line - 1]
        lines[edit.line - 1] = row[: edit.start] + new + row[edit.end :]
    return "\n".join(lines)


def test_renaming_a_principal_rewrites_its_declaration_and_every_use_and_nothing_else():
    line, col = at(POLICY, "reviewer", nth=0)
    result = apply(POLICY, rename(POLICY, line, col, "approver"), "approver")
    assert result.count("approver") == 3 and "reviewer" not in result
    assert "# customer is mentioned in this comment" in result  # comments are left alone
    parse(result)  # still a valid policy
    assert [f.code for f in __import__("kelvra").analysis.analyse(parse(result))] == [
        f.code for f in __import__("kelvra").analysis.analyse(parse(POLICY))
    ]


def test_renaming_one_name_does_not_touch_a_longer_name_that_contains_it():
    text = (
        "policy P\nprincipal customer, customer_vip\nsink k\n"
        "    accepts confidential(customer, customer_vip)\n"
    )
    result = apply(text, rename(text, 2, len("principal cus"), "client"), "client")
    assert "customer_vip" in result and result.count("client") == 2


def test_a_rename_is_refused_with_a_reason_when_it_would_break_the_policy():
    line, col = at(POLICY, "reviewer", nth=0)
    cases = {
        "": "not a valid name",
        "has space": "not a valid name",
        "9lives": "not a valid name",
        "to": "keyword",
        "public": "keyword",
        "customer": "already a principal",
        "support_team": "already a principal",
    }
    for new, why in cases.items():
        with pytest.raises(RenameError, match=why):
            rename(POLICY, line, col, new)
    with pytest.raises(RenameError, match="no name here"):
        rename(POLICY, 1, 0, "x")
    assert rename(POLICY, line, col, "reviewer") == []  # to the same name: nothing to do


def test_a_purpose_and_a_principal_may_share_a_name_when_renaming_each():
    text = (
        "policy P\nprincipal support\npurpose support\nsource s\n"
        "    confidential(support) for support\n"
    )
    result = apply(text, rename(text, 3, len("purpose s"), "help"), "help")
    assert result == text.replace("purpose support", "purpose help").replace(
        "for support", "for help"
    )


def test_rename_works_on_a_file_that_does_not_parse():
    text = "policy P\nprincipal a\nsource s\n    confidential(a)\n    bogus clause\n"
    result = apply(text, rename(text, 2, len("principal "), "z"), "z")
    assert "principal z" in result and "confidential(z)" in result


@settings(max_examples=120, deadline=None, suppress_health_check=list(HealthCheck))
@given(st.data())
def test_renaming_and_renaming_back_gives_the_original_text(data):
    spec = data.draw(policy_spec())
    text = render(spec)
    names = [o for o in occurrences(text) if o.space == "principal" and o.role == "decl"]
    if not names:
        return
    target = data.draw(st.sampled_from(names))
    new = "zz_renamed"
    if new in {o.name for o in occurrences(text)}:
        return
    edits = rename(text, target.line, target.start, new)
    renamed = apply(text, edits, new)
    back_edits = rename(renamed, target.line, target.start, target.name)
    assert apply(renamed, back_edits, target.name) == text
    parse(renamed)


# -- declaring what is missing --------------------------------------------------------------


def test_a_missing_principal_is_added_to_the_last_principal_line():
    text = "policy P\nprincipal a\nsource s\n    confidential(b)\n"
    assert declaration_edit(text, "b", "principal") == (2, len("principal a"), ", b")
    commented = "policy P\nprincipal a   # who\nsource s\n"
    assert declaration_edit(commented, "b", "principal") == (2, len("principal a"), ", b")


def test_with_no_principal_line_a_new_one_goes_after_policy_and_version():
    assert declaration_edit("policy P\nsource s\n", "b", "principal") == (1, 8, "\nprincipal b")
    assert declaration_edit("policy P\nversion 2\nsource s\n", "b", "principal") == (
        2, len("version 2"), "\nprincipal b",
    )  # fmt: skip
    assert declaration_edit("", "b", "principal") == (1, 0, "\nprincipal b")
    with pytest.raises(ValueError):
        declaration_edit("policy P\n", "b", "source")


def test_purposes_are_declared_on_a_purpose_line_not_a_principal_line():
    text = "policy P\nprincipal a\npurpose p\n"
    assert declaration_edit(text, "q", "purpose") == (3, len("purpose p"), ", q")


def test_the_quick_fix_applies_to_the_parsers_own_wording_and_fixes_the_file():
    text = "policy P\nprincipal a\nsource s\n    confidential(b)\n"
    with pytest.raises(KlvError) as error:
        parse(text)
    title, line, column, insert = quick_fix_for(text, error.value.message)
    assert title == "Declare principal 'b'"
    lines = text.split("\n")
    lines[line - 1] = lines[line - 1][:column] + insert + lines[line - 1][column:]
    parse("\n".join(lines))  # the error is gone
    assert quick_fix_for(text, "unknown keyword 'x' at top level") is None
    assert quick_fix_for(text, "") is None


def test_the_completion_pairs_the_server_used_to_return_are_still_returned():
    pairs = completions_for("policy P\n", 2, 0)
    assert ("source", "where data enters") in pairs and all(len(p) == 2 for p in pairs)
    assert KEYWORDS >= {"source", "accepts", "public"}
