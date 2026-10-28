"""What an editor does with a policy beyond colouring it: suggestions, jump to definition, rename.

Pure functions of text, like the rest of the language server's logic, so they are tested without
an editor and run without ``pygls``. They work on a file that does not parse, because that is when
an editor is used most: a policy is mid-edit more often than it is valid.

Names live in two separate spaces, as in the language itself (spec/policy-language.md):
principals and purposes are declared by ``principal`` and ``purpose`` lines and *used* inside
``confidential(...)``, ``endorsed(...)``, ``consent(...)`` and after ``for``; sources, sinks and
declassifiers are declared by their header and referred to by nothing else in the file. So a name
has references only if it is a principal or a purpose, and a block's name has its declaration and
nothing more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .klv import split_lines

IDENT = r"[A-Za-z_][A-Za-z0-9_.\-]*"
_IDENT = re.compile(IDENT)
_NAME_LIST = re.compile(r"^(\s*)(principal|purpose)\b(.*)$")
_BLOCK = re.compile(rf"^(\s*)(source|sink|declassify|endorse)\s+({IDENT})")
_CONSTRUCTOR = re.compile(r"\b(confidential|endorsed|consent)\s*\(([^)]*)")
_FOR = re.compile(rf"(?<![\w.\-])for\s+({IDENT})")

KEYWORDS = frozenset(
    {
        "policy", "version", "principal", "purpose", "source", "sink", "declassify", "endorse",
        "accepts", "requires", "integrity", "from", "to", "for", "audit",
        "confidential", "endorsed", "consent", "public", "untrusted", "trusted", "always",
    }
)  # fmt: skip


@dataclass(frozen=True)
class Occurrence:
    """One place a name appears. ``line`` is 1-based, ``start``/``end`` are columns in that line."""

    line: int
    start: int
    end: int
    name: str
    space: str  # "principal", "purpose" or "block"
    role: str  # "decl" or "use"


def occurrences(text: str) -> list[Occurrence]:
    found: list[Occurrence] = []
    for number, raw in enumerate(split_lines(text), start=1):
        code = raw.split("#", 1)[0]

        def add(match: re.Match[str], offset: int, space: str, role: str, number: int = number):
            found.append(
                Occurrence(
                    number,
                    offset + match.start(),
                    offset + match.end(),
                    match.group(0),
                    space,
                    role,
                )
            )

        listed = _NAME_LIST.match(code)
        if listed:
            offset = listed.start(3)
            for name in _IDENT.finditer(listed.group(3)):
                add(name, offset, listed.group(2), "decl")
            continue
        block = _BLOCK.match(code)
        if block:
            found.append(
                Occurrence(number, block.start(3), block.end(3), block.group(3), "block", "decl")
            )
            continue
        for ctor in _CONSTRUCTOR.finditer(code):
            for name in _IDENT.finditer(ctor.group(2)):
                add(name, ctor.start(2), "principal", "use")
        for clause in _FOR.finditer(code):
            found.append(
                Occurrence(
                    number, clause.start(1), clause.end(1), clause.group(1), "purpose", "use"
                )
            )
    return found


def occurrence_at(text: str, line: int, character: int) -> Occurrence | None:
    """The name under the cursor; the cursor may sit at either edge of it."""
    for item in occurrences(text):
        if item.line == line and item.start <= character <= item.end:
            return item
    return None


def definition(text: str, line: int, character: int) -> Occurrence | None:
    """Where the name under the cursor is declared, or ``None`` if it is not (yet)."""
    here = occurrence_at(text, line, character)
    if here is None:
        return None
    for item in occurrences(text):
        if item.role == "decl" and (item.space, item.name) == (here.space, here.name):
            return item
    return None


def references(
    text: str, line: int, character: int, include_declaration: bool = True
) -> list[Occurrence]:
    here = occurrence_at(text, line, character)
    if here is None:
        return []
    return [
        item
        for item in occurrences(text)
        if (item.space, item.name) == (here.space, here.name)
        and (include_declaration or item.role == "use")
    ]


class RenameError(ValueError):
    """The rename was refused; the message says why in terms the person can act on."""


def rename(text: str, line: int, character: int, new_name: str) -> list[Occurrence]:
    """Every occurrence to rewrite as ``new_name``, or a :class:`RenameError`."""
    here = occurrence_at(text, line, character)
    if here is None:
        raise RenameError("there is no name here to rename")
    if not re.fullmatch(IDENT, new_name):
        raise RenameError(f"{new_name!r} is not a valid name (letters, digits, _, . and -)")
    if new_name in KEYWORDS:
        raise RenameError(f"{new_name!r} is a keyword of the language")
    if new_name == here.name:
        return []
    taken = {item.name for item in occurrences(text) if item.space == here.space}
    if new_name in taken:
        raise RenameError(f"{new_name!r} is already a {here.space} in this policy")
    return [
        item for item in occurrences(text) if (item.space, item.name) == (here.space, here.name)
    ]


def declaration_edit(text: str, name: str, space: str) -> tuple[int, int, str]:
    """An edit (line, column, text) that declares ``name`` as a principal or purpose.

    Added to the last ``principal`` (or ``purpose``) line if there is one, else as a new line just
    after the ``policy`` line (and ``version`` line, if present). Lines are 1-based.
    """
    if space not in ("principal", "purpose"):
        raise ValueError("only principals and purposes are declared this way")
    lines = split_lines(text)
    last = None
    for number, raw in enumerate(lines, start=1):
        listed = _NAME_LIST.match(raw.split("#", 1)[0])
        if listed and listed.group(2) == space:
            last = number
    if last is not None:
        code = lines[last - 1].split("#", 1)[0].rstrip()
        return last, len(code), f", {name}"
    after = 1
    for number, raw in enumerate(lines, start=1):
        head = raw.split("#", 1)[0].strip().split(" ", 1)[0]
        if head in ("policy", "version"):
            after = number
    return after, len(lines[after - 1]) if lines else 0, f"\n{space} {name}"


# -- suggestions -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Suggestion:
    label: str
    detail: str
    kind: str  # keyword, principal, purpose, constant, function or snippet
    insert: str | None = None  # LSP snippet syntax; ``None`` means insert the label
    documentation: str | None = None
    retrigger: bool = False  # offer the next suggestions as soon as this one is accepted


def _s(label, detail, kind, insert=None, documentation=None, retrigger=False) -> Suggestion:
    return Suggestion(label, detail, kind, insert, documentation, retrigger)


_BLOCK_OPENERS = (
    _s(
        "source",
        "where data enters",
        "snippet",
        "source ${1:inbox.imap}\n"
        "    confidential(${2:principal})\n"
        "    integrity ${3|trusted,untrusted|}",
        "A source and the label its data carries. Labels are declared, not verified.",
    ),
    _s(
        "sink",
        "where data leaves",
        "snippet",
        "sink ${1:slack.support_channel}\n    accepts confidential(${2:principal})",
        "A destination, and who it may show data to. Add `requires endorsed(...)` or "
        "`requires consent(...)` to guard it.",
    ),
    _s(
        "declassify",
        "lower confidentiality",
        "snippet",
        "declassify ${1:pii_redaction}\n"
        "    from confidential(${2:principal})\n"
        "    to   confidential(${2:principal}, ${3:principal})\n"
        "    audit always",
        "The only declared way to widen who may read. Every use is recorded.",
    ),
    _s(
        "endorse",
        "raise integrity",
        "snippet",
        "endorse ${1:human_review}\n"
        "    from untrusted\n"
        "    to   endorsed(${2:principal})\n"
        "    requires consent(${2:principal})\n"
        "    audit always",
        "A vouch for untrusted data. Without `requires consent(...)` nobody answers for it.",
    ),
    _s("principal", "declare names", "keyword", "principal ${1:name}"),
    _s("purpose", "declare purposes", "keyword", "purpose ${1:name}"),
)

_DECLASSIFY_MEMBERS = (
    _s("from", "documentation only: what this is for", "keyword", "from ", retrigger=True),
    _s("to", "what this grants", "keyword", "to   ", retrigger=True),
    _s("requires", "someone must answer for this", "keyword", "requires consent(${1:principal})"),
    _s("audit", "always", "keyword", "audit always"),
)
_MEMBERS = {
    "source": (
        _s("confidential", "readable only by these principals", "function",
           "confidential(${1:principal})"),
        _s("public", "readable by anyone", "constant"),
        _s("integrity", "trusted or untrusted", "keyword", "integrity ${1|trusted,untrusted|}"),
    ),
    "sink": (
        _s("accepts", "what this sink receives", "keyword", "accepts ", retrigger=True),
        _s("requires", "a vouch or a human decision", "keyword", "requires ", retrigger=True),
        _s("for", "the purpose this sink serves", "keyword", "for ", retrigger=True),
    ),
    "declassify": _DECLASSIFY_MEMBERS,
    "endorse": _DECLASSIFY_MEMBERS,
}  # fmt: skip

_AFTER = {
    "integrity": (
        _s("trusted", "someone vouches for it", "constant"),
        _s("untrusted", "nobody vouches for it", "constant"),
    ),
    "accepts": (
        _s("public", "any reader", "constant"),
        _s("confidential", "only these principals", "function", "confidential(${1:principal})"),
    ),
    "requires": (
        _s("endorsed", "someone must have vouched", "function", "endorsed(${1:principal})"),
        _s("consent", "a human decision, per use", "function", "consent(${1:principal})"),
    ),
    "from": (
        _s("public", "any reader", "constant"),
        _s("untrusted", "arrived from outside", "constant"),
        _s("confidential", "readable by these principals", "function",
           "confidential(${1:principal})"),
        _s("endorsed", "vouched for by these principals", "function", "endorsed(${1:principal})"),
    ),
    "to": (
        _s("public", "any reader", "constant"),
        _s("confidential", "adds these readers", "function", "confidential(${1:principal})"),
        _s("endorsed", "adds these endorsers", "function", "endorsed(${1:principal})"),
    ),
    "audit": (_s("always", "the only audit mode", "constant"),),
}  # fmt: skip


def _declared(text: str, space: str) -> list[str]:
    names = {item.name for item in occurrences(text) if item.space == space and item.role == "decl"}
    return sorted(names)


def _fill_with_declared_names(items: list[Suggestion], text: str) -> list[Suggestion]:
    """Make the placeholders in a snippet a list of the names this policy declares.

    ``${1:principal}`` becomes ``${1|customer,reviewer|}``: a drop-down of names that exist, so that
    accepting a suggestion produces something the parser accepts rather than a name to invent.
    Repeated tab stops keep one choice list each, which an editor mirrors. With nothing declared the
    placeholder stays as it is.
    """
    principals, purposes = _declared(text, "principal"), _declared(text, "purpose")

    def fill(insert: str) -> str:
        for word, names in (("principal", principals), ("purpose", purposes)):
            if names:
                choice = ",".join(names)

                def pick(match: re.Match[str], choice: str = choice) -> str:
                    return f"${{{match.group(1)}|{choice}|}}"

                insert = re.sub(r"\$\{(\d+):" + word + r"\}", pick, insert)
        return insert

    return [
        Suggestion(i.label, i.detail, i.kind, fill(i.insert) if i.insert else None,
                   i.documentation, i.retrigger)
        for i in items
    ]  # fmt: skip


def _block_kind(lines: list[str], line: int) -> str | None:
    """The kind of the block the cursor is in: the nearest unindented header above it."""
    for index in range(min(line, len(lines)) - 1, -1, -1):
        code = lines[index].split("#", 1)[0]
        if not code.strip() or code.startswith((" ", "\t")):
            continue
        head = code.strip().split(None, 1)[0]
        return head if head in _MEMBERS else None
    return None


def suggestions(text: str, line: int, character: int) -> list[Suggestion]:
    """What to offer at the cursor, from the words before it on the line and the block it is in."""
    return _fill_with_declared_names(_suggest(text, line, character), text)


def _suggest(text: str, line: int, character: int) -> list[Suggestion]:
    lines = split_lines(text)
    prefix = lines[line - 1][:character] if 1 <= line <= len(lines) else ""
    code = prefix.split("#", 1)[0]
    if "#" in prefix:
        return []  # inside a comment

    if re.search(r"(confidential|endorsed|consent)\s*\([^)]*$", code):
        return [_s(n, "declared principal", "principal") for n in _declared(text, "principal")]
    if re.search(r"(?<![\w.\-])for\s+[\w.\-]*$", code):
        return [_s(n, "declared purpose", "purpose") for n in _declared(text, "purpose")]
    if re.match(r"^\s*(principal|purpose)\b", code):
        return []  # a name being invented, not chosen
    word = re.search(r"^\s*(integrity|accepts|requires|from|to|audit)\s+[\w.\-]*$", code)
    if word:
        return list(_AFTER[word.group(1)])

    if code.startswith((" ", "\t")):
        kind = _block_kind(lines, line - 1)
        if kind == "source" and re.search(r"confidential\([^)]*\)\s+\w*$", code):
            return [_s("for", "limit to a purpose", "keyword", "for ", retrigger=True)]
        if kind in _MEMBERS:
            return list(_MEMBERS[kind])
        # Not in a known block: every clause is possible, none is certain.
        seen: dict[str, Suggestion] = {}
        for group in _MEMBERS.values():
            for item in group:
                seen.setdefault(item.label, item)
        return list(seen.values())

    if not code.strip() or re.fullmatch(r"\w+", code.strip()):
        return list(_BLOCK_OPENERS)
    return []
