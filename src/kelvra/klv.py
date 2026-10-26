"""Parser for the ``.klv`` policy language.

Implements spec/policy-language.md. Hand-written rather than generated, for
three reasons: the grammar is line-oriented with no expressions, recursion or
precedence, so a generator buys little; the core carries no third-party
dependencies and this keeps that true; and the diagnostics are the point.

That last one decides it. A policy file is read by someone who does not write
code, and a generic "unexpected token at line 12" would fail exactly the
reader this language exists for. Every error here carries a line number, the
offending text, and where possible what to do instead.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .labels import Label, PrincipalSet
from .policy import Declassifier, Policy, Sink, Source

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*$")

BLOCK_KEYWORDS = ("source", "sink", "declassify", "endorse")


class KlvError(Exception):
    """A problem in a .klv file, always located.

    Carries the line number, the offending text and, where one exists, what to
    do instead. A diagnostic without a location is a complaint, not a
    diagnostic -- see spec/policy-language.md section 4.
    """

    def __init__(self, message: str, line: int, text: str = "", hint: str = "") -> None:
        self.message = message
        self.line = line
        self.text = text
        self.hint = hint
        self.filename: str | None = None
        super().__init__(self._render())

    def _render(self) -> str:
        where = f"{self.filename}:{self.line}" if self.filename else f"line {self.line}"
        out = f"{where}: {self.message}"
        if self.text:
            out += f"\n    {self.text.strip()}"
        if self.hint:
            out += f"\n  hint: {self.hint}"
        return out

    def located_in(self, filename: str | None) -> KlvError:
        """Attach a filename. Useful when parsing many policies at once."""
        if filename is not None:
            self.filename = filename
            self.args = (self._render(),)
        return self


@dataclass
class _Line:
    number: int
    indent: int
    text: str
    raw: str


@dataclass
class _Warnings:
    items: list[str] = field(default_factory=list)
    located: list[tuple[int, str]] = field(default_factory=list)

    def add(self, message: str, line: int) -> None:
        self.items.append(f"line {line}: {message}")
        self.located.append((line, message))


# -- lexing -----------------------------------------------------------------


def _strip_comment(raw: str) -> str:
    return raw.split("#", 1)[0].rstrip()


# spec/policy-language.md section 1: lines end with LF, CRLF or (tolerated) CR,
# and nothing else. ``str.splitlines()`` also breaks on U+2028, U+2029, U+0085,
# VT, FF and the FS/GS/RS separators. A comment containing one of those would
# end early *for the parser* while most viewers still show a single comment
# line, so the text a reviewer reads would not be the text that is enforced.
_LINE_BREAK = re.compile(r"\r\n|\n|\r")

_ALLOWED_CONTROL = ("\t",)


def _forbidden_character(raw: str) -> str | None:
    """The first character that must not appear anywhere in a policy file.

    Rejected, comments included: control characters (Cc), format characters
    such as bidirectional overrides and zero-width characters (Cf), and the
    Unicode line and paragraph separators (Zl, Zp). None has a legitimate use
    in a declaration language read by humans, and each can make the rendered
    text differ from the parsed text.
    """
    for ch in raw:
        if ch in _ALLOWED_CONTROL:
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            return ch
    return None


def split_lines(text: str) -> list[str]:
    """Split on the line terminators the specification defines, and no others."""
    return _LINE_BREAK.split(text)


def _scan(text: str) -> list[_Line]:
    lines: list[_Line] = []
    uses_tabs = uses_spaces = False

    for number, raw in enumerate(split_lines(text), start=1):
        bad = _forbidden_character(raw)
        if bad is not None:
            raise KlvError(
                f"forbidden character U+{ord(bad):04X} ({unicodedata.name(bad, 'unnamed')})",
                number,
                ascii(raw),
                "control, invisible and line-separator characters are rejected even "
                "inside comments: they can make the text a reviewer sees differ from "
                "the text that is enforced",
            )
        body = _strip_comment(raw)
        if not body.strip():
            continue

        leading = body[: len(body) - len(body.lstrip())]
        if "\t" in leading:
            uses_tabs = True
        if " " in leading:
            uses_spaces = True
        if uses_tabs and uses_spaces:
            raise KlvError(
                "indentation mixes tabs and spaces",
                number,
                raw,
                "pick one and use it throughout the file; guessing here would "
                "change which clauses belong to which declaration",
            )

        lines.append(_Line(number, len(leading), body.strip(), raw))

    return lines


def _tokenise_names(inner: str, line: _Line) -> list[str]:
    names = [n.strip() for n in inner.split(",")]
    for name in names:
        if not name:
            raise KlvError("empty name in list", line.number, line.raw)
        if name == "*":
            raise KlvError(
                "'*' is not a valid name",
                line.number,
                line.raw,
                "it is reserved for the universe; a principal literally called "
                "'*' would make every label ambiguous",
            )
        if not IDENTIFIER.match(name):
            raise KlvError(f"{name!r} is not a valid identifier", line.number, line.raw)
    return names


_LEADING_WORD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)")


def _keyword(text: str) -> str:
    """The leading identifier of a clause.

    ``split()[0]`` is wrong here: on ``confidential(customer) for support`` it
    returns ``confidential(customer)``, and the clause is then never
    recognised. Stop at the first character that cannot be part of a keyword.
    """
    match = _LEADING_WORD.match(text.strip())
    return match.group(1) if match else text.strip().split()[0]


_CALL = re.compile(r"^(\w+)\s*\((.*)\)$")


def _call(text: str, line: _Line) -> tuple[str, list[str]] | None:
    """Match ``name(a, b)``. Returns None if it is not a call."""
    match = _CALL.match(text.strip())
    if not match:
        return None
    return match.group(1), _tokenise_names(match.group(2), line)


# -- parsing ----------------------------------------------------------------


def parse(text: str, *, filename: str | None = None) -> Policy:
    """Parse a ``.klv`` document into a :class:`~kelvra.policy.Policy`.

    Raises :class:`KlvError` on any problem, always with a line number.
    """
    policy, _ = parse_with_warnings(text, filename=filename)
    return policy


@dataclass(frozen=True)
class ParseResult:
    """Everything the parser learned, not just the policy.

    Tooling needs more than the domain object. An editor cannot underline a
    finding about ``sink 'crm.write'`` without knowing which line declared
    it, so the line numbers are carried out here rather than pushed into
    :class:`~kelvra.policy.Policy`, which has no business knowing about text.
    """

    policy: Policy
    warnings: list[str]
    warning_lines: list[tuple[int, str]]
    """The same warnings as ``(line, message)``, for tools that place them."""

    declaration_lines: dict[str, int]
    """Declaration name to the line it was declared on."""

    name_lines: dict[str, int]
    """Principal or purpose name to the line that declared it."""


def parse_detailed(text: str, *, filename: str | None = None) -> ParseResult:
    """Parse, and report where everything was declared."""
    try:
        # A byte-order mark is an encoding artefact some Windows editors add,
        # not content; it is the one format character tolerated, once, at the start.
        lines = _scan(text.removeprefix("\ufeff"))
        if not lines:
            raise KlvError(
                "empty policy file", 1, "", "expected 'policy <name>' on the first line"
            )

        state = _State(lines)
        state.parse_header()
        state.parse_declarations()
        state.check_unused()
    except KlvError as error:
        raise error.located_in(filename) from None

    return ParseResult(
        policy=state.policy,
        warnings=state.warnings.items,
        warning_lines=list(state.warnings.located),
        declaration_lines=dict(state.declared_at),
        name_lines=dict(state.name_lines),
    )


def parse_with_warnings(text: str, *, filename: str | None = None) -> tuple[Policy, list[str]]:
    """Like :func:`parse`, but also returns non-fatal warnings."""
    result = parse_detailed(text, filename=filename)
    return result.policy, result.warnings


def parse_file(path: str | Path) -> Policy:
    p = Path(path)
    return parse(p.read_text(encoding="utf-8"), filename=str(p))


class _State:
    """The parser proper. One pass, line-oriented, no backtracking."""

    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0
        self.policy = Policy(name="")
        self.principals: set[str] = set()
        self.purposes: set[str] = set()
        self.used_principals: set[str] = set()
        self.used_purposes: set[str] = set()
        self.declared_at: dict[str, int] = {}
        self.name_lines: dict[str, int] = {}
        self.warnings = _Warnings()

    # -- cursor ----------------------------------------------------------

    def peek(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def take(self) -> _Line:
        line = self.lines[self.pos]
        self.pos += 1
        return line

    def block(self, header: _Line) -> list[_Line]:
        body: list[_Line] = []
        while (line := self.peek()) is not None and line.indent > header.indent:
            body.append(self.take())
        return body

    # -- name resolution -------------------------------------------------

    def claim(self, name: str, line: _Line, kind: str) -> None:
        if name in self.declared_at:
            raise KlvError(
                f"{kind} {name!r} is declared twice",
                line.number,
                line.raw,
                f"first declared on line {self.declared_at[name]}",
            )
        self.declared_at[name] = line.number

    def principals_of(self, names: list[str], line: _Line) -> PrincipalSet:
        for name in names:
            if name not in self.principals:
                raise KlvError(
                    f"principal {name!r} is not declared",
                    line.number,
                    line.raw,
                    "add it to a 'principal' line -- declaring names is what turns "
                    "a typo into this error rather than a policy that silently "
                    "denies everything",
                )
            self.used_principals.add(name)
        return PrincipalSet.from_iterable(names)

    def purpose_of(self, name: str, line: _Line) -> str:
        if name not in self.purposes:
            raise KlvError(
                f"purpose {name!r} is not declared",
                line.number,
                line.raw,
                "add it to a 'purpose' line",
            )
        self.used_purposes.add(name)
        return name

    # -- header ----------------------------------------------------------

    def parse_header(self) -> None:
        line = self.peek()
        assert line is not None
        if _keyword(line.text) != "policy":
            raise KlvError(
                "a policy file must begin with 'policy <name>'",
                line.number,
                line.raw,
            )
        parts = line.text.split()
        if len(parts) != 2:
            raise KlvError("'policy' takes exactly one name", line.number, line.raw)
        self.policy.name = parts[1]
        self.take()

        while (line := self.peek()) is not None and line.indent == 0:
            keyword = _keyword(line.text)
            if keyword == "version":
                self.parse_version(self.take())
            elif keyword in ("principal", "purpose"):
                self.parse_names(self.take())
            elif keyword in BLOCK_KEYWORDS:
                return
            else:
                raise KlvError(
                    f"unknown keyword {keyword!r} at top level",
                    line.number,
                    line.raw,
                    f"expected version, principal, purpose, or one of: "
                    f"{', '.join(BLOCK_KEYWORDS)}",
                )

    def parse_version(self, line: _Line) -> None:
        parts = line.text.split()
        # ``str.isdigit()`` is true for characters such as '²' that ``int()``
        # rejects, and ``int()`` refuses very long digit strings. Both used to
        # escape as ValueError instead of a located KlvError.
        if (
            len(parts) != 2
            or not parts[1].isascii()
            or not parts[1].isdigit()
            or len(parts[1]) > 9
        ):
            raise KlvError(
                "'version' takes a single integer of at most 9 ASCII digits",
                line.number,
                line.raw,
                "for example: version 1",
            )
        self.policy.version = int(parts[1])

    def parse_names(self, line: _Line) -> None:
        keyword, _, rest = line.text.partition(" ")
        if not rest.strip():
            raise KlvError(f"'{keyword}' needs at least one name", line.number, line.raw)
        names = _tokenise_names(rest, line)
        target = self.principals if keyword == "principal" else self.purposes
        for name in names:
            if name in target:
                self.warnings.add(f"{keyword} {name!r} declared more than once", line.number)
            target.add(name)
            self.name_lines.setdefault(name, line.number)

    # -- declarations ----------------------------------------------------

    def parse_declarations(self) -> None:
        while (line := self.peek()) is not None:
            if line.indent != 0:
                raise KlvError(
                    "unexpected indented line outside a declaration",
                    line.number,
                    line.raw,
                    "clauses must sit under a source, sink, declassify or endorse header",
                )
            keyword = _keyword(line.text)
            if keyword == "source":
                self.parse_source()
            elif keyword == "sink":
                self.parse_sink()
            elif keyword in ("declassify", "endorse"):
                self.parse_declassifier()
            else:
                raise KlvError(
                    f"unknown declaration {keyword!r}",
                    line.number,
                    line.raw,
                    f"expected one of: {', '.join(BLOCK_KEYWORDS)}",
                )

    def _header_name(self, line: _Line, keyword: str) -> str:
        parts = line.text.split()
        if len(parts) != 2:
            raise KlvError(
                f"'{keyword}' takes exactly one name",
                line.number,
                line.raw,
                f"for example: {keyword} inbox.imap",
            )
        if not IDENTIFIER.match(parts[1]):
            raise KlvError(f"{parts[1]!r} is not a valid identifier", line.number, line.raw)
        return parts[1]

    # -- source ----------------------------------------------------------

    def parse_source(self) -> None:
        header = self.take()
        name = self._header_name(header, "source")
        self.claim(name, header, "source")

        readers: PrincipalSet | None = None
        purposes = PrincipalSet.all()
        endorsers = PrincipalSet.all()
        seen_confidentiality = False
        seen_integrity = False

        for line in self.block(header):
            keyword = _keyword(line.text)
            if keyword in ("public", "confidential"):
                if seen_confidentiality:
                    raise KlvError(
                        f"source {name!r} declares confidentiality twice",
                        line.number,
                        line.raw,
                        "a source carries exactly one confidentiality label",
                    )
                seen_confidentiality = True
                readers, purposes = self.parse_confidentiality(line)
            elif keyword == "integrity":
                if seen_integrity:
                    raise KlvError(
                        f"source {name!r} declares integrity twice",
                        line.number,
                        line.raw,
                        "a source carries exactly one integrity label; letting the last "
                        "one win would let a later line quietly undo 'untrusted'",
                    )
                seen_integrity = True
                endorsers = self.parse_integrity(line)
            else:
                raise KlvError(
                    f"unknown clause {keyword!r} in source {name!r}",
                    line.number,
                    line.raw,
                    "a source accepts: public, confidential(...), integrity",
                )

        if readers is None:
            raise KlvError(
                f"source {name!r} declares no confidentiality",
                header.number,
                header.raw,
                "add 'public' or 'confidential(...)'; an unlabelled source is "
                "the failure this whole system exists to prevent",
            )

        if not seen_integrity:
            self.warnings.add(
                f"source {name!r} declares no integrity and defaults to trusted; "
                "say 'integrity trusted' or 'integrity untrusted' so the choice is visible",
                header.number,
            )
        self.policy.sources[name] = Source(name, Label(readers, endorsers, purposes))

    def parse_confidentiality(self, line: _Line) -> tuple[PrincipalSet, PrincipalSet]:
        text = line.text
        purposes = PrincipalSet.all()

        head, sep, tail = text.partition(" for ")
        if sep:
            purpose = tail.strip()
            if " " in purpose:
                raise KlvError("'for' takes a single purpose", line.number, line.raw)
            purposes = PrincipalSet.of(self.purpose_of(purpose, line))
            text = head.strip()

        if text.strip() == "public":
            return PrincipalSet.all(), purposes

        call = _call(text, line)
        if call is None or call[0] != "confidential":
            raise KlvError(
                "expected 'public' or 'confidential(...)'",
                line.number,
                line.raw,
            )
        return self.principals_of(call[1], line), purposes

    def parse_integrity(self, line: _Line) -> PrincipalSet:
        parts = line.text.split()
        if len(parts) != 2 or parts[1] not in ("trusted", "untrusted"):
            raise KlvError(
                "'integrity' takes 'trusted' or 'untrusted'",
                line.number,
                line.raw,
                "to name specific endorsers on a sink, use 'requires endorsed(...)'",
            )
        return PrincipalSet.all() if parts[1] == "trusted" else PrincipalSet.none()

    # -- sink ------------------------------------------------------------

    def parse_sink(self) -> None:
        header = self.take()
        name = self._header_name(header, "sink")
        self.claim(name, header, "sink")

        audience: PrincipalSet | None = None
        endorsement = PrincipalSet.none()
        purpose: str | None = None
        consent: str | None = None

        for line in self.block(header):
            keyword = _keyword(line.text)
            if keyword == "accepts":
                if audience is not None:
                    raise KlvError(
                        f"sink {name!r} declares 'accepts' twice", line.number, line.raw
                    )
                audience = self.parse_audience(line)
            elif keyword == "requires":
                endorsement, consent = self.parse_requirement(line, endorsement, consent)
            elif keyword == "for":
                parts = line.text.split()
                if len(parts) != 2:
                    raise KlvError("'for' takes a single purpose", line.number, line.raw)
                if purpose is not None:
                    raise KlvError(
                        f"sink {name!r} declares 'for' twice",
                        line.number,
                        line.raw,
                        "a sink serves exactly one purpose",
                    )
                purpose = self.purpose_of(parts[1], line)
            else:
                raise KlvError(
                    f"unknown clause {keyword!r} in sink {name!r}",
                    line.number,
                    line.raw,
                    "a sink accepts: accepts, requires, for",
                )

        if audience is None:
            raise KlvError(
                f"sink {name!r} declares no 'accepts'",
                header.number,
                header.raw,
                "add 'accepts public' or 'accepts confidential(...)'; without it "
                "there is nothing to check a flow against",
            )

        self.policy.sinks[name] = Sink(
            name,
            audience=audience,
            requires_endorsement=endorsement,
            purpose=purpose,
            requires_consent_from=consent,
        )

    def parse_audience(self, line: _Line) -> PrincipalSet:
        rest = line.text[len("accepts") :].strip()
        if rest == "public":
            return PrincipalSet.all()
        call = _call(rest, line)
        if call is None or call[0] != "confidential":
            raise KlvError(
                "'accepts' takes 'public' or 'confidential(...)'",
                line.number,
                line.raw,
            )
        return self.principals_of(call[1], line)

    def parse_requirement(
        self, line: _Line, endorsement: PrincipalSet, consent: str | None
    ) -> tuple[PrincipalSet, str | None]:
        rest = line.text[len("requires") :].strip()

        if rest.startswith("integrity"):
            raise KlvError(
                "'requires integrity' is not part of the language",
                line.number,
                line.raw,
                "name the endorser instead: 'requires endorsed(reviewer)'. "
                "'trusted' alone does not say trusted by whom",
            )

        call = _call(rest, line)
        if call is None:
            raise KlvError(
                "'requires' takes endorsed(...) or consent(...)",
                line.number,
                line.raw,
            )
        kind, names = call
        if kind == "endorsed":
            return endorsement | self.principals_of(names, line), consent
        if kind == "consent":
            if len(names) != 1:
                raise KlvError(
                    "'consent' takes exactly one principal", line.number, line.raw
                )
            if consent is not None:
                raise KlvError(
                    "a second 'requires consent' on the same declaration",
                    line.number,
                    line.raw,
                    f"consent from {consent!r} is already required here; only one "
                    "consenting principal is supported, and keeping the last one "
                    "would silently drop the other",
                )
            self.principals_of(names, line)
            return endorsement, names[0]
        raise KlvError(
            f"unknown requirement {kind!r}",
            line.number,
            line.raw,
            "expected endorsed(...) or consent(...)",
        )

    # -- declassifier ----------------------------------------------------

    def parse_declassifier(self) -> None:
        header = self.take()
        keyword = _keyword(header.text)
        name = self._header_name(header, keyword)
        self.claim(name, header, keyword)

        grants_readers = PrincipalSet.none()
        grants_endorsement = PrincipalSet.none()
        consent: str | None = None
        seen_to = False
        expects: Label | None = None

        for line in self.block(header):
            clause = _keyword(line.text)
            if clause == "from":
                # Documentation, not enforcement (spec/policy-language.md
                # section 3) -- but it is read, so a typo in it is an error and
                # a use outside it can be recorded.
                bound = self.parse_from(line)
                expects = bound if expects is None else expects.join(bound)
            elif clause == "to":
                seen_to = True
                grants_readers, grants_endorsement = self.parse_grant(
                    line, grants_readers, grants_endorsement
                )
            elif clause == "audit":
                self.parse_audit(line)
            elif clause == "requires":
                asked = _call(line.text[len("requires") :].strip(), line)
                if asked is not None and asked[0] == "endorsed":
                    raise KlvError(
                        f"'requires endorsed(...)' has no effect in {keyword} {name!r}",
                        line.number,
                        line.raw,
                        "a declassifier cannot demand an endorsement of its input; put "
                        "'requires endorsed(...)' on the sink that needs it, or "
                        "'requires consent(...)' here",
                    )
                _, consent = self.parse_requirement(line, PrincipalSet.none(), consent)
            else:
                raise KlvError(
                    f"unknown clause {clause!r} in {keyword} {name!r}",
                    line.number,
                    line.raw,
                    "expected: from, to, audit, requires",
                )

        if not seen_to:
            raise KlvError(
                f"{keyword} {name!r} declares no 'to'",
                header.number,
                header.raw,
                "'to' is what the construct grants; without it it grants nothing "
                "and the declaration has no effect",
            )

        if keyword == "declassify" and grants_readers.is_empty:
            self.warnings.add(
                f"declassify {name!r} grants no readers -- did you mean 'endorse'?",
                header.number,
            )
        if keyword == "endorse" and grants_endorsement.is_empty:
            self.warnings.add(
                f"endorse {name!r} grants no endorsement -- did you mean 'declassify'?",
                header.number,
            )

        self.policy.declassifiers[name] = Declassifier(
            name=name,
            grants_readers=grants_readers,
            grants_endorsement=grants_endorsement,
            requires_consent_from=consent,
            expects=expects,
        )

    def parse_from(self, line: _Line) -> Label:
        """``from`` as an upper bound on the data: at least this restrictive."""
        rest = line.text[len("from") :].strip()
        if rest == "public":
            return Label()
        if rest == "untrusted":
            return Label(endorsers=PrincipalSet.none())
        call = _call(rest, line)
        if call is not None and call[0] == "confidential":
            return Label(readers=self.principals_of(call[1], line))
        if call is not None and call[0] == "endorsed":
            return Label(endorsers=self.principals_of(call[1], line))
        raise KlvError(
            "'from' takes public, untrusted, confidential(...) or endorsed(...)",
            line.number,
            line.raw,
        )

    def parse_grant(
        self, line: _Line, readers: PrincipalSet, endorsement: PrincipalSet
    ) -> tuple[PrincipalSet, PrincipalSet]:
        rest = line.text[len("to") :].strip()
        if rest == "public":
            return PrincipalSet.all(), endorsement

        call = _call(rest, line)
        if call is None:
            raise KlvError(
                "'to' takes public, confidential(...) or endorsed(...)",
                line.number,
                line.raw,
            )
        kind, names = call
        if kind == "confidential":
            return readers | self.principals_of(names, line), endorsement
        if kind == "endorsed":
            return readers, endorsement | self.principals_of(names, line)
        raise KlvError(
            f"cannot grant {kind!r}",
            line.number,
            line.raw,
            "expected confidential(...) or endorsed(...)",
        )

    def parse_audit(self, line: _Line) -> None:
        parts = line.text.split()
        if len(parts) != 2 or parts[1] != "always":
            raise KlvError(
                "'audit' accepts only 'always'",
                line.number,
                line.raw,
                "every declassification is recorded regardless; a word that "
                "promises otherwise would be a lie in the file",
            )

    # -- post-parse checks -----------------------------------------------

    def check_unused(self) -> None:
        # Point at the line that declared the name. "line 0" is not a location,
        # and an editor cannot underline it.
        for name in sorted(self.principals - self.used_principals):
            self.warnings.add(
                f"principal {name!r} is declared but never used", self.name_lines.get(name, 1)
            )
        for name in sorted(self.purposes - self.used_purposes):
            self.warnings.add(
                f"purpose {name!r} is declared but never used", self.name_lines.get(name, 1)
            )
