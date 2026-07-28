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

    def add(self, message: str, line: int) -> None:
        self.items.append(f"line {line}: {message}")


# -- lexing -----------------------------------------------------------------


def _strip_comment(raw: str) -> str:
    return raw.split("#", 1)[0].rstrip()


def _scan(text: str) -> list[_Line]:
    lines: list[_Line] = []
    uses_tabs = uses_spaces = False

    for number, raw in enumerate(text.splitlines(), start=1):
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


def parse_with_warnings(text: str, *, filename: str | None = None) -> tuple[Policy, list[str]]:
    """Like :func:`parse`, but also returns non-fatal warnings."""
    try:
        lines = _scan(text)
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

    return state.policy, state.warnings.items


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
        if not line.text.startswith("policy"):
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
        if len(parts) != 2 or not parts[1].isdigit():
            raise KlvError(
                "'version' takes a single integer", line.number, line.raw, "for example: version 1"
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

        for line in self.block(header):
            clause = _keyword(line.text)
            if clause == "from":
                continue  # documentation; see spec/policy-language.md section 3
            if clause == "to":
                seen_to = True
                grants_readers, grants_endorsement = self.parse_grant(
                    line, grants_readers, grants_endorsement
                )
            elif clause == "audit":
                self.parse_audit(line)
            elif clause == "requires":
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
        for name in sorted(self.principals - self.used_principals):
            self.warnings.add(f"principal {name!r} is declared but never used", 0)
        for name in sorted(self.purposes - self.used_purposes):
            self.warnings.add(f"purpose {name!r} is declared but never used", 0)
