"""Language server for ``.klv``.

One protocol, every editor. Without it Kelvra would need a VS Code plugin,
then a Neovim one, then Zed, Helix, Emacs -- with it there is one server and
any editor that speaks LSP can use it.

What it changes for this project specifically: ``kelvra check`` assumes you
remember to run it, so the gap between writing a mistake and seeing it is
"whenever CI runs". Here the finding appears under the offending line as it
is typed. And hovering a sink answers the question a reviewer actually has --
*who can reach this?* -- which is the reachability analysis surfaced at the
cursor rather than buried in a report.

Structure
---------
Everything below the protocol boundary is a pure function of text: they take
a document and return diagnostics, hover text or symbols, and they import
nothing. The pygls handlers at the bottom are adapters and contain no logic,
which is what makes the interesting half testable without a client -- and
what would make a different transport cheap.

pygls is an optional dependency (``pip install kelvra[lsp]``). The core has
none, and this module does not change that: the pure functions here work
without it, and the import only happens inside :func:`serve`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .analysis import analyse
from .klv import KlvError, parse_detailed
from .policy import Policy, check_flow

DiagnosticSeverity = Literal["error", "warning", "information"]

# `subject` on a Finding reads like "sink 'crm.write'". Recovering the bare
# name is what lets a finding be attached to the line that declared it.
_SUBJECT = re.compile(r"^(?:\w+)\s+'([^']+)'$")

_DECLARATION = re.compile(r"^(source|sink|declassify|endorse)\s+([\w.-]+)")


@dataclass(frozen=True)
class Diagnostic:
    """A finding placed on a line. Lines and columns are 1-based here.

    LSP counts from zero and measures columns in UTF-16 code units; the
    conversion happens at the protocol boundary, not in this half, so that
    the pure functions stay readable and testable in ordinary terms.
    """

    line: int
    severity: DiagnosticSeverity
    code: str
    message: str
    hint: str = ""

    @property
    def full_message(self) -> str:
        return f"{self.message}\n\nhint: {self.hint}" if self.hint else self.message


def _subject_name(subject: str) -> str | None:
    match = _SUBJECT.match(subject)
    return match.group(1) if match else None


def diagnostics_for(text: str, *, filename: str | None = None) -> list[Diagnostic]:
    """Everything wrong with a document: parse errors, then policy findings.

    A parse error stops the analysis -- there is no policy to analyse -- so
    the two never appear together. That is deliberate: reporting speculative
    findings against a half-parsed file would break the soundness contract
    the analysis promises.
    """
    try:
        result = parse_detailed(text, filename=filename)
    except KlvError as error:
        return [
            Diagnostic(
                line=error.line,
                severity="error",
                code="syntax",
                message=error.message,
                hint=error.hint,
            )
        ]

    diagnostics: list[Diagnostic] = []

    for warning in result.warnings:
        line, _, message = warning.partition(": ")
        number = int(line.removeprefix("line ")) if line.startswith("line ") else 1
        diagnostics.append(
            Diagnostic(
                line=max(number, 1),
                severity="warning",
                code="policy",
                message=message or warning,
            )
        )

    for finding in analyse(result.policy):
        name = _subject_name(finding.subject)
        diagnostics.append(
            Diagnostic(
                line=result.declaration_lines.get(name or "", 1),
                severity="error" if finding.severity == "error" else "warning",
                code=finding.code,
                message=f"{finding.subject}: {finding.message}",
                hint=finding.hint,
            )
        )

    return sorted(diagnostics, key=lambda d: (d.line, d.code))


# -- hover ------------------------------------------------------------------


def word_at(text: str, line: int, character: int) -> str | None:
    """The identifier under a 1-based line and 0-based character offset."""
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return None
    source = lines[line - 1]
    if not 0 <= character <= len(source):
        return None

    for match in re.finditer(r"[A-Za-z_][\w.-]*", source):
        if match.start() <= character <= match.end():
            return match.group(0)
    return None


def hover_at(text: str, line: int, character: int) -> str | None:
    """Markdown describing whatever is under the cursor.

    The sink case is the one that matters: it answers *who can reach this*,
    which is the question a reviewer opens the file to ask.
    """
    word = word_at(text, line, character)
    if word is None:
        return None

    try:
        result = parse_detailed(text)
    except KlvError:
        return None

    policy = result.policy

    if word in policy.sinks:
        return _describe_sink(policy, word)
    if word in policy.sources:
        return _describe_source(policy, word)
    if word in policy.declassifiers:
        return _describe_declassifier(policy, word)
    if word in result.name_lines:
        return _describe_name(policy, word, result.name_lines[word])
    return None


def _describe_sink(policy: Policy, name: str) -> str:
    sink = policy.sinks[name]
    lines = [f"**sink `{name}`**", "", f"- accepts: `{sink.audience!r}`"]
    if not sink.requires_endorsement.is_empty:
        lines.append(f"- requires endorsement by: `{sink.requires_endorsement!r}`")
    if sink.requires_consent_from:
        lines.append(f"- requires consent from: `{sink.requires_consent_from}`")
    if sink.purpose:
        lines.append(f"- purpose: `{sink.purpose}`")

    direct, indirect = [], []
    for source_name, source in sorted(policy.sources.items()):
        if check_flow(source.label, sink).allowed:
            direct.append(source_name)
        elif _reachable(policy, source.label, name):
            indirect.append(source_name)

    lines.append("")
    if not direct and not indirect:
        lines.append("**Unreachable.** No declared source can satisfy this sink.")
    else:
        lines.append("**Reachable by**")
        for n in direct:
            lines.append(f"- `{n}` (directly)")
        for n in indirect:
            lines.append(f"- `{n}` (after declassification)")

    untrusted = [n for n in direct + indirect if policy.sources[n].label.is_untrusted]
    if untrusted and sink.requires_endorsement.is_empty and not sink.requires_consent_from:
        lines += [
            "",
            "⚠ Untrusted data reaches this sink with nothing in the way. "
            "If it takes an action rather than recording one, injected content can drive it.",
        ]
    return "\n".join(lines)


def _reachable(policy: Policy, label, sink_name: str) -> bool:
    from .analysis import _most_permissive

    return check_flow(_most_permissive(label, policy), policy.sinks[sink_name]).allowed


def _describe_source(policy: Policy, name: str) -> str:
    source = policy.sources[name]
    lines = [f"**source `{name}`**", "", f"- label: `{source.label.describe()}`"]
    if source.label.is_untrusted:
        lines.append("- **untrusted** — nothing vouches for this data")

    reaches = sorted(
        s for s in policy.sinks if _reachable(policy, source.label, s)
    )
    lines.append("")
    lines.append(
        "**Can reach** " + ", ".join(f"`{s}`" for s in reaches)
        if reaches
        else "**Reaches nothing.** No declared sink accepts this data."
    )
    lines += [
        "",
        "_Source labels are declarative and unverified — nothing checks that this is true._",
    ]
    return "\n".join(lines)


def _describe_declassifier(policy: Policy, name: str) -> str:
    d = policy.declassifiers[name]
    grants = []
    if not d.grants_readers.is_empty:
        grants.append(f"readers `{d.grants_readers!r}`")
    if not d.grants_endorsement.is_empty:
        grants.append(f"endorsement by `{d.grants_endorsement!r}`")

    lines = [f"**declassifier `{name}`**", "", f"- grants: {' and '.join(grants) or 'nothing'}"]
    if d.requires_consent_from:
        lines.append(f"- requires consent from: `{d.requires_consent_from}`")
    lines += [
        "",
        "One of the only places a leak is possible in this policy. "
        "Kelvra records every use; it cannot check that the transformation is correct.",
    ]
    return "\n".join(lines)


def _describe_name(policy: Policy, name: str, declared_line: int) -> str:
    reads = sorted(s for s, sink in policy.sinks.items() if name in sink.audience)
    holds = sorted(s for s, src in policy.sources.items() if name in src.label.readers)

    lines = [f"**principal `{name}`**", "", f"declared on line {declared_line}"]
    if holds:
        lines.append("")
        lines.append("May read data from " + ", ".join(f"`{s}`" for s in holds))
    if reads:
        lines.append("")
        lines.append("In the audience of " + ", ".join(f"`{s}`" for s in reads))
    return "\n".join(lines)


# -- symbols and completion -------------------------------------------------


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    line: int


def symbols_for(text: str) -> list[Symbol]:
    """The document outline. Works on unparseable files, by design.

    An outline that vanishes the moment a file has a syntax error is an
    outline that disappears exactly when you are lost in the file.
    """
    symbols = []
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _DECLARATION.match(raw.split("#", 1)[0].strip())
        if match:
            symbols.append(Symbol(name=match.group(2), kind=match.group(1), line=number))
    return symbols


def completions_for(text: str, line: int, character: int) -> list[tuple[str, str]]:
    """``(label, detail)`` pairs for the cursor position."""
    lines = text.splitlines()
    prefix = lines[line - 1][:character] if 1 <= line <= len(lines) else ""

    try:
        result = parse_detailed(text)
        known = sorted(result.name_lines)
    except KlvError:
        known = sorted(set(re.findall(r"^(?:principal|purpose)\s+(.+)$", text, re.MULTILINE)))
        known = sorted({n.strip() for line_ in known for n in line_.split(",")})

    if re.search(r"(confidential|endorsed|consent)\s*\([^)]*$", prefix):
        return [(name, "declared principal") for name in known]

    # Indentation is checked before emptiness, and the order matters: an
    # indented blank line is blank *and* indented, and offering top-level
    # declarations inside a block would be exactly wrong there.
    if prefix.startswith((" ", "\t")):
        return [
            ("accepts", "what this sink receives"),
            ("requires", "endorsed(...) or consent(...)"),
            ("integrity", "trusted or untrusted"),
            ("confidential", "confidential(a, b)"),
            ("public", "readable by anyone"),
            ("from", "documentation only"),
            ("to", "what this grants"),
            ("audit", "always"),
        ]

    if not prefix.strip():
        return [
            ("source", "where data enters"),
            ("sink", "where data leaves"),
            ("declassify", "lower confidentiality"),
            ("endorse", "raise integrity"),
            ("principal", "declare names"),
            ("purpose", "declare purposes"),
        ]
    return []


# -- the protocol boundary --------------------------------------------------


def serve() -> int:
    """Run the server on stdio. Requires ``pip install kelvra[lsp]``."""
    try:
        from lsprotocol import types as lsp
        from pygls.lsp.server import LanguageServer
    except ImportError:  # pragma: no cover - depends on optional extra
        print(
            "the language server needs pygls: pip install 'kelvra[lsp]'",
            file=__import__("sys").stderr,
        )
        return 1

    from . import __version__

    server = LanguageServer("kelvra", __version__)

    _SEVERITY = {
        "error": lsp.DiagnosticSeverity.Error,
        "warning": lsp.DiagnosticSeverity.Warning,
        "information": lsp.DiagnosticSeverity.Information,
    }
    _KIND = {
        "source": lsp.SymbolKind.Field,
        "sink": lsp.SymbolKind.Method,
        "declassify": lsp.SymbolKind.Function,
        "endorse": lsp.SymbolKind.Function,
    }

    def publish(uri: str) -> None:
        text = server.workspace.get_text_document(uri).source
        server.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=uri,
                diagnostics=[
                    lsp.Diagnostic(
                        range=lsp.Range(
                            start=lsp.Position(line=max(d.line - 1, 0), character=0),
                            end=lsp.Position(line=max(d.line - 1, 0), character=10_000),
                        ),
                        severity=_SEVERITY[d.severity],
                        code=d.code,
                        source="kelvra",
                        message=d.full_message,
                    )
                    for d in diagnostics_for(text, filename=uri)
                ],
            )
        )

    @server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    @server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    @server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def _on_change(params) -> None:
        publish(params.text_document.uri)

    @server.feature(lsp.TEXT_DOCUMENT_HOVER)
    def _on_hover(params):
        text = server.workspace.get_text_document(params.text_document.uri).source
        markdown = hover_at(text, params.position.line + 1, params.position.character)
        if markdown is None:
            return None
        return lsp.Hover(
            contents=lsp.MarkupContent(kind=lsp.MarkupKind.Markdown, value=markdown)
        )

    @server.feature(lsp.TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    def _on_symbols(params):
        text = server.workspace.get_text_document(params.text_document.uri).source
        return [
            lsp.DocumentSymbol(
                name=symbol.name,
                kind=_KIND.get(symbol.kind, lsp.SymbolKind.Variable),
                detail=symbol.kind,
                range=lsp.Range(
                    start=lsp.Position(line=symbol.line - 1, character=0),
                    end=lsp.Position(line=symbol.line - 1, character=10_000),
                ),
                selection_range=lsp.Range(
                    start=lsp.Position(line=symbol.line - 1, character=0),
                    end=lsp.Position(line=symbol.line - 1, character=10_000),
                ),
            )
            for symbol in symbols_for(text)
        ]

    @server.feature(
        lsp.TEXT_DOCUMENT_COMPLETION,
        lsp.CompletionOptions(trigger_characters=["(", ",", " "]),
    )
    def _on_completion(params):
        text = server.workspace.get_text_document(params.text_document.uri).source
        return lsp.CompletionList(
            is_incomplete=False,
            items=[
                lsp.CompletionItem(label=label, detail=detail)
                for label, detail in completions_for(
                    text, params.position.line + 1, params.position.character
                )
            ],
        )

    server.start_io()
    return 0


__all__ = [
    "Diagnostic",
    "Symbol",
    "completions_for",
    "diagnostics_for",
    "hover_at",
    "serve",
    "symbols_for",
    "word_at",
]
