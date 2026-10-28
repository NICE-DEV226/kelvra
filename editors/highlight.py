"""Colour .klv text with the editor's own grammar, without an editor.

    python editors/highlight.py examples/support_agent/policy.klv --svg out.svg
    python editors/highlight.py examples/support_agent/policy.klv --ansi

GitHub does not know what ``.klv`` is, a browser cannot run a TextMate grammar, and a test cannot
start VS Code. This reads ``vscode/syntaxes/klv.tmLanguage.json``, the grammar the extension ships,
and applies it with a small TextMate engine of its own: ``match`` and ``begin``/``end`` rules,
``include``, and ``captures`` that carry their own patterns. That is the whole of what the grammar
uses. One grammar, so the colours in the editor, in the README image, in the demo page and in the
tests cannot drift apart.

It is not a general TextMate implementation. Where it could differ from Oniguruma (the engine the
editor uses) is regular-expression syntax; the grammar sticks to the subset Python reads the same
way, and ``tests/test_klv_highlighting.py`` says what was compared against the real engine.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

GRAMMAR = Path(__file__).resolve().parent / "vscode" / "syntaxes" / "klv.tmLanguage.json"
ROOT_SCOPE = "source.klv"

# scope prefix -> class, most specific first
CLASSES = (
    ("comment", "comment"),
    ("keyword.control", "keyword"),
    ("entity.name", "name"),
    ("keyword.other.directive", "directive"),
    ("support.function", "function"),
    ("variable.parameter.principal", "principal"),
    ("variable.other.purpose", "purpose"),
    ("constant.language", "constant"),
    ("constant.numeric", "number"),
    ("punctuation", "punctuation"),
)

# GitHub's dark palette. The picture carries its own background, so it reads on either theme.
PALETTE = {
    "background": "#0d1117",
    "border": "#30363d",
    "text": "#e6edf3",
    "comment": "#8b949e",
    "keyword": "#ff7b72",
    "name": "#d2a8ff",
    "directive": "#79c0ff",
    "function": "#ffa657",
    "principal": "#7ee787",
    "purpose": "#e3b341",
    "constant": "#56d4dd",
    "number": "#79c0ff",
    "punctuation": "#8b949e",
}
ANSI = {
    "comment": "90", "keyword": "1;31", "name": "35", "directive": "36", "function": "33",
    "principal": "32", "purpose": "93", "constant": "96", "number": "34", "punctuation": "90",
}  # fmt: skip

Span = tuple[int, int, tuple[str, ...]]


class Grammar:
    def __init__(self, path: Path = GRAMMAR) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        self.repository: dict = data["repository"]
        self.root = self._resolve(data["patterns"])
        self._regex: dict[str, re.Pattern[str]] = {}

    def _resolve(self, patterns: list[dict]) -> list[dict]:
        out: list[dict] = []
        for pattern in patterns:
            if "include" in pattern:
                name = pattern["include"].removeprefix("#")
                target = self.repository[name]
                out.extend(
                    self._resolve(target["patterns"])
                    if "patterns" in target and not ("match" in target or "begin" in target)
                    else [target]
                )
            else:
                out.append(pattern)
        return out

    def regex(self, source: str) -> re.Pattern[str]:
        if source not in self._regex:
            self._regex[source] = re.compile(source)
        return self._regex[source]


def _paint(scopes: list[tuple[str, ...]], start: int, end: int, value: tuple[str, ...]) -> None:
    for index in range(start, end):
        scopes[index] = value


def _earliest(grammar: Grammar, line: str, pos: int, candidates: list[tuple[dict, str]]):
    best = None
    for order, (rule, kind) in enumerate(candidates):
        source = rule["end"] if kind == "end" else rule.get("match") or rule["begin"]
        match = grammar.regex(source).search(line, pos)
        if match is None:
            continue
        key = (match.start(), 0 if kind == "end" else 1, order)
        if best is None or key < best[0]:
            best = (key, rule, kind, match)
    return best


def _apply_captures(grammar, line, match, captures, base, scopes) -> None:
    for group, capture in sorted(captures.items(), key=lambda item: int(item[0])):
        start, end = match.span(int(group))
        if start < 0 or start == end:
            continue
        inner = base + ((capture["name"],) if "name" in capture else ())
        _paint(scopes, start, end, inner)
        if "patterns" in capture:
            nested = grammar._resolve(capture["patterns"])
            _tokenise_range(grammar, line[:end], start, nested, inner, scopes)


def _tokenise_range(grammar, line, pos, patterns, base, scopes) -> None:
    """Apply plain ``match`` patterns over line[pos:], painting into ``scopes``."""
    candidates = [(p, "match") for p in patterns if "match" in p]
    while pos < len(line):
        found = _earliest(grammar, line, pos, candidates)
        if found is None:
            return
        _, rule, _, match = found
        value = base + ((rule["name"],) if "name" in rule else ())
        if match.end() == match.start():
            pos = match.end() + 1
            continue
        _paint(scopes, match.start(), match.end(), value)
        _apply_captures(grammar, line, match, rule.get("captures", {}), base, scopes)
        pos = match.end()


def tokenize_line(grammar: Grammar, line: str, stack: list[dict]) -> tuple[list[Span], list[dict]]:
    """One line: its spans, and the rules still open at its end."""
    stack = list(stack)
    scopes: list[tuple[str, ...]] = [(ROOT_SCOPE,)] * len(line)

    def active() -> tuple[str, ...]:
        names = [ROOT_SCOPE]
        for frame in stack:
            names += [n for n in (frame.get("name"), frame.get("contentName")) if n]
        return tuple(names)

    pos = 0
    while pos < len(line):
        patterns = (
            grammar._resolve(stack[-1]["patterns"])
            if stack and "patterns" in stack[-1]
            else ([] if stack else grammar.root)
        )
        candidates = [(p, "begin" if "begin" in p else "match") for p in patterns]
        if stack:
            candidates.insert(0, (stack[-1], "end"))
        found = _earliest(grammar, line, pos, candidates)
        if found is None:
            _paint(scopes, pos, len(line), active())
            break
        _, rule, kind, match = found
        _paint(scopes, pos, match.start(), active())
        if kind == "end":
            value = active()
            _paint(scopes, match.start(), match.end(), value)
            _apply_captures(grammar, line, match, rule.get("endCaptures", {}), value, scopes)
            stack.pop()
        elif kind == "begin":
            value = active() + ((rule["name"],) if "name" in rule else ())
            _paint(scopes, match.start(), match.end(), value)
            _apply_captures(grammar, line, match, rule.get("beginCaptures", {}), active(), scopes)
            stack.append(rule)
        else:
            value = active() + ((rule["name"],) if "name" in rule else ())
            _paint(scopes, match.start(), match.end(), value)
            _apply_captures(grammar, line, match, rule.get("captures", {}), active(), scopes)
        pos = match.end() if match.end() > match.start() else match.end() + 1
    runs: list[Span] = []
    for index, value in enumerate(scopes):
        if runs and runs[-1][2] == value and runs[-1][1] == index:
            runs[-1] = (runs[-1][0], index + 1, value)
        else:
            runs.append((index, index + 1, value))
    return runs, stack


_GRAMMAR: Grammar | None = None


def grammar() -> Grammar:
    global _GRAMMAR
    if _GRAMMAR is None:
        _GRAMMAR = Grammar()
    return _GRAMMAR


def tokenize(text: str) -> list[list[tuple[str, tuple[str, ...]]]]:
    """Per line, a list of (text, scopes). Lines split as the parser splits them: LF, CRLF, CR."""
    g = grammar()
    stack: list[dict] = []
    out = []
    for line in re.split(r"\r\n|\n|\r", text):
        runs, stack = tokenize_line(g, line, stack)
        out.append([(line[a:b], scopes) for a, b, scopes in runs])
    return out


def classify(scopes: tuple[str, ...]) -> str:
    """The colour class of a token: the last scope that has one, or ``""`` for plain text."""
    for scope in reversed(scopes):
        for prefix, name in CLASSES:
            if scope == prefix or scope.startswith(prefix + "."):
                return name
    return ""


def classes(text: str) -> list[list[tuple[str, str]]]:
    """Per line, (class, text) pairs with neighbouring tokens of one class merged."""
    lines = []
    for line in tokenize(text):
        merged: list[tuple[str, str]] = []
        for piece, scopes in line:
            name = classify(scopes)
            if merged and merged[-1][0] == name:
                merged[-1] = (name, merged[-1][1] + piece)
            else:
                merged.append((name, piece))
        lines.append(merged)
    return lines


def to_ansi(text: str) -> str:
    out = []
    for line in classes(text):
        out.append(
            "".join(
                f"\x1b[{ANSI[name]}m{piece}\x1b[0m" if name and piece.strip() else piece
                for name, piece in line
            )
        )
    return "\n".join(out)


CHAR_WIDTH = 8.4  # at 14px in a monospace face; the picture does not depend on it being exact
LINE_HEIGHT = 20
PAD = 16


def to_svg(text: str, label: str = "A Kelvra policy") -> str:
    """A picture of the text, coloured. Self-contained: no font file, no script, no link."""
    rows = [[(n, p.expandtabs(4)) for n, p in line] for line in classes(text.rstrip("\n"))]
    widest = max((sum(len(p) for _, p in row) for row in rows), default=0)
    width = round(2 * PAD + widest * CHAR_WIDTH)
    height = 2 * PAD + len(rows) * LINE_HEIGHT
    quoted = escape(label, {'"': "&quot;"})
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{quoted}">',
        f"<title>{escape(label)}</title>",
        f'<rect width="{width}" height="{height}" rx="8" fill="{PALETTE["background"]}" '
        f'stroke="{PALETTE["border"]}"/>',
        f'<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="14" '
        f'fill="{PALETTE["text"]}">',
    ]
    for number, row in enumerate(rows):
        y = PAD + (number + 1) * LINE_HEIGHT - 6
        spans = []
        column = 0
        for name, piece in row:
            if piece.strip():
                # Every visible piece is placed at its own column. Leading and repeated spaces are
                # not relied on: renderers collapse them, and indentation and alignment are layout.
                left = len(piece) - len(piece.lstrip())
                x = round(PAD + (column + left) * CHAR_WIDTH, 1)
                shown = piece.strip(" ")
                attrs = f' x="{x}"'
                if name:
                    attrs += f' fill="{PALETTE[name]}"'
                    attrs += ' font-style="italic"' if name == "comment" else ""
                    attrs += ' font-weight="bold"' if name == "keyword" else ""
                spans.append(f"<tspan{attrs}>{escape(shown)}</tspan>")
            column += len(piece)
        if spans:
            out.append(f'<text y="{y}">{"".join(spans)}</text>')
    out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", type=Path)
    parser.add_argument("--svg", type=Path, help="write a coloured SVG here")
    parser.add_argument("--ansi", action="store_true", help="print with terminal colours")
    parser.add_argument("--label", default="A Kelvra policy")
    parser.add_argument(
        "--lines", help="only these lines, 1-based and inclusive, for example 18-70"
    )
    args = parser.parse_args(argv)
    text = args.file.read_text(encoding="utf-8")
    if args.lines:
        first, _, last = args.lines.partition("-")
        text = "\n".join(text.split("\n")[int(first) - 1 : int(last)])
    if args.svg:
        args.svg.write_text(to_svg(text, args.label), encoding="utf-8")
        print(f"wrote {args.svg}")
    if args.ansi or not args.svg:
        print(to_ansi(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
