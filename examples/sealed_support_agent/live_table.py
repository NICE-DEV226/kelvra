"""The table of live results in spec/sealing-verification.md, drawn from the result files.

    python examples/sealed_support_agent/live_table.py            # print it
    python examples/sealed_support_agent/live_table.py --check    # exit 1 if the document differs

The numbers in a document that says what was measured should be the measurements, not a copy made
by hand: a test runs the same function and fails if the table in the document and the files in
``evaluation/live/`` disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evaluation" / "live"
DOCUMENT = ROOT / "spec" / "sealing-verification.md"
START, END = "<!-- live:start -->", "<!-- live:end -->"
SCENARIOS = {
    "honest": "normal",
    "injected": "injection (hand-written)",
    "injected_real": "injection (public datasets)",
}
HEAD = (
    "| model | message | trials used | token copied exactly | reply complete | tried another "
    "destination | delivered elsewhere | plaintext in prompt | calls that failed |"
)


def short(text: str) -> str:
    """``94% (45/48, 95% CI 83-98%)`` -> ``94% (45/48)``: the interval is in the files."""
    return text.split(", 95%")[0] + ")" if ", 95%" in text else text


def rows(paths: list[Path] | None = None) -> list[str]:
    out = []
    for path in sorted(paths or RESULTS.glob("results-*.json")):
        for s in json.loads(path.read_text(encoding="utf-8"))["summaries"]:
            model = s["target"].split(":", 1)[1] + " (" + s["target"].split(":", 1)[0] + ")"
            out.append(
                f"| {model} | {SCENARIOS[s['scenario']]} | {s['valid']} of {s['trials']} | "
                f"{short(s['token_copy'])} | {short(s['reply_complete'])} | "
                f"{short(s['obeyed_injection'])} | {s['leaks']} | "
                f"{s['plaintext_in_prompts']} of {s['valid']} | {s['api_errors']} of {s['trials']}"
                f"{' (stopped: quota)' if s.get('stopped') else ''} |"
            )
    return out


def table(paths: list[Path] | None = None) -> str:
    return "\n".join([HEAD, "|" + "---|" * 9, *rows(paths)])


def embedded(document: str) -> str | None:
    if START not in document or END not in document:
        return None
    return document.split(START, 1)[1].split(END, 1)[0].strip("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        found = embedded(DOCUMENT.read_text(encoding="utf-8"))
        if found != table():
            print("spec/sealing-verification.md does not match evaluation/live/", file=sys.stderr)
            return 1
        return 0
    print(table())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
