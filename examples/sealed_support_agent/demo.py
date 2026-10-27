"""A support agent whose model provider only ever holds ciphertext.

Run it (offline, deterministic apart from random nonces):

    pip install -e ".[seal]"
    python examples/sealed_support_agent/demo.py

With a real model behind an OpenAI-compatible endpoint (you supply the key; nothing is
stored, and the prompt it receives contains no plaintext account detail either way):

    export OPENAI_API_KEY=...        # yours; never put it in a file
    python examples/sealed_support_agent/demo.py --model http

What it shows, in order: what the provider receives, what the model asks for, what the
boundary does with each request, and what an auditor can check afterwards.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import HonestModel, HttpChatModel, InjectedModel
from pipeline import INJECTED, LEGIT, Case, Pipeline, Result

WIDTH = 78


def rule(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m\n" + "-" * WIDTH)


def shorten(text: str, limit: int = 66) -> str:
    text = text.replace("\n", " / ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def leaks(result: Result, case: Case) -> list[str]:
    """Which plaintext values appear anywhere the provider could see."""
    seen = result.prompt + result.reply
    return [
        name
        for name, value in (("name", case.name), ("iban", case.iban), ("phone", case.phone))
        if value in seen
    ]


def show(title: str, case: Case, result: Result) -> None:
    rule(title)
    print("  What the provider received (the whole prompt):")
    for line in result.prompt.splitlines():
        print(f"    | {shorten(line, 70)}")
    found = leaks(result, case)
    print(f"\n  Plaintext account details in that prompt: {found or 'none'}")
    print(f"  Master key in that prompt: no (key id {result.key_id} names it, reveals nothing)")

    print("\n  What the model asked for, and what the boundary did:")
    for attempt in result.attempts:
        label = {"delivered": "DELIVERED", "denied": "DENIED   ", "refused": "REFUSED  "}[
            attempt.outcome
        ]
        print(f"    {label} -> {attempt.sink}")
        print(f"              asked : {shorten(attempt.text, 60)}")
        if attempt.outcome == "delivered":
            print(f"              sent  : {shorten(attempt.detail, 60)}")
        else:
            print(f"              why   : {shorten(attempt.detail, 60)}")


def audit(result: Result) -> None:
    rule("What the auditor receives")
    print(result.report)
    print(f"\n  record summary : {result.record['summary']}")
    print(f"  signature check: {'valid' if result.verified else 'INVALID'}")


def build_model(args: argparse.Namespace, scripted):
    if args.model == "http":
        return HttpChatModel(base_url=args.base_url, model=args.llm_model, key_env=args.key_env)
    return scripted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", choices=("scripted", "http"), default="scripted")
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    parser.add_argument("--llm-model", default="gpt-4o-mini")
    parser.add_argument("--key-env", default="OPENAI_API_KEY")
    parser.add_argument("--only", choices=("legit", "injection"))
    args = parser.parse_args()

    runs = []
    if args.only in (None, "legit"):
        runs.append(("1. A normal request", LEGIT, build_model(args, HonestModel())))
    if args.only in (None, "injection"):
        runs.append(
            (
                "2. The same agent, after an injection in the message",
                INJECTED,
                build_model(args, InjectedModel()),
            )
        )

    result = None
    for title, case, model in runs:
        try:
            result = Pipeline(model).run(case)
        except RuntimeError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        show(title, case, result)

    if result is not None:
        audit(result)
    rule("What this does not do")
    print("  The model cannot read the sealed fields, so it cannot reason about them: it can")
    print("  copy them. Code running in this process can reach the key; the boundary is for the")
    print("  model and the provider, not for the application (LIMITATIONS.md).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
