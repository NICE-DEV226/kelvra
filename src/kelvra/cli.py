"""``kelvra`` on the command line.

Deliberately built before a language server. An LSP is JSON-RPC plumbing
around an analysis; the analysis is the part with value, and a CLI puts it
in someone's CI in one line today rather than in their editor next quarter.
The language server, when it comes, wraps this same :mod:`kelvra.analysis`
and adds no checks of its own.

Exit codes, chosen so CI can act on them:

  0  clean, or warnings only
  1  errors found, or the file would not parse
  2  the command itself was misused
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis import Finding, analyse, describe_reachability
from .klv import KlvError, parse_with_warnings
from .policy import Policy

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _colour(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _load(path: Path) -> tuple[Policy, list[str]]:
    return parse_with_warnings(path.read_text(encoding="utf-8"), filename=str(path))


def _print_findings(findings: list[Finding], *, colour: bool) -> None:
    for finding in findings:
        tint = "31" if finding.severity == "error" else "33"
        label = _colour(finding.severity, tint, colour)
        print(f"{label}[{finding.code}] {finding.subject}: {finding.message}")
        if finding.hint:
            print(f"  hint: {finding.hint}")


def cmd_check(args: argparse.Namespace) -> int:
    """Parse and analyse policies. The command CI runs."""
    colour = sys.stdout.isatty() and not args.no_colour
    worst = EXIT_OK

    for path in args.files:
        try:
            policy, warnings = _load(path)
        except KlvError as error:
            print(str(error), file=sys.stderr)
            worst = EXIT_FINDINGS
            continue
        except OSError as error:
            print(f"cannot read {path}: {error}", file=sys.stderr)
            worst = EXIT_FINDINGS
            continue

        findings = analyse(policy)

        if args.json:
            print(
                json.dumps(
                    {
                        "file": str(path),
                        "policy": policy.name,
                        "version": policy.version,
                        "fingerprint": policy.fingerprint(),
                        "parse_warnings": warnings,
                        "findings": [
                            {
                                "code": f.code,
                                "severity": f.severity,
                                "subject": f.subject,
                                "message": f.message,
                                "hint": f.hint,
                            }
                            for f in findings
                        ],
                    },
                    indent=2,
                )
            )
        else:
            header = f"{path}  ({policy.name} v{policy.version})"
            print(_colour(header, "1", colour))
            for warning in warnings:
                print(f"{_colour('warning', '33', colour)}[syntax] {warning}")
            _print_findings(findings, colour=colour)
            if not warnings and not findings:
                print(_colour("  no findings", "32", colour))
            print()

        if any(f.severity == "error" for f in findings):
            worst = EXIT_FINDINGS
        if args.strict and (findings or warnings):
            worst = EXIT_FINDINGS

    return worst


def cmd_explain(args: argparse.Namespace) -> int:
    """Show which sources can reach which sinks.

    Not a check. This is what someone reviewing a policy actually asks, and
    it runs the same computation the findings are derived from.
    """
    try:
        policy, _ = _load(args.file)
    except KlvError as error:
        print(str(error), file=sys.stderr)
        return EXIT_FINDINGS

    print(f"{policy.name} v{policy.version}")
    print(f"fingerprint {policy.fingerprint()}")
    print(f"\n{len(policy.sources)} sources, {len(policy.sinks)} sinks, "
          f"{len(policy.declassifiers)} declassifiers\n")

    print("reachability:")
    for line in describe_reachability(policy):
        print(f"  {line}")

    if policy.declassifiers:
        print("\ndeclassifiers (the only places a leak is possible):")
        for name, d in sorted(policy.declassifiers.items()):
            grants = []
            if not d.grants_readers.is_empty:
                grants.append(f"readers {d.grants_readers!r}")
            if not d.grants_endorsement.is_empty:
                grants.append(f"endorsement {d.grants_endorsement!r}")
            consent = f", consent from {d.requires_consent_from}" if d.requires_consent_from else ""
            print(f"  {name}: grants {' and '.join(grants) or 'nothing'}{consent}")

    return EXIT_OK


def cmd_lsp(args: argparse.Namespace) -> int:
    """Start the language server. Imported lazily: pygls is an optional extra."""
    from .lsp import serve

    return serve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kelvra",
        description="Declare what an AI agent may know, prove what it did.",
    )
    parser.add_argument("--version", action="version", version=f"kelvra {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help="parse and analyse policy files",
        description=(
            "Exit 1 on an error or a parse failure. Warnings alone exit 0 unless "
            "--strict is given, so a warning never breaks a build by surprise."
        ),
    )
    check.add_argument("files", nargs="+", type=Path, metavar="FILE.klv")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.add_argument("--strict", action="store_true", help="treat warnings as failures")
    check.add_argument("--no-colour", action="store_true", help="never colourise")
    check.set_defaults(func=cmd_check)

    explain = sub.add_parser(
        "explain", help="show which sources can reach which sinks"
    )
    explain.add_argument("file", type=Path, metavar="FILE.klv")
    explain.set_defaults(func=cmd_explain)

    lsp = sub.add_parser(
        "lsp",
        help="run the language server on stdio",
        description=(
            "Speaks the Language Server Protocol on stdin/stdout. Editors launch "
            "this; you rarely run it by hand. Needs: pip install 'kelvra[lsp]'"
        ),
    )
    lsp.set_defaults(func=cmd_lsp)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        # argparse exits 0 for --help and --version, 2 for a usage error.
        # Do not collapse that with `or`: zero is falsy, so `code or EXIT_USAGE`
        # turns a successful --version into a failure, which is exactly the
        # kind of thing a CI smoke test trips over.
        if exit_.code is None:
            return EXIT_OK
        return int(exit_.code)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
