"""Kelvra -- declare what an AI agent may know, prove what it did.

Specification stage. This package is the reference implementation of the
label model and provenance record; it is deliberately not the only possible
one. See README.md for positioning and spec/threat-model.md for what this
does and does not defend against.

The core has no third-party dependencies. Adapters that bind it to MCP or
to a framework live under ``kelvra.adapters`` and carry their own extras.
"""

from .labels import PUBLIC, SECRET, Label, PrincipalSet, join_all
from .policy import (
    Decision,
    Declassifier,
    Policy,
    Sink,
    Source,
    check_flow,
    declassify_to,
    endorse_as,
)
from .provenance import Ledger, sign, verify
from .taint import ConsentRefused, Denied, Kelvra, Tainted

__version__ = "0.1.0"

__all__ = [
    "PUBLIC",
    "SECRET",
    "ConsentRefused",
    "Decision",
    "Declassifier",
    "Denied",
    "Kelvra",
    "Label",
    "Ledger",
    "Policy",
    "PrincipalSet",
    "Sink",
    "Source",
    "Tainted",
    "__version__",
    "check_flow",
    "declassify_to",
    "endorse_as",
    "join_all",
    "sign",
    "verify",
]
