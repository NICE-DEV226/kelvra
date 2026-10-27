"""Kelvra -- declare what an AI agent may know, prove what it did.

Specification stage. This package is the reference implementation of the
label model and provenance record; it is deliberately not the only possible
one. See README.md for positioning and spec/threat-model.md for what this
does and does not defend against.

The core has no third-party dependencies. Adapters that would bind it to MCP or
to a framework do not exist yet; when they do they will carry their own extras.
"""

from .klv import KlvError, parse, parse_file, parse_with_warnings
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
from .provenance import (
    FORMAT_VERSION,
    Journal,
    JournalContents,
    JournalError,
    Ledger,
    LedgerClosed,
    UnsignedRecordWarning,
    Verification,
    journal_to_record,
    read_journal,
    sign,
    verify,
    verify_record,
)
from .sealing import MasterKey, SealError
from .taint import (
    AgentSession,
    ConsentDecision,
    ConsentRefused,
    Denied,
    Kelvra,
    PolicyIntegrityError,
    Tainted,
    approved_by,
)

__version__ = "0.1.0"

__all__ = [
    "FORMAT_VERSION",
    "PUBLIC",
    "SECRET",
    "AgentSession",
    "ConsentDecision",
    "ConsentRefused",
    "Decision",
    "Declassifier",
    "Denied",
    "Journal",
    "JournalContents",
    "JournalError",
    "Kelvra",
    "KlvError",
    "Label",
    "Ledger",
    "LedgerClosed",
    "MasterKey",
    "Policy",
    "PolicyIntegrityError",
    "PrincipalSet",
    "SealError",
    "Sink",
    "Source",
    "Tainted",
    "UnsignedRecordWarning",
    "Verification",
    "__version__",
    "approved_by",
    "check_flow",
    "declassify_to",
    "endorse_as",
    "join_all",
    "journal_to_record",
    "parse",
    "parse_file",
    "parse_with_warnings",
    "read_journal",
    "sign",
    "verify",
    "verify_record",
]
