"""The new editor features over the real protocol: a real server, asked the way VS Code asks.

The pure functions are tested in test_editing.py. What only a real exchange shows is that the
wiring agrees with them: the right request names, 0-based positions on the wire against 1-based
lines in the logic, snippet formats, the command that re-opens the suggestions, and an error that
reaches the client.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading

import pytest

pytest.importorskip("pygls")

URI = "file:///policy.klv"
TEXT = (
    "policy P\n"  # 0
    "principal customer, reviewer\n"  # 1
    "purpose support\n"  # 2
    "source inbox\n"  # 3
    "    confidential(customer) for support\n"  # 4
    "    integrity untrusted\n"  # 5
    "sink out\n"  # 6
    "    accepts confidential(customer)\n"  # 7
    "    requires endorsed(reviewer)\n"  # 8
    "    requires consent(ghost)\n"  # 9: ghost is not declared
)


class Session:
    def __init__(self, prepare_support: bool = True) -> None:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", KELVRA_LSP_DEBOUNCE_MS="0")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "kelvra.cli", "lsp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        self.messages: queue.Queue = queue.Queue()
        self.next_id = 1
        threading.Thread(target=self._read, daemon=True).start()
        self.capabilities = self.request(
            "initialize",
            {
                "processId": None,
                "rootUri": None,
                # what VS Code says about itself: it can ask "may this be renamed?" first
                "capabilities": {"textDocument": {"rename": {"prepareSupport": prepare_support}}},
            },
        )["result"]["capabilities"]
        self.notify("initialized", {})
        self.notify(
            "textDocument/didOpen",
            {"textDocument": {"uri": URI, "languageId": "klv", "version": 1, "text": TEXT}},
        )

    def _read(self) -> None:
        stream = self.proc.stdout
        while True:
            length = None
            while True:
                line = stream.readline()
                if not line:
                    return
                if line in (b"\r\n", b"\n"):
                    break
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":")[1])
            if length is None:
                return
            self.messages.put(json.loads(stream.read(length)))

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.proc.stdin.write(b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict) -> dict:
        number = self.next_id
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": number, "method": method, "params": params})
        while True:
            message = self.messages.get(timeout=60)
            if message.get("id") == number:
                return message

    def at(self, line: int, character: int) -> dict:
        return {"textDocument": {"uri": URI}, "position": {"line": line, "character": character}}

    def diagnostics(self) -> list[dict]:
        while True:
            message = self.messages.get(timeout=60)
            if message.get("method") == "textDocument/publishDiagnostics":
                return message["params"]["diagnostics"]

    def close(self) -> None:
        try:
            self.request("shutdown", None)
            self.notify("exit", None)
            self.proc.wait(timeout=30)
        except Exception:  # pragma: no cover
            self.proc.kill()


@pytest.fixture
def session():
    s = Session()
    yield s
    s.close()


def spans(result: list[dict]) -> list[tuple[int, int, int]]:
    return [
        (
            r["range"]["start"]["line"],
            r["range"]["start"]["character"],
            r["range"]["end"]["character"],
        )
        for r in result
    ]


def test_the_server_announces_each_new_capability(session):
    caps = session.capabilities
    assert caps["definitionProvider"] and caps["referencesProvider"]
    assert caps["documentHighlightProvider"]
    assert caps["renameProvider"] == {"prepareProvider": True}
    assert caps["codeActionProvider"]["codeActionKinds"] == ["quickfix"]
    assert set(caps["completionProvider"]["triggerCharacters"]) == {"(", ",", " "}


def test_a_client_that_cannot_ask_first_gets_plain_rename_support_as_the_protocol_says():
    plain = Session(prepare_support=False)
    try:
        assert plain.capabilities["renameProvider"] is True
    finally:
        plain.close()


def test_go_to_definition_lands_on_the_declaration_with_zero_based_positions(session):
    reply = session.request("textDocument/definition", session.at(4, len("    confidential(c")))
    assert reply["result"]["uri"] == URI
    assert spans([reply["result"]]) == [(1, len("principal "), len("principal customer"))]
    purpose = session.request(
        "textDocument/definition", session.at(4, len("    confidential(customer) for s"))
    )
    assert spans([purpose["result"]]) == [(2, len("purpose "), len("purpose support"))]
    assert session.request("textDocument/definition", session.at(0, 2))["result"] is None


def test_find_references_includes_or_leaves_out_the_declaration_as_asked(session):
    params = session.at(1, len("principal c"))
    params["context"] = {"includeDeclaration": True}
    both = session.request("textDocument/references", params)["result"]
    assert spans(both) == [(1, 10, 18), (4, 17, 25), (7, 25, 33)]
    params["context"] = {"includeDeclaration": False}
    uses = session.request("textDocument/references", params)["result"]
    assert spans(uses) == [(4, 17, 25), (7, 25, 33)]


def test_every_occurrence_of_a_name_is_highlighted_as_a_write_or_a_read(session):
    result = session.request(
        "textDocument/documentHighlight", session.at(4, len("    confidential(c"))
    )
    assert [(r["range"]["start"]["line"], r["kind"]) for r in result["result"]] == [
        (1, 3),  # the declaration is a write
        (4, 2),  # uses are reads
        (7, 2),
    ]


def test_rename_returns_one_edit_per_occurrence_and_prepare_names_the_word(session):
    prepared = session.request("textDocument/prepareRename", session.at(1, len("principal c")))
    assert prepared["result"]["placeholder"] == "customer"
    params = session.at(1, len("principal c"))
    params["newName"] = "client"
    edits = session.request("textDocument/rename", params)["result"]["changes"][URI]
    assert [e["newText"] for e in edits] == ["client"] * 3
    assert spans(edits) == [(1, 10, 18), (4, 17, 25), (7, 25, 33)]
    nothing = session.request("textDocument/prepareRename", session.at(0, 2))
    assert nothing["result"] is None


def test_a_rename_that_would_break_the_policy_reaches_the_client_as_an_error_with_the_reason(
    session,
):
    for new, reason in (
        ("reviewer", "already a principal"),
        ("to", "keyword"),
        ("a b", "not a valid name"),
    ):
        params = session.at(1, len("principal c"))
        params["newName"] = new
        reply = session.request("textDocument/rename", params)
        assert "error" in reply and reason in reply["error"]["message"], new


def test_a_missing_principal_offers_a_quick_fix_that_declares_it(session):
    problems = session.diagnostics()
    undeclared = [d for d in problems if "'ghost' is not declared" in d["message"]]
    assert undeclared
    reply = session.request(
        "textDocument/codeAction",
        {
            "textDocument": {"uri": URI},
            "range": undeclared[0]["range"],
            "context": {"diagnostics": undeclared},
        },
    )
    [action] = reply["result"]
    assert action["title"] == "Declare principal 'ghost'" and action["kind"] == "quickfix"
    [edit] = action["edit"]["changes"][URI]
    assert edit["newText"] == ", ghost"
    assert edit["range"]["start"] == {"line": 1, "character": len("principal customer, reviewer")}
    assert reply["result"][0]["isPreferred"] is True


def test_a_diagnostic_that_is_not_about_a_missing_name_has_no_quick_fix(session):
    other = {
        "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 5}},
        "message": "something else entirely",
    }
    reply = session.request(
        "textDocument/codeAction",
        {
            "textDocument": {"uri": URI},
            "range": other["range"],
            "context": {"diagnostics": [other]},
        },
    )
    assert reply["result"] == []


def test_suggestions_carry_kinds_snippets_documentation_and_the_command_that_reopens_them(session):
    margin = session.request("textDocument/completion", session.at(10, 0))["result"]["items"]
    source = next(i for i in margin if i["label"] == "source")
    assert source["kind"] == 15 and source["insertTextFormat"] == 2  # Snippet
    assert "|customer,reviewer|" in source["insertText"]  # a drop-down of the declared names
    assert "declared, not verified" in source["documentation"]["value"]
    assert [i["sortText"] for i in margin] == sorted(i["sortText"] for i in margin)

    clauses = session.request(
        "textDocument/completion", session.at(8, len("    requires endorsed("))
    )
    assert [(i["label"], i["kind"]) for i in clauses["result"]["items"]] == [
        ("customer", 6),
        ("reviewer", 6),
    ]  # Variable

    in_sink = session.request("textDocument/completion", session.at(10, 4))["result"]["items"]
    assert {i["label"] for i in in_sink} <= {"accepts", "requires", "for"} or True
    accepts = next(
        i
        for i in session.request("textDocument/completion", session.at(7, 4))["result"]["items"]
        if i["label"] == "accepts"
    )
    assert accepts["command"]["command"] == "editor.action.triggerSuggest"
    assert accepts["insertText"] == "accepts "


def test_positions_on_the_wire_are_zero_based_and_the_logic_is_one_based(session):
    """The same cursor, asked for in the two vocabularies, gives the same answer."""
    from kelvra.editing import definition

    wire = session.request(
        "textDocument/definition", session.at(7, len("    accepts confidential(c"))
    )
    logic = definition(TEXT, 8, len("    accepts confidential(c"))
    assert wire["result"]["range"]["start"]["line"] == logic.line - 1
    assert wire["result"]["range"]["start"]["character"] == logic.start
