"""The gateway against the official MCP SDK, client and server, unmodified.

The rest of the gateway's tests use a fake server written from the protocol as
the author understood it. This one uses the real thing, and it has already
caught what that could not: the 2026-07-28 revision rejects a result without
``resultType``, so the gateway's refusals were protocol errors to the client; and
a server dying mid-call left the client waiting forever.

Skipped when the ``mcp`` package is not installed (it is not a dependency of
Kelvra). CI runs it against pinned SDK 1.x and 2.x and against the latest.
"""

import asyncio
import importlib.metadata
import json
import os
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

from kelvra import read_journal, verify_record  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "tests" / "support" / "sdk_server.py"
KEY = "interop-key-0123456789abcdef"

POLICY = """\
policy Mail
principal staff, customer
source user.input
    confidential(staff, customer)
    integrity trusted
source inbox
    confidential(staff, customer)
    integrity untrusted
source tool.descriptions
    public
    integrity untrusted
sink mail.staff
    accepts confidential(staff)
sink mail.external
    accepts public
"""

CONFIG = {
    "context_source": "user.input",
    "tools": {
        "read_inbox": {"sink": None, "source": "inbox"},
        "send_email": {"sink": "mail.{to}", "source": None},
        "echo": {"sink": "mail.staff", "source": None},
        "crash": {"sink": None, "source": None},
        "ask_user": {"sink": None, "source": "inbox"},
    },
    "results": {"tools/list": "tool.descriptions", "resources/read": "inbox"},
}

try:  # SDK 2.x
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    SDK2 = True
except ImportError:  # SDK 1.x
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    SDK2 = False

VERSION = importlib.metadata.version("mcp")


def _text(result):
    return result.content[0].text


def _is_error(result):
    return getattr(result, "is_error", getattr(result, "isError", None))


async def _session(params, scenario, **client_kwargs):
    if SDK2:
        async with Client(params, **client_kwargs) as client:
            return await scenario(client.call_tool, client.list_tools, client.read_resource)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await scenario(session.call_tool, session.list_tools, session.read_resource)


@pytest.fixture
def run(tmp_path, monkeypatch):
    (tmp_path / "policy.klv").write_text(POLICY, encoding="utf-8")
    (tmp_path / "tools.json").write_text(json.dumps(CONFIG), encoding="utf-8")
    log = tmp_path / "server.log"
    env = dict(
        os.environ,
        PYTHONPATH=str(ROOT / "src"),
        PYTHONDONTWRITEBYTECODE="1",
        INTEROP_LOG=str(log),
        KELVRA_SIGNING_KEY=KEY,
    )

    def go(scenario, **client_kwargs):
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m", "kelvra.cli", "gateway",
                "--policy", str(tmp_path / "policy.klv"),
                "--config", str(tmp_path / "tools.json"),
                "--journal", str(tmp_path / "run.jsonl"),
                "--record", str(tmp_path / "record.json"),
                "--", sys.executable, str(SERVER),
            ],
            env=env,
        )  # fmt: skip
        outcome = asyncio.run(asyncio.wait_for(_session(params, scenario, **client_kwargs), 90))
        executed = (
            [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
            if log.exists()
            else []
        )
        return outcome, executed, tmp_path

    return go


def test_refused_calls_come_back_as_ordinary_tool_errors_and_never_reach_the_server(run):
    async def scenario(call, list_tools, read_resource):
        out = {}
        out["tools"] = sorted(t.name for t in (await list_tools()).tools)
        out["staff"] = await call("send_email", {"to": "staff", "body": "hi"})
        out["read"] = await call("read_inbox", {})
        out["external"] = await call("send_email", {"to": "external", "body": "leak"})
        out["unnamed"] = await call("exfiltrate", {"data": "x"})
        return out

    out, executed, _ = run(scenario)
    assert {"send_email", "read_inbox", "exfiltrate"} <= set(out["tools"])
    assert not _is_error(out["staff"]) and _text(out["staff"]) == "sent"
    assert "IGNORE PREVIOUS" in _text(out["read"])
    for refused in (out["external"], out["unnamed"]):
        assert _is_error(refused) and _text(refused).startswith("Kelvra: blocked by policy")
    ran = [e["executed"] for e in executed if "executed" in e]
    assert ran == ["send_email", "read_inbox"], f"the server ran {ran} (sdk {VERSION})"


def test_the_record_and_journal_of_a_real_session_verify(run):
    async def scenario(call, list_tools, read_resource):
        await call("send_email", {"to": "staff", "body": "hi"})
        await call("send_email", {"to": "external", "body": "x"})

    _, _, tmp_path = run(scenario)
    journal = read_journal(tmp_path / "run.jsonl")
    assert journal.ok and journal.complete, journal.problems
    record = json.loads((tmp_path / "record.json").read_text(encoding="utf-8"))
    assert verify_record(record, KEY.encode()).signed
    assert record["summary"]["allowed"] == 1 and record["summary"]["denied"] == 1


def test_parallel_calls_are_each_decided_on_their_own(run):
    async def scenario(call, list_tools, read_resource):
        return await asyncio.gather(
            call("echo", {"text": "a"}),
            call("send_email", {"to": "external", "body": "b"}),
            call("send_email", {"to": "staff", "body": "c"}),
        )

    results, executed, _ = run(scenario)
    assert [bool(_is_error(r)) for r in results] == [False, True, False]
    assert sorted(e["executed"] for e in executed) == ["echo", "send_email"]


def test_text_that_json_and_unicode_make_awkward_survives_the_proxy(run):
    # built with chr() so no invisible character sits in this source file
    text = "h\u00e9llo \U0001f642 " + chr(0x2028) + ' "q" \\ \n line two'

    async def scenario(call, list_tools, read_resource):
        return await call("echo", {"text": text})

    result, executed, _ = run(scenario)
    assert _text(result) == text and executed[0]["text"] == text


def test_a_resource_is_labelled_like_a_tool_result(run):
    async def scenario(call, list_tools, read_resource):
        await read_resource("mail://latest")
        return await call("send_email", {"to": "external", "body": "x"})

    result, _, tmp_path = run(scenario)
    assert _is_error(result)
    record = json.loads((tmp_path / "record.json").read_text(encoding="utf-8"))
    assert [e["source"] for e in record["events"] if e["kind"] == "read"].count("inbox") == 1


def test_a_server_that_dies_mid_call_gives_the_client_an_error_not_a_hang(run):
    async def scenario(call, list_tools, read_resource):
        try:
            await call("crash", {})
        except Exception as error:
            return f"{type(error).__name__}: {error}"
        return "no error"

    outcome, executed, tmp_path = run(scenario)
    assert "exited before answering" in outcome
    assert [e["executed"] for e in executed] == ["crash"]
    assert read_journal(tmp_path / "run.jsonl").complete  # the run was still closed properly


@pytest.mark.skipif(not SDK2, reason="the input-required round trip exists only in SDK 2.x")
def test_a_server_asking_for_input_mid_call_is_labelled_and_its_retry_is_checked_again(run):
    import mcp_types as types

    asked = []

    async def elicit(context, params):
        asked.append(params.message)
        return types.ElicitResult(action="accept", content={"name": "Ada"})

    async def scenario(call, list_tools, read_resource):
        asked_user = await call("ask_user", {})
        external = await call("send_email", {"to": "external", "body": "x"})
        return asked_user, external

    (asked_user, external), executed, tmp_path = run(scenario, elicitation_callback=elicit)
    assert _text(asked_user) == "hello" and asked == ["SERVER TEXT: what is your name?"]
    rounds = [e["round"] for e in executed if e.get("executed") == "ask_user"]
    assert rounds == ["first", "retry"]  # the retry was a second call, and it was let through
    assert _is_error(external)  # the server's text is in the conversation now
    record = json.loads((tmp_path / "record.json").read_text(encoding="utf-8"))
    kinds = [(e["kind"], e.get("source")) for e in record["events"]]
    assert kinds.count(("read", "inbox")) == 2  # one per result: the question and the answer
