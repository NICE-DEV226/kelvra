"""A tool-call gateway: the enforcement point the threat model asks for.

Everything else in this package is a library that an agent's author calls. The
threat model names the real weak point: *the enforcement point applies decisions*
(spec/threat-model.md section 6), and a library the agent can simply not call
enforces nothing. A gateway sits where the agent has no choice -- between it and
its tools -- so a tool call that the policy refuses never reaches the tool.

What it can and cannot know. A proxy sees tool calls and tool results; it does
not see the model's context window. So it tracks the one thing it can: the
**conversation label**, the join of the label of everything that has come back
from a tool so far. Any call is checked against that label, as if the arguments
carried all of it. That is the model-call rule of spec/labels.md section 7 (a
total join) applied to a whole session, with the same cost: it is coarse and it
never under-labels, and label creep is real -- a session that has read something
confidential can only send to sinks that may receive it. This is the
"granularity" open question of the label model, answered at the coarsest level
because that is the only one a proxy can see.

Fail-closed by construction:

* a tool the configuration does not name is a sink nobody declared, so it is
  refused and the refusal is recorded;
* every tool states both where its arguments go (``sink``) and what its result
  is (``source``), each either a declared name or an explicit ``null``; a missing
  key is a configuration error, not a default;
* a sink template is filled only from string arguments, and a name that was never
  declared is refused, so an attacker-chosen argument cannot choose an
  allowed destination.

The gateway holds an :class:`~kelvra.taint.AgentSession`, not the authority: it
can read, join and emit, and cannot declassify. ``relabel`` is the control-plane
hook for an operator to apply a declared declassification to the conversation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .policy import Policy
from .taint import ConsentRefused, Denied, Kelvra, Tainted

_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_MAX_ARGUMENT = 200

_CONFIG_KEYS = {"tools", "results", "context_source"}
_TOOL_KEYS = {"sink", "source"}


class GatewayConfigError(ValueError):
    """The tool configuration is incomplete or names something the policy lacks."""


class ToolRefused(Exception):
    """A tool call the policy does not allow. Carries a message safe to show."""


@dataclass(frozen=True)
class ToolSpec:
    sink: str | None
    """Template for the sink the call's arguments reach, or ``None`` for "nowhere"."""

    source: str | None
    """Declared source the call's result is read as, or ``None`` for "unlabelled"."""


@dataclass(frozen=True)
class GatewayConfig:
    tools: Mapping[str, ToolSpec]
    results: Mapping[str, str]
    """Other MCP methods whose results enter the model's context -> declared source."""

    context_source: str | None = None
    """Declared source for what the user typed, read once when the session starts."""

    @staticmethod
    def from_dict(data: object, policy: Policy) -> GatewayConfig:
        """Validate ``data`` against ``policy``. Every mistake is an error with a name."""
        if not isinstance(data, dict):
            raise GatewayConfigError("the configuration must be an object")
        unknown = set(data) - _CONFIG_KEYS
        if unknown:
            raise GatewayConfigError(f"unknown configuration keys: {sorted(unknown)}")

        def declared_source(name: object, where: str) -> str | None:
            if name is None:
                return None
            if not isinstance(name, str) or name not in policy.sources:
                raise GatewayConfigError(f"{where}: source {name!r} is not declared in the policy")
            return name

        tools: dict[str, ToolSpec] = {}
        for tool, spec in (data.get("tools") or {}).items():
            if not isinstance(spec, dict) or set(spec) != _TOOL_KEYS:
                raise GatewayConfigError(
                    f"tool {tool!r} must state both 'sink' and 'source' (each a name or null): "
                    "leaving one out would be a silent default"
                )
            sink = spec["sink"]
            if sink is not None and not isinstance(sink, str):
                raise GatewayConfigError(f"tool {tool!r}: sink must be a string or null")
            if isinstance(sink, str) and "{" not in sink and sink not in policy.sinks:
                raise GatewayConfigError(
                    f"tool {tool!r}: sink {sink!r} is not declared in the policy"
                )
            tools[tool] = ToolSpec(sink, declared_source(spec["source"], f"tool {tool!r}"))
        results = {
            method: declared_source(source, f"results[{method!r}]")
            for method, source in (data.get("results") or {}).items()
        }
        if any(source is None for source in results.values()):
            raise GatewayConfigError("results must name a declared source for each method")
        return GatewayConfig(
            tools, results, declared_source(data.get("context_source"), "context_source")
        )

    @staticmethod
    def from_json(text: str, policy: Policy) -> GatewayConfig:
        try:
            return GatewayConfig.from_dict(json.loads(text), policy)
        except json.JSONDecodeError as error:
            raise GatewayConfigError(f"the configuration is not valid JSON: {error}") from None


class Gateway:
    """Decides tool calls against a policy and keeps the conversation's label."""

    def __init__(self, kelvra: Kelvra, config: GatewayConfig) -> None:
        self._kelvra = kelvra
        self._agent = kelvra.agent_session()
        self.config = config
        self._lock = threading.RLock()
        # Nothing read yet: the public, fully trusted label, issued by this session.
        self._context: Tainted = self._agent.model_call("gateway.start")
        if config.context_source is not None:
            self.ingest(config.context_source)

    # -- the decision ----------------------------------------------------

    def sink_for(self, tool: str, arguments: object) -> str | None:
        """The sink this call's arguments reach, or ``None`` if the tool declares none.

        An unnamed tool maps to ``tool.<name>``, which the policy does not declare,
        so it is refused by the ordinary default-deny rule and the refusal is recorded.
        """
        spec = self.config.tools.get(tool)
        if spec is None:
            return f"tool.{tool}"
        if spec.sink is None:
            return None
        args = arguments if isinstance(arguments, dict) else {}

        def fill(match: re.Match[str]) -> str:
            value = args.get(match.group(1))
            if not isinstance(value, str) or not value or len(value) > _MAX_ARGUMENT:
                raise ToolRefused(
                    f"cannot tell where {tool!r} sends data: "
                    f"argument {match.group(1)!r} is missing, not text, or too long"
                )
            if not value.isprintable():
                raise ToolRefused(f"argument {match.group(1)!r} contains control characters")
            return value

        return _PLACEHOLDER.sub(fill, spec.sink)

    def before_call(self, tool: str, arguments: object) -> None:
        """Raise :class:`ToolRefused` unless the conversation may reach this tool."""
        sink = self.sink_for(tool, arguments)
        if sink is None:
            return
        with self._lock:
            context = self._context
            try:
                self._agent.emit(sink, context)
            except Denied as denied:
                raise ToolRefused(f"blocked by policy: {denied.decision.reason}") from None
            except LookupError:
                raise ToolRefused(
                    f"blocked by policy: {sink!r} is not a destination the policy declares"
                ) from None
            except ConsentRefused as refused:
                raise ToolRefused(f"blocked: {refused}") from None
            except TypeError as error:  # a consent provider that broke its contract
                raise ToolRefused(f"blocked: {error}") from None

    # -- what comes back -------------------------------------------------

    def source_for_result(self, tool: str) -> str | None:
        spec = self.config.tools.get(tool)
        return None if spec is None else spec.source

    def ingest(self, source: str | None) -> None:
        """Fold a result of the given declared source into the conversation's label.

        The payload is not kept: only its label matters here, and a gateway that
        remembered tool output would be a second copy of the data.
        """
        if source is None:
            return
        with self._lock:
            item = self._agent.read(source, None)
            self._context = self._agent.model_call(
                "gateway.context", self._context, item, produce=lambda *_: None
            )

    def relabel(self, apply: Callable[[Tainted], Tainted]) -> None:
        """Control-plane hook: replace the conversation label with ``apply(label)``.

        For an operator to take a *declared* declassification, for example
        ``gateway.relabel(lambda ctx: authority.declassify("human_review", ctx))``.
        ``apply`` must return a value issued by this session; anything else is
        refused by the session on the next call.
        """
        with self._lock:
            self._context = apply(self._context)

    @property
    def label_description(self) -> str:
        """The conversation's label, for display."""
        return self._context.label.describe()


# -- MCP over stdio -----------------------------------------------------------

_BLOCKED_FROM_SERVER = frozenset({"sampling/createMessage", "elicitation/create"})
"""Requests a server may make of the client that would put unlabelled server text
in front of the model. Refused rather than passed through unlabelled."""

# JSON-RPC 2.0 error codes
MAX_PENDING = 10_000
"""Requests in flight at once. More would let a client grow the gateway's memory at will."""

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


@dataclass(frozen=True)
class FilterOutput:
    """What to do with one line.

    ``forward`` goes onward (client to server, or server to client); ``reply``
    goes back to whoever sent the line (an error answer to a refused request).
    """

    forward: tuple[str, ...] = ()
    reply: tuple[str, ...] = ()


def _fold(key: str) -> str:
    """A key the way a case-insensitive JSON decoder would compare it.

    Go's ``encoding/json`` and several .NET and Java decoders match member names
    without regard to case, and Go's folding is wider than ``str.lower``: the long
    s (U+017F) matches ``s`` and the Kelvin sign (U+212A) matches ``k``. NFKC then
    ``casefold`` covers those.
    """
    return unicodedata.normalize("NFKC", key).casefold()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse an object with two keys a lenient decoder could take for one.

    Exact duplicates were already refused; ``name`` beside ``Name`` is the same
    attack against a decoder that ignores case, with a different winner.
    """
    folded = [_fold(k) for k, _ in pairs]
    if len(folded) != len(set(folded)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _finite_float(text: str) -> float:
    """A JSON number that is a finite float, or an error.

    ``1e999`` is valid JSON text, and Python reads it as infinity; written back out
    it becomes ``Infinity``, which is not JSON, so the gateway would have forwarded
    a line no strict decoder accepts (found by comparing against Node and jq).
    """
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("number out of range")
    return value


def _parse(line: str) -> Any:
    """Parse one JSON-RPC line the strict way, or raise ``ValueError``.

    The gateway and the server must read a message the same way, or a message can
    be innocent to one and a tool call to the other. JSON implementations disagree
    about duplicate keys (first wins, last wins, error) and about ``NaN``, so both
    are refused outright rather than guessed at.
    """
    message = json.loads(
        line,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_refuse_constant,
        parse_float=_finite_float,
    )
    if isinstance(message, dict):
        _require_exact_members(message)
    return message


_MEMBERS = ("jsonrpc", "id", "method", "params", "result", "error")
"""The only top-level members JSON-RPC 2.0 defines. Nothing else is forwarded."""

_PARAMS = ("name", "arguments")
"""What the gateway reads inside the params of a ``tools/call``."""


def _require_exact_members(message: dict[str, Any]) -> None:
    """Refuse a spelling of a member the gateway interprets that only a lenient peer accepts.

    If ``Method`` reaches a decoder that ignores case, it is the method; the gateway,
    matching exactly, saw no method and let the message through unchecked. Rejecting
    every variant spelling closes that without having to guess how each peer decodes.
    """
    _exact(message, _MEMBERS)
    _ascii_only(message, "member")
    method = message.get("method")
    if isinstance(method, str) and not method.isascii():
        raise ValueError("method names are ASCII")
    params = message.get("params")
    if isinstance(params, dict):
        _exact(params, _PARAMS)
        if method == "tools/call":
            _ascii_only(params, "parameter")
            arguments = params.get("arguments")
            if isinstance(arguments, dict):
                _ascii_only(arguments, "argument name")


def _ascii_only(obj: dict[str, Any], what: str) -> None:
    """Refuse non-ASCII keys in an object the gateway reads by name.

    Folding rules differ by decoder and by locale (the dotless and dotted i, the long
    s, the Kelvin sign, and whatever the next one is), so a list of the foldings to
    watch for is a list that is always one short. Case-insensitive matching can only
    turn a non-ASCII key into one of the ASCII names the gateway reads by way of one
    of those foldings; an ASCII-only key has no such route beyond simple case, which
    ``_exact`` rejects. So a non-ASCII key is refused here without asking what it
    might fold to. (Argument *values* are unrestricted.)
    """
    for key in obj:
        if not key.isascii():
            raise ValueError(f"{what} {key!r} is not ASCII")


def _is_variant(method: str, names: Iterable[str]) -> bool:
    """``method`` spelled differently from one of ``names`` that a lenient peer would match."""
    return any(_fold(method) == _fold(name) and method != name for name in names)


def _exact(obj: dict[str, Any], names: tuple[str, ...]) -> None:
    wanted = {_fold(name): name for name in names}
    for key in obj:
        exact = wanted.get(_fold(key))
        if exact is not None and key != exact:
            raise ValueError(f"{key!r} is a variant spelling of {exact!r}")


def _ambiguous(message: dict[str, Any]) -> bool:
    """A message whose kind depends on who is reading it.

    JSON-RPC separates requests and notifications (they have ``method``) from
    responses (``result`` or ``error``, never ``method``). A message carrying both
    is a request to a strict peer and a response to a lenient one; if the gateway
    reads it one way and the peer the other, a result reaches the model without
    its label being taken. ``result`` together with ``error`` is the same hazard,
    and so is a ``method`` that is not text. None of them is legitimate, so none
    is forwarded.
    """
    has_method = "method" in message
    has_result = "result" in message
    has_error = "error" in message
    if has_method and not isinstance(message["method"], str):
        return True
    return (has_method and (has_result or has_error)) or (has_result and has_error)


def _wire(message: dict[str, Any]) -> str:
    """What is forwarded: the members JSON-RPC defines, re-serialised, and nothing else.

    A peer never sees a member the gateway did not look at.
    """
    return _line({name: message[name] for name in _MEMBERS if name in message})


def _line(obj: dict[str, Any]) -> str:
    # ASCII only: a lone surrogate escape in a message must not become an
    # unencodable string on the way out.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def _error(request_id: object, code: int, message: str) -> str:
    return _line({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def _tool_error(request_id: object, message: str) -> str:
    """A refused tool call, reported as MCP reports a failed one: a result with isError."""
    return _line(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "isError": True,
                "content": [{"type": "text", "text": message}],
                # Required by the 2026-07-28 revision of the protocol, where a
                # result without it is rejected by the client; earlier revisions
                # ignore a field they do not know. Found by running the official
                # SDK's client against the gateway, not by reading the spec.
                "resultType": "complete",
            },
        }
    )


class McpFilter:
    """The MCP stdio protocol (newline-delimited JSON-RPC) with a gateway in the middle.

    Pure: a line goes in, lines to forward and lines to answer come out, so it can
    be tested with no process at all. :func:`run_stdio` wires it to real pipes.

    It handles what it can reason about and is explicit about the rest:

    * ``tools/call`` is checked before it reaches the server, and its result is
      folded into the conversation's label before it reaches the client;
    * other methods named in ``config.results`` (``resources/read``,
      ``prompts/get``, ``tools/list``) have their results labelled the same way;
    * JSON-RPC batches are refused outright (the current MCP revision does not
      allow them, and a batch is a way to hide a call);
    * a response with an id nobody is waiting on is dropped, not forwarded: a
      server cannot inject results the client did not ask for;
    * server-initiated ``sampling/createMessage`` and ``elicitation/create`` are
      refused, because they would put unlabelled server text in the model's context;
    * every other message passes through untouched. A method that puts data in the
      model's context and is *not* listed in ``results`` is therefore unlabelled
      -- the configuration is where that gap is closed, and it is a gap.
    """

    def __init__(self, gateway: Gateway) -> None:
        self.gateway = gateway
        self._pending: dict[str, tuple[str, str | None]] = {}
        self._lock = threading.Lock()

    def abandon(self) -> list[object]:
        """Forget every request in flight and return their ids, so each can be answered."""
        with self._lock:
            ids = [json.loads(key) for key in self._pending]
            self._pending.clear()
        return ids

    @property
    def pending(self) -> int:
        """How many requests have been forwarded and not yet answered."""
        with self._lock:
            return len(self._pending)

    # -- client -> server --------------------------------------------------

    def client_to_server(self, line: str) -> FilterOutput:
        try:
            message = _parse(line)
        except (ValueError, RecursionError):
            return FilterOutput(reply=(_error(None, _PARSE_ERROR, "parse error"),))
        if isinstance(message, list):
            return FilterOutput(
                reply=(_error(None, _INVALID_REQUEST, "batches are not accepted by the gateway"),)
            )
        if not isinstance(message, dict):
            return FilterOutput(reply=(_error(None, _INVALID_REQUEST, "invalid request"),))
        if _ambiguous(message):
            return FilterOutput(
                reply=(
                    _error(None, _INVALID_REQUEST, "a message cannot be both request and response"),
                )
            )

        method = message.get("method")
        request_id = message.get("id")
        if isinstance(method, str) and _is_variant(
            method, ("tools/call", *self.gateway.config.results)
        ):
            # 'Tools/Call' is no tool call to a gateway matching exactly, and one to a
            # server matching without regard to case.
            return FilterOutput(
                reply=(_error(None, _INVALID_REQUEST, "method names are case-sensitive"),)
            )
        has_id = "id" in message and request_id is not None
        if has_id and (isinstance(request_id, bool) or not isinstance(request_id, int | str)):
            return FilterOutput(reply=(_error(None, _INVALID_REQUEST, "invalid id"),))

        if method == "tools/call":
            return self._tools_call(message, request_id, has_id)

        if has_id and isinstance(method, str):
            # Every request is remembered, so its answer is recognised as an answer:
            # an id nobody is waiting on is dropped on the way back.
            key = json.dumps(request_id)
            with self._lock:
                if key in self._pending or len(self._pending) >= MAX_PENDING:
                    return FilterOutput(
                        reply=(_error(request_id, _INVALID_REQUEST, "id already in flight"),)
                    )
                self._pending[key] = (method, None)
        return FilterOutput(forward=(_wire(message),))

    def _tools_call(self, message: dict, request_id: object, has_id: bool) -> FilterOutput:
        if not has_id:
            # A notification cannot be answered, and a call nobody can answer is not
            # one to run. Dropping it is the only fail-closed reading.
            return FilterOutput()
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        arguments_ok = arguments is None or isinstance(arguments, dict)
        if not (isinstance(name, str) and name and arguments_ok):
            return FilterOutput(reply=(_error(request_id, _INVALID_PARAMS, "invalid tools/call"),))
        key = json.dumps(request_id)
        with self._lock:
            if key in self._pending:
                return FilterOutput(
                    reply=(_error(request_id, _INVALID_REQUEST, "id already in flight"),)
                )
        try:
            self.gateway.before_call(name, arguments)
        except ToolRefused as refused:
            return FilterOutput(reply=(_tool_error(request_id, f"Kelvra: {refused}"),))
        with self._lock:
            self._pending[key] = ("tools/call", name)
        return FilterOutput(forward=(_wire(message),))

    # -- server -> client --------------------------------------------------

    def server_to_client(self, line: str) -> FilterOutput:
        try:
            message = _parse(line)
        except (ValueError, RecursionError):
            return FilterOutput()  # not MCP; do not hand it to the client
        if not isinstance(message, dict) or _ambiguous(message):
            return FilterOutput()  # not handed on: the client might read it differently

        method = message.get("method")
        if isinstance(method, str) and _is_variant(method, _BLOCKED_FROM_SERVER):
            return FilterOutput()  # a spelling only a lenient client would act on
        if isinstance(method, str):
            if method in _BLOCKED_FROM_SERVER:
                if message.get("id") is None:
                    return FilterOutput()
                return FilterOutput(
                    reply=(
                        _error(
                            message["id"],
                            _METHOD_NOT_FOUND,
                            f"{method} is refused by the gateway: it would put unlabelled "
                            "server text in front of the model",
                        ),
                    )
                )
            return FilterOutput(forward=(_wire(message),))

        if "result" not in message and "error" not in message:
            return FilterOutput()
        request_id = message.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, int | str):
            return FilterOutput()
        with self._lock:
            entry = self._pending.pop(json.dumps(request_id), None)
        if entry is None:
            return FilterOutput()  # an answer to nothing the client asked
        method, tool = entry
        source = (
            self.gateway.source_for_result(tool or "")
            if method == "tools/call"
            else self.gateway.config.results.get(method)
        )
        self.gateway.ingest(source)
        return FilterOutput(forward=(_wire(message),))


class FdLineReader:
    """Reads newline-terminated lines from a raw file descriptor, with no Python-level buffer.

    ``sys.stdin.buffer`` holds a lock while a thread is blocked reading it, and
    CPython aborts ("could not acquire lock ... at interpreter shutdown") if the
    process ends while a daemon thread still holds it -- which is exactly what
    happens when the server dies and the gateway stops while the client has not
    disconnected. ``os.read`` on the descriptor has no such lock.
    """

    def __init__(self, fd: int = 0, chunk: int = 65536) -> None:
        if sys.platform == "win32":  # pipes opened in text mode would rewrite CRLF
            import msvcrt

            msvcrt.setmode(fd, os.O_BINARY)
        self._fd = fd
        self._chunk = chunk
        self._buffer = bytearray()

    def readline(self) -> bytes:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                return line
            try:
                data = os.read(self._fd, self._chunk)
            except OSError:
                data = b""
            if not data:
                line, self._buffer = bytes(self._buffer), bytearray()
                return line
            self._buffer.extend(data)


def run_stdio(
    flt: McpFilter,
    command: Sequence[str],
    client_in: Any,
    client_out: Any,
    *,
    drain_seconds: float = 5.0,
) -> int:
    """Run ``command`` as an MCP server with ``flt`` between it and the client.

    ``client_in`` and ``client_out`` are binary streams (``sys.stdin.buffer`` and
    ``sys.stdout.buffer`` for a real client). Binary on purpose: text mode
    translates line endings differently on Windows, and a protocol that is
    newline-delimited must not care. Returns the server's exit code.

    Two ways to end, both of which leave the client with an answer to every
    request it sent. The client disconnects: the gateway waits briefly for the
    answers it is still owed, then closes the server's input. The server dies:
    every request still in flight is answered with a JSON-RPC error, and the
    gateway stops, so the client sees the same end of stream it would have seen
    from the server directly instead of waiting forever. (Found by killing a
    server mid-call under the official SDK's client, which hung.)
    """
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr.buffer if hasattr(sys.stderr, "buffer") else None,
    )
    assert process.stdin is not None and process.stdout is not None
    out_lock = threading.Lock()
    in_lock = threading.Lock()
    wake = threading.Event()
    state = {"client_done": False, "server_done": False}

    def to_client(text: str) -> None:
        with out_lock:
            try:
                client_out.write(text.encode("utf-8") + b"\n")
                client_out.flush()
            except (BrokenPipeError, OSError, ValueError):
                state["client_done"] = True
                wake.set()

    def to_server(text: str) -> bool:
        with in_lock:
            try:
                process.stdin.write(text.encode("utf-8") + b"\n")  # type: ignore[union-attr]
                process.stdin.flush()  # type: ignore[union-attr]
                return True
            except (BrokenPipeError, OSError):
                return False

    def pump_server() -> None:
        for raw in iter(process.stdout.readline, b""):  # type: ignore[union-attr]
            try:
                text = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                continue
            if not text:
                continue
            result = flt.server_to_client(text)
            for line in result.forward:
                to_client(line)
            for line in result.reply:
                to_server(line)
        state["server_done"] = True
        wake.set()

    def pump_client() -> None:
        try:
            for raw in iter(client_in.readline, b""):
                try:
                    text = raw.decode("utf-8").rstrip("\r\n")
                except UnicodeDecodeError:
                    to_client(_error(None, _PARSE_ERROR, "parse error"))
                    continue
                if not text:
                    continue
                result = flt.client_to_server(text)
                for line in result.reply:
                    to_client(line)
                for line in result.forward:
                    if not to_server(line):
                        return
        finally:
            state["client_done"] = True
            wake.set()

    # Daemon threads: a thread blocked reading the client must not keep the
    # process alive once the server has gone.
    server_thread = threading.Thread(target=pump_server, daemon=True)
    client_thread = threading.Thread(target=pump_client, daemon=True)
    server_thread.start()
    client_thread.start()

    while not (state["client_done"] or state["server_done"]):
        wake.wait(0.2)

    if state["server_done"]:
        server_thread.join(timeout=1)
        for request_id in flt.abandon():
            to_client(_error(request_id, _INTERNAL_ERROR, "the server exited before answering"))
        code = process.wait()
        with out_lock:
            try:
                client_out.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
        return code

    # The client has gone. Answers to what it already asked are still on their
    # way, and a server whose input closes may stop before sending them (or before
    # reading the refusals we owe it). Give it a moment to finish.
    deadline = time.monotonic() + drain_seconds
    while flt.pending and not state["server_done"] and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        process.stdin.close()
    except OSError:
        pass
    code = process.wait()
    server_thread.join(timeout=5)
    return code
