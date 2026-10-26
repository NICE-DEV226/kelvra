# The Kelvra gateway

**Version 0.1 — draft. Status: unstable.** Implemented by `kelvra.gateway` and `kelvra gateway`.

RFC 2119 keywords apply.

A library that an agent's author calls enforces nothing the agent can simply not
call ([threat-model.md](threat-model.md) §6, "enforcement point"). The gateway
sits where the agent has no choice: between it and its tools. A call the policy
refuses never reaches the tool.

## 1. What a proxy can know

It sees tool calls and tool results. It does not see the model's context window.
So it tracks one thing, the **conversation label**: the join
([labels.md](labels.md) §3) of the label of everything that has come back from a
tool, starting from the label of the user's input. Every call is checked against
that label *as if its arguments carried all of it*.

This is the total-join rule of [labels.md](labels.md) §7 applied to a whole
session. It is coarse and it never under-labels. Its cost is label creep: a
session that has read something confidential can only send to sinks that may
receive it, however little of it the arguments actually contain. Per-value
precision needs a runtime inside the agent; a proxy cannot have it.

## 2. Configuration

A JSON document, validated against the policy when the gateway starts. Every
mistake is an error that names it; nothing is defaulted.

```json
{
  "context_source": "user.input",
  "tools": {
    "read_inbox": { "sink": null,            "source": "inbox.imap" },
    "send_email": { "sink": "mail.{to}",     "source": null },
    "search":     { "sink": "web.search",    "source": null }
  },
  "results": { "tools/list": "server.descriptions", "resources/read": "server.files" }
}
```

* `tools` — every tool states **both** `sink` (where its arguments go) and `source`
  (what its result is), each a declared name or an explicit `null`. A missing key
  is a configuration error: `null` is an assertion ("the arguments go nowhere
  observable", "the result carries no label"), not a default.
* `sink` MAY be a template. `{name}` is replaced by the argument `name`, which MUST
  be non-empty printable text of at most 200 characters; otherwise the call is
  refused. The resulting name MUST be a declared sink, so an argument cannot choose
  a destination the policy does not allow.
* `results` — other MCP methods whose results enter the model's context, each with
  the declared source they are read as.
* `context_source` — the declared source the user's own input is read as. Without it, the
  conversation starts public and fully trusted (the join identity), so the first call is
  checked as if nothing confidential had been said; name the source if that is untrue.

A tool the configuration does not name maps to the sink `tool.<name>`, which no
policy declares. It is therefore refused by the ordinary default-deny rule
([labels.md](labels.md) §5), and the refusal is recorded as a `deny`.

## 3. Behaviour

For `tools/call`, before it reaches the server: the sink is derived, and the
conversation label is checked against it exactly as `emit` checks a value. A sink
that requires consent asks the session's consent provider. A refusal is answered
to the client as an MCP tool error (`isError: true`) so the model sees why, and
the request is **not forwarded**.

For a result, before it reaches the client: it is read as the tool's declared
`source` and joined into the conversation label. The payload is not retained.

Also:

* A JSON-RPC **batch** is refused. The current MCP revision does not allow
  batches, and a batch is a way to hide a call among others.
* A `tools/call` **notification** (no id) is dropped: a call nobody can answer is
  not one to run.
* A **response whose id nobody is waiting on** is dropped, not forwarded: a server
  cannot inject results the client did not ask for. An id already in flight is
  refused.
* Server-initiated **`sampling/createMessage`** and **`elicitation/create`** are
  refused with "method not found": they would put unlabelled server text in front
  of the model.
* A line is read **strictly**: duplicate object keys and `NaN`/`Infinity` are parse
  errors, because JSON implementations disagree about them (first key wins, last
  key wins) and a message that is innocent to the gateway and a tool call to the
  server is a bypass. What is forwarded is the gateway's own re-serialisation of the
  message it checked, not the original bytes, so the server reads exactly what was
  checked.
* At most 10 000 requests may be in flight; more are refused.
* Lines that are not JSON are not forwarded.
* When the **server dies** with requests in flight, each of them is answered with a
  JSON-RPC internal error (`-32603`) and the gateway exits with the server's exit
  code, so the client sees an end of stream instead of waiting forever. Client input
  is read from the raw descriptor, because a buffered `stdin` can make the
  interpreter abort at shutdown when a thread is still blocked on it.
* A refusal is returned as an ordinary tool error: `isError: true` with
  `resultType: "complete"`. The 2026-07-28 revision rejects a result without
  `resultType`; earlier revisions ignore the field.
* **Input-required round trips** (revision 2026-07-28): a tool result that asks the
  client for input is labelled like any other result, and the client's retry is a
  new `tools/call`, checked again like any other. Over stdio that revision has no
  server-initiated requests, which is why the two refused above only matter to the
  earlier one.
* When the client disconnects, the gateway waits (up to five seconds) for the
  answers it is still owed before it closes the server's input.

## 4. Tested against

The official MCP Python SDK, client and server unmodified, over the gateway:

* SDK **1.30.0** (`initialize` handshake) and SDK **2.3.0** (revision 2026-07-28:
  `server/discover`, per-request `_meta`, `resultType`), by `tests/test_interop_mcp_sdk.py`.
* Refused calls reach the client as tool errors and never reach the server; labels
  and the journal are correct; parallel calls are decided independently; text with
  escapes, an emoji and U+2028 survives; resources are labelled; a server dying
  mid-call is reported; a 1.x server's sampling request is refused; the 2.x
  input-required round trip works.

Not tested: any MCP *application* (a desktop client, an IDE), any transport but
stdio, protocol revisions other than those two, and servers that misbehave in ways
the SDK's server does not.

## 5. What it does not do

Stated because each one is a way the guarantee does not hold:

* **Methods not listed in `results`** put their results into the model's context
  unlabelled. The configuration is where that is closed, and it is a gap.
* **Only stdio.** There is no HTTP transport and no TLS-terminating mode.
* **Tool arguments are not inspected.** The gateway reasons about labels, not
  content: it cannot tell that a permitted `search` query contains something it
  should not (non-property N1).
* **No human is attached** to `kelvra gateway`, so sinks that require consent are
  refused. A library embedding can supply a consent provider.
* **Declassification** is a control-plane act (`Gateway.relabel`), not something
  the gateway or the agent can do.
* **A server that cheats about what its tools do** (adversary A3) is outside the
  model; the declared `sink` and `source` are the operator's claim.
* **The proxy is a trust-base component.** If the agent can reach the server
  without it, or edit the policy, nothing here holds.
