"""Does the gateway read a message the way the program behind it will?

Three automated reviews in a row found the same kind of hole in the gateway: it
read a line one way and a different JSON decoder would read it another (duplicate
keys, hybrid request/response, member names in another case, method names in another
case). Fixing them one report at a time is how the fourth gets missed, so this tests
the property itself.

For thousands of generated, deliberately awkward lines, the gateway decides; if it
forwards something, every real decoder available here (Python, Node, Ruby, PHP, Perl,
jq and Go, whose ``encoding/json`` ignores case) is asked what it sees in what was
forwarded, and the answer must be what the gateway checked: the same method, the same
tool name, the same ``to`` argument, the same notion of "is this a response".

A decoder that refuses the line is fine (it will not act on it). A decoder that
accepts it and sees something different is a bypass.

A control test runs the same comparison against a gateway that forwards the original
bytes, and requires the harness to find disagreements, so that "no mismatch" cannot be
the result of a harness that looks at nothing.
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "support"))

import json_peers

from kelvra import Kelvra, parse
from kelvra.gateway import FilterOutput, Gateway, GatewayConfig, McpFilter

BS = chr(92)  # a backslash, so no escape sequence has to be typed in this file
N_CLIENT = int(os.environ.get("KELVRA_DIFF_CLIENT", "4000"))
N_SERVER = int(os.environ.get("KELVRA_DIFF_SERVER", "1500"))

POLICY = """\
policy Diff
principal staff
source inbox
    confidential(staff)
    integrity untrusted
sink mail.staff
    accepts public
sink mail.external
    accepts public
"""

CONFIG = {
    "tools": {
        "send_email": {"sink": "mail.{to}", "source": None},
        "echo": {"sink": "mail.staff", "source": None},
        "read_inbox": {"sink": None, "source": "inbox"},
    },
    "results": {"tools/list": "inbox"},
}


def fresh_filter() -> tuple[McpFilter, list[tuple[str, object]]]:
    """A filter whose ``before_call`` decisions are recorded, to say what was checked."""
    policy = parse(POLICY)
    gateway = Gateway(Kelvra(policy), GatewayConfig.from_dict(CONFIG, policy))
    checked: list[tuple[str, object]] = []
    original = gateway.before_call

    def recording(tool, arguments):
        original(tool, arguments)
        checked.append((tool, arguments))

    gateway.before_call = recording  # type: ignore[method-assign]
    return McpFilter(gateway), checked


# -- generating awkward lines ------------------------------------------------------


def lit(text: str, rng: random.Random | None = None) -> str:
    """A JSON string literal, ASCII-escaped or (sometimes) with raw characters."""
    if rng is not None and rng.random() < 0.15:
        return json.dumps(text, ensure_ascii=False)
    return json.dumps(text)


def spell(rng: random.Random, key: str) -> str:
    """A JSON literal for ``key``, often spelled so a lenient decoder would still match it."""
    # Mostly the plain spelling, so that a fair share of lines is well formed and gets
    # forwarded; the rest are the tricks. Without that bias almost nothing passes the gateway
    # and there is nothing to compare.
    r = rng.random()
    if r < 0.88:
        return lit(key)
    r = (r - 0.88) / 0.12 * 0.4 + 0.40  # spread the remainder over the variants below
    if r < 0.50:
        return lit(key.upper())
    if r < 0.58:
        return lit(key.capitalize())
    if r < 0.66:
        return lit("".join(c.upper() if rng.random() < 0.5 else c for c in key))
    if r < 0.78:
        swaps = {
            "s": chr(0x17F),
            "k": chr(0x212A),
            "i": rng.choice([chr(0x131), chr(0x130)]),
            "a": chr(0xFF41),
            "e": chr(0xFF45),
            "t": chr(0xFF54),
            "n": chr(0xFF4E),
            "m": chr(0xFF4D),
        }
        return lit("".join(swaps.get(c, c) if rng.random() < 0.7 else c for c in key), rng)
    if r < 0.84:
        cut = rng.randrange(len(key) + 1)
        return lit(key[:cut] + rng.choice([chr(0x200B), chr(0), chr(0xFEFF), " "]) + key[cut:])
    if r < 0.90:
        return lit(key + rng.choice([" ", chr(0xA0), chr(0x2028)]))
    # the same name, spelled with \u escapes: a decoder must read it as the plain one
    return '"' + "".join(f"{BS}u{ord(c):04x}" for c in key) + '"'


METHODS = [
    '"tools/call"',
    '"tools/call"',
    '"tools/call"',
    '"Tools/Call"',
    '"TOOLS/CALL"',
    lit("tool" + chr(0x17F) + "/call"),
    '"ping"',
    '"notifications/initialized"',
    '"tools/list"',
    '"sampling/createMessage"',
    '"Sampling/CreateMessage"',
    "5",
    "null",
    '["tools/call"]',
    "true",
]
NAMES = [
    '"send_email"',
    '"send_email"',
    '"echo"',
    '"read_inbox"',
    '"exfiltrate"',
    '"Send_Email"',
    '"send_email "',
    lit("send_emai" + chr(0x131)),
    "5",
    "null",
    '""',
    '["send_email"]',
]
TOS = [
    '"staff"',
    '"staff"',
    '"external"',
    '"STAFF"',
    '"staff "',
    lit("staff" + chr(0)),
    lit("sta" + chr(0x17F) + "f"),
    '""',
    lit("x" * 300),
    "5",
    "null",
    '["staff"]',
    '{"a":1}',
]
IDS = [
    "1",
    "1",
    "2",
    '"a"',
    '"1"',
    "7",
    "1.0",
    "1e0",
    "1E2",
    "-0",
    "1e999",
    "-1e999",
    "9007199254740993",
    "123456789012345678901234567890",
    "true",
    "null",
    "[1]",
    "{}",
]
RESULTS = ["{}", "[]", "null", '"x"', "5", '{"content":[]}', "true"]
ERRORS = ['{"code":-1,"message":"m"}', "null", '"e"', "5"]
EXTRAS = ["debug", "x", "jsonrpc2", "params2", "Params", "ID", "meta", "_meta", "Result", "ERROR"]


def obj(pairs: list[tuple[str, str]]) -> str:
    return "{" + ",".join(f"{k}:{v}" for k, v in pairs) + "}"


def member(rng, out: list[tuple[str, str]], name: str, values: list[str], dup=0.08) -> None:
    out.append((spell(rng, name), rng.choice(values)))
    if rng.random() < dup:  # a second, differently spelled and valued, copy
        out.append((rng.choice([lit(name), spell(rng, name)]), rng.choice(values)))


def generate_client(rng: random.Random) -> str:
    kind = rng.choice(["call"] * 6 + ["ping", "note", "resp", "weird"])
    top: list[tuple[str, str]] = []
    if rng.random() < 0.9:
        top.append(('"jsonrpc"', '"2.0"'))
    if kind in ("call", "ping", "resp", "weird"):
        member(rng, top, "id", IDS[:9] if rng.random() < 0.8 else IDS)
    if kind == "call":
        member(rng, top, "method", METHODS[:4] + METHODS[5:7], 0.25)
        inner: list[tuple[str, str]] = []
        member(rng, inner, "name", NAMES, 0.25)
        args: list[tuple[str, str]] = []
        member(rng, args, "to", TOS, 0.3)
        if rng.random() < 0.5:
            args.append((spell(rng, "body"), '"b"'))
        arg_value = obj(args) if rng.random() < 0.9 else rng.choice(["[]", "null", '"s"', "5"])
        inner.append((spell(rng, "arguments"), arg_value))
        if rng.random() < 0.15:
            inner.append((spell(rng, "arguments"), obj([(lit("to"), '"external"')])))
        top.append((spell(rng, "params"), obj(inner) if rng.random() < 0.93 else "[]"))
    elif kind == "ping":
        member(rng, top, "method", METHODS, 0.2)
    elif kind == "note":
        member(rng, top, "method", METHODS, 0.2)
    elif kind == "resp":
        member(rng, top, "result", RESULTS, 0.2)
    else:  # hybrids and nonsense
        member(rng, top, "method", METHODS, 0.3)
        member(rng, top, "result", RESULTS, 0.4)
        member(rng, top, "error", ERRORS, 0.4)
        member(rng, top, "params", ["{}", "[]", "null", '"p"'], 0.3)
    for _ in range(rng.choice([0, 0, 0, 1, 2])):
        top.append((spell(rng, rng.choice(EXTRAS)), rng.choice(RESULTS)))
    if rng.random() < 0.3:
        rng.shuffle(top)
    text = obj(top)
    r = rng.random()
    if r < 0.03:
        text = "[" + text + "]"
    elif r < 0.05:
        text = chr(0xFEFF) + text
    elif r < 0.07:
        text = text[:-1]  # truncated
    elif r < 0.09:
        text = text + " " + text
    return text


def generate_call_with_one_trick(rng: random.Random) -> str:
    """A valid ``tools/call`` with exactly one thing wrong, or odd but legal.

    The free-for-all generator is hostile enough that almost nothing reaches a decoder, so
    the case the gateway exists for -- a tool call it lets through -- is barely tested.
    Starting from a message it would accept and changing one thing tests what an attacker
    would actually try, and the harmless variations (member order, whitespace, escapes in
    names and values, extra members, long or unusual text) must pass and be read the same.
    """
    tool = rng.choice(["send_email", "send_email", "echo", "read_inbox"])
    to = rng.choice(["staff", "external"])
    members = {
        "jsonrpc": '"2.0"',
        "id": rng.choice(["1", "2", '"a"', '"req-7"', "123456"]),
        "method": '"tools/call"',
    }
    arguments = {
        "to": lit(to),
        "body": lit(rng.choice(["b", "caf\u00e9", "x" * 400, "line\nbreak"])),
    }
    params = {"name": lit(tool), "arguments": obj([(lit(k), v) for k, v in arguments.items()])}
    pairs = [*members.items(), ("params", None)]
    trick = rng.choice(
        ["none", "none", "order", "space", "escape", "extra", "respell", "dup", "value", "hybrid",
         "id", "argrespell", "argdup", "extrainner", "unicode_value"]
    )  # fmt: skip

    def render(order: list[str] | None = None) -> str:
        names = order or [k for k, _ in pairs]
        out = []
        for name in names:
            if name == "params":
                inner = [(lit(k), v) for k, v in params.items()]
                out.append((lit(name), obj(inner)))
            else:
                out.append((lit(name), members[name]))
        return obj(out)

    if trick == "none":
        return render()
    if trick == "order":
        names = [k for k, _ in pairs]
        rng.shuffle(names)
        return render(names)
    if trick == "space":
        return render().replace(",", " ,\n\t ").replace(":", " : ")
    if trick == "escape":
        text = render()
        for word in ("method", "name", "arguments", "to", "tools"):
            if rng.random() < 0.5:
                text = text.replace(
                    f'"{word}"', '"' + "".join(f"{BS}u{ord(c):04x}" for c in word) + '"'
                )
        return text
    if trick == "extra":
        members[rng.choice(EXTRAS)] = rng.choice(RESULTS)
        pairs.append((next(reversed(members)), None))
        return render()
    if trick == "extrainner":
        params[rng.choice(["_meta", "extra", "Extra", "cursor"])] = rng.choice(RESULTS)
        return render()
    if trick == "unicode_value":
        params["arguments"] = obj(
            [
                (lit("to"), lit(to)),
                (lit("body"), lit("h\u00e9llo \U0001f642 " + chr(0x2028) + chr(0x131))),
            ]
        )
        return render()
    if trick == "id":
        members["id"] = rng.choice(IDS)
        return render()
    if trick == "value":
        which = rng.choice(["method", "name", "to"])
        if which == "method":
            members["method"] = rng.choice(METHODS)
        elif which == "name":
            params["name"] = rng.choice(NAMES)
        else:
            params["arguments"] = obj([(lit("to"), rng.choice(TOS)), (lit("body"), '"b"')])
        return render()
    if trick == "hybrid":
        members[rng.choice(["result", "error"])] = rng.choice(RESULTS)
        pairs.append((next(reversed(members)), None))
        return render()
    # the remaining tricks respell or duplicate one name
    names = {
        "respell": ["jsonrpc", "id", "method", "params"],
        "dup": ["id", "method", "params"],
        "argrespell": ["name", "arguments", "to"],
        "argdup": ["name", "arguments", "to"],
    }[trick]
    victim = rng.choice(names)
    text = render()
    plain = lit(victim)
    other = spell(rng, victim)
    if trick in ("respell", "argrespell"):
        return text.replace(plain, other, 1)
    value = {
        "id": rng.choice(IDS),
        "method": rng.choice(METHODS),
        "params": "{}",
        "name": rng.choice(NAMES),
        "arguments": "{}",
        "to": rng.choice(TOS),
    }[victim]
    # a second copy of the name, spelled differently and given another value, before the first
    return text.replace(plain, other + ":" + value + "," + plain, 1)


def generate_server(rng: random.Random) -> str:
    top: list[tuple[str, str]] = []
    if rng.random() < 0.9:
        top.append(('"jsonrpc"', '"2.0"'))
    member(rng, top, "id", ["1", "1", "2", '"a"', "7", "1.0", "99", "null", "true"], 0.15)
    kind = rng.choice(["ok"] * 4 + ["err", "hybrid", "request", "both"])
    if kind == "ok":
        member(rng, top, "result", RESULTS, 0.2)
    elif kind == "err":
        member(rng, top, "error", ERRORS, 0.2)
    elif kind == "both":
        member(rng, top, "result", RESULTS, 0.1)
        member(rng, top, "error", ERRORS, 0.1)
    elif kind == "hybrid":
        member(rng, top, "method", METHODS, 0.2)
        member(rng, top, rng.choice(["result", "error"]), RESULTS, 0.2)
    else:
        member(rng, top, "method", METHODS, 0.2)
        member(rng, top, "params", ["{}", "[]", "null"], 0.2)
    for _ in range(rng.choice([0, 0, 1])):
        top.append((spell(rng, rng.choice(EXTRAS)), rng.choice(RESULTS)))
    return obj(top)


# -- the gateway's own view --------------------------------------------------------


def _strict(line: str):
    def refuse(name):
        raise ValueError(name)

    return json.loads(line, parse_constant=refuse)


def _exact_get(obj_, key, default=None):
    return obj_.get(key, default)


def gateway_view(line: str):
    return json_peers.view_of(_strict(line), _exact_get)


def _uses_to(name: str | None) -> bool:
    spec = CONFIG["tools"].get(name or "")
    return bool(spec and spec["sink"] and "{to}" in spec["sink"])


def comparable(peer_view, gateway_view_) -> bool:
    """Does the peer see what the gateway acted on?

    Only the fields the gateway interprets for this message are compared: its method, its
    result/error shape and its id always; the tool name for a ``tools/call``; and the ``to``
    argument for a tool whose destination is built from it. A Go decoder reading
    ``arguments.TO`` as ``to`` inside a ``ping`` is not a bypass of anything. An id one
    side cannot represent (``None``) is skipped.
    """
    if peer_view is None or gateway_view_ is None:
        return False
    fields = [0, 3, 4]
    if gateway_view_[0] == "tools/call":
        fields.append(1)
        if _uses_to(gateway_view_[1]):
            fields.append(2)
    if any(peer_view[i] != gateway_view_[i] for i in fields):
        return False
    return peer_view[5] is None or gateway_view_[5] is None or peer_view[5] == gateway_view_[5]


_PROBED: dict[str, bool] = {}


def _works(peer) -> bool:
    """Is the decoder installed *and* does it answer a trivial question correctly?

    A runtime that is present but unusable (an old Ruby, a PHP without the json extension,
    a Go that cannot build offline) must not turn the suite red for a reason that has
    nothing to do with the gateway, nor be counted as a decoder that agreed.
    """
    if peer.name not in _PROBED:
        try:
            probe = '{"method":"m","params":{"name":"n","arguments":{"to":"t"}},"id":1}'
            view = peer.available() and peer.run([probe])[0]
            expected = ["m", "n", "t", False, False, "i:1"]
            _PROBED[peer.name] = bool(view) and (
                view[:5] == expected[:5] and view[5] in (None, expected[5])
            )
        except Exception:
            _PROBED[peer.name] = False
    return _PROBED[peer.name]


def available_peers():
    peers = [p for p in json_peers.all_peers() if _works(p)]
    required = [n for n in os.environ.get("KELVRA_REQUIRE_PEERS", "").split(",") if n]
    missing = [n for n in required if n not in {p.name for p in peers}]
    assert not missing, (
        f"required JSON decoders are not usable here: {missing} "
        "(KELVRA_REQUIRE_PEERS makes a missing decoder a failure instead of a skip)"
    )
    return peers


# -- the tests -----------------------------------------------------------------------


def _run_client_side(lines: list[str]):
    """Forward every line through a fresh filter; return what was forwarded and checked."""
    records = []
    for line in lines:
        flt, checked = fresh_filter()
        out = flt.client_to_server(line)
        records.append((line, out, list(checked)))
    return records


def _compare(records, forward_of, peers):
    """Mismatches, per peer, between what the gateway checked and what a peer would see."""
    forwarded = [(i, forward_of(r)) for i, r in enumerate(records) if forward_of(r) is not None]
    texts = [text for _, text in forwarded]
    mismatches: dict[str, list[str]] = {p.name: [] for p in peers}
    refused: dict[str, int] = {p.name: 0 for p in peers}
    for peer in peers:
        views = peer.run(texts)
        for (_, text), view in zip(forwarded, views, strict=True):
            if view is None:
                refused[peer.name] += 1  # the peer will not act on it: harmless
            elif not comparable(view, gateway_view(text)):
                mismatches[peer.name].append(
                    f"{text!r}\n    gateway {gateway_view(text)} / {peer.name} {view}"
                )
    return forwarded, mismatches, refused


def test_what_the_gateway_forwards_is_what_every_real_decoder_sees_client_to_server():
    rng = random.Random(20261026)
    lines = [
        generate_call_with_one_trick(rng) if i % 2 else generate_client(rng)
        for i in range(N_CLIENT)
    ]
    records = _run_client_side(lines)
    forwarded, mismatches, _ = _compare(
        records, lambda r: r[1].forward[0] if r[1].forward else None, available_peers()
    )

    # the harness must be exploring, not looking at a handful of easy lines
    assert len(forwarded) > N_CLIENT // 30, f"only {len(forwarded)} of {N_CLIENT} were forwarded"
    assert len(forwarded) < N_CLIENT * 0.6, (
        "the gateway forwarded almost everything: nothing was awkward"
    )

    # what the gateway *checked* must be what it forwarded, as a call to that tool
    for line, out, checked in records:
        if not out.forward:
            continue
        sent = gateway_view(out.forward[0])
        if sent[0] == "tools/call":
            assert len(checked) == 1, (line, checked)
            params = _strict(out.forward[0])["params"]
            assert checked[0][0] == params["name"] and checked[0][1] == params.get("arguments")
        else:
            assert not checked, (line, checked)

    bad = {name: found for name, found in mismatches.items() if found}
    assert not bad, "a decoder reads a forwarded message differently:\n" + "\n".join(
        f"  [{name}] {len(found)} e.g. {found[0]}" for name, found in bad.items()
    )


def test_a_forwarded_message_is_strict_json_to_every_decoder_not_only_to_python():
    """Re-serialising Python values can emit text that is not JSON (Infinity, NaN)."""
    rng = random.Random(7)
    lines = [generate_client(rng) for _ in range(N_CLIENT)] + [
        '{"jsonrpc":"2.0","id":1e999,"method":"ping"}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1e999}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":-1e999}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1E400}}',
    ]
    for line in lines:
        flt, _ = fresh_filter()
        for forwarded in flt.client_to_server(line).forward:
            try:
                _strict(forwarded)
            except ValueError as error:
                pytest.fail(f"forwarded text is not strict JSON ({error}): {forwarded[:200]!r}")
            assert "Infinity" not in forwarded and "NaN" not in forwarded, forwarded[:200]


def test_what_the_gateway_hands_the_client_is_what_every_real_decoder_sees():
    rng = random.Random(99)
    lines = [generate_server(rng) for _ in range(N_SERVER)]
    records = []
    for line in lines:
        flt, _ = fresh_filter()
        for pending in (1, 2, '"a"', 7):  # requests the client has made and awaits answers to
            flt.client_to_server(
                json.dumps({"jsonrpc": "2.0", "id": json.loads(str(pending)), "method": "ping"})
            )
        waiting = flt.pending
        out = flt.server_to_client(line)
        records.append((line, out, (waiting, flt.pending)))

    # What the gateway DID with each forwarded message must match what it is, to anyone.
    # Comparing views read back out of the forwarded text would be circular: a hybrid
    # carries "result" in the text whether or not the gateway took its label.
    for line, out, (before, after) in records:
        if not out.forward:
            continue
        sent = _strict(out.forward[0])
        is_response = "result" in sent or "error" in sent
        if is_response:
            assert "method" not in sent, (line, out.forward)
            assert after == before - 1, ("a response was forwarded without being taken", line)
        else:
            assert after == before, ("a request or notification consumed a pending call", line)

    forwarded, mismatches, _ = _compare(
        records, lambda r: r[1].forward[0] if r[1].forward else None, available_peers()
    )
    assert len(forwarded) > N_SERVER // 20, f"only {len(forwarded)} of {N_SERVER} were forwarded"
    bad = {name: found for name, found in mismatches.items() if found}
    assert not bad, "a decoder reads a forwarded server message differently:\n" + "\n".join(
        f"  [{name}] {len(found)} e.g. {found[0]}" for name, found in bad.items()
    )


class _ForwardsVerbatim:
    """A deliberately naive gateway: it checks what it parsed, and forwards the original bytes."""

    def __init__(self, flt: McpFilter) -> None:
        self._flt = flt

    def client_to_server(self, line: str) -> FilterOutput:
        out = self._flt.client_to_server(line)
        return FilterOutput(forward=(line,), reply=out.reply) if out.forward else out


def test_the_harness_finds_the_bugs_a_naive_gateway_would_have(monkeypatch):
    """Power check. If a careless gateway showed no disagreement, the tests above would prove
    nothing. This one parses leniently (the last duplicate wins, NaN and Infinity pass, any
    spelling goes), checks what it parsed, and forwards the original bytes: it must show
    plenty of disagreement, from exactly the decoders expected to differ."""
    import kelvra.gateway as gateway_module

    monkeypatch.setattr(gateway_module, "_parse", json.loads)
    rng = random.Random(20261026)
    lines = [generate_client(rng) for _ in range(N_CLIENT)]
    forwarded: list[str] = []
    for line in lines:
        flt, _ = fresh_filter()
        out = _ForwardsVerbatim(flt).client_to_server(line)
        if out.forward:
            forwarded.append(out.forward[0])
    assert len(forwarded) > 50

    found: dict[str, int] = {}
    for peer in available_peers():
        views = peer.run(forwarded)
        count = 0
        for text, view in zip(forwarded, views, strict=True):
            try:
                mine = json_peers.view_of(json.loads(text), _exact_get)
            except ValueError:
                continue
            if view is not None and not comparable(view, mine):
                count += 1
        found[peer.name] = count

    assert found["python-first"] > 0, found  # duplicate keys: first wins, not last
    assert found["python-casefold"] > 0, found  # a decoder that ignores case
    if "go" in found:
        assert found["go"] > 0, found  # the real one
    assert sum(found.values()) > 20, found


def test_the_peers_that_ran_are_reported():
    names = [p.name for p in available_peers()]
    assert {"python-last", "python-first", "python-casefold"} <= set(names)
    print("peers:", ", ".join(names))
