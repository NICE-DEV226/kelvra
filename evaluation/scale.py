"""How long Kelvra takes, and how much it holds, as policies and runs grow.

    python evaluation/scale.py            # the sizes quoted in LIMITATIONS.md
    python evaluation/scale.py --quick    # tiny sizes; what the test suite runs

Timings depend on the machine and the interpreter, so the numbers in the documentation say where
they were taken. What does not depend on the machine is the *shape*: how a cost grows with the
size of the input. This measures Kelvra's own work (parse, analyse, label, record, verify, filter).
It says nothing about a model, a network or a real agent.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kelvra import Kelvra, Label, PrincipalSet, parse, verify_record
from kelvra.analysis import analyse
from kelvra.gateway import Gateway, GatewayConfig, McpFilter
from kelvra.policy import Declassifier, Policy, Sink, Source

KEY = b"scale-key-not-for-production-use"
RUN_POLICY = "policy P\nprincipal a\nsource s\n    confidential(a)\n    integrity trusted\n"
RUN_POLICY += "sink out\n    accepts confidential(a)\n"


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def klv(sources: int, sinks: int, declassifiers: int) -> str:
    lines = ["policy Big", "principal " + ", ".join(f"p{i}" for i in range(50))]
    for i in range(sources):
        lines += [
            f"source s{i}",
            f"    confidential(p{i % 50}, p{(i + 1) % 50})",
            "    integrity trusted",
        ]
    for i in range(sinks):
        lines += [f"sink k{i}", f"    accepts confidential(p{i % 50})"]
    for i in range(declassifiers):
        lines += [f"declassify d{i}", f"    from confidential(p{i % 50})"]
        lines += [f"    to confidential(p{(i + 7) % 50})", "    audit always"]
    return "\n".join(lines) + "\n"


def useless(n: int, declassifiers: int) -> Policy:
    """Declassifiers granting a principal no sink asks for: every one is unused."""
    policy = Policy(name="Useless")
    for i in range(n):
        policy.add_source(Source(f"s{i}", Label(PrincipalSet.of(f"p{i % 50}"))))
        policy.add_sink(Sink(f"k{i}", PrincipalSet.of(f"p{i % 50}")))
    for i in range(declassifiers):
        policy.add_declassifier(Declassifier(f"d{i}", grants_readers=PrincipalSet.of("nobody")))
    return policy


def distinct(n: int, declassifiers: int) -> Policy:
    """The case that still costs the full product: every label and signature differs, and
    every declassifier asks nothing of any source but matters to every sink."""
    policy = Policy(name="Distinct")
    ys = [f"y{i}" for i in range(declassifiers)]
    for i in range(n):
        policy.add_source(Source(f"s{i}", Label(PrincipalSet.of(f"u{i}", *ys))))
        policy.add_sink(Sink(f"k{i}", PrincipalSet.of(f"u{i}", *ys)))
    for y in ys:
        policy.add_declassifier(Declassifier(f"d_{y}", grants_readers=PrincipalSet.of(y)))
    return policy


def gateway_filter() -> McpFilter:
    policy = parse(
        "policy M\nprincipal staff\nsource user.input\n    confidential(staff)\n"
        "    integrity trusted\nsink mail.staff\n    accepts confidential(staff)\n"
    )
    config = GatewayConfig.from_dict(
        {
            "context_source": "user.input",
            "tools": {"send_email": {"sink": "mail.staff", "source": None}},
            "results": {},
        },
        policy,
    )
    return McpFilter(Gateway(Kelvra(policy), config))


def rows(quick: bool) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []

    def add(what: str, size: str, seconds: float) -> None:
        out.append((what, size, f"{seconds * 1000:,.1f} ms"))

    # -- the policy: parse and analyse ----------------------------------------------------
    n = 100 if quick else 1000
    text = klv(n, n, n // 20)
    policy, seconds = timed(lambda: parse(text))
    add("parse", f"{n} sources, {n} sinks, {n // 20} declassifiers", seconds)
    _, seconds = timed(lambda: analyse(policy))
    add("analyse", "the same policy", seconds)
    for build, label in ((useless, "useless declassifiers"), (distinct, "all-different")):
        size = 60 if quick else 400
        p = build(size, 10)
        _, seconds = timed(lambda p=p: analyse(p))
        add("analyse", f"{size} x {size} x 10, {label}", seconds)

    # -- a run: label, record, verify ---------------------------------------------------------
    pairs = 500 if quick else 20_000
    kelvra = Kelvra(parse(RUN_POLICY), signing_key=KEY)
    session = kelvra.agent_session()

    def run() -> None:
        for _ in range(pairs):
            session.emit("out", session.read("s", "x"))

    _, seconds = timed(run)  # not under tracemalloc, which slows this loop several times over
    events = len(kelvra.ledger.events)
    add("read + emit", f"{pairs:,} pairs = {events:,} events", seconds)
    record, seconds = timed(kelvra.record)
    add(
        "record (chain and sign)",
        f"{events:,} events, {len(json.dumps(record)) // 1024:,} KiB",
        seconds,
    )
    _, seconds = timed(lambda: verify_record(record, KEY))
    add("verify", f"{events:,} events, with the key", seconds)

    # -- what a run holds: measured on its own, because tracing memory distorts time ----------
    sample = 250 if quick else 5_000
    traced = Kelvra(parse(RUN_POLICY), signing_key=KEY)
    traced_session = traced.agent_session()
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    for _ in range(sample):
        traced_session.emit("out", traced_session.read("s", "x"))
    held = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()
    count = len(traced.ledger.events)
    per_event = held // count
    out.append(("held in memory", f"{count:,} events, kept until record()", f"{per_event} B each"))
    out.append(
        ("held in memory", "1,000,000 events (extrapolated, it is linear)", f"{per_event:,} MB")
    )

    # -- the gateway ----------------------------------------------------------------------
    calls = 500 if quick else 20_000
    filt = gateway_filter()

    def through() -> None:
        for i in range(1, calls + 1):
            request = {"jsonrpc": "2.0", "id": i, "method": "tools/call"}
            request["params"] = {"name": "send_email", "arguments": {"to": "staff"}}
            filt.client_to_server(json.dumps(request))
            reply = {"jsonrpc": "2.0", "id": i, "result": {"content": []}}
            filt.server_to_client(json.dumps(reply))

    _, seconds = timed(through)
    out.append(
        (
            "gateway",
            f"{calls:,} tool calls, request and reply",
            f"{seconds / calls * 1e6:,.0f} us per call",
        )
    )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true", help="tiny sizes, for the test suite")
    args = parser.parse_args(argv)
    print(f"Python {sys.version.split()[0]} on {sys.platform}\n")
    print("| what | size | time |\n|---|---|---|")
    for what, size, took in rows(args.quick):
        print(f"| {what} | {size} | {took} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
