"""Properties, not examples.

The example-based tests say "this input gives that output", and every one of them was
written by someone who already knew the answer. These say what must hold for *every*
input and let hypothesis look for the one that breaks it, then shrink it to the smallest
that still does.

* the label algebra obeys its laws, and joining never lets a flow through that either
  operand alone would be refused;
* a value derived from several sources never carries a more permissive label than the
  join of them, whatever sequence of reads, model calls and maps produced it;
* a policy written out as text and parsed back is the policy that was written, however it
  is indented, commented, or has its lines ended;
* no text at all makes the parser or the language server raise anything but a located error;
* any change to a signed-or-not record, one event at a time, is detected without a key;
* the static analysis says "unreachable" exactly when no execution reaches the sink.

``HYPOTHESIS_PROFILE=thorough`` runs a few thousand examples per property instead of a
hundred; do that before changing the label model, the parser or the record format.
"""

from __future__ import annotations

import itertools
import json
import os
import random

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from kelvra import (  # noqa: E402
    Declassifier,
    Kelvra,
    KlvError,
    Label,
    Policy,
    PrincipalSet,
    Sink,
    Source,
    approved_by,
    check_flow,
    join_all,
    parse,
    verify_record,
)
from kelvra.analysis import analyse  # noqa: E402
from kelvra.gateway import Gateway, GatewayConfig, McpFilter  # noqa: E402
from kelvra.lsp import completions_for, diagnostics_for, hover_at, symbols_for  # noqa: E402

settings.register_profile(
    "ci",
    max_examples=100,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile(
    "thorough",
    max_examples=3000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

NAMES = ["a", "b", "c", "d"]
PURPOSES = ["p", "q"]

# -- strategies ---------------------------------------------------------------------

principal_sets = st.one_of(
    st.just(PrincipalSet.all()),
    st.frozensets(st.sampled_from(NAMES)).map(PrincipalSet.from_iterable),
)
labels = st.builds(Label, principal_sets, principal_sets, principal_sets)
sinks = st.builds(
    Sink,
    st.just("s"),
    audience=principal_sets,
    requires_endorsement=principal_sets,
    purpose=st.sampled_from([None, *PURPOSES, "other"]),
)
declassifiers = st.builds(
    Declassifier,
    st.just("d"),
    grants_readers=principal_sets,
    grants_endorsement=principal_sets,
    grants_purposes=principal_sets,
)


# -- 1. the label algebra -------------------------------------------------------------


@given(labels, labels, labels)
def test_join_is_commutative_associative_and_idempotent(a, b, c):
    assert a.join(b) == b.join(a)
    assert a.join(b).join(c) == a.join(b.join(c))
    assert a.join(a) == a


@given(labels)
def test_public_is_the_identity_and_secret_absorbs(a):
    from kelvra import PUBLIC, SECRET

    assert a.join(PUBLIC) == a
    assert a.join(SECRET) == SECRET


@given(labels, labels)
def test_a_join_is_at_least_as_restrictive_as_each_side_on_every_axis(a, b):
    j = a.join(b)
    assert j.is_at_least_as_restrictive_as(a) and j.is_at_least_as_restrictive_as(b)


@given(labels, labels, sinks)
def test_joining_never_lets_through_what_either_side_alone_would_be_refused(a, b, sink):
    """The safety property of taint propagation: mixing data cannot make it more shareable."""
    if check_flow(a.join(b), sink).allowed:
        assert check_flow(a, sink).allowed and check_flow(b, sink).allowed


@given(labels, declassifiers)
def test_a_declassifier_only_ever_widens(label, d):
    out = d.apply(label)
    assert label.readers <= out.readers
    assert label.endorsers <= out.endorsers
    assert label.purposes <= out.purposes
    assert d.apply(out) == out  # idempotent


@given(labels, declassifiers, declassifiers)
def test_declassifiers_commute(label, d1, d2):
    assert d2.apply(d1.apply(label)) == d1.apply(d2.apply(label))


def _members(ps):
    return None if ps.is_all else frozenset(ps)


def _oracle_le(a, b):
    if b is None:
        return True
    if a is None:
        return False
    return a <= b


@given(labels, sinks)
def test_the_flow_rule_is_the_three_inclusions_of_the_specification(label, sink):
    """labels.md section 5, written out with plain sets, independently of the code."""
    expected = (
        _oracle_le(_members(sink.audience), _members(label.readers))
        and _oracle_le(_members(sink.requires_endorsement), _members(label.endorsers))
        and (sink.purpose is None or label.purposes.is_all or sink.purpose in label.purposes)
    )
    decision = check_flow(label, sink)
    assert decision.allowed == expected
    assert len(decision.reasons) == len(decision.axes)
    assert bool(decision.reasons) == (not expected)


# -- 2. taint tracking over arbitrary programs -------------------------------------------

step = st.one_of(
    st.tuples(st.just("read"), st.integers(0, 2)),
    st.tuples(st.just("call"), st.lists(st.integers(0, 50), min_size=0, max_size=4)),
    st.tuples(st.just("map"), st.integers(0, 50)),
    st.tuples(st.just("combine"), st.lists(st.integers(0, 50), min_size=1, max_size=3)),
)


@given(
    st.lists(labels, min_size=3, max_size=3),
    st.lists(sinks, min_size=1, max_size=3),
    st.lists(step, min_size=1, max_size=14),
)
def test_a_derived_value_is_never_less_restricted_than_the_join_of_its_sources(
    source_labels, sink_list, program
):
    policy = Policy(name="Prop")
    for i, label in enumerate(source_labels):
        policy.add_source(Source(f"s{i}", label))
    for i, sink in enumerate(sink_list):
        policy.add_sink(Sink(f"k{i}", sink.audience, sink.requires_endorsement, sink.purpose))
    k = Kelvra(policy)

    values = []  # (tainted, set of source indexes it derives from)
    for op, arg in program:
        if op == "read":
            values.append((k.read(f"s{arg}", arg), {arg}))
        elif not values:
            continue
        elif op == "call":
            picked = [values[i % len(values)] for i in arg]
            out = k.model_call("m", *(v for v, _ in picked))
            values.append((out, set().union(*(s for _, s in picked), set())))
        elif op == "map":
            v, s = values[arg % len(values)]
            values.append((v.map(lambda x: x), s))
        else:
            picked = [values[i % len(values)] for i in arg]
            label = k.combine("c", *(v for v, _ in picked))
            ancestors = set().union(*(s for _, s in picked))
            assert label == join_all(source_labels[i] for i in ancestors)

    for value, ancestors in values:
        expected = join_all(source_labels[i] for i in ancestors)
        assert value.label == expected  # exactly the join: nothing lost, nothing invented
        for name, sink in policy.sinks.items():
            allowed = k.would_allow(name, value)
            if allowed:  # and so it must have been allowed from every source alone
                assert all(check_flow(source_labels[i], sink).allowed for i in ancestors)


# -- 3. policies written as text ---------------------------------------------------------

identifier = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,6}", fullmatch=True)
decl_name = st.from_regex(r"[A-Za-z_][A-Za-z0-9_.-]{0,8}", fullmatch=True)


@st.composite
def policy_spec(draw):
    principals = draw(st.lists(identifier, min_size=1, max_size=4, unique=True))
    purposes = draw(st.lists(identifier, min_size=0, max_size=2, unique=True))
    names = draw(st.lists(decl_name, min_size=1, max_size=6, unique=True))
    subset = st.lists(st.sampled_from(principals), min_size=1, max_size=3, unique=True)
    purpose = st.sampled_from(purposes) if purposes else st.nothing()
    decls = []
    for name in names:
        kind = draw(st.sampled_from(["source", "sink", "declassify", "endorse"]))
        if kind == "source":
            conf = draw(st.one_of(st.just(("public", None)), subset.map(lambda s: ("conf", s))))
            decls.append(
                (
                    kind,
                    name,
                    {
                        "conf": conf,
                        "purpose": draw(st.one_of(st.none(), purpose)) if purposes else None,
                        "integrity": draw(st.sampled_from([None, "trusted", "untrusted"])),
                    },
                )
            )
        elif kind == "sink":
            decls.append(
                (
                    kind,
                    name,
                    {
                        "accepts": draw(
                            st.one_of(st.just(("public", None)), subset.map(lambda s: ("conf", s)))
                        ),
                        "endorsed": draw(st.lists(subset, max_size=2)),
                        "consent": draw(st.one_of(st.none(), st.sampled_from(principals))),
                        "purpose": draw(st.one_of(st.none(), purpose)) if purposes else None,
                    },
                )
            )
        else:
            tos = draw(
                st.lists(
                    st.one_of(
                        st.just(("public", None)),
                        subset.map(lambda s: ("conf", s)),
                        subset.map(lambda s: ("endorsed", s)),
                    ),
                    min_size=1,
                    max_size=3,
                )
            )
            froms = draw(
                st.lists(
                    st.one_of(
                        st.just(("public", None)),
                        st.just(("untrusted", None)),
                        subset.map(lambda s: ("conf", s)),
                        subset.map(lambda s: ("endorsed", s)),
                    ),
                    max_size=2,
                )
            )
            decls.append(
                (
                    kind,
                    name,
                    {
                        "to": tos,
                        "from": froms,
                        "consent": draw(st.one_of(st.none(), st.sampled_from(principals))),
                        "audit": draw(st.booleans()),
                    },
                )
            )
    return {"principals": principals, "purposes": purposes, "decls": decls}


def _names(kind, subset):
    return f"{kind}({', '.join(subset)})"


def render(spec, rng: random.Random | None = None, *, indent="    ", eol="\n", noisy=False) -> str:
    """Write a spec as .klv; with ``noisy``, with comments and blank lines in odd places."""
    rng = rng or random.Random(0)
    lines = ["policy Prop", "version 3"]
    lines.append("principal " + ", ".join(spec["principals"]))
    if spec["purposes"]:
        lines.append("purpose " + ", ".join(spec["purposes"]))

    def clause(text):
        return indent + text

    for kind, name, d in spec["decls"]:
        lines.append(f"{kind} {name}")
        if kind == "source":
            what, subset = d["conf"]
            text = "public" if what == "public" else _names("confidential", subset)
            if d["purpose"]:
                text += f" for {d['purpose']}"
            lines.append(clause(text))
            if d["integrity"]:
                lines.append(clause(f"integrity {d['integrity']}"))
        elif kind == "sink":
            what, subset = d["accepts"]
            lines.append(
                clause(
                    "accepts " + ("public" if what == "public" else _names("confidential", subset))
                )
            )
            for names in d["endorsed"]:
                lines.append(clause("requires " + _names("endorsed", names)))
            if d["consent"]:
                lines.append(clause(f"requires consent({d['consent']})"))
            if d["purpose"]:
                lines.append(clause(f"for {d['purpose']}"))
        else:
            for what, subset in d["from"]:
                lines.append(
                    clause(
                        "from "
                        + (
                            what
                            if what in ("public", "untrusted")
                            else _names("confidential" if what == "conf" else "endorsed", subset)
                        )
                    )
                )
            for what, subset in d["to"]:
                lines.append(
                    clause(
                        "to "
                        + (
                            "public"
                            if what == "public"
                            else _names("confidential" if what == "conf" else "endorsed", subset)
                        )
                    )
                )
            if d["consent"]:
                lines.append(clause(f"requires consent({d['consent']})"))
            if d["audit"]:
                lines.append(clause("audit always"))
        if noisy:
            if rng.random() < 0.5:
                lines.insert(rng.randrange(1, len(lines)), "")
            if rng.random() < 0.5:
                lines.insert(
                    rng.randrange(1, len(lines) + 1),
                    "# a comment, with ( parentheses ) and, commas",
                )
    if noisy:
        lines = [ln + "   # trailing" if ln.strip() and rng.random() < 0.2 else ln for ln in lines]
        lines = [ln + "  " if ln.strip() and rng.random() < 0.2 else ln for ln in lines]
    return eol.join(lines) + eol


def oracle(spec) -> Policy:
    """The policy the spec means, built through the Python API, never through the parser."""

    def ps(what, subset):
        return PrincipalSet.all() if what == "public" else PrincipalSet.from_iterable(subset)

    p = Policy(name="Prop", version=3)
    for kind, name, d in spec["decls"]:
        if kind == "source":
            readers = ps(*d["conf"])
            endorsers = {
                None: PrincipalSet.all(),
                "trusted": PrincipalSet.all(),
                "untrusted": PrincipalSet.none(),
            }[d["integrity"]]
            purposes = PrincipalSet.of(d["purpose"]) if d["purpose"] else PrincipalSet.all()
            p.add_source(Source(name, Label(readers, endorsers, purposes)))
        elif kind == "sink":
            req = PrincipalSet.none()
            for names in d["endorsed"]:
                req = req | PrincipalSet.from_iterable(names)
            p.add_sink(Sink(name, ps(*d["accepts"]), req, d["purpose"], d["consent"]))
        else:
            readers = endorse = PrincipalSet.none()
            for what, subset in d["to"]:
                if what in ("public", "conf"):
                    readers = readers | ps(what, subset)
                else:
                    endorse = endorse | PrincipalSet.from_iterable(subset)
            expects = None
            for what, subset in d["from"]:
                bound = {
                    "public": Label(),
                    "untrusted": Label(endorsers=PrincipalSet.none()),
                    "conf": Label(readers=PrincipalSet.from_iterable(subset or [])),
                    "endorsed": Label(endorsers=PrincipalSet.from_iterable(subset or [])),
                }[what]
                expects = bound if expects is None else expects.join(bound)
            p.add_declassifier(
                Declassifier(
                    name, readers, endorse, requires_consent_from=d["consent"], expects=expects
                )
            )
    return p


@given(policy_spec())
def test_a_policy_written_out_and_parsed_back_is_the_policy_that_was_written(spec):
    assert parse(render(spec)).fingerprint() == oracle(spec).fingerprint()


@given(
    policy_spec(),
    st.sampled_from([" ", "  ", "    ", "\t", "       "]),
    st.sampled_from(["\n", "\r\n", "\r"]),
    st.integers(0, 10_000),
)
def test_indentation_line_endings_comments_and_blank_lines_do_not_change_the_policy(
    spec, indent, eol, seed
):
    plain = parse(render(spec)).fingerprint()
    noisy = parse(render(spec, random.Random(seed), indent=indent, eol=eol, noisy=True))
    assert noisy.fingerprint() == plain


@given(policy_spec())
def test_a_parsed_policy_survives_sealing_and_keeps_its_fingerprint(spec):
    policy = parse(render(spec))
    assert policy.seal().fingerprint() == policy.fingerprint()


@given(st.text(max_size=400))
def test_no_text_makes_the_parser_raise_anything_but_a_located_klv_error(text):
    try:
        parse(text)
    except KlvError as error:
        assert error.line >= 1
    # anything else propagates and fails the test


@given(policy_spec(), st.data())
def test_a_valid_policy_with_a_few_characters_changed_still_only_ever_raises_klv_error(spec, data):
    text = list(render(spec))
    for _ in range(data.draw(st.integers(1, 4))):
        if not text:
            break
        i = data.draw(st.integers(0, len(text) - 1))
        op = data.draw(st.sampled_from(["delete", "insert", "swap"]))
        if op == "delete":
            del text[i]
        elif op == "insert":
            text.insert(
                i,
                data.draw(
                    st.sampled_from([*"#(),*\t \n\r:.-_9aZ", chr(0x2028), chr(0xFEFF), chr(0x131)])
                ),
            )
        elif i + 1 < len(text):
            text[i], text[i + 1] = text[i + 1], text[i]
    try:
        parse("".join(text))
    except KlvError as error:
        assert error.line >= 1


@given(st.text(max_size=300), st.integers(0, 12), st.integers(0, 40))
def test_the_language_server_functions_never_raise_on_any_document(text, line, character):
    diagnostics_for(text)
    symbols_for(text)
    completions_for(text, line, character)
    hover_at(text, line, character)


# -- 4. the record -----------------------------------------------------------------------

ledger_ops = st.lists(
    st.tuples(
        st.sampled_from(["read", "emit_ok", "emit_denied", "emit_unknown", "refuse_read", "join"]),
        st.integers(0, 2),
    ),
    min_size=1,
    max_size=12,
)

LEDGER_POLICY = """\
policy Ledger
principal a, b
source s0
    confidential(a)
    integrity trusted
source s1
    confidential(b)
    integrity trusted
source s2
    public
    integrity trusted
sink open
    accepts public
sink only_a
    accepts confidential(a)
"""


def _record(ops):
    k = Kelvra(parse(LEDGER_POLICY), consent=approved_by("x"))
    held = []
    for op, n in ops:
        try:
            if op == "read":
                held.append(k.read(f"s{n}", n))
            elif not held:
                continue
            elif op == "emit_ok":
                k.emit("open", held[n % len(held)])
            elif op == "emit_denied":
                k.emit("only_a", held[n % len(held)])
            elif op == "emit_unknown":
                k.emit(f"nowhere{n}", held[n % len(held)])
            elif op == "refuse_read":
                k.read(f"missing{n}", 0)
            else:
                held.append(k.model_call("m", *held[: n + 1]))
        except Exception:
            pass
    return k.record()


@given(ledger_ops)
def test_any_run_produces_a_record_that_verifies_without_a_key(ops):
    result = verify_record(_record(ops))
    assert result.ok, result.problems


@given(ledger_ops, st.data())
def test_changing_a_record_one_event_at_a_time_is_always_detected(ops, data):
    record = _record(ops)
    events = record["events"]
    assume(events)
    i = data.draw(st.integers(0, len(events) - 1))
    kind = data.draw(
        st.sampled_from(["delete", "duplicate", "swap", "edit_time", "edit_field", "truncate"])
    )
    tampered = json.loads(json.dumps(record))
    ev = tampered["events"]
    if kind == "delete":
        del ev[i]
    elif kind == "duplicate":
        ev.insert(i, dict(ev[i]))
    elif kind == "swap":
        assume(i + 1 < len(ev) and ev[i] != ev[i + 1])
        ev[i], ev[i + 1] = ev[i + 1], ev[i]
    elif kind == "edit_time":
        ev[i]["at"] = ev[i]["at"][:-1] + ("0" if ev[i]["at"][-1] != "0" else "1")
    elif kind == "edit_field":
        keys = [k for k in ev[i] if k not in ("kind", "seq", "prev") and isinstance(ev[i][k], str)]
        assume(keys)
        key = data.draw(st.sampled_from(keys))
        ev[i][key] = ev[i][key] + "x"
    else:
        del ev[i:]
    assert not verify_record(tampered).ok


@given(
    st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.text(max_size=20),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(st.text(max_size=8), children, max_size=5),
        ),
        max_leaves=25,
    )
)
def test_verify_record_never_raises_on_any_json_value(value):
    assert verify_record(value).ok in (True, False)
    assert verify_record(value, b"k" * 32).ok in (True, False)


# -- 5. the static analysis ---------------------------------------------------------------


@given(
    st.lists(labels, min_size=1, max_size=3),
    st.lists(sinks, min_size=1, max_size=2),
    st.lists(declassifiers, min_size=0, max_size=3),
)
def test_a_sink_is_reported_unreachable_exactly_when_no_execution_reaches_it(srcs, snks, decs):
    policy = Policy(name="A")
    for i, label in enumerate(srcs):
        policy.add_source(Source(f"s{i}", label))
    for i, sink in enumerate(snks):
        policy.add_sink(Sink(f"k{i}", sink.audience, sink.requires_endorsement, sink.purpose))
    for i, d in enumerate(decs):
        policy.add_declassifier(
            Declassifier(f"d{i}", d.grants_readers, d.grants_endorsement, d.grants_purposes)
        )
    flagged = {f.name for f in analyse(policy) if f.code == "unsatisfiable-sink"}
    sources = list(policy.sources.values())
    ds = list(policy.declassifiers.values())
    for name, sink in policy.sinks.items():
        reachable = False
        for r in range(1, len(sources) + 1):
            for subset in itertools.combinations(sources, r):
                base = join_all(s.label for s in subset)
                for count in range(len(ds) + 1):
                    for order in itertools.permutations(ds, count):
                        label = base
                        for d in order:
                            label = d.apply(label)
                        reachable = reachable or check_flow(label, sink).allowed
        assert (name in flagged) == (not reachable), (name, reachable)


# -- 6. the gateway -----------------------------------------------------------------------

_GW_POLICY = (
    "policy G\nprincipal staff\nsource inbox\n    confidential(staff)\n"
    "    integrity untrusted\nsink mail.staff\n    accepts public\n"
)
_GW_CONFIG = {"tools": {"echo": {"sink": "mail.staff", "source": None}}, "results": {}}


def _gateway_filter():
    policy = parse(_GW_POLICY)
    return McpFilter(Gateway(Kelvra(policy), GatewayConfig.from_dict(_GW_CONFIG, policy)))


@given(st.text(max_size=400))
def test_the_gateway_answers_any_line_from_either_side_without_raising(text):
    flt = _gateway_filter()
    flt.client_to_server(text)
    flt.server_to_client(text)


json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=10)),
    lambda c: st.one_of(
        st.lists(c, max_size=3), st.dictionaries(st.text(max_size=6), c, max_size=4)
    ),
    max_leaves=12,
)


@given(json_values)
def test_the_gateway_answers_any_json_value_without_raising(value):
    line = json.dumps(value)
    flt = _gateway_filter()
    flt.client_to_server(line)
    flt.server_to_client(line)


@given(
    st.dictionaries(
        st.sampled_from(["jsonrpc", "id", "method", "params", "extra", "x"]), json_values
    )
)
def test_what_the_gateway_forwards_contains_only_the_members_json_rpc_defines(message):
    flt = _gateway_filter()
    for out in (
        flt.client_to_server(json.dumps(message)),
        _gateway_filter().server_to_client(json.dumps(message)),
    ):
        for line in out.forward:
            assert set(json.loads(line)) <= {"jsonrpc", "id", "method", "params", "result", "error"}
