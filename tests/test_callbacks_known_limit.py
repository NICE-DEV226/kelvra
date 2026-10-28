"""Callbacks see plaintext and closures are not tracked. Written down so it stays true.

``Tainted``'s docstring used to say that ``unsafe_value`` was the only way a payload leaves
the label model. It is not: ``map``, ``model_call(produce=...)`` and ``declassify(transform=...)``
all give the raw payload to a function, and a function can read other values on the side.
These tests state what is true, show the way that works (pass the value as an input), and pin
the documentation to the behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kelvra import Denied, Kelvra, Tainted, parse

POLICY = """\
policy P
principal a
source pub
    public
    integrity trusted
source sec
    confidential(a)
    integrity trusted
sink open
    accepts public
sink inner
    accepts confidential(a)
declassify widen
    from confidential(a)
    to public
    audit always
"""


def session():
    k = Kelvra(parse(POLICY), signing_key=b"k" * 32)
    return k, k.agent_session()


def test_each_callback_receives_the_raw_payload():
    k, s = session()
    seen = []
    sec = s.read("sec", "SECRET")
    sec.map(lambda v: seen.append(("map", v)))
    s.model_call("m", sec, produce=lambda v: seen.append(("produce", v)))
    k.declassify("widen", sec, transform=lambda v: seen.append(("transform", v)))
    assert seen == [("map", "SECRET"), ("produce", "SECRET"), ("transform", "SECRET")]


def test_known_limit_a_closure_over_another_value_is_not_joined_in():
    """Documented, not defended: Kelvra labels what it is given, not what a function reads."""
    _, s = session()
    pub, sec = s.read("pub", "hello"), s.read("sec", "SECRET")
    leaked = pub.map(lambda _: sec.unsafe_value)
    assert leaked.label == pub.label  # the secret's label is not in it
    assert s.would_allow("open", leaked) is True
    assert s.emit("open", leaked) == "SECRET"
    via_call = s.model_call("m", pub, produce=lambda _: sec.unsafe_value)
    assert s.would_allow("open", via_call) is True


def test_a_value_passed_as_an_input_does_carry_its_label():
    """The way that works: everything the callback needs is an input, so the label joins."""
    _, s = session()
    pub, sec = s.read("pub", "hello"), s.read("sec", "SECRET")
    out = s.model_call("m", pub, sec, produce=lambda p, c: c)
    assert s.would_allow("open", out) is False
    with pytest.raises(Denied):
        s.emit("open", out)
    assert s.emit("inner", out) == "SECRET"  # and the destination that may hold it still works
    mapped = sec.map(lambda v: v.lower())
    assert mapped.label == sec.label and s.would_allow("open", mapped) is False


def test_the_documentation_says_what_the_code_does():
    doc = Tainted.__doc__
    assert "callbacks you hand to the session" in doc
    assert "does *not* find every place" in doc
    assert "only spelling" not in doc
    assert "grep for it" not in Tainted.unsafe_value.__doc__
    assert "Not the only one" in Tainted.unsafe_value.__doc__
    root = Path(__file__).resolve().parents[1]
    limitations = (root / "LIMITATIONS.md").read_text(encoding="utf-8")
    assert "Callbacks see plaintext, and closures are not tracked" in limitations
    assert "not** the only hole" in limitations
