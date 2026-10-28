"""The unused-declassifier analysis is faster and says exactly what it said before.

Asking whether a declassifier is needed compared every source with every sink for every
declassifier. On 800 sources, 800 sinks and 10 useless declassifiers that took 35 seconds, and
the language server ran it on every keystroke. Two shortcuts (a declassifier the others already
cover changes nothing; one can only matter to sinks that ask for something it grants) keep the
answer and drop the cost.

"Keep the answer" is the part that has to be shown, so the previous algorithm is kept here,
verbatim, as the reference, and compared on thousands of random policies, including grants the
language cannot express (purposes, the universe) because the shortcut reasons about them.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

import kelvra.analysis as analysis
from kelvra import Label, PrincipalSet, parse_file
from kelvra.analysis import _grants, _reaches, analyse
from kelvra.policy import Declassifier, Policy, Sink, Source

ROOT = Path(__file__).resolve().parents[1]


def reference_unused(policy: Policy) -> list[str]:
    """The algorithm as it was before: every source against every sink, for each declassifier."""
    if not policy.sources or not policy.sinks:
        return []
    with_all = _grants(policy)
    unused = []
    for name in sorted(policy.declassifiers):
        without = _grants(policy, exclude=name)
        needed = False
        for source in policy.sources.values():
            for sink in policy.sinks.values():
                if _reaches(source.label, sink, policy, with_all) and not _reaches(
                    source.label, sink, policy, without
                ):
                    needed = True
                    break
            if needed:
                break
        if not needed:
            unused.append(name)
    return unused


def unused_now(policy: Policy) -> list[str]:
    return [f.name for f in analyse(policy) if f.code == "unused-declassifier"]


def pick(rng: random.Random, pool: list[str], *, allow_all=True, allow_empty=True) -> PrincipalSet:
    roll = rng.random()
    if allow_all and roll < 0.12:
        return PrincipalSet.all()
    if allow_empty and roll < 0.25:
        return PrincipalSet.none()
    return PrincipalSet.from_iterable(rng.sample(pool, rng.randint(1, min(3, len(pool)))))


def random_policy(rng: random.Random) -> Policy:
    principals = [f"p{i}" for i in range(rng.randint(2, 5))]
    purposes = ["billing", "support"]
    policy = Policy(name="Random")
    for i in range(rng.randint(1, 6)):
        label = Label(
            pick(rng, principals, allow_empty=False),
            rng.choice([PrincipalSet.all(), PrincipalSet.none(), pick(rng, principals)]),
            rng.choice([PrincipalSet.all(), PrincipalSet.of(rng.choice(purposes))]),
        )
        policy.add_source(Source(f"s{i}", label))
    for i in range(rng.randint(1, 6)):
        policy.add_sink(
            Sink(
                f"k{i}",
                pick(rng, principals, allow_empty=False),
                pick(rng, principals, allow_all=False),
                rng.choice([None, *purposes]),
                None,
            )
        )
    for i in range(rng.randint(0, 6)):
        policy.add_declassifier(
            Declassifier(
                f"d{i}",
                grants_readers=pick(rng, principals),
                grants_endorsement=pick(rng, principals),
                grants_purposes=rng.choice(
                    [PrincipalSet.none(), PrincipalSet.all(), PrincipalSet.of(rng.choice(purposes))]
                ),
            )
        )
    return policy


def test_the_faster_analysis_gives_the_reference_answer_on_random_policies():
    rng = random.Random(20261027)
    seen = {"needed": 0, "unused": 0, "covered": 0}
    for _ in range(4000):
        policy = random_policy(rng)
        assert unused_now(policy) == reference_unused(policy), policy
        flagged = set(reference_unused(policy))
        seen["unused"] += len(flagged)
        seen["needed"] += len(policy.declassifiers) - len(flagged)
        for name, d in policy.declassifiers.items():
            without = _grants(policy, exclude=name)
            if d.grants_readers <= without[0] and d.grants_endorsement <= without[1]:
                seen["covered"] += 1
    # the generator exercises all three situations the shortcuts distinguish
    assert min(seen.values()) > 500, seen


@pytest.mark.parametrize(
    "path",
    [
        "examples/support_agent/policy.klv",
        "examples/sealed_support_agent/policy.klv",
        "evaluation/policy.klv",
    ],
)
def test_the_shipped_policies_give_the_reference_answer(path):
    file = ROOT / path
    if not file.exists():
        pytest.skip(f"{path} is not in this tree")
    policy = parse_file(file)
    assert unused_now(policy) == reference_unused(policy)


def big_policy(sources: int, sinks: int, declassifiers: int) -> Policy:
    """Declassifiers that grant a principal no sink asks for: every one is unused."""
    policy = Policy(name="Big")
    for i in range(sources):
        policy.add_source(Source(f"s{i}", Label(PrincipalSet.of(f"p{i % 50}"))))
    for i in range(sinks):
        policy.add_sink(Sink(f"k{i}", PrincipalSet.of(f"p{i % 50}")))
    for i in range(declassifiers):
        policy.add_declassifier(Declassifier(f"d{i}", grants_readers=PrincipalSet.of("nobody")))
    return policy


def test_useless_declassifiers_cost_no_source_to_sink_comparison_at_all(monkeypatch):
    calls = []
    real = analysis._reaches
    monkeypatch.setattr(analysis, "_reaches", lambda *a, **k: calls.append(1) or real(*a, **k))
    policy = big_policy(60, 60, 10)
    found = unused_now(policy)
    assert len(found) == 10  # all reported, none looked for in the 3,600 pairs
    # the other checks compare each source with each sink about once; the 10 declassifiers add 0
    assert len(calls) <= 3 * 60 * 60, len(calls)
    calls.clear()
    analysis._unused_declassifiers(policy)
    assert calls == []


def test_a_needed_declassifier_is_still_found_among_many_useless_ones():
    policy = big_policy(50, 50, 8)
    policy.add_declassifier(Declassifier("needed", grants_readers=PrincipalSet.of("p1", "p2")))
    policy.add_sink(Sink("wants_both", PrincipalSet.of("p1", "p2")))
    found = unused_now(policy)
    assert "needed" not in found and len(found) == 8
    assert found == reference_unused(policy)


def test_the_case_that_took_seconds_now_takes_a_fraction_of_one():
    policy = big_policy(400, 400, 10)  # 6.4 s before
    start = time.perf_counter()
    unused_now(policy)
    assert time.perf_counter() - start < 2.0  # a loose bound: it is milliseconds in practice


def relevant_but_useless(n: int, d: int = 10) -> Policy:
    """Every sink asks for what every declassifier grants, and every source already holds it."""
    ys = [f"y{i}" for i in range(d)]
    policy = Policy(name="Hard")
    for i in range(n):
        policy.add_source(Source(f"s{i}", Label(PrincipalSet.of(f"p{i % 50}", *ys))))
        policy.add_sink(Sink(f"k{i}", PrincipalSet.of(f"p{i % 50}", *ys)))
    for i in range(d):
        policy.add_declassifier(Declassifier(f"d{i}", grants_readers=PrincipalSet.of(ys[i])))
    return policy


def test_sources_with_one_label_and_sinks_with_one_signature_are_compared_once(monkeypatch):
    calls = []
    real = analysis._reaches
    monkeypatch.setattr(analysis, "_reaches", lambda *a, **k: calls.append(1) or real(*a, **k))
    policy = relevant_but_useless(150)  # 150 sources, 150 sinks, but 50 labels and 50 signatures
    assert unused_now(policy) == reference_unused(policy)
    calls.clear()
    analysis._unused_declassifiers(policy)
    # 50 x 50 once for the whole policy, then each of 10 declassifiers over those, not 150 x 150
    assert len(calls) <= 50 * 50 * (1 + 10 * 2), len(calls)
    assert len(calls) < 150 * 150


def test_the_relevant_but_useless_case_that_took_nine_seconds_is_a_fraction_of_one():
    policy = relevant_but_useless(400)  # 8.9 s before
    start = time.perf_counter()
    found = unused_now(policy)
    assert time.perf_counter() - start < 2.0
    assert len(found) == 10
