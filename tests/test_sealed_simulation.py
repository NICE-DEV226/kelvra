"""The simulated tickets look real and cannot be anyone's.

Looking real is what makes the simulation a fair test of a model; being impossible to match to a
person is
what makes it safe to send to an outside service. Both are checked, the first with a check
independent of the
generator (the ISO 13616 mod-97 rule, written out here again from its definition).
"""

from __future__ import annotations

import random
import re
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sealed_support_agent"
sys.path.insert(0, str(EXAMPLE))

import simulation as sim  # noqa: E402


def many(scenario: str, n: int = 400):
    rng = random.Random(20261028)
    return [sim.ticket(rng, scenario) for _ in range(n)]


def test_every_iban_is_well_formed_has_valid_check_digits_and_no_bank_behind_it():
    for t in many("honest"):
        compact = t.iban.replace(" ", "")
        assert re.fullmatch(r"FR\d{25}", compact), t.iban
        assert t.iban == " ".join(compact[i : i + 4] for i in range(0, 27, 4))
        # mod-97 as the standard defines it: move 4, A=10..Z=35, the number mod 97 is 1
        rearranged = compact[4:] + compact[:4]
        assert int("".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)) % 97 == 1
        assert compact[4:9] == "99999" and compact[9:14] == "99999"  # bank and branch: none exist
        account, key = int(compact[14:25]), int(compact[25:27])
        assert key == 97 - ((89 * 99999 + 15 * 99999 + 3 * account) % 97)  # the French RIB key


def test_the_validity_helper_agrees_with_the_independent_rule_and_rejects_a_typo():
    iban = many("honest", 1)[0].iban
    assert sim.iban_is_valid(iban)
    digit = next(i for i, c in enumerate(iban) if c.isdigit() and i > 6)
    typo = iban[:digit] + str((int(iban[digit]) + 1) % 10) + iban[digit + 1 :]
    assert not sim.iban_is_valid(typo)
    assert sim.iban_is_valid("GB82 WEST 1234 5698 7654 32")  # a published example IBAN


def test_every_phone_number_is_in_the_range_reserved_for_fiction():
    assert all(re.fullmatch(r"\+33 6 39 98 \d\d \d\d", t.phone) for t in many("honest"))


def test_tickets_vary_in_name_language_topic_and_numbers():
    tickets = many("honest")
    assert len({t.name for t in tickets}) > 200 and len({t.iban for t in tickets}) == len(tickets)
    assert {t.language for t in tickets} == {"fr", "en"}
    assert (
        len({re.sub(r"\d+", "N", t.message.split("\n")[0]) for t in tickets}) == 10
    )  # 5 topics, 2 languages
    assert any(re.search(r"[à-ÿ]", t.name) for t in tickets)  # accents occur


def test_an_honest_ticket_asks_a_question_and_contains_no_instruction():
    for t in many("honest", 100):
        assert (
            t.style == "honest" and "mail.external" not in t.message and "SYSTEM" not in t.message
        )
        assert re.search(r"\d{5}", t.message) and t.message.rstrip().endswith(t.name.split()[0])


def test_every_injection_style_occurs_and_each_asks_for_a_destination_the_model_can_name():
    tickets = many("injected")
    assert {t.style for t in tickets} == set(sim.INJECTIONS)
    for t in tickets:
        assert sim.INJECTIONS[t.style] in t.message
        assert "mail.external" in t.message or "crm.note" in t.message
    assert {"fr", "en"} == {t.language for t in tickets}


def test_the_account_details_never_appear_in_the_message_a_customer_writes():
    for t in many("injected", 100) + many("honest", 100):
        assert t.iban not in t.message and t.phone not in t.message
        assert t.name not in t.message  # only the first name signs it


def test_the_same_seed_gives_the_same_tickets():
    assert many("injected", 20) == many("injected", 20)


@pytest.mark.parametrize("scenario", ["honest", "injected"])
def test_a_ticket_goes_through_the_real_pipeline(scenario):
    pytest.importorskip("cryptography")
    from models import HonestModel
    from pipeline import Case, Pipeline

    t = sim.ticket(random.Random(5), scenario)
    result = Pipeline(HonestModel()).run(Case(t.message, t.name, t.iban, t.phone))
    assert (
        t.iban not in result.prompt and t.phone not in result.prompt and t.name not in result.prompt
    )
    assert result.verified
