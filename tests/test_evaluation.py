"""The adversarial evaluation, and the integrity of its corpus.

Two things are guarded here. The first is the result: a regression in the label
model should surface as an attack getting through, not as an abstract unit test
turning red. The second is subtler — the obfuscated document earns its place in
the corpus through Unicode characters that a careless text pipeline would strip
or normalise away. A corpus whose payload silently vanishes still passes every
test and stops testing anything.
"""

import importlib.util
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "evaluation"
CORPUS = EVALUATION / "corpus"
OBFUSCATED = CORPUS / "reunion_obfusque.txt"

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}


@pytest.fixture(scope="module")
def evaluation():
    spec = importlib.util.spec_from_file_location("_evaluation", EVALUATION / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["_evaluation"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def outcomes(evaluation):
    return [evaluation.run(s) for s in evaluation.SCENARIOS]


# -- the result -------------------------------------------------------------


def test_every_attack_in_the_model_is_contained(outcomes):
    escaped = [
        o.scenario.name
        for o in outcomes
        if o.scenario.hostile and not o.scenario.outside_model and not o.contained
    ]
    assert not escaped, f"attacks got through: {escaped}"


def test_no_false_positives_on_benign_work(outcomes):
    blocked = [o.scenario.name for o in outcomes if not o.scenario.hostile and o.contained]
    assert not blocked, f"legitimate work was refused: {blocked}"


def test_containment_comes_from_more_than_default_deny(outcomes):
    """An evaluation stopped only by unknown sink names tests the namespace.

    The label model has to carry some of the weight, or the result says
    nothing about the lattice this project is built on.
    """
    reasons = [o.reason for o in outcomes if o.scenario.hostile and o.contained]
    by_lattice = [r for r in reasons if "not declared" not in r]
    assert len(by_lattice) >= 2, (
        "at least two attacks must be contained by the labels rather than by "
        f"an undeclared sink; got {by_lattice}"
    )
    assert any("permitted to read" in r for r in by_lattice), "confidentiality axis unexercised"
    assert any("endorsement" in r for r in by_lattice), "integrity axis unexercised"


def test_the_out_of_model_attack_is_still_out_of_model(outcomes):
    """Honesty check. If this starts passing, the claim in the README is stale."""
    outside = [o for o in outcomes if o.scenario.outside_model]
    assert len(outside) == 1
    assert not outside[0].contained
    assert "never observes" in outside[0].reason


def test_the_harness_exits_zero_today():
    result = subprocess.run(
        [sys.executable, str(EVALUATION / "run.py")], capture_output=True, timeout=120
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


# -- corpus integrity -------------------------------------------------------


def test_the_obfuscated_document_still_carries_its_payload():
    text = OBFUSCATED.read_text(encoding="utf-8")

    invisible = [c for c in text if ord(c) in ZERO_WIDTH]
    cyrillic = [c for c in text if "CYRILLIC" in unicodedata.name(c, "")]

    assert invisible, "the zero-width characters are gone; this is no longer an obfuscated attack"
    assert cyrillic, "the homoglyphs are gone; this is no longer an obfuscated attack"


def test_git_normalisation_did_not_touch_the_payload():
    """`.gitattributes` sets `text=auto eol=lf`. Confirm that is all it does."""
    on_disk = OBFUSCATED.read_bytes()
    stored = subprocess.run(
        ["git", "show", f":evaluation/corpus/{OBFUSCATED.name}"],
        capture_output=True,
        cwd=ROOT,
    )
    if stored.returncode != 0:
        pytest.skip("file not in the index yet")

    def payload(raw: bytes) -> tuple[list[int], list[int]]:
        text = raw.decode("utf-8")
        return (
            [ord(c) for c in text if ord(c) in ZERO_WIDTH],
            [ord(c) for c in text if "CYRILLIC" in unicodedata.name(c, "")],
        )

    assert payload(on_disk) == payload(stored.stdout)


def test_the_corpus_is_complete():
    assert {p.name for p in CORPUS.glob("*.txt")} == {
        "doc_rh_piege.txt",
        "reunion_obfusque.txt",
        "ticket_support_piege.txt",
        "page_web_piege.txt",
        "note_conges.txt",
        "politique_securite.txt",
        "rapport_activite.txt",
    }


def test_the_benign_control_that_talks_about_security_is_present():
    """politique_securite.txt discusses security instructions without being an
    attack. It is the document a content-based detector is most likely to trip
    on, which is why it belongs in the corpus."""
    text = (CORPUS / "politique_securite.txt").read_text(encoding="utf-8")
    assert text.strip()
