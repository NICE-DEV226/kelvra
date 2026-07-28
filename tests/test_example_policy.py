"""Keep policy.klv and demo.py from drifting apart.

There is no .klv parser yet, so the example policy exists twice: once in the
surface syntax nobody can execute, and once in Python that demo.py actually
runs. Two sources of truth drift, and a syntax example that contradicts the
running code is worse than no example at all.

This does not parse .klv -- it extracts the declared names and checks they
match the Policy object. It is a stopgap, and it is deleted the day the
parser lands.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "support_agent"
KLV = EXAMPLE / "policy.klv"


def load_demo_policy():
    spec = importlib.util.spec_from_file_location("_demo", EXAMPLE / "demo.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["_demo"] = module
    spec.loader.exec_module(module)  # main() is guarded by __name__
    return module.policy


def declared(keyword: str) -> set[str]:
    """Names declared with ``keyword <name>`` at the start of a line."""
    text = KLV.read_text(encoding="utf-8")
    return set(re.findall(rf"^{keyword}\s+([\w.]+)", text, flags=re.MULTILINE))


@pytest.fixture(scope="module")
def policy():
    return load_demo_policy()


def test_the_klv_file_exists_and_is_not_empty():
    assert KLV.exists()
    assert KLV.stat().st_size > 0


def test_sources_match(policy):
    assert declared("source") == set(policy.sources)


def test_sinks_match(policy):
    assert declared("sink") == set(policy.sinks)


def test_declassifiers_match(policy):
    from_klv = declared("declassify") | declared("endorse")
    assert from_klv == set(policy.declassifiers)


def test_policy_name_and_version_match(policy):
    text = KLV.read_text(encoding="utf-8")
    assert re.search(rf"^policy\s+{policy.name}$", text, flags=re.MULTILINE)
    assert re.search(rf"^version\s+{policy.version}$", text, flags=re.MULTILINE)


def test_the_stopgap_is_labelled_as_one():
    """If the parser lands and this file survives, that is a bug."""
    assert "NOT PARSED YET" in KLV.read_text(encoding="utf-8")
