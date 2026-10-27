"""The scale measurements run, and LIMITATIONS.md says where they come from.

Timings are not asserted: they belong to the machine. What is checked is that the script runs
at small sizes, reports every row it promises, measures a plausible memory cost per event, and
that the documentation points at it instead of quoting numbers from nowhere.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location("kelvra_scale", ROOT / "evaluation" / "scale.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_quick_run_reports_every_row_and_exits_cleanly(capsys):
    scale = load()
    assert scale.main(["--quick"]) == 0
    out = capsys.readouterr().out
    table = [line for line in out.splitlines() if line.startswith("| ") and "---" not in line][1:]
    whats = [line.split("|")[1].strip() for line in table]
    assert whats == [
        "parse",
        "analyse",
        "analyse",
        "analyse",
        "read + emit",
        "record (chain and sign)",
        "verify",
        "held in memory",
        "held in memory",
        "gateway",
    ]
    assert all(line.count("|") == 4 for line in table)


def test_the_cost_per_event_is_a_few_hundred_bytes_and_the_extrapolation_follows_from_it():
    rows = load().rows(quick=True)
    per_event = int(next(r for r in rows if r[1].endswith("until record()"))[2].split()[0])
    assert 100 < per_event < 2000
    megabytes = next(r for r in rows if "1,000,000" in r[1])[2]
    assert megabytes == f"{per_event:,} MB"  # bytes per event x a million events = that many MB


def test_the_limitation_names_the_script_and_the_run_holds_its_events():
    limitations = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")
    assert "evaluation/scale.py" in limitations
    assert re.search(r"holds all its events until `record\(\)`", limitations)
    assert "no measurement exists" not in limitations
