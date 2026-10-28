"""Tracks audit regressions whose fix is scheduled in a later roadmap step.

``tests/test_audit_regressions.py`` states, from the specifications, properties
that the audit found violated. Each test whose fix has landed must pass. Those
still pending are marked ``xfail(strict=True)`` with the finding and roadmap
step that will fix them: the suite stays honest (the defect is visible, not
hidden) and ``strict`` turns a fix into a failure until the marker is removed,
so a pending entry cannot outlive its defect.
"""

import pytest

PENDING = {}


MAX_TEST_ID = 1000


def pytest_collection_modifyitems(config, items):
    # pytest puts the test id in the PYTEST_CURRENT_TEST environment variable, and
    # Windows refuses an environment variable longer than 32767 characters: a test
    # parametrised with a 100000-character string errored at setup there, on every
    # Python version, and left an empty report because the failure came while printing
    # it. Linux and macOS never noticed. Give such a case an explicit id.
    too_long = [item.nodeid[:100] for item in items if len(item.nodeid) > MAX_TEST_ID]
    if too_long:
        raise pytest.UsageError(
            f"test ids over {MAX_TEST_ID} characters break the run on Windows; "
            "pass pytest.param(..., id='short-name'): " + "; ".join(too_long)
        )
    for item in items:
        if not item.nodeid.startswith("tests/test_audit_regressions.py"):
            continue
        for tid, why in PENDING.items():
            if item.name.startswith(f"test_{tid}_"):
                item.add_marker(pytest.mark.xfail(strict=True, reason=f"audit {why}", run=True))
