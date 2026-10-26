"""Tracks audit regressions whose fix is scheduled in a later roadmap step.

``tests/test_audit_regressions.py`` states, from the specifications, properties
that the audit found violated. Each test whose fix has landed must pass. Those
still pending are marked ``xfail(strict=True)`` with the finding and roadmap
step that will fix them: the suite stays honest (the defect is visible, not
hidden) and ``strict`` turns a fix into a failure until the marker is removed,
so a pending entry cannot outlive its defect.
"""

import pytest

PENDING = {
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        if not item.nodeid.startswith("tests/test_audit_regressions.py"):
            continue
        for tid, why in PENDING.items():
            if item.name.startswith(f"test_{tid}_"):
                item.add_marker(
                    pytest.mark.xfail(strict=True, reason=f"audit {why}", run=True)
                )
