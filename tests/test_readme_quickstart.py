"""The Python example in the README is run, so it cannot rot."""

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _python_blocks() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return re.findall(r"```python\n(.*?)```", readme, re.S)


def test_the_readme_has_a_python_example():
    assert _python_blocks()


def test_every_python_example_in_the_readme_runs(monkeypatch):
    monkeypatch.chdir(ROOT)  # the example opens examples/support_agent/policy.klv
    for index, block in enumerate(_python_blocks()):
        out = io.StringIO()
        with redirect_stdout(out):
            exec(compile(block, f"README.md[python #{index}]", "exec"), {"__name__": "__readme__"})
        assert "denied" in out.getvalue() and out.getvalue().rstrip().endswith("True")
