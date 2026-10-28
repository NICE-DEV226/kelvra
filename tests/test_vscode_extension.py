"""The VS Code extension: its manifest, its icons, and what its code does without VS Code.

VS Code does not start in CI. So the real ``extension.js`` is run under Node with doubles for
``vscode`` and for the language client (tests/support/extension_harness.js). That shows how it
chooses a server, what it says when there is none, and what it asks the client to start. Once it
also runs against the real ``kelvra lsp --check``. What no test here establishes: how it looks and
behaves inside an actual editor; that is looked at by hand, and the README says how.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "editors" / "vscode"
HARNESS = ROOT / "tests" / "support" / "extension_harness.js"
NODE = shutil.which("node")
PACKAGE = json.loads((EXT / "package.json").read_text(encoding="utf-8"))
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


def run(scenario: dict, env: dict | None = None) -> dict:
    done = subprocess.run(
        [NODE, str(HARNESS), str(EXT / "extension.js"), json.dumps(scenario)],
        capture_output=True,
        timeout=120,
        env={**os.environ, **(env or {})},
        check=False,
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")[-800:]
    return json.loads(done.stdout.decode("utf-8"))


# -- the manifest ---------------------------------------------------------------------------


def test_the_manifest_points_at_files_that_exist():
    assert (EXT / PACKAGE["main"]).is_file()
    assert (EXT / PACKAGE["icon"]).is_file()
    contributes = PACKAGE["contributes"]
    [language] = contributes["languages"]
    for theme in language["icon"].values():
        assert (EXT / theme).is_file()
    assert (EXT / language["configuration"]).is_file()
    for grammar in contributes["grammars"]:
        assert (EXT / grammar["path"]).is_file()
    for snippets in contributes["snippets"]:
        assert (EXT / snippets["path"]).is_file()


def test_the_extension_activates_only_for_klv_files():
    assert PACKAGE["activationEvents"] == ["onLanguage:klv"]
    assert PACKAGE["contributes"]["languages"][0]["id"] == "klv"


def test_every_command_the_manifest_declares_is_registered_by_the_code_and_the_other_way_round():
    declared = {c["command"] for c in PACKAGE["contributes"]["commands"]}
    code = (EXT / "extension.js").read_text(encoding="utf-8")
    registered = set(re.findall(r'registerCommand\(\s*"([^"]+)"', code))
    assert declared == registered and declared


def test_every_setting_the_code_reads_is_declared_with_a_default_and_a_description():
    properties = PACKAGE["contributes"]["configuration"]["properties"]
    code = (EXT / "extension.js").read_text(encoding="utf-8")
    read = {f"kelvra.{key}" for key in re.findall(r'settings\.get\(\s*"([^"]+)"', code)}
    assert read == set(properties)
    for name, spec in properties.items():
        assert "default" in spec and (spec.get("description") or spec.get("markdownDescription")), (
            name
        )
    assert properties["kelvra.diagnostics.delayMs"]["minimum"] == 0


def test_the_extension_declares_the_client_library_and_pins_it_with_hashes():
    assert "vscode-languageclient" in PACKAGE["dependencies"]
    lock = json.loads((EXT / "package-lock.json").read_text(encoding="utf-8"))
    packages = {k: v for k, v in lock["packages"].items() if k}
    assert packages and all(
        "integrity" in v and v["resolved"].startswith("https://registry.npmjs.org/")
        for v in packages.values()
    )
    client = lock["packages"]["node_modules/vscode-languageclient"]
    assert client["version"].startswith("9.")


def test_the_editor_version_asked_for_is_at_least_what_the_client_library_needs():
    lock = json.loads((EXT / "package-lock.json").read_text(encoding="utf-8"))
    needs = lock["packages"]["node_modules/vscode-languageclient"]["engines"]["vscode"]
    floor = lambda spec: tuple(int(x) for x in re.search(r"(\d+)\.(\d+)", spec).groups())  # noqa: E731
    assert floor(PACKAGE["engines"]["vscode"]) >= floor(needs)


def test_installed_dependencies_and_built_packages_are_not_committed():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").split("\n")
    assert "node_modules/" in ignore and "*.vsix" in ignore


# -- the icons ------------------------------------------------------------------------------


def test_the_extension_icon_is_a_square_png_big_enough_for_the_marketplace():
    data = (EXT / PACKAGE["icon"]).read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", data[16:24])
    assert width == height and width >= 128


def test_the_icon_is_the_projects_mascot_and_not_a_stranger():
    """Same colours as assets/kelvra-mascot.svg: the picture is the project's, drawn on its blue."""
    mascot = (ROOT / "assets" / "kelvra-mascot.svg").read_text(encoding="utf-8").upper()
    assert "#0A1E37" in mascot and "#A0CBC8" in mascot
    assert PACKAGE["galleryBanner"]["color"].upper() == "#0A1E37"


@pytest.mark.parametrize("theme,stroke", [("dark", "#A0CBC8"), ("light", "#0A1E37")])
def test_the_file_icons_are_small_well_formed_svgs_in_the_mascots_colours(theme, stroke):
    path = EXT / PACKAGE["contributes"]["languages"][0]["icon"][theme].removeprefix("./")
    text = path.read_text(encoding="utf-8")
    root = ET.fromstring(text)
    assert root.get("viewBox") == "0 0 16 16" and len(text) < 1500
    assert stroke in text and "<script" not in text.lower() and "href" not in text.lower()


# -- editing rules --------------------------------------------------------------------------


def test_blocks_fold_by_indentation_and_parentheses_are_coloured_in_pairs():
    config = json.loads((EXT / "language-configuration.json").read_text(encoding="utf-8"))
    assert config["folding"]["offSide"] is True
    assert config["colorizedBracketPairs"] == [["(", ")"]]


# -- how the extension picks a server -------------------------------------------------------


@needs_node
def test_the_candidates_are_tried_in_a_fixed_order_and_the_setting_comes_first():
    out = run({"mode": "candidates", "configured": ["/opt/kelvra", "--x"], "home": "/home/u"})
    assert [(c["source"], c["command"], c["base"]) for c in out["candidates"]] == [
        ("setting", "/opt/kelvra", ["--x"]),
        ("environment", "/home/u/.local/share/kelvra/venv/bin/kelvra", []),
        ("PATH", "kelvra", []),
        ("python", "python3", ["-m", "kelvra.cli"]),
    ]
    empty = run({"mode": "candidates", "configured": [], "home": "/home/u"})["candidates"]
    assert [c["source"] for c in empty] == ["environment", "PATH", "python"]


@needs_node
def test_on_windows_the_environment_and_python_are_the_windows_ones():
    out = run({"mode": "candidates", "configured": [], "home": "C:\\Users\\u", "platform": "win32"})
    environment, _, python = out["candidates"]
    assert environment["command"].endswith("kelvra.exe") and "Scripts" in environment["command"]
    assert python["command"] == "python"


@needs_node
def test_the_first_candidate_that_passes_the_check_is_used_and_later_ones_are_not_asked():
    out = run(
        {"mode": "first", "configured": [], "home": "/h",
         "status": {"/h/.local/share/kelvra/venv/bin/kelvra": 1, "kelvra": 0, "python3": 0}}
    )  # fmt: skip
    assert out["chosen"]["source"] == "PATH"
    assert [c[0] for c in out["log"]["calls"]] == [
        "/h/.local/share/kelvra/venv/bin/kelvra",
        "kelvra",
    ]
    assert all(c[-2:] == ["lsp", "--check"] for c in out["log"]["calls"])


@needs_node
def test_a_candidate_that_does_not_exist_is_skipped_and_none_working_gives_null():
    assert run({"mode": "first", "configured": [], "status": {}})["chosen"] is None
    out = run({"mode": "first", "configured": ["nope"], "status": {"python3": 0}})
    assert out["chosen"]["source"] == "python" and out["chosen"]["base"] == ["-m", "kelvra.cli"]


@needs_node
def test_with_a_configured_command_that_works_nothing_else_is_asked():
    out = run({"mode": "first", "configured": ["my-kelvra"], "status": {"my-kelvra": 0}})
    assert out["chosen"]["source"] == "setting" and len(out["log"]["calls"]) == 1


@needs_node
def test_the_check_is_run_against_the_real_server_command():
    pytest.importorskip("pygls")
    out = run(
        {"mode": "first", "configured": [sys.executable, "-m", "kelvra.cli"], "real": True},
        env={"PYTHONPATH": str(ROOT / "src")},
    )
    assert out["chosen"]["source"] == "setting"
    assert out["chosen"]["command"] == sys.executable


# -- what it does on activation -------------------------------------------------------------


@needs_node
def test_with_a_working_server_it_starts_a_client_for_klv_files_with_the_chosen_delay():
    out = run(
        {"settings": {"diagnostics.delayMs": 400}, "home": "/h",
         "status": {"/h/.local/share/kelvra/venv/bin/kelvra": 0}}
    )  # fmt: skip
    [client] = out["log"]["clients"]
    run_options = client["serverOptions"]["run"]
    assert run_options["command"] == "/h/.local/share/kelvra/venv/bin/kelvra"
    assert run_options["args"] == ["lsp"]
    assert run_options["options"]["env"]["KELVRA_LSP_DEBOUNCE_MS"] == "400"
    assert client["clientOptions"]["documentSelector"] == [{"language": "klv"}]
    assert out["log"]["messages"] == []
    assert set(out["log"]["commands"]) == {"kelvra.restartServer", "kelvra.showServerLog"}
    assert out["log"]["listeners"] == 1


@needs_node
def test_through_python_the_arguments_are_the_module_then_lsp():
    out = run({"status": {"python3": 0}, "home": "/h"})
    [client] = out["log"]["clients"]
    assert client["serverOptions"]["run"]["args"] == ["-m", "kelvra.cli", "lsp"]
    assert client["serverOptions"]["debug"] == client["serverOptions"]["run"]


@needs_node
def test_with_no_server_it_says_so_once_with_the_command_that_fixes_it_and_still_activates():
    out = run({"status": {}, "activateTwice": True})
    log = out["log"]
    assert log["clients"] == [] and len(log["messages"]) == 1  # twice activated, told once
    text = log["messages"][0]["text"]
    assert 'pip install "kelvra[lsp]"' in text and "Colouring and snippets still work" in text
    assert log["messages"][0]["buttons"] == ["Copy install command"]
    assert set(log["commands"]) == {"kelvra.restartServer", "kelvra.showServerLog"}
    assert out["subscriptions"] >= 3  # the commands and the settings listener still registered


@needs_node
def test_the_install_command_can_be_copied_from_the_message():
    out = run({"status": {}, "clickCopy": True})
    assert out["log"]["clipboard"] == ['pip install "kelvra[lsp]"']
    assert run({"status": {}})["log"]["clipboard"] == []  # not copied unless asked


@needs_node
def test_when_the_server_is_turned_off_nothing_is_checked_or_started():
    out = run({"settings": {"server.enabled": False}, "status": {"kelvra": 0}})
    assert (
        out["log"]["calls"] == [] and out["log"]["clients"] == [] and out["log"]["messages"] == []
    )


@needs_node
def test_a_server_that_passes_the_check_but_fails_to_start_is_reported_not_thrown():
    out = run({"startFails": True, "status": {"kelvra": 0}, "home": "/h"})
    [warning] = [m for m in out["log"]["messages"] if m["kind"] == "warning"]
    assert "did not start" in warning["text"] and "boom" in warning["text"]
    assert len(out["log"]["commands"]) == 2  # the extension is still alive
