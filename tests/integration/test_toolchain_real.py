"""Integration checks against installed open tools and the original PRX.

The Ghidra test is intentionally separate from ``seto toolchain --smoke``: the
smoke command never reads private media.  This integration test only reads the
original module and writes its Ghidra project beneath pytest's temporary path.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from seto import smoke
from seto.toolchain import BLOCKED, detect_all, ghidra_headless_argv, load_settings, run

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = (
    REPO_ROOT
    / "private"
    / "original"
    / "PSP_GAME"
    / "USRDIR"
    / "gmodule"
    / "libhtml_view.prx"
)

if not MODULE.is_file():
    pytest.skip("original PRX is absent; this check only reads private/", allow_module_level=True)


def test_ghidra_automatically_recognizes_the_real_prx_as_allegrex(tmp_path) -> None:
    """The PSP extension must win automatic format/language selection."""
    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    ghidra = next(status for status in detect_all(settings) if status.name == "ghidra")
    if not ghidra.found:
        pytest.skip("Ghidra is not configured")
    if ghidra.state == BLOCKED:
        pytest.skip(ghidra.reason or "Ghidra runtime is blocked")

    scripts = tmp_path / "scripts"
    smoke.write_language_probe_script(scripts)
    project = tmp_path / "project"
    project.mkdir()
    result = run(
        ghidra_headless_argv(
            ghidra.path or "",
            project,
            "seto_real_prx",
            MODULE,
            scripts=("SetoLanguage.java",),
            script_path=scripts,
        ),
        timeout=smoke.GHIDRA_TIMEOUT,
    )
    assert result.ok, result.combined()
    assert (project / "seto_real_prx.gpr").is_file()
    match = re.search(r"SETO_LANGUAGE_ID=([^\s]+)", result.combined())
    assert match is not None, result.combined()
    assert match.group(1) == smoke.ALLEGREX_LANGUAGE
