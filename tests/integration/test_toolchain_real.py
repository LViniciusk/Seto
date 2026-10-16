"""Integration checks against installed open tools and the original PRX.

The Ghidra test is intentionally separate from ``seto toolchain --smoke``: the
smoke command never reads private media.  This integration test only reads the
original module and writes its Ghidra project beneath pytest's temporary path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seto import smoke
from seto.toolchain import BLOCKED, detect_all, load_settings, run

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


def test_ghidra_inspects_the_real_prx_and_selected_functions(tmp_path) -> None:
    """Automatic PSP import and the selected function boundaries are real."""
    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    ghidra = next(status for status in detect_all(settings) if status.name == "ghidra")
    if not ghidra.found:
        pytest.skip("Ghidra is not configured")
    if ghidra.state == BLOCKED:
        pytest.skip(ghidra.reason or "Ghidra runtime is blocked")

    scripts = REPO_ROOT / "scripts" / "ghidra"
    project = tmp_path / "project"
    project.mkdir()
    argv = (
        ghidra.path or "",
        str(project),
        "seto_real_prx",
        "-import",
        str(MODULE),
        "-scriptPath",
        str(scripts),
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x244",
        "0x278",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x6e4",
        "0x704",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x4b8",
        "0x508",
    )
    result = run(
        argv,
        timeout=smoke.GHIDRA_TIMEOUT,
    )
    assert result.ok, result.combined()
    assert (project / "seto_real_prx.gpr").is_file()
    output = result.combined()
    assert output.count(f"SETO_LANGUAGE={smoke.ALLEGREX_LANGUAGE}") == 3
    for start in ("00000244", "000006e4", "000004b8"):
        assert f"SETO_FUNCTION=not-defined-at-{start}" not in output

    instructions = [
        line.split("SETO_INSN=", 1)[1].split(" (GhidraScript)", 1)[0]
        for line in output.splitlines()
        if "SETO_INSN=" in line
    ]
    assert len(instructions) == 13 + 8 + 20
    target_calls = [
        instruction
        for instruction in instructions
        if any(f"jal 0x{target:08x}" in instruction for target in (0x2EDC, 0x2F0C, 0x2EF4, 0x2F54))
    ]
    assert [target.rsplit(" ", 1)[-1] for target in target_calls] == [
        "0x00002edc", "0x00002f0c", "0x00002ef4", "0x00002f54"
    ]
    assert "SETO_DECOMP_C_BEGIN" in output
