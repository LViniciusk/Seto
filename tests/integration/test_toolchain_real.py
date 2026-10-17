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
        "0x604860",
        "0x604b9c",
        "0x4860",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x4b8",
        "0x508",
        "0x604830",
        "0x4830",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x34",
        "0x84",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x134",
        "0x178",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x358",
        "0x39c",
    )
    result = run(
        argv,
        timeout=smoke.GHIDRA_TIMEOUT,
    )
    assert result.ok, result.combined()
    assert (project / "seto_real_prx.gpr").is_file()
    output = result.combined()
    assert output.count(f"SETO_LANGUAGE={smoke.ALLEGREX_LANGUAGE}") == 6
    starts = ("0x244", "0x6e4", "0x4b8", "0x34", "0x134", "0x358")
    ends = ("0x278", "0x704", "0x508", "0x84", "0x178", "0x39c")
    counts = (13, 8, 20, 20, 17, 17)
    sizes = (0x34, 0x20, 0x50, 0x50, 0x44, 0x44)
    blocks = {}
    for index, start in enumerate(starts):
        marker = f"SETO_FUNCTION_START={start}"
        assert marker in output
        block_start = output.index(marker)
        next_markers = [
            output.find(f"SETO_FUNCTION_START={other}", block_start + len(marker))
            for other in starts[index + 1:]
        ]
        next_markers = [position for position in next_markers if position >= 0]
        next_marker = min(next_markers, default=len(output))
        block = output[block_start:next_marker]
        blocks[start] = block
        assert f"SETO_FUNCTION_END={ends[index]}" in block
        assert f"SETO_FUNCTION_BODY_START={int(start, 16):08x}" in block
        assert f"SETO_FUNCTION_BODY_END={int(ends[index], 16):08x}" in block
        assert f"SETO_FUNCTION_BODY_ADDRESSES={sizes[index]}" in block
        assert "SETO_FUNCTION_BODY_RANGES=1" in block
        assert "SETO_BOUNDARY_STATUS=EXACT" in block
        assert "SETO_DECOMP_STATUS=OK" in block
        instructions = [line for line in block.splitlines() if "SETO_INSN=" in line]
        assert len(instructions) == counts[index]

    function_244 = blocks["0x244"]
    target_calls = [
        instruction.split("SETO_INSN=", 1)[1].split(" (GhidraScript)", 1)[0]
        for instruction in function_244.splitlines()
        if "SETO_INSN=" in instruction
        if any(f"jal 0x{target:08x}" in instruction for target in (0x2EDC, 0x2F0C, 0x2EF4, 0x2F54))
    ]
    assert [target.rsplit(" ", 1)[-1] for target in target_calls] == [
        "0x00002edc", "0x00002f0c", "0x00002ef4", "0x00002f54"
    ]
    assert "SETO_DECOMP_C_BEGIN" in function_244
