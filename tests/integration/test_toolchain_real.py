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
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x8c",
        "0x134",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x178",
        "0x244",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x278",
        "0x358",
        # SETO-DECOMP-010 reconstructions, with their data destinations.
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x0",
        "0x34",
        "0x4850",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x39c",
        "0x414",
        "0x4770",
        "-postScript",
        "SetoAnalyzeFunction.java",
        "0x414",
        "0x4b8",
        "0x4788",
        "0x47a4",
        "0x47d0",
        "0x4800",
    )
    result = run(
        argv,
        timeout=smoke.GHIDRA_TIMEOUT,
    )
    assert result.ok, result.combined()
    assert (project / "seto_real_prx.gpr").is_file()
    output = result.combined()
    assert output.count(f"SETO_LANGUAGE={smoke.ALLEGREX_LANGUAGE}") == 12

    def insn_count(block: str) -> int:
        return sum(1 for line in block.splitlines() if "SETO_INSN=" in line)

    # The nine established boundaries (SETO-DECOMP-005..009).
    starts = ("0x244", "0x6e4", "0x4b8", "0x34", "0x134", "0x358", "0x8c", "0x178", "0x278")
    ends = ("0x278", "0x704", "0x508", "0x84", "0x178", "0x39c", "0x134", "0x244", "0x358")
    counts = (13, 8, 20, 20, 17, 17, 42, 51, 56)
    sizes = (0x34, 0x20, 0x50, 0x50, 0x44, 0x44, 0xA8, 0xCC, 0xE0)
    # The three SETO-DECOMP-010 reconstructions, requested last.
    new_starts = ("0x0", "0x39c", "0x414")
    ordered = starts + new_starts

    blocks = {}
    for index, start in enumerate(ordered):
        marker = f"SETO_FUNCTION_START={start}"
        assert marker in output
        block_start = output.index(marker)
        next_markers = [
            output.find(f"SETO_FUNCTION_START={other}", block_start + len(marker))
            for other in ordered[index + 1:]
        ]
        next_markers = [position for position in next_markers if position >= 0]
        blocks[start] = output[block_start:min(next_markers, default=len(output))]

    for index, start in enumerate(starts):
        block = blocks[start]
        assert f"SETO_FUNCTION_END={ends[index]}" in block
        assert f"SETO_FUNCTION_BODY_START={int(start, 16):08x}" in block
        assert f"SETO_FUNCTION_BODY_END={int(ends[index], 16):08x}" in block
        assert f"SETO_FUNCTION_BODY_ADDRESSES={sizes[index]}" in block
        assert "SETO_FUNCTION_BODY_RANGES=1" in block
        assert "SETO_BOUNDARY_STATUS=EXACT" in block
        assert "SETO_DECOMP_STATUS=OK" in block
        assert insn_count(block) == counts[index]

    # func_00000414 (0x414-0x4B8): an exact single-range body, 41 instructions.
    block = blocks["0x414"]
    assert "SETO_FUNCTION_END=0x4b8" in block
    assert "SETO_FUNCTION_BODY_START=00000414" in block
    assert "SETO_FUNCTION_BODY_END=000004b8" in block
    assert "SETO_FUNCTION_BODY_ADDRESSES=164" in block
    assert "SETO_FUNCTION_BODY_RANGES=1" in block
    assert "SETO_BOUNDARY_STATUS=EXACT" in block
    assert "SETO_DECOMP_STATUS=OK" in block
    assert insn_count(block) == 41
    for address in ("0x4788", "0x47a4", "0x47d0", "0x4800"):
        assert f"SETO_ADDRESS_MAP={address} " in block

    # func_0000039C (0x39C-0x414): the exclusive end is the next function's start,
    # but Ghidra's flow excludes the unreachable `default:` word pair at 0x404, so
    # its body is two ranges of 116 addresses. That hole is independent evidence
    # that the reconstructed `default:` arm is dead code, not a boundary dispute.
    block = blocks["0x39c"]
    assert "SETO_FUNCTION_END=0x414" in block
    assert "SETO_FUNCTION_BODY_START=0000039c" in block
    assert "SETO_FUNCTION_BODY_END=00000414" in block
    assert "SETO_FUNCTION_BODY_ADDRESSES=116" in block
    assert "SETO_FUNCTION_BODY_RANGES=2" in block
    assert "SETO_BOUNDARY_STATUS=MISMATCH" in block
    assert "SETO_DECOMP_STATUS=NOT_RUN" in block
    # Ghidra never defines the unreachable word at 0x404, so its listing is 29 of
    # the 30 instructions. Both case bodies around the hole are present.
    assert insn_count(block) == 29
    assert "SETO_INSN=00000400 " in block
    assert "SETO_INSN=00000404 " not in block
    assert "SETO_INSN=00000408 " in block
    assert "SETO_ADDRESS_MAP=0x4770 " in block

    # func_00000000 (0x0-0x34): 0x0 is the image entry point, which Ghidra's
    # auto-analysis does not model as a function, but the 13 instructions and the
    # new zero-fill destination in the requested range are exact.
    block = blocks["0x0"]
    assert "SETO_FUNCTION_END=0x34" in block
    assert "SETO_BOUNDARY_STATUS=NOT_FOUND" in block
    assert "SETO_DECOMP_STATUS=NOT_RUN" in block
    assert insn_count(block) == 13
    # 0x4850 is the first byte past the file-backed image, so Ghidra reports it
    # UNMAPPED - the same boundary p_filesz records.
    assert "SETO_ADDRESS_MAP=0x4850 UNMAPPED" in block

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
