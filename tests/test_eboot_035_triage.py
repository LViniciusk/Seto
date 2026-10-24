from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from triage_eboot_035 import parse_ghidra_evidence  # noqa: E402


def _log(start: int, end: int, *, language: str = "Allegrex:LE:32:default") -> str:
    return "\n".join(
        (
            f"SETO_LANGUAGE={language}",
            "SETO_COMPILER_SPEC=default",
            f"SETO_FUNCTION_START=0x{start:x}",
            f"SETO_FUNCTION_END=0x{end:x}",
            f"SETO_FUNCTION_BODY_START={start:08x}",
            f"SETO_FUNCTION_BODY_END={end:08x}",
            f"SETO_FUNCTION_BODY_ADDRESSES={end - start}",
            "SETO_FUNCTION_BODY_RANGES=1",
            "SETO_ADDRESSABLE_UNIT_SIZE=1",
            "SETO_BOUNDARY_STATUS=EXACT",
            "SETO_DECOMP_STATUS=OK",
            *("SETO_INSN=instruction" for _ in range((end - start) // 4)),
        )
    )


def test_ghidra_evidence_requires_exact_allegrex_body_and_instruction_count() -> None:
    evidence = parse_ghidra_evidence(_log(0x33D10, 0x33D4C), 0x33D10, 0x33D4C)

    assert evidence["language"] == "Allegrex:LE:32:default"
    assert evidence["boundary_status"] == "EXACT"
    assert evidence["body_bytes"] == 60
    assert evidence["instruction_count"] == 15


@pytest.mark.parametrize(
    "text",
    (
        _log(0x33D10, 0x33D4C, language="MIPS:LE:64:default"),
        _log(0x33D10, 0x33D4C).replace(
            "SETO_BOUNDARY_STATUS=EXACT", "SETO_BOUNDARY_STATUS=MISMATCH"
        ),
        _log(0x33D10, 0x33D4C).replace(
            "SETO_FUNCTION_BODY_RANGES=1", "SETO_FUNCTION_BODY_RANGES=2"
        ),
        _log(0x33D10, 0x33D4C).rsplit("SETO_INSN=instruction", 1)[0],
    ),
)
def test_ghidra_evidence_rejects_unverified_boundaries(text: str) -> None:
    with pytest.raises(ValueError, match="Ghidra boundary evidence rejected"):
        parse_ghidra_evidence(text, 0x33D10, 0x33D4C)
