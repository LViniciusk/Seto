"""Integration tests against the real game media.

These tests are skipped automatically when the extracted module or the ISO are
absent (they are never committed - see ``.gitignore``).  Run them with::

    py -3.12 -m pytest tests/integration -m integration

Nothing here writes to the original data: the inventory and split commands are
read-only with respect to ``private/``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seto import elf, inventory, mips, split
from seto.matching import MATCHED, compare
from seto.toolchain import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "private" / "original" / "PSP_GAME" / "USRDIR" / "gmodule" / "libhtml_view.prx"
GAME_ROOT = REPO_ROOT / "private" / "original" / "PSP_GAME"
ISO = REPO_ROOT / "TF1.iso"

pytestmark = pytest.mark.integration

if not MODULE.is_file():
    pytest.skip(
        f"original module not present ({MODULE}); integration tests need private/",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def parsed() -> elf.ElfFile:
    return elf.parse(MODULE)


def test_header_matches_the_documented_baseline(parsed: elf.ElfFile) -> None:
    assert parsed.is_prx
    assert parsed.is_mips
    assert parsed.header.e_machine == elf.EM_MIPS
    comment = parsed.comment()
    assert comment is not None and "MW MIPS C Compiler" in comment


def test_text_section_geometry(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    assert text.offset == 0x60
    assert text.size == 0x7F4
    assert text.addr == 0x0


def test_function_discovery_is_stable(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    functions = mips.find_functions(parsed.section_data(text), text.addr)
    assert len(functions) == 16
    by_address = {function.start: function for function in functions}
    target = by_address[0x244]
    assert target.size == 0x34
    assert target.calls == (0x2EDC, 0x2F0C, 0x2EF4, 0x2F54)


def test_relocations_are_typed_and_resolved(parsed: elf.ElfFile) -> None:
    relocations = parsed.relocations_for(".text")
    assert relocations
    types = {relocation.type_name for relocation in relocations}
    assert {"R_MIPS_26", "R_MIPS_HI16", "R_MIPS_LO16"} <= types
    assert all(relocation.section_offset is not None for relocation in relocations)


def test_split_layout_validates_against_the_real_module(parsed: elf.ElfFile) -> None:
    layout = split.build_layout(parsed, "libhtml_view")
    assert split.validate_layout(layout, parsed) == ()
    assert layout.image_delta == 0x60
    assert len(layout.segments) == 3
    assert len(layout.subsegments()) == 15


def test_func_00000244_self_comparison_is_matched(parsed: elf.ElfFile) -> None:
    text = parsed.require_section(".text")
    code = parsed.section_data(text)
    function = next(
        item for item in mips.find_functions(code, text.addr) if item.start == 0x244
    )
    offset = function.start - text.addr
    region = code[offset : offset + function.size]
    result = compare(
        region,
        region,
        name=function.name(),
        address=function.start,
        original_relocations=parsed.relocations_for(".text"),
        candidate_relocations=parsed.relocations_for(".text"),
        original_section_offset=offset,
        candidate_section_offset=offset,
    )
    assert result.status == MATCHED
    assert result.total_words == 13


def test_inventory_over_the_extracted_media() -> None:
    if not GAME_ROOT.is_dir():
        pytest.skip("extracted PSP_GAME tree not present")
    manifest = inventory.build_manifest(
        extracted_root=GAME_ROOT,
        settings=load_settings(REPO_ROOT / "config" / "seto.toml"),
        verify_iso=False,
    )
    assert manifest["parameter_sfo"]["entries"]
    assert manifest["summary"]["module_count"] == 2
    assert manifest["summary"]["function_count"] == 41
    assert manifest["module_errors"] == []


def test_iso_matches_the_documented_baseline() -> None:
    if not ISO.is_file():
        pytest.skip("TF1.iso not present")
    settings = load_settings(REPO_ROOT / "config" / "seto.toml")
    manifest = inventory.build_manifest(
        iso_path=ISO,
        extracted_root=GAME_ROOT if GAME_ROOT.is_dir() else REPO_ROOT / "private" / "missing",
        settings=settings,
        verify_iso=True,
    )
    baseline = manifest["baseline"]
    assert baseline["present"] is True
    assert baseline["verified"] is True, baseline["issues"]
    assert baseline["disc_id"] == "ULUS10136"
    assert baseline["disc_version"] == "1.03"
