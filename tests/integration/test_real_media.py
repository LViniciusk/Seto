"""Integration tests against the real game media.

These tests are skipped automatically when the extracted module or the ISO are
absent (they are never committed - see ``.gitignore``).  Run them with::

    py -3.12 -m pytest tests/integration -m integration

Nothing here writes to the original data: the inventory and split commands are
read-only with respect to ``private/``.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

import pytest

from seto import cli, elf, imports, inventory, matching, mips, split
from seto.matching import MATCHED, compare
from seto.toolchain import TOOL_SPECS, find_tool, load_settings

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


def test_import_table_recovers_the_whole_module(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    assert table.limitations == ()
    assert [item.library for item in table.tables] == [
        "libehsys", "sceNet", "sceNetInet", "sceNetApctl",
        "sceNetResolver", "sceSsl", "sceHttp", "sceUtility",
    ]
    assert len(table.imports) == 1268
    assert table.code_range == (0x0, 0x7F4)
    # Every identity the table keeps must really be a trampoline of the module.
    stub_section = parsed.require_section(".sceStub.text")
    data = parsed.section_data(stub_section)
    for address in table.imports:
        offset = address - stub_section.addr
        assert data[offset : offset + 4] == b"\x08\x00\xe0\x03"


def test_the_four_calls_of_func_00000244_have_proven_identities(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    references = imports.call_references(
        parsed, table, section=".text", start=0x244, end=0x278
    )
    assert [
        (item.address, item.kind, item.imported.library, item.imported.nid)
        for item in references
    ] == [
        (0x24C, "import", "sceHttp", 0x76D1363B),
        (0x254, "import", "sceHttp", 0xF9D8EB63),
        (0x25C, "import", "sceHttp", 0xD1C8945E),
        (0x264, "import", "sceSsl", 0x191CDEFF),
    ]
    assert all(item.delay_slot is not None for item in references)


def test_every_call_of_the_module_is_classified(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    references = imports.call_references(parsed, table, section=".text")
    assert len(references) == 72
    assert {item.kind for item in references} == {"import", "local"}


def test_a_call_can_be_told_apart_from_another_import(parsed: elf.ElfFile) -> None:
    table = imports.build_import_table(parsed)
    resolver = partial(imports.resolve_call_target, module_imports=table)
    site = matching.RelocationSite
    # The first call of func_00000244 reaches sceHttp/0x76D1363B; a candidate
    # that reaches another stub of the same library must not be accepted.
    first = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2EDC, symbol=None))
    other = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2EF4, symbol=None))
    assert first.identity == ("sceHttp", 0x76D1363B)
    assert other.identity == ("sceHttp", 0xD1C8945E)
    assert first.identity != other.identity
    ssl = resolver(site(word_index=0, type=elf.R_MIPS_26, addend=0x2F54, symbol=None))
    assert ssl.identity == ("sceSsl", 0x191CDEFF)


def test_split_run_splat_verifies_the_real_listing(tmp_path) -> None:
    splat = find_tool(next(spec for spec in TOOL_SPECS if spec.name == "splat"))
    if not splat.found:
        pytest.skip("splat is not installed")
    out = tmp_path / "split"
    code = cli.main(
        [
            "split", "--prx", str(MODULE), "--out", str(out),
            "--base-path", "..", "--target-path", str(MODULE), "--run-splat",
        ]
    )
    assert code == 0
    assert (out / "libhtml_view.yaml").is_file()
    assert (tmp_path / "asm" / "libhtml_view" / "text.s").is_file()


def test_split_run_splat_verifies_the_real_listing(tmp_path) -> None:
    splat = find_tool(next(spec for spec in TOOL_SPECS if spec.name == "splat"))
    if not splat.found:
        pytest.skip("splat is not installed")
    out = tmp_path / "split"
    code = cli.main(
        [
            "split", "--prx", str(MODULE), "--out", str(out),
            "--base-path", "..", "--target-path", str(MODULE), "--run-splat",
        ]
    )
    assert code == 0
    assert (out / "libhtml_view.yaml").is_file()
    assert (tmp_path / "asm" / "libhtml_view" / "text.s").is_file()


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
