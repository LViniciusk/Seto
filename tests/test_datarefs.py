"""Unit tests for conservative section/offset identities of data relocations."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from seto import elf, synthetic
from seto.datarefs import (
    INFERRED,
    PROVEN,
    UNKNOWN,
    DataTarget,
    build_reference_report,
    data_target_details,
    load_location,
    recover_references,
    resolve_data_target,
)


def _object(tmp_path: Path) -> elf.ElfFile:
    path = tmp_path / "seto_smoke.o"
    path.write_bytes(synthetic.build_mips_object())
    return elf.parse(path)


def test_defined_et_rel_symbol_resolves_to_section_plus_addend(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    relocation = replace(
        next(rel for rel in parsed.relocations if rel.type == elf.R_MIPS_32),
        addend=0,
    )
    target = resolve_data_target(relocation, parsed.symbols, parsed)

    assert target == DataTarget(".rodata", 0)
    assert data_target_details(parsed, target) == {
        "section": ".rodata",
        "offset": "0x0",
        "elf_virtual_address": "0x0",
        "file_offset": "0x40",
        "section_type": "file-backed",
        "load_segment": None,
    }

    adjusted = replace(relocation, addend=2)
    assert resolve_data_target(adjusted, parsed.symbols, parsed) == DataTarget(".rodata", 2)


def test_undefined_symbol_requires_an_explicit_original_binary_mapping(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    relocation = replace(
        next(rel for rel in parsed.relocations if rel.type == elf.R_MIPS_32),
        addend=0,
    )
    symbol = replace(
        parsed.symbols[relocation.symbol_index],
        name="D_00000040",
        value=0,
        size=0,
        shndx=elf.SHN_UNDEF,
    )
    symbols = tuple(symbol if item.index == symbol.index else item for item in parsed.symbols)
    undefined = replace(relocation, symbol=symbol.name)

    assert resolve_data_target(undefined, symbols, parsed) is None
    assert resolve_data_target(
        undefined,
        symbols,
        parsed,
        explicit_targets={symbol.name: DataTarget(".rodata", 0)},
    ) == DataTarget(".rodata", 0)
    assert resolve_data_target(
        replace(undefined, addend=1),
        symbols,
        parsed,
        explicit_targets={symbol.name: DataTarget(".rodata", 0)},
    ) == DataTarget(".rodata", 1)


def test_stripped_linked_address_resolves_only_inside_one_allocated_section(
    tmp_path: Path,
) -> None:
    parsed = _object(tmp_path)
    rodata = replace(parsed.require_section(".rodata"), addr=0x40)
    sections = tuple(rodata if section.name == ".rodata" else section for section in parsed.sections)
    linked = replace(
        parsed,
        header=replace(parsed.header, e_type=elf.ET_MIPS_PSP_PRX),
        sections=sections,
        _by_name={section.name: section for section in sections},
    )
    relocation = replace(
        parsed.relocations[0],
        type=elf.R_MIPS_32,
        symbol_index=0,
        symbol=None,
        addend=0x42,
    )

    assert resolve_data_target(relocation, (), linked) == DataTarget(".rodata", 2)
    assert resolve_data_target(replace(relocation, addend=0x4860), (), linked) is None


def test_nobits_targets_are_identified_without_reading_file_bytes(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    rodata = parsed.require_section(".rodata")
    bss = replace(
        rodata,
        name=".bss",
        type=elf.SHT_NOBITS,
        flags=elf.SHF_ALLOC,
        addr=0x500,
        offset=0,
        size=0x10,
    )
    sections = tuple(bss if section.name == ".rodata" else section for section in parsed.sections)
    layout = replace(
        parsed,
        header=replace(parsed.header, e_type=elf.ET_MIPS_PSP_PRX),
        sections=sections,
        _by_name={section.name: section for section in sections},
    )
    relocation = replace(
        parsed.relocations[0],
        type=elf.R_MIPS_32,
        symbol_index=0,
        symbol=None,
        addend=0x504,
    )

    target = resolve_data_target(relocation, (), layout)

    assert target == DataTarget(".bss", 4)
    details = data_target_details(layout, target)
    assert details is not None
    assert details["section_type"] == "SHT_NOBITS"
    assert details["file_offset"] is None


def test_overlapping_sections_do_not_produce_an_arbitrary_target(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    text = parsed.require_section(".text")
    rodata = parsed.require_section(".rodata")
    overlapping_text = replace(text, addr=rodata.addr)
    sections = tuple(overlapping_text if item.name == ".text" else item for item in parsed.sections)
    layout = replace(
        parsed,
        header=replace(parsed.header, e_type=elf.ET_MIPS_PSP_PRX),
        sections=sections,
        _by_name={section.name: section for section in sections},
    )
    relocation = replace(
        parsed.relocations[0],
        type=elf.R_MIPS_32,
        symbol_index=0,
        symbol=None,
        addend=rodata.addr,
    )

    assert resolve_data_target(relocation, (), layout) is None


def rel(
    section_offset: int,
    rel_type: int,
    *,
    addend: int = 0,
    symbol: str | None = None,
    symbol_index: int = 0,
    target_section: str = ".text",
) -> elf.Relocation:
    return elf.Relocation(
        offset=section_offset,
        type=rel_type,
        symbol_index=symbol_index,
        addend=addend,
        symbol=symbol,
        target_section=target_section,
        section_offset=section_offset,
        file_offset=None,
    )


def _module(
    parsed: elf.ElfFile,
    *,
    sections: tuple[elf.Section, ...] | None = None,
    relocations: tuple[elf.Relocation, ...] | None = None,
    segments: tuple[elf.Segment, ...] | None = None,
    e_type: int = elf.ET_MIPS_PSP_PRX,
) -> elf.ElfFile:
    sections = parsed.sections if sections is None else sections
    relocations = parsed.relocations if relocations is None else relocations
    by_target: dict[str, list[elf.Relocation]] = {}
    for relocation in relocations:
        if relocation.target_section:
            by_target.setdefault(relocation.target_section, []).append(relocation)
    return replace(
        parsed,
        header=replace(parsed.header, e_type=e_type),
        sections=sections,
        relocations=relocations,
        segments=parsed.segments if segments is None else segments,
        _by_name={section.name: section for section in sections if section.name},
        _relocations_by_target={name: tuple(items) for name, items in by_target.items()},
    )


def test_load_location_reports_the_segment_offset_and_zero_fill(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    segment = elf.Segment(
        index=0, type=1, offset=0, vaddr=0x4000, paddr=0x4000,
        filesz=0x100, memsz=0x400, flags=0, align=4,
    )
    module = _module(parsed, segments=(segment,))

    assert load_location(module, 0x4000) == load_location(module, 0x4000)
    initialized = load_location(module, 0x4050)
    assert initialized is not None and initialized.segment == 0
    assert initialized.offset == 0x50 and initialized.initialized
    zero_fill = load_location(module, 0x4200)
    assert zero_fill is not None and zero_fill.offset == 0x200
    assert not zero_fill.initialized
    assert load_location(module, 0x5000) is None


def test_recover_references_classifies_proven_inferred_and_unknown(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    rodata = replace(parsed.require_section(".rodata"), addr=0x4850, size=0x40)
    sections = tuple(rodata if item.name == ".rodata" else item for item in parsed.sections)
    segment = elf.Segment(
        index=0, type=1, offset=0, vaddr=0, paddr=0,
        filesz=0x1000, memsz=0x2000, flags=0, align=4,
    )
    relocations = (
        rel(0x00, elf.R_MIPS_HI16, addend=0x0),
        rel(0x04, elf.R_MIPS_LO16, addend=0x4860),  # .rodata + 0x10 -> PROVEN
        rel(0x08, elf.R_MIPS_HI16, addend=0x0),
        rel(0x0C, elf.R_MIPS_LO16, addend=0x1900),  # zero-fill -> INFERRED
        rel(0x10, elf.R_MIPS_HI16, addend=0x0),     # orphan HI16 -> UNKNOWN
        rel(0x14, elf.R_MIPS_32, addend=0x3000),    # outside the segment -> UNKNOWN
    )
    module = _module(parsed, sections=sections, segments=(segment,), relocations=relocations)

    references = recover_references(module, ".text", 0, 0x18)
    by_instruction = {reference.instruction: reference for reference in references}

    proven = by_instruction[0x04]
    assert proven.status == PROVEN
    assert proven.target == DataTarget(".rodata", 0x10)
    assert proven.kind == "hi16-lo16"
    assert [name for name, _ in proven.relocations] == ["R_MIPS_HI16", "R_MIPS_LO16"]

    inferred = by_instruction[0x0C]
    assert inferred.status == INFERRED
    assert inferred.target is None
    assert inferred.location is not None and not inferred.location.initialized

    orphan = by_instruction[0x10]
    assert orphan.status == UNKNOWN
    assert "without a resolvable LO16" in orphan.evidence

    unknown = by_instruction[0x14]
    assert unknown.status == UNKNOWN
    assert unknown.kind == "r_mips_32"

    assert set(by_instruction) == {0x04, 0x0C, 0x10, 0x14}


def test_reference_report_groups_by_function_deterministically(tmp_path: Path) -> None:
    parsed = _object(tmp_path)
    rodata = replace(parsed.require_section(".rodata"), addr=0x4850, size=0x40)
    sections = tuple(rodata if item.name == ".rodata" else item for item in parsed.sections)
    relocations = (
        rel(0x00, elf.R_MIPS_HI16, addend=0x0),
        rel(0x04, elf.R_MIPS_LO16, addend=0x4860),
    )
    module = _module(parsed, sections=sections, relocations=relocations)

    report = build_reference_report(
        module, ".text", [("func_a", 0, 0x8), ("func_b", 0x8, 0x10)]
    )
    assert report["section"] == ".text"
    assert [entry["function"] for entry in report["functions"]] == ["func_a", "func_b"]
    first, second = report["functions"]
    assert first["references"][0]["target"] == {"section": ".rodata", "offset": "0x10"}
    assert first["references"][0]["status"] == PROVEN
    assert second["references"] == []


def test_reference_summary_is_json_serialisable(tmp_path: Path) -> None:
    import json

    parsed = _object(tmp_path)
    rodata = replace(parsed.require_section(".rodata"), addr=0x4850, size=0x40)
    sections = tuple(rodata if item.name == ".rodata" else item for item in parsed.sections)
    segment = elf.Segment(
        index=0, type=1, offset=0, vaddr=0, paddr=0,
        filesz=0x1000, memsz=0x2000, flags=0, align=4,
    )
    relocations = (
        rel(0x00, elf.R_MIPS_HI16, addend=0x0),
        rel(0x04, elf.R_MIPS_LO16, addend=0x1900),
    )
    module = _module(parsed, sections=sections, segments=(segment,), relocations=relocations)

    report = build_reference_report(module, ".text", [("func_a", 0, 0x8)])
    payload = json.dumps(report, sort_keys=True)
    assert "load_offset" in payload
    assert "0x1900" in payload
