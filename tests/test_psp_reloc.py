"""Tests for the PSP relocation-format model (``SHT_PSPREL``).

The fixtures are synthetic on purpose: the semantics have to be pinned by the
format, not by one file.  Each test states which field of ``r_info`` or
``r_offset`` it exercises, so a regression names the field it broke.
"""

from __future__ import annotations

import pytest

from seto import psp_reloc
from seto.binio import ParseError
from seto.elf import (
    ET_MIPS_PSP_PRX,
    R_MIPS_26,
    R_MIPS_32,
    R_MIPS_HI16,
    R_MIPS_LO16,
    R_MIPS_NONE,
    SHT_MIPS_PSPREL,
    SHT_MIPS_PSPREL2,
    SHT_PROGBITS,
    parse,
)

from conftest import (
    SHF_ALLOC,
    SHF_EXECINSTR,
    build_elf32,
    build_relocations,
    word,
)

CODE = word(0x00000000) * 8


def _psp_module(*, program_headers, relocations, code: bytes = CODE, addr: int = 0, section=".text"):
    return parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=program_headers,
            sections=[
                {
                    "name": section,
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": addr,
                    "data": code,
                },
                {
                    "name": f".rel{section}",
                    "type": SHT_MIPS_PSPREL,
                    "data": relocations,
                    "entsize": 8,
                },
            ],
        )
    )


# --------------------------------------------------------------------- r_info


def test_decode_info_splits_the_three_psp_fields() -> None:
    info = (0x07 << 16) | (0x03 << 8) | 0x05
    decoded = psp_reloc.decode_info(info)
    assert decoded.type == 0x05
    assert decoded.segment_index == 0x03
    assert decoded.relative_index == 0x07
    assert decoded.summary() == {
        "type": "R_MIPS_HI16",
        "segment_index": 3,
        "relative_index": 7,
    }


def test_the_type_field_is_only_four_bits() -> None:
    # A high bit that spills past bit 3 is a segment field, not a new type.
    assert psp_reloc.decode_info(0x0000_0112).type == R_MIPS_32
    assert psp_reloc.decode_info(0x0000_0112).segment_index == 0x01


def test_a_stray_high_type_bit_never_invents_an_unknown_type() -> None:
    # 0x10 is outside the 4-bit mask; the loader sees type 0, not 16.
    assert psp_reloc.decode_info(0x10).type == R_MIPS_NONE


# ------------------------------------------------------------------- r_offset


def test_a_psp_offset_is_relative_to_its_segment() -> None:
    relocations = build_relocations([(0x10, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0x4000, "filesz": len(CODE), "memsz": 0x1000}],
        relocations=relocations,
        addr=0x4000,
    )
    (relocation,) = module.relocations
    assert relocation.format == "PSP"
    assert relocation.raw_offset == 0x10
    assert relocation.offset == 0x4010
    assert relocation.section_offset == 0x10
    assert relocation.source_section == ".rel.text"
    assert any("segment 0 has vaddr 0x4000" in item for item in module.observations)


def test_a_relocation_naming_an_absent_segment_is_reported_not_dropped() -> None:
    relocations = build_relocations([(0x00, R_MIPS_32, 2)])  # segment 2
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    (relocation,) = module.relocations
    assert relocation.segment_index == 2
    # The raw offset is kept, and the limitation is visible.
    assert relocation.offset == 0x00
    assert any("names segment 2" in item for item in module.observations)


def test_a_relocation_naming_a_non_load_segment_is_reported() -> None:
    relocations = build_relocations([(0x00, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[
            {"type": 4, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)},  # PT_NOTE
        ],
        relocations=relocations,
    )
    (relocation,) = module.relocations
    assert relocation.offset == 0x00
    assert any("not PT_LOAD" in item for item in module.observations)


def test_the_relative_segment_supplies_the_base() -> None:
    relocations = build_relocations([(0x10, R_MIPS_32, (1 << 8) | 1)])  # relative 1, segment 1
    module = _psp_module(
        program_headers=[
            {"type": 1, "vaddr": 0x0000, "filesz": len(CODE), "memsz": len(CODE)},
            {"type": 1, "vaddr": 0x1000, "filesz": len(CODE), "memsz": len(CODE)},
        ],
        relocations=relocations,
        addr=0x1000,
    )
    (relocation,) = module.relocations
    assert relocation.segment_index == 1
    assert relocation.relative_index == 1
    assert relocation.offset == 0x1010
    assert psp_reloc.relative_base(module, relocation) == 0x1000


def test_a_relative_segment_that_is_not_loaded_contributes_nothing() -> None:
    relocations = build_relocations([(0x00, R_MIPS_32, 3 << 8)])  # relative 3, segment 0
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    (relocation,) = module.relocations
    assert relocation.segment_index == 0
    assert relocation.relative_index == 3
    assert psp_reloc.relative_base(module, relocation) == 0


# --------------------------------------------------------------- compressed


def test_a_compressed_psp2_section_is_reported_not_decoded() -> None:
    module = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            sections=[
                {
                    "name": ".text",
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": 0,
                    "data": CODE,
                },
                {
                    "name": ".rel.text",
                    "type": SHT_MIPS_PSPREL2,
                    "data": b"\x01\x02\x03\x04\x05\x06\x07\x08",
                    "entsize": 8,
                },
            ],
        )
    )
    assert module.relocations == ()
    assert any("PSPREL2" in item for item in module.observations)


# ------------------------------------------------------------------ segments


def test_a_segment_larger_in_file_than_in_memory_is_rejected() -> None:
    with pytest.raises(ParseError, match="p_filesz"):
        parse(
            build_elf32(
                program_headers=[{"type": 1, "filesz": 8, "memsz": 4}],
                sections=[
                    {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "data": b"\x00" * 8}
                ],
            )
        )


# ------------------------------------------------------------------- loader


def test_apply_relocation_models_the_loaders_arithmetic() -> None:
    assert psp_reloc.apply_relocation(R_MIPS_32, 0x00004830, 0x08800000) == 0x08804830
    # R_MIPS_26 keeps the opcode and adds the base as a word index.
    assert psp_reloc.apply_relocation(R_MIPS_26, 0x0C000010, 0x08800000) == 0x0E200010
    assert psp_reloc.apply_relocation(R_MIPS_26, 0x0C000010, 0) == 0x0C000010
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x24844860, 0x1000) == 0x24845860
    assert psp_reloc.apply_relocation(R_MIPS_NONE, 0x12345678, 0x08800000) == 0x12345678
    # A GPREL16 is a notification: the word is left alone.
    assert psp_reloc.apply_relocation(psp_reloc.R_MIPS_GPREL16, 0x12345678, 0x08800000) == 0x12345678


def test_apply_relocation_returns_none_for_what_it_does_not_model() -> None:
    assert psp_reloc.apply_relocation(0x63, 0x12345678, 0) is None
    # HI16 cannot be resolved without its LO16 partner.
    assert psp_reloc.apply_relocation(R_MIPS_HI16, 0x3C030060, 0) is None


def test_hi16_absorbs_the_sign_of_its_lo16_partner() -> None:
    # hi 0x0060 + lo 0x4860 = 0x00604860, so a zero base changes nothing.
    assert (
        psp_reloc.apply_relocation(R_MIPS_HI16, 0x3C030060, 0, lo16_word=0x24634860)
        == 0x3C030060
    )
    # A low half with bit 15 set is negative, so the high half loses one.
    assert (
        psp_reloc.apply_relocation(R_MIPS_HI16, 0x3C030001, 0, lo16_word=0x24638000)
        == 0x3C030000
    )


# ------------------------------------------------------------------ inventory


def test_the_inventory_records_formats_types_and_segments() -> None:
    relocations = build_relocations(
        [
            (0x00, R_MIPS_32, 0),
            (0x04, R_MIPS_HI16, 0),
            (0x08, R_MIPS_LO16, 0),
        ]
    )
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0x0000, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["formats"] == ["PSP"]
    assert inventory["psp_entries"] == 3
    assert inventory["standard_entries"] == 0
    assert inventory["types"] == {"R_MIPS_32": 1, "R_MIPS_HI16": 1, "R_MIPS_LO16": 1}
    assert inventory["unknown_types"] == []
    assert inventory["segment_indices"] == {"0": 3}
    assert inventory["relative_indices"] == {"0": 3}
    assert inventory["compressed_sections"] == []
    assert inventory["segment_relocation_payloads"] == []
    assert inventory["entries_needing_a_rebase"] == []
    (section,) = inventory["sections"]
    assert section["name"] == ".rel.text"
    assert section["entries"] == 3
    assert section["targets"] == [".text"]


def test_the_inventory_flags_entries_that_need_a_rebase() -> None:
    relocations = build_relocations([(0x10, R_MIPS_32, (1 << 8) | 1)])
    module = _psp_module(
        program_headers=[
            {"type": 1, "vaddr": 0x0000, "filesz": len(CODE), "memsz": len(CODE)},
            {"type": 1, "vaddr": 0x1000, "filesz": len(CODE), "memsz": len(CODE)},
        ],
        relocations=relocations,
        addr=0x1000,
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["entries_needing_a_rebase"] == [1]
    assert inventory["segment_indices"] == {"1": 1}
    assert inventory["relative_indices"] == {"1": 1}


def test_the_inventory_records_an_unknown_type() -> None:
    relocations = build_relocations([(0x00, 0x63, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["unknown_types"] == ["R_MIPS_UNKNOWN(99)"]
    assert inventory["types"] == {"R_MIPS_UNKNOWN(99)": 1}
