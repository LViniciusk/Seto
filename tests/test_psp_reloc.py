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
    SHT_REL,
    SHT_MIPS_PSPREL,
    SHT_MIPS_PSPREL2,
    SHT_NOBITS,
    SHT_PROGBITS,
    parse,
)
from seto.matching import INCONCLUSIVE, compare, relocation_sites

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
        "reserved": "0x00000000",
    }


def test_the_type_field_is_only_four_bits() -> None:
    # PSP r_info 0x112 means type 2, segment 1, plus an unexpected reserved bit.
    decoded = psp_reloc.decode_info(0x0000_0112)
    assert decoded.type == R_MIPS_32
    assert decoded.segment_index == 0x01
    assert decoded.relative_index == 0
    assert decoded.reserved == 0x10


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


def test_segment_relative_address_overflow_is_not_wrapped() -> None:
    relocations = build_relocations([(0x20, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0xFFFFFFF0, "filesz": len(CODE), "memsz": 0x40}],
        relocations=relocations,
        addr=0xFFFFFFF0,
    )
    (relocation,) = module.relocations
    assert relocation.offset == 0x20  # diagnostic raw fallback only
    assert not relocation.application_valid
    assert relocation.section_offset is None
    assert any("exceeds the 32-bit address space" in item for item in module.observations)


def test_a_word_ending_at_the_32bit_limit_is_still_valid() -> None:
    relocations = build_relocations([(0, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[
            {"type": 1, "vaddr": 0xFFFFFFFC, "filesz": 0, "memsz": 4},
        ],
        relocations=relocations,
        addr=0xFFFFFFFC,
    )
    (relocation,) = module.relocations
    assert relocation.offset == 0xFFFFFFFC
    assert relocation.application_valid
    assert relocation.section_offset == 0
    assert relocation.file_offset is None
    assert relocation.addend_valid
    assert any("zero-filled PT_LOAD tail" in item for item in module.observations)


@pytest.mark.parametrize(
    ("memsz", "raw_offset", "valid"),
    ((8, 4, True), (8, 5, False), (3, 0, False), (8, 8, False)),
)
def test_a_psp_relocation_requires_all_four_bytes_inside_p_memsz(memsz, raw_offset, valid) -> None:
    relocations = build_relocations([(raw_offset, R_MIPS_32, 0)])
    module = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[{"type": 1, "vaddr": 0, "filesz": 0, "memsz": memsz}],
            sections=[
                {"name": ".bss", "type": SHT_NOBITS, "flags": SHF_ALLOC, "addr": 0, "size": memsz},
                {"name": ".rel.bss", "type": SHT_MIPS_PSPREL, "data": relocations, "entsize": 8},
            ],
        )
    )
    (relocation,) = module.relocations
    assert relocation.application_valid is valid
    if valid:
        assert relocation.section_offset == raw_offset
        assert relocation.file_offset is None
        assert relocation.addend_valid
        assert relocation.addend == 0
        assert len(psp_reloc.psp_inventory(module)["zero_fill_entries"]) == 1
    else:
        assert relocation.section_offset is None
        assert relocation.file_offset is None
        assert not relocation.addend_valid
        assert psp_reloc.psp_inventory(module)["complete"] is False


def test_a_complete_zero_filled_word_is_not_read_from_section_file_bytes() -> None:
    module = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[{"type": 1, "vaddr": 0, "filesz": 4, "memsz": 8}],
            sections=[
                {
                    "name": ".text",
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": 0,
                    "data": word(0x11111111),
                },
                {"name": ".bss", "type": SHT_NOBITS, "flags": SHF_ALLOC, "addr": 4, "size": 4},
                {
                    "name": ".rel.bss",
                    "type": SHT_MIPS_PSPREL,
                    "data": build_relocations([(4, R_MIPS_32, 0)]),
                    "entsize": 8,
                },
            ],
        )
    )
    (relocation,) = module.relocations
    assert relocation.application_valid
    assert relocation.section_offset == 0
    assert relocation.file_offset is None
    assert relocation.addend_valid
    assert relocation.addend == 0
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["complete"]
    assert inventory["zero_fill_entries"][0]["raw_offset"] == "0x4"


def test_a_word_straddling_p_filesz_keeps_its_memory_location_but_not_an_addend() -> None:
    relocations = build_relocations([(4, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": 6, "memsz": 8}],
        relocations=relocations,
    )
    (relocation,) = module.relocations
    assert relocation.application_valid
    assert relocation.section_offset == 4
    assert relocation.file_offset is None
    assert not relocation.addend_valid
    assert psp_reloc.psp_inventory(module)["complete"] is False
    result = compare(
        CODE,
        CODE,
        name="straddles-p-filesz",
        original_relocations=[relocation],
        candidate_relocations=[relocation],
    )
    assert result.status == INCONCLUSIVE


def test_a_relocation_naming_an_absent_segment_is_reported_not_dropped() -> None:
    relocations = build_relocations([(0x00, R_MIPS_32, 2)])  # segment 2
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    (relocation,) = module.relocations
    assert relocation.segment_index == 2
    # The raw offset coincides with .text, but invalid segment metadata must not
    # turn that coincidence into an application location or readable addend.
    assert relocation.offset == 0x00
    assert relocation.raw_offset == 0x00
    assert not relocation.application_valid
    assert relocation.section_offset is None
    assert relocation.file_offset is None
    assert relocation.addend == 0
    assert any("names segment 2" in item for item in module.observations)
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["complete"] is False
    assert len(inventory["invalid_entries"]) == 1
    mapped = relocation_sites(module.relocations, 0, len(CODE))
    assert mapped.sites == {}
    assert mapped.limitations
    result = compare(CODE, CODE, name="invalid-segment", original_relocations=module.relocations)
    assert result.status == INCONCLUSIVE


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
    assert not relocation.application_valid
    assert relocation.section_offset is None
    assert relocation.file_offset is None
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
    assert psp_reloc.relative_base(module, relocation) is None


def test_runtime_segment_address_requires_an_explicit_load_base() -> None:
    relocations = build_relocations([(0x00, R_MIPS_32, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0x1000, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
        addr=0x1000,
    )
    (segment,) = module.segments
    (relocation,) = module.relocations
    assert psp_reloc.segment_runtime_address(segment, 0) == 0x1000
    assert psp_reloc.segment_runtime_address(segment, 0x08800000) == 0x08801000
    assert psp_reloc.relative_base(module, relocation) == 0x1000
    assert psp_reloc.relative_base(module, relocation, load_base=0x08800000) == 0x08801000
    with pytest.raises(ValueError, match="overflows"):
        psp_reloc.segment_runtime_address(segment, 0xFFFFF000)


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
    assert psp_reloc.psp_inventory(module)["complete"] is False


def test_a_compressed_program_header_payload_is_incomplete_inventory() -> None:
    module = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[
                {"type": psp_reloc.PT_PSPREL1, "filesz": 4, "memsz": 4},
            ],
            sections=[
                {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "data": CODE},
            ],
        )
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["segment_relocation_payloads"] == [0]
    assert inventory["complete"] is False


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
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x24844860, 0x08800000) == 0x24844860
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x24844860, 0x08801000) == 0x24845860
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x24847FFF, 1) == 0x24848000
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x24848000, 1) == 0x24848001
    assert psp_reloc.apply_relocation(R_MIPS_LO16, 0x2484FFFF, 1) == 0x24840000
    assert psp_reloc.apply_relocation(R_MIPS_NONE, 0x12345678, 0x08800000) == 0x12345678
    # A GPREL16 is a notification: the word is left alone.
    assert psp_reloc.apply_relocation(psp_reloc.R_MIPS_GPREL16, 0x12345678, 0x08800000) == 0x12345678


def test_apply_relocation_returns_none_for_what_it_does_not_model() -> None:
    assert psp_reloc.apply_relocation(0x63, 0x12345678, 0) is None
    # HI16 cannot be resolved without its LO16 partner.
    assert psp_reloc.apply_relocation(R_MIPS_HI16, 0x3C030060, 0) is None


def test_hi16_rounds_the_sign_extended_lo16_before_taking_the_high_half() -> None:
    # HI 1 plus signed LO -0x8000 reconstructs 0x00008000; the rounded high
    # immediate must remain 1 (the old truncating calculation incorrectly gave 0).
    assert (
        psp_reloc.apply_relocation(R_MIPS_HI16, 0x3C030001, 0, lo16_word=0x24638000)
        == 0x3C030001
    )
    # Carry caused by a nonzero runtime base is included before the rounding.
    assert (
        psp_reloc.apply_relocation(
            R_MIPS_HI16, 0x3C030001, 0x08800000, lo16_word=0x24638000
        )
        == 0x3C030881
    )
    # Overflow wraps at 32 bits before the high-half rounding.
    assert (
        psp_reloc.apply_relocation(
            R_MIPS_HI16, 0x3C03FFFF, 0x00010000, lo16_word=0x24637FFF
        )
        == 0x3C030000
    )
    # Non-relocation bits (opcode/register fields) remain unchanged.
    assert psp_reloc.apply_relocation(
        R_MIPS_HI16, 0x3C03FFFF, 0x00010000, lo16_word=0x24637FFF
    ) & 0xFFFF0000 == 0x3C030000


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
    assert inventory["relative_segments_with_nonzero_vaddr"] == []
    assert inventory["runtime_addressing"] == "load_base + p_vaddr; load_base is not inferred from the ELF"
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
    assert inventory["relative_segments_with_nonzero_vaddr"] == [1]
    assert inventory["segment_indices"] == {"1": 1}
    assert inventory["relative_indices"] == {"1": 1}


def test_the_inventory_records_an_unknown_type() -> None:
    relocations = build_relocations([(0x00, 0x63, 0)])
    module = parse(
        build_elf32(
            e_type=1,
            sections=[
                {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "data": CODE},
                {"name": ".rel.text", "type": SHT_REL, "data": relocations, "entsize": 8},
            ],
        )
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["unknown_types"] == ["R_MIPS_UNKNOWN(99)"]
    assert inventory["types"] == {"R_MIPS_UNKNOWN(99)": 1}
    assert inventory["complete"] is False


def test_a_known_but_unimplemented_relocation_is_reported_as_unsupported() -> None:
    # R_MIPS_16 and R_MIPS_REL32 are known MIPS values but this evaluator
    # deliberately does not model their arithmetic; neither may look complete.
    relocations = build_relocations([(0x00, 1, 0), (0x04, 3, 0)])
    module = _psp_module(
        program_headers=[{"type": 1, "vaddr": 0, "filesz": len(CODE), "memsz": len(CODE)}],
        relocations=relocations,
    )
    inventory = psp_reloc.psp_inventory(module)
    assert inventory["unknown_types"] == []
    assert inventory["unsupported_types"] == ["R_MIPS_16", "R_MIPS_REL32"]
    assert inventory["complete"] is False
    assert psp_reloc.apply_relocation(1, 0x12345678, 0x08800000) is None
