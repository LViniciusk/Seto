"""Tests for the ELF32 parser: headers, sections, relocations and comments."""

from __future__ import annotations

import struct

import pytest

from seto import psp_reloc
from seto.binio import ParseError
from seto.elf import (
    ET_MIPS_PSP_PRX,
    R_MIPS_32,
    R_MIPS_HI16,
    R_MIPS_26,
    R_MIPS_LO16,
    SHT_MIPS_PSPREL,
    SHT_NOBITS,
    SHT_PROGBITS,
    SHT_REL,
    decode_relocation_addend,
    parse,
    relocation_mask,
)

from conftest import (
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHT_STRTAB,
    SHT_SYMTAB,
    build_elf32,
    build_relocations,
    build_symbol_table,
)


def _text_section(code: bytes, addr: int = 0) -> dict:
    return {
        "name": ".text",
        "type": SHT_PROGBITS,
        "flags": SHF_ALLOC | SHF_EXECINSTR,
        "addr": addr,
        "data": code,
    }


def test_parse_minimal_elf() -> None:
    parsed = parse(build_elf32(sections=[_text_section(b"\x08\x00\xe0\x03\x00\x00\x00\x00")]))
    assert parsed.header.e_machine == 8
    assert parsed.header.file_type_name == "ET_REL"
    assert not parsed.is_prx
    assert parsed.require_section(".text").size == 8
    assert parsed.section_data(".text") == b"\x08\x00\xe0\x03\x00\x00\x00\x00"
    assert parsed.relocations == ()
    assert parsed.comment() is None


def test_parse_rejects_bad_magic() -> None:
    with pytest.raises(ParseError, match="bad ELF magic"):
        parse(build_elf32(magic=b"NOTELF", sections=[_text_section(b"\x00" * 4)]))


def test_parse_rejects_wrong_class() -> None:
    with pytest.raises(ParseError, match="unsupported ELF class"):
        parse(build_elf32(ei_class=2, sections=[_text_section(b"\x00" * 4)]))


def test_parse_rejects_big_endian() -> None:
    with pytest.raises(ParseError, match="unsupported byte order"):
        parse(build_elf32(ei_data=2, sections=[_text_section(b"\x00" * 4)]))


def test_parse_rejects_wrong_architecture() -> None:
    with pytest.raises(ParseError, match="unexpected machine"):
        parse(build_elf32(e_machine=3, sections=[_text_section(b"\x00" * 4)]))


def test_parse_allows_architecture_check_to_be_disabled() -> None:
    parsed = parse(build_elf32(e_machine=3, sections=[_text_section(b"\x00" * 4)]), expected_machine=None)
    assert parsed.header.e_machine == 3
    assert not parsed.is_mips


def test_parse_rejects_truncated_header() -> None:
    with pytest.raises(ParseError, match="too small"):
        parse(b"\x7fELF\x01\x01\x01")


def test_parse_rejects_truncated_section_table() -> None:
    payload = build_elf32(sections=[_text_section(b"\x00" * 16)])
    with pytest.raises(ParseError):
        parse(payload[:-8])


def test_parse_rejects_section_body_outside_the_file() -> None:
    payload = bytearray(build_elf32(sections=[_text_section(b"\x00" * 16)]))
    shoff = struct.unpack_from("<I", payload, 0x20)[0]
    struct.pack_into("<I", payload, shoff + 40 + 0x14, 0x100000)  # .text sh_size
    with pytest.raises(ParseError):
        parse(bytes(payload))


def test_parse_rejects_shstrndx_out_of_range() -> None:
    with pytest.raises(ParseError, match="e_shstrndx"):
        parse(build_elf32(sections=[_text_section(b"\x00" * 4)], e_shstrndx_override=99))


def test_parse_rejects_section_name_table_that_is_not_strtab() -> None:
    payload = build_elf32(sections=[_text_section(b"\x00" * 4)])
    with pytest.raises(ParseError, match="not a string table"):
        # Point e_shstrndx at .text (index 1), which is PROGBITS.
        parse(
            build_elf32(
                sections=[_text_section(b"\x00" * 4)],
                e_shstrndx_override=1,
            )
        )
    del payload


def test_parse_rejects_section_name_escaping_string_table() -> None:
    payload = bytearray(build_elf32(sections=[_text_section(b"\x00" * 4)]))
    shoff = struct.unpack_from("<I", payload, 0x20)[0]
    struct.pack_into("<I", payload, shoff + 40, 0xFFFF)  # .text sh_name
    with pytest.raises(ParseError, match="escapes the string table"):
        parse(bytes(payload))


def test_parse_rejects_truncated_program_header_table() -> None:
    payload = build_elf32(
        sections=[_text_section(b"\x00" * 4)],
        program_headers=[{"type": 1, "filesz": 4}],
    )
    header_only = bytearray(payload)
    struct.pack_into("<H", header_only, 0x2C, 4)  # pretend there are 4 phdrs
    with pytest.raises(ParseError):
        parse(bytes(header_only))


def test_parse_rejects_relocation_size_not_multiple_of_eight() -> None:
    payload = build_elf32(
        sections=[
            _text_section(b"\x00" * 16),
            {"name": ".rel.text", "type": SHT_REL, "data": b"\x00" * 12, "info": 1},
        ]
    )
    with pytest.raises(ParseError, match="not a multiple"):
        parse(payload)


def test_comment_signature_is_extracted() -> None:
    parsed = parse(
        build_elf32(
            sections=[
                _text_section(b"\x00" * 4),
                {"name": ".comment", "type": SHT_PROGBITS, "data": b"MW MIPS C Compiler (2.4.1.01)\x00PSP\x00"},
            ]
        )
    )
    assert parsed.comment() == "MW MIPS C Compiler (2.4.1.01)"


def test_prx_sections_and_relocations() -> None:
    # addiu $a0, $a0, 0x2edc (HI16/LO16 pair) and jal 0x2edc encoded in place.
    hi = 0x3C040000  # lui $a0, 0x0000
    lo = 0x24840000 | 0x2EDC  # addiu $a0, $a0, 0x2edc
    call = 0x0C000000 | (0x2EDC >> 2)  # jal 0x2edc
    code = struct.pack("<III", hi, lo, call) + b"\x08\x00\xe0\x03"
    relocations = build_relocations(
        [(0x00, R_MIPS_HI16, 0), (0x04, R_MIPS_LO16, 0), (0x08, R_MIPS_26, 0)]
    )
    parsed = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[{"type": 1, "vaddr": 0, "filesz": len(code), "memsz": len(code)}],
            sections=[
                _text_section(code),
                {"name": ".comment", "type": SHT_PROGBITS, "data": b"MW MIPS C Compiler\x00"},
                {
                    "name": ".rel.text",
                    "type": SHT_MIPS_PSPREL,
                    "data": relocations,
                    "entsize": 8,
                },
            ],
        )
    )
    assert parsed.is_prx
    assert len(parsed.relocations) == 3
    assert {item.target_section for item in parsed.relocations} == {".text"}
    by_offset = {item.section_offset: item for item in parsed.relocations}
    assert by_offset[0x00].type == R_MIPS_HI16
    assert by_offset[0x00].addend == 0
    assert by_offset[0x04].addend == 0x2EDC
    assert by_offset[0x08].addend == 0x2EDC
    assert parsed.relocations_for(".text") == parsed.relocations


def test_prx_shstrtab_with_address_zero_does_not_shadow_text() -> None:
    """``.shstrtab`` has ``addr == 0``; it must not be used to decode relocations."""
    code = struct.pack("<I", 0x24840000 | 0x0034) + b"\x00" * 4
    parsed = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[{"type": 1, "vaddr": 0, "filesz": len(code), "memsz": len(code)}],
            sections=[
                _text_section(code),
                {
                    "name": ".rel.text",
                    "type": SHT_MIPS_PSPREL,
                    "data": build_relocations([(0x00, R_MIPS_LO16, 0), (0x04, R_MIPS_LO16, 0)]),
                    "entsize": 8,
                },
            ],
        )
    )
    assert parsed.relocations[0].addend == 0x34
    assert parsed.relocations[1].addend == 0


def test_psp_r_info_is_a_segment_not_a_symbol_index() -> None:
    """The same ``r_info`` bits are a symbol index in SHT_REL and a segment in PSP."""
    code = struct.pack("<I", 0x00000000) * 2
    parsed = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[
                {"type": 1, "vaddr": 0x0000, "filesz": len(code), "memsz": len(code)},
                {"type": 1, "vaddr": 0x1000, "filesz": len(code), "memsz": len(code)},
            ],
            sections=[
                _text_section(code, addr=0x1000),
                {
                    "name": ".rel.text",
                    "type": SHT_MIPS_PSPREL,
                    # r_info = (relative 2 << 16) | (segment 1 << 8) | R_MIPS_LO16
                    "data": build_relocations([(0x00, R_MIPS_LO16, (2 << 8) | 1)]),
                    "entsize": 8,
                },
            ],
        )
    )
    relocation = parsed.relocations_for(".text")[0]
    assert relocation.info == (2 << 16) | (1 << 8) | R_MIPS_LO16
    assert relocation.format == "PSP"
    assert relocation.segment_index == 1
    assert relocation.relative_index == 2
    # Bits 8..15 name a segment here, so they must not be read as a symbol index.
    assert relocation.symbol_index == 0
    # r_offset is segment-relative, so the patched address is segment.vaddr + it.
    assert relocation.raw_offset == 0x00
    assert relocation.offset == 0x1000
    assert relocation.section_offset == 0x00


def test_psp_r_info_uses_low_nibble_for_type_and_reports_reserved_bits() -> None:
    code = struct.pack("<I", 0x00000000) * 2
    relocation_bytes = bytearray(build_relocations([(0x00, R_MIPS_32, 1)]))
    # PSP loader sees type 2 in the low nibble and segment 1 in bits 8..15;
    # bit 4 is reserved, not part of an invented type 0x12.
    struct.pack_into("<I", relocation_bytes, 4, 0x00000112)
    parsed = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[
                {"type": 1, "vaddr": 0, "filesz": len(code), "memsz": len(code)},
                {"type": 1, "vaddr": 0x1000, "filesz": len(code), "memsz": len(code)},
            ],
            sections=[
                _text_section(code, addr=0x1000),
                {
                    "name": ".rel.text",
                    "type": SHT_MIPS_PSPREL,
                    "data": bytes(relocation_bytes),
                    "entsize": 8,
                },
            ],
        )
    )
    (relocation,) = parsed.relocations
    assert relocation.type == R_MIPS_32
    assert relocation.segment_index == 1
    assert relocation.relative_index == 0
    assert relocation.info == 0x112
    assert relocation.application_valid
    inventory = psp_reloc.psp_inventory(parsed)
    assert inventory["reserved_field_entries"]
    assert inventory["complete"] is False
    assert any("reserved bits set (0x00000010)" in item for item in parsed.observations)


def test_standard_rel_r_info_is_a_symbol_index() -> None:
    symbol_table, string_table = build_symbol_table(["", "func_a"])
    code = struct.pack("<I", 0x0C000000 | (0x20 >> 2)) + b"\x00" * 4
    parsed = parse(
        build_elf32(
            e_type=1,
            sections=[
                _text_section(code),
                {"name": ".symtab", "type": SHT_SYMTAB, "data": symbol_table, "link": 3, "entsize": 16},
                {"name": ".strtab", "type": SHT_STRTAB, "data": string_table},
                {
                    "name": ".rel.text",
                    "type": SHT_REL,
                    "data": build_relocations([(0x00, R_MIPS_26, 1)]),
                    "entsize": 8,
                },
            ],
        )
    )
    relocation = parsed.relocations_for(".text")[0]
    assert relocation.format == "REL"
    assert relocation.symbol_index == 1
    assert relocation.symbol == "func_a"
    assert relocation.segment_index == 0
    assert relocation.relative_index == 0
    assert relocation.raw_offset == relocation.offset == 0x00


def test_relocation_symbols_from_symtab() -> None:
    symbol_table, string_table = build_symbol_table(["", "func_a", "func_b"])
    code = struct.pack("<I", 0x0C000000 | (0x20 >> 2)) + b"\x00" * 4
    parsed = parse(
        build_elf32(
            e_type=1,  # ET_REL
            sections=[
                _text_section(code),
                {"name": ".symtab", "type": SHT_SYMTAB, "data": symbol_table, "link": 3, "entsize": 16},
                {"name": ".strtab", "type": SHT_STRTAB, "data": string_table},
                {
                    "name": ".rel.text",
                    "type": SHT_REL,
                    "data": build_relocations([(0x00, R_MIPS_26, 1)]),
                    "link": 2,
                    "info": 1,
                    "entsize": 8,
                },
            ],
        )
    )
    assert len(parsed.symbols) == 3
    relocation = parsed.relocations_for(".text")[0]
    assert relocation.symbol == "func_a"
    assert relocation.section_offset == 0
    assert relocation.addend == 0x20


def test_relocation_with_rogue_symbol_index_has_no_name() -> None:
    parsed = parse(
        build_elf32(
            e_type=1,
            sections=[
                _text_section(struct.pack("<I", 0x0C000000 | (0x20 >> 2)) + b"\x00" * 4),
                {
                    "name": ".rel.text",
                    "type": SHT_REL,
                    "data": build_relocations([(0x00, R_MIPS_26, 99)]),
                    "info": 1,
                    "entsize": 8,
                },
            ],
        )
    )
    assert parsed.relocations_for(".text")[0].symbol is None


def test_data_relocations_use_the_data_section() -> None:
    parsed = parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            program_headers=[{"type": 1, "vaddr": 0, "filesz": 16, "memsz": 0x2000}],
            sections=[
                _text_section(b"\x00" * 8),
                {
                    "name": ".data",
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC | 0x1,
                    "addr": 0x1000,
                    "data": struct.pack("<I", 0x1200) + b"\x00" * 4,
                },
                {
                    "name": ".rel.data",
                    "type": SHT_MIPS_PSPREL,
                    "data": build_relocations([(0x1000, R_MIPS_32, 0)]),
                    "entsize": 8,
                },
            ],
        )
    )
    relocation = parsed.relocations_for(".data")[0]
    assert relocation.section_offset == 0
    assert relocation.addend == 0x1200


def test_nobits_section_has_no_data() -> None:
    parsed = parse(
        build_elf32(
            sections=[
                _text_section(b"\x00" * 4),
                {"name": ".bss", "type": SHT_NOBITS, "flags": SHF_ALLOC | 0x1, "size": 16, "align": 4},
            ]
        )
    )
    assert parsed.require_section(".bss").is_nobits
    assert parsed.section_data(".bss") == b""


def test_missing_section_raises() -> None:
    parsed = parse(build_elf32(sections=[_text_section(b"\x00" * 4)]))
    with pytest.raises(ParseError, match="not found"):
        parsed.require_section(".rodata")


def test_summary_is_json_friendly() -> None:
    import json

    parsed = parse(build_elf32(sections=[_text_section(b"\x00" * 4)]))
    json.dumps(parsed.summary())


@pytest.mark.parametrize(
    ("rel_type", "expected_mask"),
    [
        (R_MIPS_32, 0xFFFFFFFF),
        (R_MIPS_26, 0x03FFFFFF),
        (R_MIPS_HI16, 0x0000FFFF),
        (R_MIPS_LO16, 0x0000FFFF),
        (0, 0),
        (77, 0),
    ],
)
def test_relocation_mask(rel_type: int, expected_mask: int) -> None:
    assert relocation_mask(rel_type) == expected_mask


def test_decode_relocation_addend() -> None:
    assert decode_relocation_addend(0x0C001234, R_MIPS_26) == 0x1234 << 2
    assert decode_relocation_addend(0x2484FFFE, R_MIPS_LO16) == -2
    assert decode_relocation_addend(0x3C04FFFF, R_MIPS_HI16) == -1
    assert decode_relocation_addend(0xDEADBEEF, R_MIPS_32) == 0xDEADBEEF
