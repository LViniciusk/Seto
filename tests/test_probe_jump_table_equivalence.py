"""Pure regression tests for the controlled SETO-DECOMP-015 code+table comparison.

Every fixture is synthetic: no PRX, no Metrowerks, no linker.  The tests pin the
code-word comparison, the six-entry table comparison, the R_MIPS_32 / HI16/LO16
relocation handling, the negative controls and the build-path confinement.
"""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from seto import elf, mips
from seto.binio import ParseError

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "probe_jump_table_equivalence.py"
SPEC = importlib.util.spec_from_file_location("seto_probe_jump_table_equivalence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

from conftest import (  # noqa: E402
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHT_PROGBITS,
    SHT_REL,
    SHT_STRTAB,
    SHT_SYMTAB,
    build_elf32,
    build_relocations,
    build_symbols,
    word,
)

ET_MIPS_PSP_PRX = elf.ET_MIPS_PSP_PRX
ET_EXEC = elf.ET_EXEC
ET_REL = elf.ET_REL
SHT_MIPS_PSPREL = elf.SHT_MIPS_PSPREL
R_MIPS_32 = elf.R_MIPS_32
R_MIPS_26 = elf.R_MIPS_26
R_MIPS_HI16 = elf.R_MIPS_HI16
R_MIPS_LO16 = elf.R_MIPS_LO16

# The real original function words (`.text[0x39C:0x414)`), reused as the linked
# baseline because case A reproduces them exactly.
FUNCTION_WORDS = (
    0x27BDFFF0, 0xAFBF000C, 0x0C0008D9, 0x00000000, 0x2C410006,
    0x50200015, 0x24020001, 0x3C030000, 0x00021080, 0x24634770,
    0x00431021, 0x8C420000, 0x00400008, 0x00000000, 0x1000000C,
    0x00001021, 0x1000000A, 0x24020001, 0x10000008, 0x24020006,
    0x10000006, 0x24020002, 0x10000004, 0x24020005, 0x10000002,
    0x24020003, 0x24020001, 0x8FBF000C, 0x03E00008, 0x27BD0010,
)
TABLE_ENTRIES = (0x3D4, 0x3DC, 0x3E4, 0x3EC, 0x3F4, 0x3FC)
OBJECT_OFFSETS = (0x38, 0x40, 0x48, 0x50, 0x58, 0x60)


def _u32_words(values) -> bytes:
    return b"".join(word(value) for value in values)


def _candidate_object_bytes(
    *,
    offsets: Sequence[int] = OBJECT_OFFSETS,
    table_words: Sequence[int] | None = None,
    with_mwcats: bool = True,
) -> bytes:
    symtab, strtab = build_symbols(
        [
            {"name": "", "value": 0, "size": 0, "info": 0, "shndx": 0},
            {"name": "@13", "value": 0, "size": 24, "info": 0x01, "shndx": 3},
            {"name": "func_0000039C", "value": 0, "size": 0x78, "info": 0x02, "shndx": 1},
            {"name": "func_00002364", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
        ]
    )
    text = _u32_words(FUNCTION_WORDS)
    actual_words = tuple(offsets if table_words is None else table_words)
    table = _u32_words(actual_words)
    text_rels = build_relocations(
        [(2 * 4, R_MIPS_26, 3), (7 * 4, R_MIPS_HI16, 1), (9 * 4, R_MIPS_LO16, 1)]
    )
    table_rels = build_relocations([(index * 4, R_MIPS_32, 2) for index in range(len(offsets))])
    sections: list[dict[str, object]] = [
        {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0, "size": len(text), "data": text},
        {"name": ".rel.text", "type": SHT_REL, "data": text_rels, "link": 6 if with_mwcats else 5, "info": 1, "entsize": 8},
        {"name": ".rodata", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": 0, "size": len(table), "data": table},
        {"name": ".rel.rodata", "type": SHT_REL, "data": table_rels, "link": 6 if with_mwcats else 5, "info": 3, "entsize": 8},
    ]
    if with_mwcats:
        sections.append(
            {"name": ".mwcats", "type": SHT_PROGBITS, "data": struct.pack("<II", 0, 0x39C)}
        )
    symtab_index = len(sections) + 1
    strtab_index = symtab_index + 1
    sections.append(
        {"name": ".symtab", "type": SHT_SYMTAB, "data": symtab, "link": strtab_index, "info": 1, "entsize": 16}
    )
    sections.append({"name": ".strtab", "type": SHT_STRTAB, "data": strtab, "align": 1})
    return build_elf32(sections=sections)


def _linked_elf_bytes(
    *,
    text_words=FUNCTION_WORDS,
    entries=TABLE_ENTRIES,
    table_address=0x4770,
    metadata_pointer=0x39C,
    with_rodata=True,
    with_metadata=True,
) -> bytes:
    text = _u32_words(text_words)
    table = _u32_words(entries)
    symtab, strtab = build_symbols(
        [
            {"name": "", "value": 0, "size": 0, "info": 0, "shndx": 0},
            {"name": "func_0000039C", "value": 0x39C, "size": 0x78, "info": 0x02, "shndx": 1},
            {"name": "func_00002364", "value": 0x2364, "size": 0, "info": 0x10, "shndx": elf.SHN_ABS},
        ]
    )
    sections: list[dict[str, object]] = [
        {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0x39C, "size": len(text), "data": text}
    ]
    if with_rodata:
        sections.append(
            {"name": ".rodata", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": table_address, "size": len(table), "data": table}
        )
    if with_metadata:
        sections.append(
            {"name": ".mwcats", "type": SHT_PROGBITS, "data": struct.pack("<II", 0, metadata_pointer)}
        )
    strtab_index = len(sections) + 2
    sections.append(
        {"name": ".symtab", "type": SHT_SYMTAB, "data": symtab, "link": strtab_index, "info": 1, "entsize": 16}
    )
    sections.append({"name": ".strtab", "type": SHT_STRTAB, "data": strtab, "align": 1})
    return build_elf32(e_type=ET_EXEC, sections=sections)


def _lui(register: int, immediate: int) -> int:
    return (0x0F << 26) | (register << 16) | (immediate & 0xFFFF)


def _addiu(target: int, source: int, immediate: int) -> int:
    return (0x09 << 26) | (source << 21) | (target << 16) | (immediate & 0xFFFF)


def _psp_rel(offset: int, rel_type: int) -> bytes:
    return struct.pack("<II", offset, rel_type)


# ----------------------------------------------------------------- word comparison


def test_compare_word_sequences_requires_exactly_thirty_words() -> None:
    words = (0,) * 30
    assert probe.compare_word_sequences(words, words) == []
    with pytest.raises(ParseError, match="expected 30 words"):
        probe.compare_word_sequences(words[:-1], words)
    with pytest.raises(ParseError, match="expected 30 words"):
        probe.compare_word_sequences(words, words + (0,))


def test_compare_word_sequences_reports_a_nonrelocated_instruction() -> None:
    original = list(FUNCTION_WORDS)
    linked = list(FUNCTION_WORDS)
    linked[0] = 0x27BDFFF1
    assert probe.compare_word_sequences(original, linked) == [
        {"word_index": 0, "address": "0x39c", "original": "0x27bdfff0", "linked": "0x27bdfff1"}
    ]


# ------------------------------------------------------------------ table comparison


def test_compare_table_entries_requires_six_and_reports_differences() -> None:
    assert probe.compare_table_entries(TABLE_ENTRIES, TABLE_ENTRIES) == []
    with pytest.raises(ParseError, match="expected 6 table entries"):
        probe.compare_table_entries(TABLE_ENTRIES[:-1], TABLE_ENTRIES)
    swapped = (TABLE_ENTRIES[1], TABLE_ENTRIES[0], *TABLE_ENTRIES[2:])
    assert probe.compare_table_entries(TABLE_ENTRIES, swapped) == [
        {"entry_index": 0, "original": "0x000003d4", "linked": "0x000003dc"},
        {"entry_index": 1, "original": "0x000003dc", "linked": "0x000003d4"},
    ]


def test_entry_destinations_flag_case_bodies_and_account_every_entry() -> None:
    rows = probe.entry_destination_rows(TABLE_ENTRIES)
    assert [row["matches_expected_case"] for row in rows] == [True] * 6
    assert all(row["inside_function"] for row in rows)
    probe.validate_case_destinations(TABLE_ENTRIES)
    wrong = list(TABLE_ENTRIES)
    wrong[3] = 0x3E0
    with pytest.raises(probe.ProbeError, match="does not map"):
        probe.validate_case_destinations(wrong)


def test_compare_table_entries_reports_multiple_divergent_entries() -> None:
    divergent = list(TABLE_ENTRIES)
    divergent[2] = 0x3E0
    divergent[3] = 0x3E8
    differences = probe.compare_table_entries(TABLE_ENTRIES, divergent)
    assert len(differences) == 2
    assert differences == [
        {"entry_index": 2, "original": "0x000003e4", "linked": "0x000003e0"},
        {"entry_index": 3, "original": "0x000003ec", "linked": "0x000003e8"},
    ]


def test_validate_structural_destinations_accepts_valid_divergence_and_rejects_structural_faults() -> None:
    probe.validate_structural_destinations(TABLE_ENTRIES)
    divergent = list(TABLE_ENTRIES)
    divergent[3] = 0x3E0
    probe.validate_structural_destinations(divergent)

    misaligned = list(TABLE_ENTRIES)
    misaligned[3] = 0x3E1
    with pytest.raises(probe.ProbeError, match="outside aligned function code"):
        probe.validate_structural_destinations(misaligned)

    out_of_bounds_high = list(TABLE_ENTRIES)
    out_of_bounds_high[3] = 0x414
    with pytest.raises(probe.ProbeError, match="outside aligned function code"):
        probe.validate_structural_destinations(out_of_bounds_high)

    out_of_bounds_low = list(TABLE_ENTRIES)
    out_of_bounds_low[3] = 0x398
    with pytest.raises(probe.ProbeError, match="outside aligned function code"):
        probe.validate_structural_destinations(out_of_bounds_low)

    with pytest.raises(probe.ProbeError, match="expected 6 table entries"):
        probe.validate_structural_destinations(TABLE_ENTRIES[:-1])


def test_equivalence_claim_never_promotes_controlled_equality() -> None:
    assert probe.equivalence_claim(30, 6) == "ASSUMPTION_DEPENDENT"
    assert probe.equivalence_claim(30, 5) == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"
    assert probe.equivalence_claim(29, 6) == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


# ------------------------------------------------------------------ negative controls


def test_layout_control_changes_only_the_lo16_word() -> None:
    baseline = list(FUNCTION_WORDS)
    moved = list(FUNCTION_WORDS)
    moved[9] = _addiu(3, 3, 0x4774)
    differences = probe.validate_layout_control(baseline, moved)
    assert [row["word_index"] for row in differences] == [9]
    changed_elsewhere = list(moved)
    changed_elsewhere[0] ^= 1
    with pytest.raises(probe.ProbeError, match="only the HI16/LO16"):
        probe.validate_layout_control(baseline, changed_elsewhere)


def test_control_b_reconstructs_its_own_assigned_address() -> None:
    baseline = list(FUNCTION_WORDS)
    moved = list(FUNCTION_WORDS)
    moved[9] = _addiu(3, 3, 0x4774)
    differences = probe.validate_layout_destination(baseline, moved, assigned_address=0x4774)
    assert [row["word_index"] for row in differences] == [9]
    assert probe.paired_effective_address(moved[7], moved[9]) == 0x4774


def test_control_b_rejects_a_pair_that_reconstructs_a_different_address() -> None:
    baseline = list(FUNCTION_WORDS)
    moved = list(FUNCTION_WORDS)
    moved[9] = _addiu(3, 3, 0x4778)
    # The LO16 word differs from A at the expected index, yet the pair reconstructs
    # 0x4778: differing from A is not enough, so control B must be rejected.
    assert [row["word_index"] for row in probe.compare_word_sequences(baseline, moved)] == [9]
    assert probe.paired_effective_address(moved[7], moved[9]) == 0x4778
    with pytest.raises(probe.ProbeError, match="reconstructs 0x4778, expected 0x4774"):
        probe.validate_layout_destination(baseline, moved, assigned_address=0x4774)


def test_control_b_rejects_an_invalid_hi16_lo16_pair() -> None:
    with pytest.raises(ParseError, match="not a LUI"):
        probe.paired_effective_address(0x00000000, _addiu(3, 3, 0x4774))
    with pytest.raises(ParseError, match="not an ADDIU"):
        probe.paired_effective_address(_lui(3, 0), 0x00000000)


def test_control_b_propagates_an_invalid_pair_through_its_validator() -> None:
    # An invalid HI16/LO16 pair reaches paired_effective_address through the
    # composed validator and keeps raising ParseError (no silent acceptance).
    baseline = list(FUNCTION_WORDS)
    baseline[7] = 0x00000000  # not a LUI, in both artifacts
    moved = list(baseline)
    moved[9] = _addiu(3, 3, 0x4774)
    assert [row["word_index"] for row in probe.compare_word_sequences(baseline, moved)] == [9]
    with pytest.raises(ParseError, match="not a LUI"):
        probe.validate_layout_destination(baseline, moved, assigned_address=0x4774)


def test_table_swap_is_detected_at_exactly_the_swapped_entries() -> None:
    swapped = (TABLE_ENTRIES[1], TABLE_ENTRIES[0], *TABLE_ENTRIES[2:])
    assert [row["entry_index"] for row in probe.validate_table_swap(TABLE_ENTRIES, swapped)] == [0, 1]
    unrelated = (TABLE_ENTRIES[3], *TABLE_ENTRIES[1:])
    with pytest.raises(probe.ProbeError, match="swapping two table entries"):
        probe.validate_table_swap(TABLE_ENTRIES, unrelated)


def test_table_destination_tamper_requires_a_distinct_case_body() -> None:
    tampered = list(TABLE_ENTRIES)
    tampered[3] = 0x3E0
    differences = probe.validate_table_destination_tamper(TABLE_ENTRIES, tampered, entry_index=3)
    assert [row["entry_index"] for row in differences] == [3]
    with pytest.raises(probe.ProbeError, match="destination tamper"):
        probe.validate_table_destination_tamper(TABLE_ENTRIES, tampered, entry_index=0)


def test_nonrelocated_tamper_requires_a_nonrelocated_site() -> None:
    original = list(FUNCTION_WORDS)
    tampered = list(FUNCTION_WORDS)
    tampered[0] ^= 1
    assert probe.validate_nonrelocated_tamper(original, tampered, word_index=0, relocation_sites={})[0]["address"] == "0x39c"
    with pytest.raises(probe.ProbeError, match="is relocated"):
        probe.validate_nonrelocated_tamper(
            original, tampered, word_index=0, relocation_sites={0: object()}
        )


# --------------------------------------------------------------- linked ELF checks


def test_linked_text_layout_and_table_section_are_validated() -> None:
    module = elf.parse(_linked_elf_bytes())
    assert probe.validate_linked_text_layout(module, label="test").addr == 0x39C
    assert probe.validate_table_section(module, table_address=0x4770, label="test").size == 0x18
    with pytest.raises(probe.ProbeError, match="rodata layout"):
        probe.validate_table_section(module, table_address=0x4774, label="test")


def test_linked_text_layout_rejects_a_wrong_address() -> None:
    module = elf.parse(_linked_elf_bytes())
    module._by_name = {
        **module._by_name,
        ".text": replace(module.require_section(".text"), addr=0x400),
    }
    with pytest.raises(probe.ProbeError, match=".text layout"):
        probe.validate_linked_text_layout(module, label="test")


def test_table_section_rejects_missing_and_short_rodata() -> None:
    without = elf.parse(_linked_elf_bytes(with_rodata=False))
    with pytest.raises(probe.ProbeError, match="has no .rodata section"):
        probe.validate_table_section(without, table_address=0x4770, label="test")
    short = elf.parse(_linked_elf_bytes(entries=(0, 0, 0)))
    with pytest.raises(probe.ProbeError, match="rodata layout"):
        probe.validate_table_section(short, table_address=0x4770, label="test")


def test_linked_structure_requires_one_executable_section_and_resolved_metadata() -> None:
    probe.validate_linked_structure(elf.parse(_linked_elf_bytes()), label="test")

    rogue = elf.parse(_linked_elf_bytes())
    rogue.sections = (
        *rogue.sections,
        replace(rogue.require_section(".text"), name=".text.rogue"),
    )
    with pytest.raises(probe.ProbeError, match="executable sections"):
        probe.validate_linked_structure(rogue, label="test")

    no_metadata = elf.parse(_linked_elf_bytes(with_metadata=False))
    with pytest.raises(probe.ProbeError, match="8-byte .mwcats"):
        probe.validate_linked_structure(no_metadata, label="test")

    bad_pointer = elf.parse(_linked_elf_bytes(metadata_pointer=0x400))
    with pytest.raises(probe.ProbeError, match="mwcats function pointer"):
        probe.validate_linked_structure(bad_pointer, label="test")


def test_linked_projection_matches_a_correct_linked_elf() -> None:
    linked = elf.parse(_linked_elf_bytes())
    projection = probe._linked_projection(
        FUNCTION_WORDS, TABLE_ENTRIES, linked, label="test", table_address=0x4770
    )
    assert projection["equal_words"] == 30
    assert projection["equal_entries"] == 6
    assert projection["hi16_lo16_effective_address"] == "0x4770"
    assert projection["hi16_lo16_reconstructs_table"] is True
    assert projection["call_target"] == "0x2364"
    assert projection["call_is_controlled_target"] is True


def test_linked_projection_reports_a_moved_rodata_layout() -> None:
    moved_words = list(FUNCTION_WORDS)
    moved_words[9] = _addiu(3, 3, 0x4774)
    linked = elf.parse(_linked_elf_bytes(text_words=moved_words, table_address=0x4774))
    projection = probe._linked_projection(
        FUNCTION_WORDS, TABLE_ENTRIES, linked, label="moved", table_address=0x4774
    )
    assert projection["equal_words"] == 29
    assert [row["word_index"] for row in projection["differences"]] == [9]
    assert projection["hi16_lo16_effective_address"] == "0x4774"


def test_link_has_no_unresolved_rejects_relocations_and_undefined_symbols() -> None:
    with pytest.raises(probe.ProbeError, match="unconsumed relocations"):
        probe.validate_link_has_no_unresolved(elf.parse(_candidate_object_bytes()))
    linked = elf.parse(_linked_elf_bytes())
    index = next(index for index, symbol in enumerate(linked.symbols) if symbol.name)
    undefined = replace(linked.symbols[index], shndx=elf.SHN_UNDEF)
    linked.symbols = (*linked.symbols[:index], undefined, *linked.symbols[index + 1 :])
    linked.relocations = ()
    with pytest.raises(probe.ProbeError, match="undefined symbols"):
        probe.validate_link_has_no_unresolved(linked)


def test_require_mips_elf_rejects_wrong_type_arch_and_endianness() -> None:
    module = elf.parse(_candidate_object_bytes())
    probe._require_mips_elf(module, file_type=ET_REL, label="synthetic ET_REL")
    with pytest.raises(probe.ProbeError, match="type"):
        probe._require_mips_elf(module, file_type=ET_EXEC, label="wrong type")
    wrong_endian = elf.parse(_candidate_object_bytes())
    wrong_endian.header = replace(wrong_endian.header, ei_data=2)
    with pytest.raises(probe.ProbeError, match="little-endian"):
        probe._require_mips_elf(wrong_endian, file_type=ET_REL, label="wrong endian")
    wrong_machine = elf.parse(_candidate_object_bytes())
    wrong_machine.header = replace(wrong_machine.header, e_machine=3)
    with pytest.raises(probe.ProbeError, match="not MIPS"):
        probe._require_mips_elf(wrong_machine, file_type=ET_REL, label="wrong machine")
    wrong_class = elf.parse(_candidate_object_bytes())
    wrong_class.header = replace(wrong_class.header, ei_class=2)
    with pytest.raises(probe.ProbeError, match="not ELF32"):
        probe._require_mips_elf(wrong_class, file_type=ET_REL, label="wrong class")


# ---------------------------------------------------------------- candidate object


def test_candidate_table_relocations_require_six_r_mips_32_in_order() -> None:
    module = elf.parse(_candidate_object_bytes())
    relocations = probe.candidate_table_relocations(module, symbol="func_0000039C")
    assert [relocation.section_offset for relocation in relocations] == [0, 4, 8, 12, 16, 20]
    assert {relocation.type for relocation in relocations} == {R_MIPS_32}
    assert {relocation.symbol for relocation in relocations} == {"func_0000039C"}
    section, _relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    assert section.name == ".rodata"
    assert words == OBJECT_OFFSETS


def _with_table_relocations(module, transform) -> elf.ElfFile:
    current = module.relocations_for(probe.TABLE_SECTION)
    module._relocations_by_target = {
        **module._relocations_by_target,
        probe.TABLE_SECTION: tuple(transform(current)),
    }
    return module


def test_candidate_table_relocations_reject_wrong_count_and_type() -> None:
    module = _with_table_relocations(elf.parse(_candidate_object_bytes()), lambda rels: [])
    with pytest.raises(probe.ProbeError, match="relocations, expected 6") as count_exc:
        probe.candidate_table_relocations(module, symbol="func_0000039C")
    assert count_exc.value.status == "UNSUPPORTED"

    other = _with_table_relocations(
        elf.parse(_candidate_object_bytes()),
        lambda rels: [replace(relocation, type=R_MIPS_26) for relocation in rels],
    )
    with pytest.raises(probe.ProbeError, match="expected R_MIPS_32") as type_exc:
        probe.candidate_table_relocations(other, symbol="func_0000039C")
    assert type_exc.value.status == "UNSUPPORTED"


def test_candidate_table_relocations_reject_unexpected_symbol() -> None:
    module = _with_table_relocations(
        elf.parse(_candidate_object_bytes()),
        lambda rels: [replace(relocation, symbol="func_00002364") for relocation in rels],
    )
    with pytest.raises(probe.ProbeError, match="expected 'func_0000039C'") as exc_info:
        probe.candidate_table_relocations(module, symbol="func_0000039C")
    assert exc_info.value.status == "UNSUPPORTED"


def test_candidate_table_requires_a_full_rodata_section() -> None:
    module = elf.parse(_candidate_object_bytes())
    module._by_name = {
        name: section for name, section in module._by_name.items() if name != ".rodata"
    }
    with pytest.raises(probe.ProbeError, match="no .rodata section"):
        probe.candidate_table_relocations(module, symbol="func_0000039C")

    short = elf.parse(_candidate_object_bytes())
    short._by_name = {
        **short._by_name,
        ".rodata": replace(short.require_section(".rodata"), size=0xC),
    }
    with pytest.raises(probe.ProbeError, match="size is 0xc"):
        probe.candidate_table_relocations(short, symbol="func_0000039C")


def test_validate_candidate_table_invariants_accepts_valid_divergence() -> None:
    module = elf.parse(_candidate_object_bytes(offsets=(0x38, 0x40, 0x48, 0x44, 0x58, 0x60)))
    _section, relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    addends = probe.validate_candidate_table_invariants(relocations, words)
    assert addends == (0x38, 0x40, 0x48, 0x44, 0x58, 0x60)


def test_validate_candidate_table_invariants_rejects_misaligned_addend() -> None:
    module = elf.parse(_candidate_object_bytes(offsets=(0x38, 0x40, 0x48, 0x41, 0x58, 0x60)))
    _section, relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    with pytest.raises(probe.ProbeError, match="outside aligned function code") as exc_info:
        probe.validate_candidate_table_invariants(relocations, words)
    assert exc_info.value.status == "FAIL"


def test_validate_candidate_table_invariants_rejects_out_of_bounds_addend() -> None:
    module = elf.parse(_candidate_object_bytes(offsets=(0x38, 0x40, 0x48, 0x78, 0x58, 0x60)))
    _section, relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    with pytest.raises(probe.ProbeError, match="outside aligned function code") as exc_info:
        probe.validate_candidate_table_invariants(relocations, words)
    assert exc_info.value.status == "FAIL"


def test_validate_candidate_table_invariants_rejects_word_disagreement() -> None:
    module = elf.parse(_candidate_object_bytes())
    _section, relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    tampered_words = list(words)
    tampered_words[3] = 0x44
    with pytest.raises(probe.ProbeError, match="table words disagree with relocation addends") as exc_info:
        probe.validate_candidate_table_invariants(relocations, tampered_words)
    assert exc_info.value.status == "FAIL"


def test_validate_candidate_table_invariants_rejects_invalid_relocation_addend() -> None:
    module = elf.parse(_candidate_object_bytes())
    _section, relocations, words = probe.candidate_table_entries(module, symbol="func_0000039C")
    invalid_relocations = list(relocations)
    invalid_relocations[3] = replace(invalid_relocations[3], addend_valid=False)
    with pytest.raises(probe.ProbeError, match="invalid table relocation addend") as exc_info:
        probe.validate_candidate_table_invariants(invalid_relocations, words)
    assert exc_info.value.status == "UNSUPPORTED"


# The relocation count/type/symbol is enforced upstream by candidate_table_relocations
# (see test_candidate_table_relocations_reject_wrong_count_and_type); the invariant
# helper assumes that validated list and does not repeat the count check.


# ------------------------------------------------------------- PSP relocation model


def _psp_module(*, segments, sections):
    return elf.parse(
        build_elf32(e_type=ET_MIPS_PSP_PRX, program_headers=segments, sections=sections)
    )


def test_psp_region_relocations_model_module_relative_r_mips_32() -> None:
    module = _psp_module(
        segments=[{"type": 1, "vaddr": 0, "filesz": 0, "memsz": 0x200}],
        sections=[
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0, "size": 0x78, "data": _u32_words(FUNCTION_WORDS)},
            {"name": ".data", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": 0x100, "size": 0x20, "data": b"\x00" * 0x20},
        ],
    )
    # No relocation section -> no sites; add the PSP table relocations explicitly.
    module = _psp_module(
        segments=[{"type": 1, "vaddr": 0, "filesz": 0, "memsz": 0x200}],
        sections=[
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0, "size": 0x78, "data": _u32_words(FUNCTION_WORDS)},
            {"name": ".data", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": 0x100, "size": 0x20, "data": b"\x00" * 0x20},
            {
                "name": ".rel.data",
                "type": SHT_MIPS_PSPREL,
                "data": b"".join(_psp_rel(0x108 + index * 4, R_MIPS_32) for index in range(6)),
                "entsize": 8,
            },
        ],
    )
    report = probe._psp_region_relocations(
        module, ".data", section_offset=0x8, size=0x18, words=TABLE_ENTRIES
    )
    relocations = report["relocations"]
    assert [row["type"] for row in relocations] == ["R_MIPS_32"] * 6
    assert [row["site"] for row in relocations] == [f"0x{0x108 + index * 4:x}" for index in range(6)]
    assert [row["module_relative_applied_word"] for row in relocations] == [
        f"0x{value:08x}" for value in TABLE_ENTRIES
    ]
    assert report["runtime_comparison"] == "NOT_DEMONSTRATED"


def test_psp_region_relocations_pair_hi16_lo16() -> None:
    module = _psp_module(
        segments=[{"type": 1, "vaddr": 0, "filesz": 0, "memsz": 0x200}],
        sections=[
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0, "size": 0x78, "data": _u32_words(FUNCTION_WORDS)},
            {
                "name": ".rel.text",
                "type": SHT_MIPS_PSPREL,
                "data": _psp_rel(2 * 4, R_MIPS_26) + _psp_rel(7 * 4, R_MIPS_HI16) + _psp_rel(9 * 4, R_MIPS_LO16),
                "entsize": 8,
            },
        ],
    )
    report = probe._psp_region_relocations(
        module, ".text", section_offset=0, size=0x78, words=FUNCTION_WORDS
    )
    relocations = {row["type"]: row for row in report["relocations"]}
    assert relocations["R_MIPS_HI16"]["module_relative_applied_word"] == "0x3c030000"
    assert relocations["R_MIPS_LO16"]["module_relative_applied_word"] == "0x24634770"
    assert relocations["R_MIPS_26"]["module_relative_applied_word"] == "0x0c0008d9"


# ------------------------------------------------------------------ physical checks


def test_linker_script_pins_layout_and_method() -> None:
    script = probe._linker_script(0x4770)
    assert '.text 0x39c : SUBALIGN(4) { *(.text) }' in script
    assert '.rodata 0x4770 : SUBALIGN(4) { *(.rodata) }' in script
    assert "ASSERT(SIZEOF(.rodata) == 0x18" in script
    assert "ASSERT(ADDR(.rodata) == 0x4770" in script
    assert ".mwcats 0 : SUBALIGN(4) { KEEP(*(.mwcats)) }" in script
    assert "ASSERT(SIZEOF(.mwcats) == 0x8" in script
    assert "stub" not in script.lower()


def test_report_classification_never_promotes_controlled_equality() -> None:
    report = probe._base_report()
    assert report["experiment_status"] == "FAIL"
    assert report["baseline"]["status"] == "INCONCLUSIVE"
    assert report["jump_table"]["layout_assignment"] == "CONTROLLED"
    assert report["independent_identity_proven"] is False
    assert report["promoted_to_matched"] is False


def _not_run_controls() -> dict[str, dict[str, object]]:
    # The exact shape run_experiment must record for the baseline-dependent
    # controls when artifact A does not equal the original (see not_run_controls).
    return {
        label: {
            "status": "NOT_RUN",
            "reason": "baseline comparison diverged",
            "detected": False,
            "promoted_to_matched": False,
        }
        for label in ("C", "D", "E")
    }


def test_not_run_controls_never_claims_a_baseline_dependent_control_passed() -> None:
    assert probe.not_run_controls() == _not_run_controls()
    for control in probe.not_run_controls().values():
        assert control["status"] == "NOT_RUN"
        assert control["detected"] is False
        assert control["promoted_to_matched"] is False


def _report_with(
    *,
    equal_words: int,
    equal_entries: int,
    controls: dict[str, dict[str, object]],
) -> dict[str, object]:
    report = probe._base_report()
    report["code"] = {
        "equal_words": equal_words,
        "total_words": 30,
        "differences": []
        if equal_words == 30
        else [{"word_index": 0, "address": "0x39c", "original": "0x27bdfff0", "linked": "0x27bdfff1"}],
    }
    report["jump_table"]["equal_entries"] = equal_entries
    report["jump_table"]["differences"] = (
        []
        if equal_entries == 6
        else [{"entry_index": 3, "original": "0x000003ec", "linked": "0x000003e0"}]
    )
    report["controls"] = controls
    return report


@pytest.mark.parametrize(
    ("equal_words", "equal_entries", "expected_status", "expected_exit"),
    [
        (30, 6, "PASS", 0),
        (29, 6, "DIVERGENCE", 3),
        (30, 5, "DIVERGENCE", 3),
        (29, 5, "DIVERGENCE", 3),
    ],
)
def test_finalize_classifies_valid_comparisons(
    equal_words, equal_entries, expected_status, expected_exit
) -> None:
    report = _report_with(equal_words=equal_words, equal_entries=equal_entries, controls={})
    exit_code = probe.finalize_experiment_report(report)
    assert exit_code == expected_exit
    assert report["experiment_status"] == expected_status
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["promoted_to_matched"] is False
    assert report["independent_identity_proven"] is False


def test_finalize_never_passes_when_counts_and_differences_disagree() -> None:
    # A false PASS must be impossible: if the word/entry counts read "equal" while the
    # difference lists are non-empty, the classification must fail conservatively.
    report = _report_with(equal_words=30, equal_entries=6, controls={})
    report["code"]["differences"] = [
        {"word_index": 0, "address": "0x39c", "original": "0x27bdfff0", "linked": "0x27bdfff1"}
    ]
    report["jump_table"]["differences"] = [
        {"entry_index": 3, "original": "0x000003ec", "linked": "0x000003e0"}
    ]
    exit_code = probe.finalize_experiment_report(report)
    assert exit_code == probe.DIVERGENCE_EXIT_CODE
    assert report["experiment_status"] == "DIVERGENCE"


@pytest.mark.parametrize(
    ("equal_words", "equal_entries", "expected_status", "expected_exit"),
    [
        (30, 6, "PASS", 0),
        (29, 6, "DIVERGENCE", 3),
        (30, 5, "DIVERGENCE", 3),
        (29, 5, "DIVERGENCE", 3),
    ],
)
def test_finalize_and_write_report_never_drops_divergence_evidence(
    tmp_path, monkeypatch, equal_words, equal_entries, expected_status, expected_exit
) -> None:
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    out = repo / "build/seto015/report.json"

    controls = (
        _not_run_controls()
        if expected_status != "PASS"
        else {label: {"detected": True, "promoted_to_matched": False} for label in ("C", "D", "E")}
    )
    report = _report_with(equal_words=equal_words, equal_entries=equal_entries, controls=controls)
    exit_code = probe.finalize_experiment_report(report)
    probe._write_report(out, report)

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["experiment_status"] == expected_status
    assert written["equivalence_claim"] == probe.equivalence_claim(equal_words, equal_entries)
    assert written["original_match_status"] == "INCONCLUSIVE"
    assert written["promoted_to_matched"] is False
    assert written["independent_identity_proven"] is False
    assert exit_code == expected_exit == (0 if expected_status == "PASS" else probe.DIVERGENCE_EXIT_CODE)
    # All 30 words and all 6 entries are preserved, with the exact differences.
    assert written["code"]["equal_words"] == equal_words
    assert len(written["code"]["differences"]) == 30 - equal_words
    assert written["jump_table"]["equal_entries"] == equal_entries
    assert len(written["jump_table"]["differences"]) == 6 - equal_entries
    assert written["controls"] == controls


def test_invalid_layout_is_not_reported_as_a_divergence() -> None:
    # Structural integrity failures keep failing immediately as ProbeError; they are
    # never converted into the DIVERGENCE classification of a valid comparison.
    with pytest.raises(probe.ProbeError) as unsupported:
        probe.validate_table_section(
            elf.parse(_linked_elf_bytes(with_rodata=False)), table_address=0x4770, label="test"
        )
    assert unsupported.value.status == "UNSUPPORTED"
    with pytest.raises(probe.ProbeError) as failed:
        probe.validate_linked_structure(
            elf.parse(_linked_elf_bytes(with_metadata=False)), label="test"
        )
    assert failed.value.status == "FAIL"


def test_divergence_exit_code_matches_the_repository_mismatch_convention() -> None:
    from seto.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_INCONCLUSIVE, EXIT_MISMATCH, EXIT_OK

    assert probe.DIVERGENCE_EXIT_CODE == EXIT_MISMATCH == 3
    assert probe.DIVERGENCE_EXIT_CODE not in (EXIT_OK, EXIT_ERROR, EXIT_BLOCKED, EXIT_INCONCLUSIVE)


def test_canonical_json_is_stable_and_sorted() -> None:
    assert probe.canonical_json({"z": [1, 2], "a": {"b": True}}) == probe.canonical_json(
        {"a": {"b": True}, "z": [1, 2]}
    )
    assert probe.canonical_json({"a": 1}).endswith("\n")


def test_recorded_hash_and_saved_match_record_are_checked() -> None:
    probe.validate_recorded_hash("object", "a" * 64, "a" * 64)
    with pytest.raises(probe.ProbeError, match="SHA-256"):
        probe.validate_recorded_hash("object", "a" * 64, "b" * 64)
    stdout = {"function": "func_0000039C", "status": "INCONCLUSIVE", "provenance": {"object_sha256": "b" * 64}}
    saved = dict(stdout)
    probe.validate_saved_match_record(stdout, saved)
    with pytest.raises(probe.ProbeError, match="persisted match_function record"):
        probe.validate_saved_match_record(stdout, {**saved, "status": "MATCHED"})


def test_input_path_cannot_escape_the_seto015_build_tree() -> None:
    root = (REPO_ROOT / "build/seto015").resolve()
    with pytest.raises(probe.ProbeError, match="escapes allowed tree"):
        probe._repo_path(Path("../../private/original/module.prx"), allowed_root=root)


def test_validate_arguments_rejects_an_out_path_outside_the_seto015_tree() -> None:
    arguments = probe.build_parser().parse_args(["--out", "build/seto015-escape/report.json"])
    with pytest.raises(probe.ProbeError, match="escapes allowed tree"):
        probe._validate_arguments(arguments)


def test_main_never_writes_an_out_path_outside_the_tree(capsys) -> None:
    escaped = REPO_ROOT / "build/seto015-escape-report.json"
    assert not escaped.exists()
    exit_code = probe.main(["--out", escaped.relative_to(REPO_ROOT).as_posix()])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert "escapes allowed tree" in captured.err
    assert "PASS" not in captured.out
    assert not escaped.exists()


def test_validated_build_root_accepts_real_and_missing_directories_without_creating_them(
    tmp_path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    assert probe._validated_build_root() == (repo / "build/seto015").resolve()
    assert not (repo / "build").exists()
    (repo / "build").mkdir()
    assert probe._validated_build_root() == (repo / "build/seto015").resolve()
    assert not (repo / "build/seto015").exists()


@pytest.mark.parametrize("component", ["build", "seto015"])
def test_validated_build_root_rejects_regular_files(tmp_path, monkeypatch, component) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    path = repo / "build"
    if component == "seto015":
        path.mkdir()
        path = path / "seto015"
    path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(probe.ProbeError, match="build path is not a directory"):
        probe._validated_build_root()


def _create_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")


@pytest.mark.parametrize("component", ["build", "seto015"])
@pytest.mark.parametrize("broken", [False, True], ids=["external", "broken"])
def test_validated_build_root_rejects_symlinks_before_resolve(tmp_path, monkeypatch, component, broken) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    if not broken:
        outside.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    link = repo / "build"
    if component == "seto015":
        link.mkdir()
        link = link / "seto015"
    target = outside / "does-not-exist" if broken else outside
    _create_symlink_or_skip(link, target)
    with pytest.raises(probe.ProbeError, match="build directory must not be a symlink"):
        probe._validated_build_root()


def test_readelf_output_write_rejects_preexisting_file_symlinks(tmp_path) -> None:
    repo = tmp_path / "repo"
    build_root = repo / "build" / "seto015"
    logs = build_root / "logs"
    outside = tmp_path / "outside"
    logs.mkdir(parents=True)
    outside.mkdir()
    sentinel = outside / "case-a.readelf.txt"
    sentinel.write_text("sentinel", encoding="utf-8")
    log_path = logs / "case-a.readelf.txt"
    try:
        log_path.symlink_to(sentinel)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local file symlink creation: {exc}")

    with pytest.raises(probe.ProbeError, match="build output may not be a symlink"):
        probe._write_build_text(log_path, "would overwrite", build_root.resolve())
    assert sentinel.read_text(encoding="utf-8") == "sentinel"


def test_invalid_build_root_never_writes_report_to_symlink_target(tmp_path, monkeypatch, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    monkeypatch.chdir(repo)
    _create_symlink_or_skip(repo / "build", outside)

    exit_code = probe.main([])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert "build directory must not be a symlink" in captured.err
    assert "PASS" not in captured.out
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]


def _setup_synthetic_experiment_env(tmp_path, monkeypatch, *, candidate_offsets, linked_entries_a=None):
    repo = tmp_path / "repo"
    (repo / "build/seto015").mkdir(parents=True)
    (repo / "decomp/src").mkdir(parents=True)
    (repo / "config/wsl").mkdir(parents=True)
    (repo / "private/original/PSP_GAME/USRDIR/gmodule").mkdir(parents=True)

    source_path = repo / "decomp/src/func_0000039C.c"
    source_path.write_text("// dummy source\n", encoding="utf-8")
    config_path = repo / "config/wsl/seto.toml"
    config_path.write_text("[tools]\n", encoding="utf-8")

    prx_path = repo / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"
    prx_bytes = build_elf32(
        e_type=ET_MIPS_PSP_PRX,
        sections=[
            {
                "name": ".text",
                "type": SHT_PROGBITS,
                "flags": SHF_ALLOC | SHF_EXECINSTR,
                "addr": 0x39C,
                "size": 0x78,
                "data": _u32_words(FUNCTION_WORDS),
            },
        ],
    )
    prx_path.write_bytes(prx_bytes)

    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    # The synthetic experiment never runs the real GNU MIPSel tools; stub only the
    # availability gate so the flow reaches the linker/compare stage.
    monkeypatch.setattr(probe.shutil, "which", lambda name: f"/usr/bin/{name}")

    candidate_bytes = _candidate_object_bytes(offsets=candidate_offsets)

    def fake_run(argv, *, cwd=None, timeout=300, env=None):
        if "scripts/match_function.py" in argv:
            candidate_dir = repo / "build/seto015/experiment/candidate"
            candidate_dir.mkdir(parents=True, exist_ok=True)
            candidate_path = candidate_dir / f"{source_path.stem}.o"
            candidate_path.write_bytes(candidate_bytes)

            match_record_path = candidate_dir / "match-record.json"
            record = {
                "function": "func_0000039C",
                "address": "0x39c",
                "section": ".text",
                "status": "INCONCLUSIVE",
                "match": {
                    "status": "INCONCLUSIVE",
                    "matching_words": 28,
                    "total_words": 30,
                    "difference_count": 0,
                    "relocation_issues": [],
                },
                "provenance": {
                    "source": probe._relative(source_path),
                    "object": probe._relative(candidate_path),
                    "object_sha256": probe.sha256_file(candidate_path),
                    "source_sha256": probe.sha256_file(source_path),
                    "flags": ["-O4,p", "-sdatathreshold", "0"],
                },
            }
            match_record_path.write_text(
                json.dumps({key: value for key, value in record.items() if key != "match"}),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=argv, returncode=5, stdout=json.dumps(record), stderr="")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="fake", stderr="")

    monkeypatch.setattr(probe, "_run", fake_run)
    monkeypatch.setattr(
        probe,
        "_toolchain_versions",
        lambda config_path, logs_dir, build_root, env: ("GNU ld 2.40", "mwccpsp 3.0.1", "wibo 0.4.0"),
    )
    monkeypatch.setattr(
        probe,
        "_original_table_evidence",
        lambda module, words: {
            "section": ".data",
            "offset": "0x8",
            "address": "0x4770",
            "entries": [f"0x{value:08x}" for value in TABLE_ENTRIES],
            "entries_match_recorded_baseline": True,
            "size": 24,
        },
    )
    monkeypatch.setattr(
        probe,
        "_original_call_evidence",
        lambda module: {
            "call_index": 2,
            "site": "0x3a4",
            "target": "0x2364",
            "symbol": "func_00002364",
        },
    )
    monkeypatch.setattr(
        probe,
        "_psp_region_relocations",
        lambda module, section_name, *, section_offset, size, words: {
            "section": section_name,
            "coordinate_system": "model",
            "load_base_zero_is_model_only": True,
            "relocations": [],
            "runtime_comparison": "NOT_DEMONSTRATED",
        },
    )

    def fake_link(*, object_path, script_path, output_path, table_address, call_target, logs_dir, label):
        # Faithful mini-linker: place the object's own .text (patching the HI16/LO16
        # destination word for the assigned .rodata address) and resolve the table's
        # R_MIPS_32 addends over the positioned function, so the controls that tamper
        # the object are reflected in the linked output.
        module = elf.parse(object_path)
        text_words = list(
            mips.decode_words(module.section_data(module.require_section(".text")), "candidate text")
        )
        text_words[9] = (text_words[9] & 0xFFFF0000) | (table_address & 0xFFFF)
        _section, relocations, _words = probe.candidate_table_entries(module, symbol=probe.FUNCTION_NAME)
        resolved = tuple(
            probe.FUNCTION_ADDRESS + (relocation.addend & 0xFFFFFFFF) for relocation in relocations
        )
        entries = tuple(linked_entries_a) if linked_entries_a is not None else resolved
        output_path.write_bytes(
            _linked_elf_bytes(text_words=text_words, entries=entries, table_address=table_address)
        )
        linked = elf.parse(output_path)
        build_root = probe._validated_build_root()
        probe._write_build_text(logs_dir / f"{label}.readelf.txt", "readelf", build_root)
        probe._write_build_text(logs_dir / f"{label}.objdump.txt", "objdump", build_root)
        probe._write_build_text(logs_dir / f"{label}.file.txt", "file", build_root)
        return linked, {"argv": ["mipsel-linux-gnu-ld"], "returncode": 0}

    monkeypatch.setattr(probe, "_link", fake_link)

    out_path = repo / "build/seto015/jump-table-equivalence.json"
    arguments = probe.build_parser().parse_args([
        "--prx", str(prx_path),
        "--source", str(source_path),
        "--config", str(config_path),
        "--out", str(out_path),
    ])
    return arguments, out_path


def test_run_experiment_reports_valid_divergence(tmp_path, monkeypatch) -> None:
    # The synthetic linker derives the linked table from the object's own addends.
    divergent_offsets = (0x38, 0x40, 0x48, 0x44, 0x58, 0x60)
    arguments, out_path = _setup_synthetic_experiment_env(
        tmp_path, monkeypatch, candidate_offsets=divergent_offsets
    )

    exit_code, report = probe.run_experiment(arguments)

    assert exit_code == 3
    assert report["experiment_status"] == "DIVERGENCE"
    assert report["equivalence_claim"] == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["promoted_to_matched"] is False
    assert report["independent_identity_proven"] is False

    # Code words: 30/30 equal, zero differences
    assert report["code"]["equal_words"] == 30
    assert report["code"]["total_words"] == 30
    assert report["code"]["differences"] == []

    # Table entries: 5/6 equal, difference at entry 3
    assert report["jump_table"]["equal_entries"] == 5
    assert report["jump_table"]["entry_count"] == 6
    assert report["jump_table"]["differences"] == [
        {"entry_index": 3, "original": "0x000003ec", "linked": "0x000003e0"}
    ]

    # Entry destinations: entry 3 inside_function=True, matches_expected_case=False
    destinations = report["linker"]["variants"]["A"]["entry_destinations"]
    assert destinations[3] == {
        "entry_index": 3,
        "address": "0x3e0",
        "expected_case_address": "0x3ec",
        "inside_function": True,
        "matches_expected_case": False,
    }

    # Controls C, D, E are recorded as NOT_RUN
    assert report["controls"]["C"] == {
        "status": "NOT_RUN",
        "reason": "baseline comparison diverged",
        "detected": False,
        "promoted_to_matched": False,
    }
    assert report["controls"]["D"]["status"] == "NOT_RUN"
    assert report["controls"]["E"]["status"] == "NOT_RUN"

    # Only controls that actually ran are advertised: B (layout) is always validated,
    # while the NOT_RUN C/D/E placeholders must not be claimed as false-positive evidence.
    assert report["code"]["false_positive_controls"] == []
    assert report["jump_table"]["false_positive_controls"] == ["B"]

    # Report was written to disk
    assert out_path.is_file()
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["experiment_status"] == "DIVERGENCE"
    assert written["jump_table"]["differences"] == report["jump_table"]["differences"]


def test_run_experiment_rejects_linker_resolution_disagreeing_with_addends(tmp_path, monkeypatch) -> None:
    divergent_offsets = (0x38, 0x40, 0x48, 0x44, 0x58, 0x60)
    # Linked entries have 0x3EC at index 3 instead of resolving candidate addend 0x44 (which would be 0x3E0)
    disagreeing_linked_entries = TABLE_ENTRIES
    arguments, _out_path = _setup_synthetic_experiment_env(
        tmp_path, monkeypatch, candidate_offsets=divergent_offsets, linked_entries_a=disagreeing_linked_entries
    )

    with pytest.raises(probe.ProbeError, match="linked table differs from candidate relocation resolution") as exc_info:
        probe.run_experiment(arguments)
    assert exc_info.value.status == "FAIL"


def test_run_experiment_reports_pass_for_matching_baseline(tmp_path, monkeypatch) -> None:
    # The recorded baseline still yields PASS with the controls preserved.
    arguments, out_path = _setup_synthetic_experiment_env(
        tmp_path, monkeypatch, candidate_offsets=OBJECT_OFFSETS
    )

    exit_code, report = probe.run_experiment(arguments)

    assert exit_code == 0
    assert report["experiment_status"] == "PASS"
    assert report["equivalence_claim"] == "ASSUMPTION_DEPENDENT"
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["promoted_to_matched"] is False
    assert report["independent_identity_proven"] is False
    assert report["code"]["equal_words"] == 30
    assert report["code"]["differences"] == []
    assert report["jump_table"]["equal_entries"] == 6
    assert report["jump_table"]["differences"] == []
    # Controls are exercised on the equal baseline, and only executed controls are advertised.
    assert report["controls"]["C"]["detected"] is True
    assert report["controls"]["D"]["detected"] is True
    assert report["controls"]["E"]["detected"] is True
    assert report["code"]["false_positive_controls"] == ["E"]
    assert report["jump_table"]["false_positive_controls"] == ["B", "C", "D"]
    assert report["linker"]["variants"]["B"]["hi16_lo16_effective_address"] == "0x4774"
    assert out_path.is_file()
    assert json.loads(out_path.read_text(encoding="utf-8"))["experiment_status"] == "PASS"


def test_run_experiment_preserves_multiple_valid_divergences(tmp_path, monkeypatch) -> None:
    # Two valid divergent entries (3 and 5) must both survive into the report.
    divergent_offsets = (0x38, 0x40, 0x48, 0x44, 0x58, 0x68)
    arguments, _out_path = _setup_synthetic_experiment_env(
        tmp_path, monkeypatch, candidate_offsets=divergent_offsets
    )

    exit_code, report = probe.run_experiment(arguments)

    assert exit_code == 3
    assert report["experiment_status"] == "DIVERGENCE"
    assert report["code"]["equal_words"] == 30
    assert report["jump_table"]["equal_entries"] == 4
    assert report["jump_table"]["differences"] == [
        {"entry_index": 3, "original": "0x000003ec", "linked": "0x000003e0"},
        {"entry_index": 5, "original": "0x000003fc", "linked": "0x00000404"},
    ]
    assert report["code"]["false_positive_controls"] == []
    assert report["jump_table"]["false_positive_controls"] == ["B"]
