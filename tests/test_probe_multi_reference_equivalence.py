"""Pure unit and regression tests for SETO-DECOMP-016 (func_00000414).

Every fixture is synthetic: no private PRX, no Metrowerks compiler, no external
linker.  Covers the 41-word code comparison, 7-entry jump table, 5 HI16/LO16
pairs (including shared D_000047D0 at 21->24 and 33->36), 5 R_MIPS_26 calls,
3 .data strings, negative controls A-E, conservative classification, and
build/seto016 path confinement.
"""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

import pytest

from seto import datarefs, elf, mips
from seto.binio import ParseError

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "probe_multi_reference_equivalence.py"
SPEC = importlib.util.spec_from_file_location("seto_probe_multi_reference_equivalence", SCRIPT)
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

# Linked/PRX instruction words for func_00000414 (.text[0x414:0x4b8), 41 words).
LINKED_WORDS = (
    0x27BDFFF0, 0xAFBF000C, 0xAFB00008, 0x0C0008D5, 0x00808021,
    0x2C410007, 0x1020001A, 0x00000000, 0x3C030000, 0x00021080,
    0x24634788, 0x00431021, 0x8C420000, 0x00400008, 0x00000000,
    0x3C050000, 0x02002021, 0x0C000229, 0x24A547A4, 0x10000012,
    0x8FBF000C, 0x3C050000, 0x02002021, 0x0C000229, 0x24A547D0,
    0x1000000B, 0x00000000, 0x3C050000, 0x02002021, 0x0C000229,
    0x24A54800, 0x10000005, 0x00000000, 0x3C050000, 0x02002021,
    0x0C000229, 0x24A547D0, 0x8FBF000C, 0x8FB00008, 0x03E00008,
    0x27BD0010,
)

# Unlinked candidate .text words (zero in-place addends at relocated words).
CANDIDATE_WORDS = (
    0x27BDFFF0, 0xAFBF000C, 0xAFB00008, 0x0C000000, 0x00808021,
    0x2C410007, 0x1020001A, 0x00000000, 0x3C030000, 0x00021080,
    0x24630000, 0x00431021, 0x8C420000, 0x00400008, 0x00000000,
    0x3C050000, 0x02002021, 0x0C000000, 0x24A50000, 0x10000012,
    0x8FBF000C, 0x3C050000, 0x02002021, 0x0C000000, 0x24A50000,
    0x1000000B, 0x00000000, 0x3C050000, 0x02002021, 0x0C000000,
    0x24A50000, 0x10000005, 0x00000000, 0x3C050000, 0x02002021,
    0x0C000000, 0x24A50000, 0x8FBF000C, 0x8FB00008, 0x03E00008,
    0x27BD0010,
)

TABLE_ENTRIES = (0x450, 0x468, 0x480, 0x480, 0x480, 0x480, 0x480)
OBJECT_OFFSETS = (0x3C, 0x54, 0x6C, 0x6C, 0x6C, 0x6C, 0x6C)


def _u32_words(values: Sequence[int]) -> bytes:
    return b"".join(word(value) for value in values)


def _lui(register: int, immediate: int) -> int:
    return (0x0F << 26) | (register << 16) | (immediate & 0xFFFF)


def _addiu(target: int, source: int, immediate: int) -> int:
    return (0x09 << 26) | (source << 21) | (target << 16) | (immediate & 0xFFFF)


def _psp_rel(offset: int, rel_type: int) -> bytes:
    return struct.pack("<II", offset, rel_type)


def _candidate_object_bytes(
    *,
    text_words: Sequence[int] = CANDIDATE_WORDS,
    offsets: Sequence[int] = OBJECT_OFFSETS,
    table_words: Sequence[int] | None = None,
    with_mwcats: bool = True,
    extra_undef_symbol: str | None = None,
    table_symbol_name: str = "@15",
) -> bytes:
    symbols = [
        {"name": "", "value": 0, "size": 0, "info": 0, "shndx": 0},
        {"name": table_symbol_name, "value": 0, "size": 28, "info": 0x01, "shndx": 3},
        {"name": "func_00000414", "value": 0, "size": 0xA4, "info": 0x12, "shndx": 1},
        {"name": "func_00002354", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
        {"name": "func_000008A4", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
        {"name": "D_000047A4", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
        {"name": "D_000047D0", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
        {"name": "D_00004800", "value": 0, "size": 0, "info": 0x10, "shndx": 0},
    ]
    if extra_undef_symbol is not None:
        symbols.append({"name": extra_undef_symbol, "value": 0, "size": 0, "info": 0x10, "shndx": 0})
    symtab, strtab = build_symbols(symbols)

    text = _u32_words(text_words)
    actual_words = tuple(offsets if table_words is None else table_words)
    table = _u32_words(actual_words)
    # Symbol indices: 1=@15, 2=func_00000414, 3=func_00002354, 4=func_000008A4,
    # 5=D_000047A4, 6=D_000047D0, 7=D_00004800
    text_rels = build_relocations(
        [
            (3 * 4, R_MIPS_26, 3),
            (8 * 4, R_MIPS_HI16, 1),
            (10 * 4, R_MIPS_LO16, 1),
            (15 * 4, R_MIPS_HI16, 5),
            (17 * 4, R_MIPS_26, 4),
            (18 * 4, R_MIPS_LO16, 5),
            (21 * 4, R_MIPS_HI16, 6),
            (23 * 4, R_MIPS_26, 4),
            (24 * 4, R_MIPS_LO16, 6),
            (27 * 4, R_MIPS_HI16, 7),
            (29 * 4, R_MIPS_26, 4),
            (30 * 4, R_MIPS_LO16, 7),
            (33 * 4, R_MIPS_HI16, 6),
            (35 * 4, R_MIPS_26, 4),
            (36 * 4, R_MIPS_LO16, 6),
        ]
    )
    table_rels = build_relocations([(index * 4, R_MIPS_32, 2) for index in range(len(offsets))])
    symtab_link = 6 if with_mwcats else 5
    sections: list[dict[str, object]] = [
        {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0, "size": len(text), "data": text},
        {"name": ".rel.text", "type": SHT_REL, "data": text_rels, "link": symtab_link, "info": 1, "entsize": 8},
        {"name": ".rodata", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": 0, "size": len(table), "data": table},
        {"name": ".rel.rodata", "type": SHT_REL, "data": table_rels, "link": symtab_link, "info": 3, "entsize": 8},
    ]
    if with_mwcats:
        sections.append(
            {"name": ".mwcats", "type": SHT_PROGBITS, "data": struct.pack("<II", 0x00A40002, 0)}
        )
    symtab_index = len(sections) + 1
    strtab_index = symtab_index + 1
    sections.append(
        {"name": ".symtab", "type": SHT_SYMTAB, "data": symtab, "link": strtab_index, "info": 2, "entsize": 16}
    )
    sections.append({"name": ".strtab", "type": SHT_STRTAB, "data": strtab, "align": 1})
    return build_elf32(sections=sections)


def _linked_elf_bytes(
    *,
    text_words: Sequence[int] = LINKED_WORDS,
    entries: Sequence[int] = TABLE_ENTRIES,
    table_address: int = 0x4788,
    controlled_symbols: dict[str, int] | None = None,
    metadata_pointer: int = 0x414,
    with_rodata: bool = True,
    with_metadata: bool = True,
) -> bytes:
    assigned = dict(probe.CONTROLLED_SYMBOLS if controlled_symbols is None else controlled_symbols)
    text = _u32_words(text_words)
    table = _u32_words(entries)
    sym_rows = [
        {"name": "", "value": 0, "size": 0, "info": 0, "shndx": 0},
        {"name": "func_00000414", "value": 0x414, "size": 0xA4, "info": 0x12, "shndx": 1},
    ]
    for name, value in sorted(assigned.items()):
        sym_rows.append(
            {"name": name, "value": value, "size": 0, "info": 0x10, "shndx": elf.SHN_ABS}
        )
    symtab, strtab = build_symbols(sym_rows)
    sections: list[dict[str, object]] = [
        {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR, "addr": 0x414, "size": len(text), "data": text}
    ]
    if with_rodata:
        sections.append(
            {"name": ".rodata", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "addr": table_address, "size": len(table), "data": table}
        )
    if with_metadata:
        sections.append(
            {"name": ".mwcats", "type": SHT_PROGBITS, "data": struct.pack("<II", 0x00A40002, metadata_pointer)}
        )
    strtab_index = len(sections) + 2
    sections.append(
        {"name": ".symtab", "type": SHT_SYMTAB, "data": symtab, "link": strtab_index, "info": 1, "entsize": 16}
    )
    sections.append({"name": ".strtab", "type": SHT_STRTAB, "data": strtab, "align": 1})
    return build_elf32(e_type=ET_EXEC, sections=sections)


# ------------------------------------ 1. Candidate relocation & symbol inventory


def test_candidate_text_and_table_inventory_validates_all_relocations() -> None:
    module = elf.parse(_candidate_object_bytes())
    sites, pairing = probe.validate_candidate_text_inventory(module, CANDIDATE_WORDS)
    assert len(sites.sites) == 15
    assert pairing.hi_to_lo == {8: 10, 15: 18, 21: 24, 27: 30, 33: 36}
    assert not pairing.limitations

    section, relocations, words = probe.candidate_table_entries(module)
    assert section.name == ".rodata"
    assert len(relocations) == 7
    assert [rel.section_offset for rel in relocations] == [0, 4, 8, 12, 16, 20, 24]
    assert {rel.type for rel in relocations} == {R_MIPS_32}
    assert {rel.symbol for rel in relocations} == {"func_00000414"}
    assert probe.validate_candidate_table_invariants(relocations, words) == OBJECT_OFFSETS


def test_candidate_inventory_rejects_unexpected_or_missing_symbols() -> None:
    extra = elf.parse(_candidate_object_bytes(extra_undef_symbol="unexpected_sym"))
    with pytest.raises(probe.ProbeError, match="candidate undefined symbols") as exc_info:
        probe.validate_candidate_symbols(extra)
    assert exc_info.value.status == "FAIL"

    wrong_table_sym = elf.parse(_candidate_object_bytes(table_symbol_name="@13"))
    with pytest.raises(probe.ProbeError, match="does not define @15") as tbl_exc:
        probe.validate_candidate_symbols(wrong_table_sym)
    assert tbl_exc.value.status == "UNSUPPORTED"


def test_candidate_text_inventory_rejects_missing_relocations_or_wrong_shared_symbol() -> None:
    module = elf.parse(_candidate_object_bytes())
    rels = list(module.relocations_for(".text"))
    # Drop one of the 15 .text relocations
    module._relocations_by_target = {**module._relocations_by_target, ".text": tuple(rels[:-1])}
    with pytest.raises(probe.ProbeError, match="relocation inventory differs") as exc_info:
        probe.validate_candidate_text_inventory(module, CANDIDATE_WORDS)
    assert exc_info.value.status == "UNSUPPORTED"

    # Change shared symbol at 33->36 from D_000047D0 to D_00004800
    wrong_sym_module = elf.parse(_candidate_object_bytes())
    mutated_rels = [
        replace(rel, symbol="D_00004800") if rel.section_offset in (33 * 4, 36 * 4) else rel
        for rel in wrong_sym_module.relocations_for(".text")
    ]
    wrong_sym_module._relocations_by_target = {
        **wrong_sym_module._relocations_by_target,
        ".text": tuple(mutated_rels),
    }
    with pytest.raises(probe.ProbeError, match="relocation inventory differs"):
        probe.validate_candidate_text_inventory(wrong_sym_module, CANDIDATE_WORDS)


def test_candidate_text_inventory_rejects_nonzero_inplace_addends_and_broken_pairing() -> None:
    non_zero_words = list(CANDIDATE_WORDS)
    non_zero_words[24] = _addiu(5, 5, 4)
    module = elf.parse(_candidate_object_bytes(text_words=non_zero_words))
    with pytest.raises(probe.ProbeError, match="zero in-place addends") as exc_info:
        probe.validate_candidate_text_inventory(module, non_zero_words)
    assert exc_info.value.status == "UNSUPPORTED"

    broken_words = list(CANDIDATE_WORDS)
    broken_words[8] = 0x00000000  # Not a LUI -> breaks HI16/LO16 pairing
    broken_module = elf.parse(_candidate_object_bytes(text_words=broken_words))
    with pytest.raises(probe.ProbeError, match="HI16/LO16") as pair_exc:
        probe.validate_candidate_text_inventory(broken_module, broken_words)
    assert pair_exc.value.status == "UNSUPPORTED"


# ------------------------------ 2. Jump table validation, comparison & invariants


def test_compare_word_sequences_and_table_entries_enforce_sizes_and_detect_diffs() -> None:
    assert probe.compare_word_sequences(LINKED_WORDS, LINKED_WORDS) == []
    with pytest.raises(ParseError, match="expected 41 words"):
        probe.compare_word_sequences(LINKED_WORDS[:-1], LINKED_WORDS)

    assert probe.compare_table_entries(TABLE_ENTRIES, TABLE_ENTRIES) == []
    with pytest.raises(ParseError, match="expected 7 table entries"):
        probe.compare_table_entries(TABLE_ENTRIES[:-1], TABLE_ENTRIES)

    swapped = (TABLE_ENTRIES[1], TABLE_ENTRIES[0], *TABLE_ENTRIES[2:])
    assert probe.compare_table_entries(TABLE_ENTRIES, swapped) == [
        {"entry_index": 0, "original": "0x00000450", "linked": "0x00000468"},
        {"entry_index": 1, "original": "0x00000468", "linked": "0x00000450"},
    ]


def test_validate_structural_destinations_and_entry_rows() -> None:
    rows = probe.entry_destination_rows(TABLE_ENTRIES)
    assert len(rows) == 7
    assert all(row["inside_function"] and row["aligned"] and row["matches_expected_case"] for row in rows)
    assert rows[0]["function_relative_offset"] == "0x3c"
    probe.validate_structural_destinations(TABLE_ENTRIES)

    # Valid in-function divergence passes structural validation
    divergent = list(TABLE_ENTRIES)
    divergent[2] = 0x454
    probe.validate_structural_destinations(divergent)
    div_rows = probe.entry_destination_rows(divergent)
    assert div_rows[2]["inside_function"] is True
    assert div_rows[2]["matches_expected_case"] is False

    for bad_addr in (0x451, 0x410, 0x4B8):
        invalid = list(TABLE_ENTRIES)
        invalid[2] = bad_addr
        with pytest.raises(probe.ProbeError, match="outside aligned function code") as exc_info:
            probe.validate_structural_destinations(invalid)
        assert exc_info.value.status == "FAIL"


def test_candidate_table_relocations_and_invariants_reject_faults() -> None:
    base = elf.parse(_candidate_object_bytes())
    # Missing .rodata
    no_rodata = elf.parse(_candidate_object_bytes())
    no_rodata._by_name = {k: v for k, v in no_rodata._by_name.items() if k != ".rodata"}
    with pytest.raises(probe.ProbeError, match="has no .rodata section"):
        probe.candidate_table_relocations(no_rodata)

    # Short .rodata
    short_rodata = elf.parse(_candidate_object_bytes())
    short_rodata._by_name = {
        **short_rodata._by_name,
        ".rodata": replace(short_rodata.require_section(".rodata"), size=0x18),
    }
    with pytest.raises(probe.ProbeError, match="size is 0x18, expected 0x1c"):
        probe.candidate_table_relocations(short_rodata)

    # Wrong relocation type and wrong symbol
    wrong_type = elf.parse(_candidate_object_bytes())
    wrong_type._relocations_by_target = {
        **wrong_type._relocations_by_target,
        ".rodata": tuple(replace(r, type=R_MIPS_26) for r in base.relocations_for(".rodata")),
    }
    with pytest.raises(probe.ProbeError, match="expected R_MIPS_32"):
        probe.candidate_table_relocations(wrong_type)

    wrong_sym = elf.parse(_candidate_object_bytes())
    wrong_sym._relocations_by_target = {
        **wrong_sym._relocations_by_target,
        ".rodata": tuple(replace(r, symbol="func_000008A4") for r in base.relocations_for(".rodata")),
    }
    with pytest.raises(probe.ProbeError, match="expected 'func_00000414'"):
        probe.candidate_table_relocations(wrong_sym)

    # Invariants: misaligned addend, out-of-bounds addend, word disagreement, invalid addend
    for bad_offset in (0x3D, 0xA4):
        bad_mod = elf.parse(
            _candidate_object_bytes(offsets=(bad_offset, *OBJECT_OFFSETS[1:]))
        )
        _sec, rels, words = probe.candidate_table_entries(bad_mod)
        with pytest.raises(probe.ProbeError, match="outside aligned function code") as exc_info:
            probe.validate_candidate_table_invariants(rels, words)
        assert exc_info.value.status == "FAIL"

    _sec, rels, words = probe.candidate_table_entries(base)
    with pytest.raises(probe.ProbeError, match="table words disagree"):
        probe.validate_candidate_table_invariants(rels, (0x54, *words[1:]))
    with pytest.raises(probe.ProbeError, match="invalid table relocation addend") as inv_exc:
        probe.validate_candidate_table_invariants(
            (replace(rels[0], addend_valid=False), *rels[1:]), words
        )
    assert inv_exc.value.status == "UNSUPPORTED"


# ---------------- 3. HI16/LO16 pairs, R_MIPS_26 calls & PRX string evidence


def test_reconstruct_and_validate_hi16_lo16_pairs_and_shared_d_000047d0() -> None:
    targets = {probe.TABLE_SYMBOL: 0x4788, **probe.CONTROLLED_SYMBOLS}
    rows = probe.reconstruct_hi16_lo16_pairs(LINKED_WORDS, LINKED_WORDS, assigned_targets=targets)
    probe.validate_hi16_lo16_pairs(rows)
    assert len(rows) == 5
    shared = [r for r in rows if r["shared_symbol"]]
    assert [(r["hi_index"], r["lo_index"], r["linked_effective_address"]) for r in shared] == [
        (21, 24, "0x47d0"),
        (33, 36, "0x47d0"),
    ]
    assert all(r["independent_identity_proven"] is False for r in rows)

    # Reject if shared pairs resolve to different addresses
    diverged_shared = [dict(r) for r in rows]
    diverged_shared[4]["linked_effective_address"] = "0x47d4"
    with pytest.raises(probe.ProbeError, match="same effective address"):
        probe.validate_hi16_lo16_pairs(diverged_shared)

    # Reject if non-shared target collides with shared target
    colliding = [dict(r) for r in rows]
    colliding[1]["linked_effective_address"] = "0x47d0"
    with pytest.raises(probe.ProbeError, match="distinct from one another"):
        probe.validate_hi16_lo16_pairs(colliding)


def test_reconstruct_and_validate_call_sites() -> None:
    rows = probe.reconstruct_call_sites(
        LINKED_WORDS, LINKED_WORDS, assigned_targets=probe.CONTROLLED_SYMBOLS
    )
    probe.validate_call_sites(rows)
    assert [r["linked_target"] for r in rows] == ["0x2354", "0x8a4", "0x8a4", "0x8a4", "0x8a4"]
    assert all(r["independent_identity_proven"] is False for r in rows)

    # Non-JAL instruction at call site is rejected
    bad_words = list(LINKED_WORDS)
    bad_words[3] = 0x080008D5  # J instead of JAL
    with pytest.raises(probe.ProbeError, match="not a JAL instruction"):
        probe.reconstruct_call_sites(
            LINKED_WORDS, bad_words, assigned_targets=probe.CONTROLLED_SYMBOLS
        )

    # Wrong reconstructed call target is rejected
    wrong_target_words = list(LINKED_WORDS)
    wrong_target_words[17] = 0x0C00022A  # 0x8a8 instead of 0x8a4
    wrong_rows = probe.reconstruct_call_sites(
        LINKED_WORDS, wrong_target_words, assigned_targets=probe.CONTROLLED_SYMBOLS
    )
    with pytest.raises(probe.ProbeError, match="reconstructs 0x8a8, expected 0x8a4"):
        probe.validate_call_sites(wrong_rows)


def _synthetic_prx_with_strings(
    *,
    s1: bytes = b"synthetic_string_one\x00",
    s2: bytes = b"synthetic_shared_string_two\x00",
    s3: bytes = b"synthetic_string_three\x00",
    data_size: int = 0xE8,
) -> tuple[elf.ElfFile, list[datarefs.DataReference]]:
    data_buf = bytearray(b"\x00" * data_size)
    data_buf[0x20 : 0x20 + 0x1C] = _u32_words(TABLE_ENTRIES)
    data_buf[0x3C : 0x3C + len(s1)] = s1
    data_buf[0x68 : 0x68 + len(s2)] = s2
    data_buf[0x98 : 0x98 + len(s3)] = s3

    module = elf.parse(
        build_elf32(
            e_type=ET_MIPS_PSP_PRX,
            sections=[
                {
                    "name": ".text",
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC | SHF_EXECINSTR,
                    "addr": 0,
                    "size": 0x4B8,
                    "data": b"\x00" * 0x414 + _u32_words(LINKED_WORDS),
                },
                {
                    "name": ".data",
                    "type": SHT_PROGBITS,
                    "flags": SHF_ALLOC,
                    "addr": 0x4768,
                    "size": len(data_buf),
                    "data": bytes(data_buf),
                },
            ],
        )
    )
    refs: list[datarefs.DataReference] = []
    for hi_idx, lo_idx, _sym, _role, target_addr in probe.PAIR_SPECS:
        hi_addr = 0x414 + hi_idx * 4
        lo_addr = 0x414 + lo_idx * 4
        hi_ev = datarefs.RelocationEvidence(
            type="R_MIPS_HI16",
            format="PSP",
            site=hi_addr,
            application_section=".text",
            application_offset=hi_addr,
            raw_offset=hi_addr,
            raw_info=R_MIPS_HI16,
            segment_index=0,
            relative_index=0,
            source_section=".rel.text",
            addend=0,
            addend_valid=True,
        )
        lo_ev = datarefs.RelocationEvidence(
            type="R_MIPS_LO16",
            format="PSP",
            site=lo_addr,
            application_section=".text",
            application_offset=lo_addr,
            raw_offset=lo_addr,
            raw_info=R_MIPS_LO16,
            segment_index=0,
            relative_index=0,
            source_section=".rel.text",
            addend=target_addr,
            addend_valid=True,
        )
        refs.append(
            datarefs.DataReference(
                instruction=lo_addr,
                kind="hi16-lo16",
                relocations=(hi_ev, lo_ev),
                addends=(0, target_addr),
                combined=target_addr,
                target=datarefs.DataTarget(".data", target_addr - 0x4768),
                load=None,
                pairing="PROVEN",
                location="PROVEN",
                status="PROVEN",
                evidence="synthetic",
            )
        )
    return module, refs


def test_extract_original_string_evidence_validates_bounds_nul_and_shared_reference() -> None:
    module, refs = _synthetic_prx_with_strings()
    rows = probe.extract_original_string_evidence(module, refs, LINKED_WORDS)
    assert [r["candidate_symbol"] for r in rows] == ["D_000047A4", "D_000047D0", "D_00004800"]
    assert [r["shared_reference"] for r in rows] == [False, True, False]
    assert [r["reference_count"] for r in rows] == [1, 2, 1]
    for row in rows:
        assert row["nul_terminated"] is True
        assert row["within_section_bounds"] is True
        assert row["address_resolution"] == "CONTROLLED"
        assert row["candidate_string_bytes_proven"] is False
        assert row["cross_artifact_identity"] == "UNPROVEN"
        assert row["runtime_comparison"] == "NOT_DEMONSTRATED"

    # Missing NUL terminator within bounds is rejected
    no_nul_mod, no_nul_refs = _synthetic_prx_with_strings(s1=b"A" * (0x68 - 0x3C))
    with pytest.raises(probe.ProbeError, match="no NUL terminator within bounds"):
        probe.extract_original_string_evidence(no_nul_mod, no_nul_refs, LINKED_WORDS)

    # Non-printable bytes before NUL are rejected
    bad_ascii_mod, bad_ascii_refs = _synthetic_prx_with_strings(s2=b"bad\x01text\x00")
    with pytest.raises(probe.ProbeError, match="non-printable bytes"):
        probe.extract_original_string_evidence(bad_ascii_mod, bad_ascii_refs, LINKED_WORDS)

    # Truncated .data section is rejected
    short_mod, short_refs = _synthetic_prx_with_strings(s3=b"ok\x00", data_size=0xA0)
    with pytest.raises(probe.ProbeError, match="exceed .data size"):
        probe.extract_original_string_evidence(short_mod, short_refs, LINKED_WORDS)


# ------------------------ 4 & 5 & 7. Negative controls B, C, D, E


def test_control_b_accepts_valid_rodata_move_and_rejects_wrong_reconstructed_address() -> None:
    moved = list(LINKED_WORDS)
    moved[10] = _addiu(3, 3, 0x4784)
    diffs = probe.validate_control_b(
        LINKED_WORDS, moved, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x4784
    )
    assert [row["word_index"] for row in diffs] == [10]

    # Localized at index 10, but reconstructs 0x4780 instead of 0x4784 -> FAIL
    wrong_addr = list(LINKED_WORDS)
    wrong_addr[10] = _addiu(3, 3, 0x4780)
    with pytest.raises(probe.ProbeError, match="reconstructs 0x4780, expected 0x4784"):
        probe.validate_control_b(
            LINKED_WORDS, wrong_addr, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x4784
        )

    # Extra code change or table entry change -> FAIL
    extra_diff = list(moved)
    extra_diff[0] ^= 1
    with pytest.raises(probe.ProbeError, match="only the jump-table LO16"):
        probe.validate_control_b(
            LINKED_WORDS, extra_diff, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x4784
        )
    with pytest.raises(probe.ProbeError, match="jump-table entries"):
        probe.validate_control_b(
            LINKED_WORDS,
            moved,
            TABLE_ENTRIES,
            (0x468, 0x450, *TABLE_ENTRIES[2:]),
            assigned_address=0x4784,
        )


def test_control_c_requires_both_shared_d_000047d0_pairs_and_rejects_partial_mutation() -> None:
    mutated = list(LINKED_WORDS)
    mutated[24] = _addiu(5, 5, 0x47D4)
    mutated[36] = _addiu(5, 5, 0x47D4)
    diffs = probe.validate_control_c(
        LINKED_WORDS, mutated, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x47D4
    )
    assert [row["word_index"] for row in diffs] == [24, 36]

    # Partial mutation affecting only 1 of the 2 shared references (index 24 only or 36 only)
    only_first = list(LINKED_WORDS)
    only_first[24] = _addiu(5, 5, 0x47D4)
    with pytest.raises(probe.ProbeError, match="exactly word indices \\[24, 36\\]"):
        probe.validate_control_c(
            LINKED_WORDS, only_first, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x47D4
        )

    only_second = list(LINKED_WORDS)
    only_second[36] = _addiu(5, 5, 0x47D4)
    with pytest.raises(probe.ProbeError, match="exactly word indices \\[24, 36\\]"):
        probe.validate_control_c(
            LINKED_WORDS, only_second, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x47D4
        )

    # Both indices [24, 36] changed, but second pair reconstructs 0x47D8 instead of 0x47D4
    mismatched_pair = list(mutated)
    mismatched_pair[36] = _addiu(5, 5, 0x47D8)
    with pytest.raises(probe.ProbeError, match="reconstruct 0x47d4 and 0x47d8, expected 0x47d4"):
        probe.validate_control_c(
            LINKED_WORDS, mismatched_pair, TABLE_ENTRIES, TABLE_ENTRIES, assigned_address=0x47D4
        )


def test_controls_d_and_e_isolate_table_and_nonrelocated_code() -> None:
    swapped_entries = (TABLE_ENTRIES[1], TABLE_ENTRIES[0], *TABLE_ENTRIES[2:])
    d_diffs = probe.validate_control_d(
        TABLE_ENTRIES, swapped_entries, LINKED_WORDS, LINKED_WORDS, swapped_indices=(0, 1)
    )
    assert [row["entry_index"] for row in d_diffs] == [0, 1]

    # Swapping identical entries (2 and 3 are both 0x480) must fail
    with pytest.raises(probe.ProbeError, match="two distinct baseline table entries"):
        probe.validate_control_d(
            TABLE_ENTRIES, TABLE_ENTRIES, LINKED_WORDS, LINKED_WORDS, swapped_indices=(2, 3)
        )

    # Control E: non-relocated word 0 flipped
    module = elf.parse(_candidate_object_bytes())
    sites, _pairing = probe.validate_candidate_text_inventory(module, CANDIDATE_WORDS)
    tampered_words = list(LINKED_WORDS)
    tampered_words[0] ^= 1
    e_diffs = probe.validate_control_e(
        LINKED_WORDS,
        tampered_words,
        TABLE_ENTRIES,
        TABLE_ENTRIES,
        word_index=0,
        relocation_sites=sites.sites,
    )
    assert [row["word_index"] for row in e_diffs] == [0]

    # Attempting to tamper a relocated word (e.g. word 24) is rejected
    reloc_tampered = list(LINKED_WORDS)
    reloc_tampered[24] ^= 4
    with pytest.raises(probe.ProbeError, match="is relocated"):
        probe.validate_control_e(
            LINKED_WORDS,
            reloc_tampered,
            TABLE_ENTRIES,
            TABLE_ENTRIES,
            word_index=24,
            relocation_sites=sites.sites,
        )


# -------------------- 8 & 11. Classification, NOT_RUN & determinism


@pytest.mark.parametrize(
    ("equal_words", "equal_entries", "expected_status", "expected_exit", "expected_claim"),
    [
        (41, 7, "PASS", 0, "ASSUMPTION_DEPENDENT"),
        (40, 7, "DIVERGENCE", 3, "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"),
        (41, 6, "DIVERGENCE", 3, "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"),
        (39, 5, "DIVERGENCE", 3, "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"),
    ],
)
def test_finalize_experiment_report_classifies_conservatively(
    equal_words: int,
    equal_entries: int,
    expected_status: str,
    expected_exit: int,
    expected_claim: str,
) -> None:
    report = probe._base_report()
    report["code"] = {
        "equal_words": equal_words,
        "total_words": 41,
        "differences": [] if equal_words == 41 else [{"word_index": 0}],
    }
    report["jump_table"]["equal_entries"] = equal_entries
    report["jump_table"]["differences"] = [] if equal_entries == 7 else [{"entry_index": 0}]
    exit_code = probe.finalize_experiment_report(report)
    assert exit_code == expected_exit
    assert report["experiment_status"] == expected_status
    assert report["equivalence_claim"] == expected_claim
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["independent_identity_proven"] is False
    assert report["promoted_to_matched"] is False


def test_finalize_never_passes_when_counts_and_difference_lists_disagree() -> None:
    report = probe._base_report()
    report["code"] = {"equal_words": 41, "total_words": 41, "differences": [{"word_index": 0}]}
    report["jump_table"]["equal_entries"] = 7
    report["jump_table"]["differences"] = []
    exit_code = probe.finalize_experiment_report(report)
    assert exit_code == probe.DIVERGENCE_EXIT_CODE == 3
    assert report["experiment_status"] == "DIVERGENCE"
    assert report["equivalence_claim"] == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


def test_not_run_controls_and_canonical_json_determinism() -> None:
    controls = probe.not_run_controls()
    assert set(controls) == {"C", "D", "E"}
    for record in controls.values():
        assert record == {
            "status": "NOT_RUN",
            "reason": "baseline comparison diverged",
            "detected": False,
            "promoted_to_matched": False,
        }
    assert probe.canonical_json({"b": 1, "a": [2, 3]}) == probe.canonical_json({"a": [2, 3], "b": 1})


# ------------------------ 10. Security & build/seto016 confinement


def test_validate_arguments_enforces_confinement_and_authorized_source(tmp_path, monkeypatch) -> None:
    escaped = probe.build_parser().parse_args(["--out", "build/seto016-escape/report.json"])
    with pytest.raises(probe.ProbeError, match="escapes allowed tree"):
        probe._validate_arguments(escaped)

    wrong_src = probe.build_parser().parse_args(["--source", "decomp/src/func_0000039C.c"])
    with pytest.raises(probe.ProbeError, match="only accepts the authorized func_00000414.c"):
        probe._validate_arguments(wrong_src)


def _create_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")


@pytest.mark.parametrize("component", ["build", "seto016"])
@pytest.mark.parametrize("broken", [False, True], ids=["external", "broken"])
def test_validated_build_root_rejects_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str, broken: bool
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    if not broken:
        outside.mkdir()
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    link = repo / "build"
    if component == "seto016":
        link.mkdir()
        link = link / "seto016"
    target = outside / "missing" if broken else outside
    _create_symlink_or_skip(link, target)
    with pytest.raises(probe.ProbeError, match="build directory must not be a symlink"):
        probe._validated_build_root()


# ---------------- 6, 8 & 9. Synthetic end-to-end run_experiment()


def _setup_synthetic_experiment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate_offsets: Sequence[int] = OBJECT_OFFSETS,
    candidate_words: Sequence[int] = CANDIDATE_WORDS,
    linked_entries_override: Sequence[int] | None = None,
    missing_tool: bool = False,
) -> tuple[ object, Path]:
    repo = tmp_path / "repo"
    (repo / "build/seto016").mkdir(parents=True)
    (repo / "decomp/src").mkdir(parents=True)
    (repo / "config/wsl").mkdir(parents=True)
    (repo / "private/original/PSP_GAME/USRDIR/gmodule").mkdir(parents=True)

    source_path = repo / "decomp/src/func_00000414.c"
    source_path.write_text("// synthetic func_00000414\n", encoding="utf-8")
    config_path = repo / "config/wsl/seto.toml"
    config_path.write_text("[tools]\n", encoding="utf-8")
    prx_path = repo / "private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"
    prx_mod, _refs = _synthetic_prx_with_strings()
    prx_path.write_bytes(prx_mod.reader.data)

    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    monkeypatch.setattr(
        probe.shutil, "which", (lambda _name: None) if missing_tool else (lambda name: f"/usr/bin/{name}")
    )

    candidate_bytes = _candidate_object_bytes(text_words=candidate_words, offsets=candidate_offsets)

    def fake_run(argv, *, cwd=None, timeout=300, env=None):
        if "scripts/match_function.py" in argv:
            candidate_dir = repo / "build/seto016/experiment/candidate"
            candidate_dir.mkdir(parents=True, exist_ok=True)
            candidate_path = candidate_dir / "func_00000414.o"
            candidate_path.write_bytes(candidate_bytes)
            match_record_path = candidate_dir / "match-record.json"
            record = {
                "function": "func_00000414",
                "address": "0x414",
                "section": ".text",
                "status": "INCONCLUSIVE",
                "match": {
                    "status": "INCONCLUSIVE",
                    "matching_words": 31,
                    "total_words": 41,
                    "difference_count": 0,
                    "relocation_issues": [],
                },
                "provenance": {
                    "source": probe.relative(source_path, repo),
                    "object": probe.relative(candidate_path, repo),
                    "object_sha256": probe.sha256_file(candidate_path),
                    "source_sha256": probe.sha256_file(source_path),
                    "flags": ["-O4,p", "-sdatathreshold", "0"],
                    "includes": ["decomp/include"],
                },
            }
            match_record_path.write_text(
                json.dumps({k: v for k, v in record.items() if k != "match"}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(args=argv, returncode=5, stdout=json.dumps(record), stderr="")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="fake", stderr="")

    monkeypatch.setattr(probe, "run", fake_run)
    monkeypatch.setattr(
        probe,
        "_toolchain_versions",
        lambda config_path, logs_dir, build_root, env: (
            "GNU ld 2.42",
            "Metrowerks 3.0.1 build 219",
            "wibo 1.2.0",
        ),
    )
    _, synthetic_refs = _synthetic_prx_with_strings()
    synthetic_strings = probe.extract_original_string_evidence(prx_mod, synthetic_refs, LINKED_WORDS)
    monkeypatch.setattr(
        probe,
        "_original_table_and_strings_evidence",
        lambda module, words: (
            {
                "entries": [f"0x{value:08x}" for value in TABLE_ENTRIES],
                "entries_match_recorded_baseline": True,
                "module_relative_address": "0x4788",
                "candidate_identity_proven": False,
            },
            synthetic_strings,
        ),
    )
    monkeypatch.setattr(
        probe,
        "_original_calls_evidence",
        lambda module: [
            {
                "word_index": idx,
                "call_site": f"0x{site:x}",
                "candidate_symbol": sym,
                "original_stub_address": f"0x{target:x}",
                "assignment_kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB",
                "candidate_symbol_identity_independently_proven": False,
            }
            for idx, site, sym, target in probe.CALL_SPECS
        ],
    )
    monkeypatch.setattr(
        probe,
        "_psp_region_relocations",
        lambda module, section_name, *, section_offset, size, words, load_base=0: {
            "section": section_name,
            "coordinate_system": "model",
            "load_base_zero_is_model_only": True,
            "relocations": [],
            "runtime_comparison": "NOT_DEMONSTRATED",
        },
    )

    def fake_link(*, object_path, script_path, output_path, table_address, controlled_symbols, logs_dir, label):
        module = elf.parse(object_path)
        words = list(
            mips.decode_words(module.section_data(module.require_section(".text")), "candidate text")
        )
        # Apply R_MIPS_26 and R_MIPS_HI16/LO16 relocations faithfully from controlled_symbols + table_address
        targets = {probe.TABLE_SYMBOL: table_address, **controlled_symbols}
        for idx, _site, sym, _orig in probe.CALL_SPECS:
            words[idx] = (0x03 << 26) | ((targets[sym] >> 2) & 0x03FFFFFF)
        for hi_idx, lo_idx, sym, _role, _orig in probe.PAIR_SPECS:
            addr = targets[sym]
            hi16 = ((addr + 0x8000) >> 16) & 0xFFFF
            lo16 = addr & 0xFFFF
            words[hi_idx] = (words[hi_idx] & 0xFFFF0000) | hi16
            words[lo_idx] = (words[lo_idx] & 0xFFFF0000) | lo16
        _sec, relocations, _tbl_words = probe.candidate_table_entries(module, symbol=probe.FUNCTION_NAME)
        resolved = tuple(
            probe.FUNCTION_ADDRESS + (rel.addend & 0xFFFFFFFF) for rel in relocations
        )
        entries = (
            tuple(linked_entries_override)
            if (linked_entries_override is not None and label == "case-a")
            else resolved
        )
        output_path.write_bytes(
            _linked_elf_bytes(
                text_words=words,
                entries=entries,
                table_address=table_address,
                controlled_symbols=controlled_symbols,
            )
        )
        return elf.parse(output_path), {"argv": ["mipsel-linux-gnu-ld"], "returncode": 0}

    monkeypatch.setattr(probe, "_link", fake_link)
    out_path = repo / "build/seto016/multi-reference-equivalence.json"
    arguments = probe.build_parser().parse_args(
        [
            "--prx",
            str(prx_path),
            "--source",
            str(source_path),
            "--config",
            str(config_path),
            "--out",
            str(out_path),
        ]
    )
    return arguments, out_path


def test_run_experiment_reports_pass_and_executes_all_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments, out_path = _setup_synthetic_experiment(tmp_path, monkeypatch)
    exit_code, report = probe.run_experiment(arguments)

    assert exit_code == 0
    assert report["experiment_status"] == "PASS"
    assert report["equivalence_claim"] == "ASSUMPTION_DEPENDENT"
    assert report["original_match_status"] == "INCONCLUSIVE"
    assert report["independent_identity_proven"] is False
    assert report["promoted_to_matched"] is False
    assert report["code"]["equal_words"] == 41
    assert report["jump_table"]["equal_entries"] == 7
    assert report["code"]["false_positive_controls"] == ["B", "C", "E"]
    assert report["jump_table"]["false_positive_controls"] == ["B", "D"]
    assert report["strings"]["false_positive_controls"] == ["C"]
    for label in ("A", "B", "C", "D", "E"):
        assert report["controls"][label]["status"] == "PASS"
        assert report["controls"][label]["promoted_to_matched"] is False
    assert report["controls"]["C"]["affected_word_indices"] == [24, 36]
    assert out_path.is_file()


def test_run_experiment_reports_divergence_and_marks_cde_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    divergent_offsets = (0x3C, 0x54, 0x50, 0x6C, 0x6C, 0x6C, 0x60)
    arguments, out_path = _setup_synthetic_experiment(
        tmp_path, monkeypatch, candidate_offsets=divergent_offsets
    )
    exit_code, report = probe.run_experiment(arguments)

    assert exit_code == 3
    assert report["experiment_status"] == "DIVERGENCE"
    assert report["equivalence_claim"] == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"
    assert report["code"]["equal_words"] == 41
    assert report["jump_table"]["equal_entries"] == 5
    assert report["jump_table"]["differences"] == [
        {"entry_index": 2, "original": "0x00000480", "linked": "0x00000464"},
        {"entry_index": 6, "original": "0x00000480", "linked": "0x00000474"},
    ]
    assert report["controls"]["A"]["status"] == "DIVERGENCE"
    assert report["controls"]["B"]["status"] == "PASS"
    for label in ("C", "D", "E"):
        assert report["controls"][label]["status"] == "NOT_RUN"
        assert report["controls"][label]["detected"] is False
    assert report["code"]["false_positive_controls"] == ["B"]
    assert report["jump_table"]["false_positive_controls"] == ["B"]
    assert report["strings"]["false_positive_controls"] == []
    assert json.loads(out_path.read_text(encoding="utf-8"))["experiment_status"] == "DIVERGENCE"


def test_run_experiment_rejects_linker_disagreement_and_reports_blocked_when_tools_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    divergent_offsets = (0x3C, 0x54, 0x50, 0x6C, 0x6C, 0x6C, 0x6C)
    arguments, _out_path = _setup_synthetic_experiment(
        tmp_path,
        monkeypatch,
        candidate_offsets=divergent_offsets,
        linked_entries_override=TABLE_ENTRIES,
    )
    with pytest.raises(
        probe.ProbeError, match="linked table differs from candidate relocation resolution"
    ) as exc_info:
        probe.run_experiment(arguments)
    assert exc_info.value.status == "FAIL"

    blocked_args, blocked_out = _setup_synthetic_experiment(
        tmp_path / "blocked", monkeypatch, missing_tool=True
    )
    code, blocked_report = probe.run_experiment(blocked_args)
    assert code == 4
    assert blocked_report["experiment_status"] == "BLOCKED"
    assert blocked_out.is_file()
