"""Pure unit and regression tests for SETO-DECOMP-017 (Integrated Module Equivalence).

Every fixture in this test module is synthetic: no dependency on private PRX, Metrowerks
compiler, or external toolchain. Validates the 509-word integrated module layout, 16 intervals,
fragment 0x84 accounting, local call resolution vs controlled imports, co-linked jump tables,
Controls A-E, conservative classification (ASSUMPTION_DEPENDENT, non-promotion), and
build path safety.
"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path
from typing import Sequence

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from seto import elf, imports, mips
from seto.binio import ParseError

SCRIPT = REPO_ROOT / "scripts" / "probe_integrated_module_equivalence.py"
SPEC = importlib.util.spec_from_file_location("probe_integrated_module_equivalence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

from probe_common import paired_effective_address, validate_link_has_no_unresolved

from conftest import (  # noqa: E402
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHT_PROGBITS,
    SHT_REL,
    SHT_STRTAB,
    SHT_SYMTAB,
    build_elf32,
    build_call_object,
    build_symbols,
    jal,
    word,
)


def _u32_words(values: Sequence[int]) -> bytes:
    return b"".join(word(value) for value in values)


def _mwcats_records(cases: Sequence[tuple[int, str, str, int, int]]) -> bytes:
    """Canonical Metrowerks metadata: ``(size << 16) | tag`` then the function pointer."""
    return b"".join(
        struct.pack("<II", ((total_w * 4) << 16) | probe.MWCATS_FUNCTION_TAG, addr)
        for addr, _c_name, _status, _mw, total_w in cases
    )


def _synthetic_linked_elf(
    *,
    text_words: Sequence[int] | None = None,
    rodata_words: Sequence[int] | None = None,
    text_addr: int = probe.TEXT_START,
    text_size: int = probe.TEXT_SIZE,
    rodata_addr: int = probe.RODATA_START,
    rodata_size: int = probe.RODATA_SIZE,
    cases: Sequence[tuple[int, str, str, int, int]] | None = None,
    extra_exec_section: bool = False,
    displace_func: str | None = None,
    displaced_addr: int = 0x1000,
    controlled_symbols: dict[str, int] | None = None,
    with_mwcats: bool = True,
    mwcats_bytes: bytes | None = None,
    mwcats_flags: int = 0,
    undefined_symbol: str | None = None,
    with_unconsumed_relocations: bool = False,
) -> bytes:
    if cases is None:
        cases = probe.ordered_inventory()
    if text_words is None:
        text_words = [0x00000000] * probe.TEXT_WORDS
    if rodata_words is None:
        rodata_words = [0x00000000] * probe.TOTAL_TABLE_ENTRIES

    # Build symbols: STN_UNDEF, 15 functions, 1 fragment layout symbol, controlled symbols
    symbols: list[dict[str, object]] = [
        {"name": "", "value": 0, "size": 0, "info": 0, "shndx": 0}
    ]
    # Sections will be: 1=.text, 2=.rodata, 3=.mwcats (optional), etc.
    text_shndx = 1
    rodata_shndx = 2

    for addr, _c_name, _status, _mw, total_w in cases:
        fname = mips.function_name(addr)
        val = displaced_addr if (displace_func == fname) else addr
        symbols.append(
            {
                "name": fname,
                "value": val,
                "size": total_w * 4,
                "info": 0x12,  # STB_GLOBAL, STT_FUNC
                "shndx": text_shndx,
            }
        )

    # Fragment symbol
    symbols.append(
        {
            "name": probe.FRAGMENT_SYMBOL,
            "value": probe.FRAGMENT_START,
            "size": probe.FRAGMENT_SIZE,
            "info": 0x10,  # STB_GLOBAL, STT_NOTYPE
            "shndx": text_shndx,
        }
    )

    # Controlled symbols (SHN_ABS = 0xFFF1)
    if controlled_symbols is not None:
        for sym, val in sorted(controlled_symbols.items()):
            symbols.append(
                {
                    "name": sym,
                    "value": val,
                    "size": 0,
                    "info": 0x10,
                    "shndx": elf.SHN_ABS,
                }
            )

    # Optional unresolved symbol (SHN_UNDEF = 0)
    if undefined_symbol is not None:
        symbols.append(
            {
                "name": undefined_symbol,
                "value": 0,
                "size": 0,
                "info": 0x10,  # STB_GLOBAL, STT_NOTYPE
                "shndx": elf.SHN_UNDEF,
            }
        )

    symtab_data, strtab_data = build_symbols(symbols)

    sections = [
        {
            "name": ".text",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC | SHF_EXECINSTR,
            "addr": text_addr,
            "data": _u32_words(text_words),
            "link": 0,
            "info": 0,
            "addralign": 4,
            "entsize": 0,
        },
        {
            "name": ".rodata",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC,
            "addr": rodata_addr,
            "data": _u32_words(rodata_words),
            "link": 0,
            "info": 0,
            "addralign": 4,
            "entsize": 0,
        },
    ]

    if with_mwcats:
        mwcats_data = mwcats_bytes if mwcats_bytes is not None else _mwcats_records(cases)
        sections.append(
            {
                "name": ".mwcats",
                "type": SHT_PROGBITS,
                "flags": mwcats_flags,
                "addr": 0,
                "data": mwcats_data,
                "link": 0,
                "info": 0,
                "addralign": 4,
                "entsize": 0,
            }
        )

    if extra_exec_section:
        sections.append(
            {
                "name": ".extra_code",
                "type": SHT_PROGBITS,
                "flags": SHF_ALLOC | SHF_EXECINSTR,
                "addr": 0x2000,
                "data": b"\x00" * 16,
                "link": 0,
                "info": 0,
                "addralign": 4,
                "entsize": 0,
            }
        )

    # symtab and strtab
    sections.extend(
        [
            {
                "name": ".symtab",
                "type": SHT_SYMTAB,
                "flags": 0,
                "addr": 0,
                "data": symtab_data,
                "link": len(sections) + 2,  # strtab index
                "info": 1,
                "addralign": 4,
                "entsize": 16,
            },
            {
                "name": ".strtab",
                "type": SHT_STRTAB,
                "flags": 0,
                "addr": 0,
                "data": strtab_data,
                "link": 0,
                "info": 0,
                "addralign": 1,
                "entsize": 0,
            },
        ]
    )

    if with_unconsumed_relocations:
        symtab_shndx = len(sections) - 1
        rel_data = struct.pack("<II", 0x0, (1 << 8) | 4)  # offset 0, sym 1, R_MIPS_26
        sections.append(
            {
                "name": ".rel.text",
                "type": SHT_REL,
                "flags": 0,
                "addr": 0,
                "data": rel_data,
                "link": symtab_shndx,
                "info": text_shndx,
                "addralign": 4,
                "entsize": 8,
            }
        )

    return build_elf32(sections=sections, e_type=elf.ET_EXEC)


# ---------------------------------------------------------------------------
# 1. Inventory & Interval Accounting Tests
# ---------------------------------------------------------------------------


def test_ordered_inventory_has_15_functions_and_strict_baseline_counts() -> None:
    cases = probe.ordered_inventory()
    assert len(cases) == 15
    # Strict order by address
    addresses = [c[0] for c in cases]
    assert addresses == sorted(addresses)
    assert addresses[0] == 0x0
    assert addresses[-1] == 0x704

    # Strict baseline counts: 7 MATCHED, 8 INCONCLUSIVE, 0 NONMATCHING
    matched = [c for c in cases if c[2] == "MATCHED"]
    inconclusive = [c for c in cases if c[2] == "INCONCLUSIVE"]
    nonmatching = [c for c in cases if c[2] == "NONMATCHING"]
    assert len(matched) == 7
    assert len(inconclusive) == 8
    assert len(nonmatching) == 0

    # Total C words = 507
    total_c_words = sum(c[4] for c in cases)
    assert total_c_words == probe.C_RECONSTRUCTED_WORDS


def test_layout_intervals_form_contiguous_16_intervals_with_fragment_0x84() -> None:
    cases = probe.ordered_inventory()
    intervals = probe.compute_layout_intervals(cases)
    assert len(intervals) == 16
    probe.validate_layout_intervals(intervals)

    # Verify fragment 0x84 interval
    frag = next(iv for iv in intervals if iv.kind == "ORIGINAL_UNRECONSTRUCTED_FRAGMENT")
    assert frag.start == 0x84
    assert frag.end == 0x8C
    assert frag.size_bytes == 8
    assert frag.words_count == 2
    assert frag.symbol == "func_00000084"
    assert frag.source_file is None
    assert frag.expected_status is None

    # Total layout range [0x0, 0x7F4)
    assert intervals[0].start == 0x0
    assert intervals[-1].end == probe.TEXT_SIZE


def test_layout_intervals_reject_gaps_overlaps_and_misalignment() -> None:
    cases = probe.ordered_inventory()

    # Gap: artificially shift func_0000008C by 4 bytes
    bad_cases_gap = [
        (c[0] + 4 if c[0] >= 0x8C else c[0], c[1], c[2], c[3], c[4]) for c in cases
    ]
    with pytest.raises(probe.ProbeError, match="layout gap or overlap"):
        probe.compute_layout_intervals(bad_cases_gap)

    # Overlap / premature end
    intervals = probe.compute_layout_intervals(cases)
    bad_intervals = list(intervals)
    bad_intervals[0] = probe.LayoutInterval(
        kind=intervals[0].kind,
        start=1,  # unaligned
        end=intervals[0].end,
        size_bytes=intervals[0].size_bytes,
        words_count=intervals[0].words_count,
        symbol=intervals[0].symbol,
        source_file=intervals[0].source_file,
        expected_status=intervals[0].expected_status,
    )
    with pytest.raises(probe.ProbeError, match="not contiguous|not 4-byte aligned"):
        probe.validate_layout_intervals(bad_intervals)


# ---------------------------------------------------------------------------
# 2. Fragment 0x84 Epistemological Accounting
# ---------------------------------------------------------------------------


def test_fragment_0x84_never_promoted_to_verified_c_decompilation() -> None:
    report = {
        "code": {"equal_words": 509, "total_words": 509, "differences": []},
        "jump_table": {"equal_entries": 13, "entry_count": 13, "differences": []},
    }
    code = probe.finalize_experiment_report(report)
    assert code == 0
    assert report["experiment_status"] == "PASS"
    assert report["equivalence_claim"] == "ASSUMPTION_DEPENDENT"
    assert report["independent_identity_proven"] is False
    assert report["promoted_to_matched"] is False
    assert report["runtime_comparison"] == "NOT_DEMONSTRATED"


# ---------------------------------------------------------------------------
# 3. Linker Script Generation & Placement
# ---------------------------------------------------------------------------


def test_generate_linker_script_places_all_15_objects_and_fragment_in_order() -> None:
    cases = probe.ordered_inventory()
    script = probe.generate_linker_script(cases, rodata_address=0x4770)

    # Check key structural directives
    assert "OUTPUT_FORMAT(\"elf32-tradlittlemips\")" in script
    assert "ENTRY(func_00000000)" in script
    assert ".text 0x0 : SUBALIGN(4)" in script
    assert "*func_00000000*(.text)" in script
    assert "*func_00000034*(.text)" in script
    assert "func_00000084 = .;" in script
    assert "LONG(0x03E00008)" in script
    assert "LONG(0x00000000)" in script
    assert "*func_0000008C*(.text)" in script
    assert "*func_00000704*(.text)" in script
    assert ".rodata 0x4770 : SUBALIGN(4)" in script
    assert "*func_0000039C*(.rodata)" in script
    assert "*func_00000414*(.rodata)" in script
    assert "ASSERT(ADDR(.text) == 0x0" in script
    assert "ASSERT(SIZEOF(.text) == 0x7f4" in script
    assert "ASSERT(ADDR(.rodata) == 0x4770" in script
    assert "ASSERT(SIZEOF(.rodata) == 0x34" in script


# ---------------------------------------------------------------------------
# 4. Word Comparison & Differences Reporting
# ---------------------------------------------------------------------------


def test_compare_word_sequences_identifies_exact_differences() -> None:
    original = [0x10000000 + i for i in range(509)]
    candidate = list(original)
    candidate[13] = 0xDEADBEEF
    candidate[70] = 0xCAFEBABE

    diffs = probe.compare_word_sequences(original, candidate)
    assert len(diffs) == 2
    assert diffs[0]["word_index"] == 13
    assert diffs[0]["address"] == f"0x{13 * 4:x}"
    assert diffs[0]["original"] == f"0x{original[13]:08x}"
    assert diffs[0]["linked"] == "0xdeadbeef"
    assert diffs[1]["word_index"] == 70
    assert diffs[1]["address"] == f"0x{70 * 4:x}"


def test_compare_word_sequences_rejects_wrong_lengths() -> None:
    with pytest.raises(ParseError, match="expected 509 words"):
        probe.compare_word_sequences([0] * 508, [0] * 509)


# ---------------------------------------------------------------------------
# 5. Jump Table Comparison & Invariants
# ---------------------------------------------------------------------------


def test_compare_table_entries_identifies_differences() -> None:
    orig = list(range(13))
    cand = list(range(13))
    cand[6] = 99
    diffs = probe.compare_table_entries(orig, cand)
    assert len(diffs) == 1
    assert diffs[0]["entry_index"] == 6
    assert diffs[0]["original"] == f"0x{6:08x}"
    assert diffs[0]["linked"] == f"0x{99:08x}"


def test_validate_candidate_table_invariants_rejects_mismatched_words_and_offsets() -> None:
    from seto.elf import Relocation

    # Valid 6-entry table for func_0000039C
    offsets = probe.TABLE_39C_EXPECTED_OFFSETS
    relocs = [
        Relocation(
            offset=i * 4,
            type=elf.R_MIPS_32,
            symbol_index=1,
            symbol="func_0000039C",
            addend=off,
            target_section=".text",
            section_offset=i * 4,
            file_offset=0,
            addend_valid=True,
        )
        for i, off in enumerate(offsets)
    ]
    words = list(offsets)
    addends = probe.validate_candidate_table_invariants(
        relocs, words, function_symbol="func_0000039C", expected_entries=6, function_size=0x78
    )
    assert addends == offsets

    # Disagreement between words and addends
    bad_words = list(words)
    bad_words[0] = 0x10
    with pytest.raises(probe.ProbeError, match="table words disagree with relocation addends"):
        probe.validate_candidate_table_invariants(
            relocs, bad_words, function_symbol="func_0000039C", expected_entries=6, function_size=0x78
        )

    # Target out of bounds
    out_relocs = list(relocs)
    out_relocs[0] = Relocation(
        offset=0,
        type=elf.R_MIPS_32,
        symbol_index=1,
        symbol="func_0000039C",
        addend=0x80,  # exceeds function_size 0x78
        target_section=".text",
        section_offset=0,
        file_offset=0,
        addend_valid=True,
    )
    with pytest.raises(probe.ProbeError, match="table target is outside aligned function code"):
        probe.validate_candidate_table_invariants(
            out_relocs, [0x80] + words[1:], function_symbol="func_0000039C", expected_entries=6, function_size=0x78
        )


# ---------------------------------------------------------------------------
# 6. Linked ELF Structure Validation
# ---------------------------------------------------------------------------


def test_validate_linked_structure_accepts_valid_elf_and_rejects_tampered_layouts() -> None:
    cases = probe.ordered_inventory()
    valid_elf_bytes = _synthetic_linked_elf(cases=cases)
    mod = elf.parse(valid_elf_bytes)
    text_sec, rodata_sec = probe.validate_linked_structure(mod, label="test-valid", expected_cases=cases)
    assert text_sec.addr == 0x0
    assert text_sec.size == 0x7F4
    assert rodata_sec.addr == 0x4770
    assert rodata_sec.size == 0x34

    # Rejection: extra executable section
    extra_exec_bytes = _synthetic_linked_elf(cases=cases, extra_exec_section=True)
    mod_extra = elf.parse(extra_exec_bytes)
    with pytest.raises(probe.ProbeError, match="executable sections are"):
        probe.validate_linked_structure(mod_extra, label="test-extra", expected_cases=cases)

    # Rejection: displaced function symbol
    displaced_bytes = _synthetic_linked_elf(cases=cases, displace_func="func_00000244", displaced_addr=0x248)
    mod_disp = elf.parse(displaced_bytes)
    with pytest.raises(probe.ProbeError, match="function symbol func_00000244 is at 0x248, expected 0x244"):
        probe.validate_linked_structure(mod_disp, label="test-disp", expected_cases=cases)


def test_validate_linked_controlled_symbols_checks_abs_values() -> None:
    cases = probe.ordered_inventory()
    ctrl = {"func_00001F04": 0x1F04, "D_000047D0": 0x47D0}
    elf_bytes = _synthetic_linked_elf(cases=cases, controlled_symbols=ctrl)
    mod = elf.parse(elf_bytes)
    probe.validate_linked_controlled_symbols(mod, ctrl)

    # Tampered symbol address
    bad_ctrl = {"func_00001F04": 0x1F08, "D_000047D0": 0x47D0}
    with pytest.raises(probe.ProbeError, match="linked controlled symbol func_00001F04 does not equal its assignment"):
        probe.validate_linked_controlled_symbols(mod, bad_ctrl)


# ---------------------------------------------------------------------------
# 7. Classification, Divergence & NOT_RUN Controls
# ---------------------------------------------------------------------------


def test_finalize_experiment_report_handles_divergence_exit_code_3() -> None:
    report = {
        "code": {
            "equal_words": 508,
            "total_words": 509,
            "differences": [{"word_index": 10, "original": "0x1", "linked": "0x2"}],
        },
        "jump_table": {"equal_entries": 13, "entry_count": 13, "differences": []},
    }
    code = probe.finalize_experiment_report(report)
    assert code == 3
    assert report["experiment_status"] == "DIVERGENCE"
    assert report["equivalence_claim"] == "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


def test_not_run_controls_marks_b_c_d_e_as_not_run() -> None:
    records = probe.not_run_controls()
    assert set(records.keys()) == {"B", "C", "D", "E"}
    for label, rec in records.items():
        assert rec["status"] == "NOT_RUN"
        assert rec["detected"] is False
        assert "baseline diverged" in str(rec["reason"])
        assert rec["promoted_to_matched"] is False


# ---------------------------------------------------------------------------
# 8. Path Confinement & Security
# ---------------------------------------------------------------------------


def test_build_root_confinement_rejects_escaping_paths(tmp_path: Path) -> None:
    root = probe.validated_build_root(tmp_path, subdir="seto017")
    probe.ensure_build_dir(root / "safe", root)

    # Escaping path
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(probe.ProbeError, match="escapes allowed tree|escapes its allowed root"):
        probe.repo_path(outside, repo_root=tmp_path, allowed_root=root)


def test_canonical_json_is_deterministic() -> None:
    payload = {"z": 1, "a": [3, 2, 1], "nested": {"k": "v"}}
    s1 = probe.canonical_json(payload)
    s2 = probe.canonical_json(payload)
    assert s1 == s2
    assert s1.startswith('{\n  "a": [\n    3,\n    2,\n    1\n  ],\n  "nested": {\n    "k": "v"\n  },\n  "z": 1\n}')


# ---------------------------------------------------------------------------
# 9. Relocation Semantics & Link Resolution Invariants
# ---------------------------------------------------------------------------


def test_hi16_lo16_pairing_and_carry_semantics() -> None:
    # 1. Non-carry case: target 0x00604864
    # lui $v0, 0x0060  -> 0x3c020060
    # addiu $v0, $v0, 0x4864 -> 0x24424864 (signed immediate 0x4864 > 0)
    addr = paired_effective_address(0x3C020060, 0x24424864)
    assert addr == 0x00604864

    # 2. Carry case: target 0x00608000
    # addiu $v0, $v0, -32768 (0x8000) has bit 15 set (sign extension)
    # lui $v0, 0x0061 (0x3c020061)
    # (0x0061 << 16) + (-0x8000) = 0x00610000 - 0x8000 = 0x00608000
    addr_carry = paired_effective_address(0x3C020061, 0x24428000)
    assert addr_carry == 0x00608000

    # 3. Carry boundary case: target 0x0060FFFF
    # lui $v0, 0x0061 -> 0x3c020061
    # addiu $v0, $v0, -1 -> 0x2442FFFF
    # (0x0061 << 16) - 1 = 0x0060FFFF
    addr_boundary = paired_effective_address(0x3C020061, 0x2442FFFF)
    assert addr_boundary == 0x0060FFFF

    # 4. Incorrect register pairing: lui defines $v0 (2), addiu consumes $v1 (3)
    with pytest.raises(ParseError, match="LO16 site is not an ADDIU consuming the LUI register"):
        paired_effective_address(0x3C020060, 0x24634864)

    # 5. Invalid opcode: non-LUI instruction at HI16 site
    with pytest.raises(ParseError, match="HI16 site is not a LUI instruction"):
        paired_effective_address(0x24020060, 0x24424864)


def test_validate_link_has_no_unresolved_rejects_unconsumed_relocations_and_undefined_symbols() -> None:
    cases = probe.ordered_inventory()

    # 1. Clean linked ELF passes
    clean_elf = _synthetic_linked_elf(cases=cases)
    mod_clean = elf.parse(clean_elf)
    validate_link_has_no_unresolved(mod_clean)

    # 2. Linked ELF with unconsumed relocations is rejected
    reloc_elf = _synthetic_linked_elf(cases=cases, with_unconsumed_relocations=True)
    mod_reloc = elf.parse(reloc_elf)
    with pytest.raises(probe.ProbeError, match="linked ELF contains unconsumed relocations"):
        validate_link_has_no_unresolved(mod_reloc)

    # 3. Linked ELF with undefined symbol is rejected
    undef_elf = _synthetic_linked_elf(cases=cases, undefined_symbol="D_UNRESOLVED")
    mod_undef = elf.parse(undef_elf)
    with pytest.raises(probe.ProbeError, match=r"linked ELF has undefined symbols: \['D_UNRESOLVED'\]"):
        validate_link_has_no_unresolved(mod_undef)


# ---------------------------------------------------------------------------
# 10. R2 hardening: mandatory .mwcats metadata
# ---------------------------------------------------------------------------


def test_validate_linked_structure_requires_mwcats_metadata_and_records() -> None:
    cases = probe.ordered_inventory()
    records = _mwcats_records(cases)

    # Canonical metadata is accepted and tied to every object.
    good = elf.parse(_synthetic_linked_elf(cases=cases, mwcats_bytes=records))
    probe.validate_linked_structure(good, label="good-mwcats", expected_cases=cases)

    # Absence of the section is rejected outright.
    missing = elf.parse(_synthetic_linked_elf(cases=cases, with_mwcats=False))
    with pytest.raises(probe.ProbeError, match="does not preserve the .mwcats"):
        probe.validate_linked_structure(missing, label="no-mwcats", expected_cases=cases)

    # Incompatible total size.
    short = elf.parse(_synthetic_linked_elf(cases=cases, mwcats_bytes=records[:-8]))
    with pytest.raises(probe.ProbeError, match=r"\.mwcats size is"):
        probe.validate_linked_structure(short, label="short-mwcats", expected_cases=cases)

    # Structurally incorrect record: wrong tag.
    bad_tag = bytearray(records)
    bad_tag[0] = probe.MWCATS_FUNCTION_TAG + 1
    tag_mod = elf.parse(_synthetic_linked_elf(cases=cases, mwcats_bytes=bytes(bad_tag)))
    with pytest.raises(probe.ProbeError, match="carries tag"):
        probe.validate_linked_structure(tag_mod, label="tag-mwcats", expected_cases=cases)

    # Structurally incorrect record: size field disagrees with the object.
    bad_size = bytearray(records)
    bad_size[2:4] = struct.pack("<H", 0x10)
    size_mod = elf.parse(_synthetic_linked_elf(cases=cases, mwcats_bytes=bytes(bad_size)))
    with pytest.raises(probe.ProbeError, match="declares size"):
        probe.validate_linked_structure(size_mod, label="size-mwcats", expected_cases=cases)

    # Structurally incorrect record: pointer no longer resolves to its object.
    bad_ptr = bytearray(records)
    bad_ptr[2 * probe.MWCATS_RECORD_SIZE + 4 : 2 * probe.MWCATS_RECORD_SIZE + 8] = struct.pack("<I", 0x999)
    ptr_mod = elf.parse(_synthetic_linked_elf(cases=cases, mwcats_bytes=bytes(bad_ptr)))
    with pytest.raises(probe.ProbeError, match="points at"):
        probe.validate_linked_structure(ptr_mod, label="ptr-mwcats", expected_cases=cases)


# ---------------------------------------------------------------------------
# 11. R2 hardening: R_MIPS_26 reconciliation and controlled imports
# ---------------------------------------------------------------------------


def _stub_import(address: int, library: str, nid: int) -> imports.PspImport:
    return imports.PspImport(
        library=library, nid=nid, stub_address=address, stub_index=0, table_offset=0
    )


def _call(
    address: int, target: int, kind: str, imported: imports.PspImport | None = None
) -> imports.CallReference:
    return imports.CallReference(
        address=address, target=target, relocation_type="R_MIPS_26", kind=kind, imported=imported
    )


def test_reconcile_call_inventory_proves_sites_against_prx_and_link() -> None:
    stub = 0x20
    imported = _stub_import(stub, "sceTest", 0xABCD0001)
    table = imports.ImportTable(
        module="m", imports={stub: imported}, code_range=(probe.TEXT_START, probe.TEXT_SIZE)
    )
    words = [0] * probe.TEXT_WORDS
    words[0x8 // 4] = jal(stub)
    words[0x10 // 4] = jal(0x100)
    prx_calls = (_call(0x8, stub, "import", imported), _call(0x10, 0x100, "local"))
    candidate_sites = {0x8: "func_00000020", 0x10: "func_00000100"}
    linked_symbols = {"func_00000100": 0x100}
    controlled = {"func_00000020": stub}

    rows = probe.reconcile_call_inventory(
        candidate_sites, linked_symbols, words, prx_calls, table, controlled
    )
    assert [row["kind"] for row in rows] == ["import", "local"]
    assert rows[0]["imported_library"] == "sceTest"
    assert rows[0]["imported_nid"] == "0xabcd0001"
    assert rows[0]["linked_call_target"] == f"0x{stub:x}"
    assert rows[1]["callee_address"] == "0x100"
    assert rows[1]["linked_call_target"] == "0x100"

    # The two inventories must describe the same sites.
    with pytest.raises(probe.ProbeError, match="does not match the PRX calls"):
        probe.reconcile_call_inventory(
            {0x8: "func_00000020"}, linked_symbols, words, prx_calls, table, controlled
        )
    with pytest.raises(probe.ProbeError, match="does not match the PRX calls"):
        probe.reconcile_call_inventory(
            {**candidate_sites, 0x14: "func_00000100"},
            linked_symbols,
            words,
            prx_calls,
            table,
            controlled,
        )

    # An import symbol must name a stub the PRX import table actually resolves.
    with pytest.raises(probe.ProbeError, match="does not name a stub"):
        probe.reconcile_call_inventory(
            {0x8: "func_00000030", 0x10: "func_00000100"},
            linked_symbols,
            words,
            prx_calls,
            table,
            {"func_00000030": 0x30},
        )

    # A local call symbol must be a defined function of the linked module.
    with pytest.raises(probe.ProbeError, match="not a defined function"):
        probe.reconcile_call_inventory(
            candidate_sites, {}, words, prx_calls, table, controlled
        )

    # The local PRX target and the symbol address must agree.
    wrong_local = (_call(0x8, stub, "import", imported), _call(0x10, 0x104, "local"))
    with pytest.raises(probe.ProbeError, match="targets 0x104"):
        probe.reconcile_call_inventory(
            candidate_sites, linked_symbols, words, wrong_local, table, controlled
        )

    # The linked instruction must be the jal that was actually produced.
    non_jal = list(words)
    non_jal[0x8 // 4] = 0
    with pytest.raises(probe.ProbeError, match="is not a jal"):
        probe.reconcile_call_inventory(
            candidate_sites, linked_symbols, non_jal, prx_calls, table, controlled
        )
    wrong_jal = list(words)
    wrong_jal[0x8 // 4] = jal(0x30)
    with pytest.raises(probe.ProbeError, match="does not jump to"):
        probe.reconcile_call_inventory(
            candidate_sites, linked_symbols, wrong_jal, prx_calls, table, controlled
        )


def test_validate_controlled_imports_matches_the_prx_import_table() -> None:
    imported_a = _stub_import(0x20, "sceA", 0x11)
    imported_b = _stub_import(0x24, "sceB", 0x22)
    calls = (_call(0x8, 0x20, "import", imported_a), _call(0xC, 0x24, "import", imported_b))

    probe.validate_controlled_imports(calls, {"func_00000020": 0x20, "func_00000024": 0x24})

    with pytest.raises(probe.ProbeError, match="missing"):
        probe.validate_controlled_imports(calls, {"func_00000020": 0x20})
    with pytest.raises(probe.ProbeError, match="excess"):
        probe.validate_controlled_imports(
            calls, {"func_00000020": 0x20, "func_00000024": 0x24, "func_00000028": 0x28}
        )
    with pytest.raises(probe.ProbeError, match="incorrect"):
        probe.validate_controlled_imports(calls, {"func_00000020": 0x20, "func_00000024": 0x28})


# ---------------------------------------------------------------------------
# 12. R2 hardening: fail-closed finalization and record provenance
# ---------------------------------------------------------------------------


def test_finalize_experiment_report_rejects_incomplete_and_inconsistent_reports() -> None:
    jump_table = {"equal_entries": 13, "entry_count": 13, "differences": []}

    with pytest.raises(probe.ProbeError, match="structured code and jump_table"):
        probe.finalize_experiment_report({})
    with pytest.raises(probe.ProbeError, match="structured code and jump_table"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": 509, "total_words": 509, "differences": []}}
        )
    with pytest.raises(probe.ProbeError, match="integer field"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": None, "total_words": 509, "differences": []}, "jump_table": jump_table}
        )
    with pytest.raises(probe.ProbeError, match="integer field"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": True, "total_words": 509, "differences": []}, "jump_table": jump_table}
        )
    with pytest.raises(probe.ProbeError, match="difference lists"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": 509, "total_words": 509, "differences": "x"}, "jump_table": jump_table}
        )
    with pytest.raises(probe.ProbeError, match="exactly 509 words and 13 entries"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": 508, "total_words": 508, "differences": []}, "jump_table": jump_table}
        )
    with pytest.raises(probe.ProbeError, match="code equal-count disagrees"):
        probe.finalize_experiment_report(
            {"code": {"equal_words": 508, "total_words": 509, "differences": []}, "jump_table": jump_table}
        )
    with pytest.raises(probe.ProbeError, match="jump-table equal-count disagrees"):
        probe.finalize_experiment_report(
            {
                "code": {"equal_words": 509, "total_words": 509, "differences": []},
                "jump_table": {"equal_entries": 12, "entry_count": 13, "differences": []},
            }
        )


def _match_record(
    compiler: str, loader: Sequence[str], flags: Sequence[str], includes: Sequence[str]
) -> dict[str, object]:
    return {
        "provenance": {
            "compiler": compiler,
            "loader": list(loader),
            "flags": list(flags),
            "includes": list(includes),
        }
    }


def test_consistent_provenance_reads_and_sanitizes_the_match_records() -> None:
    cases = probe.ordered_inventory()
    records = {
        c_name: _match_record(
            "/mnt/c/tools/mwccpsp_3.0.1_219/mwccpsp.exe",
            ["/home/user/.local/bin/wibo"],
            ["-O4,p", "-sdatathreshold", "0"],
            ["decomp/include"],
        )
        for _addr, c_name, *_rest in cases
    }

    provenance = probe.consistent_provenance(records, cases)
    assert provenance["compiler"] == "mwccpsp.exe"
    assert provenance["loader"] == ["wibo"]
    assert provenance["flags"] == ["-O4,p", "-sdatathreshold", "0"]
    assert provenance["includes"] == ["decomp/include"]

    divergent = dict(records)
    divergent[cases[0][1]] = _match_record(
        "/mnt/c/tools/mwccpsp_3.0.1_219/other.exe",
        ["/home/user/.local/bin/wibo"],
        ["-O4,p", "-sdatathreshold", "0"],
        ["decomp/include"],
    )
    with pytest.raises(probe.ProbeError, match="compiler is not consistent"):
        probe.consistent_provenance(divergent, cases)

    broken = dict(records)
    broken[cases[1][1]] = {}
    with pytest.raises(probe.ProbeError, match="no provenance block"):
        probe.consistent_provenance(broken, cases)

    no_flags = dict(records)
    no_flags[cases[2][1]] = {
        "provenance": {
            "compiler": "mwccpsp.exe",
            "loader": ["wibo"],
            "includes": ["decomp/include"],
        }
    }
    with pytest.raises(probe.ProbeError, match="no flags list"):
        probe.consistent_provenance(no_flags, cases)

    other_loader = dict(records)
    other_loader[cases[3][1]] = _match_record(
        "/mnt/c/tools/mwccpsp_3.0.1_219/mwccpsp.exe",
        ["/home/user/.local/bin/wibo-ng"],
        ["-O4,p", "-sdatathreshold", "0"],
        ["decomp/include"],
    )
    with pytest.raises(probe.ProbeError, match="loader is not consistent"):
        probe.consistent_provenance(other_loader, cases)

    other_includes = dict(records)
    other_includes[cases[4][1]] = _match_record(
        "/mnt/c/tools/mwccpsp_3.0.1_219/mwccpsp.exe",
        ["/home/user/.local/bin/wibo"],
        ["-O4,p", "-sdatathreshold", "0"],
        ["decomp/include", "decomp/extra"],
    )
    with pytest.raises(probe.ProbeError, match="includes is not consistent"):
        probe.consistent_provenance(other_includes, cases)


# ---------------------------------------------------------------------------
# 13. R2 hardening: candidate R_MIPS_26 collection and executable metadata
# ---------------------------------------------------------------------------


def _single_case_object(tmp_path: Path, code: bytes, calls: Sequence[tuple[int, str]]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    obj_path = tmp_path / "func_00000100.o"
    obj_path.write_bytes(build_call_object(code, calls))
    return obj_path


def test_collect_candidate_call_sites_reads_the_object_relocations(tmp_path: Path) -> None:
    cases = [(0x100, "func_00000100.c", "MATCHED", 16, 4)]
    obj = _single_case_object(tmp_path, word(0) + word(jal(0)) + word(0) + word(0), [(4, "func_00000200")])
    objects = {"func_00000100.c": obj}

    assert probe.collect_candidate_call_sites(cases, objects) == {0x104: "func_00000200"}

    # A relocation inside .text but past the declared function is rejected.
    outside = _single_case_object(tmp_path / "n", word(0) * 6, [(20, "func_00000200")])
    with pytest.raises(probe.ProbeError, match="outside its function"):
        probe.collect_candidate_call_sites(cases, {"func_00000100.c": outside})

    # A relocation past the object's own .text has no validated section offset.
    past_end = _single_case_object(tmp_path / "e", word(0) * 4, [(0x40, "func_00000200")])
    with pytest.raises(probe.ProbeError, match="no validated section offset"):
        probe.collect_candidate_call_sites(cases, {"func_00000100.c": past_end})

    # A non-zero in-place addend is rejected.
    addended = _single_case_object(tmp_path / "a", word(0) + word(jal(4)) + word(0) + word(0), [(4, "func_00000200")])
    with pytest.raises(probe.ProbeError, match="carries an in-place addend"):
        probe.collect_candidate_call_sites(cases, {"func_00000100.c": addended})

    # The same site emitted by two objects is ambiguous.
    with pytest.raises(probe.ProbeError, match="emitted by more than one object"):
        probe.collect_candidate_call_sites(
            [
                (0x100, "func_00000100.c", "MATCHED", 16, 4),
                (0x100, "func_00000100b.c", "MATCHED", 16, 4),
            ],
            {"func_00000100.c": obj, "func_00000100b.c": obj},
        )


def test_validate_linked_structure_rejects_executable_mwcats() -> None:
    cases = probe.ordered_inventory()
    elf_bytes = _synthetic_linked_elf(cases=cases, mwcats_flags=SHF_ALLOC | SHF_EXECINSTR)
    module = elf.parse(elf_bytes)
    with pytest.raises(probe.ProbeError, match="executable sections"):
        probe.validate_linked_structure(module, label="exec-mwcats", expected_cases=cases)

