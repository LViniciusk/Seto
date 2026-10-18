#!/usr/bin/env python3
"""Run the controlled post-link and data-reference equivalence probe for func_00000414.

SETO-DECOMP-016 extends the controlled post-link comparison from 014/015 to a
function that combines a 7-entry compiler-generated jump table in ``.rodata``
(7 x ``R_MIPS_32``), 5 ``R_MIPS_HI16``/``R_MIPS_LO16`` address pairs in ``.text``
(1 for the jump table and 4 for 3 ``.data`` strings, including the shared
``D_000047D0`` symbol at ``21->24`` and ``33->36``), and 5 ``R_MIPS_26`` external
calls (1 to ``func_00002354`` and 4 to ``func_000008A4``).

Equality under these controlled assignments is assumption-dependent and never
promotes ``seto match`` from ``INCONCLUSIVE`` to ``MATCHED``, nor does it prove
candidate string bytes or cross-artifact symbol identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from probe_common import (  # noqa: E402
    ProbeError,
    canonical_json,
    compare_word_sequences as _compare_word_sequences,
    ensure_build_dir,
    paired_effective_address,
    prepare_build_file,
    relative,
    repo_path,
    require_mips_elf,
    run,
    validate_link_has_no_unresolved,
    validate_nonrelocated_tamper as _validate_nonrelocated_tamper,
    validate_recorded_hash,
    validate_saved_match_record,
    validated_build_root,
    write_build_bytes,
    write_build_text,
)
from seto import datarefs, elf, imports, matching, mips, psp_reloc  # noqa: E402
from seto.binio import ParseError  # noqa: E402
from seto.hashing import sha256_file  # noqa: E402

FUNCTION_NAME = "func_00000414"
FUNCTION_ADDRESS = 0x414
FUNCTION_SIZE = 0xA4
FUNCTION_WORDS = FUNCTION_SIZE // 4
BASELINE_MATCHING_WORDS = 31

TABLE_SECTION = ".rodata"
TABLE_SYMBOL = "@15"
TABLE_ORIGINAL_SECTION = ".data"
TABLE_ORIGINAL_OFFSET = 0x20
TABLE_ADDRESS = 0x4788
TABLE_ALTERNATE_ADDRESS = 0x4784
TABLE_ENTRIES = 7
TABLE_SIZE = TABLE_ENTRIES * 4
EXPECTED_TARGETS = (0x450, 0x468, 0x480, 0x480, 0x480, 0x480, 0x480)
EXPECTED_OFFSETS = (0x3C, 0x54, 0x6C, 0x6C, 0x6C, 0x6C, 0x6C)

CONTROLLED_SYMBOLS: dict[str, int] = {
    "func_00002354": 0x2354,
    "func_000008A4": 0x8A4,
    "D_000047A4": 0x47A4,
    "D_000047D0": 0x47D0,
    "D_00004800": 0x4800,
}
SHARED_DATA_SYMBOL = "D_000047D0"
SHARED_DATA_ALTERNATE_ADDRESS = 0x47D4

EXPECTED_PAIRS: dict[int, int] = {8: 10, 15: 18, 21: 24, 27: 30, 33: 36}

PAIR_SPECS: tuple[tuple[int, int, str, str, int], ...] = (
    (8, 10, TABLE_SYMBOL, "jump_table", TABLE_ADDRESS),
    (15, 18, "D_000047A4", "data_string", 0x47A4),
    (21, 24, "D_000047D0", "shared_data_string", 0x47D0),
    (27, 30, "D_00004800", "data_string", 0x4800),
    (33, 36, "D_000047D0", "shared_data_string", 0x47D0),
)

CALL_SPECS: tuple[tuple[int, int, str, int], ...] = (
    (3, 0x420, "func_00002354", 0x2354),
    (17, 0x458, "func_000008A4", 0x8A4),
    (23, 0x470, "func_000008A4", 0x8A4),
    (29, 0x488, "func_000008A4", 0x8A4),
    (35, 0x4A0, "func_000008A4", 0x8A4),
)

STRING_SPECS: tuple[tuple[str, str, int, int, int, tuple[tuple[int, int], ...]], ...] = (
    ("D_000047A4", ".data", 0x3C, 0x47A4, 0x68, ((15, 18),)),
    ("D_000047D0", ".data", 0x68, 0x47D0, 0x98, ((21, 24), (33, 36))),
    ("D_00004800", ".data", 0x98, 0x4800, 0xE8, ((27, 30),)),
)

LINKER = "mipsel-linux-gnu-ld"
READELF = "mipsel-linux-gnu-readelf"
OBJDUMP = "mipsel-linux-gnu-objdump"
FILE = "file"
DIVERGENCE_EXIT_CODE = 3


def _validated_build_root() -> Path:
    return validated_build_root(REPO_ROOT, subdir="seto016")


def compare_word_sequences(
    original: Sequence[int], candidate: Sequence[int], *, address: int = FUNCTION_ADDRESS
) -> list[dict[str, object]]:
    """Compare all 41 words literally; no relocation masks or normalization apply."""
    return _compare_word_sequences(
        original, candidate, address=address, expected_words=FUNCTION_WORDS
    )


def validate_nonrelocated_tamper(
    original: Sequence[int],
    tampered: Sequence[int],
    *,
    word_index: int,
    relocation_sites: dict[int, matching.RelocationSite],
) -> list[dict[str, object]]:
    return _validate_nonrelocated_tamper(
        original,
        tampered,
        word_index=word_index,
        relocation_sites=relocation_sites,
        address=FUNCTION_ADDRESS,
        expected_words=FUNCTION_WORDS,
    )


def compare_table_entries(
    original: Sequence[int], candidate: Sequence[int]
) -> list[dict[str, object]]:
    """Compare the seven jump-table words literally, entry by entry."""
    if len(original) != TABLE_ENTRIES or len(candidate) != TABLE_ENTRIES:
        raise ParseError(
            f"expected {TABLE_ENTRIES} table entries on each side; "
            f"got original={len(original)}, candidate={len(candidate)}"
        )
    return [
        {"entry_index": index, "original": f"0x{left:08x}", "linked": f"0x{right:08x}"}
        for index, (left, right) in enumerate(zip(original, candidate, strict=True))
        if left != right
    ]


def entry_destination_rows(entries: Sequence[int]) -> list[dict[str, object]]:
    """Return the effective destination of each linked entry and its relationship to the function."""
    if len(entries) != TABLE_ENTRIES:
        raise ParseError(f"expected {TABLE_ENTRIES} table entries, got {len(entries)}")
    rows: list[dict[str, object]] = []
    for index, (address, expected) in enumerate(zip(entries, EXPECTED_TARGETS, strict=True)):
        inside = FUNCTION_ADDRESS <= address < FUNCTION_ADDRESS + FUNCTION_SIZE
        rows.append(
            {
                "entry_index": index,
                "address": f"0x{address:x}",
                "function_relative_offset": f"0x{address - FUNCTION_ADDRESS:x}" if inside else None,
                "expected_case_address": f"0x{expected:x}",
                "inside_function": inside,
                "aligned": address % 4 == 0,
                "matches_expected_case": address == expected,
            }
        )
    return rows


def validate_structural_destinations(entries: Sequence[int]) -> None:
    """Require every linked entry to land at an aligned address inside the function."""
    if len(entries) != TABLE_ENTRIES:
        raise ProbeError("FAIL", f"expected {TABLE_ENTRIES} table entries, got {len(entries)}")
    for index, address in enumerate(entries):
        if address % 4 != 0 or not (FUNCTION_ADDRESS <= address < FUNCTION_ADDRESS + FUNCTION_SIZE):
            raise ProbeError(
                "FAIL",
                f"linked jump table entry {index} at 0x{address:x} is outside aligned function code "
                f"[0x{FUNCTION_ADDRESS:x}:0x{FUNCTION_ADDRESS + FUNCTION_SIZE:x})",
            )


def equivalence_claim(
    equal_words: int,
    equal_entries: int,
    *,
    code_differences: Sequence[object] = (),
    table_differences: Sequence[object] = (),
) -> str:
    """Keep equality under a controlled layout and symbol map explicitly conditional."""
    if (
        equal_words == FUNCTION_WORDS
        and equal_entries == TABLE_ENTRIES
        and not code_differences
        and not table_differences
    ):
        return "ASSUMPTION_DEPENDENT"
    return "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


def reconstruct_hi16_lo16_pairs(
    original_words: Sequence[int],
    linked_words: Sequence[int],
    *,
    assigned_targets: dict[str, int],
) -> list[dict[str, object]]:
    """Reconstruct and compare all five HI16/LO16 pairs from the instruction words."""
    if len(original_words) != FUNCTION_WORDS or len(linked_words) != FUNCTION_WORDS:
        raise ParseError(f"expected {FUNCTION_WORDS} instruction words on each side")
    rows: list[dict[str, object]] = []
    for hi_index, lo_index, symbol, role, _expected_orig in PAIR_SPECS:
        if symbol not in assigned_targets:
            raise ProbeError("FAIL", f"missing controlled target assignment for {symbol}")
        hi_address = FUNCTION_ADDRESS + hi_index * 4
        lo_address = FUNCTION_ADDRESS + lo_index * 4
        original_effective = paired_effective_address(original_words[hi_index], original_words[lo_index])
        linked_effective = paired_effective_address(linked_words[hi_index], linked_words[lo_index])
        assigned_address = assigned_targets[symbol]
        rows.append(
            {
                "hi_index": hi_index,
                "lo_index": lo_index,
                "hi_address": f"0x{hi_address:x}",
                "lo_address": f"0x{lo_address:x}",
                "candidate_symbol": symbol,
                "role": role,
                "shared_symbol": symbol == SHARED_DATA_SYMBOL,
                "relocation_types": ["R_MIPS_HI16", "R_MIPS_LO16"],
                "original_hi_word": f"0x{original_words[hi_index]:08x}",
                "original_lo_word": f"0x{original_words[lo_index]:08x}",
                "linked_hi_word": f"0x{linked_words[hi_index]:08x}",
                "linked_lo_word": f"0x{linked_words[lo_index]:08x}",
                "original_effective_address": f"0x{original_effective:x}",
                "linked_effective_address": f"0x{linked_effective:x}",
                "assigned_target": f"0x{assigned_address:x}",
                "reconstructs_assigned_target": linked_effective == assigned_address,
                "matches_original_effective_address": linked_effective == original_effective,
                "evidence_grade": (
                    "CONTROLLED_LAYOUT" if symbol == TABLE_SYMBOL else "CONTROLLED_SYMBOL_ASSIGNMENT"
                ),
                "independent_identity_proven": False,
            }
        )
    return rows


def validate_hi16_lo16_pairs(pair_rows: Sequence[dict[str, object]]) -> None:
    """Validate that all 5 HI16/LO16 pairs reconstruct their targets and share D_000047D0."""
    if len(pair_rows) != len(PAIR_SPECS):
        raise ProbeError("FAIL", f"expected {len(PAIR_SPECS)} HI16/LO16 pair rows, got {len(pair_rows)}")
    for row in pair_rows:
        if not row.get("reconstructs_assigned_target"):
            raise ProbeError(
                "FAIL",
                f"HI16/LO16 pair {row.get('hi_index')}->{row.get('lo_index')} ({row.get('candidate_symbol')}) "
                f"reconstructs {row.get('linked_effective_address')}, expected {row.get('assigned_target')}",
            )
    shared_rows = [row for row in pair_rows if row.get("candidate_symbol") == SHARED_DATA_SYMBOL]
    if len(shared_rows) != 2 or [(r["hi_index"], r["lo_index"]) for r in shared_rows] != [(21, 24), (33, 36)]:
        raise ProbeError("FAIL", "shared D_000047D0 pairs must be at indices 21->24 and 33->36")
    shared_addresses = {row["linked_effective_address"] for row in shared_rows}
    if len(shared_addresses) != 1:
        raise ProbeError("FAIL", "shared D_000047D0 pairs do not resolve to the same effective address")
    non_shared = [row["linked_effective_address"] for row in pair_rows if row.get("candidate_symbol") != SHARED_DATA_SYMBOL]
    if len(non_shared) != 3 or len(set(non_shared) | shared_addresses) != 4:
        raise ProbeError("FAIL", "non-shared HI16/LO16 targets must remain distinct from one another")


def reconstruct_call_sites(
    original_words: Sequence[int],
    linked_words: Sequence[int],
    *,
    assigned_targets: dict[str, int],
) -> list[dict[str, object]]:
    """Reconstruct and compare all five R_MIPS_26 JAL call sites."""
    if len(original_words) != FUNCTION_WORDS or len(linked_words) != FUNCTION_WORDS:
        raise ParseError(f"expected {FUNCTION_WORDS} instruction words on each side")
    rows: list[dict[str, object]] = []
    for word_index, site_address, symbol, _expected_orig in CALL_SPECS:
        if symbol not in assigned_targets:
            raise ProbeError("FAIL", f"missing controlled call target assignment for {symbol}")
        orig_word, link_word = original_words[word_index], linked_words[word_index]
        if (orig_word >> 26) != 0x03 or (link_word >> 26) != 0x03:
            raise ProbeError("FAIL", f"call site at 0x{site_address:x} is not a JAL instruction")
        original_target = mips.jump_target(orig_word, site_address)
        linked_target = mips.jump_target(link_word, site_address)
        if original_target is None or linked_target is None:
            raise ProbeError("FAIL", f"could not decode JAL target at 0x{site_address:x}")
        assigned_address = assigned_targets[symbol]
        rows.append(
            {
                "word_index": word_index,
                "call_site": f"0x{site_address:x}",
                "candidate_symbol": symbol,
                "relocation_type": "R_MIPS_26",
                "original_word": f"0x{orig_word:08x}",
                "linked_word": f"0x{link_word:08x}",
                "original_target": f"0x{original_target:x}",
                "linked_target": f"0x{linked_target:x}",
                "assigned_target": f"0x{assigned_address:x}",
                "reconstructs_assigned_target": linked_target == assigned_address,
                "matches_original_target": linked_target == original_target,
                "independent_identity_proven": False,
            }
        )
    return rows


def validate_call_sites(call_rows: Sequence[dict[str, object]]) -> None:
    """Require all 5 R_MIPS_26 call sites to reconstruct their controlled targets."""
    if len(call_rows) != len(CALL_SPECS):
        raise ProbeError("FAIL", f"expected {len(CALL_SPECS)} call rows, got {len(call_rows)}")
    for row in call_rows:
        if not row.get("reconstructs_assigned_target"):
            raise ProbeError(
                "FAIL",
                f"call site {row.get('call_site')} ({row.get('candidate_symbol')}) "
                f"reconstructs {row.get('linked_target')}, expected {row.get('assigned_target')}",
            )


def validate_control_b(
    baseline_words: Sequence[int],
    moved_words: Sequence[int],
    baseline_entries: Sequence[int],
    moved_entries: Sequence[int],
    *,
    assigned_address: int = TABLE_ALTERNATE_ADDRESS,
) -> list[dict[str, object]]:
    """Control B (.rodata: 0x4788 -> 0x4784): only the table pair changes and reconstructs 0x4784."""
    differences = compare_word_sequences(baseline_words, moved_words)
    if [row["word_index"] for row in differences] != [10]:
        raise ProbeError(
            "FAIL",
            "control B (.rodata move) did not change only the jump-table LO16 instruction word at index 10",
        )
    effective = paired_effective_address(moved_words[8], moved_words[10])
    if effective != assigned_address:
        raise ProbeError(
            "FAIL",
            f"control B jump-table pair reconstructs 0x{effective:x}, expected 0x{assigned_address:x}",
        )
    for hi_idx, lo_idx, symbol, _role, _orig in PAIR_SPECS[1:]:
        if paired_effective_address(moved_words[hi_idx], moved_words[lo_idx]) != CONTROLLED_SYMBOLS[symbol]:
            raise ProbeError("FAIL", f"control B unexpectedly altered data pair {hi_idx}->{lo_idx} ({symbol})")
    if compare_table_entries(baseline_entries, moved_entries):
        raise ProbeError("FAIL", "control B altered the .text-relative jump-table entries")
    return differences


def validate_control_c(
    baseline_words: Sequence[int],
    mutated_words: Sequence[int],
    baseline_entries: Sequence[int],
    mutated_entries: Sequence[int],
    *,
    assigned_address: int = SHARED_DATA_ALTERNATE_ADDRESS,
) -> list[dict[str, object]]:
    """Control C (D_000047D0: 0x47D0 -> 0x47D4): both shared pairs change and reconstruct 0x47D4."""
    differences = compare_word_sequences(baseline_words, mutated_words)
    if [row["word_index"] for row in differences] != [24, 36]:
        raise ProbeError(
            "FAIL",
            "control C (shared D_000047D0 move) did not change exactly word indices [24, 36]",
        )
    eff_first = paired_effective_address(mutated_words[21], mutated_words[24])
    eff_second = paired_effective_address(mutated_words[33], mutated_words[36])
    if eff_first != assigned_address or eff_second != assigned_address:
        raise ProbeError(
            "FAIL",
            f"control C shared pairs reconstruct 0x{eff_first:x} and 0x{eff_second:x}, "
            f"expected 0x{assigned_address:x}",
        )
    if paired_effective_address(mutated_words[8], mutated_words[10]) != TABLE_ADDRESS:
        raise ProbeError("FAIL", "control C altered the jump-table address pair")
    if paired_effective_address(mutated_words[15], mutated_words[18]) != CONTROLLED_SYMBOLS["D_000047A4"]:
        raise ProbeError("FAIL", "control C altered D_000047A4")
    if paired_effective_address(mutated_words[27], mutated_words[30]) != CONTROLLED_SYMBOLS["D_00004800"]:
        raise ProbeError("FAIL", "control C altered D_00004800")
    if compare_table_entries(baseline_entries, mutated_entries):
        raise ProbeError("FAIL", "control C altered the jump-table entries")
    return differences


def validate_control_d(
    baseline_entries: Sequence[int],
    tampered_entries: Sequence[int],
    baseline_words: Sequence[int],
    tampered_words: Sequence[int],
    *,
    swapped_indices: tuple[int, int] = (0, 1),
) -> list[dict[str, object]]:
    """Control D: swapping two distinct table addends changes only those two table entries."""
    idx_a, idx_b = swapped_indices
    if baseline_entries[idx_a] == baseline_entries[idx_b]:
        raise ProbeError("FAIL", "control D requires two distinct baseline table entries to swap")
    differences = compare_table_entries(baseline_entries, tampered_entries)
    if [row["entry_index"] for row in differences] != [idx_a, idx_b]:
        raise ProbeError(
            "FAIL", f"control D table swap was not detected at exactly entries [{idx_a}, {idx_b}]"
        )
    if tampered_entries[idx_a] != baseline_entries[idx_b] or tampered_entries[idx_b] != baseline_entries[idx_a]:
        raise ProbeError("FAIL", "control D linked table entries do not match the swapped addends")
    if compare_word_sequences(baseline_words, tampered_words):
        raise ProbeError("FAIL", "control D altered the linked code words")
    return differences


def validate_control_e(
    baseline_words: Sequence[int],
    tampered_words: Sequence[int],
    baseline_entries: Sequence[int],
    tampered_entries: Sequence[int],
    *,
    word_index: int = 0,
    relocation_sites: dict[int, matching.RelocationSite],
) -> list[dict[str, object]]:
    """Control E: flipping one non-relocated word changes only that code word and no table entries."""
    differences = validate_nonrelocated_tamper(
        baseline_words, tampered_words, word_index=word_index, relocation_sites=relocation_sites
    )
    if compare_table_entries(baseline_entries, tampered_entries):
        raise ProbeError("FAIL", "control E altered the jump-table entries")
    return differences


def _function_symbol(module: elf.ElfFile, name: str = FUNCTION_NAME) -> elf.Symbol:
    symbols = [symbol for symbol in module.symbols if symbol.name == name]
    if len(symbols) != 1 or not symbols[0].is_function:
        raise ParseError(f"object must define one function symbol {name}")
    return symbols[0]


def _function_words(
    module: elf.ElfFile, start: int, size: int = FUNCTION_SIZE, *, label: str
) -> tuple[int, ...]:
    if size != FUNCTION_SIZE or start < 0:
        raise ParseError(f"{label} function interval is not exactly 0x{FUNCTION_SIZE:x} bytes")
    section = module.require_section(".text")
    section_offset = start - section.addr
    if section_offset < 0 or section_offset + size > section.size:
        raise ParseError(f"{label} function range is outside .text")
    words = mips.decode_words(
        module.section_data(section)[section_offset : section_offset + size], label
    )
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"{label} decoded {len(words)} words, expected {FUNCTION_WORDS}")
    return words


def validate_candidate_symbols(module: elf.ElfFile) -> None:
    """Require the exact undefined symbol set and defined @15 table symbol."""
    undefined = {
        symbol.name for symbol in module.symbols if symbol.name and symbol.shndx == elf.SHN_UNDEF
    }
    if undefined != set(CONTROLLED_SYMBOLS):
        raise ProbeError(
            "FAIL",
            f"candidate undefined symbols are {sorted(undefined)}, expected {sorted(CONTROLLED_SYMBOLS)}",
        )
    rodata_index = next(
        (idx for idx, section in enumerate(module.sections) if section.name == TABLE_SECTION), None
    )
    table_symbols = [symbol for symbol in module.symbols if symbol.name == TABLE_SYMBOL]
    if (
        rodata_index is None
        or len(table_symbols) != 1
        or table_symbols[0].shndx != rodata_index
        or table_symbols[0].value != 0
    ):
        raise ProbeError(
            "UNSUPPORTED",
            f"candidate object does not define {TABLE_SYMBOL} at offset 0 of {TABLE_SECTION}",
        )


def validate_candidate_text_inventory(
    module: elf.ElfFile,
    candidate_words: Sequence[int],
    *,
    candidate_offset: int = 0,
) -> tuple[matching.RelocationSiteMap, matching.Hi16Lo16Pairing]:
    """Validate the 15 .text relocations (5 R_MIPS_26 + 5 HI16/LO16 pairs)."""
    validate_candidate_symbols(module)
    sites = matching.relocation_sites(
        module.relocations_for(".text"), candidate_offset, FUNCTION_SIZE
    )
    if sites.limitations:
        raise ProbeError(
            "UNSUPPORTED",
            f"fresh candidate .text relocation placement has limitations: {sites.limitations}",
        )
    required_text_relocations = {
        *((elf.R_MIPS_26, idx, sym) for idx, _addr, sym, _tgt in CALL_SPECS),
        *((elf.R_MIPS_HI16, hi, sym) for hi, _lo, sym, _role, _tgt in PAIR_SPECS),
        *((elf.R_MIPS_LO16, lo, sym) for _hi, lo, sym, _role, _tgt in PAIR_SPECS),
    }
    actual_text_relocations = {
        (site.type, index, site.symbol) for index, site in sites.sites.items()
    }
    if actual_text_relocations != required_text_relocations:
        raise ProbeError(
            "UNSUPPORTED",
            f"fresh candidate .text relocation inventory differs from the contract: "
            f"{sorted(actual_text_relocations)}",
        )
    if any(not site.addend_valid or site.addend != 0 for site in sites.sites.values()):
        raise ProbeError("UNSUPPORTED", "candidate .text relocations must have zero in-place addends")
    pairing = matching.pair_hi16_lo16(sites.sites, candidate_words)
    if pairing.hi_to_lo != EXPECTED_PAIRS or pairing.limitations:
        raise ProbeError(
            "UNSUPPORTED",
            f"fresh candidate HI16/LO16 pairing is not proven: {pairing.hi_to_lo}, "
            f"limitations={pairing.limitations}",
        )
    for hi_index, lo_index, _symbol, _role, _target in PAIR_SPECS:
        try:
            paired_effective_address(candidate_words[hi_index], candidate_words[lo_index])
        except ParseError as exc:
            raise ProbeError(
                "UNSUPPORTED",
                f"fresh candidate HI16/LO16 instruction pair ({hi_index}->{lo_index}) is invalid: {exc}",
            ) from exc
    return sites, pairing


def candidate_table_relocations(
    module: elf.ElfFile, *, symbol: str = FUNCTION_NAME
) -> tuple[elf.Relocation, ...]:
    """Require exactly one R_MIPS_32 per entry, in order, against func_00000414."""
    section = module.section(TABLE_SECTION)
    if section is None:
        raise ProbeError("UNSUPPORTED", f"candidate object has no {TABLE_SECTION} section")
    if section.size != TABLE_SIZE:
        raise ProbeError(
            "UNSUPPORTED",
            f"candidate {TABLE_SECTION} size is 0x{section.size:x}, expected 0x{TABLE_SIZE:x}",
        )
    relocations = module.relocations_for(TABLE_SECTION)
    if len(relocations) != TABLE_ENTRIES:
        raise ProbeError(
            "UNSUPPORTED",
            f"candidate {TABLE_SECTION} has {len(relocations)} relocations, expected {TABLE_ENTRIES}",
        )
    ordered = tuple(sorted(relocations, key=lambda item: item.section_offset or 0))
    for index, relocation in enumerate(ordered):
        if relocation.section_offset != index * 4:
            raise ProbeError("UNSUPPORTED", "candidate table relocations are not one per 4-byte entry in order")
        if relocation.type != elf.R_MIPS_32:
            raise ProbeError(
                "UNSUPPORTED",
                f"candidate table relocation {index} is {relocation.type_name}, expected R_MIPS_32",
            )
        if relocation.symbol != symbol:
            raise ProbeError(
                "UNSUPPORTED",
                f"candidate table relocation {index} references {relocation.symbol!r}, expected {symbol!r}",
            )
    return ordered


def candidate_table_entries(
    module: elf.ElfFile, *, symbol: str = FUNCTION_NAME
) -> tuple[elf.Section, tuple[elf.Relocation, ...], tuple[int, ...]]:
    """Return the candidate table section, its validated relocations, and its in-place words."""
    relocations = candidate_table_relocations(module, symbol=symbol)
    section = module.require_section(TABLE_SECTION)
    words = mips.decode_words(module.section_data(section), "candidate table")
    if len(words) != TABLE_ENTRIES:
        raise ParseError(f"candidate table decoded {len(words)} words, expected {TABLE_ENTRIES}")
    return section, relocations, words


def validate_candidate_table_invariants(
    table_relocations: Sequence[elf.Relocation],
    table_words: Sequence[int],
) -> tuple[int, ...]:
    """Check content-independent structural invariants of the candidate jump table."""
    if any(not relocation.addend_valid for relocation in table_relocations):
        raise ProbeError("UNSUPPORTED", "invalid table relocation addend")
    addends = tuple(relocation.addend & 0xFFFFFFFF for relocation in table_relocations)
    if addends != tuple(table_words):
        raise ProbeError("FAIL", "table words disagree with relocation addends")
    if any(offset % 4 != 0 or offset >= FUNCTION_SIZE for offset in addends):
        raise ProbeError("FAIL", "table target is outside aligned function code")
    return addends


def validate_linked_structure(module: elf.ElfFile, *, label: str) -> elf.Section:
    """Require one executable section (.text at 0x414/0xa4), function symbol, and resolved .mwcats."""
    executable = tuple(
        section.name for section in module.sections if section.flags & mips.SHF_EXECINSTR
    )
    if executable != (".text",):
        raise ProbeError("FAIL", f"{label} executable sections are {list(executable)}, expected ['.text']")
    text = module.require_section(".text")
    if text.addr != FUNCTION_ADDRESS or text.size != FUNCTION_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} .text layout is {text.addr:#x}/{text.size:#x}, expected 0x{FUNCTION_ADDRESS:x}/0x{FUNCTION_SIZE:x}",
        )
    function = _function_symbol(module, FUNCTION_NAME)
    if function.value != FUNCTION_ADDRESS or function.size != FUNCTION_SIZE:
        raise ProbeError("FAIL", f"{label} function symbol is not at 0x{FUNCTION_ADDRESS:x}/0x{FUNCTION_SIZE:x}")
    mwcats = module.section(".mwcats")
    if mwcats is None or mwcats.size != 0x8:
        raise ProbeError("FAIL", f"{label} does not preserve the 8-byte .mwcats metadata")
    metadata = module.section_data(mwcats)
    if len(metadata) < 8 or int.from_bytes(metadata[4:8], "little") != FUNCTION_ADDRESS:
        raise ProbeError("FAIL", f"{label} .mwcats function pointer was not resolved to 0x{FUNCTION_ADDRESS:x}")
    return text


def validate_table_section(
    module: elf.ElfFile, *, table_address: int, label: str
) -> elf.Section:
    section = module.section(TABLE_SECTION)
    if section is None:
        raise ProbeError("UNSUPPORTED", f"{label} has no {TABLE_SECTION} section")
    if section.addr != table_address or section.size != TABLE_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} {TABLE_SECTION} layout is {section.addr:#x}/{section.size:#x}, "
            f"expected 0x{table_address:x}/0x{TABLE_SIZE:x}",
        )
    return section


def linked_table_entries(module: elf.ElfFile, *, table_address: int) -> tuple[int, ...]:
    section = validate_table_section(module, table_address=table_address, label="linked ELF")
    words = mips.decode_words(module.section_data(section), "linked table")
    if len(words) != TABLE_ENTRIES:
        raise ParseError(f"linked table decoded {len(words)} words, expected {TABLE_ENTRIES}")
    return words


def validate_linked_controlled_symbols(
    module: elf.ElfFile, controlled_symbols: dict[str, int]
) -> None:
    """Require every --defsym symbol to appear as an SHN_ABS symbol with its assigned address."""
    for name, expected_value in sorted(controlled_symbols.items()):
        matches = [symbol for symbol in module.symbols if symbol.name == name]
        if len(matches) != 1 or matches[0].value != expected_value or matches[0].shndx != elf.SHN_ABS:
            raise ProbeError(
                "FAIL", f"linked controlled symbol {name} does not equal its assignment 0x{expected_value:x}"
            )


def extract_original_string_evidence(
    module: elf.ElfFile,
    references: Sequence[datarefs.DataReference],
    words: Sequence[int],
) -> list[dict[str, object]]:
    """Verify location, bounds, NUL-termination and SHA-256 of the 3 PRX .data strings."""
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"expected {FUNCTION_WORDS} original words, got {len(words)}")
    rows: list[dict[str, object]] = []
    for symbol, section_name, offset, expected_address, max_end_offset, pair_indices in STRING_SPECS:
        section = module.section(section_name)
        if section is None or section.is_nobits:
            raise ProbeError("FAIL", f"original PRX section {section_name} is missing or NOBITS")
        if offset < 0 or max_end_offset > section.size or offset >= max_end_offset:
            raise ProbeError(
                "FAIL",
                f"original string {symbol} bounds [0x{offset:x}:0x{max_end_offset:x}) "
                f"exceed {section_name} size 0x{section.size:x}",
            )
        if section.addr + offset != expected_address:
            raise ProbeError(
                "FAIL",
                f"original string {symbol} at {section_name}+0x{offset:x} has address "
                f"0x{section.addr + offset:x}, expected 0x{expected_address:x}",
            )
        window = module.section_data(section)[offset:max_end_offset]
        nul_pos = window.find(b"\x00")
        if nul_pos <= 0:
            raise ProbeError(
                "FAIL",
                f"original string {symbol} at {section_name}+0x{offset:x} has no NUL terminator within bounds",
            )
        raw_without_nul, raw_with_nul = window[:nul_pos], window[: nul_pos + 1]
        if not all(0x20 <= byte <= 0x7E for byte in raw_without_nul):
            raise ProbeError(
                "FAIL",
                f"original string {symbol} at {section_name}+0x{offset:x} contains non-printable bytes",
            )
        for hi_idx, lo_idx in pair_indices:
            hi_addr, lo_addr = FUNCTION_ADDRESS + hi_idx * 4, FUNCTION_ADDRESS + lo_idx * 4
            ref = next(
                (
                    item
                    for item in references
                    if item.kind == "hi16-lo16"
                    and item.instruction == lo_addr
                    and len(item.relocations) == 2
                    and item.relocations[0].application_offset == hi_addr
                    and item.relocations[1].application_offset == lo_addr
                ),
                None,
            )
            if (
                ref is None
                or ref.target is None
                or ref.status != "PROVEN"
                or ref.location != "PROVEN"
                or ref.pairing != "PROVEN"
                or ref.target.section != section_name
                or ref.target.offset != offset
            ):
                raise ProbeError("FAIL", f"original PRX string reference {symbol} at {hi_idx}->{lo_idx} is not proven")
            if datarefs.data_target_details(module, ref.target) is None:
                raise ProbeError("FAIL", f"original PRX string target {symbol} has no file mapping")
            effective = paired_effective_address(words[hi_idx], words[lo_idx])
            if effective != expected_address:
                raise ProbeError(
                    "FAIL",
                    f"original HI16/LO16 pair {hi_idx}->{lo_idx} reconstructs 0x{effective:x}, "
                    f"expected 0x{expected_address:x}",
                )
        rows.append(
            {
                "candidate_symbol": symbol,
                "original_section": section_name,
                "original_section_offset": f"0x{offset:x}",
                "original_address": f"0x{expected_address:x}",
                "file_offset": f"0x{section.offset + offset:x}",
                "byte_length_without_nul": len(raw_without_nul),
                "byte_length_with_nul": len(raw_with_nul),
                "end_section_offset_exclusive": f"0x{offset + len(raw_with_nul):x}",
                "nul_terminated": True,
                "printable_ascii": True,
                "within_section_bounds": True,
                "non_overlapping": True,
                "sha256_without_nul": hashlib.sha256(raw_without_nul).hexdigest(),
                "sha256_with_nul": hashlib.sha256(raw_with_nul).hexdigest(),
                "referenced_by_pairs": [
                    {
                        "hi_index": hi_idx,
                        "lo_index": lo_idx,
                        "hi_address": f"0x{FUNCTION_ADDRESS + hi_idx * 4:x}",
                        "lo_address": f"0x{FUNCTION_ADDRESS + lo_idx * 4:x}",
                    }
                    for hi_idx, lo_idx in pair_indices
                ],
                "reference_count": len(pair_indices),
                "shared_reference": len(pair_indices) > 1,
                "address_resolution": "CONTROLLED",
                "candidate_string_bytes_proven": False,
                "cross_artifact_identity": "UNPROVEN",
                "runtime_comparison": "NOT_DEMONSTRATED",
            }
        )
    return rows


def _original_table_and_strings_evidence(
    module: elf.ElfFile, words: tuple[int, ...]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    references = datarefs.recover_references(
        module, ".text", FUNCTION_ADDRESS, FUNCTION_ADDRESS + FUNCTION_SIZE
    )
    hi_lo_refs = [item for item in references if item.kind == "hi16-lo16"]
    if len(hi_lo_refs) != len(PAIR_SPECS):
        raise ProbeError(
            "FAIL", f"expected {len(PAIR_SPECS)} original HI16/LO16 references, got {len(hi_lo_refs)}"
        )
    table_ref = next(
        (
            item
            for item in hi_lo_refs
            if item.instruction == FUNCTION_ADDRESS + 10 * 4
            and len(item.relocations) == 2
            and item.relocations[0].application_offset == FUNCTION_ADDRESS + 8 * 4
            and item.relocations[1].application_offset == FUNCTION_ADDRESS + 10 * 4
        ),
        None,
    )
    if (
        table_ref is None
        or table_ref.target is None
        or table_ref.status != "PROVEN"
        or table_ref.location != "PROVEN"
        or table_ref.pairing != "PROVEN"
        or table_ref.target.section != TABLE_ORIGINAL_SECTION
        or table_ref.target.offset != TABLE_ORIGINAL_OFFSET
    ):
        raise ProbeError("FAIL", "original PRX jump-table reference at 8->10 is not proven")
    details = datarefs.data_target_details(module, table_ref.target)
    if details is None:
        raise ProbeError("FAIL", "original PRX jump-table target has no validated file mapping")
    section = module.require_section(TABLE_ORIGINAL_SECTION)
    if section.is_nobits or TABLE_ORIGINAL_OFFSET + TABLE_SIZE > section.size:
        raise ProbeError("FAIL", "original jump-table bytes are not fully file-backed")
    table_bytes = module.section_data(section)[
        TABLE_ORIGINAL_OFFSET : TABLE_ORIGINAL_OFFSET + TABLE_SIZE
    ]
    entries = tuple(mips.decode_words(table_bytes, "original jump table"))
    if len(entries) != TABLE_ENTRIES:
        raise ParseError("original jump table is not seven entries")
    pair_address = paired_effective_address(words[8], words[10])
    if pair_address != TABLE_ADDRESS:
        raise ProbeError(
            "FAIL", f"original HI16/LO16 pair 8->10 reconstructs 0x{pair_address:x}, expected 0x4788"
        )
    table_evidence: dict[str, object] = {
        "reference": table_ref.summary(),
        "target": details,
        "table_bytes_hex": table_bytes.hex(),
        "table_bytes_sha256": hashlib.sha256(table_bytes).hexdigest(),
        "entries": [f"0x{value:08x}" for value in entries],
        "module_relative_address": f"0x{pair_address:x}",
        "entries_match_recorded_baseline": entries == EXPECTED_TARGETS,
        "candidate_identity_proven": False,
    }
    return table_evidence, extract_original_string_evidence(module, hi_lo_refs, words)


def _original_calls_evidence(module: elf.ElfFile) -> list[dict[str, object]]:
    table = imports.build_import_table(module)
    references = imports.call_references(
        module, table, section=".text", start=FUNCTION_ADDRESS, end=FUNCTION_ADDRESS + FUNCTION_SIZE
    )
    if len(references) != len(CALL_SPECS):
        raise ProbeError("FAIL", f"expected {len(CALL_SPECS)} original call sites, got {len(references)}")
    rows: list[dict[str, object]] = []
    for word_index, site_address, symbol, expected_target in CALL_SPECS:
        ref = next((item for item in references if item.address == site_address), None)
        if ref is None or ref.kind != "import" or ref.imported is None:
            raise ProbeError("FAIL", f"original call site 0x{site_address:x} is not a resolved PRX import")
        if ref.target != expected_target:
            raise ProbeError(
                "FAIL",
                f"original call target at 0x{site_address:x} is 0x{ref.target:x}, expected 0x{expected_target:x}",
            )
        rows.append(
            {
                "word_index": word_index,
                "call_site": f"0x{site_address:x}",
                "candidate_symbol": symbol,
                "original_stub_address": f"0x{ref.target:x}",
                "original_import": ref.imported.summary(),
                "assignment_kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB",
                "candidate_symbol_identity_independently_proven": False,
            }
        )
    return rows


def _psp_region_relocations(
    module: elf.ElfFile,
    section_name: str,
    *,
    section_offset: int,
    size: int,
    words: tuple[int, ...],
    load_base: int = 0,
) -> dict[str, object]:
    """Model the original region's PSP relocations in module-relative coordinates."""
    section = module.require_section(section_name)
    relocations = module.relocations_for(section_name)
    sites = matching.relocation_sites(relocations, section_offset, size)
    if sites.limitations:
        raise ProbeError("UNSUPPORTED", f"{section_name} relocation placement has limitations: {sites.limitations}")
    pairing = matching.pair_hi16_lo16(sites.sites, words)
    if pairing.limitations:
        raise ProbeError("UNSUPPORTED", f"{section_name} HI16/LO16 pairing has limitations: {pairing.limitations}")
    rows = []
    for index, site in sorted(sites.sites.items()):
        relocation = next(
            item for item in relocations if item.section_offset == section_offset + index * 4
        )
        if relocation.format != "PSP":
            raise ProbeError("FAIL", "expected the original PRX relocations to use PSP format")
        relative_base = psp_reloc.relative_base(module, relocation, load_base=load_base)
        if relative_base is None:
            raise ProbeError(
                "UNSUPPORTED", f"PSP relocation at 0x{relocation.offset:x} has no loadable relative segment"
            )
        lo16_word = words[pairing.hi_to_lo[index]] if index in pairing.hi_to_lo else None
        applied = psp_reloc.apply_relocation(site.type, words[index], relative_base, lo16_word=lo16_word)
        if applied is None:
            raise ProbeError("UNSUPPORTED", f"PSP relocation type {site.type_name} is not modeled")
        rows.append(
            {
                "site": f"0x{section.addr + section_offset + index * 4:x}",
                "type": site.type_name,
                "segment_index": relocation.segment_index,
                "relative_index": relocation.relative_index,
                "module_relative_base_load0": f"0x{relative_base:x}",
                "raw_word": f"0x{words[index]:08x}",
                "module_relative_applied_word": f"0x{applied:08x}",
                "actual_runtime_load_base_known": False,
            }
        )
    return {
        "section": section_name,
        "coordinate_system": "on-disk PRX/module-relative; no actual runtime base inferred",
        "load_base_zero_is_model_only": True,
        "relocations": rows,
        "runtime_comparison": "NOT_DEMONSTRATED",
    }


def _linker_script(table_address: int = TABLE_ADDRESS) -> str:
    """Return the controlled linker script for func_00000414 and its 7-entry jump table."""
    return f'''OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(func_00000414)

SECTIONS
{{
  .mwcats 0 : SUBALIGN(4) {{ KEEP(*(.mwcats)) }}
  .comment 0 : {{ *(.comment) }}
  .text 0x414 : SUBALIGN(4) {{ *(.text) }}
  .rodata 0x{table_address:x} : SUBALIGN(4) {{ *(.rodata) }}
}}

ASSERT(ADDR(.text) == 0x414, "wrong text address")
ASSERT(SIZEOF(.text) == 0xA4, "wrong function size")
ASSERT(ADDR(.rodata) == 0x{table_address:x}, "wrong table address")
ASSERT(SIZEOF(.rodata) == 0x1C, "wrong table size")
ASSERT(func_00000414 == 0x414, "wrong function symbol")
ASSERT(SIZEOF(.mwcats) == 0x8, "Metrowerks .mwcats metadata must be retained")
'''


def _link(
    *,
    object_path: Path,
    script_path: Path,
    output_path: Path,
    table_address: int,
    controlled_symbols: dict[str, int],
    logs_dir: Path,
    label: str,
) -> tuple[elf.ElfFile, dict[str, object]]:
    build_root = _validated_build_root()
    prepare_build_file(output_path, build_root)
    definitions = [
        f"--defsym={symbol}=0x{address:x}"
        for symbol, address in sorted(controlled_symbols.items())
    ]
    args = [
        LINKER,
        "-m",
        "elf32ltsmip",
        "-T",
        relative(script_path, REPO_ROOT),
        *definitions,
        "-o",
        relative(output_path, REPO_ROOT),
        relative(object_path, REPO_ROOT),
    ]
    result = run(args, cwd=REPO_ROOT, timeout=120)
    write_build_text(logs_dir / f"{label}.ld.stdout.txt", result.stdout, build_root)
    write_build_text(logs_dir / f"{label}.ld.stderr.txt", result.stderr, build_root)
    command_info: dict[str, object] = {"argv": args, "returncode": result.returncode}
    if result.returncode != 0:
        raise ProbeError("FAIL", f"GNU MIPSel link {label} failed: {result.stderr.strip()}")

    linked = elf.parse(output_path)
    require_mips_elf(linked, file_type=elf.ET_EXEC, label=f"linked ELF {label}")
    validate_linked_structure(linked, label=f"linked ELF {label}")
    validate_table_section(linked, table_address=table_address, label=f"linked ELF {label}")
    validate_link_has_no_unresolved(linked)
    validate_linked_controlled_symbols(linked, controlled_symbols)

    rel_out = relative(output_path, REPO_ROOT)
    for exe, flag_args, suffix in (
        (READELF, ["-hWr", "-s", rel_out], "readelf"),
        (OBJDUMP, ["-dr", rel_out], "objdump"),
        (FILE, [rel_out], "file"),
    ):
        insp = run([exe, *flag_args], cwd=REPO_ROOT, timeout=60)
        write_build_text(logs_dir / f"{label}.{suffix}.stderr.txt", insp.stderr, build_root)
        if insp.returncode != 0:
            raise ProbeError("FAIL", f"{exe} failed ({insp.returncode}): {insp.stderr.strip()}")
        write_build_text(logs_dir / f"{label}.{suffix}.txt", insp.stdout, build_root)
    return linked, command_info


def _linked_projection(
    original_words: tuple[int, ...],
    original_entries: tuple[int, ...],
    linked: elf.ElfFile,
    *,
    label: str,
    table_address: int,
    controlled_symbols: dict[str, int],
) -> dict[str, object]:
    text = linked.require_section(".text")
    words = mips.decode_words(linked.section_data(text), f"linked {label}")
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"linked {label} .text has {len(words)} words, expected {FUNCTION_WORDS}")
    entries = linked_table_entries(linked, table_address=table_address)
    assigned_targets = {TABLE_SYMBOL: table_address, **controlled_symbols}
    pair_rows = reconstruct_hi16_lo16_pairs(original_words, words, assigned_targets=assigned_targets)
    validate_hi16_lo16_pairs(pair_rows)
    call_rows = reconstruct_call_sites(original_words, words, assigned_targets=controlled_symbols)
    validate_call_sites(call_rows)
    code_differences = compare_word_sequences(original_words, words)
    table_differences = compare_table_entries(original_entries, entries)
    return {
        "elf_header": linked.header.summary(),
        "text_section": text.summary(),
        "table_section": linked.require_section(TABLE_SECTION).summary(),
        "assigned_table_address": f"0x{table_address:x}",
        "controlled_symbols": {
            symbol: f"0x{address:x}" for symbol, address in sorted(controlled_symbols.items())
        },
        "linked_words": [f"0x{word:08x}" for word in words],
        "equal_words": FUNCTION_WORDS - len(code_differences),
        "total_words": FUNCTION_WORDS,
        "differences": code_differences,
        "hi16_lo16_pairs": pair_rows,
        "calls": call_rows,
        "linked_entries": [f"0x{value:08x}" for value in entries],
        "entry_destinations": entry_destination_rows(entries),
        "equal_entries": TABLE_ENTRIES - len(table_differences),
        "total_entries": TABLE_ENTRIES,
        "table_differences": table_differences,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prx",
        type=Path,
        default=Path("private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"),
    )
    parser.add_argument("--source", type=Path, default=Path("decomp/src/func_00000414.c"))
    parser.add_argument("--config", type=Path, default=Path("config/wsl/seto.toml"))
    parser.add_argument("--build-dir", type=Path, default=Path("build/seto016/experiment"))
    parser.add_argument(
        "--out", type=Path, default=Path("build/seto016/multi-reference-equivalence.json")
    )
    return parser


def _validate_arguments(
    arguments: argparse.Namespace,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    build_root = _validated_build_root()
    build_dir = repo_path(arguments.build_dir, repo_root=REPO_ROOT, allowed_root=build_root)
    out = repo_path(arguments.out, repo_root=REPO_ROOT, allowed_root=build_root)
    prx = repo_path(arguments.prx, repo_root=REPO_ROOT, allowed_root=(REPO_ROOT / "private").resolve())
    source = repo_path(
        arguments.source, repo_root=REPO_ROOT, allowed_root=(REPO_ROOT / "decomp/src").resolve()
    )
    config = repo_path(arguments.config, repo_root=REPO_ROOT, allowed_root=(REPO_ROOT / "config").resolve())
    if source != (REPO_ROOT / "decomp/src/func_00000414.c").resolve():
        raise ProbeError("FAIL", "SETO-DECOMP-016 only accepts the authorized func_00000414.c source")
    for label, path in (("PRX", prx), ("source", source), ("config", config)):
        if not path.is_file():
            raise ProbeError("BLOCKED", f"{label} file is unavailable")
    return build_root, build_dir, out, prx, source, config


def finalize_experiment_report(report: dict[str, object]) -> int:
    """Set the terminal classification of a built report and return the exit code."""
    code, table = report["code"], report["jump_table"]
    code_equal = (
        code.get("equal_words") == FUNCTION_WORDS
        and code.get("total_words") == FUNCTION_WORDS
        and not code.get("differences")
    )
    table_equal = (
        table.get("equal_entries") == TABLE_ENTRIES
        and table.get("entry_count") == TABLE_ENTRIES
        and not table.get("differences")
    )
    report["original_match_status"] = matching.INCONCLUSIVE
    report["independent_identity_proven"] = False
    report["promoted_to_matched"] = False
    report["equivalence_claim"] = equivalence_claim(
        code.get("equal_words") if code_equal else 0,
        table.get("equal_entries") if table_equal else 0,
        code_differences=code.get("differences") or (),
        table_differences=table.get("differences") or (),
    )
    if code_equal and table_equal:
        report["experiment_status"] = "PASS"
        return 0
    report["experiment_status"] = "DIVERGENCE"
    return DIVERGENCE_EXIT_CODE


def not_run_controls() -> dict[str, dict[str, object]]:
    """Baseline-dependent controls (C, D, E), recorded when A diverges from the PRX."""
    return {
        label: {
            "status": "NOT_RUN",
            "reason": "baseline comparison diverged",
            "detected": False,
            "promoted_to_matched": False,
        }
        for label in ("C", "D", "E")
    }


def _base_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "experiment_status": "FAIL",
        "function": FUNCTION_NAME,
        "function_address": f"0x{FUNCTION_ADDRESS:x}",
        "function_size_bytes": FUNCTION_SIZE,
        "original_match_status": matching.INCONCLUSIVE,
        "baseline": {
            "status": matching.INCONCLUSIVE,
            "matching_words": BASELINE_MATCHING_WORDS,
            "total_words": FUNCTION_WORDS,
        },
        "code": {"equal_words": None, "total_words": FUNCTION_WORDS, "differences": []},
        "jump_table": {
            "original_address": f"0x{TABLE_ADDRESS:x}",
            "entry_count": TABLE_ENTRIES,
            "equal_entries": None,
            "differences": [],
            "layout_assignment": "CONTROLLED",
        },
        "strings": {
            "address_resolution": "CONTROLLED",
            "candidate_string_bytes_proven": False,
            "cross_artifact_identity": "UNPROVEN",
            "runtime_comparison": "NOT_DEMONSTRATED",
            "items": [],
        },
        "independent_identity_proven": False,
        "equivalence_claim": "NONE",
        "promoted_to_matched": False,
    }


def _toolchain_versions(
    config_path: Path, logs_dir: Path, build_root: Path, env: dict[str, str]
) -> tuple[str, str, str]:
    linker_version_result = run([LINKER, "--version"], cwd=REPO_ROOT, timeout=30)
    linker_emulation_result = run([LINKER, "-V"], cwd=REPO_ROOT, timeout=30)
    if linker_version_result.returncode != 0 or linker_emulation_result.returncode != 0:
        raise ProbeError("BLOCKED", "GNU MIPSel linker version/emulation probe failed")
    linker_version = linker_version_result.stdout.splitlines()[0]
    if "elf32ltsmip" not in linker_emulation_result.stdout:
        raise ProbeError("UNSUPPORTED", "GNU linker does not expose elf32ltsmip emulation")

    toolchain_result = run(
        [sys.executable, "-m", "seto", "--config", relative(config_path, REPO_ROOT), "toolchain"],
        cwd=REPO_ROOT,
        timeout=120,
        env=env,
    )
    write_build_text(logs_dir / "seto-toolchain.stdout.txt", toolchain_result.stdout, build_root)
    write_build_text(logs_dir / "seto-toolchain.stderr.txt", toolchain_result.stderr, build_root)
    mw_version = wibo_version = None
    for line in toolchain_result.stdout.splitlines():
        if line.lstrip().startswith("mwccpsp") and (
            found := re.search(r"\bVersion\s+([0-9.]+\s+build\s+\d+)", line)
        ):
            mw_version = f"Metrowerks {found.group(1)}"
        elif line.lstrip().startswith("wibo") and (found := re.search(r"\bwibo\s+([0-9.]+)", line)):
            wibo_version = f"wibo {found.group(1)}"
    if mw_version is None or wibo_version is None:
        raise ProbeError(
            "BLOCKED", "Seto toolchain inventory could not confirm configured Metrowerks/wibo versions"
        )
    return linker_version, mw_version, wibo_version


def run_experiment(arguments: argparse.Namespace) -> tuple[int, dict[str, object]]:
    report = _base_report()
    build_root, build_dir, out, prx_path, source_path, config_path = _validate_arguments(arguments)
    if not all(shutil.which(tool) for tool in (LINKER, READELF, OBJDUMP, FILE)):
        report["experiment_status"] = "BLOCKED"
        report["error"] = "required GNU MIPSel link/inspection executable is missing"
        ensure_build_dir(out.parent, build_root)
        write_build_text(out, canonical_json(report), build_root)
        return 4, report

    logs_dir, candidate_dir, links_dir = (
        build_dir / "logs",
        build_dir / "candidate",
        build_dir / "links",
    )
    for directory in (build_dir, logs_dir, candidate_dir, links_dir):
        ensure_build_dir(directory, build_root)

    match_record_path = candidate_dir / "match-record.json"
    object_path = candidate_dir / f"{source_path.stem}.o"
    for path in (match_record_path, object_path):
        prepare_build_file(path, build_root)
        path.unlink(missing_ok=True)

    source_hash_before, prx_hash_before = sha256_file(source_path), sha256_file(prx_path)
    script_paths: dict[str, Path] = {}
    for case, table_address in (("A", TABLE_ADDRESS), ("B", TABLE_ALTERNATE_ADDRESS)):
        script_path = build_dir / f"controlled-link-{case.lower()}.ld"
        write_build_text(script_path, _linker_script(table_address), build_root)
        script_paths[case] = script_path

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    match_command = [
        sys.executable,
        "scripts/match_function.py",
        "--config",
        relative(config_path, REPO_ROOT),
        "--prx",
        relative(prx_path, REPO_ROOT),
        "--function",
        hex(FUNCTION_ADDRESS),
        "--source",
        relative(source_path, REPO_ROOT),
        "--out",
        relative(candidate_dir, REPO_ROOT),
        "--report",
        relative(match_record_path, REPO_ROOT),
        "--json",
    ]
    match_result = run(match_command, cwd=REPO_ROOT, timeout=600, env=env)
    write_build_text(logs_dir / "match-function.stdout.json", match_result.stdout, build_root)
    write_build_text(logs_dir / "match-function.stderr.txt", match_result.stderr, build_root)
    if match_result.returncode == 4:
        report["experiment_status"] = "BLOCKED"
        report["error"] = "match_function reports the Metrowerks compiler or loader unavailable"
        ensure_build_dir(out.parent, build_root)
        write_build_text(out, canonical_json(report), build_root)
        return 4, report
    if match_result.returncode != 5:
        raise ProbeError(
            "FAIL", f"fresh match_function run exited {match_result.returncode}, expected 5/INCONCLUSIVE"
        )
    try:
        match_record = json.loads(match_result.stdout)
    except json.JSONDecodeError as exc:
        raise ProbeError("FAIL", f"match_function did not emit valid JSON: {exc}") from exc
    payload = match_record.get("match")
    if (
        not isinstance(payload, dict)
        or match_record.get("status") != matching.INCONCLUSIVE
        or payload.get("status") != matching.INCONCLUSIVE
        or payload.get("matching_words") != BASELINE_MATCHING_WORDS
        or payload.get("total_words") != FUNCTION_WORDS
        or payload.get("difference_count") != 0
        or payload.get("relocation_issues")
    ):
        raise ProbeError(
            "FAIL",
            f"fresh compile does not match the required {BASELINE_MATCHING_WORDS}/{FUNCTION_WORDS} INCONCLUSIVE baseline",
        )
    if not object_path.is_file() or not match_record_path.is_file():
        raise ProbeError("FAIL", "fresh match_function run did not produce both object and provenance report")
    validate_saved_match_record(
        match_record, json.loads(match_record_path.read_text(encoding="utf-8"))
    )
    provenance = match_record["provenance"]
    if (
        match_record.get("function") != FUNCTION_NAME
        or match_record.get("address") != hex(FUNCTION_ADDRESS)
        or match_record.get("section") != ".text"
        or provenance.get("source") != relative(source_path, REPO_ROOT)
        or provenance.get("object") != relative(object_path, REPO_ROOT)
    ):
        raise ProbeError("FAIL", "match_function provenance does not identify this fresh 0x414 compile")

    object_hash, source_hash, prx_hash = (
        sha256_file(object_path),
        sha256_file(source_path),
        sha256_file(prx_path),
    )
    if source_hash != source_hash_before or prx_hash != prx_hash_before:
        raise ProbeError("FAIL", "source or PRX changed during fresh compile/match execution")
    validate_recorded_hash("candidate object", object_hash, provenance.get("object_sha256"))
    validate_recorded_hash("candidate source", source_hash, provenance.get("source_sha256"))
    if provenance.get("flags") != ["-O4,p", "-sdatathreshold", "0"]:
        raise ProbeError("FAIL", f"unexpected compiler flags: {provenance.get('flags')}")

    original, candidate = elf.parse(prx_path), elf.parse(object_path)
    require_mips_elf(original, file_type=elf.ET_MIPS_PSP_PRX, label="original PRX")
    require_mips_elf(candidate, file_type=elf.ET_REL, label="fresh Metrowerks object")
    original_words = _function_words(original, FUNCTION_ADDRESS, FUNCTION_SIZE, label="original PRX")

    candidate_symbol = _function_symbol(candidate, FUNCTION_NAME)
    if not candidate_symbol.is_defined or candidate_symbol.size != FUNCTION_SIZE:
        raise ProbeError("FAIL", "fresh candidate function symbol is undefined or has the wrong size")
    candidate_text = candidate.require_section(".text")
    if candidate_symbol.value != 0 or candidate_text.size != FUNCTION_SIZE:
        raise ProbeError(
            "UNSUPPORTED",
            "fresh candidate .text must contain exactly the target function at section offset zero",
        )
    if candidate.section(".mwcats") is None:
        raise ProbeError("UNSUPPORTED", "fresh Metrowerks object has no .mwcats metadata section")

    candidate_offset = candidate_symbol.value
    candidate_words = _function_words(candidate, candidate_offset, FUNCTION_SIZE, label="fresh candidate")
    candidate_sites, _pairing = validate_candidate_text_inventory(
        candidate, candidate_words, candidate_offset=candidate_offset
    )
    table_section, table_relocations, table_words = candidate_table_entries(candidate, symbol=FUNCTION_NAME)
    addends = validate_candidate_table_invariants(table_relocations, table_words)

    original_table, original_strings = _original_table_and_strings_evidence(original, original_words)
    original_entries = tuple(int(value, 16) for value in original_table["entries"])
    original_calls = _original_calls_evidence(original)
    psp_text = _psp_region_relocations(
        original,
        ".text",
        section_offset=FUNCTION_ADDRESS - original.require_section(".text").addr,
        size=FUNCTION_SIZE,
        words=original_words,
    )
    psp_table = _psp_region_relocations(
        original,
        TABLE_ORIGINAL_SECTION,
        section_offset=TABLE_ORIGINAL_OFFSET,
        size=TABLE_SIZE,
        words=original_entries,
    )

    linker_version, mw_version, wibo_version = _toolchain_versions(config_path, logs_dir, build_root, env)
    script_hashes = {case: sha256_file(path) for case, path in script_paths.items()}

    variants: dict[str, dict[str, object]] = {}
    link_commands: dict[str, dict[str, object]] = {}
    for case, table_address in (("A", TABLE_ADDRESS), ("B", TABLE_ALTERNATE_ADDRESS)):
        variant_dir = links_dir / f"case-{case.lower()}"
        ensure_build_dir(variant_dir, build_root)
        output_path = variant_dir / "linked.elf"
        linked, command_info = _link(
            object_path=object_path,
            script_path=script_paths[case],
            output_path=output_path,
            table_address=table_address,
            controlled_symbols=CONTROLLED_SYMBOLS,
            logs_dir=logs_dir,
            label=f"case-{case.lower()}",
        )
        link_commands[case] = command_info
        projection = _linked_projection(
            original_words,
            original_entries,
            linked,
            label=f"case {case}",
            table_address=table_address,
            controlled_symbols=CONTROLLED_SYMBOLS,
        )
        projection["linked_elf_path"] = relative(output_path, REPO_ROOT)
        projection["linked_elf_sha256"] = sha256_file(output_path)
        variants[case] = projection

    baseline = variants["A"]
    baseline_entries = tuple(int(value, 16) for value in baseline["linked_entries"])
    validate_structural_destinations(baseline_entries)
    resolved_entries = tuple(FUNCTION_ADDRESS + addend for addend in addends)
    if resolved_entries != baseline_entries:
        raise ProbeError("FAIL", "linked table differs from candidate relocation resolution")

    a_words = tuple(int(word, 16) for word in variants["A"]["linked_words"])
    b_words = tuple(int(word, 16) for word in variants["B"]["linked_words"])
    b_entries = tuple(int(value, 16) for value in variants["B"]["linked_entries"])
    b_vs_a = validate_control_b(
        a_words, b_words, baseline_entries, b_entries, assigned_address=TABLE_ALTERNATE_ADDRESS
    )

    code_equal = baseline["equal_words"] == FUNCTION_WORDS and not baseline["differences"]
    table_equal = baseline["equal_entries"] == TABLE_ENTRIES and not baseline["table_differences"]
    baseline_equal = code_equal and table_equal

    control_records: dict[str, dict[str, object]] = {
        "A": {
            "status": "PASS" if baseline_equal else "DIVERGENCE",
            "mutation": "none (controlled baseline layout and symbol assignments)",
            "equal_words": baseline["equal_words"],
            "equal_entries": baseline["equal_entries"],
            "differences": baseline["differences"],
            "table_differences": baseline["table_differences"],
            "promoted_to_matched": False,
        },
        "B": {
            "status": "PASS",
            "mutation_stage": "linker_script_layout",
            "mutation": f"moved {TABLE_SECTION} from 0x{TABLE_ADDRESS:x} to 0x{TABLE_ALTERNATE_ADDRESS:x}",
            "assigned_table_address": f"0x{TABLE_ALTERNATE_ADDRESS:x}",
            "effective_table_address": f"0x{paired_effective_address(b_words[8], b_words[10]):x}",
            "differences_vs_a": b_vs_a,
            "equal_entries_vs_a": TABLE_ENTRIES,
            "detected": True,
            "promoted_to_matched": False,
        },
    }

    if baseline_equal:
        # Control C: move shared symbol D_000047D0 from 0x47D0 to 0x47D4 via --defsym.
        c_symbols = {**CONTROLLED_SYMBOLS, SHARED_DATA_SYMBOL: SHARED_DATA_ALTERNATE_ADDRESS}
        c_dir = links_dir / "control-c-shared-symbol"
        ensure_build_dir(c_dir, build_root)
        c_output_path = c_dir / "linked.elf"
        c_linked, c_command_info = _link(
            object_path=object_path,
            script_path=script_paths["A"],
            output_path=c_output_path,
            table_address=TABLE_ADDRESS,
            controlled_symbols=c_symbols,
            logs_dir=logs_dir,
            label="control-c-shared-symbol",
        )
        c_projection = _linked_projection(
            original_words,
            original_entries,
            c_linked,
            label="control C",
            table_address=TABLE_ADDRESS,
            controlled_symbols=c_symbols,
        )
        c_words = tuple(int(word, 16) for word in c_projection["linked_words"])
        c_entries = tuple(int(value, 16) for value in c_projection["linked_entries"])
        c_differences = validate_control_c(
            a_words, c_words, baseline_entries, c_entries, assigned_address=SHARED_DATA_ALTERNATE_ADDRESS
        )
        control_records["C"] = {
            "status": "PASS",
            "mutation_stage": "controlled_defsym_assignment",
            "mutation": (
                f"reassigned shared symbol {SHARED_DATA_SYMBOL} "
                f"from 0x{CONTROLLED_SYMBOLS[SHARED_DATA_SYMBOL]:x} to 0x{SHARED_DATA_ALTERNATE_ADDRESS:x}"
            ),
            "symbol": SHARED_DATA_SYMBOL,
            "assigned_address": f"0x{SHARED_DATA_ALTERNATE_ADDRESS:x}",
            "affected_pairs": ["21->24", "33->36"],
            "affected_word_indices": [24, 36],
            "linked_elf_path": relative(c_output_path, REPO_ROOT),
            "linked_elf_sha256": sha256_file(c_output_path),
            "link_command": c_command_info,
            "differences": c_differences,
            "equal_words": c_projection["equal_words"],
            "equal_entries": c_projection["equal_entries"],
            "detected": True,
            "promoted_to_matched": False,
        }

        object_bytes = bytearray(object_path.read_bytes())
        table_file_offset = table_section.offset

        def _tampered_object(label: str, mutations: list[tuple[int, int]]) -> tuple[Path, elf.ElfFile]:
            data = bytearray(object_bytes)
            for offset, value in mutations:
                data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")
            path = build_dir / f"tampered-{label}.o"
            write_build_bytes(path, bytes(data), build_root)
            module = elf.parse(path)
            sites = matching.relocation_sites(
                module.relocations_for(".text"), candidate_offset, FUNCTION_SIZE
            )
            if sites.sites != candidate_sites.sites:
                raise ProbeError("FAIL", f"control {label} changed the .text relocation inventory")
            relocations = candidate_table_relocations(module, symbol=FUNCTION_NAME)
            if tuple((r.type, r.section_offset, r.symbol) for r in relocations) != tuple(
                (r.type, r.section_offset, r.symbol) for r in table_relocations
            ):
                raise ProbeError("FAIL", f"control {label} changed the table relocation inventory")
            return path, module

        def _link_tampered(label: str, tampered_object_path: Path) -> dict[str, object]:
            variant_dir = links_dir / f"control-{label}"
            ensure_build_dir(variant_dir, build_root)
            output_path = variant_dir / "linked.elf"
            linked_elf, cmd_info = _link(
                object_path=tampered_object_path,
                script_path=script_paths["A"],
                output_path=output_path,
                table_address=TABLE_ADDRESS,
                controlled_symbols=CONTROLLED_SYMBOLS,
                logs_dir=logs_dir,
                label=f"control-{label}",
            )
            proj = _linked_projection(
                original_words,
                original_entries,
                linked_elf,
                label=f"control {label}",
                table_address=TABLE_ADDRESS,
                controlled_symbols=CONTROLLED_SYMBOLS,
            )
            proj["linked_elf_path"] = relative(output_path, REPO_ROOT)
            proj["linked_elf_sha256"] = sha256_file(output_path)
            proj["link_command"] = cmd_info
            return proj

        # Control D: swap distinct in-place addends of table entries 0 (0x3c) and 1 (0x54).
        d_path, _d_module = _tampered_object(
            "d-swap-entries", [(table_file_offset + 0, addends[1]), (table_file_offset + 4, addends[0])]
        )
        d_projection = _link_tampered("d-swap-entries", d_path)
        d_words = tuple(int(word, 16) for word in d_projection["linked_words"])
        d_entries = tuple(int(value, 16) for value in d_projection["linked_entries"])
        d_differences = validate_control_d(
            original_entries, d_entries, a_words, d_words, swapped_indices=(0, 1)
        )
        control_records["D"] = {
            "status": "PASS",
            "mutation_stage": "pre_link_object_copy",
            "relocation_inventory_preserved": True,
            "mutation": "swapped the distinct in-place addends of table entries 0 and 1",
            "tampered_object_path": relative(d_path, REPO_ROOT),
            "tampered_object_sha256": sha256_file(d_path),
            "linked_elf_path": d_projection["linked_elf_path"],
            "linked_elf_sha256": d_projection["linked_elf_sha256"],
            "linked_entries": d_projection["linked_entries"],
            "equal_words": d_projection["equal_words"],
            "table_differences": d_differences,
            "detected": True,
            "promoted_to_matched": False,
        }

        # Control E: flip bit 0 of non-relocated instruction word 0 in a copy of the object.
        text_file_offset = candidate_text.offset + candidate_offset
        original_word0 = int.from_bytes(object_bytes[text_file_offset : text_file_offset + 4], "little")
        mutated_word0 = original_word0 ^ 0x1
        e_path, _e_module = _tampered_object(
            "e-nonrelocated-word", [(text_file_offset, mutated_word0)]
        )
        e_projection = _link_tampered("e-nonrelocated-word", e_path)
        e_words = tuple(int(word, 16) for word in e_projection["linked_words"])
        e_entries = tuple(int(value, 16) for value in e_projection["linked_entries"])
        e_differences = validate_control_e(
            a_words,
            e_words,
            original_entries,
            e_entries,
            word_index=0,
            relocation_sites=candidate_sites.sites,
        )
        control_records["E"] = {
            "status": "PASS",
            "mutation_stage": "pre_link_object_copy",
            "relocation_inventory_preserved": True,
            "mutation": "flipped bit 0 of non-relocated instruction word 0",
            "tampered_object_path": relative(e_path, REPO_ROOT),
            "tampered_object_sha256": sha256_file(e_path),
            "linked_elf_path": e_projection["linked_elf_path"],
            "linked_elf_sha256": e_projection["linked_elf_sha256"],
            "original_word0": f"0x{original_word0:08x}",
            "mutated_word0": f"0x{mutated_word0:08x}",
            "differences": e_differences,
            "equal_words": e_projection["equal_words"],
            "equal_entries": e_projection["equal_entries"],
            "detected": True,
            "promoted_to_matched": False,
        }
    else:
        control_records.update(not_run_controls())

    validate_recorded_hash("PRX during experiment", sha256_file(prx_path), prx_hash)
    validate_recorded_hash("source during experiment", sha256_file(source_path), source_hash)
    validate_recorded_hash("fresh object during experiment", sha256_file(object_path), object_hash)

    executed_controls = {label for label, record in control_records.items() if record.get("detected")}

    report = {
        "schema_version": 1,
        "function": FUNCTION_NAME,
        "function_address": f"0x{FUNCTION_ADDRESS:x}",
        "function_size_bytes": FUNCTION_SIZE,
        "original_match_status": matching.INCONCLUSIVE,
        "code": {
            "equal_words": baseline["equal_words"],
            "total_words": FUNCTION_WORDS,
            "differences": baseline["differences"],
            "file_byte_comparison": True,
            "false_positive_controls": [label for label in ("B", "C", "E") if label in executed_controls],
        },
        "jump_table": {
            "original_address": f"0x{TABLE_ADDRESS:x}",
            "entry_count": TABLE_ENTRIES,
            "equal_entries": baseline["equal_entries"],
            "differences": baseline["table_differences"],
            "layout_assignment": "CONTROLLED",
            "original_section": TABLE_ORIGINAL_SECTION,
            "original_offset": f"0x{TABLE_ORIGINAL_OFFSET:x}",
            "candidate_section": TABLE_SECTION,
            "candidate_symbol": TABLE_SYMBOL,
            "candidate_address": baseline["assigned_table_address"],
            "file_byte_comparison": True,
            "false_positive_controls": [label for label in ("B", "D") if label in executed_controls],
        },
        "hi16_lo16_pairs": baseline["hi16_lo16_pairs"],
        "calls": baseline["calls"],
        "strings": {
            "address_resolution": "CONTROLLED",
            "candidate_string_bytes_proven": False,
            "cross_artifact_identity": "UNPROVEN",
            "runtime_comparison": "NOT_DEMONSTRATED",
            "shared_symbol": SHARED_DATA_SYMBOL,
            "shared_pair_indices": ["21->24", "33->36"],
            "false_positive_controls": ["C"] if "C" in executed_controls else [],
            "items": original_strings,
        },
        "baseline": {
            "status": matching.INCONCLUSIVE,
            "matching_words": BASELINE_MATCHING_WORDS,
            "total_words": FUNCTION_WORDS,
            "difference_count": 0,
            "relocation_issues": [],
            "match_function_exit_code": match_result.returncode,
            "compile_gate": "PASS_VERIFIED_BY_match_function_BEFORE_COMPARISON",
        },
        "provenance": {
            "prx_path": relative(prx_path, REPO_ROOT),
            "prx_sha256": prx_hash,
            "source_path": relative(source_path, REPO_ROOT),
            "source_sha256": source_hash,
            "fresh_object_path": relative(object_path, REPO_ROOT),
            "fresh_object_sha256": object_hash,
            "linker_script_sha256": script_hashes,
            "compiler": mw_version,
            "loader": wibo_version,
            "linker": linker_version,
            "linker_emulation": "elf32ltsmip",
            "flags": provenance.get("flags"),
            "includes": provenance.get("includes"),
        },
        "original_prx": {
            "text_section_address": f"0x{original.require_section('.text').addr:x}",
            "function_file_words": [f"0x{word:08x}" for word in original_words],
            "jump_table": original_table,
            "calls": original_calls,
            "strings": original_strings,
            "psp_text_relocations": psp_text,
            "psp_table_relocations": psp_table,
        },
        "candidate_object": {
            "table_section": table_section.summary(),
            "table_symbol": TABLE_SYMBOL,
            "inplace_entries": [f"0x{value:08x}" for value in table_words],
            "table_relocations": [
                {
                    "type": relocation.type_name,
                    "section_offset": f"0x{relocation.section_offset:x}",
                    "symbol": relocation.symbol,
                    "addend": f"0x{relocation.addend & 0xFFFFFFFF:08x}",
                }
                for relocation in table_relocations
            ],
            "symbol_relative_offsets": [f"0x{value:08x}" for value in addends],
            "resolved_entries_from_object": [f"0x{value:08x}" for value in resolved_entries],
            "text_relocations": [
                {
                    "type": site.type_name,
                    "word_index": index,
                    "symbol": site.symbol,
                    "addend": f"0x{site.addend & 0xFFFFFFFF:08x}",
                }
                for index, site in sorted(candidate_sites.sites.items())
            ],
            "undefined_symbols": sorted(CONTROLLED_SYMBOLS),
        },
        "linker": {
            "linker_scripts": {
                case: {"path": relative(path, REPO_ROOT), "sha256": script_hashes[case]}
                for case, path in script_paths.items()
            },
            "text_start": f"0x{FUNCTION_ADDRESS:x}",
            "text_size": f"0x{FUNCTION_SIZE:x}",
            "table_layouts": {"A": f"0x{TABLE_ADDRESS:x}", "B": f"0x{TABLE_ALTERNATE_ADDRESS:x}"},
            "table_size": f"0x{TABLE_SIZE:x}",
            "subalign": 4,
            "controlled_symbols": {
                symbol: f"0x{address:x}" for symbol, address in sorted(CONTROLLED_SYMBOLS.items())
            },
            "generated_stubs": False,
            "variants": variants,
            "link_commands": link_commands,
            "layout_control_b_vs_a": b_vs_a,
        },
        "controls": control_records,
        "assumptions": [
            {"section": ".text", "address": f"0x{FUNCTION_ADDRESS:x}", "kind": "CONTROLLED_LAYOUT"},
            {"section": TABLE_SECTION, "address": f"0x{TABLE_ADDRESS:x}", "kind": "CONTROLLED_LAYOUT"},
            *[
                {
                    "symbol": symbol,
                    "address": f"0x{address:x}",
                    "kind": (
                        "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB"
                        if symbol.startswith("func_")
                        else "CONTROLLED_FROM_ORIGINAL_PRX_DATA_OFFSET"
                    ),
                }
                for symbol, address in sorted(CONTROLLED_SYMBOLS.items())
            ],
            {"runtime_load_base": None, "kind": "UNKNOWN_NOT_INFERRED"},
        ],
        "limitations": [
            "code and jump-table equality hold only under the imposed .text/.rodata layout and controlled --defsym symbol assignments",
            "candidate string symbols (D_000047A4, D_000047D0, D_00004800) remain undefined externs resolved via --defsym; the candidate object contains no string bytes",
            "original PSP runtime relocations are not demonstrated; the module load base is not in the file",
            "cross-artifact symbol and object identity between the fresh candidate and the original module is not proven",
        ],
        "independent_identity_proven": False,
        "promoted_to_matched": False,
    }
    exit_code = finalize_experiment_report(report)
    ensure_build_dir(out.parent, build_root)
    write_build_text(out, canonical_json(report), build_root)
    return exit_code, report


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        code, report = run_experiment(arguments)
    except ProbeError as exc:
        report = _base_report()
        report["experiment_status"] = exc.status
        report["error"] = str(exc)
        try:
            out = repo_path(arguments.out, repo_root=REPO_ROOT, allowed_root=_validated_build_root())
            ensure_build_dir(out.parent, _validated_build_root())
            write_build_text(out, canonical_json(report), _validated_build_root())
        except ProbeError:
            pass
        print(f"{exc.status}: {exc}", file=sys.stderr)
        return 4 if exc.status == "BLOCKED" else 1
    except (
        OSError,
        subprocess.SubprocessError,
        ParseError,
        RuntimeError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        report = _base_report()
        report["experiment_status"] = "FAIL"
        report["error"] = str(exc)
        try:
            out = repo_path(arguments.out, repo_root=REPO_ROOT, allowed_root=_validated_build_root())
            ensure_build_dir(out.parent, _validated_build_root())
            write_build_text(out, canonical_json(report), _validated_build_root())
        except ProbeError:
            pass
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(report), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
