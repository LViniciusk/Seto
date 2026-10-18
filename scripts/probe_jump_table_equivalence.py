#!/usr/bin/env python3
"""Run the controlled post-link comparison of func_0000039C code and its
compiler-generated jump table.

Unlike SETO-DECOMP-014, the candidate table already exists as compiler output:
the six ``R_MIPS_32`` entries in the object's ``.rodata`` are preserved and the
GNU MIPSel linker resolves them against the positioned ``.text``.  The
controlled step is only the section layout (``.text`` at ``0x39c``, ``.rodata``
at ``0x4770``) and the address of the one external call.

This is an experimental report, not a replacement for ``seto match``.  A linked
word/table equality obtained with a manually imposed layout remains
assumption-dependent and never changes the original match classification, and a
structurally equivalent table is never the same claim as a proven original
object identity.
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
    ensure_build_dir as _ensure_build_dir,
    paired_effective_address,
    prepare_build_file as _prepare_build_file,
    relative as _relative_common,
    repo_path as _repo_path_common,
    require_mips_elf as _require_mips_elf,
    run as _run_common,
    validate_link_has_no_unresolved,
    validate_nonrelocated_tamper as _validate_nonrelocated_tamper,
    validate_recorded_hash,
    validate_saved_match_record,
    validated_build_root as _validated_build_root_common,
    write_build_bytes as _write_build_bytes,
    write_build_text as _write_build_text,
)
from seto import datarefs, elf, imports, matching, mips, psp_reloc  # noqa: E402
from seto.binio import ParseError  # noqa: E402
from seto.hashing import sha256_file  # noqa: E402

FUNCTION_ADDRESS = 0x39C
FUNCTION_SIZE = 0x78
FUNCTION_WORDS = FUNCTION_SIZE // 4
FUNCTION_NAME = "func_0000039C"
CALL_SYMBOL = "func_00002364"
CALL_TARGET = 0x2364
CALL_SITE = 0x3A4
CALL_INDEX = (CALL_SITE - FUNCTION_ADDRESS) // 4
HI16_ADDRESS = 0x3B8
LO16_ADDRESS = 0x3C0
HI_INDEX = (HI16_ADDRESS - FUNCTION_ADDRESS) // 4
LO_INDEX = (LO16_ADDRESS - FUNCTION_ADDRESS) // 4
TABLE_SECTION = ".rodata"
TABLE_ORIGINAL_SECTION = ".data"
TABLE_ORIGINAL_OFFSET = 0x8
TABLE_ORIGINAL_ADDRESS = 0x4770
TABLE_SIZE = 0x18
TABLE_ENTRIES = TABLE_SIZE // 4
EXPECTED_TARGETS = (0x3D4, 0x3DC, 0x3E4, 0x3EC, 0x3F4, 0x3FC)
EXPECTED_OFFSETS = (0x38, 0x40, 0x48, 0x50, 0x58, 0x60)
TABLE_LAYOUTS = (("A", 0x4770), ("B", 0x4774))
LINKER = "mipsel-linux-gnu-ld"
READELF = "mipsel-linux-gnu-readelf"
OBJDUMP = "mipsel-linux-gnu-objdump"
FILE = "file"


# --------------------------------------------------------------------------- #
# Reused helper bindings (probe_common), kept behind the local names so both    #
# experiment scripts read identically.                                          #
# --------------------------------------------------------------------------- #


def _validated_build_root() -> Path:
    """Reject redirected build roots before resolving any path components."""
    return _validated_build_root_common(REPO_ROOT, subdir="seto015")


def _repo_path(value: Path, *, allowed_root: Path) -> Path:
    return _repo_path_common(value, repo_root=REPO_ROOT, allowed_root=allowed_root)


def _relative(path: Path) -> str:
    return _relative_common(path, REPO_ROOT)


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run_common(argv, cwd=REPO_ROOT if cwd is None else cwd, timeout=timeout, env=env)


def compare_word_sequences(
    original: Sequence[int], candidate: Sequence[int], *, address: int = FUNCTION_ADDRESS
) -> list[dict[str, object]]:
    """Compare all 30 words literally; no relocation masks or normalization apply."""
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


# --------------------------------------------------------------------------- #
# Pure validators and comparisons                                              #
# --------------------------------------------------------------------------- #


def compare_table_entries(
    original: Sequence[int], candidate: Sequence[int]
) -> list[dict[str, object]]:
    """Compare the six jump-table words literally, entry by entry."""
    if len(original) != TABLE_ENTRIES or len(candidate) != TABLE_ENTRIES:
        raise ParseError(
            f"expected {TABLE_ENTRIES} table entries on each side; "
            f"got original={len(original)}, candidate={len(candidate)}"
        )
    return [
        {
            "entry_index": index,
            "original": f"0x{left:08x}",
            "linked": f"0x{right:08x}",
        }
        for index, (left, right) in enumerate(zip(original, candidate, strict=True))
        if left != right
    ]


def entry_destination_rows(entries: Sequence[int]) -> list[dict[str, object]]:
    """The effective destination of each linked entry, with validity flags."""
    return [
        {
            "entry_index": index,
            "address": f"0x{address:x}",
            "expected_case_address": f"0x{expected:x}",
            "inside_function": FUNCTION_ADDRESS <= address < FUNCTION_ADDRESS + FUNCTION_SIZE,
            "matches_expected_case": address == expected,
        }
        for index, (address, expected) in enumerate(
            zip(entries, EXPECTED_TARGETS, strict=True)
        )
    ]


def validate_case_destinations(entries: Sequence[int]) -> None:
    """Require every linked entry to land on the expected case body inside .text."""
    invalid = [row for row in entry_destination_rows(entries) if not row["matches_expected_case"]]
    if invalid:
        raise ProbeError("FAIL", f"linked jump table does not map to the expected case bodies: {invalid}")


def equivalence_claim(equal_words: int, equal_entries: int) -> str:
    """Keep equality under a controlled layout explicitly conditional."""
    if equal_words == FUNCTION_WORDS and equal_entries == TABLE_ENTRIES:
        return "ASSUMPTION_DEPENDENT"
    return "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


def validate_layout_control(baseline: Sequence[int], moved: Sequence[int]) -> list[dict[str, object]]:
    """Moving .rodata must change only the HI16/LO16 destination word."""
    differences = compare_word_sequences(baseline, moved)
    if [row["word_index"] for row in differences] != [LO_INDEX]:
        raise ProbeError("FAIL", "moving .rodata did not change only the HI16/LO16 destination word")
    return differences


def validate_table_swap(original: Sequence[int], swapped: Sequence[int]) -> list[dict[str, object]]:
    """Two swapped in-place entries must be detected at exactly those entries."""
    differences = compare_table_entries(original, swapped)
    if [row["entry_index"] for row in differences] != [0, 1]:
        raise ProbeError("FAIL", "swapping two table entries was not detected at exactly those entries")
    return differences


def validate_table_destination_tamper(
    original: Sequence[int], tampered: Sequence[int], *, entry_index: int
) -> list[dict[str, object]]:
    """A tampered entry must change and must no longer name a case body."""
    differences = compare_table_entries(original, tampered)
    if [row["entry_index"] for row in differences] != [entry_index]:
        raise ProbeError("FAIL", "destination tamper was not detected at exactly one entry")
    row = entry_destination_rows(tampered)[entry_index]
    if row["matches_expected_case"] or not row["inside_function"]:
        raise ProbeError("FAIL", "destination tamper did not produce a distinct in-function address")
    return differences


def validate_linked_text_layout(module: elf.ElfFile, *, label: str) -> elf.Section:
    section = module.require_section(".text")
    if section.addr != FUNCTION_ADDRESS or section.size != FUNCTION_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} .text layout is {section.addr:#x}/{section.size:#x}, expected 0x39c/0x78",
        )
    return section


def validate_linked_structure(module: elf.ElfFile, *, label: str) -> elf.Section:
    """Require exactly one executable section, the target layout and resolved metadata.

    The linker must not insert code, stubs or trampolines, the function symbol must
    land at the assigned address, and the `.mwcats` function pointer must have been
    resolved against the positioned ``.text``.
    """
    executable = tuple(
        section.name for section in module.sections if section.flags & mips.SHF_EXECINSTR
    )
    if executable != (".text",):
        raise ProbeError(
            "FAIL", f"{label} executable sections are {list(executable)}, expected ['.text']"
        )
    text = validate_linked_text_layout(module, label=label)
    function = _function_symbol(module, FUNCTION_NAME)
    if function.value != FUNCTION_ADDRESS or function.size != FUNCTION_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} function symbol is not at 0x{FUNCTION_ADDRESS:x}/0x{FUNCTION_SIZE:x}",
        )
    mwcats = module.section(".mwcats")
    if mwcats is None or mwcats.size != 0x8:
        raise ProbeError("FAIL", f"{label} does not preserve the 8-byte .mwcats metadata")
    metadata = module.section_data(mwcats)
    if len(metadata) < 8 or int.from_bytes(metadata[4:8], "little") != FUNCTION_ADDRESS:
        raise ProbeError(
            "FAIL", f"{label} .mwcats function pointer was not resolved to 0x{FUNCTION_ADDRESS:x}"
        )
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


def candidate_table_relocations(
    module: elf.ElfFile, *, symbol: str
) -> tuple[elf.Relocation, ...]:
    """Require exactly one R_MIPS_32 per entry, in order, against the function."""
    section = module.section(TABLE_SECTION)
    if section is None:
        raise ProbeError("UNSUPPORTED", f"candidate object has no {TABLE_SECTION} section")
    if section.size != TABLE_SIZE:
        raise ProbeError("UNSUPPORTED", f"candidate {TABLE_SECTION} size is 0x{section.size:x}, expected 0x{TABLE_SIZE:x}")
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


def candidate_table_entries(module: elf.ElfFile, *, symbol: str) -> tuple[elf.Section, tuple[elf.Relocation, ...], tuple[int, ...]]:
    """The candidate table's in-place words and its validated relocation list."""
    section = module.require_section(TABLE_SECTION)
    relocations = candidate_table_relocations(module, symbol=symbol)
    words = mips.decode_words(module.section_data(section), "candidate table")
    if len(words) != TABLE_ENTRIES:
        raise ParseError(f"candidate table decoded {len(words)} words, expected {TABLE_ENTRIES}")
    return section, relocations, words


def linked_table_entries(module: elf.ElfFile, *, table_address: int) -> tuple[int, ...]:
    section = validate_table_section(module, table_address=table_address, label="linked ELF")
    words = mips.decode_words(module.section_data(section), "linked table")
    if len(words) != TABLE_ENTRIES:
        raise ParseError(f"linked table decoded {len(words)} words, expected {TABLE_ENTRIES}")
    return words


# --------------------------------------------------------------------------- #
# Object / ELF extraction helpers                                              #
# --------------------------------------------------------------------------- #


def _function_symbol(module: elf.ElfFile, name: str) -> elf.Symbol:
    symbols = [symbol for symbol in module.symbols if symbol.name == name]
    if len(symbols) != 1 or not symbols[0].is_function:
        raise ParseError(f"object must define one function symbol {name}")
    return symbols[0]


def _function_words(module: elf.ElfFile, start: int, size: int, *, label: str) -> tuple[int, ...]:
    if size != FUNCTION_SIZE or start < 0:
        raise ParseError(f"{label} function interval is not exactly 0x{FUNCTION_SIZE:x} bytes")
    section = module.require_section(".text")
    section_offset = start - section.addr
    if section_offset < 0 or section_offset + size > section.size:
        raise ParseError(f"{label} function range is outside .text")
    code = module.section_data(section)[section_offset : section_offset + size]
    words = mips.decode_words(code, label)
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"{label} decoded {len(words)} words, expected {FUNCTION_WORDS}")
    return words


def _read_u32(data: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _write_u32(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


# --------------------------------------------------------------------------- #
# Original PRX evidence                                                         #
# --------------------------------------------------------------------------- #


def _original_table_evidence(module: elf.ElfFile, words: tuple[int, ...]) -> dict[str, object]:
    references = datarefs.recover_references(
        module, ".text", FUNCTION_ADDRESS, FUNCTION_ADDRESS + FUNCTION_SIZE
    )
    reference = next((item for item in references if item.kind == "hi16-lo16"), None)
    if reference is None or reference.target is None:
        raise ProbeError("FAIL", "original PRX jump-table reference was not recovered")
    details = datarefs.data_target_details(module, reference.target)
    if details is None:
        raise ProbeError("FAIL", "original PRX jump-table target has no validated file mapping")
    if (
        reference.target.section != TABLE_ORIGINAL_SECTION
        or reference.target.offset != TABLE_ORIGINAL_OFFSET
    ):
        raise ProbeError("FAIL", f"original PRX jump-table target differs from baseline: {reference.target}")
    if (
        reference.status != "PROVEN"
        or reference.location != "PROVEN"
        or reference.pairing != "PROVEN"
    ):
        raise ProbeError("FAIL", "original PRX jump-table pair is not proven by Seto's existing API")
    section = module.require_section(TABLE_ORIGINAL_SECTION)
    if section.is_nobits or TABLE_ORIGINAL_OFFSET + TABLE_SIZE > section.size:
        raise ProbeError("FAIL", "original jump-table bytes are not fully file-backed")
    data = module.section_data(section)
    table_bytes = data[TABLE_ORIGINAL_OFFSET : TABLE_ORIGINAL_OFFSET + TABLE_SIZE]
    entries = tuple(mips.decode_words(table_bytes, "original jump table"))
    if len(entries) != TABLE_ENTRIES:
        raise ParseError("original jump table is not six entries")
    pair_address = paired_effective_address(words[HI_INDEX], words[LO_INDEX])
    if pair_address != TABLE_ORIGINAL_ADDRESS:
        raise ProbeError("FAIL", f"original HI16/LO16 pair reconstructs 0x{pair_address:x}, expected 0x4770")
    return {
        "reference": reference.summary(),
        "target": details,
        "table_bytes_hex": table_bytes.hex(),
        "table_bytes_sha256": hashlib.sha256(table_bytes).hexdigest(),
        "entries": [f"0x{value:08x}" for value in entries],
        "module_relative_address": f"0x{pair_address:x}",
        "entries_match_recorded_baseline": entries == EXPECTED_TARGETS,
        "candidate_identity_proven": False,
    }


def _original_call_evidence(module: elf.ElfFile) -> dict[str, object]:
    table = imports.build_import_table(module)
    references = imports.call_references(
        module,
        table,
        section=".text",
        start=FUNCTION_ADDRESS,
        end=FUNCTION_ADDRESS + FUNCTION_SIZE,
    )
    matching_reference = next(
        (item for item in references if item.address == CALL_SITE), None
    )
    if matching_reference is None or matching_reference.kind != "import" or matching_reference.imported is None:
        raise ProbeError("FAIL", "original call site is not a resolved PRX import")
    if matching_reference.target != CALL_TARGET or len(references) != 1:
        raise ProbeError("FAIL", f"original call target differs from the baseline: {matching_reference.target:#x}")
    return {
        "call_site": f"0x{CALL_SITE:x}",
        "candidate_symbol": CALL_SYMBOL,
        "original_stub_address": f"0x{matching_reference.target:x}",
        "original_import": matching_reference.imported.summary(),
        "assignment_kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB",
        "candidate_symbol_identity_independently_proven": False,
    }


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
            item
            for item in relocations
            if item.section_offset == section_offset + index * 4
        )
        if relocation.format != "PSP":
            raise ProbeError("FAIL", "expected the original PRX relocations to use PSP format")
        relative = psp_reloc.relative_base(module, relocation, load_base=load_base)
        if relative is None:
            raise ProbeError("UNSUPPORTED", f"PSP relocation at 0x{relocation.offset:x} has no loadable relative segment")
        lo16_word = words[pairing.hi_to_lo[index]] if index in pairing.hi_to_lo else None
        applied = psp_reloc.apply_relocation(
            site.type, words[index], relative, lo16_word=lo16_word
        )
        if applied is None:
            raise ProbeError("UNSUPPORTED", f"PSP relocation type {site.type_name} is not modeled")
        rows.append(
            {
                "site": f"0x{section.addr + section_offset + index * 4:x}",
                "type": site.type_name,
                "segment_index": relocation.segment_index,
                "relative_index": relocation.relative_index,
                "module_relative_base_load0": f"0x{relative:x}",
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


# --------------------------------------------------------------------------- #
# Linker                                                                        #
# --------------------------------------------------------------------------- #


def _linker_script(table_address: int) -> str:
    """A target-specific script: fixed text/rodata layout and preserved metadata."""
    return f'''OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(func_0000039C)
SECTIONS
{{
  .mwcats 0 : SUBALIGN(4) {{ KEEP(*(.mwcats)) }}
  .comment 0 : {{ *(.comment) }}
  .text 0x39c : SUBALIGN(4) {{ *(.text) }}
  .rodata 0x{table_address:x} : SUBALIGN(4) {{ *(.rodata) }}
}}
ASSERT(ADDR(.text) == 0x39c, "func_0000039C text address must be 0x39c")
ASSERT(SIZEOF(.text) == 0x78, "func_0000039C text size must be 0x78")
ASSERT(ADDR(.rodata) == 0x{table_address:x}, "jump table rodata address must be 0x{table_address:x}")
ASSERT(SIZEOF(.rodata) == 0x18, "jump table size must be 0x18")
ASSERT(func_0000039C == 0x39c, "function symbol must be at 0x39c")
ASSERT(SIZEOF(.mwcats) == 0x8, "Metrowerks .mwcats metadata must be retained")
'''


def _inspection_output(executable: str, args: list[str], logs_dir: Path, name: str) -> str:
    result = _run([executable, *args], timeout=60)
    _write_build_text(
        logs_dir / f"{name}.stderr.txt", result.stderr, _validated_build_root()
    )
    if result.returncode != 0:
        raise ProbeError("FAIL", f"{executable} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def _link(
    *,
    object_path: Path,
    script_path: Path,
    output_path: Path,
    table_address: int,
    call_target: int,
    logs_dir: Path,
    label: str,
) -> tuple[elf.ElfFile, dict[str, object]]:
    build_root = _validated_build_root()
    _prepare_build_file(output_path, build_root)
    args = [
        LINKER,
        "-m",
        "elf32ltsmip",
        "-T",
        _relative(script_path),
        f"--defsym={CALL_SYMBOL}=0x{call_target:x}",
        "-o",
        _relative(output_path),
        _relative(object_path),
    ]
    result = _run(args, timeout=120)
    _write_build_text(logs_dir / f"{label}.ld.stdout.txt", result.stdout, build_root)
    _write_build_text(logs_dir / f"{label}.ld.stderr.txt", result.stderr, build_root)
    command_info: dict[str, object] = {"argv": args, "returncode": result.returncode}
    if result.returncode != 0:
        raise ProbeError("FAIL", f"GNU MIPSel link {label} failed: {result.stderr.strip()}")

    linked = elf.parse(output_path)
    _require_mips_elf(linked, file_type=elf.ET_EXEC, label=f"linked ELF {label}")
    validate_linked_structure(linked, label=f"linked ELF {label}")
    validate_link_has_no_unresolved(linked)
    call_symbols = [symbol for symbol in linked.symbols if symbol.name == CALL_SYMBOL]
    if (
        len(call_symbols) != 1
        or call_symbols[0].value != call_target
        or call_symbols[0].shndx != elf.SHN_ABS
    ):
        raise ProbeError("FAIL", f"linked call symbol {CALL_SYMBOL} does not equal its controlled assignment")

    _write_build_text(
        logs_dir / f"{label}.readelf.txt",
        _inspection_output(READELF, ["-hWr", "-s", _relative(output_path)], logs_dir, f"{label}.readelf"),
        build_root,
    )
    _write_build_text(
        logs_dir / f"{label}.objdump.txt",
        _inspection_output(OBJDUMP, ["-dr", _relative(output_path)], logs_dir, f"{label}.objdump"),
        build_root,
    )
    _write_build_text(
        logs_dir / f"{label}.file.txt",
        _inspection_output(FILE, [_relative(output_path)], logs_dir, f"{label}.file"),
        build_root,
    )
    return linked, command_info


def _linked_projection(
    original_words: tuple[int, ...],
    original_entries: tuple[int, ...],
    linked: elf.ElfFile,
    *,
    label: str,
    table_address: int,
) -> dict[str, object]:
    text = linked.require_section(".text")
    words = mips.decode_words(linked.section_data(text), f"linked {label}")
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"linked {label} .text has {len(words)} words, expected {FUNCTION_WORDS}")
    pair_effective = paired_effective_address(words[HI_INDEX], words[LO_INDEX])
    call_target = mips.jump_target(words[CALL_INDEX], CALL_SITE)
    entries = linked_table_entries(linked, table_address=table_address)
    code_differences = compare_word_sequences(original_words, words)
    table_differences = compare_table_entries(original_entries, entries)
    return {
        "elf_header": linked.header.summary(),
        "text_section": text.summary(),
        "table_section": linked.require_section(TABLE_SECTION).summary(),
        "linked_words": [f"0x{word:08x}" for word in words],
        "equal_words": FUNCTION_WORDS - len(code_differences),
        "total_words": FUNCTION_WORDS,
        "differences": code_differences,
        "hi16_word": f"0x{words[HI_INDEX]:08x}",
        "lo16_word": f"0x{words[LO_INDEX]:08x}",
        "hi16_lo16_effective_address": f"0x{pair_effective:x}",
        "assigned_table_address": f"0x{table_address:x}",
        "hi16_lo16_reconstructs_table": pair_effective == table_address,
        "call_site": f"0x{CALL_SITE:x}",
        "call_target": f"0x{call_target:x}",
        "call_is_controlled_target": call_target == CALL_TARGET,
        "linked_entries": [f"0x{value:08x}" for value in entries],
        "entry_destinations": entry_destination_rows(entries),
        "equal_entries": TABLE_ENTRIES - len(table_differences),
        "total_entries": TABLE_ENTRIES,
        "table_differences": table_differences,
    }


# --------------------------------------------------------------------------- #
# Report and experiment                                                         #
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prx",
        type=Path,
        default=Path("private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"),
    )
    parser.add_argument("--source", type=Path, default=Path("decomp/src/func_0000039C.c"))
    parser.add_argument("--config", type=Path, default=Path("config/wsl/seto.toml"))
    parser.add_argument("--build-dir", type=Path, default=Path("build/seto015/experiment"))
    parser.add_argument("--out", type=Path, default=Path("build/seto015/jump-table-equivalence.json"))
    return parser


def _write_report(out: Path, report: dict[str, object]) -> None:
    build_root = _validated_build_root()
    _ensure_build_dir(out.parent, build_root)
    _write_build_text(out, canonical_json(report), build_root)


def _validate_arguments(
    arguments: argparse.Namespace,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    build_root = _validated_build_root()
    build_dir = _repo_path(arguments.build_dir, allowed_root=build_root)
    out = _repo_path(arguments.out, allowed_root=build_root)
    prx = _repo_path(arguments.prx, allowed_root=(REPO_ROOT / "private").resolve())
    source = _repo_path(arguments.source, allowed_root=(REPO_ROOT / "decomp/src").resolve())
    config = _repo_path(arguments.config, allowed_root=(REPO_ROOT / "config").resolve())
    expected_source = (REPO_ROOT / "decomp/src/func_0000039C.c").resolve()
    if source != expected_source:
        raise ProbeError("FAIL", "SETO-DECOMP-015 only accepts the authorized func_0000039C.c source")
    for label, path in (("PRX", prx), ("source", source), ("config", config)):
        if not path.is_file():
            raise ProbeError("BLOCKED", f"{label} file is unavailable")
    return build_root, build_dir, out, prx, source, config


def _base_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "experiment_status": "FAIL",
        "function": FUNCTION_NAME,
        "function_address": f"0x{FUNCTION_ADDRESS:x}",
        "function_size_bytes": FUNCTION_SIZE,
        "original_match_status": matching.INCONCLUSIVE,
        "baseline": {"status": matching.INCONCLUSIVE, "matching_words": 28, "total_words": FUNCTION_WORDS},
        "code": {"equal_words": None, "total_words": FUNCTION_WORDS, "differences": []},
        "jump_table": {
            "original_address": f"0x{TABLE_ORIGINAL_ADDRESS:x}",
            "entry_count": TABLE_ENTRIES,
            "equal_entries": None,
            "differences": [],
            "layout_assignment": "CONTROLLED",
        },
        "independent_identity_proven": False,
        "equivalence_claim": "NONE",
        "promoted_to_matched": False,
    }


def _toolchain_versions(config_path: Path, logs_dir: Path, build_root: Path, env: dict[str, str]) -> tuple[str, str, str]:
    linker_version_result = _run([LINKER, "--version"], timeout=30)
    linker_emulation_result = _run([LINKER, "-V"], timeout=30)
    if linker_version_result.returncode != 0 or linker_emulation_result.returncode != 0:
        raise ProbeError("BLOCKED", "GNU MIPSel linker version/emulation probe failed")
    linker_version = linker_version_result.stdout.splitlines()[0]
    if "elf32ltsmip" not in linker_emulation_result.stdout:
        raise ProbeError("UNSUPPORTED", "GNU linker does not expose elf32ltsmip emulation")

    toolchain_command = [sys.executable, "-m", "seto", "--config", _relative(config_path), "toolchain"]
    toolchain_result = _run(toolchain_command, timeout=120, env=env)
    _write_build_text(logs_dir / "seto-toolchain.stdout.txt", toolchain_result.stdout, build_root)
    _write_build_text(logs_dir / "seto-toolchain.stderr.txt", toolchain_result.stderr, build_root)
    mw_version = None
    for line in toolchain_result.stdout.splitlines():
        if line.lstrip().startswith("mwccpsp"):
            found = re.search(r"\bVersion\s+([0-9.]+\s+build\s+\d+)", line)
            if found:
                mw_version = f"Metrowerks {found.group(1)}"
                break
    wibo_version = None
    for line in toolchain_result.stdout.splitlines():
        if line.lstrip().startswith("wibo"):
            found = re.search(r"\bwibo\s+([0-9.]+)", line)
            if found:
                wibo_version = f"wibo {found.group(1)}"
                break
    if mw_version is None or wibo_version is None:
        raise ProbeError("BLOCKED", "Seto toolchain inventory could not confirm configured Metrowerks/wibo versions")
    return linker_version, mw_version, wibo_version


def run_experiment(arguments: argparse.Namespace) -> tuple[int, dict[str, object]]:
    report = _base_report()
    build_root, build_dir, out, prx_path, source_path, config_path = _validate_arguments(arguments)
    if not all(shutil.which(tool) for tool in (LINKER, READELF, OBJDUMP, FILE)):
        report["experiment_status"] = "BLOCKED"
        report["error"] = "required GNU MIPSel link/inspection executable is missing"
        _write_report(out, report)
        return 4, report

    _ensure_build_dir(build_dir, build_root)
    logs_dir = build_dir / "logs"
    _ensure_build_dir(logs_dir, build_root)
    candidate_dir = build_dir / "candidate"
    _ensure_build_dir(candidate_dir, build_root)
    links_dir = build_dir / "links"
    _ensure_build_dir(links_dir, build_root)

    match_record_path = candidate_dir / "match-record.json"
    object_path = candidate_dir / f"{source_path.stem}.o"
    for path in (match_record_path, object_path):
        _prepare_build_file(path, build_root)
        path.unlink(missing_ok=True)

    source_hash_before = sha256_file(source_path)
    prx_hash_before = sha256_file(prx_path)

    script_paths: dict[str, Path] = {}
    for case, table_address in TABLE_LAYOUTS:
        script_path = build_dir / f"controlled-link-{case.lower()}.ld"
        _write_build_text(script_path, _linker_script(table_address), build_root)
        script_paths[case] = script_path

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    match_command = [
        sys.executable,
        "scripts/match_function.py",
        "--config",
        _relative(config_path),
        "--prx",
        _relative(prx_path),
        "--function",
        hex(FUNCTION_ADDRESS),
        "--source",
        _relative(source_path),
        "--out",
        _relative(candidate_dir),
        "--report",
        _relative(match_record_path),
        "--json",
    ]
    match_result = _run(match_command, timeout=600, env=env)
    _write_build_text(logs_dir / "match-function.stdout.json", match_result.stdout, build_root)
    _write_build_text(logs_dir / "match-function.stderr.txt", match_result.stderr, build_root)
    if match_result.returncode == 4:
        report["experiment_status"] = "BLOCKED"
        report["error"] = "match_function reports the Metrowerks compiler or loader unavailable"
        _write_report(out, report)
        return 4, report
    if match_result.returncode not in (5,):
        raise ProbeError("FAIL", f"fresh match_function run exited {match_result.returncode}, expected 5/INCONCLUSIVE")
    try:
        match_record = json.loads(match_result.stdout)
    except json.JSONDecodeError as exc:
        raise ProbeError("FAIL", f"match_function did not emit valid JSON: {exc}") from exc
    payload = match_record.get("match")
    if (
        not isinstance(payload, dict)
        or match_record.get("status") != matching.INCONCLUSIVE
        or payload.get("status") != matching.INCONCLUSIVE
        or payload.get("matching_words") != 28
        or payload.get("total_words") != FUNCTION_WORDS
        or payload.get("difference_count") != 0
        or payload.get("relocation_issues")
    ):
        raise ProbeError("FAIL", "fresh compile does not match the required 28/30 INCONCLUSIVE baseline")
    if not object_path.is_file() or not match_record_path.is_file():
        raise ProbeError("FAIL", "fresh match_function run did not produce both object and provenance report")
    saved_match_record = json.loads(match_record_path.read_text(encoding="utf-8"))
    validate_saved_match_record(match_record, saved_match_record)
    provenance = match_record["provenance"]
    if (
        match_record.get("function") != FUNCTION_NAME
        or match_record.get("address") != hex(FUNCTION_ADDRESS)
        or match_record.get("section") != ".text"
        or provenance.get("source") != _relative(source_path)
        or provenance.get("object") != _relative(object_path)
    ):
        raise ProbeError("FAIL", "match_function provenance does not identify this fresh 0x39C compile")

    object_hash = sha256_file(object_path)
    source_hash = sha256_file(source_path)
    prx_hash = sha256_file(prx_path)
    if source_hash != source_hash_before or prx_hash != prx_hash_before:
        raise ProbeError("FAIL", "source or PRX changed during fresh compile/match execution")
    validate_recorded_hash("candidate object", object_hash, provenance.get("object_sha256"))
    validate_recorded_hash("candidate source", source_hash, provenance.get("source_sha256"))
    if provenance.get("flags") != ["-O4,p", "-sdatathreshold", "0"]:
        raise ProbeError("FAIL", f"unexpected compiler flags: {provenance.get('flags')}")

    original = elf.parse(prx_path)
    candidate = elf.parse(object_path)
    _require_mips_elf(original, file_type=elf.ET_MIPS_PSP_PRX, label="original PRX")
    _require_mips_elf(candidate, file_type=elf.ET_REL, label="fresh Metrowerks object")
    original_words = _function_words(original, FUNCTION_ADDRESS, FUNCTION_SIZE, label="original PRX")

    candidate_symbol = _function_symbol(candidate, FUNCTION_NAME)
    if not candidate_symbol.is_defined or candidate_symbol.size != FUNCTION_SIZE:
        raise ProbeError("FAIL", "fresh candidate function symbol is undefined or has the wrong size")
    candidate_text = candidate.require_section(".text")
    if candidate_symbol.value != 0 or candidate_text.size != FUNCTION_SIZE:
        raise ProbeError("UNSUPPORTED", "fresh candidate .text must contain exactly the target function at section offset zero")
    candidate_offset = candidate_symbol.value
    candidate_words = _function_words(candidate, candidate_offset, FUNCTION_SIZE, label="fresh candidate")

    undefined_calls = {
        symbol.name
        for symbol in candidate.symbols
        if symbol.name == CALL_SYMBOL and symbol.shndx == elf.SHN_UNDEF
    }
    if undefined_calls != {CALL_SYMBOL}:
        raise ProbeError("FAIL", "fresh candidate does not expose the expected undefined external call symbol")
    if candidate.section(".mwcats") is None:
        raise ProbeError("UNSUPPORTED", "fresh Metrowerks object has no .mwcats metadata section")

    candidate_sites = matching.relocation_sites(
        candidate.relocations_for(".text"), candidate_offset, FUNCTION_SIZE
    )
    if candidate_sites.limitations:
        raise ProbeError("UNSUPPORTED", f"fresh candidate .text relocation placement has limitations: {candidate_sites.limitations}")
    required_text_relocations = {
        (elf.R_MIPS_26, CALL_INDEX, CALL_SYMBOL),
        (elf.R_MIPS_HI16, HI_INDEX, "@13"),
        (elf.R_MIPS_LO16, LO_INDEX, "@13"),
    }
    actual_text_relocations = {
        (site.type, index, site.symbol) for index, site in candidate_sites.sites.items()
    }
    if actual_text_relocations != required_text_relocations:
        raise ProbeError(
            "UNSUPPORTED",
            f"fresh candidate .text relocation inventory differs from the contract: {actual_text_relocations}",
        )
    pairing = matching.pair_hi16_lo16(candidate_sites.sites, candidate_words)
    if pairing.hi_to_lo != {HI_INDEX: LO_INDEX} or pairing.limitations:
        raise ProbeError("UNSUPPORTED", "fresh candidate HI16/LO16 pairing is not proven")

    table_section, table_relocations, table_words = candidate_table_entries(candidate, symbol=FUNCTION_NAME)
    addends = tuple(relocation.addend & 0xFFFFFFFF for relocation in table_relocations)
    if addends != EXPECTED_OFFSETS or table_words != EXPECTED_OFFSETS:
        raise ProbeError(
            "FAIL",
            f"fresh candidate table symbol-relative offsets {addends} differ from the recorded baseline {EXPECTED_OFFSETS}",
        )

    original_table = _original_table_evidence(original, original_words)
    original_entries = tuple(int(value, 16) for value in original_table["entries"])
    original_call = _original_call_evidence(original)
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
    for case, table_address in TABLE_LAYOUTS:
        variant_dir = links_dir / f"case-{case.lower()}"
        _ensure_build_dir(variant_dir, build_root)
        output_path = variant_dir / "linked.elf"
        linked, command_info = _link(
            object_path=object_path,
            script_path=script_paths[case],
            output_path=output_path,
            table_address=table_address,
            call_target=CALL_TARGET,
            logs_dir=logs_dir,
            label=f"case-{case.lower()}",
        )
        link_commands[case] = command_info
        projection = _linked_projection(
            original_words, original_entries, linked, label=f"case {case}", table_address=table_address
        )
        projection["linked_elf_path"] = _relative(output_path)
        projection["linked_elf_sha256"] = sha256_file(output_path)
        variants[case] = projection

    baseline = variants["A"]
    if baseline["equal_words"] != FUNCTION_WORDS or baseline["differences"]:
        raise ProbeError("FAIL", "linked baseline .text does not equal the original PRX function")
    if baseline["equal_entries"] != TABLE_ENTRIES or baseline["table_differences"]:
        raise ProbeError("FAIL", "linked baseline jump table does not equal the original PRX table")
    if not baseline["hi16_lo16_reconstructs_table"] or not baseline["call_is_controlled_target"]:
        raise ProbeError("FAIL", "linked baseline did not reconstruct the table address or the controlled call target")
    baseline_entries = tuple(int(value, 16) for value in baseline["linked_entries"])
    validate_case_destinations(baseline_entries)

    # Cross-check (necessary consistency, not by itself proof of provenance): the
    # linked entries must equal the candidate object's own R_MIPS_32 addends applied
    # over the positioned .text. Provenance evidence comes from the validated
    # relocation inventory plus the literal equality with the original table.
    resolved_entries = tuple(FUNCTION_ADDRESS + addend for addend in addends)
    if resolved_entries != baseline_entries:
        raise ProbeError(
            "FAIL",
            "linked table differs from the candidate object's own R_MIPS_32 addends applied over .text",
        )

    a_words = tuple(int(word, 16) for word in variants["A"]["linked_words"])
    b_words = tuple(int(word, 16) for word in variants["B"]["linked_words"])
    b_vs_a = validate_layout_control(a_words, b_words)
    if variants["B"]["linked_entries"] != variants["A"]["linked_entries"]:
        raise ProbeError("FAIL", "moving .rodata changed the table entries, which are .text-relative")

    # ---- Controls C/D/E: pre-link tampering of explicitly-derived copies. ----
    object_bytes = bytearray(object_path.read_bytes())
    table_file_offset = table_section.offset
    control_records: dict[str, dict[str, object]] = {}

    def _tampered_object(label: str, mutations: list[tuple[int, int]]) -> tuple[Path, elf.ElfFile]:
        data = bytearray(object_bytes)
        for offset, value in mutations:
            _write_u32(data, offset, value)
        path = build_dir / f"tampered-{label}.o"
        _write_build_bytes(path, bytes(data), build_root)
        module = elf.parse(path)
        sites = matching.relocation_sites(module.relocations_for(".text"), candidate_offset, FUNCTION_SIZE)
        if sites.sites != candidate_sites.sites:
            raise ProbeError("FAIL", f"control {label} changed the .text relocation inventory")
        relocations = candidate_table_relocations(module, symbol=FUNCTION_NAME)
        if tuple(
            (relocation.type, relocation.section_offset, relocation.symbol) for relocation in relocations
        ) != tuple(
            (relocation.type, relocation.section_offset, relocation.symbol) for relocation in table_relocations
        ):
            raise ProbeError("FAIL", f"control {label} changed the table relocation inventory")
        return path, module

    def _link_control(label: str, object_module_path: Path, table_address: int) -> dict[str, object]:
        variant_dir = links_dir / f"control-{label}"
        _ensure_build_dir(variant_dir, build_root)
        output_path = variant_dir / "linked.elf"
        linked, command_info = _link(
            object_path=object_module_path,
            script_path=script_paths["A"],
            output_path=output_path,
            table_address=table_address,
            call_target=CALL_TARGET,
            logs_dir=logs_dir,
            label=f"control-{label}",
        )
        projection = _linked_projection(
            original_words, original_entries, linked, label=f"control {label}", table_address=table_address
        )
        projection["linked_elf_path"] = _relative(output_path)
        projection["linked_elf_sha256"] = sha256_file(output_path)
        projection["link_command"] = command_info
        return projection

    # Control C: swap the in-place addends of entries 0 and 1.
    swap_mutations = [
        (table_file_offset + 0, EXPECTED_OFFSETS[1]),
        (table_file_offset + 4, EXPECTED_OFFSETS[0]),
    ]
    c_path, _c_module = _tampered_object("swap-entries", swap_mutations)
    c_projection = _link_control("swap-entries", c_path, 0x4770)
    c_entries = tuple(int(value, 16) for value in c_projection["linked_entries"])
    c_vs_original = validate_table_swap(original_entries, c_entries)
    if c_projection["equal_words"] != FUNCTION_WORDS or c_projection["differences"]:
        raise ProbeError("FAIL", "control C changed the code; the control must isolate the table")
    control_records["C"] = {
        "mutation_stage": "pre_link_object_copy",
        "relocation_inventory_preserved": True,
        "mutation": "swapped the in-place addends of table entries 0 and 1",
        "linked_entries": c_projection["linked_entries"],
        "equal_words": c_projection["equal_words"],
        "table_differences": c_vs_original,
        "detected": True,
        "promoted_to_matched": False,
    }

    # Control D: point entry 3 at a wrong but in-function address.
    tampered_entry_value = 0x44
    wrong_address = FUNCTION_ADDRESS + tampered_entry_value
    d_mutations = [(table_file_offset + 12, tampered_entry_value)]
    d_path, _d_module = _tampered_object("wrong-destination", d_mutations)
    d_projection = _link_control("wrong-destination", d_path, 0x4770)
    d_entries = tuple(int(value, 16) for value in d_projection["linked_entries"])
    d_vs_original = validate_table_destination_tamper(original_entries, d_entries, entry_index=3)
    if d_projection["equal_words"] != FUNCTION_WORDS or d_projection["differences"]:
        raise ProbeError("FAIL", "control D changed the code; the control must isolate the table")
    control_records["D"] = {
        "mutation_stage": "pre_link_object_copy",
        "relocation_inventory_preserved": True,
        "mutation": "redirected table entry 3 to a non-case in-function address",
        "expected_wrong_address": f"0x{wrong_address:x}",
        "linked_entries": d_projection["linked_entries"],
        "equal_words": d_projection["equal_words"],
        "table_differences": d_vs_original,
        "detected": True,
        "promoted_to_matched": False,
    }

    # Control E: mutate one non-relocated instruction word in a copy of the object.
    text_file_offset = candidate_text.offset + candidate_offset
    original_word0 = _read_u32(object_bytes, text_file_offset)
    mutated_word0 = original_word0 ^ 0x1
    e_mutations = [(text_file_offset, mutated_word0)]
    e_path, _e_module = _tampered_object("nonrelocated-word", e_mutations)
    e_projection = _link_control("nonrelocated-word", e_path, 0x4770)
    original_linked_words = tuple(int(word, 16) for word in variants["A"]["linked_words"])
    e_linked_words = tuple(int(word, 16) for word in e_projection["linked_words"])
    e_differences = validate_nonrelocated_tamper(
        original_linked_words,
        e_linked_words,
        word_index=0,
        relocation_sites=candidate_sites.sites,
    )
    if e_projection["table_differences"] or e_projection["equal_entries"] != TABLE_ENTRIES:
        raise ProbeError("FAIL", "control E changed the table; the control must isolate the code")
    control_records["E"] = {
        "mutation_stage": "pre_link_object_copy",
        "relocation_inventory_preserved": True,
        "mutation": "flipped one bit in the non-relocated word 0",
        "original_word0": f"0x{original_word0:08x}",
        "mutated_word0": f"0x{mutated_word0:08x}",
        "linked_words": e_projection["linked_words"],
        "differences": e_differences,
        "equal_entries": e_projection["equal_entries"],
        "detected": True,
        "promoted_to_matched": False,
    }

    validate_recorded_hash("PRX during experiment", sha256_file(prx_path), prx_hash)
    validate_recorded_hash("source during experiment", sha256_file(source_path), source_hash)
    validate_recorded_hash("fresh object during experiment", sha256_file(object_path), object_hash)

    report = {
        "schema_version": 1,
        "experiment_status": "PASS",
        "function": FUNCTION_NAME,
        "function_address": f"0x{FUNCTION_ADDRESS:x}",
        "function_size_bytes": FUNCTION_SIZE,
        "original_match_status": matching.INCONCLUSIVE,
        "code": {
            "equal_words": baseline["equal_words"],
            "total_words": FUNCTION_WORDS,
            "differences": baseline["differences"],
            "file_byte_comparison": True,
            "false_positive_controls": ["E"],
        },
        "jump_table": {
            "original_address": f"0x{TABLE_ORIGINAL_ADDRESS:x}",
            "entry_count": TABLE_ENTRIES,
            "equal_entries": baseline["equal_entries"],
            "differences": baseline["table_differences"],
            "layout_assignment": "CONTROLLED",
            "original_section": TABLE_ORIGINAL_SECTION,
            "original_offset": f"0x{TABLE_ORIGINAL_OFFSET:x}",
            "candidate_section": TABLE_SECTION,
            "candidate_address": variants["A"]["assigned_table_address"],
            "file_byte_comparison": True,
            "false_positive_controls": ["B", "C", "D"],
        },
        "baseline": {
            "status": matching.INCONCLUSIVE,
            "matching_words": 28,
            "total_words": FUNCTION_WORDS,
            "difference_count": 0,
            "relocation_issues": [],
            "match_function_exit_code": match_result.returncode,
            "compile_gate": "PASS_VERIFIED_BY_match_function_BEFORE_COMPARISON",
        },
        "provenance": {
            "prx_path": _relative(prx_path),
            "prx_sha256": prx_hash,
            "source_path": _relative(source_path),
            "source_sha256": source_hash,
            "fresh_object_path": _relative(object_path),
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
            "call": original_call,
            "psp_text_relocations": psp_text,
            "psp_table_relocations": psp_table,
        },
        "candidate_object": {
            "section": table_section.summary(),
            "inplace_entries": [f"0x{value:08x}" for value in table_words],
            "relocations": [
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
        },
        "linker": {
            "linker_scripts": {
                case: {"path": _relative(path), "sha256": script_hashes[case]}
                for case, path in script_paths.items()
            },
            "text_start": f"0x{FUNCTION_ADDRESS:x}",
            "text_size": f"0x{FUNCTION_SIZE:x}",
            "table_layouts": {case: f"0x{address:x}" for case, address in TABLE_LAYOUTS},
            "table_size": f"0x{TABLE_SIZE:x}",
            "subalign": 4,
            "call_assignment": {"symbol": CALL_SYMBOL, "address": f"0x{CALL_TARGET:x}"},
            "generated_stubs": False,
            "variants": variants,
            "link_commands": link_commands,
            "layout_control_b_vs_a": b_vs_a,
        },
        "controls": control_records,
        "assumptions": [
            {"symbol": CALL_SYMBOL, "address": f"0x{CALL_TARGET:x}", "kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB"},
            {"section": TABLE_SECTION, "address": f"0x{TABLE_ORIGINAL_ADDRESS:x}", "kind": "CONTROLLED_LAYOUT"},
            {"runtime_load_base": None, "kind": "UNKNOWN_NOT_INFERRED"},
        ],
        "limitations": [
            "code and table equality hold only under the imposed .text/.rodata layout",
            "the candidate .rodata at 0x4770 is an experimental placement, not a recovered original location",
            "original PSP runtime reloads are not demonstrated; the module load base is not in the file",
            "object identity between the fresh candidate and the original module is not proven",
        ],
        "independent_identity_proven": False,
        "equivalence_claim": equivalence_claim(baseline["equal_words"], baseline["equal_entries"]),
        "promoted_to_matched": False,
    }
    _write_report(out, report)
    return 0, report


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        code, report = run_experiment(arguments)
    except ProbeError as exc:
        report = _base_report()
        report["experiment_status"] = exc.status
        report["error"] = str(exc)
        try:
            out = _repo_path(arguments.out, allowed_root=_validated_build_root())
            _write_report(out, report)
        except ProbeError:
            pass
        print(f"{exc.status}: {exc}", file=sys.stderr)
        return 4 if exc.status == "BLOCKED" else 1
    except (OSError, subprocess.SubprocessError, ParseError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        report = _base_report()
        report["experiment_status"] = "FAIL"
        report["error"] = str(exc)
        try:
            out = _repo_path(arguments.out, allowed_root=_validated_build_root())
            _write_report(out, report)
        except ProbeError:
            pass
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(report), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
