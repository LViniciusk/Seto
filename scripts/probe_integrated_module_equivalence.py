#!/usr/bin/env python3
"""Integrated module reconstruction and link-time equivalence probe for libhtml_view.prx.

SETO-DECOMP-017 compiles fresh all 15 C candidate functions (the full REAL_MATCH_CASES
inventory), links them in a single operation under controlled module layout
(.text [0x0, 0x7F4), 509 instructions: 507 C + 2 un-reconstructed fragment words at 0x84),
resolves 22 local calls via actual defined symbols across candidate objects, resolves
50 import calls via controlled stub assignments from the module's own import table,
co-links the two compiler-generated jump tables in .rodata at 0x4770 (6 + 7 = 13 entries),
resolves external un-reconstructed data symbols via controlled --defsym, compares the
entire 509 words and 13 jump table entries against libhtml_view.prx, executes negative
controls A through E, and emits canonical JSON to build/seto017/integrated-module-equivalence.json.

Equality under controlled assignments remains ASSUMPTION_DEPENDENT and never promotes
INCONCLUSIVE functions to MATCHED, nor does it certify the 2-word fragment as C decompilation.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from match_baselines import REAL_MATCH_CASES  # noqa: E402
from probe_common import (  # noqa: E402
    ProbeError,
    canonical_json,
    compare_word_sequences as _compare_word_sequences,
    ensure_build_dir,
    relative,
    repo_path,
    require_mips_elf,
    run,
    validate_link_has_no_unresolved,
    validate_recorded_hash,
    validate_saved_match_record,
    validated_build_root,
    write_build_bytes,
    write_build_text,
)
from seto import elf, imports, mips  # noqa: E402
from seto.binio import ParseError  # noqa: E402
from seto.hashing import sha256_file  # noqa: E402

MODULE_NAME = "libhtml_view.prx"
TEXT_START = 0x0
TEXT_SIZE = 0x7F4
TEXT_WORDS = TEXT_SIZE // 4  # 509 words
C_RECONSTRUCTED_WORDS = 507

FRAGMENT_START = 0x84
FRAGMENT_SIZE = 0x8
FRAGMENT_WORDS = (0x03E00008, 0x00000000)  # jr $ra; nop
FRAGMENT_SYMBOL = "func_00000084"
FRAGMENT_CLASSIFICATION = "ORIGINAL_UNRECONSTRUCTED_FRAGMENT"

RODATA_START = 0x4770
RODATA_SIZE = 0x34  # 52 bytes: 0x18 (func_0000039C) + 0x1C (func_00000414)
RODATA_WORDS = RODATA_SIZE // 4  # 13 words
RODATA_ORIGINAL_SECTION = ".data"
RODATA_ORIGINAL_OFFSET = 0x8

TABLE_39C_START = 0x4770
TABLE_39C_SIZE = 0x18
TABLE_39C_ENTRIES = 6
TABLE_39C_EXPECTED_TARGETS = (0x3D4, 0x3DC, 0x3E4, 0x3EC, 0x3F4, 0x3FC)
TABLE_39C_EXPECTED_OFFSETS = (0x38, 0x40, 0x48, 0x50, 0x58, 0x60)

TABLE_414_START = 0x4788
TABLE_414_SIZE = 0x1C
TABLE_414_ENTRIES = 7
TABLE_414_EXPECTED_TARGETS = (0x450, 0x468, 0x480, 0x480, 0x480, 0x480, 0x480)
TABLE_414_EXPECTED_OFFSETS = (0x3C, 0x54, 0x6C, 0x6C, 0x6C, 0x6C, 0x6C)

TOTAL_TABLE_ENTRIES = TABLE_39C_ENTRIES + TABLE_414_ENTRIES  # 13 entries

TOTAL_CALLS = 72
LOCAL_CALLS = 22
IMPORT_CALLS = 50

# 35 distinct import stub targets derived from PRX import table and sce_stubs.h.
CONTROLLED_IMPORTS: dict[str, int] = {
    "func_00000854": 0x854,
    "func_00000894": 0x894,
    "func_000008A4": 0x8A4,
    "func_00000964": 0x964,
    "func_00000B1C": 0xB1C,
    "func_00001F04": 0x1F04,
    "func_00002354": 0x2354,
    "func_0000235C": 0x235C,
    "func_00002364": 0x2364,
    "func_0000295C": 0x295C,
    "func_00002ADC": 0x2ADC,
    "func_00002D0C": 0x2D0C,
    "func_00002EDC": 0x2EDC,
    "func_00002EE4": 0x2EE4,
    "func_00002EEC": 0x2EEC,
    "func_00002EF4": 0x2EF4,
    "func_00002EFC": 0x2EFC,
    "func_00002F04": 0x2F04,
    "func_00002F0C": 0x2F0C,
    "func_00002F14": 0x2F14,
    "func_00002F1C": 0x2F1C,
    "func_00002F24": 0x2F24,
    "func_00002F2C": 0x2F2C,
    "func_00002F34": 0x2F34,
    "func_00002F3C": 0x2F3C,
    "func_00002F44": 0x2F44,
    "func_00002F4C": 0x2F4C,
    "func_00002F54": 0x2F54,
    "func_00002F5C": 0x2F5C,
    "func_00002F64": 0x2F64,
    "func_00002F6C": 0x2F6C,
    "func_00002F74": 0x2F74,
    "func_00002F7C": 0x2F7C,
    "func_00002F84": 0x2F84,
    "func_00002F8C": 0x2F8C,
}

# 11 external un-reconstructed data symbols referenced across the 15 candidate functions.
CONTROLLED_DATA_SYMBOLS: dict[str, int] = {
    "D_000047A4": 0x47A4,
    "D_000047D0": 0x47D0,
    "D_00004800": 0x4800,
    "D_00004830": 0x4830,
    "D_00004850": 0x4850,
    "D_00004860": 0x4860,
    "D_00604860": 0x604860,
    "D_00604864": 0x604864,
    "D_00604918": 0x604918,
    "D_00604B18": 0x604B18,
    "D_00604B9C": 0x604B9C,
}

SHARED_DATA_SYMBOL = "D_000047D0"
SHARED_DATA_MUTATED_ADDRESS = 0x47D4

LINKER = "mipsel-linux-gnu-ld"
READELF = "mipsel-linux-gnu-readelf"
OBJDUMP = "mipsel-linux-gnu-objdump"
FILE = "file"
DIVERGENCE_EXIT_CODE = 3


def _validated_build_root() -> Path:
    return validated_build_root(REPO_ROOT, subdir="seto017")


def ordered_inventory() -> list[tuple[int, str, str, int, int]]:
    """Return REAL_MATCH_CASES sorted strictly by starting module address."""
    return sorted(REAL_MATCH_CASES, key=lambda case: case[0])


@dataclass(frozen=True)
class LayoutInterval:
    kind: str  # "C_FUNCTION" or "ORIGINAL_UNRECONSTRUCTED_FRAGMENT"
    start: int
    end: int
    size_bytes: int
    words_count: int
    symbol: str
    source_file: str | None
    expected_status: str | None


def compute_layout_intervals(
    cases: Sequence[tuple[int, str, str, int, int]],
) -> list[LayoutInterval]:
    """Build the contiguous list of 16 intervals spanning [0x0, 0x7F4)."""
    intervals: list[LayoutInterval] = []
    current_addr = 0
    for addr, c_filename, expected_status, _match_w, total_w in cases:
        size_bytes = total_w * 4
        if addr == FRAGMENT_START and current_addr < FRAGMENT_START:
            # Insert fragment interval
            frag_size = FRAGMENT_SIZE
            intervals.append(
                LayoutInterval(
                    kind="ORIGINAL_UNRECONSTRUCTED_FRAGMENT",
                    start=FRAGMENT_START,
                    end=FRAGMENT_START + frag_size,
                    size_bytes=frag_size,
                    words_count=frag_size // 4,
                    symbol=FRAGMENT_SYMBOL,
                    source_file=None,
                    expected_status=None,
                )
            )
            current_addr += frag_size
        elif current_addr == FRAGMENT_START and addr > FRAGMENT_START:
            frag_size = FRAGMENT_SIZE
            intervals.append(
                LayoutInterval(
                    kind="ORIGINAL_UNRECONSTRUCTED_FRAGMENT",
                    start=FRAGMENT_START,
                    end=FRAGMENT_START + frag_size,
                    size_bytes=frag_size,
                    words_count=frag_size // 4,
                    symbol=FRAGMENT_SYMBOL,
                    source_file=None,
                    expected_status=None,
                )
            )
            current_addr += frag_size

        if addr != current_addr:
            raise ProbeError(
                "FAIL",
                f"layout gap or overlap: function {c_filename} at 0x{addr:x}, expected 0x{current_addr:x}",
            )
        func_sym = mips.function_name(addr)
        intervals.append(
            LayoutInterval(
                kind="C_FUNCTION",
                start=addr,
                end=addr + size_bytes,
                size_bytes=size_bytes,
                words_count=total_w,
                symbol=func_sym,
                source_file=c_filename,
                expected_status=expected_status,
            )
        )
        current_addr += size_bytes

    if current_addr != TEXT_SIZE:
        raise ProbeError(
            "FAIL",
            f"intervals do not span exact .text layout: ended at 0x{current_addr:x}, expected 0x{TEXT_SIZE:x}",
        )
    return intervals


def validate_layout_intervals(intervals: Sequence[LayoutInterval]) -> None:
    """Validate alignment, bounds, total word counts and non-overlapping invariants."""
    if len(intervals) != 16:
        raise ProbeError("FAIL", f"expected 16 intervals, got {len(intervals)}")
    c_words = sum(iv.words_count for iv in intervals if iv.kind == "C_FUNCTION")
    frag_words = sum(
        iv.words_count for iv in intervals if iv.kind == "ORIGINAL_UNRECONSTRUCTED_FRAGMENT"
    )
    if c_words != C_RECONSTRUCTED_WORDS or frag_words != 2 or (c_words + frag_words) != TEXT_WORDS:
        raise ProbeError(
            "FAIL",
            f"word accounting mismatch: {c_words} C words + {frag_words} fragment words != {TEXT_WORDS}",
        )
    current = 0
    for iv in intervals:
        if iv.start != current or iv.end != current + iv.size_bytes:
            raise ProbeError("FAIL", f"interval {iv.symbol} [0x{iv.start:x}:0x{iv.end:x}) not contiguous at 0x{current:x}")
        if iv.start % 4 != 0 or iv.size_bytes % 4 != 0:
            raise ProbeError("FAIL", f"interval {iv.symbol} is not 4-byte aligned")
        current = iv.end


def generate_linker_script(
    ordered_cases: Sequence[tuple[int, str, str, int, int]],
    *,
    rodata_address: int = RODATA_START,
) -> str:
    """Generate the GNU ld script placing all 15 objects and the 0x84 fragment explicitly."""
    text_entries: list[str] = []
    current = 0
    for addr, c_name, _status, _mw, total_w in ordered_cases:
        stem = Path(c_name).stem
        if addr > FRAGMENT_START and current <= FRAGMENT_START:
            text_entries.append(f"    {FRAGMENT_SYMBOL} = .;  /* Layout symbol for unreconstructed fragment */")
            text_entries.append(f"    LONG(0x{FRAGMENT_WORDS[0]:08X})")
            text_entries.append(f"    LONG(0x{FRAGMENT_WORDS[1]:08X})")
            current += FRAGMENT_SIZE
        text_entries.append(f"    *{stem}*(.text)")
        current += total_w * 4

    script = f"""OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(func_00000000)

SECTIONS
{{
  .mwcats 0 : SUBALIGN(4) {{ KEEP(*(.mwcats)) }}
  .comment 0 : {{ *(.comment) }}
  .text 0x0 : SUBALIGN(4) {{
{chr(10).join(text_entries)}
  }}
  .rodata 0x{rodata_address:x} : SUBALIGN(4) {{
    *func_0000039C*(.rodata)
    *func_00000414*(.rodata)
  }}
}}

ASSERT(ADDR(.text) == 0x0, "wrong text address")
ASSERT(SIZEOF(.text) == 0x{TEXT_SIZE:x}, "wrong text size")
ASSERT(ADDR(.rodata) == 0x{rodata_address:x}, "wrong rodata address")
ASSERT(SIZEOF(.rodata) == 0x{RODATA_SIZE:x}, "wrong rodata size")
"""
    return script


def compare_word_sequences(
    original: Sequence[int], candidate: Sequence[int], *, address: int = TEXT_START
) -> list[dict[str, object]]:
    """Compare all 509 words literally; no relocation masks or normalization apply."""
    return _compare_word_sequences(
        original, candidate, address=address, expected_words=TEXT_WORDS
    )


def compare_table_entries(
    original: Sequence[int], candidate: Sequence[int]
) -> list[dict[str, object]]:
    """Compare all 13 jump table words literally, entry by entry."""
    if len(original) != TOTAL_TABLE_ENTRIES or len(candidate) != TOTAL_TABLE_ENTRIES:
        raise ParseError(
            f"expected {TOTAL_TABLE_ENTRIES} table entries on each side; "
            f"got original={len(original)}, candidate={len(candidate)}"
        )
    return [
        {"entry_index": index, "original": f"0x{left:08x}", "linked": f"0x{right:08x}"}
        for index, (left, right) in enumerate(zip(original, candidate, strict=True))
        if left != right
    ]


def validate_candidate_table_invariants(
    table_relocations: Sequence[elf.Relocation],
    table_words: Sequence[int],
    *,
    function_symbol: str,
    expected_entries: int,
    function_size: int,
) -> tuple[int, ...]:
    """Check content-independent structural invariants of candidate jump tables."""
    if len(table_relocations) != expected_entries or len(table_words) != expected_entries:
        raise ProbeError(
            "FAIL",
            f"table for {function_symbol} has {len(table_relocations)} rels, {len(table_words)} words; expected {expected_entries}",
        )
    for idx, reloc in enumerate(table_relocations):
        if reloc.section_offset != idx * 4:
            raise ProbeError("UNSUPPORTED", f"table relocation {idx} not at offset 0x{idx * 4:x}")
        if reloc.type != elf.R_MIPS_32:
            raise ProbeError("UNSUPPORTED", f"table relocation {idx} is {reloc.type_name}, expected R_MIPS_32")
        if reloc.symbol != function_symbol:
            raise ProbeError("UNSUPPORTED", f"table relocation {idx} symbol is {reloc.symbol!r}, expected {function_symbol!r}")
        if not reloc.addend_valid:
            raise ProbeError("UNSUPPORTED", "invalid table relocation addend")
    addends = tuple(reloc.addend & 0xFFFFFFFF for reloc in table_relocations)
    if addends != tuple(table_words):
        raise ProbeError("FAIL", f"table words disagree with relocation addends for {function_symbol}")
    if any(offset % 4 != 0 or offset >= function_size for offset in addends):
        raise ProbeError("FAIL", f"table target is outside aligned function code for {function_symbol}")
    return addends


def validate_linked_structure(
    module: elf.ElfFile,
    *,
    label: str,
    expected_cases: Sequence[tuple[int, str, str, int, int]],
    expected_rodata_addr: int = RODATA_START,
) -> tuple[elf.Section, elf.Section]:
    """Require one executable section (.text at 0x0/0x7F4), correct symbols and rodata layout."""
    executable = tuple(
        section.name for section in module.sections if section.flags & mips.SHF_EXECINSTR
    )
    if executable != (".text",):
        raise ProbeError("FAIL", f"{label} executable sections are {list(executable)}, expected ['.text']")
    text = module.require_section(".text")
    if text.addr != TEXT_START or text.size != TEXT_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} .text layout is {text.addr:#x}/{text.size:#x}, expected 0x{TEXT_START:x}/0x{TEXT_SIZE:x}",
        )
    rodata = module.require_section(".rodata")
    if rodata.addr != expected_rodata_addr or rodata.size != RODATA_SIZE:
        raise ProbeError(
            "FAIL",
            f"{label} .rodata layout is {rodata.addr:#x}/{rodata.size:#x}, expected 0x{expected_rodata_addr:x}/0x{RODATA_SIZE:x}",
        )

    # Validate defined symbols for all 15 functions
    for addr, c_name, _status, _mw, total_w in expected_cases:
        func_sym_name = mips.function_name(addr)
        matching_symbols = [s for s in module.symbols if s.name == func_sym_name]
        if len(matching_symbols) != 1:
            raise ProbeError("FAIL", f"{label} does not define exactly one symbol for {func_sym_name}")
        sym = matching_symbols[0]
        if sym.value != addr:
            raise ProbeError(
                "FAIL", f"{label} function symbol {func_sym_name} is at 0x{sym.value:x}, expected 0x{addr:x}"
            )
        if sym.size != total_w * 4:
            raise ProbeError(
                "FAIL", f"{label} function symbol {func_sym_name} size is 0x{sym.size:x}, expected 0x{total_w * 4:x}"
            )
        if sym.shndx != module.sections.index(text):
            raise ProbeError("FAIL", f"{label} function symbol {func_sym_name} is not in .text")

    # Validate fragment layout symbol
    frag_symbols = [s for s in module.symbols if s.name == FRAGMENT_SYMBOL]
    if len(frag_symbols) != 1:
        raise ProbeError("FAIL", f"{label} does not define layout symbol {FRAGMENT_SYMBOL}")
    frag_sym = frag_symbols[0]
    if frag_sym.value != FRAGMENT_START:
        raise ProbeError(
            "FAIL", f"{label} layout symbol {FRAGMENT_SYMBOL} is at 0x{frag_sym.value:x}, expected 0x{FRAGMENT_START:x}"
        )

    # Validate .mwcats if present
    mwcats = module.section(".mwcats")
    if mwcats is not None:
        expected_mwcats_size = len(expected_cases) * 8
        if mwcats.size != expected_mwcats_size:
            raise ProbeError(
                "FAIL",
                f"{label} .mwcats size is 0x{mwcats.size:x}, expected 0x{expected_mwcats_size:x}",
            )

    return text, rodata


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


def not_run_controls() -> dict[str, dict[str, object]]:
    """Return explicit NOT_RUN records when baseline equality does not hold."""
    reason = "baseline diverged from original PRX; equality-dependent controls skipped"
    return {
        label: {
            "status": "NOT_RUN",
            "detected": False,
            "reason": reason,
            "promoted_to_matched": False,
        }
        for label in ("B", "C", "D", "E")
    }


def _write_u32(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = int(value).to_bytes(4, "little")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe_integrated_module_equivalence",
        description=__doc__.splitlines()[0],
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=(
            Path("config/wsl/seto.toml")
            if (REPO_ROOT / "config/wsl/seto.toml").is_file()
            else Path("config/seto.toml")
        ),
        help="path to toolchain config",
    )
    parser.add_argument(
        "--prx",
        type=Path,
        default=Path("private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"),
        help="path to original libhtml_view.prx",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build/seto017"),
        help="confined build directory",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("build/seto017/integrated-module-equivalence.json"),
        help="destination of canonical JSON report",
    )
    return parser


def _base_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "module": MODULE_NAME,
        "experiment_status": "FAIL",
        "equivalence_claim": "UNPROVEN",
        "independent_identity_proven": False,
        "promoted_to_matched": False,
        "runtime_comparison": "NOT_DEMONSTRATED",
        "error": None,
    }


def finalize_experiment_report(report: dict[str, object]) -> int:
    """Classify the integrated experiment report and enforce conditional invariants."""
    code = report.get("code", {})
    jump_table = report.get("jump_table", {})
    equal_words = code.get("equal_words")
    total_words = code.get("total_words")
    code_diffs = code.get("differences", [])
    equal_entries = jump_table.get("equal_entries")
    total_entries = jump_table.get("entry_count")
    table_diffs = jump_table.get("differences", [])

    is_equal = (
        equal_words == total_words
        and len(code_diffs) == 0
        and equal_entries == total_entries
        and len(table_diffs) == 0
    )

    if is_equal:
        report["experiment_status"] = "PASS"
        report["equivalence_claim"] = "ASSUMPTION_DEPENDENT"
        exit_code = 0
    else:
        report["experiment_status"] = "DIVERGENCE"
        report["equivalence_claim"] = "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"
        exit_code = DIVERGENCE_EXIT_CODE

    report["independent_identity_proven"] = False
    report["promoted_to_matched"] = False
    report["runtime_comparison"] = "NOT_DEMONSTRATED"
    return exit_code


def run_experiment(arguments: argparse.Namespace) -> tuple[int, dict[str, object]]:
    build_root = _validated_build_root()
    build_dir = repo_path(arguments.build_dir, repo_root=REPO_ROOT, allowed_root=build_root)
    out = repo_path(arguments.out, repo_root=REPO_ROOT, allowed_root=build_root)
    prx_path = repo_path(arguments.prx, repo_root=REPO_ROOT, allowed_root=REPO_ROOT)
    config_path = repo_path(
        arguments.config,
        repo_root=REPO_ROOT,
        allowed_root=(REPO_ROOT / "config").resolve(),
    )

    ensure_build_dir(build_dir, build_root)
    objects_dir = build_dir / "candidate_objects"
    links_dir = build_dir / "links"
    logs_dir = build_dir / "logs"
    for d in (objects_dir, links_dir, logs_dir):
        ensure_build_dir(d, build_root)

    report = _base_report()
    cases = ordered_inventory()
    intervals = compute_layout_intervals(cases)
    validate_layout_intervals(intervals)

    # Provenance tracking
    source_hashes: dict[str, str] = {}
    for _addr, c_name, _status, _mw, _tw in cases:
        src = REPO_ROOT / "decomp" / "src" / c_name
        if not src.is_file():
            raise ProbeError("BLOCKED", f"missing source file {c_name}")
        source_hashes[c_name] = sha256_file(src)

    prx_hash = sha256_file(prx_path)

    # Environment for tools
    env = dict(os.environ)
    paths = [str(REPO_ROOT / "src"), str(REPO_ROOT / "scripts")]
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)

    # Check linker availability
    linker_cmd = shutil.which(LINKER)
    if linker_cmd is None:
        report["experiment_status"] = "BLOCKED"
        report["error"] = f"linker {LINKER} is not available on PATH"
        ensure_build_dir(out.parent, build_root)
        write_build_text(out, canonical_json(report), build_root)
        return 4, report

    linker_version_proc = run([LINKER, "--version"], cwd=REPO_ROOT, timeout=30)
    linker_version = (
        linker_version_proc.stdout.splitlines()[0]
        if linker_version_proc.returncode == 0 and linker_version_proc.stdout
        else LINKER
    )

    # Toolchain version identification
    import re

    mw_version = "Metrowerks 3.0.1 build 219"
    wibo_version = "wibo"
    toolchain_result = run(
        [sys.executable, "-m", "seto", "--config", relative(config_path, REPO_ROOT), "toolchain"],
        cwd=REPO_ROOT,
        timeout=120,
        env=env,
    )
    write_build_text(logs_dir / "seto-toolchain.stdout.txt", toolchain_result.stdout, build_root)
    write_build_text(logs_dir / "seto-toolchain.stderr.txt", toolchain_result.stderr, build_root)
    for line in toolchain_result.stdout.splitlines():
        if line.lstrip().startswith("mwccpsp") and (found := re.search(r"\bVersion\s+([0-9.]+\s+build\s+\d+)", line)):
            mw_version = f"Metrowerks {found.group(1)}"
        elif line.lstrip().startswith("wibo") and (found := re.search(r"\bwibo\s+([0-9.]+)", line)):
            wibo_version = f"wibo {found.group(1)}"

    # 1. Compile all 15 functions fresh and validate individual baselines
    candidate_objects: dict[str, Path] = {}
    candidate_hashes: dict[str, str] = {}
    match_records: dict[str, dict[str, object]] = {}
    compiler_info: dict[str, object] = {
        "compiler": mw_version,
        "loader": wibo_version,
        "flags": ["-O4,p", "-sdatathreshold", "0"],
        "includes": ["decomp/include"],
    }

    for addr, c_name, expected_status, expected_matching, total_w in cases:
        src = REPO_ROOT / "decomp" / "src" / c_name
        obj_name = Path(c_name).with_suffix(".o").name
        obj_path = objects_dir / obj_name
        report_path = objects_dir / f"{c_name}.match.json"

        # Wipe previous artifact to guarantee fresh compilation
        if obj_path.exists():
            obj_path.unlink()
        if report_path.exists():
            report_path.unlink()

        match_cmd = [
            sys.executable,
            "scripts/match_function.py",
            "--config",
            relative(config_path, REPO_ROOT),
            "--prx",
            relative(prx_path, REPO_ROOT),
            "--function",
            hex(addr),
            "--source",
            relative(src, REPO_ROOT),
            "--out",
            relative(objects_dir, REPO_ROOT),
            "--report",
            relative(report_path, REPO_ROOT),
            "--json",
        ]
        match_result = run(match_cmd, cwd=REPO_ROOT, timeout=600, env=env)
        write_build_text(logs_dir / f"match-{c_name}.stdout.json", match_result.stdout, build_root)
        write_build_text(logs_dir / f"match-{c_name}.stderr.txt", match_result.stderr, build_root)

        if match_result.returncode == 4:
            report["experiment_status"] = "BLOCKED"
            report["error"] = f"match_function reports compiler or loader unavailable for {c_name}"
            ensure_build_dir(out.parent, build_root)
            write_build_text(out, canonical_json(report), build_root)
            return 4, report

        expected_code = 0 if expected_status == "MATCHED" else 5
        if match_result.returncode != expected_code:
            raise ProbeError(
                "FAIL",
                f"fresh match_function for {c_name} exited {match_result.returncode}, expected {expected_code}/{expected_status}",
            )

        if not obj_path.is_file() or not report_path.is_file():
            raise ProbeError(
                "FAIL", f"fresh match_function for {c_name} did not produce both object and provenance report"
            )

        try:
            m_rec = json.loads(match_result.stdout)
        except json.JSONDecodeError as exc:
            raise ProbeError("FAIL", f"match_function for {c_name} did not emit valid JSON: {exc}") from exc

        validate_saved_match_record(m_rec, json.loads(report_path.read_text(encoding="utf-8")))
        match_payload = m_rec.get("match", {})
        if (
            m_rec.get("status") != expected_status
            or match_payload.get("status") != expected_status
            or match_payload.get("matching_words") != expected_matching
            or match_payload.get("total_words") != total_w
        ):
            raise ProbeError("FAIL", f"fresh compile of {c_name} deviates from documented baseline")

        prov = m_rec.get("provenance", {})
        obj_hash = sha256_file(obj_path)
        validate_recorded_hash(f"{c_name} object", obj_hash, prov.get("object_sha256"))
        validate_recorded_hash(f"{c_name} source", source_hashes[c_name], prov.get("source_sha256"))
        candidate_objects[c_name] = obj_path
        candidate_hashes[c_name] = obj_hash
        match_records[c_name] = m_rec

    # Validate individual candidate object structural invariants
    func_symbols: dict[str, elf.Symbol] = {}
    table_relocs_39c: tuple[elf.Relocation, ...] = ()
    table_words_39c: tuple[int, ...] = ()
    table_relocs_414: tuple[elf.Relocation, ...] = ()
    table_words_414: tuple[int, ...] = ()

    for addr, c_name, _status, _mw, total_w in cases:
        obj_path = candidate_objects[c_name]
        c_mod = elf.parse(obj_path)
        require_mips_elf(c_mod, file_type=elf.ET_REL, label=f"candidate object {c_name}")
        c_text = c_mod.require_section(".text")
        func_name = mips.function_name(addr)
        syms = [s for s in c_mod.symbols if s.name == func_name]
        if len(syms) != 1 or not syms[0].is_defined or syms[0].size != total_w * 4:
            raise ProbeError("FAIL", f"{c_name} does not define {func_name} with size 0x{total_w * 4:x}")
        func_symbols[func_name] = syms[0]

        if c_name == "func_0000039C.c":
            rodata_sec = c_mod.section(".rodata")
            if rodata_sec is None or rodata_sec.size != TABLE_39C_SIZE:
                raise ProbeError("UNSUPPORTED", f"func_0000039C.o has invalid .rodata size")
            t_words = mips.decode_words(c_mod.section_data(rodata_sec), "39C table")
            t_rels = tuple(sorted(c_mod.relocations_for(".rodata"), key=lambda r: r.section_offset or 0))
            validate_candidate_table_invariants(
                t_rels, t_words, function_symbol=func_name, expected_entries=TABLE_39C_ENTRIES, function_size=total_w * 4
            )
            table_relocs_39c = t_rels
            table_words_39c = t_words
        elif c_name == "func_00000414.c":
            rodata_sec = c_mod.section(".rodata")
            if rodata_sec is None or rodata_sec.size != TABLE_414_SIZE:
                raise ProbeError("UNSUPPORTED", f"func_00000414.o has invalid .rodata size")
            t_words = mips.decode_words(c_mod.section_data(rodata_sec), "414 table")
            t_rels = tuple(sorted(c_mod.relocations_for(".rodata"), key=lambda r: r.section_offset or 0))
            validate_candidate_table_invariants(
                t_rels, t_words, function_symbol=func_name, expected_entries=TABLE_414_ENTRIES, function_size=total_w * 4
            )
            table_relocs_414 = t_rels
            table_words_414 = t_words
        else:
            if c_mod.section(".rodata") is not None and c_mod.section(".rodata").size > 0:
                raise ProbeError("UNSUPPORTED", f"unexpected .rodata in {c_name}")

    # Parse original PRX to extract baseline words, tables and calls
    original_prx = elf.parse(prx_path)
    require_mips_elf(original_prx, file_type=elf.ET_MIPS_PSP_PRX, label="original PRX")
    prx_text = original_prx.require_section(".text")
    if prx_text.addr != TEXT_START or prx_text.size != TEXT_SIZE:
        raise ProbeError(
            "FAIL",
            f"PRX .text is 0x{prx_text.addr:x}/0x{prx_text.size:x}, expected 0x{TEXT_START:x}/0x{TEXT_SIZE:x}",
        )
    prx_text_words = tuple(mips.decode_words(original_prx.section_data(prx_text), "PRX .text"))
    if len(prx_text_words) != TEXT_WORDS:
        raise ProbeError("FAIL", f"decoded {len(prx_text_words)} PRX words, expected {TEXT_WORDS}")

    # Verify fragment words in PRX
    frag_word_0 = prx_text_words[FRAGMENT_START // 4]
    frag_word_1 = prx_text_words[(FRAGMENT_START // 4) + 1]
    if (frag_word_0, frag_word_1) != FRAGMENT_WORDS:
        raise ProbeError(
            "FAIL",
            f"original PRX at 0x84 holds (0x{frag_word_0:08x}, 0x{frag_word_1:08x}), expected (0x{FRAGMENT_WORDS[0]:08x}, 0x{FRAGMENT_WORDS[1]:08x})",
        )

    # Extract original table words from PRX .data
    prx_data_sec = next(
        (s for s in original_prx.sections if s.addr <= RODATA_START < s.addr + s.size), None
    )
    if prx_data_sec is None:
        raise ProbeError("FAIL", "could not find PRX section covering jump tables at 0x4770")
    prx_data_bytes = original_prx.section_data(prx_data_sec)
    rodata_offset_in_data = RODATA_START - prx_data_sec.addr
    table_slice = prx_data_bytes[rodata_offset_in_data : rodata_offset_in_data + RODATA_SIZE]
    prx_table_words = tuple(mips.decode_words(table_slice, "PRX jump tables"))
    if len(prx_table_words) != TOTAL_TABLE_ENTRIES:
        raise ProbeError("FAIL", f"decoded {len(prx_table_words)} table entries, expected {TOTAL_TABLE_ENTRIES}")

    expected_prx_tables = TABLE_39C_EXPECTED_TARGETS + TABLE_414_EXPECTED_TARGETS
    if prx_table_words != expected_prx_tables:
        raise ProbeError(
            "FAIL",
            f"original PRX jump table words {prx_table_words} do not match documented targets {expected_prx_tables}",
        )

    # Recover PRX calls and classify into 22 local and 50 import
    import_table = imports.build_import_table(original_prx)
    prx_calls = imports.call_references(
        original_prx, import_table, section=".text", start=TEXT_START, end=TEXT_START + TEXT_SIZE
    )
    if len(prx_calls) != TOTAL_CALLS:
        raise ProbeError("FAIL", f"expected {TOTAL_CALLS} PRX calls, got {len(prx_calls)}")
    prx_local_calls = [r for r in prx_calls if r.kind == "local"]
    prx_import_calls = [r for r in prx_calls if r.kind == "import"]
    prx_unresolved_calls = [r for r in prx_calls if r.kind == "unresolved"]

    if len(prx_local_calls) != LOCAL_CALLS or len(prx_import_calls) != IMPORT_CALLS or prx_unresolved_calls:
        raise ProbeError(
            "FAIL",
            f"call classification mismatch: {len(prx_local_calls)} local, {len(prx_import_calls)} import, {len(prx_unresolved_calls)} unresolved",
        )

    # 2. Linker scripts and Controlled Link
    script_text = generate_linker_script(cases, rodata_address=RODATA_START)
    script_path = build_dir / "integrated.ld"
    write_build_text(script_path, script_text, build_root)
    script_hash = sha256_file(script_path)

    # All controlled defsyms: 35 imports + 11 data symbols
    controlled_symbols_a: dict[str, int] = dict(CONTROLLED_IMPORTS)
    controlled_symbols_a.update(CONTROLLED_DATA_SYMBOLS)

    ordered_obj_paths = [candidate_objects[c_name] for _addr, c_name, _st, _mw, _tw in cases]

    def _execute_link(
        variant_name: str,
        script_file: Path,
        symbols_map: dict[str, int],
        objects_list: Sequence[Path],
    ) -> tuple[Path, elf.ElfFile, list[str]]:
        v_dir = links_dir / variant_name
        ensure_build_dir(v_dir, build_root)
        out_elf = v_dir / "linked.elf"
        cmd = [
            LINKER,
            "-EL",
            "-m",
            "elf32ltsmip",
            "--orphan-handling=error",
            "-T",
            relative(script_file, REPO_ROOT),
            "-o",
            relative(out_elf, REPO_ROOT),
            *[f"--defsym={sym}=0x{addr:x}" for sym, addr in sorted(symbols_map.items())],
            *[relative(obj, REPO_ROOT) for obj in objects_list],
        ]
        res = run(cmd, cwd=REPO_ROOT, timeout=120)
        write_build_text(logs_dir / f"link-{variant_name}.stdout.txt", res.stdout, build_root)
        write_build_text(logs_dir / f"link-{variant_name}.stderr.txt", res.stderr, build_root)
        if res.returncode != 0:
            raise ProbeError("FAIL", f"linking variant {variant_name} failed: {res.stderr}")
        if not out_elf.is_file():
            raise ProbeError("FAIL", f"linker did not produce {out_elf}")
        linked_mod = elf.parse(out_elf)
        require_mips_elf(linked_mod, file_type=elf.ET_EXEC, label=f"linked ELF {variant_name}")
        validate_link_has_no_unresolved(linked_mod)
        validate_linked_controlled_symbols(linked_mod, symbols_map)
        return out_elf, linked_mod, cmd

    # Link Variant A (Baseline)
    elf_a_path, elf_a_mod, cmd_a = _execute_link(
        "variant-a", script_path, controlled_symbols_a, ordered_obj_paths
    )
    sec_a_text, sec_a_rodata = validate_linked_structure(
        elf_a_mod, label="variant-a", expected_cases=cases
    )
    words_a = tuple(mips.decode_words(elf_a_mod.section_data(sec_a_text), "Variant A text"))
    entries_a = tuple(mips.decode_words(elf_a_mod.section_data(sec_a_rodata), "Variant A rodata"))

    # Compare Variant A against PRX
    text_diffs = compare_word_sequences(prx_text_words, words_a)
    table_diffs = compare_table_entries(prx_table_words, entries_a)

    equal_words_count = TEXT_WORDS - len(text_diffs)
    equal_entries_count = TOTAL_TABLE_ENTRIES - len(table_diffs)

    baseline_equal = (len(text_diffs) == 0 and len(table_diffs) == 0)

    # Build detailed per-word comparison rows
    word_comparison_rows: list[dict[str, object]] = []
    current_iv_idx = 0
    for idx, (orig_w, link_w) in enumerate(zip(prx_text_words, words_a, strict=True)):
        w_addr = TEXT_START + idx * 4
        # Advance interval
        while (
            current_iv_idx < len(intervals) - 1
            and w_addr >= intervals[current_iv_idx].end
        ):
            current_iv_idx += 1
        iv = intervals[current_iv_idx]
        is_frag = iv.kind == "ORIGINAL_UNRECONSTRUCTED_FRAGMENT"
        word_comparison_rows.append(
            {
                "word_index": idx,
                "address": f"0x{w_addr:x}",
                "original": f"0x{orig_w:08x}",
                "linked": f"0x{link_w:08x}",
                "match": orig_w == link_w,
                "interval_symbol": iv.symbol,
                "is_unreconstructed_fragment": is_frag,
            }
        )

    # 3. Negative Controls A through E
    control_records: dict[str, dict[str, object]] = {
        "A": {
            "status": "PASS" if baseline_equal else "DIVERGENCE",
            "equal_words": equal_words_count,
            "total_words": TEXT_WORDS,
            "equal_entries": equal_entries_count,
            "total_entries": TOTAL_TABLE_ENTRIES,
            "detected": baseline_equal,
            "promoted_to_matched": False,
        }
    }

    if baseline_equal:
        # Control B: Mutate shared symbol D_000047D0 from 0x47D0 to 0x47D4
        controlled_symbols_b = dict(controlled_symbols_a)
        controlled_symbols_b[SHARED_DATA_SYMBOL] = SHARED_DATA_MUTATED_ADDRESS
        elf_b_path, elf_b_mod, _cmd_b = _execute_link(
            "control-b", script_path, controlled_symbols_b, ordered_obj_paths
        )
        sec_b_text, sec_b_rodata = validate_linked_structure(
            elf_b_mod, label="control-b", expected_cases=cases
        )
        words_b = tuple(mips.decode_words(elf_b_mod.section_data(sec_b_text), "Control B text"))
        entries_b = tuple(mips.decode_words(elf_b_mod.section_data(sec_b_rodata), "Control B rodata"))
        b_vs_a_text_diffs = [
            {"word_index": i, "address": f"0x{TEXT_START + i * 4:x}", "a": f"0x{w_a:08x}", "b": f"0x{w_b:08x}"}
            for i, (w_a, w_b) in enumerate(zip(words_a, words_b, strict=True))
            if w_a != w_b
        ]
        b_vs_a_table_diffs = compare_table_entries(entries_a, entries_b)

        # Expected differences in Control B: exactly words 24 and 36 of func_00000414 (addresses 0x474 and 0x4A4)
        expected_b_indices = [(0x414 // 4) + 24, (0x414 // 4) + 36]  # [285, 297]
        actual_b_indices = [row["word_index"] for row in b_vs_a_text_diffs]
        if actual_b_indices != expected_b_indices or len(b_vs_a_table_diffs) != 0:
            raise ProbeError(
                "FAIL",
                f"Control B mutation did not isolate the two D_000047D0 sites: text_diffs={b_vs_a_text_diffs}, table_diffs={b_vs_a_table_diffs}",
            )
        control_records["B"] = {
            "status": "PASS",
            "mutation": f"reassigned {SHARED_DATA_SYMBOL} from 0x{CONTROLLED_DATA_SYMBOLS[SHARED_DATA_SYMBOL]:x} to 0x{SHARED_DATA_MUTATED_ADDRESS:x}",
            "affected_addresses": [f"0x{TEXT_START + idx * 4:x}" for idx in actual_b_indices],
            "text_differences_count": len(b_vs_a_text_diffs),
            "table_differences_count": len(b_vs_a_table_diffs),
            "detected": True,
            "promoted_to_matched": False,
        }

        # Helper to produce tampered object copy
        def _tamper_object_copy(label: str, target_c_name: str, mutations: list[tuple[int, int]]) -> Path:
            stem = Path(target_c_name).stem
            orig_obj = candidate_objects[target_c_name]
            raw = bytearray(orig_obj.read_bytes())
            for offset, val in mutations:
                _write_u32(raw, offset, val)
            t_path = build_dir / f"{stem}.tampered-{label}.o"
            write_build_bytes(t_path, bytes(raw), build_root)
            return t_path

        # Control C: Mutate jump table pre-link (swap addends of entries 0 and 1 in func_00000414.o)
        mod_414 = elf.parse(candidate_objects["func_00000414.c"])
        rodata_414_sec = mod_414.require_section(".rodata")
        offset_c_entry0 = rodata_414_sec.offset
        offset_c_entry1 = rodata_414_sec.offset + 4
        c_tampered_obj = _tamper_object_copy(
            "control-c",
            "func_00000414.c",
            [
                (offset_c_entry0, TABLE_414_EXPECTED_OFFSETS[1]),
                (offset_c_entry1, TABLE_414_EXPECTED_OFFSETS[0]),
            ],
        )
        c_obj_list = [
            c_tampered_obj if p.name == "func_00000414.o" else p for p in ordered_obj_paths
        ]
        elf_c_path, elf_c_mod, _cmd_c = _execute_link(
            "control-c", script_path, controlled_symbols_a, c_obj_list
        )
        sec_c_text, sec_c_rodata = validate_linked_structure(
            elf_c_mod, label="control-c", expected_cases=cases
        )
        words_c = tuple(mips.decode_words(elf_c_mod.section_data(sec_c_text), "Control C text"))
        entries_c = tuple(mips.decode_words(elf_c_mod.section_data(sec_c_rodata), "Control C rodata"))
        c_vs_a_text_diffs = [
            {"word_index": i} for i, (w_a, w_c) in enumerate(zip(words_a, words_c, strict=True)) if w_a != w_c
        ]
        c_vs_a_table_diffs = compare_table_entries(entries_a, entries_c)
        # Expected: 0 text diffs, entries 6 and 7 swapped (the first two entries of func_00000414's table)
        if len(c_vs_a_text_diffs) != 0 or [r["entry_index"] for r in c_vs_a_table_diffs] != [6, 7]:
            raise ProbeError(
                "FAIL",
                f"Control C did not isolate jump table entries 6 and 7: text_diffs={c_vs_a_text_diffs}, table_diffs={c_vs_a_table_diffs}",
            )
        control_records["C"] = {
            "status": "PASS",
            "mutation": "swapped pre-link addends of entries 0 and 1 in func_00000414.o .rodata",
            "affected_table_entries": [6, 7],
            "text_differences_count": len(c_vs_a_text_diffs),
            "table_differences_count": len(c_vs_a_table_diffs),
            "detected": True,
            "promoted_to_matched": False,
        }

        # Control D: Non-relocated instruction bit flip (word 0 of func_00000034.o)
        mod_034 = elf.parse(candidate_objects["func_00000034.c"])
        text_034_sec = mod_034.require_section(".text")
        word0_offset = text_034_sec.offset
        word0_val = int.from_bytes(mod_034.section_data(text_034_sec)[:4], "little")
        mutated_word0 = word0_val ^ 0x1
        d_tampered_obj = _tamper_object_copy(
            "control-d", "func_00000034.c", [(word0_offset, mutated_word0)]
        )
        d_obj_list = [
            d_tampered_obj if p.name == "func_00000034.o" else p for p in ordered_obj_paths
        ]
        elf_d_path, elf_d_mod, _cmd_d = _execute_link(
            "control-d", script_path, controlled_symbols_a, d_obj_list
        )
        sec_d_text, sec_d_rodata = validate_linked_structure(
            elf_d_mod, label="control-d", expected_cases=cases
        )
        words_d = tuple(mips.decode_words(elf_d_mod.section_data(sec_d_text), "Control D text"))
        entries_d = tuple(mips.decode_words(elf_d_mod.section_data(sec_d_rodata), "Control D rodata"))
        d_vs_a_text_diffs = [
            {"word_index": i, "address": f"0x{TEXT_START + i * 4:x}"}
            for i, (w_a, w_d) in enumerate(zip(words_a, words_d, strict=True))
            if w_a != w_d
        ]
        d_vs_a_table_diffs = compare_table_entries(entries_a, entries_d)
        expected_d_index = 0x34 // 4  # 13
        if [r["word_index"] for r in d_vs_a_text_diffs] != [expected_d_index] or len(d_vs_a_table_diffs) != 0:
            raise ProbeError(
                "FAIL",
                f"Control D bit flip was not isolated to address 0x34: text_diffs={d_vs_a_text_diffs}, table_diffs={d_vs_a_table_diffs}",
            )
        control_records["D"] = {
            "status": "PASS",
            "mutation": "flipped bit 0 of non-relocated instruction word 0 in func_00000034.o",
            "affected_address": "0x34",
            "text_differences_count": len(d_vs_a_text_diffs),
            "table_differences_count": len(d_vs_a_table_diffs),
            "detected": True,
            "promoted_to_matched": False,
        }

        # Control E: Local call mutation (mutate local call reference in func_0000008C.o from func_00000134 to func_00000244)
        orig_08c_bytes = bytearray(candidate_objects["func_0000008C.c"].read_bytes())
        if b"func_00000134\x00" not in orig_08c_bytes:
            raise ProbeError("FAIL", "could not find local call symbol func_00000134 in func_0000008C.o string table")
        mutated_08c_bytes = bytes(orig_08c_bytes.replace(b"func_00000134\x00", b"func_00000244\x00", 1))
        e_tampered_obj = build_dir / "func_0000008C.tampered-control-e.o"
        write_build_bytes(e_tampered_obj, mutated_08c_bytes, build_root)
        e_obj_list = [
            e_tampered_obj if p.name == "func_0000008C.o" else p for p in ordered_obj_paths
        ]
        elf_e_path, elf_e_mod, _cmd_e = _execute_link(
            "control-e", script_path, controlled_symbols_a, e_obj_list
        )
        sec_e_text, sec_e_rodata = validate_linked_structure(
            elf_e_mod, label="control-e", expected_cases=cases
        )
        words_e = tuple(mips.decode_words(elf_e_mod.section_data(sec_e_text), "Control E text"))
        entries_e = tuple(mips.decode_words(elf_e_mod.section_data(sec_e_rodata), "Control E rodata"))
        e_vs_a_text_diffs = [
            {"word_index": i, "address": f"0x{TEXT_START + i * 4:x}", "a": f"0x{w_a:08x}", "e": f"0x{w_e:08x}"}
            for i, (w_a, w_e) in enumerate(zip(words_a, words_e, strict=True))
            if w_a != w_e
        ]
        e_vs_a_table_diffs = compare_table_entries(entries_a, entries_e)
        expected_e_index = 0x118 // 4  # 70
        if [r["word_index"] for r in e_vs_a_text_diffs] != [expected_e_index] or len(e_vs_a_table_diffs) != 0:
            raise ProbeError(
                "FAIL",
                f"Control E local call mutation was not isolated to call site 0x118: text_diffs={e_vs_a_text_diffs}, table_diffs={e_vs_a_table_diffs}",
            )
        # Verify call target changed from 0x134 to 0x244
        target_e = mips.jump_target(words_e[expected_e_index], 0x118)
        if target_e != 0x244:
            raise ProbeError("FAIL", f"Control E call target is 0x{target_e:x}, expected 0x244")
        control_records["E"] = {
            "status": "PASS",
            "mutation": "retargeted local call in func_0000008C.o from func_00000134 (0x134) to func_00000244 (0x244)",
            "affected_call_site": "0x118",
            "original_call_target": "0x134",
            "mutated_call_target": "0x244",
            "text_differences_count": len(e_vs_a_text_diffs),
            "table_differences_count": len(e_vs_a_table_diffs),
            "detected": True,
            "promoted_to_matched": False,
        }
    else:
        control_records.update(not_run_controls())

    # Validate file hashes were preserved during entire probe
    validate_recorded_hash("PRX file", sha256_file(prx_path), prx_hash)
    for c_name, expected_src_h in source_hashes.items():
        validate_recorded_hash(f"{c_name} source", sha256_file(REPO_ROOT / "decomp" / "src" / c_name), expected_src_h)
    for c_name, expected_obj_h in candidate_hashes.items():
        validate_recorded_hash(f"{c_name} object", sha256_file(candidate_objects[c_name]), expected_obj_h)

    # Compile final canonical report
    executed_controls = [lbl for lbl, rec in control_records.items() if rec.get("detected")]

    report = {
        "schema_version": 1,
        "module": MODULE_NAME,
        "experiment_status": "PASS" if baseline_equal else "DIVERGENCE",
        "equivalence_claim": "ASSUMPTION_DEPENDENT" if baseline_equal else "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS",
        "independent_identity_proven": False,
        "promoted_to_matched": False,
        "runtime_comparison": "NOT_DEMONSTRATED",
        "summary": {
            "total_text_words": TEXT_WORDS,
            "equal_text_words": equal_words_count,
            "c_reconstructed_words": C_RECONSTRUCTED_WORDS,
            "equal_c_words": sum(
                1 for r in word_comparison_rows if not r["is_unreconstructed_fragment"] and r["match"]
            ),
            "unreconstructed_fragment_words": FRAGMENT_SIZE // 4,
            "equal_fragment_words": sum(
                1 for r in word_comparison_rows if r["is_unreconstructed_fragment"] and r["match"]
            ),
            "total_table_entries": TOTAL_TABLE_ENTRIES,
            "equal_table_entries": equal_entries_count,
            "functions_total": len(cases),
            "functions_matched": sum(1 for c in cases if c[2] == "MATCHED"),
            "functions_inconclusive": sum(1 for c in cases if c[2] == "INCONCLUSIVE"),
            "functions_nonmatching": 0,
            "total_calls": TOTAL_CALLS,
            "local_calls": LOCAL_CALLS,
            "import_calls": IMPORT_CALLS,
        },
        "fragment_0x84": {
            "address": f"0x{FRAGMENT_START:x}",
            "size_bytes": FRAGMENT_SIZE,
            "words": [f"0x{w:08x}" for w in FRAGMENT_WORDS],
            "classification": FRAGMENT_CLASSIFICATION,
            "verified_c_decompilation": False,
            "layout_symbol": FRAGMENT_SYMBOL,
            "referenced_by": "func_00000000",
            "matches_original_prx": (frag_word_0, frag_word_1) == FRAGMENT_WORDS,
        },
        "provenance": {
            "prx_path": relative(prx_path, REPO_ROOT),
            "prx_sha256": prx_hash,
            "compiler": compiler_info.get("compiler"),
            "loader": compiler_info.get("loader"),
            "flags": compiler_info.get("flags"),
            "includes": compiler_info.get("includes"),
            "linker": linker_version,
            "linker_emulation": "elf32ltsmip",
            "linker_script_path": relative(script_path, REPO_ROOT),
            "linker_script_sha256": script_hash,
            "candidate_sources": {
                c_name: {"path": f"decomp/src/{c_name}", "sha256": h}
                for c_name, h in sorted(source_hashes.items())
            },
            "candidate_objects": {
                c_name: {"path": relative(candidate_objects[c_name], REPO_ROOT), "sha256": h}
                for c_name, h in sorted(candidate_hashes.items())
            },
        },
        "functions_inventory": [
            {
                "function": mips.function_name(addr),
                "address": f"0x{addr:x}",
                "source": f"decomp/src/{c_name}",
                "expected_status": status,
                "matching_words": mw,
                "total_words": tw,
                "object_sha256": candidate_hashes[c_name],
            }
            for addr, c_name, status, mw, tw in cases
        ],
        "symbols": {
            "defined_functions_count": len(cases),
            "local_symbols": [mips.function_name(c[0]) for c in cases],
            "fragment_symbol": FRAGMENT_SYMBOL,
            "controlled_imports_count": len(CONTROLLED_IMPORTS),
            "controlled_imports": {
                sym: f"0x{addr:x}" for sym, addr in sorted(CONTROLLED_IMPORTS.items())
            },
            "controlled_data_count": len(CONTROLLED_DATA_SYMBOLS),
            "controlled_data": {
                sym: f"0x{addr:x}" for sym, addr in sorted(CONTROLLED_DATA_SYMBOLS.items())
            },
        },
        "layout": {
            "text": {
                "address": f"0x{TEXT_START:x}",
                "size": f"0x{TEXT_SIZE:x}",
                "intervals_count": len(intervals),
                "intervals": [
                    {
                        "symbol": iv.symbol,
                        "kind": iv.kind,
                        "start": f"0x{iv.start:x}",
                        "end": f"0x{iv.end:x}",
                        "size_bytes": iv.size_bytes,
                        "words_count": iv.words_count,
                    }
                    for iv in intervals
                ],
            },
            "rodata": {
                "address": f"0x{RODATA_START:x}",
                "size": f"0x{RODATA_SIZE:x}",
                "tables": [
                    {
                        "function": "func_0000039C",
                        "address": f"0x{TABLE_39C_START:x}",
                        "size": f"0x{TABLE_39C_SIZE:x}",
                        "entries": TABLE_39C_ENTRIES,
                    },
                    {
                        "function": "func_00000414",
                        "address": f"0x{TABLE_414_START:x}",
                        "size": f"0x{TABLE_414_SIZE:x}",
                        "entries": TABLE_414_ENTRIES,
                    },
                ],
            },
        },
        "calls": {
            "total_calls": TOTAL_CALLS,
            "local_calls_count": LOCAL_CALLS,
            "import_calls_count": IMPORT_CALLS,
            "local_calls_resolved_by_candidate_symbols": True,
            "local_calls": [
                {
                    "site_address": f"0x{c.address:x}",
                    "caller": next(iv.symbol for iv in intervals if iv.start <= c.address < iv.end),
                    "callee": mips.function_name(c.target),
                    "callee_address": f"0x{c.target:x}",
                }
                for c in prx_local_calls
            ],
            "import_calls": [
                {
                    "site_address": f"0x{c.address:x}",
                    "caller": next(iv.symbol for iv in intervals if iv.start <= c.address < iv.end),
                    "stub_symbol": mips.function_name(c.target),
                    "stub_address": f"0x{c.target:x}",
                    "imported_library": c.imported.library if c.imported else None,
                    "imported_nid": f"0x{c.imported.nid:08x}" if c.imported else None,
                }
                for c in prx_import_calls
            ],
        },
        "code": {
            "total_words": TEXT_WORDS,
            "equal_words": equal_words_count,
            "differences": text_diffs,
            "file_byte_comparison": True,
            "false_positive_controls": [c for c in ("B", "D", "E") if c in executed_controls],
        },
        "jump_table": {
            "original_address": f"0x{RODATA_START:x}",
            "original_section": RODATA_ORIGINAL_SECTION,
            "original_offset": f"0x{RODATA_ORIGINAL_OFFSET:x}",
            "candidate_section": ".rodata",
            "entry_count": TOTAL_TABLE_ENTRIES,
            "equal_entries": equal_entries_count,
            "differences": table_diffs,
            "table_39c": {
                "address": f"0x{TABLE_39C_START:x}",
                "entries": TABLE_39C_ENTRIES,
                "equal_entries": sum(1 for a, b in zip(prx_table_words[:6], entries_a[:6]) if a == b),
            },
            "table_414": {
                "address": f"0x{TABLE_414_START:x}",
                "entries": TABLE_414_ENTRIES,
                "equal_entries": sum(1 for a, b in zip(prx_table_words[6:], entries_a[6:]) if a == b),
            },
            "false_positive_controls": [c for c in ("C",) if c in executed_controls],
        },
        "controls": control_records,
        "assumptions": [
            {"section": ".text", "address": f"0x{TEXT_START:x}", "kind": "CONTROLLED_LAYOUT"},
            {"section": ".rodata", "address": f"0x{RODATA_START:x}", "kind": "CONTROLLED_LAYOUT"},
            *[
                {
                    "symbol": sym,
                    "address": f"0x{addr:x}",
                    "kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB",
                }
                for sym, addr in sorted(CONTROLLED_IMPORTS.items())
            ],
            *[
                {
                    "symbol": sym,
                    "address": f"0x{addr:x}",
                    "kind": "CONTROLLED_FROM_ORIGINAL_PRX_DATA_OFFSET",
                }
                for sym, addr in sorted(CONTROLLED_DATA_SYMBOLS.items())
            ],
        ],
        "limitations": [
            "code and jump-table equality hold only under the imposed .text/.rodata layout and controlled --defsym symbol assignments",
            "fragment 0x84-0x8C (jr $ra; nop) is an unreconstructed original binary fragment placed via linker script directives, not a verified C decompilation",
            "equality of 509/509 words does not imply 509 verified C decompilations",
            "external data symbols remain undefined externs resolved via --defsym; candidate objects contain no string or bss representations",
            "original PSP runtime relocations are not demonstrated; module load base is not inferred",
            "cross-artifact symbol and object identity between candidate objects and the original module is not proven",
        ],
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
