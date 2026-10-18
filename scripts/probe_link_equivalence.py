#!/usr/bin/env python3
"""Run the controlled post-link comparison for func_000004B8.

This is an experimental report, not a replacement for ``seto match``. A linked
word equality obtained with manually supplied symbols remains assumption-dependent
and never changes the original match classification.
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

FUNCTION_ADDRESS = 0x4B8
FUNCTION_SIZE = 0x50
FUNCTION_WORDS = FUNCTION_SIZE // 4
FUNCTION_NAME = "func_000004B8"
DATA_SYMBOL = "D_00004830"
DATA_TARGET = 0x4830
CALL_SYMBOL_SITES = (
    ("func_00000894", 0x4CC),
    ("func_00000854", 0x4DC),
    ("func_00002D0C", 0x4E4),
    ("func_000008A4", 0x4F0),
)
LINK_VARIANTS = (("A", 0x4830), ("B", 0x4834), ("C", 0x8004))
LINKER = "mipsel-linux-gnu-ld"
READELF = "mipsel-linux-gnu-readelf"
OBJDUMP = "mipsel-linux-gnu-objdump"
NM = "mipsel-linux-gnu-nm"
FILE = "file"


def compare_word_sequences(
    original: Sequence[int], candidate: Sequence[int], *, address: int = FUNCTION_ADDRESS
) -> list[dict[str, object]]:
    """Compare all words literally; no relocation masks or normalization apply."""
    return _compare_word_sequences(
        original, candidate, address=address, expected_words=FUNCTION_WORDS
    )


def equivalence_claim(equal_words: int) -> str:
    """Keep equality under controlled symbol assignments explicitly conditional."""
    if equal_words == FUNCTION_WORDS:
        return "ASSUMPTION_DEPENDENT"
    return "DIVERGENCE_UNDER_CONTROLLED_ASSIGNMENTS"


def validate_match_baseline(record: dict[str, object], returncode: int) -> dict[str, object]:
    payload = record.get("match")
    if not isinstance(payload, dict):
        raise ProbeError("FAIL", "match_function JSON is missing its comparator result")
    if (
        returncode != 5
        or record.get("status") != matching.INCONCLUSIVE
        or payload.get("status") != matching.INCONCLUSIVE
        or payload.get("matching_words") != 18
        or payload.get("total_words") != FUNCTION_WORDS
        or payload.get("difference_count") != 0
        or payload.get("relocation_issues")
    ):
        raise ProbeError("FAIL", "fresh compile does not match the required 18/20 INCONCLUSIVE baseline")
    return payload


def validate_linked_text_layout(module: elf.ElfFile) -> elf.Section:
    section = module.require_section(".text")
    if section.addr != FUNCTION_ADDRESS or section.size != FUNCTION_SIZE:
        raise ProbeError(
            "FAIL",
            f"linked .text layout is {section.addr:#x}/{section.size:#x}, expected 0x4b8/0x50",
        )
    return section


def validate_address_controls(
    baseline: Sequence[int], address_plus_four: Sequence[int], carry: Sequence[int]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    plus_four = compare_word_sequences(baseline, address_plus_four)
    carry_changes = compare_word_sequences(baseline, carry)
    if [row["word_index"] for row in plus_four] != [6]:
        raise ProbeError("FAIL", "case B did not change only the LO16 destination word")
    if [row["word_index"] for row in carry_changes] != [3, 6]:
        raise ProbeError("FAIL", "case C did not change exactly the carry-sensitive HI16/LO16 words")
    return plus_four, carry_changes


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


def _validated_build_root() -> Path:
    """Reject redirected build roots before resolving any path components."""
    return _validated_build_root_common(REPO_ROOT, subdir="seto014")


def _repo_path(value: Path, *, allowed_root: Path) -> Path:
    return _repo_path_common(value, repo_root=REPO_ROOT, allowed_root=allowed_root)


def _relative(path: Path) -> str:
    return _relative_common(path, REPO_ROOT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prx", type=Path, default=Path("private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx"))
    parser.add_argument("--source", type=Path, default=Path("decomp/src/func_000004B8.c"))
    parser.add_argument("--config", type=Path, default=Path("config/wsl/seto.toml"))
    parser.add_argument("--build-dir", type=Path, default=Path("build/seto014/r2"))
    parser.add_argument("--out", type=Path, default=Path("build/seto014/link-equivalence.json"))
    return parser


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run_common(argv, cwd=REPO_ROOT if cwd is None else cwd, timeout=timeout, env=env)


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


def _function_symbol(module: elf.ElfFile, name: str) -> elf.Symbol:
    symbols = [symbol for symbol in module.symbols if symbol.name == name]
    if len(symbols) != 1 or not symbols[0].is_function:
        raise ParseError(f"candidate object must define one function symbol {name}")
    return symbols[0]


def _text_relocation_evidence(
    module: elf.ElfFile,
    *,
    section_offset: int,
    words: tuple[int, ...],
    label: str,
) -> tuple[dict[str, object], dict[int, int]]:
    relocations = module.relocations_for(".text")
    sites = matching.relocation_sites(relocations, section_offset, FUNCTION_SIZE)
    pairing = matching.pair_hi16_lo16(sites.sites, words)
    if sites.limitations:
        raise ProbeError("UNSUPPORTED", f"{label} relocation placement has limitations: {sites.limitations}")
    expected = {3: 6}
    if pairing.hi_to_lo != expected or pairing.limitations:
        raise ProbeError(
            "UNSUPPORTED",
            f"{label} HI16/LO16 pairing differs from the verified pair: "
            f"{pairing.hi_to_lo}, {pairing.limitations}",
        )
    return (
        {
            "sites": [
                {
                    "word_index": index,
                    "type": site.type_name,
                    "symbol": site.symbol,
                    "symbol_index": site.symbol_index,
                    "addend": f"0x{site.addend & 0xffffffff:08x}",
                    "addend_valid": site.addend_valid,
                }
                for index, site in sorted(sites.sites.items())
            ],
            "pair_hi_to_lo": {str(key): value for key, value in pairing.hi_to_lo.items()},
            "pair_evidence": {str(key): value for key, value in pairing.evidence.items()},
            "limitations": list(pairing.limitations),
        },
        pairing.hi_to_lo,
    )


def _original_data_evidence(module: elf.ElfFile) -> dict[str, object]:
    references = datarefs.recover_references(module, ".text", FUNCTION_ADDRESS, FUNCTION_ADDRESS + FUNCTION_SIZE)
    reference = next((item for item in references if item.kind == "hi16-lo16"), None)
    if reference is None or reference.target is None:
        raise ProbeError("FAIL", "original PRX data target was not recovered")
    details = datarefs.data_target_details(module, reference.target)
    if details is None:
        raise ProbeError("FAIL", "original PRX data target has no validated file mapping")
    if reference.target.section != ".data" or reference.target.offset != 0xC8:
        raise ProbeError("FAIL", f"original PRX target differs from baseline: {reference.target}")
    section = module.require_section(".data")
    if section.is_nobits or reference.target.offset + 14 > section.size:
        raise ProbeError("FAIL", "original target bytes are not fully file-backed")
    data = module.section_data(section)
    target_bytes = data[reference.target.offset : reference.target.offset + 14]
    if reference.status != "PROVEN" or reference.location != "PROVEN" or reference.pairing != "PROVEN":
        raise ProbeError("FAIL", "original PRX data target/pair is not proven by Seto's existing API")
    if target_bytes != b"/PSP/SAVEDATA/":
        raise ProbeError("FAIL", "the bytes at the PRX-derived target do not match the recorded baseline string")
    return {
        "reference": reference.summary(),
        "target": details,
        "bytes_hex": target_bytes.hex(),
        "utf8": target_bytes.decode("utf-8", "strict"),
        "bytes_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "candidate_identity_proven": False,
    }


def _original_calls(module: elf.ElfFile) -> tuple[list[dict[str, object]], dict[str, int]]:
    table = imports.build_import_table(module)
    references = imports.call_references(
        module,
        table,
        section=".text",
        start=FUNCTION_ADDRESS,
        end=FUNCTION_ADDRESS + FUNCTION_SIZE,
    )
    if len(references) != len(CALL_SYMBOL_SITES):
        raise ProbeError("FAIL", f"expected four original call references, got {len(references)}")
    targets_by_site = {reference.address: reference for reference in references}
    expected_targets: dict[str, int] = {}
    rows: list[dict[str, object]] = []
    for symbol, site in CALL_SYMBOL_SITES:
        reference = targets_by_site.get(site)
        if reference is None or reference.kind != "import" or reference.imported is None:
            raise ProbeError("FAIL", f"original call at 0x{site:x} is not a resolved PRX import")
        expected_targets[symbol] = reference.target
        rows.append(
            {
                "candidate_symbol": symbol,
                "original_call_site": f"0x{site:x}",
                "original_stub_address": f"0x{reference.target:x}",
                "original_import": reference.imported.summary(),
                "assignment_kind": "CONTROLLED_FROM_ORIGINAL_PRX_IMPORT_STUB",
                "candidate_symbol_identity_independently_proven": False,
            }
        )
    return rows, expected_targets


def _original_psp_relocation_analysis(
    module: elf.ElfFile,
    words: tuple[int, ...],
    pairing: dict[int, int],
) -> dict[str, object]:
    section = module.require_section(".text")
    start_offset = FUNCTION_ADDRESS - section.addr
    rows = []
    for relocation in module.relocations_for(".text"):
        if relocation.section_offset is None:
            continue
        delta = relocation.section_offset - start_offset
        if delta < 0 or delta >= FUNCTION_SIZE:
            continue
        if relocation.format != "PSP":
            raise ProbeError("FAIL", "expected the original PRX relocations to use PSP format")
        word_index = delta // 4
        raw_word = words[word_index]
        relative = psp_reloc.relative_base(module, relocation, load_base=0)
        if relative is None:
            raise ProbeError("UNSUPPORTED", f"PSP relocation at 0x{relocation.offset:x} has no loadable relative segment")
        lo16_word = words[pairing[word_index]] if relocation.type == elf.R_MIPS_HI16 else None
        applied = psp_reloc.apply_relocation(
            relocation.type,
            raw_word,
            relative,
            lo16_word=lo16_word,
        )
        if applied is None:
            raise ProbeError("UNSUPPORTED", f"PSP relocation type {relocation.type_name} is not modeled")
        applied_pair_address = None
        if relocation.type == elf.R_MIPS_HI16:
            lo_index = pairing[word_index]
            lo_relocation = next(
                (
                    item
                    for item in module.relocations_for(".text")
                    if item.section_offset == start_offset + lo_index * 4
                ),
                None,
            )
            if lo_relocation is None:
                raise ProbeError("UNSUPPORTED", "paired PSP LO16 relocation is absent")
            lo_relative = psp_reloc.relative_base(module, lo_relocation, load_base=0)
            if lo_relative is None or lo_relative != relative:
                raise ProbeError("UNSUPPORTED", "paired PSP HI16/LO16 use different or unavailable relative bases")
            lo_applied = psp_reloc.apply_relocation(elf.R_MIPS_LO16, words[lo_index], lo_relative)
            if lo_applied is None:
                raise ProbeError("UNSUPPORTED", "PSP LO16 application is not modeled")
            applied_pair_address = f"0x{paired_effective_address(applied, lo_applied):x}"
        rows.append(
            {
                "site": f"0x{FUNCTION_ADDRESS + delta:x}",
                "type": relocation.type_name,
                "segment_index": relocation.segment_index,
                "relative_index": relocation.relative_index,
                "module_relative_base_load0": f"0x{relative:x}",
                "raw_word": f"0x{raw_word:08x}",
                "module_relative_applied_word": f"0x{applied:08x}",
                "module_relative_applied_pair_address": applied_pair_address,
                "actual_runtime_load_base_known": False,
            }
        )
    return {
        "coordinate_system": "on-disk PRX/module-relative; no actual runtime base inferred",
        "load_base_zero_is_model_only": True,
        "relocations": rows,
        "runtime_comparison": "NOT_DEMONSTRATED",
        "reason": "PSP loader load_base is not supplied by the PRX file; do not apply these transformations to the on-disk byte comparison or apply relocations twice",
    }


def _linker_script() -> str:
    """A target-specific script: fixed text layout and preserved MW metadata."""
    return '''OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(func_000004B8)
SECTIONS
{
  .mwcats 0 : SUBALIGN(4) { KEEP(*(.mwcats)) }
  .comment 0 : { *(.comment) }
  .text 0x4b8 : SUBALIGN(4) { *(.text) }
}
ASSERT(ADDR(.text) == 0x4b8, "func_000004B8 text address must be 0x4b8")
ASSERT(SIZEOF(.text) == 0x50, "func_000004B8 text size must be 0x50")
ASSERT(func_000004B8 == 0x4b8, "function symbol must be at 0x4b8")
ASSERT(SIZEOF(.mwcats) == 0x8, "Metrowerks .mwcats metadata must be retained")
'''


def _link(
    *,
    object_path: Path,
    script_path: Path,
    output_path: Path,
    data_address: int,
    call_targets: dict[str, int],
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
        f"--defsym={DATA_SYMBOL}=0x{data_address:x}",
    ]
    for symbol, _site in CALL_SYMBOL_SITES:
        args.append(f"--defsym={symbol}=0x{call_targets[symbol]:x}")
    args.extend(["-o", _relative(output_path), _relative(object_path)])
    result = _run(args, timeout=120)
    _write_build_text(logs_dir / f"{label}.ld.stdout.txt", result.stdout, build_root)
    _write_build_text(logs_dir / f"{label}.ld.stderr.txt", result.stderr, build_root)
    command_info = {"argv": args, "returncode": result.returncode}
    if result.returncode != 0:
        raise ProbeError("FAIL", f"GNU MIPSel link {label} failed: {result.stderr.strip()}")

    linked = elf.parse(output_path)
    _require_mips_elf(linked, file_type=elf.ET_EXEC, label=f"linked ELF {label}")
    text = validate_linked_text_layout(linked)
    function = _function_symbol(linked, FUNCTION_NAME)
    if function.value != FUNCTION_ADDRESS or function.size != FUNCTION_SIZE:
        raise ProbeError("FAIL", "linked function symbol address/size differs from target layout")
    executable_sections = [section.name for section in linked.sections if section.flags & mips.SHF_EXECINSTR]
    if executable_sections != [".text"]:
        raise ProbeError("FAIL", f"unexpected executable sections/stubs after link: {executable_sections}")
    if linked.require_section(".mwcats").size != 0x8:
        raise ProbeError("FAIL", "linked ELF does not preserve the input .mwcats metadata")
    validate_link_has_no_unresolved(linked)
    for symbol, target in ((DATA_SYMBOL, data_address), *call_targets.items()):
        resolved = [item for item in linked.symbols if item.name == symbol]
        if len(resolved) != 1 or resolved[0].value != target or resolved[0].shndx != elf.SHN_ABS:
            raise ProbeError("FAIL", f"linked symbol {symbol} does not equal its controlled assignment 0x{target:x}")

    # The .mwcats R_MIPS_32 site is metadata, not code; ensure it was applied to
    # the linked function instead of discarding the section or leaving a reloc.
    mwcats = linked.require_section(".mwcats")
    metadata = linked.section_data(mwcats)
    if len(metadata) < 8 or int.from_bytes(metadata[4:8], "little") != FUNCTION_ADDRESS:
        raise ProbeError("FAIL", "linked .mwcats function pointer was not resolved")
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
    undefined_output = _inspection_output(NM, ["-u", _relative(output_path)], logs_dir, f"{label}.nm")
    if undefined_output.strip():
        raise ProbeError("FAIL", f"nm reports undefined symbols after link: {undefined_output.strip()}")
    return linked, command_info


def _inspection_output(executable: str, args: list[str], logs_dir: Path, name: str) -> str:
    result = _run([executable, *args], timeout=60)
    _write_build_text(
        logs_dir / f"{name}.stderr.txt",
        result.stderr,
        _validated_build_root(),
    )
    if result.returncode != 0:
        raise ProbeError("FAIL", f"{executable} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def _linked_projection(
    original_words: tuple[int, ...],
    linked: elf.ElfFile,
    *,
    label: str,
    assigned_data: int,
    expected_calls: dict[str, int],
) -> dict[str, object]:
    text = linked.require_section(".text")
    mwcats = linked.require_section(".mwcats")
    mwcats_data = linked.section_data(mwcats)
    words = mips.decode_words(linked.section_data(text), f"linked {label}")
    if len(words) != FUNCTION_WORDS:
        raise ParseError(f"linked {label} .text has {len(words)} words, expected 20")
    pair_effective = paired_effective_address(words[3], words[6])
    if pair_effective != assigned_data:
        raise ProbeError("FAIL", f"linked {label} HI16/LO16 target is 0x{pair_effective:x}, expected 0x{assigned_data:x}")
    calls = {}
    for symbol, site in CALL_SYMBOL_SITES:
        index = (site - FUNCTION_ADDRESS) // 4
        actual = mips.jump_target(words[index], site)
        if actual != expected_calls[symbol]:
            raise ProbeError("FAIL", f"linked call at 0x{site:x} targets 0x{actual:x}, expected 0x{expected_calls[symbol]:x}")
        calls[symbol] = f"0x{actual:x}"
    differences = compare_word_sequences(original_words, words)
    return {
        "elf_header": linked.header.summary(),
        "sections": [section.summary() for section in linked.sections],
        "text_section": text.summary(),
        "mwcats": {
            "section": mwcats.summary(),
            "data_sha256": hashlib.sha256(mwcats_data).hexdigest(),
            "resolved_function_pointer": f"0x{int.from_bytes(mwcats_data[4:8], 'little'):x}",
        },
        "assigned_data_address": f"0x{assigned_data:x}",
        "linked_words": [f"0x{word:08x}" for word in words],
        "equal_words": FUNCTION_WORDS - len(differences),
        "total_words": FUNCTION_WORDS,
        "differences": differences,
        "hi16_word": f"0x{words[3]:08x}",
        "hi16_immediate": f"0x{mips.immediate(words[3]):04x}",
        "lo16_word": f"0x{words[6]:08x}",
        "lo16_immediate": f"0x{mips.immediate(words[6]):04x}",
        "lo16_signed": mips.signed_immediate(words[6]),
        "effective_data_address": f"0x{pair_effective:x}",
        "hi16_lo16_semantic_group": {
            "word_indices": [3, 6],
            "addresses": ["0x4c4", "0x4d0"],
            "effective_target": f"0x{pair_effective:x}",
            "controlled_target": f"0x{assigned_data:x}",
            "matches_original_target": pair_effective == DATA_TARGET,
        },
        "linked_call_targets": calls,
        "equivalence_claim": equivalence_claim(FUNCTION_WORDS - len(differences)),
    }


def _write_report(out: Path, report: dict[str, object]) -> None:
    build_root = _validated_build_root()
    _ensure_build_dir(out.parent, build_root)
    _write_build_text(out, canonical_json(report), build_root)


def _validate_arguments(arguments: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path, Path]:
    build_root = _validated_build_root()
    build_dir = _repo_path(arguments.build_dir, allowed_root=build_root)
    out = _repo_path(arguments.out, allowed_root=build_root)
    prx = _repo_path(arguments.prx, allowed_root=(REPO_ROOT / "private").resolve())
    source = _repo_path(arguments.source, allowed_root=(REPO_ROOT / "decomp/src").resolve())
    config = _repo_path(arguments.config, allowed_root=(REPO_ROOT / "config").resolve())
    expected_source = (REPO_ROOT / "decomp/src/func_000004B8.c").resolve()
    if source != expected_source:
        raise ProbeError("FAIL", "R2 only accepts the authorized func_000004B8.c source")
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
        "original_match_status": "INCONCLUSIVE",
        "baseline": {"status": "INCONCLUSIVE", "matching_words": 18, "total_words": 20},
        "linked_comparison": {"equal_words": None, "total_words": FUNCTION_WORDS, "differences": []},
        "assumptions": [],
        "independent_evidence": {},
        "identity_evidence": {
            "symbol": DATA_SYMBOL,
            "assignment": "CONTROLLED",
            "independently_verified": False,
        },
        "equivalence_claim": "NONE",
        "promoted_to_matched": False,
    }


def run_experiment(arguments: argparse.Namespace) -> tuple[int, dict[str, object]]:
    report = _base_report()
    build_root, build_dir, out, prx_path, source_path, config_path = _validate_arguments(arguments)
    if not all(shutil.which(tool) for tool in (LINKER, READELF, OBJDUMP, NM, FILE)):
        report["experiment_status"] = "BLOCKED"
        report["error"] = "required GNU MIPSel link/inspection executable is missing"
        _write_report(out, report)
        return 4, report

    _ensure_build_dir(build_dir, build_root)
    logs_dir = build_dir / "logs"
    _ensure_build_dir(logs_dir, build_root)
    candidate_dir = build_dir / "candidate"
    _ensure_build_dir(candidate_dir, build_root)
    match_record_path = candidate_dir / "match-record.json"
    object_path = candidate_dir / f"{source_path.stem}.o"
    _prepare_build_file(match_record_path, build_root)
    match_record_path.unlink(missing_ok=True)
    _prepare_build_file(object_path, build_root)
    object_path.unlink(missing_ok=True)
    source_hash_before = sha256_file(source_path)
    prx_hash_before = sha256_file(prx_path)
    script_path = build_dir / "controlled-link.ld"
    script_text = _linker_script()
    _write_build_text(script_path, script_text, build_root)

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
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    match_result = _run(match_command, timeout=600, env=env)
    _write_build_text(logs_dir / "match-function.stdout.json", match_result.stdout, build_root)
    _write_build_text(logs_dir / "match-function.stderr.txt", match_result.stderr, build_root)
    if match_result.returncode == 4:
        report["experiment_status"] = "BLOCKED"
        report["error"] = "match_function reports the Metrowerks compiler or loader unavailable"
        report["compile_and_match"] = {"returncode": match_result.returncode}
        _write_report(out, report)
        return 4, report
    if match_result.returncode not in (5,):
        raise ProbeError("FAIL", f"fresh match_function run exited {match_result.returncode}, expected 5/INCONCLUSIVE")
    try:
        match_record = json.loads(match_result.stdout)
    except json.JSONDecodeError as exc:
        raise ProbeError("FAIL", f"match_function did not emit valid JSON: {exc}") from exc
    match_payload = validate_match_baseline(match_record, match_result.returncode)
    if not object_path.is_file() or not match_record_path.is_file():
        raise ProbeError("FAIL", "fresh match_function run did not produce both object and provenance report")
    saved_match_record = json.loads(match_record_path.read_text(encoding="utf-8"))
    validate_saved_match_record(match_record, saved_match_record)
    provenance = match_record["provenance"]
    if (
        match_record.get("function") != FUNCTION_NAME
        or match_record.get("address") != "0x4b8"
        or match_record.get("section") != ".text"
        or provenance.get("source") != _relative(source_path)
        or provenance.get("object") != _relative(object_path)
    ):
        raise ProbeError("FAIL", "match_function provenance does not identify this fresh 0x4B8 compile")
    object_hash = sha256_file(object_path)
    source_hash = sha256_file(source_path)
    prx_hash = sha256_file(prx_path)
    if source_hash != source_hash_before or prx_hash != prx_hash_before:
        raise ProbeError("FAIL", "source or PRX changed during fresh compile/match execution")
    validate_recorded_hash("candidate object", object_hash, provenance.get("object_sha256"))
    validate_recorded_hash("candidate source", source_hash, provenance.get("source_sha256"))
    if not prx_hash:
        raise ProbeError("FAIL", "PRX SHA-256 could not be computed")
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
    data_symbols = [symbol for symbol in candidate.symbols if symbol.name == DATA_SYMBOL]
    if len(data_symbols) != 1 or data_symbols[0].shndx != elf.SHN_UNDEF:
        raise ProbeError("FAIL", "fresh candidate data symbol is not exactly one undefined D_00004830")
    expected_call_symbols = {name for name, _site in CALL_SYMBOL_SITES}
    undefined_calls = {
        symbol.name
        for symbol in candidate.symbols
        if symbol.name in expected_call_symbols and symbol.shndx == elf.SHN_UNDEF
    }
    if undefined_calls != expected_call_symbols:
        raise ProbeError("FAIL", "fresh candidate does not expose the four expected undefined call symbols")
    candidate_text = candidate.require_section(".text")
    candidate_offset = candidate_symbol.value
    if candidate_offset != 0 or candidate_text.size != FUNCTION_SIZE:
        raise ProbeError(
            "UNSUPPORTED",
            "fresh candidate .text must contain exactly the target function at section offset zero",
        )
    candidate_words = _function_words(candidate, candidate_offset, FUNCTION_SIZE, label="fresh candidate")
    candidate_relocation_table = candidate.relocations_for(".text")
    candidate_sites = matching.relocation_sites(candidate_relocation_table, candidate_offset, FUNCTION_SIZE)
    required_candidate_relocations = {
        (elf.R_MIPS_HI16, 3, DATA_SYMBOL),
        (elf.R_MIPS_LO16, 6, DATA_SYMBOL),
        (elf.R_MIPS_26, 5, "func_00000894"),
        (elf.R_MIPS_26, 9, "func_00000854"),
        (elf.R_MIPS_26, 11, "func_00002D0C"),
        (elf.R_MIPS_26, 14, "func_000008A4"),
    }
    actual_candidate_relocations = {
        (site.type, index, site.symbol) for index, site in candidate_sites.sites.items()
    }
    if actual_candidate_relocations != required_candidate_relocations or candidate_sites.limitations:
        raise ProbeError("UNSUPPORTED", "fresh object relocation inventory differs from the R2 contract")
    candidate_pairing = matching.pair_hi16_lo16(candidate_sites.sites, candidate_words)
    if candidate_pairing.hi_to_lo != {3: 6} or candidate_pairing.limitations:
        raise ProbeError("UNSUPPORTED", "fresh object HI16/LO16 pairing is not proven")

    original_text = original.require_section(".text")
    original_offset = FUNCTION_ADDRESS - original_text.addr
    original_relocation_evidence, original_pairing = _text_relocation_evidence(
        original,
        section_offset=original_offset,
        words=original_words,
        label="original PRX",
    )
    data_evidence = _original_data_evidence(original)
    call_rows, call_targets = _original_calls(original)
    required_targets = {
        "func_00000894": 0x894,
        "func_00000854": 0x854,
        "func_00002D0C": 0x2D0C,
        "func_000008A4": 0x8A4,
    }
    if call_targets != required_targets:
        raise ProbeError("FAIL", f"original PRX call targets differ from the R2 baseline: {call_targets}")
    psp_runtime = _original_psp_relocation_analysis(original, original_words, original_pairing)

    original_object_relocations = [
        relocation
        for relocation in candidate.relocations
        if relocation.source_section == ".rel.mwcats"
    ]
    if not any(
        item.type == elf.R_MIPS_32 and item.symbol == FUNCTION_NAME
        for item in original_object_relocations
    ):
        raise ProbeError("UNSUPPORTED", "fresh Metrowerks object has no expected .mwcats R_MIPS_32 entry")
    if candidate.section(".mwcats") is None:
        raise ProbeError("UNSUPPORTED", "fresh Metrowerks object has no .mwcats metadata section")

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
    mw_lines = [line.strip() for line in toolchain_result.stdout.splitlines() if line.lstrip().startswith("mwccpsp")]
    wibo_lines = [line.strip() for line in toolchain_result.stdout.splitlines() if line.lstrip().startswith("wibo")]
    mw_version = None
    for line in mw_lines:
        found = re.search(r"\bVersion\s+([0-9.]+\s+build\s+\d+)", line)
        if found:
            mw_version = f"Metrowerks {found.group(1)}"
            break
    wibo_version = None
    for line in wibo_lines:
        found = re.search(r"\bwibo\s+([0-9.]+)", line)
        if found:
            wibo_version = f"wibo {found.group(1)}"
            break
    if mw_version is None or wibo_version is None:
        raise ProbeError("BLOCKED", "Seto toolchain inventory could not confirm configured Metrowerks/wibo versions")

    script_hash = sha256_file(script_path)
    if script_hash == "":
        raise ProbeError("FAIL", "linker script hash could not be computed")
    links_dir = build_dir / "links"
    _ensure_build_dir(links_dir, build_root)
    variant_payload: dict[str, dict[str, object]] = {}
    link_commands: dict[str, dict[str, object]] = {}
    for case, target in LINK_VARIANTS:
        variant_dir = links_dir / case
        _ensure_build_dir(variant_dir, build_root)
        output_path = variant_dir / "linked.elf"
        label = f"case-{case.lower()}"
        linked, command_info = _link(
            object_path=object_path,
            script_path=script_path,
            output_path=output_path,
            data_address=target,
            call_targets=call_targets,
            logs_dir=logs_dir,
            label=label,
        )
        link_commands[case] = command_info
        variant_payload[case] = _linked_projection(
            original_words,
            linked,
            label=f"case {case}",
            assigned_data=target,
            expected_calls=call_targets,
        )
        variant_payload[case]["linked_elf_path"] = _relative(output_path)
        variant_payload[case]["linked_elf_sha256"] = sha256_file(output_path)
        variant_payload[case]["linker_exit_code"] = command_info["returncode"]

    # A and B must differ at the LO16 destination word only; C exercises signed
    # LO16 carry and changes both halves. These are controls between linked outputs,
    # not claims that B/C model the original module.
    a_words = tuple(int(word, 16) for word in variant_payload["A"]["linked_words"])
    b_words = tuple(int(word, 16) for word in variant_payload["B"]["linked_words"])
    c_words = tuple(int(word, 16) for word in variant_payload["C"]["linked_words"])
    b_vs_a, c_vs_a = validate_address_controls(a_words, b_words, c_words)
    if variant_payload["C"]["hi16_immediate"] != "0x0001" or variant_payload["C"]["lo16_immediate"] != "0x8004" or variant_payload["C"]["lo16_signed"] != -32764:
        raise ProbeError("FAIL", "case C did not encode the specified HI16/LO16 carry result")

    # Negative control: mutate one bit in unrelocated word 0 in a COPY of the
    # fresh ET_REL. Never modify the original freshly compiled candidate.
    bad_object = build_dir / "negative-nonrelocated.o"
    original_object_bytes = object_path.read_bytes()
    mutated_object_bytes = bytearray(original_object_bytes)
    text_field_offset = candidate_text.offset + candidate_offset
    original_word0 = int.from_bytes(mutated_object_bytes[text_field_offset : text_field_offset + 4], "little")
    mutated_word0 = original_word0 ^ 0x1
    mutated_object_bytes[text_field_offset : text_field_offset + 4] = mutated_word0.to_bytes(4, "little")
    _write_build_bytes(bad_object, bytes(mutated_object_bytes), build_root)
    bad_module = elf.parse(bad_object)
    bad_sites = matching.relocation_sites(bad_module.relocations_for(".text"), candidate_offset, FUNCTION_SIZE)
    if bad_sites.sites != candidate_sites.sites:
        raise ProbeError("FAIL", "nonrelocated mutation changed the candidate relocation inventory")
    bad_output = links_dir / "tampered-nonrelocated" / "linked.elf"
    _ensure_build_dir(bad_output.parent, build_root)
    bad_link, bad_command = _link(
        object_path=bad_object,
        script_path=script_path,
        output_path=bad_output,
        data_address=DATA_TARGET,
        call_targets=call_targets,
        logs_dir=logs_dir,
        label="tampered-nonrelocated",
    )
    bad_text = bad_link.require_section(".text")
    bad_words = mips.decode_words(bad_link.section_data(bad_text), "tampered negative link")
    tamper_differences = validate_nonrelocated_tamper(
        original_words,
        bad_words,
        word_index=0,
        relocation_sites=candidate_sites.sites,
    )

    validate_recorded_hash("PRX during experiment", sha256_file(prx_path), prx_hash)
    validate_recorded_hash("source during experiment", sha256_file(source_path), source_hash)
    validate_recorded_hash("fresh object during experiment", sha256_file(object_path), object_hash)
    validate_recorded_hash("linker script during experiment", sha256_file(script_path), script_hash)

    baseline_a_equal = variant_payload["A"]["equal_words"] == FUNCTION_WORDS
    report = {
        "schema_version": 1,
        "experiment_status": "PASS",
        "function": FUNCTION_NAME,
        "function_address": f"0x{FUNCTION_ADDRESS:x}",
        "function_size_bytes": FUNCTION_SIZE,
        "baseline": {
            "status": matching.INCONCLUSIVE,
            "matching_words": 18,
            "total_words": FUNCTION_WORDS,
            "difference_count": 0,
            "relocation_issues": [],
            "match_function_exit_code": match_result.returncode,
            "compile_gate": "PASS_VERIFIED_BY_match_function_BEFORE_COMPARISON",
        },
        "compile_and_match": {
            "command": [
                "python",
                "scripts/match_function.py",
                "--config",
                _relative(config_path),
                "--prx",
                _relative(prx_path),
                "--function",
                "0x4b8",
                "--source",
                _relative(source_path),
                "--out",
                _relative(candidate_dir),
                "--report",
                _relative(match_record_path),
                "--json",
            ],
            "match_function_exit_code": match_result.returncode,
            "compiler_exit_check": "match_function refuses to invoke the comparator after a failed compile",
            "provenance_record": _relative(match_record_path),
        },
        "provenance": {
            "prx_path": _relative(prx_path),
            "prx_sha256": prx_hash,
            "source_path": _relative(source_path),
            "source_sha256": source_hash,
            "fresh_object_path": _relative(object_path),
            "fresh_object_sha256": object_hash,
            "linker_script_path": _relative(script_path),
            "linker_script_sha256": script_hash,
            "compiler": mw_version,
            "loader": wibo_version,
            "flags": provenance.get("flags"),
            "includes": provenance.get("includes"),
            "linker": linker_version,
            "linker_emulation": "elf32ltsmip",
        },
        "original_prx": {
            "text_section_address": f"0x{original_text.addr:x}",
            "function_file_words": [f"0x{word:08x}" for word in original_words],
            "relocation_evidence": original_relocation_evidence,
            "data_target": data_evidence,
            "import_call_assignments": call_rows,
            "psp_runtime_relocation_analysis": psp_runtime,
        },
        "candidate_object": {
            "header": candidate.header.summary(),
            "sections": [section.summary() for section in candidate.sections],
            "text_section_address": f"0x{candidate_text.addr:x}",
            "text_section_size": candidate_text.size,
            "function_symbol_value": f"0x{candidate_symbol.value:x}",
            "function_section_offset": candidate_offset,
            "function_words_before_link": [f"0x{word:08x}" for word in candidate_words],
            "text_relocations": [
                {
                    "word_index": index,
                    "type": site.type_name,
                    "symbol": site.symbol,
                    "symbol_index": site.symbol_index,
                    "addend": f"0x{site.addend & 0xffffffff:08x}",
                    "addend_valid": site.addend_valid,
                }
                for index, site in sorted(candidate_sites.sites.items())
            ],
            "relocation_pairing": {
                "hi_to_lo": {str(key): value for key, value in candidate_pairing.hi_to_lo.items()},
                "evidence": {str(key): value for key, value in candidate_pairing.evidence.items()},
            },
            "mwcats": {
                "preserved_by_link_script": True,
                "section": candidate.require_section(".mwcats").summary(),
                "input_relocation_types": [item.type_name for item in original_object_relocations],
                "input_relocations": [item.summary() for item in original_object_relocations],
            },
        },
        "linker": {
            "linker_script": script_text,
            "text_start": f"0x{FUNCTION_ADDRESS:x}",
            "text_size": f"0x{FUNCTION_SIZE:x}",
            "subalign": 4,
            "generated_stubs": False,
            "variants": variant_payload,
            "link_commands": link_commands,
            "case_b_vs_a_differences": b_vs_a,
            "case_c_vs_a_differences": c_vs_a,
            "tampered_nonrelocated_negative": {
                "source_object_sha256": object_hash,
                "mutated_object_path": _relative(bad_object),
                "mutated_object_sha256": sha256_file(bad_object),
                "link_command": bad_command,
                "original_word0": f"0x{original_word0:08x}",
                "mutated_word0": f"0x{mutated_word0:08x}",
                "linked_elf_sha256": sha256_file(bad_output),
                "linked_elf_path": _relative(bad_output),
                "differences": tamper_differences,
                "detected": True,
                "promoted_to_matched": False,
            },
        },
        "linked_comparison": {
            "equal_words": variant_payload["A"]["equal_words"],
            "total_words": FUNCTION_WORDS,
            "differences": variant_payload["A"]["differences"],
            "file_byte_comparison": True,
            "runtime_equivalence": "NOT_DEMONSTRATED",
        },
        "assumptions": [
            {"symbol": DATA_SYMBOL, "address": "0x4830", "kind": "CONTROLLED_ASSIGNMENT"},
            *call_rows,
            {"runtime_load_base": None, "kind": "UNKNOWN_NOT_INFERRED"},
        ],
        "independent_evidence": {
            "original_data_location_and_bytes": "read from the PRX via Seto's section/dataref APIs",
            "candidate_symbol_identity": False,
            "original_calls": "matched to PRX import-table entries by the existing imports API; linker address assignments remain controlled assumptions",
            "runtime_load_base": False,
        },
        "identity_evidence": {
            "symbol": DATA_SYMBOL,
            "assignment": "CONTROLLED",
            "independently_verified": False,
        },
        "original_match_status": matching.INCONCLUSIVE,
        "equivalence_claim": equivalence_claim(variant_payload["A"]["equal_words"]),
        "promoted_to_matched": False,
    }
    _write_build_text(
        logs_dir / "match-function.provenance.json",
        canonical_json({
            "function": match_record.get("function"),
            "status": match_record.get("status"),
            "evidence": match_record.get("evidence"),
            "equivalence": match_record.get("equivalence"),
            "verified_decompilation": match_record.get("verified_decompilation"),
            "exit_code": match_record.get("exit_code"),
            "source_sha256": provenance.get("source_sha256"),
            "object_sha256": provenance.get("object_sha256"),
            "flags": provenance.get("flags"),
            "includes": provenance.get("includes"),
        }),
        build_root,
    )
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
