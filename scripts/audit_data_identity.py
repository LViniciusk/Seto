#!/usr/bin/env python3
"""Project existing Seto match/data-reference evidence into a gap audit.

This is deliberately not a matcher or a symbol-link verifier.  It locates
unresolved HI16/LO16 *pairs* from the match report's exact identity limitations,
then projects the existing ELF, relocation-pairing, and data-reference APIs onto
the two words in each pair.  It never infers pending word indexes from a count.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from seto import datarefs, elf
from seto.binio import ParseError
from seto.matching import (
    INCONCLUSIVE,
    combine_hi16_lo16,
    pair_hi16_lo16,
    relocation_sites,
)
from seto.mips import decode_words
from seto.sfo import parse_source as parse_sfo

FUNCTIONS = (
    ("f000", "func_00000000", 0x0, 6, 13),
    ("f39c", "func_0000039C", 0x39C, 2, 30),
    ("f414", "func_00000414", 0x414, 10, 41),
    ("f4b8", "func_000004B8", 0x4B8, 2, 20),
    ("f508", "func_00000508", 0x508, 12, 75),
    ("f634", "func_00000634", 0x634, 2, 44),
    ("f6e4", "func_000006E4", 0x6E4, 6, 8),
    ("f704", "func_00000704", 0x704, 20, 60),
)
REPO_ROOT = Path(__file__).resolve().parents[1]

_IDENTITY_LIMITATION = re.compile(
    r"^word (\d+): HI16/LO16 data identity cannot be proven \(.+\)$"
)


def pending_hi_indices(limitations: list[str], total_words: int) -> dict[int, str]:
    """Return pair-start indexes explicitly named by comparator limitations.

    The output is sourced from the matcher's per-word limitations, not from the
    difference between total and matching word counts.  Duplicate, malformed,
    and out-of-range locations are rejected instead of silently normalized.
    """
    pending: dict[int, str] = {}
    for limitation in limitations:
        match = _IDENTITY_LIMITATION.fullmatch(limitation)
        if match is None:
            continue
        index = int(match.group(1))
        if not 0 <= index < total_words:
            raise ParseError(f"identity limitation word {index} is outside {total_words} words")
        if index in pending:
            raise ParseError(f"duplicate identity limitation for HI16 word {index}")
        pending[index] = limitation
    return pending


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checked_artifact(
    provenance: dict[str, object],
    kind: str,
    function: str,
    *,
    expected_path: Path,
) -> Path:
    """Check the report's local artifact path and SHA-256 before consuming it."""
    raw_path = provenance.get(kind)
    expected_hash = provenance.get(f"{kind}_sha256")
    if not isinstance(raw_path, str) or not raw_path:
        raise ParseError(f"{function}: missing {kind} path")
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash) is None:
        raise ParseError(f"{function}: invalid {kind} SHA-256")

    path = Path(raw_path)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.is_file():
        raise ParseError(f"{function}: {kind} file is missing or is not a regular file: {path}")
    expected_resolved = expected_path.resolve()
    actual_resolved = path.resolve()
    if actual_resolved != expected_resolved:
        raise ParseError(
            f"{function}: {kind} path does not match the expected baseline artifact "
            f"(expected {expected_resolved}, report names {actual_resolved})"
        )

    actual_hash = _hash_file(path)
    if actual_hash.lower() != expected_hash.lower():
        raise ParseError(
            f"{function}: {kind} SHA-256 mismatch "
            f"(expected {expected_hash}, actual {actual_hash})"
        )
    return path


def _checked_baseline(
    report: dict[str, object],
    *,
    tag: str,
    function: str,
    address: int,
    expected_pending_words: int,
    expected_total_words: int,
    build_dir: Path,
) -> tuple[Path, Path, elf.ElfFile]:
    """Validate report identity, baseline shape, and files before parsing ELF."""
    if report.get("function") != function or report.get("symbol") != function:
        raise ParseError(f"{function}: match report belongs to another function")
    if _json_int(report.get("address"), f"{function} report address") != address:
        raise ParseError(f"{function}: match report has the wrong address")
    if (
        report.get("section") != ".text"
        or report.get("status") != INCONCLUSIVE
        or report.get("evidence") != "compiled-object"
        or report.get("exit_code") != 5
        or report.get("verified_decompilation") is not False
    ):
        raise ParseError(f"{function}: match report does not have the expected compiled INCONCLUSIVE baseline")

    match = report.get("match")
    if not isinstance(match, dict):
        raise ParseError(f"{function}: match report is missing its match object")
    expected_matching_words = expected_total_words - expected_pending_words
    if (
        match.get("name") != function
        or _json_int(match.get("address"), f"{function} comparison address") != address
        or match.get("status") != INCONCLUSIVE
        or match.get("evidence") != "binary-range"
        or match.get("total_words") != expected_total_words
        or match.get("matching_words") != expected_matching_words
        or match.get("difference_count") != 0
        or match.get("differences") != []
        or match.get("relocation_issues") != []
        or not isinstance(match.get("limitations"), list)
        or not match["limitations"]
    ):
        raise ParseError(f"{function}: match report does not match the expected baseline properties")

    candidate = match.get("candidate")
    if not isinstance(candidate, dict):
        raise ParseError(f"{function}: match report is missing candidate details")
    if _json_int(candidate.get("section_offset"), f"{function} candidate section offset") != 0:
        raise ParseError(f"{function}: candidate function is not at the expected section offset 0")
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise ParseError(f"{function}: match report is missing provenance")
    expected_source = REPO_ROOT / "decomp" / "src" / f"{function}.c"
    expected_object = build_dir / "matches" / tag / f"{function}.o"
    source_path = _checked_artifact(
        provenance, "source", function, expected_path=expected_source
    )
    object_path = _checked_artifact(
        provenance, "object", function, expected_path=expected_object
    )

    candidate_path = candidate.get("path")
    if not isinstance(candidate_path, str) or not candidate_path:
        raise ParseError(f"{function}: match report is missing the candidate object path")
    candidate_path_obj = Path(candidate_path)
    if not candidate_path_obj.is_absolute():
        candidate_path_obj = REPO_ROOT / candidate_path_obj
    if candidate_path_obj.resolve() != object_path.resolve():
        raise ParseError(f"{function}: comparison candidate path differs from provenance object")

    # Hash checks above must finish before this parser consumes the candidate.
    return source_path, object_path, elf.parse(object_path)


def _json_int(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise ParseError(f"{label}: boolean is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ParseError(f"{label}: invalid integer {value!r}") from exc
    raise ParseError(f"{label}: expected an integer")


def _symbol_record(parsed: elf.ElfFile, relocation: elf.Relocation) -> dict[str, object] | None:
    if relocation.symbol_index == 0:
        return None
    symbol = next(
        (item for item in parsed.symbols if item.index == relocation.symbol_index), None
    )
    if symbol is None:
        raise ParseError(
            f"relocation symbol index {relocation.symbol_index} is absent from {parsed.reader.name}"
        )
    section = next((item for item in parsed.sections if item.index == symbol.shndx), None)
    return {
        "index": symbol.index,
        "name": symbol.name,
        "shndx": symbol.shndx,
        "section": None if section is None else section.name,
        "value": f"0x{symbol.value:x}",
        "section_offset": f"0x{symbol.value:x}" if symbol.is_defined else None,
        "size": symbol.size,
        "defined": symbol.is_defined,
        "type": symbol.type,
    }


def _relocation_record(
    parsed: elf.ElfFile,
    relocation: elf.Relocation,
    word_index: int,
    region_offset: int,
) -> dict[str, object]:
    mask = relocation.mask
    record: dict[str, object] = {
        "word_index": word_index,
        "section_offset": f"0x{region_offset + word_index * 4:x}",
        "type": relocation.type_name,
        "format": relocation.format,
        "field_mask": f"0x{mask:08x}",
        "field_bits": [bit for bit in range(32) if mask & (1 << bit)],
        "raw_info": f"0x{relocation.info:08x}",
        "raw_offset": f"0x{relocation.raw_offset:x}",
        "symbol_index": relocation.symbol_index,
        "symbol": relocation.symbol,
        "symbol_identity": _symbol_record(parsed, relocation),
        "addend": relocation.addend,
        "addend_hex": f"0x{relocation.addend & 0xFFFFFFFF:08x}",
        "addend_valid": relocation.addend_valid,
    }
    return record


def _destination(reference: datarefs.DataReference) -> dict[str, object] | None:
    if reference.target is not None:
        return {"kind": "section", **reference.target.summary()}
    if reference.load is not None:
        return {
            "kind": "segment",
            "segment": reference.load.segment,
            "offset": f"0x{reference.load.offset:x}",
            "initialized": reference.load.initialized,
        }
    return None


def _pair_projection(
    *,
    function: str,
    start: int,
    total_words: int,
    original: elf.ElfFile,
    candidate: elf.ElfFile,
    original_words: tuple[int, ...],
    candidate_words: tuple[int, ...],
    original_pairs: Any,
    candidate_pairs: Any,
    original_sites: dict[int, Any],
    candidate_sites: dict[int, Any],
    original_relocations: dict[int, elf.Relocation],
    candidate_relocations: dict[int, elf.Relocation],
    original_region_offset: int,
    candidate_region_offset: int,
    references: tuple[datarefs.DataReference, ...],
    limitation_by_hi: dict[int, str],
    original_resolver: Any,
    candidate_resolver: Any,
) -> list[dict[str, object]]:
    reference_by_instruction = {item.instruction: item for item in references}
    pairs: list[dict[str, object]] = []
    for hi_index in sorted(limitation_by_hi):
        original_low = original_pairs.hi_to_lo.get(hi_index)
        candidate_low = candidate_pairs.hi_to_lo.get(hi_index)
        if original_low is None or candidate_low is None:
            raise ParseError(f"{function}: unresolved HI16 pairing at word {hi_index}")
        if original_low != candidate_low:
            raise ParseError(
                f"{function}: original/candidate HI16 pair differs at word {hi_index} "
                f"({original_low} vs {candidate_low})"
            )
        low_index = original_low
        if not (0 <= hi_index < total_words and 0 <= low_index < total_words):
            raise ParseError(f"{function}: pair {hi_index}->{low_index} is outside the function")

        original_hi = original_relocations.get(original_region_offset + hi_index * 4)
        original_lo = original_relocations.get(original_region_offset + low_index * 4)
        candidate_hi = candidate_relocations.get(candidate_region_offset + hi_index * 4)
        candidate_lo = candidate_relocations.get(candidate_region_offset + low_index * 4)
        if None in (original_hi, original_lo, candidate_hi, candidate_lo):
            raise ParseError(f"{function}: pair {hi_index}->{low_index} lacks raw relocation entries")
        assert original_hi is not None and original_lo is not None
        assert candidate_hi is not None and candidate_lo is not None

        original_hi_site = original_sites[hi_index]
        original_lo_site = original_sites[low_index]
        candidate_hi_site = candidate_sites[hi_index]
        candidate_lo_site = candidate_sites[low_index]
        if original_hi_site.type != elf.R_MIPS_HI16 or candidate_hi_site.type != elf.R_MIPS_HI16:
            raise ParseError(f"{function}: limitation at word {hi_index} is not a HI16 pair")
        if original_lo_site.type != elf.R_MIPS_LO16 or candidate_lo_site.type != elf.R_MIPS_LO16:
            raise ParseError(f"{function}: paired word {low_index} is not LO16 on both sides")

        original_combined = combine_hi16_lo16(original_hi_site.addend, original_lo_site.addend)
        candidate_combined = combine_hi16_lo16(candidate_hi_site.addend, candidate_lo_site.addend)
        reference_instruction = original_region_offset + low_index * 4
        reference = reference_by_instruction.get(reference_instruction)
        if reference is None or reference.kind != "hi16-lo16":
            raise ParseError(
                f"{function}: datarefs has no HI16/LO16 record at section offset "
                f"0x{reference_instruction:x}"
            )
        if reference.combined != original_combined:
            raise ParseError(
                f"{function}: recover_references/addend disagreement at pair {hi_index}->{low_index}"
            )

        original_identity = original_resolver(original_hi_site, original_combined)
        candidate_identity = candidate_resolver(candidate_hi_site, candidate_combined)
        cross_artifact_identity = (
            "PROVEN"
            if original_identity is not None
            and candidate_identity is not None
            and original_identity.artifact == candidate_identity.artifact
            and original_identity.target == candidate_identity.target
            else "UNPROVEN"
        )

        word_entries: list[dict[str, object]] = []
        for word_index in (hi_index, low_index):
            orig_relocation = original_hi if word_index == hi_index else original_lo
            cand_relocation = candidate_hi if word_index == hi_index else candidate_lo
            word_entries.append(
                {
                    "word_index": word_index,
                    "instruction": f"0x{start + word_index * 4:x}",
                    "original_word": f"0x{original_words[word_index]:08x}",
                    "candidate_word": f"0x{candidate_words[word_index]:08x}",
                    "original_relocation": _relocation_record(
                        original, orig_relocation, word_index, original_region_offset
                    ),
                    "candidate_relocation": _relocation_record(
                        candidate, cand_relocation, word_index, candidate_region_offset
                    ),
                    "exact_matcher_limitation": limitation_by_hi[hi_index],
                    "limitation_origin_hi_word": hi_index,
                    "independent_identity_evidence": [],
                }
            )

        pairs.append(
            {
                "pair_id": f"{function}:word-{hi_index}-to-{low_index}",
                "function": function,
                "hi_word_index": hi_index,
                "lo_word_index": low_index,
                "pairing": {
                    "original": original_pairs.evidence.get(hi_index, "UNAVAILABLE"),
                    "candidate": candidate_pairs.evidence.get(hi_index, "UNAVAILABLE"),
                    "original_confidence": reference.pairing,
                    "reason": reference.evidence,
                },
                "addends": {
                    "original_hi": original_hi_site.addend,
                    "original_lo": original_lo_site.addend,
                    "original_combined": f"0x{original_combined:08x}",
                    "candidate_hi": candidate_hi_site.addend,
                    "candidate_lo": candidate_lo_site.addend,
                    "candidate_combined": f"0x{candidate_combined:08x}",
                    "all_in_place_words_valid": all(
                        item.addend_valid
                        for item in (original_hi, original_lo, candidate_hi, candidate_lo)
                    ),
                },
                "original_destination": _destination(reference),
                "original_location_confidence": reference.location,
                "original_reference_status": reference.status,
                "original_reference_unresolved": reference.unresolved,
                "original_data_identity": (
                    None if original_identity is None else original_identity.summary()
                ),
                "candidate_data_identity": (
                    None if candidate_identity is None else candidate_identity.summary()
                ),
                "cross_artifact_identity": cross_artifact_identity,
                "candidate_target": None
                if candidate_identity is None
                else candidate_identity.target.summary(),
                "matcher_limitation": limitation_by_hi[hi_index],
                "words": word_entries,
            }
        )
    return pairs


def _bounded_local_artifact_review(
    prx_path: Path, original: elf.ElfFile, build_dir: Path
) -> dict[str, object]:
    """Inventory only the known same-disc directories and neighboring files."""
    game_root = prx_path.parents[2]
    usrdir = game_root / "USRDIR"
    inspected_paths = (
        prx_path,
        usrdir / "gmodule" / "libtutoriallist.prx",
        usrdir / "module" / "libadler.prx",
        game_root / "SYSDIR" / "EBOOT.BIN",
        game_root / "PARAM.SFO",
    )
    inspected: list[dict[str, object]] = []
    for path in inspected_paths:
        record: dict[str, object] = {
            "path": path.as_posix(),
            "present": path.is_file(),
        }
        if path.is_file():
            record["sha256"] = _hash_file(path)
            if path.suffix.lower() == ".prx":
                with path.open("rb") as handle:
                    magic = handle.read(4)
                record["first_four_bytes"] = magic.hex()
                if magic == elf.ELF_MAGIC:
                    parsed = original if path.resolve() == prx_path.resolve() else elf.parse(path)
                    record["format"] = parsed.header.file_type_name
                    record["symbol_count"] = len(parsed.symbols)
                    record["debug_sections"] = [
                        section.name
                        for section in parsed.sections
                        if section.name.startswith((".debug", ".symtab", ".strtab"))
                    ]
                    record["comment"] = parsed.comment()
                else:
                    record["format"] = "non-ELF PRX payload; not decoded or executed"
            else:
                with path.open("rb") as handle:
                    record["first_four_bytes"] = handle.read(4).hex()
                if path.name == "PARAM.SFO":
                    metadata = parse_sfo(path)
                    values = metadata.as_dict()
                    record["format"] = "PSF/PARAM.SFO"
                    record["package_metadata"] = {
                        key: value.rstrip(b"\x00").decode("utf-8", "replace")
                        if isinstance(value, bytes)
                        else value
                        for key, value in values.items()
                        if key in ("TITLE", "DISC_ID", "DISC_VERSION", "PSP_SYSTEM_VER")
                    }
                else:
                    record["format"] = "not parsed or executed in this audit"
        inspected.append(record)

    directories = (game_root, usrdir, usrdir / "gmodule", usrdir / "module", game_root / "SYSDIR")
    relevant_suffixes = {".map", ".o", ".elf", ".sym", ".dbg", ".pdb", ".dwo"}
    directory_inventory: list[dict[str, object]] = []
    for directory in directories:
        files = sorted(
            child.name
            for child in directory.iterdir()
            if child.is_file()
        ) if directory.is_dir() else []
        matching = [name for name in files if Path(name).suffix.lower() in relevant_suffixes]
        directory_inventory.append(
            {
                "path": directory.as_posix(),
                "present": directory.is_dir(),
                "immediate_files": files,
                "link_metadata_candidates": matching,
            }
        )

    candidates = sorted(
        (
            {
                "directory": item["path"],
                "filename": filename,
                "classification": "unverified candidate; filename extension is not authenticity evidence",
            }
            for item in directory_inventory
            for filename in item["link_metadata_candidates"]
        ),
        key=lambda item: (str(item["directory"]), str(item["filename"])),
    )
    evidence_search_status = "CANDIDATES_UNVERIFIED" if candidates else "NO_CANDIDATES"
    if candidates:
        finding = (
            "Candidate linker or symbol artifacts were found, but none has been independently "
            "validated. No cross-artifact identity is established."
        )
    else:
        finding = "No candidate linker or symbol artifacts were found in the bounded search paths."

    generated_context: list[dict[str, object]] = []
    for path, reason in (
        (
            REPO_ROOT / "config/splat/libhtml_view.yaml",
            "The file identifies itself as generated by seto split from this PRX; it is not an original linker map.",
        ),
        (
            REPO_ROOT / "build/libhtml_view.ld",
            "Generated Splat linker script referencing build/asm and build/assets inputs; it is not an original link artifact.",
        ),
        (
            REPO_ROOT / "build/seto011/shared-state.json",
            "Generated from the current PRX disassembly/datarefs; it records observed addresses, not cross-artifact symbol identity.",
        ),
    ):
        generated_context.append(
            {
                "path": path.relative_to(REPO_ROOT).as_posix(),
                "present": path.is_file(),
                "sha256": _hash_file(path) if path.is_file() else None,
                "disposition": reason,
                "independent_identity_evidence": False,
            }
        )

    sibling_imports: dict[str, object] | None = None
    import_report_path = build_dir / "libtutoriallist-imports.json"
    sibling_path = usrdir / "gmodule" / "libtutoriallist.prx"
    if import_report_path.is_file():
        import_report = json.loads(import_report_path.read_text(encoding="utf-8"))
        if import_report.get("sha256") != _hash_file(sibling_path):
            raise ParseError("sibling imports report does not match the inspected PRX hash")
        imports = import_report.get("imports", {})
        sibling_imports = {
            "path": import_report.get("prx"),
            "sha256": import_report["sha256"],
            "tables": imports.get("tables", []),
            "table_count": imports.get("table_count"),
            "stub_count": imports.get("stub_count"),
            "unresolved": imports.get("limitations", []),
            "interpretation": "This sibling PRX exposes an import table (libehsys NIDs), not original object symbols or data-object mapping metadata.",
            "independent_data_identity_evidence": False,
        }

    return {
        "scope": "Only the supplied PSP_GAME root, USRDIR, gmodule, module, and SYSDIR immediate entries; no system-wide search or binary execution.",
        "inspected_artifacts": inspected,
        "directory_inventory": directory_inventory,
        "evidence_search_status": evidence_search_status,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "independent_identity_verified": False,
        "generated_context_rejected_as_independent_evidence": generated_context,
        "related_module_import_review": sibling_imports,
        "independent_original_link_artifact_found": False,
        "finding": finding,
    }


def _candidate_content_observations(
    original: elf.ElfFile, candidates: dict[str, elf.ElfFile]
) -> list[dict[str, object]]:
    """Record observed table/string correlations without elevating them to identity."""
    data = original.section_data(original.require_section(".data"))
    observations: list[dict[str, object]] = []
    for function, start, data_offset, candidate_symbol in (
        ("func_0000039C", 0x39C, 0x08, "func_0000039C"),
        ("func_00000414", 0x414, 0x20, "func_00000414"),
    ):
        candidate = candidates[function]
        rodata = candidate.section(".rodata")
        if rodata is None:
            continue
        if data_offset + rodata.size > len(data):
            raise ParseError(f"{function}: candidate .rodata range exceeds original .data")
        table_relocations = [
            relocation
            for relocation in original.relocations_for(".data")
            if relocation.section_offset is not None
            and data_offset <= relocation.section_offset < data_offset + rodata.size
        ]
        candidate_relocations = [
            relocation
            for relocation in candidate.relocations_for(".rodata")
            if relocation.type == elf.R_MIPS_32
        ]
        function_symbol = next(
            (symbol for symbol in candidate.symbols if symbol.name == candidate_symbol), None
        )
        table_symbols = [
            {
                "index": symbol.index,
                "name": symbol.name,
                "shndx": symbol.shndx,
                "value": symbol.value,
                "size": symbol.size,
                "type": symbol.type,
            }
            for symbol in candidate.symbols
            if symbol.is_defined and symbol.shndx == rodata.index
        ]
        table_relocations = sorted(table_relocations, key=lambda item: item.section_offset or 0)
        candidate_relocations = sorted(candidate_relocations, key=lambda item: item.section_offset or 0)
        expected_entries = rodata.size // 4
        if rodata.size % 4 or len(table_relocations) != expected_entries or len(candidate_relocations) != expected_entries:
            raise ParseError(
                f"{function}: jump-table shape is not fully relocation-covered "
                f"(size {rodata.size}, original relocs {len(table_relocations)}, "
                f"candidate relocs {len(candidate_relocations)})"
            )
        correlations: list[dict[str, object]] = []
        for original_relocation, candidate_relocation in zip(table_relocations, candidate_relocations):
            original_target = datarefs.resolve_data_target(
                original_relocation, original.symbols, original, addend=original_relocation.addend
            )
            candidate_target = datarefs.resolve_data_target(
                candidate_relocation,
                candidate.symbols,
                candidate,
                addend=candidate_relocation.addend,
            )
            relative_match = (
                original_target is not None
                and candidate_relocation.symbol == candidate_symbol
                and original_target.section == ".text"
                and function_symbol is not None
                and original_target.offset
                == start + function_symbol.value + candidate_relocation.addend
            )
            correlations.append(
                {
                    "original_data_offset": f"0x{original_relocation.section_offset:x}",
                    "original_relocation": original_relocation.type_name,
                    "original_addend": f"0x{original_relocation.addend & 0xFFFFFFFF:08x}",
                    "original_target": None if original_target is None else original_target.summary(),
                    "candidate_rodata_offset": (
                        None
                        if candidate_relocation.section_offset is None
                        else f"0x{candidate_relocation.section_offset:x}"
                    ),
                    "candidate_relocation": candidate_relocation.type_name,
                    "candidate_symbol": candidate_relocation.symbol,
                    "candidate_addend": f"0x{candidate_relocation.addend & 0xFFFFFFFF:08x}",
                    "candidate_target": None
                    if candidate_target is None
                    else candidate_target.summary(),
                    "same_function_relative_destination": relative_match,
                }
            )
        source_word_count = max(0, min(rodata.size, len(data) - data_offset) // 4)
        original_slice = data[data_offset : data_offset + source_word_count * 4]
        candidate_slice = candidate.section_data(rodata)[:source_word_count * 4]
        observations.append(
            {
                "function": function,
                "original_location": {"section": ".data", "offset": f"0x{data_offset:x}"},
                "candidate_location": {
                    "section": ".rodata",
                    "offset": "0x0",
                    "section_index": rodata.index,
                },
                "candidate_defined_symbols_in_rodata": table_symbols,
                "original_bytes_sha256": hashlib.sha256(original_slice).hexdigest(),
                "candidate_bytes_sha256": hashlib.sha256(candidate_slice).hexdigest(),
                "original_bytes_equal_candidate_bytes": original_slice == candidate_slice,
                "relocation_correlations": correlations,
                "interpretation": (
                    "The candidate compiler emitted a local jump table whose relocated entries "
                    "point to the same function-relative instruction offsets as the PRX table. "
                    "This is content/structural correlation only; both are the compared artifacts, "
                    "and no independent linker metadata establishes object identity."
                ),
                "independent_identity_proven": False,
            }
        )

    # The string bytes are inspectable in the original, but corresponding
    # candidate symbols are undefined externals and contribute no candidate bytes.
    for offset, label in ((0x3C, "HTTP-related string A"), (0x68, "HTTP-related string B"),
                          (0x98, "HTTP-related string C"), (0xC8, "savedata path")):
        end = data.find(b"\x00", offset)
        if end < 0:
            end = len(data)
        content = data[offset : end + 1]
        observations.append(
            {
                "original_location": {"section": ".data", "offset": f"0x{offset:x}"},
                "label_from_context": label,
                "original_bytes": content.decode("ascii", "backslashreplace"),
                "original_bytes_sha256": hashlib.sha256(content).hexdigest(),
                "candidate_bytes_available": False,
                "candidate_symbols_are_undefined_externals": True,
                "independent_identity_proven": False,
                "interpretation": "Original content is known, but the compiled object contains an undefined address symbol, not corresponding data bytes or a proven link map.",
            }
        )
    return observations


def generate(prx_path: Path, build_dir: Path) -> dict[str, object]:
    original = elf.parse(prx_path)
    text_section = original.require_section(".text")
    text = original.section_data(text_section)
    functions_report = json.loads((build_dir / "functions.json").read_text(encoding="utf-8"))
    function_bounds = {
        item["name"]: (_json_int(item["start"], "function start"), _json_int(item["end"], "function end"))
        for item in functions_report["functions"]
    }
    original_resolver = datarefs.module_resolver(original, f"original:{_hash_file(prx_path)}")
    baseline_rows: list[dict[str, object]] = []
    pending_pairs: list[dict[str, object]] = []
    verified_candidates: dict[str, elf.ElfFile] = {}
    total_words = 0
    matching_words = 0

    for tag, function, expected_start, expected_pending_words, expected_total_words in FUNCTIONS:
        report_path = build_dir / "matches" / tag / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ParseError(f"{function}: match report must be a JSON object")
        _source_path, _object_path, candidate = _checked_baseline(
            report,
            tag=tag,
            function=function,
            address=expected_start,
            expected_pending_words=expected_pending_words,
            expected_total_words=expected_total_words,
            build_dir=build_dir,
        )
        verified_candidates[function] = candidate
        match = report["match"]
        start, end = function_bounds[function]
        if start != expected_start:
            raise ParseError(f"{function}: function inventory starts at 0x{start:x}, expected 0x{expected_start:x}")
        words_in_range = (end - start) // 4
        if words_in_range != expected_total_words or match["total_words"] != expected_total_words:
            raise ParseError(f"{function}: baseline size changed; refusing to project stale gap data")
        if report["status"] != INCONCLUSIVE or match["difference_count"] != 0 or match["relocation_issues"]:
            raise ParseError(f"{function}: baseline is no longer the expected inconclusive/no-difference result")

        candidate_text = candidate.require_section(".text")
        candidate_region_offset = _json_int(match["candidate"]["section_offset"], "candidate section offset")
        byte_count = expected_total_words * 4
        original_region_offset = start - text_section.addr
        if original_region_offset < 0 or original_region_offset + byte_count > len(text):
            raise ParseError(f"{function}: original function range is outside .text")
        original_bytes = text[original_region_offset : original_region_offset + byte_count]
        candidate_bytes = candidate.section_data(candidate_text)[
            candidate_region_offset : candidate_region_offset + byte_count
        ]
        if len(candidate_bytes) != byte_count:
            raise ParseError(f"{function}: candidate function range is outside candidate .text")
        original_words = decode_words(original_bytes, f"{function}: original")
        candidate_words = decode_words(candidate_bytes, f"{function}: candidate")

        original_map = relocation_sites(
            original.relocations_for(".text"), original_region_offset, byte_count
        )
        candidate_map = relocation_sites(
            candidate.relocations_for(".text"), candidate_region_offset, byte_count
        )
        original_pairs = pair_hi16_lo16(original_map.sites, original_words)
        candidate_pairs = pair_hi16_lo16(candidate_map.sites, candidate_words)
        limitation_by_hi = pending_hi_indices(match["limitations"], expected_total_words)
        pending = _pair_projection(
            function=function,
            start=start,
            total_words=expected_total_words,
            original=original,
            candidate=candidate,
            original_words=original_words,
            candidate_words=candidate_words,
            original_pairs=original_pairs,
            candidate_pairs=candidate_pairs,
            original_sites=original_map.sites,
            candidate_sites=candidate_map.sites,
            original_relocations={
                item.section_offset: item
                for item in original.relocations_for(".text")
                if item.section_offset is not None
            },
            candidate_relocations={
                item.section_offset: item
                for item in candidate.relocations_for(".text")
                if item.section_offset is not None
            },
            original_region_offset=original_region_offset,
            candidate_region_offset=candidate_region_offset,
            references=datarefs.recover_references(original, ".text", start, end),
            limitation_by_hi=limitation_by_hi,
            original_resolver=original_resolver,
            candidate_resolver=datarefs.module_resolver(
                candidate, f"candidate:{report['provenance']['object_sha256']}"
            ),
        )
        function_pending = sum(len(pair["words"]) for pair in pending)
        if function_pending != expected_pending_words:
            raise ParseError(
                f"{function}: located {function_pending} pending words from per-word limitations; "
                f"baseline expects {expected_pending_words}"
            )
        if len({word["word_index"] for pair in pending for word in pair["words"]}) != function_pending:
            raise ParseError(f"{function}: pending word indexes are duplicated")

        baseline_rows.append(
            {
                "function": function,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "status": report["status"],
                "matching_words": match["matching_words"],
                "total_words": match["total_words"],
                "located_pending_words": function_pending,
                "located_pending_pairs": len(pending),
                "difference_count": match["difference_count"],
                "relocation_issues": match["relocation_issues"],
                "limitations": match["limitations"],
                "source_sha256": report["provenance"]["source_sha256"],
                "object_sha256": report["provenance"]["object_sha256"],
                "compiler": report["provenance"]["compiler"],
                "loader": report["provenance"]["loader"],
                "flags": report["provenance"]["flags"],
            }
        )
        pending_pairs.extend(pending)
        total_words += expected_total_words
        matching_words += match["matching_words"]

    pending_word_count = sum(len(pair["words"]) for pair in pending_pairs)
    if total_words != 291 or matching_words != 231 or pending_word_count != 60:
        raise ParseError(
            f"baseline reconciliation failed: {matching_words}/{total_words}, {pending_word_count} pending words"
        )
    if len(pending_pairs) != 30:
        raise ParseError(f"expected 30 pending HI16/LO16 pairs, found {len(pending_pairs)}")

    datarefs_report = json.loads((build_dir / "datarefs.json").read_text(encoding="utf-8"))
    exit_path = build_dir / "datarefs.exit-code.txt"
    try:
        datarefs_exit_code = int(exit_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise ParseError("datarefs exit code is missing; rerun with --reproduce") from exc
    if datarefs_exit_code not in (0, 5):
        raise ParseError(f"datarefs had unexpected exit code {datarefs_exit_code}")
    if datarefs_report.get("sha256") != _hash_file(prx_path):
        raise ParseError("datarefs report does not match the inspected PRX hash")
    usage = datarefs.build_global_usage(datarefs_report)
    stored_usage = json.loads((build_dir / "global-usage.json").read_text(encoding="utf-8"))
    stored_projection = {key: stored_usage.get(key) for key in ("section", "locations", "unresolved")}
    if usage != stored_projection:
        raise ParseError("global-usage.json differs from build_global_usage(datarefs.json)")
    for key in ("prx", "sha256"):
        if key in datarefs_report and stored_usage.get(key) != datarefs_report[key]:
            raise ParseError(f"global-usage.json provenance differs from datarefs.json ({key})")

    toolchain_path = build_dir / "toolchain.json"
    toolchain_report = json.loads(toolchain_path.read_text(encoding="utf-8"))
    tool_by_name = {item["name"]: item for item in toolchain_report["tools"]}
    compiler = tool_by_name.get("mwccpsp", {})
    loader = tool_by_name.get("wibo", {})
    if (
        compiler.get("version")
        != "Metrowerks C/C++ Compiler for MIPS/PSP. (Version 3.0.1 build 219)"
        or loader.get("version") != "wibo 1.2.0 (Linux x86_64)"
    ):
        raise ParseError("the available compiler/loader versions differ from the recorded baseline")

    evidence_review = _bounded_local_artifact_review(prx_path, original, build_dir)
    if evidence_review["evidence_search_status"] == "CANDIDATES_UNVERIFIED":
        evidence_reason = (
            f"The bounded search found {evidence_review['candidate_count']} candidate file(s), "
            "but filename/extension presence does not authenticate their origin or version and "
            "does not prove a candidate-symbol link. No cross-artifact identity is established."
        )
    else:
        evidence_reason = (
            "No candidate linker or symbol artifacts were found in the bounded search paths. "
            "Generated Seto/Splat outputs are recorded separately and are not independent evidence."
        )

    return {
        "schema_version": 1,
        "purpose": "Auditable projection of the eight current INCONCLUSIVE compiled-object baselines; not a new matcher or a symbol-link verifier.",
        "original_prx": {
            "path": prx_path.as_posix(),
            "sha256": _hash_file(prx_path),
            "elf_summary": original.summary(),
        },
        "toolchain": {
            "compiler": compiler["version"],
            "compiler_path": compiler["path"],
            "loader": loader["version"],
            "loader_path": loader["path"],
            "flags": ["-O4,p", "-sdatathreshold", "0"],
            "profile": "config/wsl/seto.toml (local, git-ignored)",
        },
        "datarefs_exit_code": datarefs_exit_code,
        "reconciliation": {
            "inconclusive_functions": 8,
            "matched_words": matching_words,
            "total_words": total_words,
            "pending_words": pending_word_count,
            "pending_pairs": len(pending_pairs),
            "difference_count": 0,
            "relocation_issue_count": 0,
            "pending_indexes_source": "exact comparator limitation word indexes + relocation_sites()/pair_hi16_lo16(); never total_words - matching_words",
        },
        "functions": baseline_rows,
        "pending_pairs": pending_pairs,
        "global_usage": {
            "locations": len(usage["locations"]),
            "unresolved_references": len(usage["unresolved"]),
            "report_path": "build/seto012/global-usage.json",
        },
        "candidate_content_observations": _candidate_content_observations(
            original, verified_candidates
        ),
        "independent_evidence_search": evidence_review,
        "target_evidence_review": [
            {
                "original_target": {"section": ".text", "offset": "0x34"},
                "original_location": "PROVEN",
                "candidate_reference": "undefined symbol func_00000034 in func_00000000.o",
                "additional_observation": "The separately compiled func_00000034 baseline is MATCHED 20/20, but that candidate comparison is not an independent artifact establishing the undefined relocation's cross-object link.",
                "independent_link_proven": False,
            },
            {
                "original_target": {"section": ".text", "offset": "0x84"},
                "original_location": "PROVEN",
                "candidate_reference": "undefined symbol func_00000084 in func_00000000.o",
                "additional_observation": "func_00000000 passes this address as an argument; there is no proven direct call, and the classification does not prove an independent function identity.",
                "independent_link_proven": False,
            },
            {
                "original_target": {"segment": 0, "offset": "0x4850", "initialized": False},
                "original_location": "INFERRED",
                "candidate_reference": "undefined symbol D_00004850",
                "additional_observation": "The segment tail has no named section; no section or object identity is invented.",
                "independent_link_proven": False,
            },
            {
                "original_target": {"segment": 0, "offsets": ["0x4860", "0x604860", "0x604864", "0x604918", "0x604b18", "0x604b9c"]},
                "original_location": "INFERRED",
                "candidate_reference": "address-derived D_ symbols are undefined in the compiled ET_REL objects",
                "additional_observation": "SetoObservedBlock proves a coherent C access layout only; it is not a link to the stripped module's original object.",
                "independent_link_proven": False,
            },
        ],
        "identity_conclusion": {
            "independent_cross_artifact_link_found": False,
            "verified_symbol_links_created": 0,
            "evidence_search_status": evidence_review["evidence_search_status"],
            "candidate_count": evidence_review["candidate_count"],
            "reason": evidence_reason,
            "classification_change": "none; all eight baselines remain INCONCLUSIVE",
        },
    }


def reproduce_inputs(prx_path: Path, build_dir: Path, config: Path) -> None:
    """Run the existing CLI/compiler scripts and retain fresh, auditable inputs."""
    build_dir.mkdir(parents=True, exist_ok=True)

    def run(argv: list[str], label: str, accepted: tuple[int, ...]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode not in accepted:
            raise ParseError(
                f"{label} exited {result.returncode}; stderr: {result.stderr.strip()}"
            )
        return result

    toolchain = run(
        [
            sys.executable,
            "-m",
            "seto",
            "--config",
            str(config),
            "toolchain",
            "--json",
            "--out",
            str(build_dir / "toolchain.json"),
        ],
        "seto toolchain",
        (0,),
    )
    json.loads(toolchain.stdout)
    (build_dir / "toolchain.stdout.json").write_text(toolchain.stdout, encoding="utf-8")

    functions = run(
        [
            sys.executable,
            "-m",
            "seto",
            "--config",
            str(config),
            "functions",
            "--prx",
            str(prx_path),
            "--json",
        ],
        "seto functions",
        (0,),
    )
    json.loads(functions.stdout)
    (build_dir / "functions.json").write_text(functions.stdout, encoding="utf-8")

    datarefs_path = build_dir / "datarefs.json"
    datarefs_result = run(
        [
            sys.executable,
            "-m",
            "seto",
            "--config",
            str(config),
            "datarefs",
            "--prx",
            str(prx_path),
            "--out",
            str(datarefs_path),
            "--json",
        ],
        "seto datarefs",
        (0, 5),
    )
    json.loads(datarefs_result.stdout)
    json.loads(datarefs_path.read_text(encoding="utf-8"))
    (build_dir / "datarefs.stdout.json").write_text(
        datarefs_result.stdout, encoding="utf-8"
    )
    (build_dir / "datarefs.stderr.txt").write_text(datarefs_result.stderr, encoding="utf-8")
    (build_dir / "datarefs.exit-code.txt").write_text(
        f"{datarefs_result.returncode}\n", encoding="ascii"
    )

    usage = run(
        [
            sys.executable,
            "scripts/global_usage.py",
            "--report",
            str(datarefs_path),
            "--out",
            str(build_dir / "global-usage.json"),
        ],
        "scripts/global_usage.py",
        (0,),
    )
    (build_dir / "global-usage.stdout.txt").write_text(
        usage.stdout, encoding="utf-8"
    )

    sibling = prx_path.parent / "libtutoriallist.prx"
    if sibling.is_file():
        sibling_import_path = build_dir / "libtutoriallist-imports.json"
        sibling_imports = run(
            [
                sys.executable,
                "-m",
                "seto",
                "--config",
                str(config),
                "imports",
                "--prx",
                str(sibling),
                "--json",
                "--out",
                str(sibling_import_path),
            ],
            "seto imports libtutoriallist.prx",
            (0,),
        )
        json.loads(sibling_imports.stdout)
        json.loads(sibling_import_path.read_text(encoding="utf-8"))
        (build_dir / "libtutoriallist-imports.stdout.json").write_text(
            sibling_imports.stdout, encoding="utf-8"
        )

    for tag, function, start, _pending_words, _total_words in FUNCTIONS:
        out = build_dir / "matches" / tag
        out.mkdir(parents=True, exist_ok=True)
        source = REPO_ROOT / "decomp" / "src" / f"{function}.c"
        result = run(
            [
                sys.executable,
                "scripts/match_function.py",
                "--config",
                str(config),
                "--prx",
                str(prx_path),
                "--function",
                hex(start),
                "--source",
                str(source),
                "--out",
                str(out),
                "--json",
            ],
            f"match_function.py {function}",
            (0, 5),
        )
        record = json.loads(result.stdout)
        if record.get("status") != INCONCLUSIVE or record.get("exit_code") != 5:
            raise ParseError(f"{function}: expected the real INCONCLUSIVE baseline")
        (out / "report.json").write_text(result.stdout, encoding="utf-8")
        (out / "stderr.txt").write_text(result.stderr, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prx", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=Path("build/seto012"))
    parser.add_argument("--out", type=Path, default=Path("build/seto012/matching-gaps.json"))
    parser.add_argument("--config", type=Path, default=Path("config/wsl/seto.toml"))
    parser.add_argument(
        "--reproduce",
        action="store_true",
        help="regenerate functions/datarefs/global usage and freshly compile all eight candidates first",
    )
    args = parser.parse_args(argv)
    try:
        prx_path = args.prx if args.prx.is_absolute() else REPO_ROOT / args.prx
        build_dir = args.build_dir if args.build_dir.is_absolute() else REPO_ROOT / args.build_dir
        output = args.out if args.out.is_absolute() else REPO_ROOT / args.out
        config = args.config if args.config.is_absolute() else REPO_ROOT / args.config
        if args.reproduce:
            reproduce_inputs(prx_path, build_dir, config)
        report = generate(prx_path, build_dir)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, KeyError, TypeError, ParseError) as exc:
        print(f"audit error: {exc}", file=sys.stderr)
        return 1
    print(
        f"{output}: {report['reconciliation']['pending_words']} pending words "
        f"in {report['reconciliation']['pending_pairs']} pairs; no identity links verified"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
