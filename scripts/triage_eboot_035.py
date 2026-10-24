"""Build the deterministic SETO-DECOMP-035 EBOOT/export/import triage report."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from seto import datarefs, elf, exports, imports, mips
from seto.hashing import sha256_file

import probe_common  # noqa: E402

EBOOT_RELATIVE = Path("private/decrypted/ULUS10136_EBOOT.elf")
TUTORIALLIST_RELATIVE = Path(
    "private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx"
)
HTML_VIEW_RELATIVE = Path("private/original/PSP_GAME/USRDIR/gmodule/libhtml_view.prx")
GHIDRA_LOG_DIRECTORY = Path("build/seto035/ghidra-evidence")
OUTPUT_RELATIVE = Path("build/seto035/export-triage.json")
LIBRARY = "libehsys"
EXPECTED_GHIDRA_LANGUAGE = "Allegrex:LE:32:default"


@dataclass(frozen=True)
class Candidate:
    address: int
    end: int
    decision: str
    reason: str


# A bounded set of verified exports examined with Ghidra. These ranges are
# checked against the saved headless-script output before they enter the report.
CANDIDATES = (
    Candidate(
        0x8040,
        0x813C,
        "deferred",
        "63 instructions; indirect callback, two data references, and the automatic "
        "interval truncates at 0x80F4.",
    ),
    Candidate(
        0x33D10,
        0x33D4C,
        "MATCHED",
        "High-priority NID imported by libtutoriallist; one internal call, no data "
        "references, and a simple exact boundary. Full production comparison "
        "matched 15/15 words.",
    ),
    Candidate(
        0x38DB4,
        0x38EB0,
        "deferred",
        "63 instructions construct a multiword command from several incoming "
        "values; prototype and argument provenance need more work.",
    ),
    Candidate(
        0x302C4,
        0x30370,
        "deferred",
        "43 instructions include five load-segment-only data references without "
        "named-section identity.",
    ),
    Candidate(
        0x4217C,
        0x4222C,
        "deferred",
        "44 instructions, four internal calls, and a 0xC60-byte stack frame "
        "increase reconstruction cost.",
    ),
    Candidate(
        0x3643C,
        0x364E4,
        "NONMATCHING reconstruction",
        "42 instructions, three libtutoriallist call sites, and one internal "
        "helper. The C hypothesis compiled to the exact interval; full comparison "
        "matched 26/42 words with register/branch-scheduling differences.",
    ),
    Candidate(
        0x3F2B0,
        0x3F328,
        "rejected",
        "30-instruction comparison-only body, four libtutoriallist call sites, "
        "and no relocations or data references. C hypotheses emitted 28-, 31-, or "
        "32-word symbols, so no full-symbol comparison was accepted.",
    ),
    Candidate(
        0x37F38,
        0x38040,
        "deferred",
        "66 instructions combine two dynamic bit scans and packed command fields "
        "before an internal call.",
    ),
    Candidate(
        0xD28C,
        0xD324,
        "attempted",
        "38-instruction aligned word/byte scan, five libhtml_view call sites, and "
        "no data references; compiled symbol was 28 bytes short.",
    ),
    Candidate(
        0x9C98,
        0x9D1C,
        "NONMATCHING reconstruction",
        "33-instruction bounded comparison loop, one libtutoriallist call site, "
        "and no outgoing calls or data references. Full production comparison "
        "matched 3/33 words.",
    ),
)


def _marker(text: str, name: str) -> str | None:
    matches = re.findall(rf"\b{name}=([^\s()]+)", text)
    return matches[-1] if matches else None


def parse_ghidra_evidence(text: str, start: int, end: int) -> dict[str, object]:
    """Extract and check the exact-range markers emitted by SetoAnalyzeFunction."""
    language = _marker(text, "SETO_LANGUAGE")
    boundary = _marker(text, "SETO_BOUNDARY_STATUS")
    decomp = _marker(text, "SETO_DECOMP_STATUS")
    body_start = _marker(text, "SETO_FUNCTION_BODY_START")
    body_end = _marker(text, "SETO_FUNCTION_BODY_END")
    body_addresses = _marker(text, "SETO_FUNCTION_BODY_ADDRESSES")
    body_ranges = _marker(text, "SETO_FUNCTION_BODY_RANGES")
    addressable_unit = _marker(text, "SETO_ADDRESSABLE_UNIT_SIZE")
    requested_start = _marker(text, "SETO_FUNCTION_START")
    requested_end = _marker(text, "SETO_FUNCTION_END")
    instructions = len(re.findall(r"\bSETO_INSN=", text))

    expected = {
        "language": EXPECTED_GHIDRA_LANGUAGE,
        "boundary_status": "EXACT",
        "decomp_status": "OK",
        "body_start": f"{start:08x}",
        "body_end": f"{end:08x}",
        "body_addresses": str(end - start),
        "body_ranges": "1",
        "addressable_unit_size": "1",
        "requested_start": f"0x{start:x}",
        "requested_end": f"0x{end:x}",
        "instruction_count": str((end - start) // 4),
    }
    observed = {
        "language": language,
        "boundary_status": boundary,
        "decomp_status": decomp,
        "body_start": body_start,
        "body_end": body_end,
        "body_addresses": body_addresses,
        "body_ranges": body_ranges,
        "addressable_unit_size": addressable_unit,
        "requested_start": requested_start,
        "requested_end": requested_end,
        "instruction_count": str(instructions),
    }
    mismatches = [
        f"{field}: expected {value!r}, got {observed[field]!r}"
        for field, value in expected.items()
        if observed[field] != value
    ]
    if mismatches:
        raise ValueError("Ghidra boundary evidence rejected: " + "; ".join(mismatches))
    return {
        "tool": "Ghidra 12.1.3",
        "script": "scripts/ghidra/SetoAnalyzeFunction.java",
        "log": (GHIDRA_LOG_DIRECTORY / f"{start:x}.log").as_posix(),
        "language": language,
        "compiler_spec": _marker(text, "SETO_COMPILER_SPEC"),
        "boundary_status": boundary,
        "decomp_status": decomp,
        "body_start": f"0x{start:x}",
        "body_end": f"0x{end:x}",
        "body_bytes": end - start,
        "body_ranges": int(body_ranges or "0"),
        "addressable_unit_size": int(addressable_unit or "0"),
        "instruction_count": instructions,
    }


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _call_sites(
    code: bytes, start: int, end: int, *, section_address: int = 0
) -> list[dict[str, object]]:
    section_offset = start - section_address
    calls: list[dict[str, object]] = []
    for relative in range(0, end - start, 4):
        word = int.from_bytes(
            code[section_offset + relative : section_offset + relative + 4], "little"
        )
        address = start + relative
        if mips.is_jal(word):
            calls.append({"site": _hex(address), "target": _hex(mips.jump_target(word, address))})
    return calls


def _artifact_path(relative: Path) -> Path:
    path = REPO_ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(f"required private input is absent: {relative.as_posix()}")
    return path


def build_report() -> dict[str, object]:
    eboot_path = _artifact_path(EBOOT_RELATIVE)
    tutorial_path = _artifact_path(TUTORIALLIST_RELATIVE)
    html_path = _artifact_path(HTML_VIEW_RELATIVE)
    eboot = elf.parse(eboot_path)
    export_collection = exports.collect_exports(eboot, LIBRARY)
    text = eboot.require_section(".text")
    code = eboot.section_data(text)
    candidate_functions = mips.find_functions(code, text.addr, "EBOOT .text")
    functions_by_start = {function.start: function for function in candidate_functions}

    module_inputs = (
        ("libtutoriallist.prx", TUTORIALLIST_RELATIVE, tutorial_path),
        ("libhtml_view.prx", HTML_VIEW_RELATIVE, html_path),
    )
    parsed_modules: list[
        tuple[str, Path, elf.ElfFile, imports.ImportTable, tuple[imports.CallReference, ...]]
    ] = []
    identities: dict[tuple[str, int], dict[str, dict[str, list[object]]]] = {}
    for module_name, relative, path in module_inputs:
        parsed = elf.parse(path)
        table = imports.build_import_table(parsed)
        references = imports.call_references(parsed, table)
        parsed_modules.append((module_name, relative, parsed, table, references))
        for item in table.imports.values():
            if item.library != LIBRARY:
                continue
            entry = identities.setdefault(item.identity, {}).setdefault(
                module_name, {"stubs": [], "call_sites": []}
            )
            entry["stubs"].append(item.stub_address)
        for reference in references:
            if reference.imported is None or reference.imported.library != LIBRARY:
                continue
            entry = identities.setdefault(reference.imported.identity, {}).setdefault(
                module_name, {"stubs": [], "call_sites": []}
            )
            entry["call_sites"].append(reference.address)

    export_records: list[dict[str, object]] = []
    for item in export_collection.exports:
        importer_entries = identities.get((item.library, item.nid), {})
        imported_by: list[dict[str, object]] = []
        for module_name, _, _, table, _ in parsed_modules:
            evidence = importer_entries.get(module_name)
            if evidence is None:
                continue
            imported_by.append(
                {
                    "module": module_name,
                    "stub_addresses": [_hex(value) for value in sorted(set(evidence["stubs"]))],
                    "call_sites": [_hex(value) for value in sorted(set(evidence["call_sites"]))],
                    "table_limitations": list(table.limitations),
                }
            )
        export_records.append(
            {
                "library": item.library,
                "nid": f"0x{item.nid:08X}",
                "address": _hex(item.address),
                "entry_index": item.entry_index,
                "slot_index": item.slot_index,
                "pointer_site": _hex(item.pointer_site),
                "function_count": item.function_count,
                "version": f"0x{item.version:04x}",
                "attributes": f"0x{item.attributes:04x}",
                "pointer_relocation": item.pointer_relocation.summary(),
                "importers": imported_by,
            }
        )

    all_calls = _call_sites(code, text.addr, text.end, section_address=text.addr)
    incoming_calls: dict[int, list[str]] = {}
    for call in all_calls:
        target = int(str(call["target"]), 16)
        incoming_calls.setdefault(target, []).append(str(call["site"]))
    eboot_relocations = eboot.relocations_for(".text")
    selected: list[dict[str, object]] = []
    for candidate in CANDIDATES:
        matching_exports = [
            item for item in export_collection.exports if item.address == candidate.address
        ]
        if len(matching_exports) != 1:
            raise ValueError(
                f"candidate 0x{candidate.address:x} must have exactly one proven export; "
                f"got {len(matching_exports)}"
            )
        exported = matching_exports[0]
        ghidra_log = REPO_ROOT / GHIDRA_LOG_DIRECTORY / f"{candidate.address:x}.log"
        evidence = parse_ghidra_evidence(
            ghidra_log.read_text(encoding="utf-8", errors="replace"),
            candidate.address,
            candidate.end,
        )
        auto_function = functions_by_start.get(candidate.address)
        interval_relocations = [
            relocation.summary()
            for relocation in eboot_relocations
            if relocation.offset is not None
            and candidate.address <= relocation.offset < candidate.end
        ]
        references = datarefs.recover_references(
            eboot,
            ".text",
            candidate.address,
            candidate.end,
            symbols=eboot.symbols,
        )
        selected.append(
            {
                "nid": f"0x{exported.nid:08X}",
                "address": _hex(candidate.address),
                "export_slot": exported.slot_index,
                "export_entry": exported.entry_index,
                "pointer_site": _hex(exported.pointer_site),
                "interval": [_hex(candidate.address), _hex(candidate.end)],
                "bytes": candidate.end - candidate.address,
                "instructions": (candidate.end - candidate.address) // 4,
                "boundary_evidence": {
                    "mips_find_functions_candidate": (
                        None
                        if auto_function is None
                        else {
                            "interval": [_hex(auto_function.start), _hex(auto_function.end)],
                            "matches_ghidra_end": auto_function.end == candidate.end,
                            "classification": "candidate only; Ghidra evidence is "
                            "authoritative for this triage",
                        }
                    ),
                    "ghidra": evidence,
                },
                "incoming_eboot_call_sites": sorted(
                    incoming_calls.get(candidate.address, []), key=lambda value: int(value, 16)
                ),
                "outgoing_direct_calls": _call_sites(
                    code,
                    candidate.address,
                    candidate.end,
                    section_address=text.addr,
                ),
                "relocations": interval_relocations,
                "data_references": [reference.summary() for reference in references],
                "importers": next(
                    record["importers"]
                    for record in export_records
                    if record["address"] == _hex(candidate.address)
                ),
                "decision": candidate.decision,
                "reason": candidate.reason,
            }
        )

    nid_groups = [
        {
            "nid": f"0x{group.nid:08X}",
            "addresses": [_hex(address) for address in group.addresses],
            "ambiguous": group.ambiguous,
            "slots": [
                {
                    "address": _hex(item.address),
                    "entry_index": item.entry_index,
                    "slot_index": item.slot_index,
                }
                for item in group.exports
            ],
        }
        for group in export_collection.nid_groups
    ]
    aliases = [
        {
            "address": _hex(alias.address),
            "nids": [f"0x{nid:08X}" for nid in sorted({item.nid for item in alias.exports})],
            "slots": [
                {
                    "nid": f"0x{item.nid:08X}",
                    "entry_index": item.entry_index,
                    "slot_index": item.slot_index,
                }
                for item in alias.exports
            ],
        }
        for alias in export_collection.aliases
    ]
    limitations = [limitation.__dict__ for limitation in export_collection.limitations]
    for limitation in limitations:
        if limitation["nid"] is not None:
            limitation["nid"] = f"0x{limitation['nid']:08X}"
        for field in ("pointer_site",):
            if limitation[field] is not None:
                limitation[field] = _hex(limitation[field])

    priority_nids = (0x31454993, 0x10F3BB61, 0xB4471B5E, 0x20E340D9, 0x8171F765)
    priority_exports = []
    for nid in priority_nids:
        priority_exports.append(
            {
                "nid": f"0x{nid:08X}",
                "exports": [
                    {
                        "address": record["address"],
                        "entry_index": record["entry_index"],
                        "slot_index": record["slot_index"],
                        "importers": record["importers"],
                    }
                    for record in export_records
                    if record["nid"] == f"0x{nid:08X}"
                ],
            }
        )

    return {
        "schema_version": 1,
        "task": "SETO-DECOMP-035",
        "library": LIBRARY,
        "inputs": [
            {"path": EBOOT_RELATIVE.as_posix(), "sha256": sha256_file(eboot_path)},
            {"path": TUTORIALLIST_RELATIVE.as_posix(), "sha256": sha256_file(tutorial_path)},
            {"path": HTML_VIEW_RELATIVE.as_posix(), "sha256": sha256_file(html_path)},
        ],
        "summary": {
            "proven_exports": len(export_collection.exports),
            "unique_proven_nids": len({item.nid for item in export_collection.exports}),
            "limitations": len(export_collection.limitations),
            "unproven_export_slots": sum(
                limitation.slot_index is not None for limitation in export_collection.limitations
            ),
            "duplicate_nid_groups": len(export_collection.nid_groups),
            "ambiguous_nid_groups": len(export_collection.ambiguous_nids),
            "alias_groups": len(export_collection.aliases),
            "examined_candidates": len(selected),
            "imported_export_slots": sum(bool(record["importers"]) for record in export_records),
        },
        "exports": export_records,
        "priority_nid_checks": priority_exports,
        "duplicate_nids": nid_groups,
        "aliases": aliases,
        "limitations": limitations,
        "candidate_analysis": selected,
    }


def main() -> int:
    build_root = probe_common.validated_build_root(REPO_ROOT, subdir="seto035")
    output_path = REPO_ROOT / OUTPUT_RELATIVE
    report: dict[str, Any] = build_report()
    probe_common.write_build_text(
        output_path,
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        build_root,
    )
    print(f"wrote {OUTPUT_RELATIVE.as_posix()}")
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
