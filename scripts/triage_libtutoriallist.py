#!/usr/bin/env python3
"""Build a deterministic baseline and conservative triage for libtutoriallist.prx.

The script reuses Seto's ELF, MIPS, import, data-reference, and split APIs. It
does not compile candidates or infer cross-artifact data identity. Real match
attempts are made separately with ``scripts/match_function.py``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from probe_common import (  # noqa: E402
    ProbeError,
    canonical_json,
    ensure_build_dir,
    prepare_build_file,
    repo_path,
    relative,
    validate_saved_match_record,
    validated_build_root,
    write_build_text,
)
from seto import datarefs, elf, imports, matching, mips, split  # noqa: E402
from seto.hashing import sha256_file  # noqa: E402
from seto.psp_reloc import psp_inventory  # noqa: E402
from seto.toolchain import run as run_tool  # noqa: E402

MODULE_RELATIVE = Path("private/original/PSP_GAME/USRDIR/gmodule/libtutoriallist.prx")
EXPECTED_MODULE_SHA256 = "2d843f46680814ac9e5c918bf523e182f64de1bc7841eb9262fecdc03c268a49"
GHIDRA_EVIDENCE_NAME = "ghidra-boundaries.json"
MAX_SELECTED_FUNCTIONS = 3
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GHIDRA_MARKER_RE = re.compile(r"\bSETO_([A-Z_]+)=(.*?)(?:\s+\(GhidraScript\))?\s*$")

CONDITIONAL_BRANCH_OPCODES = {0x01, 0x04, 0x05, 0x06, 0x07, 0x14, 0x15, 0x16, 0x17}


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _reject_repo_symlink_components(path: Path, repo_root: Path, label: str) -> None:
    """Reject symlinked components before resolving an input path under the repo."""
    absolute_root = repo_root.absolute()
    absolute_path = (path if path.is_absolute() else absolute_root / path).absolute()
    try:
        relative_parts = absolute_path.relative_to(absolute_root).parts
    except ValueError as exc:
        raise ProbeError("FAIL", f"{label} path escapes the repository") from exc
    current = absolute_root
    if current.is_symlink():
        raise ProbeError("FAIL", f"{label} repository root is a symlink")
    for part in relative_parts:
        current = current / part
        if current.is_symlink():
            raise ProbeError("FAIL", f"{label} path contains a symlink component")


def verify_module_sha256(actual: str, expected: str | None = None) -> None:
    """Fail closed if the real input is not the pinned module version."""
    if expected is None:
        expected = EXPECTED_MODULE_SHA256
    if not _valid_sha256(actual) or actual != expected:
        raise ProbeError("FAIL", "libtutoriallist.prx SHA-256 differs from the pinned baseline")


def validate_function_intervals(
    functions: Sequence[mips.Function], start: int, end: int
) -> None:
    """Require aligned, non-empty intervals to tile the complete ``.text`` range."""
    if start < 0 or end <= start or start % 4 or end % 4:
        raise ProbeError("FAIL", f"invalid aligned .text range [0x{start:x}, 0x{end:x})")
    previous = start
    for function in sorted(functions, key=lambda item: (item.start, item.end)):
        if function.start % 4 or function.end % 4 or function.end <= function.start:
            raise ProbeError(
                "FAIL", f"invalid or unaligned function interval [0x{function.start:x}, 0x{function.end:x})"
            )
        if function.start != previous:
            relation = "overlap" if function.start < previous else "gap"
            raise ProbeError(
                "FAIL",
                f"function intervals contain a {relation} before 0x{function.start:x} "
                f"(expected 0x{previous:x})",
            )
        previous = function.end
    if previous != end:
        raise ProbeError("FAIL", f"function intervals end at 0x{previous:x}, not .text end 0x{end:x}")


def _flow_summary(words: Sequence[int], start: int) -> dict[str, object]:
    conditional: list[dict[str, object]] = []
    indirect_jumps = 0
    returns = 0
    direct_jumps = 0
    for index, word in enumerate(words):
        pc = start + 4 * index
        opcode = mips.opcode(word)
        is_conditional = opcode in CONDITIONAL_BRANCH_OPCODES or (
            opcode == 0x11 and mips.rs(word) == 0x08
        )
        if is_conditional:
            displacement = mips.signed_immediate(word) * 4
            target = pc + 4 + displacement
            conditional.append(
                {"address": f"0x{pc:x}", "target": f"0x{target:x}", "backward": target < pc}
            )
        elif opcode in (mips.OP_J, mips.OP_JAL):
            direct_jumps += 1
        elif mips.is_jr(word):
            if mips.rs(word) == mips.REG_RA:
                returns += 1
            else:
                indirect_jumps += 1
        elif opcode == mips.OP_SPECIAL and mips.funct(word) == mips.FUNCT_JALR:
            indirect_jumps += 1

    backward = sum(bool(item["backward"]) for item in conditional)
    shape = "INDIRECT_TRANSFER" if indirect_jumps else "LOOP" if backward else (
        "CONDITIONAL" if conditional else "LINEAR"
    )
    return {
        "shape": shape,
        "conditional_branch_count": len(conditional),
        "backward_branch_count": backward,
        "indirect_jump_count": indirect_jumps,
        "direct_jump_and_call_count": direct_jumps,
        "return_count": returns,
        "conditional_branches": conditional,
        "indirect_transfer_is_switch_proof": False,
    }


def _section_record(section: elf.Section) -> dict[str, object]:
    return {
        **section.summary(),
        "link": section.link,
        "info": section.info,
        "entry_size": section.entsize,
    }


def _resident_code_pointers(module: elf.ElfFile, text: elf.Section) -> dict[int, list[str]]:
    """Record relocated .rodata.sceResident pointers into .text without naming them."""
    result: dict[int, list[str]] = {}
    section = module.section(".rodata.sceResident")
    if section is None:
        return result
    for relocation in module.relocations_for(section.name):
        address = relocation.addend
        if (
            relocation.type == elf.R_MIPS_32
            and relocation.addend_valid
            and text.addr <= address < text.end
            and address % 4 == 0
        ):
            result.setdefault(address, []).append(f"0x{relocation.offset:x}")
    return result


def build_baseline(
    module: elf.ElfFile,
    module_sha256: str,
    *,
    module_path: str = MODULE_RELATIVE.as_posix(),
) -> dict[str, object]:
    """Build an in-memory deterministic baseline from an already parsed ELF."""
    if not _valid_sha256(module_sha256):
        raise ProbeError("FAIL", "baseline requires a valid lowercase module SHA-256")
    relative_module_path = Path(module_path)
    if relative_module_path.is_absolute() or ".." in relative_module_path.parts:
        raise ProbeError("FAIL", "baseline module path must be repository-relative")
    if not module.is_prx or not module.is_mips:
        raise ProbeError("FAIL", "baseline input must be an ELF32 little-endian MIPS PSP PRX")

    text = module.require_section(".text")
    if not text.is_allocated or not (text.flags & mips.SHF_EXECINSTR):
        raise ProbeError("FAIL", ".text must be allocated and executable")
    if text.size % 4:
        raise ProbeError("FAIL", ".text size is not a multiple of four bytes")

    discovered = mips.find_functions(module.section_data(text), text.addr)
    validate_function_intervals(discovered, text.addr, text.end)
    function_starts = {function.start for function in discovered}

    import_table = imports.build_import_table(module)
    call_refs = imports.call_references(module, import_table, section=text.name)
    reference_report = datarefs.build_reference_report(
        module,
        text.name,
        [(function.name(), function.start, function.end) for function in discovered],
    )
    references_by_start = {
        int(str(entry["start"]), 16): entry["references"]
        for entry in reference_report["functions"]
    }
    calls_by_start: dict[int, list[imports.CallReference]] = {
        function.start: [
            reference
            for reference in call_refs
            if function.start <= reference.address < function.end
        ]
        for function in discovered
    }
    incoming: dict[int, list[dict[str, str]]] = {start: [] for start in function_starts}
    for refs in calls_by_start.values():
        for reference in refs:
            if reference.kind == "local" and reference.target in incoming:
                incoming[reference.target].append(
                    {"site": f"0x{reference.address:x}", "target": f"0x{reference.target:x}"}
                )

    raw_code_pointers = _resident_code_pointers(module, text)
    words = mips.decode_words(module.section_data(text), f"{module.reader.name}:.text")
    functions: list[dict[str, object]] = []
    for function in discovered:
        section_start = function.start - text.addr
        section_end = function.end - text.addr
        function_words = words[section_start // 4 : section_end // 4]
        calls = calls_by_start[function.start]
        references = references_by_start[function.start]
        imports_seen: dict[tuple[str, int], set[int]] = {}
        call_rows: list[dict[str, object]] = []
        for reference in calls:
            row = reference.summary()
            imported = reference.imported
            if imported is not None:
                imports_seen.setdefault(imported.identity, set()).add(imported.stub_address)
            call_rows.append(row)
        call_rows.sort(key=lambda row: int(str(row["address"]), 16))

        boundary_evidence: list[str] = []
        if function.start == text.addr:
            boundary_evidence.append(".text section start")
        if incoming[function.start]:
            boundary_evidence.append("direct R_MIPS_26 call target")
        if section_start >= 8 and mips.is_return(words[section_start // 4 - 2]):
            boundary_evidence.append("instruction after jr $ra delay slot")

        imports_list = [
            {
                "library": library,
                "nid": f"0x{nid:08x}",
                "stub_addresses": [f"0x{address:x}" for address in sorted(addresses)],
            }
            for (library, nid), addresses in sorted(imports_seen.items())
        ]
        functions.append(
            {
                "name": function.name(),
                "start": f"0x{function.start:x}",
                "end": f"0x{function.end:x}",
                "size_bytes": function.size,
                "instruction_count": function.size // 4,
                "boundary_evidence": boundary_evidence,
                "incoming_direct_local_calls": sorted(
                    incoming[function.start], key=lambda item: int(item["site"], 16)
                ),
                "resident_table_code_pointer_sites": sorted(
                    raw_code_pointers.get(function.start, []), key=lambda value: int(value, 16)
                ),
                "flow": _flow_summary(function_words, function.start),
                "calls": call_rows,
                "call_counts": dict(Counter(reference.kind for reference in calls)),
                "imports": imports_list,
                "data_references": references,
            }
        )

    layout = split.build_layout(module, "libtutoriallist")
    layout_issues = split.validate_layout(layout, module)
    layout_errors = [issue.render() for issue in layout_issues if issue.severity.upper() == "ERROR"]
    if layout_errors:
        raise ProbeError("FAIL", "split layout validation failed: " + "; ".join(layout_errors))

    relocation_rows = [
        {"entry_order": index, **relocation.summary()}
        for index, relocation in enumerate(module.relocations)
    ]
    call_kind_counts = dict(Counter(reference.kind for reference in call_refs))
    unknown_calls = sum(1 for reference in call_refs if reference.kind == "unknown")
    limitations = list(module.observations)
    limitations.extend(import_table.limitations)
    limitations.extend(issue.render() for issue in layout_issues)
    if not module.symbols:
        limitations.append("the PRX is stripped; function names are address-derived and provisional")
    if any(reference.get("object_identity") == datarefs.NOT_APPLICABLE
           for entry in reference_report["functions"]
           for reference in entry["references"]):
        limitations.append(
            "data-reference locations describe this PRX only; object identity across a candidate ELF is not established"
        )

    imports_summary = import_table.summary()
    # ImportTable carries BytesReader.name for diagnostics; never serialize a
    # machine-specific absolute input path into the canonical report.
    imports_summary["module"] = "libtutoriallist.prx"

    return {
        "schema_version": 1,
        "module": {
            "name": "libtutoriallist.prx",
            "path": relative_module_path.as_posix(),
            "sha256": module_sha256,
        },
        "elf": {
            "header": module.header.summary(),
            "section_count": len(module.sections),
            "sections": [_section_record(section) for section in module.sections],
            "program_header_count": len(module.segments),
            "segments": [segment.summary() for segment in module.segments],
            "symbol_count": len(module.symbols),
            "comment": module.comment(),
            "text": text.summary(),
        },
        "layout": {
            **layout.summary(),
            "validation_issues": [issue.render() for issue in layout_issues],
        },
        "relocations": {
            "count": len(module.relocations),
            "psp_inventory": psp_inventory(module),
            "entries": relocation_rows,
        },
        "imports": {
            **imports_summary,
            "call_kind_counts": call_kind_counts,
            "unknown_call_count": unknown_calls,
        },
        "functions": functions,
        "limitations": sorted(set(limitations)),
    }


def validate_ghidra_evidence(
    report: object, baseline: Mapping[str, object]
) -> dict[int, Mapping[str, object]]:
    """Check Ghidra report consistency with the module hash and discovered intervals.

    The JSON SHA binding is local consistency evidence, not an authentication
    signature for the Ghidra process or its output.
    """
    if (
        not isinstance(report, dict)
        or isinstance(report.get("schema_version"), bool)
        or not isinstance(report.get("schema_version"), int)
        or report.get("schema_version") != 1
    ):
        raise ProbeError("FAIL", "Ghidra evidence must be a schema_version 1 object")
    module = baseline.get("module")
    if not isinstance(module, dict) or report.get("module_sha256") != module.get("sha256"):
        raise ProbeError("FAIL", "Ghidra evidence belongs to another module SHA-256")
    raw_functions = report.get("functions")
    baseline_functions = baseline.get("functions")
    if not isinstance(raw_functions, list) or not isinstance(baseline_functions, list):
        raise ProbeError("FAIL", "Ghidra evidence and baseline require function lists")
    expected = {
        (str(function.get("start")), str(function.get("end")))
        for function in baseline_functions
        if isinstance(function, dict)
    }
    indexed: dict[int, Mapping[str, object]] = {}
    observed: set[tuple[str, str]] = set()
    allowed_boundary = {"EXACT", "MISMATCH", "NOT_FOUND"}
    allowed_decomp = {"OK", "NOT_RUN", "FAILED"}
    for row in raw_functions:
        if not isinstance(row, dict):
            raise ProbeError("FAIL", "Ghidra function evidence must be an object")
        start, end = row.get("start"), row.get("end")
        key = (str(start), str(end))
        if key not in expected or key in observed:
            raise ProbeError("FAIL", "Ghidra evidence has an unknown or duplicate function interval")
        if row.get("boundary_status") not in allowed_boundary:
            raise ProbeError("FAIL", f"invalid Ghidra boundary status for {start}")
        if row.get("decomp_status") not in allowed_decomp:
            raise ProbeError("FAIL", f"invalid Ghidra decompilation status for {start}")
        if (row.get("boundary_status") == "EXACT") != (row.get("decomp_status") in ("OK", "FAILED")):
            raise ProbeError("FAIL", f"inconsistent Ghidra boundary/decompilation status for {start}")
        try:
            address = int(str(start), 16)
        except ValueError as exc:
            raise ProbeError("FAIL", f"invalid Ghidra function start {start!r}") from exc
        if row.get("boundary_status") == "EXACT":
            body_start, body_end = row.get("body_start"), row.get("body_end")
            body_addresses, body_ranges = row.get("body_addresses"), row.get("body_ranges")
            addressable_unit_size = row.get("addressable_unit_size")
            try:
                measured_start = int(str(body_start), 16)
                measured_end = int(str(body_end), 16)
                measured_addresses = int(str(body_addresses), 10)
                measured_ranges = int(str(body_ranges), 10)
                measured_unit_size = int(str(addressable_unit_size), 10)
                expected_start = int(str(start), 16)
                expected_end = int(str(end), 16)
            except (TypeError, ValueError) as exc:
                raise ProbeError("FAIL", f"exact Ghidra body evidence is incomplete for {start}") from exc
            if (
                isinstance(body_addresses, bool)
                or isinstance(body_ranges, bool)
                or isinstance(addressable_unit_size, bool)
                or measured_start != expected_start
                or measured_end != expected_end
                or measured_ranges != 1
                or measured_addresses != expected_end - expected_start
                or measured_unit_size != 1
            ):
                raise ProbeError("FAIL", f"exact Ghidra body evidence disagrees with interval {start}-{end}")
        indexed[address] = row
        observed.add(key)
    if observed != expected:
        raise ProbeError("FAIL", "Ghidra evidence does not cover every discovered interval")
    return indexed


def build_triage(
    baseline: Mapping[str, object], ghidra_report: object
) -> dict[str, object]:
    """Classify every interval and select the three lowest-risk supported candidates."""
    ghidra = validate_ghidra_evidence(ghidra_report, baseline)
    functions = baseline.get("functions")
    module = baseline.get("module")
    if not isinstance(functions, list) or not isinstance(module, dict):
        raise ProbeError("FAIL", "triage requires a complete baseline")

    function_starts = {int(str(row["start"]), 16) for row in functions if isinstance(row, dict)}
    candidates: list[tuple[tuple[int, int, int], dict[str, object]]] = []
    triage_rows: list[dict[str, object]] = []
    for function in functions:
        if not isinstance(function, dict):
            raise ProbeError("FAIL", "baseline function rows must be objects")
        start = int(str(function["start"]), 16)
        end = int(str(function["end"]), 16)
        ghidra_row = ghidra[start]
        calls = function["calls"]
        references = function["data_references"]
        if not isinstance(calls, list) or not isinstance(references, list):
            raise ProbeError("FAIL", f"baseline evidence is incomplete for {function['name']}")

        call_counts = Counter(str(call.get("kind")) for call in calls if isinstance(call, dict))
        unknown_calls = [call for call in calls if isinstance(call, dict) and call.get("kind") == "unknown"]
        missing_imports = [
            call
            for call in calls
            if isinstance(call, dict)
            and call.get("kind") == "import"
            and not isinstance(call.get("import"), dict)
        ]
        local_targets = [
            int(str(call["target"]), 16)
            for call in calls
            if isinstance(call, dict) and call.get("kind") == "local"
        ]
        non_entry_local_targets = sorted({target for target in local_targets if target not in function_starts})
        incoming = function["incoming_direct_local_calls"]
        resident_sites = function["resident_table_code_pointer_sites"]
        boundary = str(ghidra_row["boundary_status"])

        risks: list[str] = []
        if unknown_calls:
            risks.append(f"{len(unknown_calls)} call reference(s) are unresolved")
        if missing_imports:
            risks.append(f"{len(missing_imports)} import call(s) lack a recovered library/NID identity")
        if references:
            risks.append(
                f"{len(references)} static data reference(s); module-local locations do not prove "
                "cross-artifact object identity"
            )
        if non_entry_local_targets:
            risks.append(
                "local call target(s) are inside .text but not a discovered function start: "
                + ", ".join(f"0x{target:x}" for target in non_entry_local_targets)
            )
        if boundary == "MISMATCH":
            risks.append("Ghidra function body does not exactly tile this discovered interval")
        elif boundary == "NOT_FOUND":
            risks.append("Ghidra did not identify a function at this interval start")
            if incoming:
                risks.append(f"{len(incoming)} direct local call(s) still target this interval start")
            if resident_sites:
                risks.append(
                    "relocated .rodata.sceResident code pointer site(s): "
                    + ", ".join(resident_sites)
                )

        decision = "DEFERRED"
        justification: str
        eligible = (
            boundary == "EXACT"
            and not unknown_calls
            and not missing_imports
            and not references
            and not non_entry_local_targets
        )
        if boundary == "NOT_FOUND" and not incoming and not resident_sites:
            decision = "FRAGMENT"
            justification = (
                "No exact Ghidra function, direct local caller, or relocated .rodata.sceResident "
                "code pointer establishes a function identity; keep the code as an unclassified fragment."
            )
        elif eligible:
            candidates.append(
                ((function["instruction_count"], len(calls), start), function)
            )
            justification = (
                "Exact Ghidra boundary; all imports resolve by (library, NID), all local calls "
                "target discovered intervals, and there are no static data references or unresolved calls."
            )
        else:
            reasons = risks or ["function is structurally recoverable but has higher control-flow or size risk"]
            justification = "; ".join(reasons) + "."

        triage_rows.append(
            {
                "name": function["name"],
                "start": function["start"],
                "end": function["end"],
                "size_bytes": function["size_bytes"],
                "instruction_count": function["instruction_count"],
                "flow": function["flow"],
                "calls": calls,
                "call_counts": dict(call_counts),
                "imports": function["imports"],
                "data_references": references,
                "ghidra": {
                    "boundary_status": ghidra_row["boundary_status"],
                    "decomp_status": ghidra_row["decomp_status"],
                    "body_start": ghidra_row.get("body_start"),
                    "body_end": ghidra_row.get("body_end"),
                    "body_ranges": ghidra_row.get("body_ranges"),
                },
                "risks": risks,
                "decision": decision,
                "justification": justification,
            }
        )

    selected = {
        int(str(function["start"]), 16)
        for _rank, function in sorted(candidates, key=lambda item: item[0])[:MAX_SELECTED_FUNCTIONS]
    }
    for row in triage_rows:
        start = int(str(row["start"]), 16)
        if start in selected:
            row["decision"] = "SELECTED"
            row["selection_rank"] = next(
                index + 1
                for index, (_rank, function) in enumerate(sorted(candidates, key=lambda item: item[0]))
                if int(str(function["start"]), 16) == start
            )
        elif row["decision"] == "DEFERRED" and start in {
            int(str(function["start"]), 16) for _rank, function in candidates
        }:
            row["justification"] += (
                f" Eligible, but ranked after the {MAX_SELECTED_FUNCTIONS} lowest-complexity "
                "candidates selected for this round."
            )

    selected_rows = sorted(
        (row for row in triage_rows if row["decision"] == "SELECTED"),
        key=lambda row: int(row["selection_rank"]),
    )
    limitations: list[str] = [
        "Ghidra boundary JSON is local analyst evidence; its module SHA binding is consistency, not cryptographic authenticity"
    ]
    if len(selected_rows) < MAX_SELECTED_FUNCTIONS:
        limitations.append(
            f"Only {len(selected_rows)} candidates meet the strict selection criteria; do not fill the target with unsupported functions."
        )
    return {
        "schema_version": 1,
        "module": module,
        "selection_policy": {
            "maximum_selected": MAX_SELECTED_FUNCTIONS,
            "requirements": [
                "Ghidra confirms an exact function body interval",
                "no unresolved call references",
                "every import resolves to a recovered (library, NID)",
                "local calls target discovered function starts",
                "no static data references with unproven cross-artifact object identity",
            ],
            "ranking": ["instruction_count", "call_site_count", "start_address_tiebreak"],
            "preselected_address_list": False,
        },
        "function_count": len(triage_rows),
        "selected_count": len(selected_rows),
        "selected_functions": [
            {"name": row["name"], "start": row["start"], "end": row["end"], "instruction_count": row["instruction_count"]}
            for row in selected_rows
        ],
        "functions": triage_rows,
        "limitations": limitations,
    }


def validate_match_envelope(
    envelope: object,
    *,
    expected_module_sha256: str,
    expected_function: int,
    expected_total_words: int | None = None,
) -> dict[str, object]:
    """Validate an external match record without promoting any status."""
    if not isinstance(envelope, dict):
        raise ProbeError("FAIL", "match envelope must be an object")
    if envelope.get("module_sha256") != expected_module_sha256:
        raise ProbeError("FAIL", "match record belongs to another module SHA-256")
    record = envelope.get("record")
    saved = envelope.get("saved_record")
    if not isinstance(record, dict) or not isinstance(saved, dict):
        raise ProbeError("FAIL", "match envelope requires stdout and saved records")
    try:
        address = int(str(record.get("address")), 0)
    except ValueError as exc:
        raise ProbeError("FAIL", "match record has an invalid function address") from exc
    if address != expected_function or record.get("function") != mips.function_name(expected_function):
        raise ProbeError("FAIL", "match record belongs to another function")
    expected_name = mips.function_name(expected_function)
    if record.get("section") != ".text" or record.get("symbol") != expected_name:
        raise ProbeError("FAIL", "match record has the wrong section or candidate symbol")
    if record.get("evidence") != "compiled-object":
        raise ProbeError("FAIL", "match record lacks compiled-object evidence")
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        raise ProbeError("FAIL", "match record lacks provenance")
    if (
        provenance.get("source") != envelope.get("source_path")
        or provenance.get("object") != envelope.get("object_path")
    ):
        raise ProbeError("FAIL", "match record source/object paths differ from this fresh attempt")
    for key in ("source_sha256", "object_sha256"):
        expected_hash = envelope.get(key)
        if not _valid_sha256(expected_hash) or provenance.get(key) != expected_hash:
            raise ProbeError("FAIL", f"match record has an invalid {key}")
    if saved != {key: value for key, value in record.items() if key != "match"}:
        raise ProbeError("FAIL", "saved match report differs from the fresh stdout record")
    match_payload = record.get("match")
    if not isinstance(match_payload, dict) or match_payload.get("status") != record.get("status"):
        raise ProbeError("FAIL", "match record status disagrees with comparator evidence")
    if (
        match_payload.get("name") != expected_name
        or match_payload.get("address") != expected_function
        or match_payload.get("equivalence") != record.get("equivalence")
    ):
        raise ProbeError("FAIL", "comparator evidence has the wrong function identity")
    status = record.get("status")
    exit_code = record.get("exit_code")
    expected_exit = {"MATCHED": 0, "NONMATCHING": 3, "INCONCLUSIVE": 5}
    if (
        not isinstance(status, str)
        or status not in expected_exit
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or exit_code != expected_exit[status]
    ):
        raise ProbeError("FAIL", "match record has an invalid status/exit-code pair")
    total_words = match_payload.get("total_words")
    matching_words = match_payload.get("matching_words")
    difference_count = match_payload.get("difference_count")
    differences = match_payload.get("differences")
    relocation_issues = match_payload.get("relocation_issues")
    limitations = match_payload.get("limitations")
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (total_words, matching_words, difference_count)
    ) or not isinstance(differences, list) or not isinstance(relocation_issues, list) or not isinstance(limitations, list):
        raise ProbeError("FAIL", "match record has incomplete word-comparison counts")
    if (
        total_words <= 0
        or not 0 <= matching_words <= total_words
        or difference_count < 0
        or matching_words + difference_count > total_words
        or len(differences) > difference_count
    ):
        raise ProbeError("FAIL", "match record has invalid counts or too many difference details")
    if any(not isinstance(item, dict) for item in differences):
        raise ProbeError("FAIL", "match record has malformed difference details")
    if any(not isinstance(item, str) or not item for item in (*relocation_issues, *limitations)):
        raise ProbeError("FAIL", "match record has malformed relocation issues or limitations")
    if expected_total_words is not None and total_words != expected_total_words:
        raise ProbeError("FAIL", "match record word total disagrees with the selected interval")
    equivalence = record.get("equivalence")
    if match_payload.get("equivalence") != equivalence:
        raise ProbeError("FAIL", "match record equivalence disagrees with comparator evidence")
    if status == "MATCHED" and (
        matching_words != total_words
        or difference_count != 0
        or differences
        or relocation_issues
        or limitations
        or equivalence
        not in (matching.EQUIVALENCE_BINARY, matching.EQUIVALENCE_RESOLVED_RELOCATIONS)
    ):
        raise ProbeError(
            "FAIL", "MATCHED report lacks full-word equality, a valid equivalence claim, or clean evidence"
        )
    if status != "MATCHED" and equivalence != "":
        raise ProbeError("FAIL", "non-MATCHED report must not carry an equivalence claim")
    if status == "INCONCLUSIVE" and (
        difference_count != 0 or differences or relocation_issues or not limitations
    ):
        raise ProbeError("FAIL", "INCONCLUSIVE report is inconsistent with matcher limitations")
    if status == "NONMATCHING" and difference_count == 0 and not relocation_issues:
        raise ProbeError("FAIL", "NONMATCHING report lacks a proven difference or comparison issue")
    if record.get("verified_decompilation") is not (status == "MATCHED"):
        raise ProbeError("FAIL", "match record promotion flag disagrees with strict matcher status")
    return {
        "module_sha256": expected_module_sha256,
        "function": mips.function_name(expected_function),
        "address": f"0x{expected_function:x}",
        "status": status,
        "exit_code": exit_code,
        "source_sha256": envelope["source_sha256"],
        "object_sha256": envelope["object_sha256"],
        "matching_words": match_payload.get("matching_words"),
        "total_words": match_payload.get("total_words"),
        "difference_count": difference_count,
        "differences": differences,
        "relocation_issues": match_payload.get("relocation_issues"),
        "limitations": match_payload.get("limitations"),
        "resolved_calls": match_payload.get("resolved_calls"),
        "resolved_data": match_payload.get("resolved_data"),
        "equivalence": record.get("equivalence"),
        "verified_decompilation": record.get("verified_decompilation"),
    }


def _prepare_fresh_match_outputs(paths: Sequence[Path], build_root: Path) -> None:
    """Reject unsafe object/report destinations before removing stale regular files."""
    for path in paths:
        prepare_build_file(path, build_root)
    for path in paths:
        path.unlink(missing_ok=True)


def run_real_match(
    function_address: int,
    source_value: Path,
    *,
    attempt: int,
    expected_total_words: int,
    config_value: Path = Path("config/wsl/seto.toml"),
    repo_root: Path = REPO_ROOT,
    build_subdir: str = "seto018",
) -> dict[str, object]:
    """Run one fresh, guarded match_function.py attempt and validate its provenance."""
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise ProbeError("FAIL", "match attempt number must be a positive integer")
    if (
        isinstance(expected_total_words, bool)
        or not isinstance(expected_total_words, int)
        or expected_total_words <= 0
    ):
        raise ProbeError("FAIL", "selected function word total must be positive")
    if not re.fullmatch(r"seto\d{3}", build_subdir):
        raise ProbeError("FAIL", "match build subdirectory must be a setoNNN name")
    build_root = validated_build_root(repo_root, subdir=build_subdir)
    prx_input = repo_root / MODULE_RELATIVE
    _reject_repo_symlink_components(prx_input, repo_root, "original PRX")
    prx_path = repo_path(
        prx_input,
        repo_root=repo_root,
        allowed_root=(repo_root / "private").resolve(),
    )
    module_sha = sha256_file(prx_path)
    verify_module_sha256(module_sha)

    source_input = source_value if source_value.is_absolute() else repo_root / source_value
    _reject_repo_symlink_components(source_input, repo_root, "candidate source")
    source_path = repo_path(
        source_input,
        repo_root=repo_root,
        allowed_root=(repo_root / "decomp" / "src" / "libtutoriallist").resolve(),
    )
    if not source_path.is_file():
        raise ProbeError("BLOCKED", f"selected source does not exist: {source_path.name}")
    if source_path.stem != mips.function_name(function_address):
        raise ProbeError("FAIL", "selected source name disagrees with the function address")
    config_input = config_value if config_value.is_absolute() else repo_root / config_value
    _reject_repo_symlink_components(config_input, repo_root, "toolchain configuration")
    config_path = repo_path(
        config_input, repo_root=repo_root, allowed_root=(repo_root / "config").resolve()
    )
    if not config_path.is_file():
        raise ProbeError("BLOCKED", "WSL toolchain configuration is unavailable")

    ensure_build_dir(build_root, build_root)
    matches_dir = build_root / "matches"
    function_dir = matches_dir / f"f{function_address:x}"
    attempt_dir = function_dir / f"attempt-{attempt}"
    for directory in (matches_dir, function_dir, attempt_dir):
        ensure_build_dir(directory, build_root)
    object_path = attempt_dir / f"{source_path.stem}.o"
    report_path = attempt_dir / f"{source_path.name}.match.json"
    _prepare_fresh_match_outputs((object_path, report_path), build_root)

    source_sha_before = sha256_file(source_path)
    match_argv = [
        sys.executable,
        "scripts/match_function.py",
        "--config",
        relative(config_path, repo_root),
        "--prx",
        relative(prx_path, repo_root),
        "--function",
        hex(function_address),
        "--source",
        relative(source_path, repo_root),
        "--out",
        relative(attempt_dir, repo_root),
        "--report",
        relative(report_path, repo_root),
        "--json",
    ]
    result = run_tool(match_argv, cwd=repo_root, timeout=600)
    write_build_text(attempt_dir / "match.stdout.json", result.stdout, build_root)
    write_build_text(attempt_dir / "match.stderr.txt", result.stderr, build_root)
    if result.timed_out or result.returncode is None:
        raise ProbeError("FAIL", f"match_function timed out or failed to launch for {source_path.name}")
    if result.returncode == 4:
        raise ProbeError("BLOCKED", f"match_function prerequisites unavailable for {source_path.name}")
    if result.returncode == 1:
        prepare_build_file(object_path, build_root)
        prepare_build_file(report_path, build_root)
        if sha256_file(source_path) != source_sha_before or sha256_file(prx_path) != module_sha:
            raise ProbeError("FAIL", "source or original PRX changed during failed matching")
        object_sha = sha256_file(object_path) if object_path.is_file() else None
        final_error = next(
            (line.strip() for line in reversed(result.stderr.splitlines()) if line.strip()),
            "match_function returned an error without a diagnostic",
        )
        phase = "compare" if object_sha is not None and "comparing:" in result.stderr else "compile"
        return {
            "module_sha256": module_sha,
            "function": mips.function_name(function_address),
            "address": f"0x{function_address:x}",
            "status": "ERROR",
            "phase": phase,
            "exit_code": result.returncode,
            "source_sha256": source_sha_before,
            "object_sha256": object_sha,
            "report_written": report_path.is_file(),
            "error": final_error,
        }
    if result.returncode not in (0, 3, 5):
        raise ProbeError("FAIL", f"match_function exited {result.returncode} for {source_path.name}")
    prepare_build_file(object_path, build_root)
    prepare_build_file(report_path, build_root)
    if not object_path.is_file() or not report_path.is_file():
        raise ProbeError("FAIL", f"match_function did not produce fresh outputs for {source_path.name}")
    try:
        record = json.loads(result.stdout)
        saved_record = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ProbeError("FAIL", f"match_function emitted an invalid report for {source_path.name}") from exc
    if not isinstance(record, dict) or not isinstance(saved_record, dict):
        raise ProbeError("FAIL", f"match_function report is not an object for {source_path.name}")
    validate_saved_match_record(record, saved_record)

    source_sha_after = sha256_file(source_path)
    object_sha = sha256_file(object_path)
    if source_sha_before != source_sha_after:
        raise ProbeError("FAIL", f"candidate source changed during matching: {source_path.name}")
    if sha256_file(prx_path) != module_sha:
        raise ProbeError("FAIL", "original PRX changed during matching")

    envelope = {
        "module_sha256": module_sha,
        "source_path": relative(source_path, repo_root),
        "object_path": relative(object_path, repo_root),
        "source_sha256": source_sha_after,
        "object_sha256": object_sha,
        "record": record,
        "saved_record": saved_record,
    }
    return validate_match_envelope(
        envelope,
        expected_module_sha256=EXPECTED_MODULE_SHA256,
        expected_function=function_address,
        expected_total_words=expected_total_words,
    )


def write_reports(
    baseline: Mapping[str, object], triage: Mapping[str, object], *, repo_root: Path = REPO_ROOT
) -> tuple[Path, Path]:
    """Write only the two canonical reports under the guarded build/seto018 root."""
    build_root = validated_build_root(repo_root, subdir="seto018")
    ensure_build_dir(build_root, build_root)
    baseline_path = build_root / "baseline.json"
    triage_path = build_root / "triage.json"
    prepare_build_file(baseline_path, build_root)
    prepare_build_file(triage_path, build_root)
    write_build_text(baseline_path, canonical_json(baseline), build_root)
    write_build_text(triage_path, canonical_json(triage), build_root)
    return baseline_path, triage_path


def write_baseline_report(
    baseline: Mapping[str, object], *, repo_root: Path = REPO_ROOT
) -> Path:
    """Write the structural baseline without needing any Ghidra evidence."""
    build_root = validated_build_root(repo_root, subdir="seto018")
    ensure_build_dir(build_root, build_root)
    output = build_root / "baseline.json"
    write_build_text(output, canonical_json(baseline), build_root)
    return output


def parse_ghidra_output(log_text: str, baseline: Mapping[str, object]) -> dict[str, object]:
    """Extract SetoAnalyzeFunction markers into a hash-bound, path-free report.

    This parses the output protocol of the existing read-only Ghidra script; it
    does not parse MIPS instructions or infer function boundaries itself.
    """
    module = baseline.get("module")
    if not isinstance(module, dict) or not _valid_sha256(module.get("sha256")):
        raise ProbeError("FAIL", "baseline lacks a valid module hash for Ghidra evidence")
    records: list[dict[str, object]] = []
    metadata: dict[str, str] = {}
    current: dict[str, object] | None = None
    fields = {
        "GHIDRA_FUNCTION": "ghidra_function",
        "FUNCTION_BODY_START": "body_start",
        "FUNCTION_BODY_END": "body_end",
        "FUNCTION_BODY_ADDRESSES": "body_addresses",
        "FUNCTION_BODY_RANGES": "body_ranges",
        "ADDRESSABLE_UNIT_SIZE": "addressable_unit_size",
        "BOUNDARY_STATUS": "boundary_status",
        "DECOMP_STATUS": "decomp_status",
    }
    for line in log_text.splitlines():
        marker = GHIDRA_MARKER_RE.search(line)
        if marker is None:
            continue
        key, value = marker.group(1), marker.group(2).strip()
        if key == "ERROR":
            raise ProbeError("FAIL", f"Ghidra reported an error: {value}")
        if key in ("LANGUAGE", "COMPILER_SPEC", "IMAGE_BASE"):
            previous = metadata.setdefault(key.lower(), value)
            if previous != value:
                raise ProbeError("FAIL", f"Ghidra {key.lower()} changed within one scan")
            continue
        if key == "FUNCTION_START":
            if current is not None:
                records.append(current)
            current = {"start": value}
            continue
        if key == "FUNCTION_END":
            if current is None or "end" in current:
                raise ProbeError("FAIL", "Ghidra emitted an end marker before a function start")
            current["end"] = value
            continue
        field = fields.get(key)
        if field is not None:
            if current is None or field in current:
                raise ProbeError("FAIL", f"Ghidra emitted {key} before a function start")
            current[field] = value
    if current is not None:
        records.append(current)
    if not records:
        raise ProbeError("FAIL", "Ghidra output contains no SetoAnalyzeFunction records")
    if not all(key in metadata for key in ("language", "compiler_spec", "image_base")):
        raise ProbeError("FAIL", "Ghidra output is missing language/compiler/image-base metadata")

    normalized: list[dict[str, object]] = []
    for record in records:
        try:
            start = int(str(record["start"]), 0)
            end = int(str(record["end"]), 0)
        except (KeyError, ValueError) as exc:
            raise ProbeError("FAIL", "Ghidra output contains an invalid function interval") from exc
        row: dict[str, object] = {
            "start": f"0x{start:x}",
            "end": f"0x{end:x}",
            "boundary_status": record.get("boundary_status"),
            "decomp_status": record.get("decomp_status"),
        }
        if "ghidra_function" in record:
            row["ghidra_function"] = record["ghidra_function"]
        try:
            if "body_start" in record:
                row["body_start"] = f"0x{int(str(record['body_start']), 16):x}"
            if "body_end" in record:
                row["body_end"] = f"0x{int(str(record['body_end']), 16):x}"
            if "body_addresses" in record:
                row["body_addresses"] = int(str(record["body_addresses"]), 10)
            if "body_ranges" in record:
                row["body_ranges"] = int(str(record["body_ranges"]), 10)
            if "addressable_unit_size" in record:
                row["addressable_unit_size"] = int(str(record["addressable_unit_size"]), 10)
        except ValueError as exc:
            raise ProbeError("FAIL", f"invalid Ghidra body measurement for 0x{start:x}") from exc
        normalized.append(row)

    normalized.sort(key=lambda row: int(str(row["start"]), 16))
    return {
        "schema_version": 1,
        "module_name": module.get("name"),
        "module_path": module.get("path"),
        "module_sha256": module["sha256"],
        "analyzer": {
            "name": "Ghidra",
            "language": metadata["language"],
            "compiler_spec": metadata["compiler_spec"],
            "image_base": metadata["image_base"],
        },
        "functions": normalized,
    }


def _load_ghidra_report(path: Path, build_root: Path) -> dict[str, object]:
    prepare_build_file(path, build_root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError("FAIL", f"cannot read Ghidra evidence report: {exc}") from exc
    if not isinstance(value, dict):
        raise ProbeError("FAIL", "Ghidra evidence report must be a JSON object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage_libtutoriallist")
    parser.add_argument("--prx", type=Path, default=MODULE_RELATIVE)
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="write baseline.json from the pinned PRX without requiring Ghidra output",
    )
    parser.add_argument(
        "--ghidra-log",
        type=Path,
        default=None,
        help="parse SetoAnalyzeFunction.java markers from a log under build/seto018/",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        build_root = validated_build_root(REPO_ROOT, subdir="seto018")
        prx_input = arguments.prx if arguments.prx.is_absolute() else REPO_ROOT / arguments.prx
        _reject_repo_symlink_components(prx_input, REPO_ROOT, "original PRX")
        prx_path = repo_path(
            prx_input,
            repo_root=REPO_ROOT,
            allowed_root=(REPO_ROOT / "private").resolve(),
        )
        actual_sha256 = sha256_file(prx_path)
        verify_module_sha256(actual_sha256)
        module = elf.parse(prx_path)
        baseline = build_baseline(module, actual_sha256)
        baseline_path = write_baseline_report(baseline, repo_root=REPO_ROOT)
        if arguments.baseline_only:
            print(f"{baseline_path.relative_to(REPO_ROOT).as_posix()}: {len(baseline['functions'])} intervals")
            return 0

        if arguments.ghidra_log is not None:
            log_input = (
                arguments.ghidra_log
                if arguments.ghidra_log.is_absolute()
                else REPO_ROOT / arguments.ghidra_log
            )
            _reject_repo_symlink_components(log_input, REPO_ROOT, "Ghidra output log")
            log_path = repo_path(log_input, repo_root=REPO_ROOT, allowed_root=build_root)
            prepare_build_file(log_path, build_root)
            try:
                log_text = log_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise ProbeError("FAIL", f"cannot read Ghidra output log: {exc}") from exc
            ghidra_report = parse_ghidra_output(log_text, baseline)
            validate_ghidra_evidence(ghidra_report, baseline)
            write_build_text(
                build_root / GHIDRA_EVIDENCE_NAME,
                canonical_json(ghidra_report),
                build_root,
            )
        else:
            ghidra_report = _load_ghidra_report(build_root / GHIDRA_EVIDENCE_NAME, build_root)
        triage = build_triage(baseline, ghidra_report)
        baseline_path, triage_path = write_reports(baseline, triage, repo_root=REPO_ROOT)
    except (ProbeError, elf.ParseError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"{baseline_path.relative_to(REPO_ROOT).as_posix()}: {len(baseline['functions'])} intervals; "
        f"{triage_path.relative_to(REPO_ROOT).as_posix()}: {triage['selected_count']} selected"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
