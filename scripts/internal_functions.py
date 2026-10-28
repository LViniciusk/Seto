"""Small evidence catalog for non-export EBOOT/PRX functions.

Internal functions deliberately stay outside the export campaign SQLite schema:
their stable identity is (module, address), and they do not have fabricated NIDs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence


_BOUNDARY_STATES = {"EXACT", "UNVERIFIED", "MISMATCH", "NOT_FOUND"}
_RESULT_STATES = {
    "MATCHED",
    "NONMATCHING",
    "INCOMPLETE",
    "UNMATCHED",
    "BLOCKED_CALLING_CONVENTION",
    "BOUNDARY_VERIFIED_NO_SOURCE",
    "INCONCLUSIVE_IDENTITY",
}
_ADDRESS = re.compile(r"0[xX][0-9a-fA-F]{1,8}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MODULE_SECTIONS: dict[str, tuple[tuple[str, int, int], ...]] = {
    "eboot": ((".text", 0x0, 0x6AD2C), (".sceStub.text", 0x6AD2C, 0x6B5BC)),
    "libtutoriallist.prx": ((".text", 0x0, 0x25B0), (".sceStub.text", 0x25B0, 0x4C98)),
    "libhtml_view.prx": ((".text", 0x0, 0x7F4), (".sceStub.text", 0x7F4, 0x2F94)),
}


@dataclass(frozen=True)
class InternalFunction:
    module: str
    address: int
    size_bytes: int
    boundary_status: str
    evidence_path: str
    kind: str = "code"
    section: str = ".text"
    priority: int = 0


@dataclass(frozen=True)
class DiscoveredFunction:
    module: str
    address: int
    size_bytes: int
    instruction_count: int
    calls: tuple[int, ...]
    data_reference_count: int
    boundary_hint: str


@dataclass(frozen=True)
class FunctionManifest:
    module: str
    total_functions: int
    limit: int
    truncated: bool
    functions: tuple[DiscoveredFunction, ...]


def internal_function_key(function: InternalFunction) -> tuple[str, int]:
    """Return the collision-safe identity for a function outside export tables."""
    return function.module.casefold(), function.address


def _section_for_range(module: str, address: int, size_bytes: int) -> str | None:
    """Return the source ELF section only when the whole range belongs to it."""
    sections = _MODULE_SECTIONS.get(module.casefold())
    if sections is None:
        return None
    for section, start, end in sections:
        if start <= address < end and address + size_bytes <= end:
            return section
    return None


def _kind_for_section(section: str) -> str:
    return "import_stub" if section == ".sceStub.text" else "code"


def _expected_source_path(module: str, address: int) -> str | None:
    directories = {
        "eboot": "eboot",
        "libtutoriallist.prx": "libtutoriallist",
        "libhtml_view.prx": "libhtml_view",
    }
    directory = directories.get(module.casefold())
    if directory is None:
        return None
    return f"decomp/src/{directory}/func_{address:08X}.c"


def internal_reference_evidence_is_resolved(report: Mapping[str, Any]) -> bool:
    match = report.get("match")
    if not isinstance(match, Mapping):
        return False
    for field in ("resolved_calls", "resolved_data"):
        references = match.get(field)
        if not isinstance(references, list) or any(
            "unresolved" in str(reference).casefold()
            or "unknown" in str(reference).casefold()
            for reference in references
        ):
            return False
    return True


def counts_as_decompiled_code(entry: Mapping[str, Any]) -> bool:
    """Use module layout, not a caller-controlled kind label, for real coverage."""
    result = entry.get("result")
    if not isinstance(result, Mapping) or result.get("status") != "MATCHED":
        return False
    module = entry.get("module")
    address_value = entry.get("address")
    size_bytes = entry.get("size_bytes")
    if (
        not isinstance(module, str)
        or not isinstance(address_value, str)
        or not _ADDRESS.fullmatch(address_value)
        or isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or size_bytes <= 0
    ):
        return False
    section = _section_for_range(module, int(address_value, 16), size_bytes)
    return (
        section == ".text"
        and entry.get("section") == section
        and entry.get("kind") == "code"
        and result.get("section", section) == section
    )


def internal_catalog_metrics(
    entries: Iterable[Mapping[str, Any]],
    export_metrics: Mapping[str, int] | None = None,
) -> dict[str, int]:
    """Return centralized real-code, import-stub, and technical coverage totals."""
    code_functions = code_instructions = stub_functions = stub_instructions = 0
    for entry in entries:
        result = entry.get("result")
        if not isinstance(result, Mapping) or result.get("status") != "MATCHED":
            continue
        module = entry.get("module")
        address_value = entry.get("address")
        size_bytes = entry.get("size_bytes")
        if (
            not isinstance(module, str)
            or not isinstance(address_value, str)
            or not _ADDRESS.fullmatch(address_value)
            or isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
        ):
            continue
        section = _section_for_range(module, int(address_value, 16), size_bytes)
        if section is None or entry.get("section") != section:
            continue
        expected_kind = _kind_for_section(section)
        if entry.get("kind") != expected_kind:
            continue
        instructions = entry.get("instruction_count", size_bytes // 4)
        if isinstance(instructions, bool) or not isinstance(instructions, int):
            continue
        if instructions != size_bytes // 4:
            continue
        if section == ".text":
            code_functions += 1
            code_instructions += instructions
        else:
            stub_functions += 1
            stub_instructions += instructions

    exports = export_metrics or {}
    export_functions = int(exports.get("eboot_matched_functions", 0)) + int(
        exports.get("prx_matched_functions", 0)
    )
    export_instructions = int(exports.get("eboot_matched_instructions", 0)) + int(
        exports.get("prx_matched_instructions", 0)
    )
    real_functions = code_functions + export_functions
    real_instructions = code_instructions + export_instructions
    return {
        "code_matched_functions": real_functions,
        "code_matched_instructions": real_instructions,
        "import_stub_matched_functions": stub_functions,
        "import_stub_matched_instructions": stub_instructions,
        "technical_matched_functions": real_functions + stub_functions,
        "technical_matched_instructions": real_instructions + stub_instructions,
    }


def parse_ghidra_enumeration(output: str) -> FunctionManifest:
    """Parse and validate the bounded JSON-lines emitted by SetoEnumerateFunctions."""
    begin: tuple[str, int, int] | None = None
    end: tuple[str, int, int, bool] | None = None
    functions: list[DiscoveredFunction] = []
    seen: set[tuple[str, int]] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        for marker in (
            "SETO_ENUMERATION_BEGIN ",
            "SETO_ENUMERATION_END ",
            "SETO_FUNCTION_JSON=",
            "SETO_ERROR=",
        ):
            marker_index = line.find(marker)
            if marker_index >= 0:
                line = line[marker_index:].split(" (GhidraScript)", 1)[0].strip()
                break
        if line.startswith("SETO_ENUMERATION_BEGIN "):
            if begin is not None:
                raise ValueError("Ghidra enumeration has multiple begin markers")
            match = re.fullmatch(
                r"SETO_ENUMERATION_BEGIN module=(\S+) total=(\d+) limit=(\d+)", line
            )
            if match is None:
                raise ValueError("Ghidra enumeration begin marker is malformed")
            begin = (match.group(1), int(match.group(2)), int(match.group(3)))
            continue
        if line.startswith("SETO_ENUMERATION_END "):
            if end is not None:
                raise ValueError("Ghidra enumeration has multiple end markers")
            match = re.fullmatch(
                r"SETO_ENUMERATION_END module=(\S+) emitted=(\d+) total=(\d+) truncated=(true|false)",
                line,
            )
            if match is None:
                raise ValueError("Ghidra enumeration end marker is malformed")
            end = (
                match.group(1),
                int(match.group(2)),
                int(match.group(3)),
                match.group(4) == "true",
            )
            continue
        if line.startswith("SETO_ERROR="):
            raise ValueError(f"Ghidra enumeration failed: {line.removeprefix('SETO_ERROR=')}")
        if not line.startswith("SETO_FUNCTION_JSON="):
            continue
        try:
            record = json.loads(line.removeprefix("SETO_FUNCTION_JSON="))
        except json.JSONDecodeError as exc:
            raise ValueError("Ghidra enumeration contains invalid function JSON") from exc
        if not isinstance(record, dict):
            raise ValueError("Ghidra function record must be an object")
        module = record.get("module")
        address_text = record.get("address")
        size_bytes = record.get("size_bytes")
        instruction_count = record.get("instruction_count")
        calls = record.get("calls")
        data_reference_count = record.get("data_reference_count")
        boundary_hint = record.get("boundary_hint")
        if not isinstance(module, str) or not module.strip():
            raise ValueError("Ghidra function record has no module identity")
        if not isinstance(address_text, str) or not _ADDRESS.fullmatch(address_text):
            raise ValueError("Ghidra function record has an invalid address")
        address = int(address_text, 16)
        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
            or size_bytes % 4
            or isinstance(instruction_count, bool)
            or not isinstance(instruction_count, int)
            or instruction_count <= 0
            or isinstance(data_reference_count, bool)
            or not isinstance(data_reference_count, int)
            or data_reference_count < 0
        ):
            raise ValueError("Ghidra function size/count fields are invalid")
        if address + size_bytes > 0x1_0000_0000:
            raise ValueError("Ghidra function range exceeds the 32-bit address space")
        if boundary_hint not in {"CONTIGUOUS", "MULTIRANGE_OR_GAPPED"}:
            raise ValueError("Ghidra function boundary_hint is invalid")
        if boundary_hint == "CONTIGUOUS" and instruction_count != size_bytes // 4:
            raise ValueError("contiguous Ghidra function size disagrees with its instruction count")
        if not isinstance(calls, list) or any(
            not isinstance(call, str) or not _ADDRESS.fullmatch(call) for call in calls
        ):
            raise ValueError("Ghidra function call targets are invalid")
        key = (module.casefold(), address)
        if key in seen:
            raise ValueError(f"duplicate Ghidra function identity: {module}@{address_text}")
        seen.add(key)
        functions.append(
            DiscoveredFunction(
                module=module.strip(),
                address=address,
                size_bytes=size_bytes,
                instruction_count=instruction_count,
                calls=tuple(sorted({int(call, 16) for call in calls})),
                data_reference_count=data_reference_count,
                boundary_hint=boundary_hint,
            )
        )

    if begin is None or end is None:
        raise ValueError("Ghidra enumeration is missing begin/end markers")
    module, total, limit = begin
    end_module, emitted, end_total, truncated = end
    if module != end_module or total != end_total:
        raise ValueError("Ghidra enumeration markers disagree about module or total")
    if limit < 1 or limit > 4096 or emitted != len(functions) or emitted > limit or total < emitted:
        raise ValueError("Ghidra enumeration counts exceed the declared bound")
    if truncated != (emitted < total):
        raise ValueError("Ghidra enumeration truncation marker is inconsistent")
    if any(function.module != module for function in functions):
        raise ValueError("Ghidra enumeration contains a function from another module")
    if functions != sorted(functions, key=lambda item: item.address):
        raise ValueError("Ghidra enumeration is not in deterministic address order")
    contiguous = [item for item in functions if item.boundary_hint == "CONTIGUOUS"]
    for previous, current in zip(contiguous, contiguous[1:]):
        if current.address < previous.address + previous.size_bytes:
            raise ValueError("Ghidra enumeration contains overlapping contiguous function ranges")
    return FunctionManifest(module, total, limit, truncated, tuple(functions))


def serialize_function_manifest(manifest: FunctionManifest) -> str:
    """Return canonical JSON for a local, non-authoritative discovery snapshot."""
    document = {
        "schema_version": 1,
        "module": manifest.module,
        "total_functions": manifest.total_functions,
        "limit": manifest.limit,
        "truncated": manifest.truncated,
        "functions": [
            {
                "module": item.module,
                "address": f"0x{item.address:x}",
                "size_bytes": item.size_bytes,
                "instruction_count": item.instruction_count,
                "calls": [f"0x{call:x}" for call in item.calls],
                "data_reference_count": item.data_reference_count,
                "boundary_hint": item.boundary_hint,
            }
            for item in manifest.functions
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def load_function_manifest(path: Path) -> FunctionManifest:
    """Read a previously captured manifest and re-run the same schema checks."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"function manifest is unreadable: {path}") from exc
    schema_version = document.get("schema_version") if isinstance(document, dict) else None
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("function manifest schema_version must be 1")
    module = document.get("module")
    total = document.get("total_functions")
    limit = document.get("limit")
    truncated = document.get("truncated")
    functions = document.get("functions")
    if (
        not isinstance(module, str)
        or isinstance(total, bool)
        or not isinstance(total, int)
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not isinstance(truncated, bool)
        or not isinstance(functions, list)
    ):
        raise ValueError("function manifest metadata is malformed")
    lines = [f"SETO_ENUMERATION_BEGIN module={module} total={total} limit={limit}"]
    lines.extend("SETO_FUNCTION_JSON=" + json.dumps(item) for item in functions)
    lines.append(
        f"SETO_ENUMERATION_END module={module} emitted={len(functions)} "
        f"total={total} truncated={str(truncated).lower()}"
    )
    return parse_ghidra_enumeration("\n".join(lines))


def write_function_manifest(path: Path, manifest: FunctionManifest) -> str:
    """Persist a deterministic discovery snapshot without overwriting conflicts."""
    content = serialize_function_manifest(manifest)
    cursor = path
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("function manifest destination contains a symlink")
        cursor = cursor.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ValueError("refusing to overwrite a different Ghidra function manifest")
    else:
        try:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
        except FileExistsError as exc:
            raise ValueError("function manifest appeared during persistence") from exc
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def select_internal_discoveries(
    manifest: FunctionManifest,
    *,
    known_exports: Iterable[tuple[str, int]],
    known_internal: Iterable[InternalFunction],
    calls_from_matched_exports: Iterable[tuple[str, int]],
    evidence_path: str,
    limit: int = 64,
    module_address_range: tuple[int, int] | None = None,
    known_exact_ranges: Iterable[tuple[str, int, int]] = (),
) -> tuple[InternalFunction, ...]:
    """Rank Ghidra discovery hints without claiming they are exact boundaries."""
    if limit <= 0:
        raise ValueError("internal discovery selection limit must be positive")
    if module_address_range is not None and module_address_range[1] <= module_address_range[0]:
        raise ValueError("internal discovery module address range is invalid")
    evidence = PurePosixPath(evidence_path.replace("\\", "/"))
    if evidence.is_absolute() or ".." in evidence.parts:
        raise ValueError("internal discovery evidence path escapes the repository")
    export_keys = {(module.casefold(), address) for module, address in known_exports}
    export_ranges = tuple(
        (module.casefold(), address, size_bytes)
        for module, address, size_bytes in known_exact_ranges
        if size_bytes > 0
    )
    internal = tuple(known_internal)
    internal_keys = {internal_function_key(item) for item in internal}
    called_keys = {(module.casefold(), address) for module, address in calls_from_matched_exports}

    selected: list[tuple[tuple[int, int, int, int, str, int], InternalFunction]] = []
    for discovered in manifest.functions:
        key = (discovered.module.casefold(), discovered.address)
        if module_address_range is not None:
            start, end = module_address_range
            if discovered.address < start or discovered.address + discovered.size_bytes > end:
                continue
        if key in export_keys or key in internal_keys:
            continue
        if discovered.boundary_hint != "CONTIGUOUS":
            continue
        end = discovered.address + discovered.size_bytes
        overlaps_known = any(
            item.module.casefold() == key[0]
            and item.boundary_status == "EXACT"
            and discovered.address < item.address + item.size_bytes
            and item.address < end
            for item in internal
        )
        overlaps_known = overlaps_known or any(
            module == key[0]
            and discovered.address < start + size_bytes
            and start < end
            for module, start, size_bytes in export_ranges
        )
        if overlaps_known:
            continue
        function = InternalFunction(
            module=discovered.module,
            address=discovered.address,
            size_bytes=discovered.size_bytes,
            # Enumeration is a hint only; the normal address-specific script
            # must independently prove EXACT before source matching.
            boundary_status="UNVERIFIED",
            evidence_path=evidence.as_posix(),
        )
        simple_rank = 0 if 3 <= discovered.instruction_count <= 60 else 1
        called_rank = 0 if key in called_keys else 1
        selected.append(
            (
                (
                    called_rank,
                    simple_rank,
                    discovered.data_reference_count,
                    discovered.instruction_count,
                    key[0],
                    discovered.address,
                ),
                function,
            )
        )
    selected.sort(key=lambda item: item[0])
    ranked = selected[:limit]
    return tuple(
        replace(function, priority=len(ranked) - index)
        for index, (_, function) in enumerate(ranked)
    )


def load_internal_catalog(path: Path) -> tuple[InternalFunction, ...]:
    """Load, normalize, and validate a deterministic internal-function catalog."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"internal function catalog is unreadable: {path}") from exc
    schema_version = document.get("schema_version") if isinstance(document, dict) else None
    if isinstance(schema_version, bool) or schema_version != 2:
        raise ValueError("internal function catalog schema_version must be 2")
    entries = document.get("functions")
    if not isinstance(entries, list):
        raise ValueError("internal function catalog functions must be a list")

    functions: list[InternalFunction] = []
    seen: set[tuple[str, int]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"internal function entry {index} must be an object")
        if "nid" in entry:
            raise ValueError("internal function entries must not contain an NID")
        module = entry.get("module")
        address_value = entry.get("address")
        size_bytes = entry.get("size_bytes")
        boundary_status = entry.get("boundary_status")
        evidence_path = entry.get("evidence_path")
        section = entry.get("section")
        kind = entry.get("kind")
        if not isinstance(module, str) or not module.strip():
            raise ValueError(f"internal function entry {index} has no module")
        if not isinstance(address_value, str) or not _ADDRESS.fullmatch(address_value):
            raise ValueError(f"internal function entry {index} has an invalid address")
        address = int(address_value, 16)
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            raise ValueError(f"internal function entry {index} has an invalid size")
        if not isinstance(boundary_status, str) or boundary_status not in _BOUNDARY_STATES:
            raise ValueError(f"internal function entry {index} has an invalid boundary_status")
        if boundary_status == "EXACT" and (size_bytes <= 0 or size_bytes % 4):
            raise ValueError("EXACT internal function size must be a positive multiple of four")
        if size_bytes and size_bytes % 4:
            raise ValueError(f"internal function entry {index} size is not word-aligned")
        if address % 4:
            raise ValueError(f"internal function entry {index} address is not word-aligned")
        if not isinstance(section, str) or not isinstance(kind, str):
            raise ValueError(f"internal function entry {index} requires explicit section and kind")
        expected_section = _section_for_range(module, address, size_bytes)
        if expected_section is None:
            raise ValueError(
                f"internal function entry {index} range is outside a supported module section"
            )
        if section != expected_section:
            raise ValueError(
                f"internal function entry {index} section disagrees with module address range"
            )
        if kind != _kind_for_section(expected_section):
            raise ValueError(
                f"internal function entry {index} kind disagrees with its original ELF section"
            )
        if not isinstance(evidence_path, str) or not evidence_path.strip():
            raise ValueError(f"internal function entry {index} has no evidence_path")
        evidence = PurePosixPath(evidence_path.replace("\\", "/"))
        if (
            evidence.is_absolute()
            or PureWindowsPath(evidence_path).is_absolute()
            or PureWindowsPath(evidence_path).drive
            or ".." in evidence.parts
        ):
            raise ValueError(f"internal function entry {index} evidence_path escapes the repository")
        instruction_count = entry.get("instruction_count")
        if (
            isinstance(instruction_count, bool)
            or not isinstance(instruction_count, int)
            or instruction_count != size_bytes // 4
        ):
            raise ValueError(f"internal function entry {index} instruction count disagrees with size")
        result = entry.get("result")
        if not isinstance(result, dict) or result.get("status") not in _RESULT_STATES:
            raise ValueError(f"internal function entry {index} has an invalid result status")

        function = InternalFunction(
            module=module.strip(),
            address=address,
            size_bytes=size_bytes,
            boundary_status=boundary_status,
            evidence_path=evidence_path.replace("\\", "/"),
            kind=kind,
            section=section,
        )
        key = internal_function_key(function)
        if key in seen:
            raise ValueError(f"duplicate internal function identity: {module}@{address_value}")
        seen.add(key)
        functions.append(function)

    by_module: dict[str, list[InternalFunction]] = {}
    for function in functions:
        if function.boundary_status == "EXACT":
            by_module.setdefault(function.module.casefold(), []).append(function)
    for module, group in by_module.items():
        ordered = sorted(group, key=lambda item: item.address)
        for previous, current in zip(ordered, ordered[1:]):
            previous_end = previous.address + previous.size_bytes
            if current.address < previous_end:
                raise ValueError(
                    f"overlapping EXACT internal functions in {module}: "
                    f"0x{previous.address:x} and 0x{current.address:x}"
                )
    return tuple(sorted(functions, key=lambda item: (item.module.casefold(), item.address)))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable: {path}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return document


def _safe_repository_path(value: str, repo_root: Path, label: str) -> Path:
    normalized = value.replace("\\", "/")
    relative = PurePosixPath(normalized)
    if (
        not normalized
        or relative.is_absolute()
        or PureWindowsPath(normalized).is_absolute()
        or PureWindowsPath(normalized).drive
        or ".." in relative.parts
        or "." in relative.parts
    ):
        raise ValueError(f"{label} must be a repository-relative, non-traversing path")
    root = repo_root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"{label} traverses a symlink: {value}")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository: {value}") from exc
    return candidate


def _tracked_repository_paths(repo_root: Path) -> set[str] | None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "-z"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return {
        item.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for item in result.stdout.split(b"\0")
        if item
    }


def _repository_relative(path: Path, repo_root: Path) -> str:
    try:
        root = repo_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"certificate input is outside the repository: {path}") from exc
    return relative.as_posix()


def serialize_internal_certificate(document: dict[str, Any]) -> str:
    """Return the canonical on-disk form of one internal-function certificate."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def build_internal_certificate(
    *,
    module: str,
    address: int,
    size_bytes: int,
    source_path: Path,
    report_paths: Sequence[Path],
    repo_root: Path,
) -> tuple[dict[str, Any], str]:
    """Combine two independent matcher reports into one deterministic certificate.

    Both reports must be full matcher verdicts (with a ``match`` object), name the
    same source and the same address, and agree on the object digest. The source
    digest is recomputed from disk so a stale report cannot certify edited code.
    """
    from decomp_campaign import is_deterministic_match, is_strict_match

    if not isinstance(module, str) or not module.strip():
        raise ValueError("certificate module must be a non-empty string")
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < 0x1_0000_0000:
        raise ValueError("certificate address must be a 32-bit unsigned integer")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes <= 0 or size_bytes % 4:
        raise ValueError("certificate size must be a positive multiple of four")
    if len(report_paths) != 2:
        raise ValueError("a certificate requires exactly two independent matcher reports")
    if len({path.resolve() for path in report_paths}) != 2:
        raise ValueError("certificate reports must come from two distinct builds")
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError(f"certificate source is not a regular file: {source_path}")

    source_relative = _repository_relative(source_path, repo_root)
    source_path = _safe_repository_path(source_relative, repo_root, "certificate source")
    inferred_section = _section_for_range(module, address, size_bytes)
    if inferred_section is None:
        raise ValueError("certificate interval is outside the original module sections")
    expected_source = _expected_source_path(module, address)
    if source_relative != expected_source:
        raise ValueError("certificate source path does not match its module/address identity")
    source_sha256 = _sha256_file(source_path)
    reports: list[dict[str, Any]] = []
    for report_path in report_paths:
        if report_path.is_symlink():
            raise ValueError("internal matcher report path must not be a symlink")
        report_relative = _repository_relative(report_path, repo_root)
        report_path = _safe_repository_path(report_relative, repo_root, "matcher report")
        report = _read_json_object(report_path, "internal matcher report")
        if not isinstance(report.get("match"), dict):
            raise ValueError("internal matcher report has no comparison verdict")
        provenance = report.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError("internal matcher report has no provenance")
        if str(provenance.get("source_sha256")) != source_sha256:
            raise ValueError("internal matcher report was produced from a different source")
        reported_source = PurePosixPath(str(provenance.get("source", "")).replace("\\", "/"))
        if reported_source != PurePosixPath(source_relative):
            raise ValueError("internal matcher report names a different source path")
        if report.get("section") != inferred_section:
            raise ValueError("internal matcher report names a different original section")
        reports.append(report)

    for report in reports:
        if not is_strict_match(report, expected_address=address, expected_size=size_bytes):
            raise ValueError(
                f"internal matcher report is not a strict MATCHED verdict for 0x{address:x}"
            )
        if not internal_reference_evidence_is_resolved(report):
            raise ValueError("internal matcher report has incomplete call/data-reference evidence")

    object_sha256s = [str(report["provenance"]["object_sha256"]) for report in reports]
    if object_sha256s[0] != object_sha256s[1]:
        raise ValueError("independent internal builds produced different objects")
    object_paths = [report["provenance"].get("object") for report in reports]
    if not all(isinstance(path, str) for path in object_paths) or len(set(object_paths)) != 2:
        raise ValueError("internal matcher reports do not identify two distinct build outputs")

    document: dict[str, Any] = {
        "schema_version": 1,
        "module": module.strip(),
        "address": f"0x{address:x}",
        "size_bytes": size_bytes,
        "section": inferred_section,
        "source_path": source_relative,
        "source_sha256": source_sha256,
        "build_sha256": object_sha256s,
        "independent_builds": 2,
        "deterministic_match": True,
        "reports": reports,
    }
    if not is_deterministic_match(
        {
            "status": "MATCHED",
            "source_sha256": source_sha256,
            "build_sha256": object_sha256s,
            "reports": reports,
        },
        expected_address=address,
        expected_size=size_bytes,
    ):
        raise ValueError("certificate failed the deterministic-match gate")
    content = serialize_internal_certificate(document)
    return document, hashlib.sha256(content.encode("utf-8")).hexdigest()


def write_internal_certificate(
    path: Path, document: dict[str, Any], *, repo_root: Path
) -> str:
    """Persist a repository-relative certificate without overwriting conflicts."""
    if path.is_absolute():
        raise ValueError("certificate destination must be repository-relative")
    path = _safe_repository_path(path.as_posix(), repo_root, "certificate destination")
    content = serialize_internal_certificate(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ValueError("refusing to overwrite a different internal certificate")
    else:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("internal certificate temporary path already exists")
        try:
            with temporary.open("xb") as stream:
                payload = content.encode("utf-8")
                stream.write(payload)
                stream.flush()
                import os

                os.fsync(stream.fileno())
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != hashlib.sha256(payload).hexdigest():
                raise ValueError("internal certificate temporary failed its digest check")
            try:
                os.link(temporary, path)
            except FileExistsError:
                if not path.is_file() or path.read_text(encoding="utf-8") != content:
                    raise ValueError("refusing to overwrite a different internal certificate")
        except OSError as exc:
            raise ValueError("could not atomically create internal certificate") from exc
        finally:
            temporary.unlink(missing_ok=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_internal_catalog_evidence(
    catalog_path: Path,
    *,
    repo_root: Path,
    mode: str = "full",
    export_catalog_path: Path | None = None,
    require_tracked_sources: bool = True,
    check_export_overlaps: bool = True,
) -> tuple[str, ...]:
    """Validate metadata or fully audit stored reports (not fresh MWCC builds)."""
    if mode not in {"metadata-only", "full"}:
        raise ValueError("catalog validation mode must be metadata-only or full")
    functions = load_internal_catalog(catalog_path)
    document = _read_json_object(catalog_path, "internal function catalog")
    root = repo_root.resolve(strict=True)
    problems: list[str] = []
    tracked = _tracked_repository_paths(root) if require_tracked_sources else None
    export_path = export_catalog_path or root / "config/decomp_campaign_inventory.json"
    export_ranges: list[tuple[int, int]] = []
    if check_export_overlaps:
        try:
            exports = _read_json_object(export_path, "export inventory")
            ranges = exports.get("baseline", {}).get("eboot_matched_ranges", [])
            if not isinstance(ranges, list):
                raise ValueError("export baseline ranges must be a list")
            for item in ranges:
                if not isinstance(item, dict):
                    raise ValueError("export baseline range must be an object")
                address = item.get("address")
                size = item.get("size_bytes")
                if (
                    not isinstance(address, str)
                    or not _ADDRESS.fullmatch(address)
                    or isinstance(size, bool)
                    or not isinstance(size, int)
                    or size <= 0
                ):
                    raise ValueError("export baseline range has invalid address/size")
                export_ranges.append((int(address, 16), int(address, 16) + size))
        except (ValueError, OSError) as exc:
            problems.append(f"cannot validate EBOOT export overlap baseline: {exc}")

    for function, entry in zip(functions, document["functions"], strict=True):
        identity = f"{function.module}@0x{function.address:x}"
        if function.module.casefold() == "eboot" and function.boundary_status == "EXACT":
            start, end = function.address, function.address + function.size_bytes
            if any(start < export_end and export_start < end for export_start, export_end in export_ranges):
                problems.append(f"{identity}: internal range overlaps an EBOOT export baseline")

        source_value = entry.get("source_path")
        source_hash = entry.get("source_sha256")
        if source_value is not None or source_hash is not None:
            if not isinstance(source_value, str) or not _SHA256.fullmatch(str(source_hash)):
                problems.append(f"{identity}: source path/hash metadata is incomplete or malformed")
            else:
                try:
                    source_file = _safe_repository_path(source_value, root, "source path")
                    if not source_file.is_file():
                        problems.append(f"{identity}: source is missing: {source_value}")
                    elif _sha256_file(source_file) != source_hash:
                        problems.append(f"{identity}: source digest drifted: {source_value}")
                    if tracked is not None and source_value not in tracked:
                        problems.append(f"{identity}: source is not tracked by Git: {source_value}")
                    if result := entry.get("result"):
                        if result.get("status") == "MATCHED" and source_value != _expected_source_path(
                            function.module, function.address
                        ):
                            problems.append(f"{identity}: source path does not match module/address")
                except ValueError as exc:
                    problems.append(f"{identity}: unsafe source path: {exc}")

        result = entry.get("result")
        if not isinstance(result, dict):
            if function.boundary_status == "EXACT" and function.kind == "code":
                problems.append(f"{identity}: missing result metadata")
            continue
        if result.get("status") != "MATCHED":
            continue

        size_bytes = entry.get("size_bytes")
        instruction_count = entry.get("instruction_count")
        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
            or isinstance(instruction_count, bool)
            or instruction_count != size_bytes // 4
        ):
            problems.append(f"{identity}: matched size/instruction count is inconsistent")
        words = size_bytes // 4 if isinstance(size_bytes, int) and size_bytes > 0 else -1
        if result.get("matching_words") != words or result.get("total_words") != words:
            problems.append(f"{identity}: matcher word counts disagree with the function interval")

        builds = result.get("object_sha256s")
        if (
            not isinstance(builds, list)
            or len(builds) != 2
            or not all(isinstance(value, str) and _SHA256.fullmatch(value) for value in builds)
            or builds[0] != builds[1]
        ):
            problems.append(f"{identity}: matched entry lacks two valid identical object digests")

        certificate_value = result.get("certificate_path")
        certificate_hash = result.get("certificate_sha256")
        if not isinstance(certificate_value, str) or not isinstance(certificate_hash, str):
            problems.append(f"{identity}: matched entry has no certificate path/hash")
            continue
        if not _SHA256.fullmatch(certificate_hash):
            problems.append(f"{identity}: certificate SHA-256 is malformed")
            continue
        try:
            certificate = _safe_repository_path(certificate_value, root, "certificate path")
        except ValueError as exc:
            problems.append(f"{identity}: unsafe certificate path: {exc}")
            continue
        if mode == "metadata-only":
            continue
        if not certificate.is_file():
            problems.append(f"{identity}: certificate is missing: {certificate_value}")
            continue
        if _sha256_file(certificate) != certificate_hash:
            problems.append(f"{identity}: certificate digest drifted: {certificate_value}")
            continue
        try:
            certified = _read_json_object(certificate, "internal certificate")
        except ValueError as exc:
            problems.append(f"{identity}: {exc}")
            continue

        if certified.get("schema_version") != 1:
            problems.append(f"{identity}: certificate schema is unsupported")
        if certified.get("module") != function.module or certified.get("address") != entry.get("address"):
            problems.append(f"{identity}: certificate identity disagrees with the catalog")
        if certified.get("size_bytes") != size_bytes or certified.get("section") != function.section:
            problems.append(f"{identity}: certificate range/section disagrees with the catalog")
        boundary = certified.get("boundary")
        if boundary is not None and (
            not isinstance(boundary, dict)
            or boundary.get("status") != "EXACT"
            or boundary.get("module") != function.module
            or boundary.get("address") != entry.get("address")
            or boundary.get("size_bytes") != size_bytes
            or boundary.get("section") != function.section
            or not isinstance(boundary.get("ghidra_log_sha256"), str)
            or not _SHA256.fullmatch(boundary["ghidra_log_sha256"])
        ):
            problems.append(f"{identity}: certificate Ghidra boundary attestation is incomplete")
        if certified.get("source_path") != source_value or certified.get("source_sha256") != source_hash:
            problems.append(f"{identity}: certificate source identity/digest disagrees with the catalog")
        if certified.get("deterministic_match") is not True or certified.get("independent_builds") != 2:
            problems.append(f"{identity}: certificate does not declare two deterministic builds")
        certificate_builds = certified.get("build_sha256")
        if certificate_builds != builds:
            problems.append(f"{identity}: certificate build digests disagree with the catalog")

        reports = certified.get("reports")
        if not isinstance(reports, list) or len(reports) != 2:
            problems.append(f"{identity}: certificate must contain two complete matcher reports")
            continue
        try:
            from decomp_campaign import is_deterministic_match, is_strict_match

            address = function.address
            for report in reports:
                if not isinstance(report, dict):
                    raise ValueError("report is not an object")
                provenance = report.get("provenance")
                if not isinstance(provenance, dict):
                    raise ValueError("report provenance is missing")
                if (
                    int(str(report.get("address")), 0) != address
                    or report.get("match", {}).get("address") != address
                    or report.get("section") != function.section
                    or report.get("symbol") != f"func_{address:08X}"
                    or provenance.get("source") != source_value
                    or provenance.get("source_sha256") != source_hash
                ):
                    raise ValueError("report identity, section, or source disagrees with catalog")
                if not is_strict_match(report, expected_address=address, expected_size=size_bytes):
                    raise ValueError("report fails the production strict-match gate")
                if not internal_reference_evidence_is_resolved(report):
                    raise ValueError("report has incomplete call/data-reference evidence")
                for value in (provenance.get("object"), report.get("object_path")):
                    if value is not None:
                        if not isinstance(value, str):
                            raise ValueError("report object path is malformed")
                        _safe_repository_path(value, root, "report object path")
            object_paths = [report["provenance"].get("object") for report in reports]
            if not all(isinstance(path, str) for path in object_paths) or len(set(object_paths)) != 2:
                raise ValueError("reports do not identify two distinct builds")
            if not is_deterministic_match(
                {
                    "status": "MATCHED",
                    "source_sha256": source_hash,
                    "build_sha256": certificate_builds,
                    "reports": reports,
                },
                expected_address=address,
                expected_size=size_bytes,
            ):
                raise ValueError("certificate fails the production deterministic-match gate")
        except (KeyError, TypeError, ValueError, OSError) as exc:
            problems.append(f"{identity}: invalid full certificate audit: {exc}")
    return tuple(problems)


def main(argv: Sequence[str] | None = None) -> int:
    """Certify one internal function or validate the whole catalog's evidence."""
    parser = argparse.ArgumentParser(
        prog="internal_functions", description="internal-function evidence tooling"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    certify = subparsers.add_parser("certify", help="build one certificate from two reports")
    certify.add_argument("--module", required=True)
    certify.add_argument("--address", required=True, type=lambda value: int(value, 0))
    certify.add_argument("--size", required=True, type=lambda value: int(value, 0))
    certify.add_argument("--source", required=True, type=Path)
    certify.add_argument("--report", required=True, action="append", type=Path)
    certify.add_argument("--out", required=True, type=Path)
    certify.add_argument("--repo-root", type=Path, default=Path("."))
    validate = subparsers.add_parser("validate", help="verify every catalogued match")
    validate.add_argument(
        "--catalog",
        type=Path,
        default=Path("config/decomp_internal_inventory.json"),
    )
    validate.add_argument("--repo-root", type=Path, default=Path("."))
    validation_mode = validate.add_mutually_exclusive_group(required=True)
    validation_mode.add_argument("--metadata-only", action="store_const", const="metadata-only", dest="mode")
    validation_mode.add_argument("--full", action="store_const", const="full", dest="mode")
    arguments = parser.parse_args(argv)

    if arguments.command == "certify":
        document, digest = build_internal_certificate(
            module=arguments.module,
            address=arguments.address,
            size_bytes=arguments.size,
            source_path=arguments.source,
            report_paths=arguments.report,
            repo_root=arguments.repo_root,
        )
        digest = write_internal_certificate(
            arguments.out, document, repo_root=arguments.repo_root
        )
        print(f"certified {arguments.module}@0x{arguments.address:x} sha256={digest}")
        return 0

    try:
        problems = validate_internal_catalog_evidence(
            arguments.catalog,
            repo_root=arguments.repo_root,
            mode=arguments.mode,
        )
        catalog_document = _read_json_object(arguments.catalog, "internal function catalog")
        export_path = arguments.repo_root / "config/decomp_campaign_inventory.json"
        exports = _read_json_object(export_path, "export inventory").get("baseline", {})
        metrics = internal_catalog_metrics(catalog_document["functions"], exports)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    print(
        f"validated {arguments.catalog} mode={arguments.mode} problems={len(problems)} "
        f"metrics={json.dumps(metrics, sort_keys=True)}"
    )
    if arguments.mode == "full":
        print("full mode audits stored reports; it does not run fresh MWCC builds")
    else:
        print("metadata-only mode validates metadata; it does not certify MATCHED results")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
