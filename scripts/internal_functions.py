"""Small evidence catalog for non-export EBOOT/PRX functions.

Internal functions deliberately stay outside the export campaign SQLite schema:
their stable identity is (module, address), and they do not have fabricated NIDs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


_BOUNDARY_STATES = {"EXACT", "UNVERIFIED", "MISMATCH", "NOT_FOUND"}
_ADDRESS = re.compile(r"0[xX][0-9a-fA-F]{1,8}\Z")


@dataclass(frozen=True)
class InternalFunction:
    module: str
    address: int
    size_bytes: int
    boundary_status: str
    evidence_path: str


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
    return tuple(function for _, function in selected[:limit])


def load_internal_catalog(path: Path) -> tuple[InternalFunction, ...]:
    """Load, normalize, and validate a deterministic internal-function catalog."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"internal function catalog is unreadable: {path}") from exc
    schema_version = document.get("schema_version") if isinstance(document, dict) else None
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("internal function catalog schema_version must be 1")
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
        if not isinstance(evidence_path, str) or not evidence_path.strip():
            raise ValueError(f"internal function entry {index} has no evidence_path")
        evidence = PurePosixPath(evidence_path.replace("\\", "/"))
        if evidence.is_absolute() or ".." in evidence.parts:
            raise ValueError(f"internal function entry {index} evidence_path escapes the repository")

        function = InternalFunction(
            module=module.strip(),
            address=address,
            size_bytes=size_bytes,
            boundary_status=boundary_status,
            evidence_path=evidence_path.replace("\\", "/"),
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


def _repository_relative(path: Path, repo_root: Path) -> str:
    try:
        relative = path.resolve().relative_to(repo_root.resolve())
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
    source_sha256 = _sha256_file(source_path)
    reports: list[dict[str, Any]] = []
    for report_path in report_paths:
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
        reports.append(report)

    from decomp_campaign import is_strict_match

    for report in reports:
        if not is_strict_match(report, expected_address=address, expected_size=size_bytes):
            raise ValueError(
                f"internal matcher report is not a strict MATCHED verdict for 0x{address:x}"
            )

    object_sha256s = [str(report["provenance"]["object_sha256"]) for report in reports]
    if object_sha256s[0] != object_sha256s[1]:
        raise ValueError("independent internal builds produced different objects")

    document: dict[str, Any] = {
        "schema_version": 1,
        "module": module.strip(),
        "address": f"0x{address:x}",
        "size_bytes": size_bytes,
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


def write_internal_certificate(path: Path, document: dict[str, Any]) -> str:
    """Persist a certificate without overwriting a different one."""
    content = serialize_internal_certificate(document)
    cursor = path
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("certificate destination contains a symlink")
        cursor = cursor.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ValueError("refusing to overwrite a different internal certificate")
    else:
        try:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
        except FileExistsError as exc:
            raise ValueError("internal certificate appeared during persistence") from exc
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_internal_catalog_evidence(
    catalog_path: Path, *, repo_root: Path
) -> tuple[str, ...]:
    """Return every evidence problem that would make a catalogued match unverifiable."""
    load_internal_catalog(catalog_path)
    document = _read_json_object(catalog_path, "internal function catalog")
    problems: list[str] = []
    for entry in document["functions"]:
        if not isinstance(entry, dict):
            continue
        result = entry.get("result")
        if not isinstance(result, dict):
            problems.append(f"{entry.get('module')}@{entry.get('address')}: missing result")
            continue
        if result.get("status") != "MATCHED":
            continue
        identity = f"{entry.get('module')}@{entry.get('address')}"
        size_bytes = entry.get("size_bytes")
        if not isinstance(size_bytes, int) or size_bytes <= 0:
            problems.append(f"{identity}: matched entry has no positive size")
            continue
        source_path = entry.get("source_path")
        source_sha256 = entry.get("source_sha256")
        if not isinstance(source_path, str) or not source_path:
            problems.append(f"{identity}: matched entry has no source_path")
            continue
        source = repo_root / source_path
        if source.is_symlink() or not source.is_file():
            problems.append(f"{identity}: source is missing: {source_path}")
        elif _sha256_file(source) != source_sha256:
            problems.append(f"{identity}: source digest drifted: {source_path}")
        builds = result.get("object_sha256s")
        if not isinstance(builds, list) or len(builds) != 2 or builds[0] != builds[1]:
            problems.append(f"{identity}: matched entry lacks two identical object digests")
        certificate_path = result.get("certificate_path")
        certificate_sha256 = result.get("certificate_sha256")
        if not isinstance(certificate_path, str) or not certificate_path:
            problems.append(f"{identity}: matched entry has no certificate")
            continue
        certificate = repo_root / certificate_path
        if certificate.is_symlink() or not certificate.is_file():
            problems.append(f"{identity}: certificate is missing: {certificate_path}")
            continue
        if _sha256_file(certificate) != certificate_sha256:
            problems.append(f"{identity}: certificate digest drifted: {certificate_path}")
            continue
        try:
            certified = _read_json_object(certificate, "internal certificate")
        except ValueError as exc:
            problems.append(f"{identity}: {exc}")
            continue
        if certified.get("module") != entry.get("module"):
            problems.append(f"{identity}: certificate module disagrees with the catalog")
        if certified.get("address") != entry.get("address"):
            problems.append(f"{identity}: certificate address disagrees with the catalog")
        if certified.get("size_bytes") != size_bytes:
            problems.append(f"{identity}: certificate size disagrees with the catalog")
        if certified.get("source_sha256") != source_sha256:
            problems.append(f"{identity}: certificate source digest disagrees with the catalog")
        if certified.get("deterministic_match") is not True or certified.get("independent_builds") != 2:
            problems.append(f"{identity}: certificate is not a deterministic two-build match")
        certificate_builds = certified.get("build_sha256")
        if certificate_builds != builds:
            problems.append(f"{identity}: certificate build digests disagree with the catalog")
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
        digest = write_internal_certificate(arguments.out, document)
        print(f"certified {arguments.module}@0x{arguments.address:x} sha256={digest}")
        return 0

    problems = validate_internal_catalog_evidence(
        arguments.catalog, repo_root=arguments.repo_root
    )
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    print(f"validated {arguments.catalog} problems={len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
