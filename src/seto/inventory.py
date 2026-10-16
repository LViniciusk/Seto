"""Deterministic inventory of the original media: files, modules and functions.

The inventory is *read-only* with respect to the game data, contains no
timestamps, and serialises with sorted keys so two runs over the same inputs
produce byte-identical manifests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from seto import elf, formats, mips, sfo
from seto.binio import BytesReader, ParseError, read_file
from seto.hashing import FileFingerprint, fingerprint_file, verify_fingerprint
from seto.paths import relative_posix
from seto.toolchain import Settings

INVENTORY_SCHEMA = "seto/inventory/1"
FUNCTION_SECTIONS = (".text",)


@dataclass(frozen=True)
class FileRecord:
    relpath: str
    size: int
    sha256: str
    fmt: str
    detail: str

    def summary(self) -> dict[str, object]:
        return {
            "relpath": self.relpath,
            "size": self.size,
            "sha256": self.sha256,
            "format": self.fmt,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ModuleRecord:
    relpath: str
    fmt: str
    file_type: str
    machine: int
    comment: str | None
    sections: tuple[dict[str, object], ...]
    segments: tuple[dict[str, object], ...]
    relocation_count: int
    symbol_count: int
    functions: tuple[dict[str, object], ...]
    observations: tuple[str, ...]

    def summary(self) -> dict[str, object]:
        return {
            "relpath": self.relpath,
            "format": self.fmt,
            "file_type": self.file_type,
            "machine": self.machine,
            "comment": self.comment,
            "sections": [dict(section) for section in self.sections],
            "segments": [dict(segment) for segment in self.segments],
            "relocation_count": self.relocation_count,
            "symbol_count": self.symbol_count,
            "functions": [dict(function) for function in self.functions],
            "observations": list(self.observations),
        }


def iter_files(root: str | Path) -> list[Path]:
    """List every file under ``root`` in a stable, case-insensitive order."""
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(f"extracted root not found: {base}")
    files = [path for path in base.rglob("*") if path.is_file()]
    return sorted(files, key=lambda path: path.as_posix().lower())


def record_file(root: str | Path, path: str | Path) -> FileRecord:
    """Fingerprint one file and identify its container format."""
    resolved = Path(path)
    signature = formats.identify_file(resolved)
    fingerprint = fingerprint_file(resolved)
    return FileRecord(
        relpath=relative_posix(root, resolved),
        size=fingerprint.size,
        sha256=fingerprint.sha256,
        fmt=signature.fmt,
        detail=_detail_for(signature, resolved),
    )


def _detail_for(signature: formats.Signature, path: Path) -> str:
    if signature.fmt != "ELF":
        return signature.description
    with open(path, "rb") as handle:
        head = handle.read(elf.ELF_HEADER_SIZE)
    if len(head) < elf.ELF_HEADER_SIZE:
        return "truncated ELF header"
    e_type = int.from_bytes(head[0x10:0x12], "little")
    e_machine = int.from_bytes(head[0x12:0x14], "little")
    type_name = elf.FILE_TYPE_NAMES.get(e_type, f"0x{e_type:04x}")
    return f"ELF32 {type_name} machine={e_machine}"


def analyze_module(root: str | Path, path: str | Path) -> ModuleRecord:
    """Parse an ELF module and describe its sections, relocations and functions."""
    resolved = Path(path)
    parsed = elf.parse(resolved)
    functions: list[dict[str, object]] = []
    for section_name in FUNCTION_SECTIONS:
        section = parsed.section(section_name)
        if section is None or section.size == 0:
            continue
        code = parsed.section_data(section)
        for function in mips.find_functions(code, section.addr, f"{resolved.name}:{section_name}"):
            entry = function.summary()
            entry["section"] = section_name
            functions.append(entry)
    return ModuleRecord(
        relpath=relative_posix(root, resolved),
        fmt="ELF",
        file_type=parsed.header.file_type_name,
        machine=parsed.header.e_machine,
        comment=parsed.comment(),
        sections=tuple(section.summary() for section in parsed.sections),
        segments=tuple(segment.summary() for segment in parsed.segments),
        relocation_count=len(parsed.relocations),
        symbol_count=len(parsed.symbols),
        functions=tuple(functions),
        observations=parsed.observations,
    )


def read_parameter_sfo(extracted_root: str | Path) -> dict[str, object] | None:
    """Parse ``PARAM.SFO`` when it is present under ``extracted_root``."""
    candidate = Path(extracted_root) / "PARAM.SFO"
    if not candidate.is_file():
        return None
    document = sfo.parse_source(candidate)
    return {
        "version": document.version,
        "entries": [
            {
                "key": entry.key,
                "format": entry.fmt_name,
                "value": sfo.value_as_text(entry),
            }
            for entry in document.entries
        ],
    }


def baseline_from_settings(settings: Settings) -> dict[str, object]:
    baseline = settings.baseline
    return {
        "iso": str(baseline.get("iso", "TF1.iso")),
        "disc_id": baseline.get("disc_id"),
        "disc_version": baseline.get("disc_version"),
        "title": baseline.get("title"),
        "expected_size": baseline.get("size"),
        "expected_sha256": str(baseline.get("sha256", "")).upper() or None,
    }


def build_manifest(
    *,
    iso_path: str | Path | None = None,
    extracted_root: str | Path | None = None,
    settings: Settings | None = None,
    verify_iso: bool = True,
) -> dict[str, object]:
    """Build the full inventory manifest for the configured/root inputs."""
    active = settings or Settings()
    baseline = baseline_from_settings(active)
    iso = Path(iso_path) if iso_path is not None else Path(str(baseline["iso"]))
    root = Path(extracted_root) if extracted_root is not None else Path(
        str(active.baseline.get("extracted_root", "private/original/PSP_GAME"))
    )

    iso_entry: dict[str, object] = dict(baseline)
    iso_entry["path"] = str(iso)
    iso_entry["present"] = iso.is_file()
    iso_entry["verified"] = None
    iso_entry["issues"] = []

    if iso.is_file() and verify_iso and baseline["expected_size"] and baseline["expected_sha256"]:
        fingerprint: FileFingerprint = fingerprint_file(iso)
        result = verify_fingerprint(
            fingerprint, int(baseline["expected_size"]), str(baseline["expected_sha256"])
        )
        iso_entry.update(
            {
                "actual_size": fingerprint.size,
                "actual_sha256": fingerprint.sha256.upper(),
                "verified": result.ok,
                "issues": list(result.issues),
            }
        )

    files = [record_file(root, path) for path in iter_files(root)] if root.is_dir() else []
    modules: list[ModuleRecord] = []
    module_errors: list[dict[str, str]] = []
    for record in files:
        if record.fmt != "ELF":
            continue
        try:
            modules.append(analyze_module(root, root / record.relpath))
        except ParseError as exc:
            module_errors.append({"relpath": record.relpath, "error": str(exc)})

    manifest: dict[str, object] = {
        "schema": INVENTORY_SCHEMA,
        "baseline": iso_entry,
        "extracted_root": str(root),
        "parameter_sfo": read_parameter_sfo(root) if root.is_dir() else None,
        "files": [record.summary() for record in files],
        "modules": [module.summary() for module in modules],
        "module_errors": module_errors,
        "summary": {
            "file_count": len(files),
            "module_count": len(modules),
            "function_count": sum(len(module.functions) for module in modules),
        },
    }
    return manifest


def write_json(path: str | Path, payload: object) -> Path:
    """Write deterministic JSON (sorted keys, 2-space indent, trailing newline)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    target.write_text(text + "\n", encoding="utf-8", newline="\n")
    return target


def write_text(path: str | Path, text: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def load_manifest(path: str | Path) -> dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def render_markdown(manifest: dict[str, object]) -> str:
    """Render the human-readable inventory report."""
    baseline = manifest.get("baseline", {})
    lines: list[str] = ["# Seto inventory report", ""]
    lines += ["## Baseline", ""]
    lines += [
        "| Field | Value |",
        "| --- | --- |",
        f"| ISO | `{baseline.get('path')}` |",
        f"| DISC_ID | `{baseline.get('disc_id')}` |",
        f"| DISC_VERSION | `{baseline.get('disc_version')}` |",
        f"| Expected size | `{baseline.get('expected_size')}` |",
        f"| Expected SHA-256 | `{baseline.get('expected_sha256')}` |",
        f"| Actual size | `{baseline.get('actual_size')}` |",
        f"| Actual SHA-256 | `{baseline.get('actual_sha256')}` |",
        f"| Present | {baseline.get('present')} |",
        f"| Verified | {baseline.get('verified')} |",
    ]
    issues = baseline.get("issues") or []
    if issues:
        lines += ["", "Verification issues:", ""] + [f"- {issue}" for issue in issues]

    parameter = manifest.get("parameter_sfo")
    lines += ["", "## PARAM.SFO", ""]
    if not parameter:
        lines.append("_PARAM.SFO not found._")
    else:
        lines += ["| Key | Format | Value |", "| --- | --- | --- |"]
        for entry in parameter.get("entries", []):
            lines.append(f"| `{entry['key']}` | {entry['format']} | `{entry['value']}` |")

    files = manifest.get("files", [])
    lines += ["", "## Extracted files", "", "| File | Size | Format | SHA-256 |", "| --- | --- | --- | --- |"]
    for record in files:
        lines.append(
            f"| `{record['relpath']}` | {record['size']} | {record['format']} | "
            f"`{str(record['sha256'])[:16]}...` |"
        )

    lines += ["", "## Modules", ""]
    for module in manifest.get("modules", []):
        lines += [
            f"### `{module['relpath']}`",
            "",
            f"- Format: `{module['file_type']}` (machine {module['machine']})",
            f"- Compiler: `{module['comment']}`",
            f"- Relocations: {module['relocation_count']}; symbols: {module['symbol_count']}",
            f"- Functions (`.text`): {len(module['functions'])}",
            "",
        ]
        code_sections = [s for s in module["sections"] if s["name"] in FUNCTION_SECTIONS]
        if code_sections:
            lines += ["| Section | Address | Offset | Size |", "| --- | --- | --- | --- |"]
            for section in code_sections:
                lines.append(
                    f"| `{section['name']}` | `0x{section['addr']:x}` | `0x{section['offset']:x}` | "
                    f"`0x{section['size']:x}` |"
                )
            lines.append("")

    for error in manifest.get("module_errors", []):
        lines.append(f"- MODULE ERROR `{error['relpath']}`: {error['error']}")

    summary = manifest.get("summary", {})
    lines += [
        "",
        "## Summary",
        "",
        f"- Files: {summary.get('file_count')}",
        f"- Modules: {summary.get('module_count')}",
        f"- Functions discovered: {summary.get('function_count')}",
        "",
        "_No timestamps are recorded; re-running the inventory over identical inputs "
        "produces a byte-identical manifest._",
        "",
    ]
    return "\n".join(lines) + "\n"
