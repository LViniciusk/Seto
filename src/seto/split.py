"""Splitting: deterministic section layout plus a splat configuration.

Splat itself is an external dependency, so Seto does not depend on it to do
useful work.  It derives the layout from the *real* ELF section table, validates
that layout against the file (coverage, ordering, sizes, vram consistency) and
emits two artefacts:

* ``layout.json`` - the machine-readable, fully validated model;
* ``<basename>.yaml`` - a splat configuration generated from that model.

The YAML is a candidate that must still be validated by actually running
``splat``; ``check-layout`` validates the model, which is the reproducible part.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from seto.binio import ParseError
from seto.elf import SHF_ALLOC, SHT_NULL, ElfFile, Section
from seto.mips import SHF_EXECINSTR

ASM_KIND = "asm"
BIN_KIND = "bin"
CODE_TYPE = "code"

WARNING = "warning"
ERROR = "error"


@dataclass(frozen=True)
class Subsegment:
    offset: int
    kind: str
    name: str
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size

    def summary(self) -> dict[str, object]:
        return {"offset": self.offset, "kind": self.kind, "name": self.name, "size": self.size}


@dataclass(frozen=True)
class LayoutSegment:
    name: str
    type: str
    start: int
    vram: int
    subsegments: tuple[Subsegment, ...]

    @property
    def end(self) -> int:
        return self.subsegments[-1].end if self.subsegments else self.start

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "type": self.type,
            "start": self.start,
            "vram": self.vram,
            "end": self.end,
            "subsegments": [item.summary() for item in self.subsegments],
        }


@dataclass(frozen=True)
class Layout:
    basename: str
    file_size: int
    image_delta: int
    segments: tuple[LayoutSegment, ...]

    def subsegments(self) -> tuple[Subsegment, ...]:
        return tuple(
            subsegment for segment in self.segments for subsegment in segment.subsegments
        )

    def summary(self) -> dict[str, object]:
        return {
            "basename": self.basename,
            "file_size": self.file_size,
            "image_delta": self.image_delta,
            "segments": [segment.summary() for segment in self.segments],
        }

    def to_json(self) -> str:
        return json.dumps(self.summary(), indent=2, sort_keys=True) + "\n"

    @staticmethod
    def from_dict(data: dict) -> Layout:
        segments = []
        for raw_segment in data["segments"]:
            subsegments = tuple(
                Subsegment(
                    offset=item["offset"],
                    kind=item["kind"],
                    name=item["name"],
                    size=item["size"],
                )
                for item in raw_segment["subsegments"]
            )
            segments.append(
                LayoutSegment(
                    name=raw_segment["name"],
                    type=raw_segment["type"],
                    start=raw_segment["start"],
                    vram=raw_segment["vram"],
                    subsegments=subsegments,
                )
            )
        return Layout(
            basename=data["basename"],
            file_size=data["file_size"],
            image_delta=data["image_delta"],
            segments=tuple(segments),
        )


@dataclass(frozen=True)
class LayoutIssue:
    severity: str
    message: str

    def render(self) -> str:
        return f"{self.severity.upper()}: {self.message}"


def segment_name(section: Section) -> str:
    return section.name.lstrip(".").replace(".", "_") or f"section_{section.index}"


def build_layout(elf: ElfFile, basename: str) -> Layout:
    """Derive a deterministic layout from the ELF's real section table."""
    image = [
        section
        for section in elf.sections
        if section.is_allocated
        and section.type != SHT_NULL
        and section.size > 0
        and not section.is_nobits
    ]
    if not image:
        raise ParseError(f"{elf.reader.name}: no allocated section to split")
    image = sorted(image, key=lambda section: section.offset)

    first = image[0]
    delta = first.offset - first.addr
    segments: list[LayoutSegment] = []

    if first.offset > 0:
        segments.append(
            LayoutSegment(
                name="header",
                type=BIN_KIND,
                start=0,
                vram=0,
                subsegments=(
                    Subsegment(offset=0, kind=BIN_KIND, name="header", size=first.offset),
                ),
            )
        )

    code_subsegments = tuple(
        Subsegment(
            offset=section.offset,
            kind=ASM_KIND if section.flags & SHF_EXECINSTR else BIN_KIND,
            name=segment_name(section),
            size=section.size,
        )
        for section in image
    )
    segments.append(
        LayoutSegment(
            name=basename,
            type=CODE_TYPE,
            start=first.offset,
            vram=first.addr,
            subsegments=code_subsegments,
        )
    )

    tail_start = image[-1].offset + image[-1].size
    if tail_start < elf.reader.size:
        segments.append(
            LayoutSegment(
                name="elf_meta",
                type=BIN_KIND,
                start=tail_start,
                vram=0,
                subsegments=(
                    Subsegment(
                        offset=tail_start,
                        kind=BIN_KIND,
                        name="elf_meta",
                        size=elf.reader.size - tail_start,
                    ),
                ),
            )
        )

    return Layout(
        basename=basename,
        file_size=elf.reader.size,
        image_delta=delta,
        segments=tuple(segments),
    )


def validate_layout(layout: Layout, elf: ElfFile) -> tuple[LayoutIssue, ...]:
    """Check a layout against the ELF it was derived from."""
    issues: list[LayoutIssue] = []
    sections_by_offset = {
        section.offset: section
        for section in elf.sections
        if section.is_allocated and section.size > 0 and not section.is_nobits
    }

    if layout.file_size != elf.reader.size:
        issues.append(
            LayoutIssue(
                ERROR,
                f"layout file_size {layout.file_size} != real file size {elf.reader.size}",
            )
        )

    previous_end = 0
    for segment in layout.segments:
        if not segment.subsegments:
            issues.append(LayoutIssue(ERROR, f"segment {segment.name!r} has no subsegments"))
            continue
        expected_start = segment.subsegments[0].offset
        if segment.start != expected_start:
            issues.append(
                LayoutIssue(
                    ERROR,
                    f"segment {segment.name!r} start {segment.start:#x} != first subsegment "
                    f"{expected_start:#x}",
                )
            )
        for subsegment in segment.subsegments:
            if subsegment.size <= 0:
                issues.append(LayoutIssue(ERROR, f"subsegment {subsegment.name!r} has non-positive size"))
            if subsegment.offset < 0 or subsegment.end > layout.file_size:
                issues.append(
                    LayoutIssue(
                        ERROR,
                        f"subsegment {subsegment.name!r} span "
                        f"[{subsegment.offset:#x}, {subsegment.end:#x}) leaves the file",
                    )
                )
                continue
            if subsegment.offset < previous_end:
                issues.append(
                    LayoutIssue(
                        ERROR,
                        f"subsegment {subsegment.name!r} overlaps a previous region "
                        f"({subsegment.offset:#x} < {previous_end:#x})",
                    )
                )
            previous_end = max(previous_end, subsegment.end)

            reference = sections_by_offset.get(subsegment.offset)
            if reference is not None:
                if reference.size != subsegment.size:
                    issues.append(
                        LayoutIssue(
                            ERROR,
                            f"subsegment {subsegment.name!r} size {subsegment.size:#x} != "
                            f"section {reference.name!r} size {reference.size:#x}",
                        )
                    )
                expected_kind = ASM_KIND if reference.flags & SHF_EXECINSTR else BIN_KIND
                if subsegment.kind != expected_kind:
                    issues.append(
                        LayoutIssue(
                            ERROR,
                            f"subsegment {subsegment.name!r} kind {subsegment.kind!r} != "
                            f"{expected_kind!r} implied by section flags {reference.flags:#x}",
                        )
                    )
                if reference.offset - reference.addr != layout.image_delta:
                    issues.append(
                        LayoutIssue(
                            WARNING,
                            f"section {reference.name!r} breaks the constant image delta "
                            f"({reference.offset - reference.addr:#x} != {layout.image_delta:#x})",
                        )
                    )

    if previous_end != layout.file_size:
        issues.append(
            LayoutIssue(
                ERROR,
                f"layout covers [0, {previous_end:#x}) but the file is {layout.file_size:#x} bytes",
            )
        )
    return tuple(issues)


def emit_splat_yaml(
    layout: Layout,
    *,
    base_path: str,
    target_path: str,
    asm_path: str,
    ld_script_path: str,
    compiler: str = "MWCC",
    section_order: tuple[str, ...] = (".text", ".rodata", ".data", ".bss"),
) -> str:
    """Render a splat configuration from a validated layout."""
    lines = [
        f"# Generated by `seto split` - do not edit by hand.",
        f"# Validate with `splat split config/splat/{layout.basename}.yaml` before trusting it.",
        f"name: {layout.basename}",
        "options:",
        "  platform: psp",
        f"  basename: {layout.basename}",
        f"  base_path: {base_path}",
        f"  target_path: {target_path}",
        f"  asm_path: {asm_path}",
        f"  ld_script_path: {ld_script_path}",
        f"  compiler: {compiler}",
        "  find_file_boundaries: False",
        "  section_order: [" + ", ".join(f'"{name}"' for name in section_order) + "]",
        "segments:",
    ]
    for segment in layout.segments:
        if segment.type != CODE_TYPE:
            only = segment.subsegments[0]
            lines.append(f"  - [0x{segment.start:x}, {only.kind}, {only.name}]")
            continue
        lines.append(f"  - name: {segment.name}")
        lines.append(f"    type: {segment.type}")
        lines.append(f"    start: 0x{segment.start:x}")
        lines.append(f"    vram: 0x{segment.vram:x}")
        lines.append("    subsegments:")
        for subsegment in segment.subsegments:
            lines.append(
                f"      - [0x{subsegment.offset:x}, {subsegment.kind}, {subsegment.name}]"
            )
    lines.append(f"  - [0x{layout.file_size:x}]  # sentinel: total file size")
    return "\n".join(lines) + "\n"


def cross_check_yaml(text: str, layout: Layout) -> tuple[LayoutIssue, ...]:
    """Optional cross-check of the emitted YAML, when PyYAML is available."""
    try:
        import yaml  # type: ignore import-not-found
    except ImportError:
        return ()
    document = yaml.safe_load(text)
    issues: list[LayoutIssue] = []
    declared = document.get("segments", [])
    if not declared:
        return (LayoutIssue(ERROR, "YAML declares no segments"),)
    sentinel = declared[-1]
    if isinstance(sentinel, list) and len(sentinel) == 1 and sentinel[0] != layout.file_size:
        issues.append(
            LayoutIssue(
                ERROR,
                f"YAML sentinel {sentinel[0]:#x} != layout file size {layout.file_size:#x}",
            )
        )
    yaml_offsets = _yaml_offsets(declared)
    layout_offsets = [subsegment.offset for subsegment in layout.subsegments()]
    if yaml_offsets != layout_offsets:
        issues.append(LayoutIssue(ERROR, "YAML subsegment offsets do not match the layout"))
    return tuple(issues)


def _yaml_offsets(declared: list) -> list[int]:
    offsets: list[int] = []
    for entry in declared:
        if isinstance(entry, list):
            if len(entry) == 1:  # sentinel: total file size
                continue
            offsets.append(int(entry[0]))
            continue
        if not isinstance(entry, dict):
            continue
        subsegments = entry.get("subsegments")
        if subsegments:
            offsets.extend(int(subsegment[0]) for subsegment in subsegments)
        elif "start" in entry:
            offsets.append(int(entry["start"]))
    return offsets


def default_outputs(layout: Layout, output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    return directory / "layout.json", directory / f"{layout.basename}.yaml"
