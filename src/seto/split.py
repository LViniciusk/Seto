"""Splitting: deterministic section layout plus a splat configuration.

Splat itself is an external dependency, so Seto does not depend on it to do
useful work.  It derives the layout from the *real* ELF section table, validates
that layout against the file (coverage, ordering, sizes, vram consistency) and
emits two artefacts:

* ``layout.json`` - the machine-readable, fully validated model;
* ``<basename>.yaml`` - a splat configuration generated from that model.

The YAML is generated, never hand-edited, and ``seto split --run-splat`` closes
the loop when splat is installed: it runs splat on that exact configuration and
then verifies what splat wrote word by word against the original file (see
:func:`parse_listing` and :func:`verify_listing`).  ``check-layout`` validates the
model alone, which is the reproducible part that needs no external tool.
"""

from __future__ import annotations

import json
import re
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

#: The `compiler` profile splat must be given for this module.  The original
#: object was produced by Metrowerks CodeWarrior for PSP (`MW MIPS C Compiler
#: 2.4.1.01`), but spimdisasm has no dedicated ``MWCCPSP`` entry: ``MWCCPS2`` is
#: its CodeWarrior MIPS profile and is the closest accepted value.  The generic
#: ``MWCC`` is *not* in that table, so spimdisasm rejects the generated config
#: outright ("Unsupported selected compiler for spimdisasm: MWCC").
SPLAT_COMPILER = "MWCCPS2"


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParseError(f"layout field {field!r} must be an integer")
    return value


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ParseError(f"layout field {field!r} must be a string")
    return value


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
    def from_dict(data: object) -> Layout:
        """Build a layout from parsed JSON, rejecting malformed structures."""
        if not isinstance(data, dict):
            raise ParseError("layout JSON must be an object")
        for key in ("basename", "file_size", "image_delta", "segments"):
            if key not in data:
                raise ParseError(f"layout JSON is missing the {key!r} field")
        file_size = _require_int(data["file_size"], "file_size")
        if file_size <= 0:
            raise ParseError("layout field 'file_size' must be positive")
        image_delta = _require_int(data["image_delta"], "image_delta")
        if image_delta < 0:
            raise ParseError("layout field 'image_delta' must not be negative")
        raw_segments = data["segments"]
        if not isinstance(raw_segments, list) or not raw_segments:
            raise ParseError("layout field 'segments' must be a non-empty list")

        segments = []
        for index, raw_segment in enumerate(raw_segments):
            segments.append(_segment_from_dict(raw_segment, index))
        return Layout(
            basename=_require_str(data["basename"], "basename"),
            file_size=file_size,
            image_delta=image_delta,
            segments=tuple(segments),
        )


def _segment_from_dict(raw_segment: object, index: int) -> LayoutSegment:
    if not isinstance(raw_segment, dict):
        raise ParseError(f"layout segment {index} must be an object")
    for key in ("name", "type", "start", "vram", "subsegments"):
        if key not in raw_segment:
            raise ParseError(f"layout segment {index} is missing the {key!r} field")
    raw_subsegments = raw_segment["subsegments"]
    if not isinstance(raw_subsegments, list) or not raw_subsegments:
        raise ParseError(f"layout segment {index} 'subsegments' must be a non-empty list")
    subsegments = tuple(
        _subsegment_from_dict(item, index, position)
        for position, item in enumerate(raw_subsegments)
    )
    return LayoutSegment(
        name=_require_str(raw_segment["name"], f"segments[{index}].name"),
        type=_require_str(raw_segment["type"], f"segments[{index}].type"),
        start=_require_int(raw_segment["start"], f"segments[{index}].start"),
        vram=_require_int(raw_segment["vram"], f"segments[{index}].vram"),
        subsegments=subsegments,
    )


def _subsegment_from_dict(item: object, segment: int, position: int) -> Subsegment:
    if not isinstance(item, dict):
        raise ParseError(f"layout subsegment {segment}.{position} must be an object")
    for key in ("offset", "kind", "name", "size"):
        if key not in item:
            raise ParseError(
                f"layout subsegment {segment}.{position} is missing the {key!r} field"
            )
    size = _require_int(item["size"], f"segments[{segment}].subsegments[{position}].size")
    offset = _require_int(item["offset"], f"segments[{segment}].subsegments[{position}].offset")
    if size <= 0:
        raise ParseError(f"layout subsegment {segment}.{position} has a non-positive size")
    if offset < 0:
        raise ParseError(f"layout subsegment {segment}.{position} has a negative offset")
    return Subsegment(
        offset=offset,
        kind=_require_str(item["kind"], f"segments[{segment}].subsegments[{position}].kind"),
        name=_require_str(item["name"], f"segments[{segment}].subsegments[{position}].name"),
        size=size,
    )


def load_layout(path: str | Path) -> Layout:
    """Read and validate a ``layout.json`` file, rejecting malformed input."""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"cannot read layout {source}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(
            f"{source}: invalid layout JSON ({exc.msg} at line {exc.lineno} column {exc.colno})"
        ) from exc
    return Layout.from_dict(data)


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
        # SHT_NOBITS sections (.bss) occupy no file bytes, so they never take
        # part in a *file* layout; validate_layout reports them explicitly.
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
    """Check a layout against the ELF it was derived from.

    The layout must tile the file with no gaps and no overlaps: every region
    starts exactly where the previous one ends, the first starts at 0 and the
    last ends at the file size.  ``SHT_NOBITS`` sections (such as ``.bss``) own
    no file bytes, so they are reported explicitly instead of being treated as
    an unexplained gap.
    """
    issues: list[LayoutIssue] = []
    sections_by_offset = {
        section.offset: section
        for section in elf.sections
        if section.is_allocated and section.size > 0 and not section.is_nobits
    }
    nobits = [
        section
        for section in elf.sections
        if section.is_allocated and section.is_nobits and section.size > 0
    ]

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
            elif subsegment.offset > previous_end:
                issues.append(
                    LayoutIssue(
                        ERROR,
                        f"gap of {subsegment.offset - previous_end:#x} bytes before subsegment "
                        f"{subsegment.name!r} ({previous_end:#x} -> {subsegment.offset:#x})",
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
    for section in nobits:
        issues.append(
            LayoutIssue(
                WARNING,
                f"section {section.name!r} is SHT_NOBITS: it owns no file bytes and is "
                "intentionally absent from the file layout",
            )
        )
    return tuple(issues)


def _as_posix(path: str) -> str:
    """Render a path with ``/`` separators.

    The emitted config is a committed, cross-platform artefact: a Windows run
    must not bake ``\\`` into it, because the same file is consumed on Linux and
    in WSL2.
    """
    return str(path).replace("\\", "/")


def emit_splat_yaml(
    layout: Layout,
    *,
    base_path: str,
    target_path: str,
    asm_path: str,
    ld_script_path: str,
    compiler: str = SPLAT_COMPILER,
    section_order: tuple[str, ...] = (".text", ".rodata", ".data", ".bss"),
) -> str:
    """Render a splat configuration from a validated layout.

    ``base_path`` is written verbatim, but splat resolves it **relative to the
    directory that holds the config file** (``options.py``:
    ``config_path.parent / base_path``), not relative to the working directory.
    The caller must therefore pass a path that is correct as seen *from the
    config's own directory*.
    """
    lines = [
        f"# Generated by `seto split` - do not edit by hand.",
        f"# Validate with `splat split config/splat/{layout.basename}.yaml` before trusting it.",
        f"name: {layout.basename}",
        "options:",
        "  platform: psp",
        f"  basename: {layout.basename}",
        f"  base_path: {_as_posix(base_path)}",
        f"  target_path: {_as_posix(target_path)}",
        f"  asm_path: {_as_posix(asm_path)}",
        f"  ld_script_path: {_as_posix(ld_script_path)}",
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


# ------------------------------------------------------------- splat listing

#: spimdisasm renders every decoded word as a comment that carries the file
#: offset, the address and the raw word little-endian.  That comment is what
#: makes a listing checkable against the bytes it claims to describe::
#:
#:     /* 60 00000000 F0FFBD27 */  addiu $sp, $sp, -0x10
_LISTING_WORD = re.compile(
    r"^\s*/\*\s*([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]{8})\s*\*/"
)
#: The structural lines the disassembler emits beside the decoded words.
_LISTING_STRUCTURE = re.compile(
    r"^\s*(?:\.\w+|(?:glabel|endlabel|alabel|dlabel|jlabel|enddlabel|ehlabel|"
    r"nonmatching)\b)"
)
#: A listing that disagrees with the file can disagree thousands of times; the
#: report says so once and stops.
LISTING_ISSUE_LIMIT = 16


@dataclass(frozen=True)
class ListingWord:
    """One decoded word of a splat listing.

    ``data`` holds the four bytes exactly as the listing prints them, i.e. in the
    order they occupy in the file; ``word`` is the value those bytes carry when
    read the way the CPU reads them.
    """

    file_offset: int
    address: int
    data: bytes

    @property
    def word(self) -> int:
        return int.from_bytes(self.data, "little")


def parse_listing(text: str, label: str) -> tuple[ListingWord, ...]:
    """Extract the (file offset, address, word) triples of a splat listing.

    Every line that is neither structural nor a well-formed decoded word raises
    :class:`~seto.binio.ParseError`: a listing Seto cannot read in full is not a
    listing it may trust, and silently skipping a line could hide a word.
    """
    entries: list[ListingWord] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("/*"):
            match = _LISTING_WORD.match(line)
            if match is not None and line[match.end() :].strip():
                entries.append(
                    ListingWord(
                        file_offset=int(match.group(1), 16),
                        address=int(match.group(2), 16),
                        data=bytes.fromhex(match.group(3)),
                    )
                )
                continue
            if stripped.endswith("*/"):
                # A standalone comment (the disassembler header) carries no word.
                continue
            raise ParseError(f"{label}:{number}: unrecognised listing line: {stripped!r}")
        if not _LISTING_STRUCTURE.match(line):
            raise ParseError(f"{label}:{number}: unrecognised listing line: {stripped!r}")
    return tuple(entries)


def verify_listing(
    entries: tuple[ListingWord, ...],
    original: bytes,
    *,
    label: str,
    address: int,
    file_offset: int,
    size: int,
) -> tuple[LayoutIssue, ...]:
    """Check a listing against the bytes it claims to describe.

    Three things make a listing usable, and all three are checked: each address
    maps to the file offset the layout predicts, the word the listing prints is
    byte-identical to the file, and the listing covers the segment exactly -
    neither a gap, nor an overlap, nor a truncated tail.
    """
    issues: list[LayoutIssue] = []

    def report(message: str) -> None:
        if len(issues) < LISTING_ISSUE_LIMIT:
            issues.append(LayoutIssue(ERROR, f"{label}: {message}"))

    if not entries:
        report("the listing decodes no word")
        return tuple(issues)

    if entries[0].address != address:
        report(
            f"the listing starts at 0x{entries[0].address:x}, "
            f"but the segment starts at 0x{address:x}"
        )
    for position, entry in enumerate(entries):
        shifted = entry.file_offset - file_offset
        if shifted != entry.address - address:
            report(
                f"0x{entry.address:x} is listed at file offset 0x{entry.file_offset:x}, "
                f"which is {shifted - (entry.address - address):+d} bytes off the layout"
            )
            continue
        if entry.file_offset < 0 or entry.file_offset + 4 > len(original):
            report(f"0x{entry.address:x} is listed outside the file")
            continue
        real = original[entry.file_offset : entry.file_offset + 4]
        if real != entry.data:
            report(
                f"0x{entry.address:x} is listed as {entry.data.hex()} but the file holds "
                f"{real.hex()} at 0x{entry.file_offset:x}"
            )
        if position and entry.address != entries[position - 1].address + 4:
            report(
                f"0x{entry.address:x} does not follow 0x{entries[position - 1].address:x} "
                "contiguously"
            )

    covered = entries[-1].address + 4 - address
    if covered != size:
        report(
            f"the listing covers 0x{max(covered, 0):x} of 0x{size:x} bytes"
        )
    return tuple(issues)


@dataclass(frozen=True)
class VerifiedListing:
    """One listing splat wrote, and how much of it was checked."""

    name: str
    words: int
    issues: tuple[LayoutIssue, ...]

    @property
    def verified(self) -> bool:
        return not self.issues


def verify_splat_output(
    layout: Layout,
    original: bytes,
    asm_dir: str | Path,
) -> tuple[VerifiedListing, ...]:
    """Read and verify every assembly listing splat wrote for ``layout``.

    This is the one place the produced listings are judged, so a caller only has
    to decide what to do with the result: ``seto split --run-splat`` prints it,
    and the splat smoke test turns it into a capability.  A listing that is
    missing, unreadable or disagrees with the original bytes is an issue - never
    a silent success.
    """
    directory = Path(asm_dir)
    results: list[VerifiedListing] = []
    for segment in layout.segments:
        if segment.type != CODE_TYPE:
            continue
        for subsegment in segment.subsegments:
            if subsegment.kind != ASM_KIND:
                continue
            path = directory / f"{subsegment.name}.s"
            if not path.is_file():
                results.append(
                    VerifiedListing(
                        path.name,
                        0,
                        (LayoutIssue(ERROR, f"splat did not write {path}"),),
                    )
                )
                continue
            address = segment.vram + (subsegment.offset - segment.start)
            try:
                entries = parse_listing(
                    path.read_text(encoding="utf-8", errors="replace"), str(path)
                )
            except ParseError as exc:
                results.append(
                    VerifiedListing(path.name, 0, (LayoutIssue(ERROR, str(exc)),))
                )
                continue
            results.append(
                VerifiedListing(
                    path.name,
                    len(entries),
                    verify_listing(
                        entries,
                        original,
                        label=str(path),
                        address=address,
                        file_offset=subsegment.offset,
                        size=subsegment.size,
                    ),
                )
            )
    return tuple(results)
