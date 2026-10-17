"""Conservative canonical identities for MIPS data references.

An ELF relocation's ``target_section`` is the section *where the relocation is
applied*. This module resolves the destination separately, and only calls it a
``DataTarget`` when a symbol plus addend, or an unambiguous linked address, maps
to a byte range in exactly one allocated section. Load addresses, file offsets,
section virtual addresses and symbol-relative offsets are never conflated.

The resolver deliberately does not infer section identities from address-like
symbol names, a PT_LOAD span, or a zero-sized ``.bss`` section.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from seto.elf import ET_REL, R_MIPS_32, R_MIPS_HI16, R_MIPS_LO16, ElfFile, Section, Symbol


class RelocationLike(Protocol):
    """The relocation attributes needed for target resolution."""

    type: int
    symbol_index: int
    symbol: str | None
    addend: int


@dataclass(frozen=True, order=True)
class DataTarget:
    """A byte identity in one allocated section of a module."""

    section: str
    offset: int

    def summary(self) -> dict[str, str | int]:
        return {"section": self.section, "offset": f"0x{self.offset:x}"}


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _section_target(section: Section, offset: int) -> DataTarget | None:
    """Return a section-relative identity only for an addressable byte."""
    if not section.is_allocated or not 0 <= offset < section.size:
        return None
    return DataTarget(section.name, offset)


def _address_target(module: ElfFile, address: int) -> DataTarget | None:
    matches = [
        section
        for section in module.sections
        if section.is_allocated and section.contains_address(address)
    ]
    if len(matches) != 1:
        return None
    section = matches[0]
    return _section_target(section, address - section.addr)


def resolve_data_target(
    relocation: RelocationLike,
    symbol_table: Sequence[Symbol],
    module_layout: ElfFile,
    *,
    addend: int | None = None,
    explicit_targets: Mapping[str, DataTarget] | None = None,
) -> DataTarget | None:
    """Resolve a data relocation to a canonical ``(section, offset)`` target.

    For an ``ET_REL`` symbol defined in a section, the symbol's section-relative
    value plus the in-place addend identifies the target. A caller may explicitly
    map an *undefined* symbol only when it has independent evidence for that
    mapping; the addend is applied to the mapped offset, not discarded.

    For a stripped linked module with no symbol, the addend is treated as an ELF
    virtual address and resolved only when exactly one allocated ELF section
    contains it. ``R_MIPS_HI16``/``LO16`` callers must provide the combined pair
    addend. Unmapped load-segment addresses and zero-sized ``SHT_NOBITS`` targets
    stay unresolved. No file bytes are read here.
    """
    if relocation.type not in (R_MIPS_32, R_MIPS_HI16, R_MIPS_LO16):
        return None
    if relocation.type in (R_MIPS_HI16, R_MIPS_LO16) and addend is None:
        return None

    raw_addend = relocation.addend if addend is None else addend
    signed_addend = _signed32(raw_addend)
    symbols_by_index = {symbol.index: symbol for symbol in symbol_table}
    symbol = symbols_by_index.get(relocation.symbol_index) if relocation.symbol_index else None
    sections_by_index = {section.index: section for section in module_layout.sections}

    if symbol is not None and symbol.is_defined:
        section = sections_by_index.get(symbol.shndx)
        if section is None:
            return None
        if module_layout.header.e_type == ET_REL:
            target_offset = symbol.value + signed_addend
        else:
            target_offset = symbol.value + signed_addend - section.addr
        return _section_target(section, target_offset)

    explicit = explicit_targets or {}
    symbol_name = relocation.symbol or (symbol.name if symbol is not None else None)
    if symbol_name is not None:
        base = explicit.get(symbol_name)
        if base is None:
            return None
        section = module_layout.section(base.section)
        if section is None:
            return None
        return _section_target(section, base.offset + signed_addend)

    # ET_REL's symbol index zero is SHN_UNDEF. A numeric addend alone does not
    # establish which section an object-file reference names.
    if module_layout.header.e_type == ET_REL or relocation.symbol_index != 0:
        return None
    return _address_target(module_layout, raw_addend & 0xFFFFFFFF)


def data_target_details(module: ElfFile, target: DataTarget) -> dict[str, object] | None:
    """Describe the target in ELF, file, and PT_LOAD coordinates when known."""
    section = module.section(target.section)
    if section is None or _section_target(section, target.offset) != target:
        return None
    elf_address = section.addr + target.offset
    file_offset = None if section.is_nobits else section.offset + target.offset
    segments = [
        segment
        for segment in module.segments
        if segment.vaddr <= elf_address < segment.vaddr + segment.memsz
    ]
    segment_index = segments[0].index if len(segments) == 1 else None
    return {
        **target.summary(),
        "elf_virtual_address": f"0x{elf_address:x}",
        "file_offset": None if file_offset is None else f"0x{file_offset:x}",
        "section_type": "SHT_NOBITS" if section.is_nobits else "file-backed",
        "load_segment": segment_index,
    }


#: The target lies in exactly one allocated ELF section: its identity is proven.
PROVEN = "PROVEN"
#: The target lies in the module's load image (a PT_LOAD span) but not in any
#: named ELF section, so only its offset inside that segment can be stated.
INFERRED = "INFERRED"
#: No section and no segment contains the combined addend.
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LoadLocation:
    """Where a combined addend lands inside the module's load image."""

    segment: int
    offset: int
    initialized: bool


def load_location(module: ElfFile, address: int) -> LoadLocation | None:
    """Locate a raw address in exactly one PT_LOAD span, or return ``None``.

    ``initialized`` is false past ``p_filesz`` (the zero-filled tail). The ELF
    section headers are *not* consulted: this only states where the byte is in
    the loaded image, which is weaker evidence than a named section.
    """
    matches = [
        segment
        for segment in module.segments
        if segment.vaddr <= address < segment.vaddr + segment.memsz
    ]
    if len(matches) != 1:
        return None
    segment = matches[0]
    offset = address - segment.vaddr
    return LoadLocation(segment.index, offset, offset < segment.filesz)


def _classify(
    module: ElfFile, combined: int
) -> tuple[DataTarget | None, LoadLocation | None, str]:
    target = _address_target(module, combined & 0xFFFFFFFF)
    if target is not None:
        return target, None, PROVEN
    location = load_location(module, combined & 0xFFFFFFFF)
    if location is not None:
        return None, location, INFERRED
    return None, None, UNKNOWN


@dataclass(frozen=True)
class DataReference:
    """One data reference recovered from a function's relocation table."""

    instruction: int
    kind: str
    relocations: tuple[tuple[str, int], ...]
    addends: tuple[int, ...]
    combined: int
    target: DataTarget | None
    location: LoadLocation | None
    status: str
    evidence: str

    def summary(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "instruction": f"0x{self.instruction:x}",
            "kind": self.kind,
            "relocations": [
                {"type": name, "site": f"0x{site:x}"} for name, site in self.relocations
            ],
            "raw_addends": [f"0x{value & 0xFFFFFFFF:08x}" for value in self.addends],
            "combined_addend": f"0x{self.combined & 0xFFFFFFFF:08x}",
            "target": None if self.target is None else self.target.summary(),
            "status": self.status,
            "evidence": self.evidence,
        }
        if self.location is not None:
            payload["load_segment"] = self.location.segment
            payload["load_offset"] = f"0x{self.location.offset:x}"
            payload["initialized"] = self.location.initialized
        return payload


def recover_references(
    module: ElfFile,
    section_name: str,
    start: int,
    end: int,
    *,
    symbols: Sequence[Symbol] = (),
    explicit_targets: Mapping[str, DataTarget] | None = None,
) -> tuple[DataReference, ...]:
    """Recover every data reference inside ``[start, end)`` of ``section_name``.

    The pairing and combined-address semantics come from the comparator itself
    (:func:`seto.matching.pair_hi16_lo16` / ``combine_hi16_lo16``), so a reference
    reported here is the same one the comparator would compare. Calls
    (``R_MIPS_26``) are deliberately left to the import resolver.
    """
    # Imported lazily: ``seto.matching`` imports ``DataTarget`` from this module,
    # so a module-level import would be circular.
    from seto.matching import combine_hi16_lo16, pair_hi16_lo16, relocation_sites

    section = module.require_section(section_name)
    region_offset = start - section.addr
    mapping = relocation_sites(module.relocations_for(section_name), region_offset, end - start)
    sites = mapping.sites
    pairing = pair_hi16_lo16(sites)

    def order_only(word_index: int) -> bool:
        prefix = f"word {word_index}: HI16/LO16 association relies on relocation order"
        return any(item.startswith(prefix) for item in pairing.limitations)

    references: list[DataReference] = []
    for word_index in sorted(sites):
        site = sites[word_index]
        instruction = region_offset + word_index * 4
        if site.type == R_MIPS_HI16:
            low_index = pairing.hi_to_lo.get(word_index)
            if low_index is None:
                references.append(
                    DataReference(
                        instruction=instruction,
                        kind="hi16",
                        relocations=((site.type_name, instruction),),
                        addends=(site.addend,),
                        combined=site.addend,
                        target=None,
                        location=None,
                        status=UNKNOWN,
                        evidence="HI16 relocation without a resolvable LO16 partner",
                    )
                )
                continue
            low = sites[low_index]
            low_instruction = region_offset + low_index * 4
            combined = combine_hi16_lo16(site.addend, low.addend)
            target, location, status = _classify(module, combined)
            note = ", association relies on relocation order" if order_only(word_index) else ""
            references.append(
                DataReference(
                    instruction=low_instruction,
                    kind="hi16-lo16",
                    relocations=(
                        (site.type_name, instruction),
                        (low.type_name, low_instruction),
                    ),
                    addends=(site.addend, low.addend),
                    combined=combined,
                    target=target,
                    location=location,
                    status=status,
                    evidence=(
                        f"ELF {site.type_name}+{low.type_name} pair; "
                        f"combined addend 0x{combined:08x}{note}"
                    ),
                )
            )
            continue
        if site.type == R_MIPS_32:
            target = resolve_data_target(
                site,
                symbols,
                module,
                addend=site.addend,
                explicit_targets=explicit_targets,
            )
            location = None
            status = PROVEN if target is not None else UNKNOWN
            if target is None:
                location = load_location(module, site.addend & 0xFFFFFFFF)
                if location is not None:
                    status = INFERRED
            references.append(
                DataReference(
                    instruction=instruction,
                    kind="r_mips_32",
                    relocations=((site.type_name, instruction),),
                    addends=(site.addend,),
                    combined=site.addend,
                    target=target,
                    location=location,
                    status=status,
                    evidence=f"ELF {site.type_name} in-place addend",
                )
            )
    return tuple(references)


def build_reference_report(
    module: ElfFile,
    section_name: str,
    functions: Sequence[tuple[str, int, int]],
    *,
    symbols: Sequence[Symbol] = (),
    explicit_targets: Mapping[str, DataTarget] | None = None,
) -> dict[str, object]:
    """Assemble the deterministic per-function reference report."""
    entries: list[dict[str, object]] = []
    for name, start, end in functions:
        references = recover_references(
            module,
            section_name,
            start,
            end,
            symbols=symbols,
            explicit_targets=explicit_targets,
        )
        entries.append(
            {
                "function": name,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "references": [reference.summary() for reference in references],
            }
        )
    return {"section": section_name, "functions": entries}


__all__ = [
    "INFERRED",
    "PROVEN",
    "UNKNOWN",
    "DataReference",
    "DataTarget",
    "LoadLocation",
    "RelocationLike",
    "build_reference_report",
    "data_target_details",
    "load_location",
    "recover_references",
    "resolve_data_target",
]
