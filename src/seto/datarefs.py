"""Conservative canonical identities for MIPS data references.

An ELF relocation's ``target_section`` is the section *where the relocation is
applied*. This module resolves the destination separately, and only calls it a
``DataTarget`` when a symbol plus addend, or an unambiguous linked address, maps
to a byte range in exactly one allocated section. Load addresses, file offsets,
section virtual addresses and symbol-relative offsets are never conflated.

A ``DataTarget`` is a *location*, not an identity: ``(.data, 0x20)`` in two
independent files does not name the same object. Comparison therefore uses a
:class:`DataIdentity`, which carries the artifact a location was resolved in, and
a :class:`SymbolLink` states - explicitly, and only with evidence - which
original location a candidate symbol names.

The resolver deliberately does not infer section identities from address-like
symbol names, a PT_LOAD span, or a zero-sized ``.bss`` section.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from seto.elf import ET_REL, R_MIPS_32, R_MIPS_HI16, R_MIPS_LO16, ElfFile, Relocation, Section, Symbol


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


@dataclass(frozen=True)
class DataIdentity:
    """A location *plus* the artifact it was resolved in.

    ``DataTarget`` on its own is only a location: the same section name and
    offset in two independent files do not name the same object. An identity
    records the artifact, so the comparator can refuse to treat two different
    coordinate systems as one.
    """

    artifact: str
    target: DataTarget

    def summary(self) -> dict[str, str]:
        return {"artifact": self.artifact, **self.target.summary()}


#: A resolver that answers with an artifact-qualified identity, or ``None`` when
#: the evidence is insufficient. It must never answer with a bare location.
DataIdentityResolver = Callable[[RelocationLike, int], "DataIdentity | None"]


def module_resolver(
    module: ElfFile,
    artifact: str,
    *,
    symbols: Sequence[Symbol] = (),
    explicit_targets: Mapping[str, DataTarget] | None = None,
) -> DataIdentityResolver:
    """Resolve references in ``module``'s *own* coordinate system."""

    def resolve(site: RelocationLike, addend: int) -> DataIdentity | None:
        target = resolve_data_target(
            site, symbols, module, addend=addend, explicit_targets=explicit_targets
        )
        if target is None:
            return None
        return DataIdentity(artifact, target)

    return resolve


@dataclass(frozen=True)
class SymbolLink:
    """An explicit, evidence-backed candidate-symbol -> original-location map.

    A candidate object's own ``(section, offset)`` is in the candidate's
    coordinates and proves nothing about the original module. A candidate
    reference may be compared only after a link states which *original* location
    its symbol names, and that link has to rest on independent evidence - an
    original symbol, linking information, or a validated mapping - never on the
    candidate's own section name and offset.
    """

    entries: Mapping[str, DataTarget]
    evidence: tuple[str, ...] = ()

    def original_for(self, symbol: str | None, addend: int) -> DataTarget | None:
        if symbol is None:
            return None
        base = self.entries.get(symbol)
        if base is None:
            return None
        return DataTarget(base.section, base.offset + _signed32(addend))

    def resolver(self, module: ElfFile, artifact: str) -> DataIdentityResolver:
        """Answer in the *original* module's coordinates, or stay unresolved."""

        def resolve(site: RelocationLike, addend: int) -> DataIdentity | None:
            target = self.original_for(site.symbol, addend)
            if target is None:
                return None
            section = module.section(target.section)
            if section is None or _section_target(section, target.offset) != target:
                return None
            return DataIdentity(artifact, target)

        return resolve


#: The target lies in exactly one allocated ELF section: its location is proven.
PROVEN = "PROVEN"
#: The target lies in the module's load image (a PT_LOAD span) but not in any
#: named ELF section, so only its offset inside that segment can be stated.
INFERRED = "INFERRED"
#: No section and no segment contains the combined addend.
UNKNOWN = "UNKNOWN"
#: The reference has no HI16/LO16 pairing to judge (a plain ``R_MIPS_32``).
NOT_APPLICABLE = "NOT_APPLICABLE"


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
    """Separate the numeric *location* confidence from the pairing confidence."""
    target = _address_target(module, combined & 0xFFFFFFFF)
    if target is not None:
        return target, None, PROVEN
    location = load_location(module, combined & 0xFFFFFFFF)
    if location is not None:
        return None, location, INFERRED
    return None, None, UNKNOWN


def _overall_status(pairing: str, location: str) -> str:
    """The single confidence of a reference, from the two axes it rests on.

    A proven location is not enough on its own: a HI16/LO16 pair associated only
    by relocation order has a plausible combined addend but no proven pairing, so
    the reference cannot be ``PROVEN``.
    """
    if pairing == NOT_APPLICABLE:
        return location
    if pairing == PROVEN and location == PROVEN:
        return PROVEN
    if pairing == UNKNOWN or location == UNKNOWN:
        return UNKNOWN
    return INFERRED


def _unresolved_reason(pairing: str, location: str) -> str:
    reasons: list[str] = []
    if pairing == INFERRED:
        reasons.append("HI16/LO16 association rests on relocation order only")
    if location == INFERRED:
        reasons.append("destination is only in a load segment, not a named section")
    elif location == UNKNOWN:
        reasons.append("destination is outside every section and load segment")
    return "; ".join(reasons) or "insufficient evidence"


@dataclass(frozen=True)
class RelocationEvidence:
    """One relocation behind a reference, with the raw fields it was read from.

    A report has to be auditable without re-parsing the file, so every field the
    format defines is kept: which table and format the entry came from, the raw
    ``r_offset``/``r_info`` pair, the segment indices ``r_info`` packs, where the
    entry is applied, and the addend the caller combined.  ``site`` is the module
    address the loader patches; ``application`` names the section and offset.
    """

    type: str
    format: str
    site: int
    application_section: str | None
    application_offset: int | None
    raw_offset: int
    raw_info: int
    segment_index: int
    relative_index: int
    source_section: str | None
    addend: int

    @property
    def application(self) -> str | None:
        if self.application_section is None or self.application_offset is None:
            return None
        return f"{self.application_section}+0x{self.application_offset:x}"

    def summary(self) -> dict[str, object]:
        return {
            "type": self.type,
            "format": self.format,
            "site": f"0x{self.site:x}",
            "application": self.application,
            "source_section": self.source_section,
            "raw_offset": f"0x{self.raw_offset:x}",
            "raw_info": f"0x{self.raw_info:08x}",
            "segment_index": self.segment_index,
            "relative_index": self.relative_index,
            "addend": f"0x{self.addend & 0xFFFFFFFF:08x}",
        }


def relocation_evidence(relocation: Relocation) -> RelocationEvidence:
    """Project a parsed relocation onto the report's evidence shape."""
    return RelocationEvidence(
        type=relocation.type_name,
        format=relocation.format,
        site=relocation.offset,
        application_section=relocation.target_section,
        application_offset=relocation.section_offset,
        raw_offset=relocation.raw_offset,
        raw_info=relocation.info,
        segment_index=relocation.segment_index,
        relative_index=relocation.relative_index,
        source_section=relocation.source_section,
        addend=relocation.addend,
    )


@dataclass(frozen=True)
class DataReference:
    """One data reference recovered from a function's relocation table.

    Three confidences are kept apart: ``pairing`` (was the HI16/LO16 pair
    established by evidence, or only by relocation order), ``location`` (is the
    numeric destination in one named section, only in a load segment, or
    nowhere), and ``status`` (the overall confidence, ``PROVEN`` only when both
    are). A location inside ``.data`` does not make an order-only pair complete.
    """

    instruction: int
    kind: str
    relocations: tuple[RelocationEvidence, ...]
    addends: tuple[int, ...]
    combined: int
    target: DataTarget | None
    load: LoadLocation | None
    pairing: str
    location: str
    status: str
    evidence: str
    unresolved: str | None = None

    def summary(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "instruction": f"0x{self.instruction:x}",
            "kind": self.kind,
            "relocations": [item.summary() for item in self.relocations],
            "raw_addends": [f"0x{value & 0xFFFFFFFF:08x}" for value in self.addends],
            "combined_addend": f"0x{self.combined & 0xFFFFFFFF:08x}",
            "target": None if self.target is None else self.target.summary(),
            "pairing": self.pairing,
            "location": self.location,
            "status": self.status,
            "evidence": self.evidence,
            "unresolved": self.unresolved,
        }
        if self.load is not None:
            payload["load_segment"] = self.load.segment
            payload["load_offset"] = f"0x{self.load.offset:x}"
            payload["initialized"] = self.load.initialized
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

    An unpaired ``R_MIPS_LO16`` is reported too, as an incomplete reference: it is
    never silently dropped, so the report and the exit code can tell that a
    relocation was left unresolved.
    """
    # Imported lazily: ``seto.matching`` imports ``DataTarget`` from this module,
    # so a module-level import would be circular.
    from seto.matching import combine_hi16_lo16, pair_hi16_lo16, relocation_sites

    section = module.require_section(section_name)
    region_offset = start - section.addr
    section_relocations = module.relocations_for(section_name)
    mapping = relocation_sites(section_relocations, region_offset, end - start)
    sites = mapping.sites
    pairing = pair_hi16_lo16(sites)
    paired_low = set(pairing.hi_to_lo.values())

    evidence_by_offset = {
        relocation.section_offset: relocation
        for relocation in section_relocations
        if relocation.section_offset is not None
    }

    def evidence_for(word_index: int) -> RelocationEvidence:
        return relocation_evidence(evidence_by_offset[region_offset + word_index * 4])

    def order_only(hi_index: int, low_index: int) -> bool:
        # ``pair_hi16_lo16`` records the order-only note at the LO16's word index.
        return any(
            item.startswith(f"word {index}: HI16/LO16 association relies on relocation order")
            for index in (hi_index, low_index)
            for item in pairing.limitations
        )

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
                        relocations=(evidence_for(word_index),),
                        addends=(site.addend,),
                        combined=site.addend,
                        target=None,
                        load=None,
                        pairing=UNKNOWN,
                        location=UNKNOWN,
                        status=UNKNOWN,
                        evidence=f"ELF {site.type_name} has no LO16 to resolve it",
                        unresolved="no LO16 partner closes this HI16",
                    )
                )
                continue
            low = sites[low_index]
            low_instruction = region_offset + low_index * 4
            combined = combine_hi16_lo16(site.addend, low.addend)
            target, load, location = _classify(module, combined)
            pairing_status = INFERRED if order_only(word_index, low_index) else PROVEN
            status = _overall_status(pairing_status, location)
            note = (
                "pairing rests on relocation order only"
                if pairing_status == INFERRED
                else "pairing rests on symbol identity"
            )
            references.append(
                DataReference(
                    instruction=low_instruction,
                    kind="hi16-lo16",
                    relocations=(
                        evidence_for(word_index),
                        evidence_for(low_index),
                    ),
                    addends=(site.addend, low.addend),
                    combined=combined,
                    target=target,
                    load=load,
                    pairing=pairing_status,
                    location=location,
                    status=status,
                    evidence=(
                        f"ELF {site.type_name}+{low.type_name} pair; "
                        f"combined addend 0x{combined:08x}; {note}"
                    ),
                    unresolved=(
                        None if status == PROVEN else _unresolved_reason(pairing_status, location)
                    ),
                )
            )
            continue
        if site.type == R_MIPS_LO16:
            if word_index in paired_low:
                continue  # already reported as part of its HI16/LO16 pair
            references.append(
                DataReference(
                    instruction=instruction,
                    kind="lo16",
                    relocations=(evidence_for(word_index),),
                    addends=(site.addend,),
                    combined=site.addend,
                    target=None,
                    load=None,
                    pairing=UNKNOWN,
                    location=UNKNOWN,
                    status=UNKNOWN,
                    evidence=f"ELF {site.type_name} has no HI16 to complete it",
                    unresolved="no HI16 is associated with this LO16",
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
            load = None
            location = PROVEN if target is not None else UNKNOWN
            if target is None:
                load = load_location(module, site.addend & 0xFFFFFFFF)
                if load is not None:
                    location = INFERRED
            status = _overall_status(NOT_APPLICABLE, location)
            references.append(
                DataReference(
                    instruction=instruction,
                    kind="r_mips_32",
                    relocations=(evidence_for(word_index),),
                    addends=(site.addend,),
                    combined=site.addend,
                    target=target,
                    load=load,
                    pairing=NOT_APPLICABLE,
                    location=location,
                    status=status,
                    evidence=f"ELF {site.type_name} in-place addend",
                    unresolved=(
                        None if status == PROVEN else _unresolved_reason(NOT_APPLICABLE, location)
                    ),
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
    """Assemble the deterministic per-function reference report.

    The report carries the module's relocation-format inventory next to the
    references: an unknown or undecodable relocation has to be a *result*, not a
    silence, so a reader can see whether the table was understood completely.
    """
    from seto.psp_reloc import psp_inventory

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
    return {
        "section": section_name,
        "relocation_inventory": psp_inventory(module),
        "functions": entries,
    }


__all__ = [
    "INFERRED",
    "NOT_APPLICABLE",
    "PROVEN",
    "UNKNOWN",
    "DataIdentity",
    "DataIdentityResolver",
    "DataReference",
    "DataTarget",
    "LoadLocation",
    "RelocationEvidence",
    "RelocationLike",
    "SymbolLink",
    "build_reference_report",
    "data_target_details",
    "load_location",
    "module_resolver",
    "recover_references",
    "relocation_evidence",
    "resolve_data_target",
]
