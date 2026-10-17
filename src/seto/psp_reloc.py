"""PSP relocation-section semantics (``SHT_PSPREL``, PPSSPP's ``SHT_PRXRELOC``).

A PSP PRX does not relocate through the ELF symbol table.  Its relocation
sections carry ``sh_type = 0x700000A0`` and hold plain 8-byte ``Elf32_Rel``
entries whose ``r_info`` packs three fields::

    bits  0..3    relocation type (``R_MIPS_*``)
    bits  8..15   the segment the relocated word lives in
    bits 16..23   the segment whose load base is added ("relative" segment)

``r_offset`` is an offset *inside* the segment named by bits 8..15, so the byte
the loader patches is ``segments[segment].vaddr + r_offset``.  Bits 8..15 are
**not** a symbol index, and a section of this type must never be read with the
standard ``SHT_REL`` layout.  ``seto.elf`` keeps the raw fields (``info``,
``segment_index``, ``relative_index``, ``format``) and this module gives them
their PSP meaning.

Only the fixed-width form is modelled.  A module may instead compress its
relocations into a ``PT_PSPREL1``/``PT_PSPREL2`` segment; this module *reports*
such a payload and refuses to decode it, because the analysed module has none and
an untested decoder would be a liability.

Nothing here writes into an image: the helpers compute values and return
evidence, so a caller can audit every step.  The format is documented from
PPSSPP's ``ElfReader::LoadRelocations`` (GPL-2.0-or-later); only the documented
*layout* is reproduced here, not its code.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from seto.elf import (
    PT_LOAD,
    R_MIPS_26,
    R_MIPS_32,
    R_MIPS_HI16,
    R_MIPS_LO16,
    R_MIPS_NONE,
    RELOCATION_TYPE_NAMES,
    SHT_MIPS_PSPREL,
    SHT_MIPS_PSPREL2,
    SHT_REL,
    WORD_SIZE,
    ElfFile,
    Relocation,
    Segment,
    decode_psp_relocation_info,
    relocation_type_name,
)

#: ``sh_type`` of a PSP relocation table (fixed 8-byte entries).
SHT_PSPREL = SHT_MIPS_PSPREL
#: ``sh_type`` of a compressed PSP relocation table (not decoded here).
SHT_PSPREL2 = SHT_MIPS_PSPREL2

#: ``p_type`` of a segment that carries a compressed relocation payload.
PT_PSPREL1 = 0x700000A0
PT_PSPREL2 = 0x700000A1

R_MIPS_GPREL16 = 7
_SUPPORTED_TYPES = frozenset(
    (R_MIPS_NONE, R_MIPS_32, R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_GPREL16)
)


@dataclass(frozen=True)
class PspInfo:
    """The three fields a PSP ``r_info`` packs."""

    type: int
    segment_index: int
    relative_index: int
    reserved: int = 0

    def summary(self) -> dict[str, object]:
        return {
            "type": relocation_type_name(self.type),
            "segment_index": self.segment_index,
            "relative_index": self.relative_index,
            "reserved": f"0x{self.reserved:08x}",
        }


def decode_info(info: int) -> PspInfo:
    """Split a raw PSP ``r_info`` into type, segment and relative segment.

    The type is masked with 4 bits (as the loader does), so a type that needs
    more than 4 bits cannot be silently produced by a stray high bit.
    """
    rel_type, segment_index, relative_index, reserved = decode_psp_relocation_info(info)
    return PspInfo(rel_type, segment_index, relative_index, reserved)


def _sign_extend_16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def segment_runtime_address(segment: Segment, load_base: int) -> int:
    """Map a segment's ELF virtual address into runtime coordinates.

    ``p_vaddr`` is module-relative; ``load_base`` is an explicit runtime base.
    The result is not inferred from the file and is checked instead of silently
    wrapping on overflow.
    """
    if segment.type != PT_LOAD:
        raise ValueError(f"segment {segment.index} is not PT_LOAD")
    if not 0 <= load_base <= 0xFFFFFFFF:
        raise ValueError("load_base must be an unsigned 32-bit address")
    address = load_base + segment.vaddr
    if address > 0xFFFFFFFF:
        raise ValueError("runtime segment address overflows 32 bits")
    return address


def relative_base(
    module: ElfFile, relocation: Relocation, *, load_base: int = 0
) -> int | None:
    """Return the explicit runtime address used by a relocation's relative segment.

    ``None`` means the segment index is absent or not loadable; callers must not
    reinterpret the raw ``r_offset`` as a resolved destination. ``load_base=0``
    models module-relative arithmetic only; it does not claim a real PSP runtime
    load address.
    """
    index = relocation.relative_index
    if index >= len(module.segments):
        return None
    segment = module.segments[index]
    if segment.type != PT_LOAD:
        return None
    return segment_runtime_address(segment, load_base)


def apply_relocation(
    rel_type: int,
    word: int,
    base: int,
    *,
    lo16_word: int | None = None,
) -> int | None:
    """The word the PSP loader writes for a modeled relocation, or ``None`` otherwise.

    ``word`` is the in-file value at the relocated address and ``base`` the
    runtime address of the loader's relative segment (see :func:`relative_base`).
    ``R_MIPS_HI16``
    needs the paired ``R_MIPS_LO16`` word, because the low half carries the sign
    that the high half must absorb; without it the answer is ``None`` rather than
    a guess.  An unrecognised type is also ``None``: this function never invents
    a value for a relocation it does not model.
    """
    word &= 0xFFFFFFFF
    base &= 0xFFFFFFFF
    if rel_type == R_MIPS_NONE or rel_type == R_MIPS_GPREL16:
        # The loader leaves these words alone (a GPREL16 is a notification).
        return word
    if rel_type == R_MIPS_32:
        return (word + base) & 0xFFFFFFFF
    if rel_type == R_MIPS_26:
        return (word & 0xFC000000) | (((word & 0x03FFFFFF) + (base >> 2)) & 0x03FFFFFF)
    if rel_type == R_MIPS_LO16:
        return (word & 0xFFFF0000) | (((word & 0xFFFF) + base) & 0xFFFF)
    if rel_type == R_MIPS_HI16:
        if lo16_word is None:
            return None
        combined = (
            ((word & 0xFFFF) << 16) + _sign_extend_16(lo16_word) + base
        ) & 0xFFFFFFFF
        # MIPS HI16/LO16 pairs encode a signed low half.  Round before taking
        # the high half so the LUI absorbs the carry when LO16 has bit 15 set.
        return (word & 0xFFFF0000) | (((combined + 0x8000) >> 16) & 0xFFFF)
    return None


def _type_counts(relocations: list[Relocation]) -> dict[str, int]:
    counts = Counter(relocation_type_name(item.type) for item in relocations)
    return {name: counts[name] for name in sorted(counts)}


def psp_inventory(module: ElfFile) -> dict[str, object]:
    """A deterministic audit of the relocation formats a module actually uses.

    It answers the questions a reader must not assume: which relocation section
    types are present, how their ``r_info`` fields decode, which segments they
    name, whether a compressed payload exists, and whether any entry names a
    segment the file cannot back.  Nothing is summarised away: every count is
    derived from the parsed entries.
    """
    psp = [item for item in module.relocations if item.format == "PSP"]
    other = [item for item in module.relocations if item.format != "PSP"]

    by_section: dict[str, list[Relocation]] = {
        section.name: []
        for section in module.sections
        if section.type == SHT_PSPREL
    }
    for item in psp:
        by_section.setdefault(item.source_section or "?", []).append(item)

    sections = []
    for name in sorted(by_section):
        entries = by_section[name]
        sections.append(
            {
                "name": name,
                "entries": len(entries),
                "types": _type_counts(entries),
                "segment_indices": sorted({item.segment_index for item in entries}),
                "relative_indices": sorted({item.relative_index for item in entries}),
                "targets": sorted({item.target_section for item in entries if item.target_section}),
            }
        )

    segment_counts = Counter(item.segment_index for item in psp)
    relative_counts = Counter(item.relative_index for item in psp)
    unknown = sorted(
        {
            relocation_type_name(item.type)
            for item in module.relocations
            if item.type not in RELOCATION_TYPE_NAMES
        }
    )
    unsupported = sorted(
        {
            relocation_type_name(item.type)
            for item in module.relocations
            if item.type not in _SUPPORTED_TYPES
        }
    )

    formats = sorted({item.format for item in module.relocations})
    section_formats = {
        "PSP" for section in module.sections if section.type == SHT_PSPREL
    } | {
        "PSP2" for section in module.sections if section.type == SHT_PSPREL2
    } | {
        "REL" for section in module.sections if section.type == SHT_REL
    }
    formats = sorted(set(formats) | section_formats)
    compressed = sorted(
        section.name for section in module.sections if section.type == SHT_PSPREL2
    )
    payloads = sorted(
        segment.index
        for segment in module.segments
        if segment.type in (PT_PSPREL1, PT_PSPREL2)
    )

    # A nonzero relative p_vaddr must be added in module coordinates. The actual
    # runtime load_base is a separate caller input and is never inferred here.
    relative_vaddrs = [
        item.relative_index
        for item in psp
        if item.relative_index < len(module.segments)
        and module.segments[item.relative_index].type == PT_LOAD
        and module.segments[item.relative_index].vaddr != 0
    ]

    invalid_entries = [
        {
            "source_section": item.source_section,
            "type": item.type_name,
            "raw_offset": f"0x{item.raw_offset:x}",
            "raw_info": f"0x{item.info:08x}",
            "segment_index": item.segment_index,
        }
        for item in psp
        if not item.application_valid
    ]
    reserved_entries = [
        {
            "source_section": item.source_section,
            "raw_offset": f"0x{item.raw_offset:x}",
            "raw_info": f"0x{item.info:08x}",
            "reserved": f"0x{decode_info(item.info).reserved:08x}",
        }
        for item in psp
        if decode_info(item.info).reserved
    ]
    incomplete_entries = [
        {
            "source_section": item.source_section,
            "type": item.type_name,
            "raw_offset": f"0x{item.raw_offset:x}",
            "raw_info": f"0x{item.info:08x}",
            "reason": (
                "application segment is invalid"
                if not item.application_valid
                else "in-place addend is not recoverable from the file/zero-fill mapping"
                if not item.addend_valid
                else "target section or section-relative application location is unresolved"
            ),
        }
        for item in module.relocations
        if not item.application_valid
        or not item.addend_valid
        or item.target_section is None
        or item.section_offset is None
    ]
    zero_fill_entries = [
        {
            "source_section": item.source_section,
            "type": item.type_name,
            "raw_offset": f"0x{item.raw_offset:x}",
            "segment_index": item.segment_index,
            "p_filesz": f"0x{module.segments[item.segment_index].filesz:x}",
            "p_memsz": f"0x{module.segments[item.segment_index].memsz:x}",
            "addend": f"0x{item.addend & 0xFFFFFFFF:08x}",
        }
        for item in psp
        if item.application_valid
        and item.addend_valid
        and item.segment_index < len(module.segments)
        and item.raw_offset >= module.segments[item.segment_index].filesz
        and item.raw_offset + WORD_SIZE <= module.segments[item.segment_index].memsz
    ]
    complete = not (
        unknown
        or unsupported
        or invalid_entries
        or reserved_entries
        or incomplete_entries
        or compressed
        or payloads
    )

    return {
        "formats": formats,
        "psp_entries": len(psp),
        "standard_entries": len(other),
        "sections": sections,
        "types": _type_counts(list(module.relocations)),
        "unknown_types": unknown,
        "unsupported_types": unsupported,
        "segment_indices": {str(key): segment_counts[key] for key in sorted(segment_counts)},
        "relative_indices": {str(key): relative_counts[key] for key in sorted(relative_counts)},
        "compressed_sections": compressed,
        "segment_relocation_payloads": payloads,
        "relative_segments_with_nonzero_vaddr": sorted(set(relative_vaddrs)),
        "runtime_addressing": "load_base + p_vaddr; load_base is not inferred from the ELF",
        "invalid_entries": invalid_entries,
        "zero_fill_entries": zero_fill_entries,
        "reserved_field_entries": reserved_entries,
        "incomplete_entries": incomplete_entries,
        "complete": complete,
    }
