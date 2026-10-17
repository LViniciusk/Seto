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
    R_MIPS_16,
    R_MIPS_26,
    R_MIPS_32,
    R_MIPS_HI16,
    R_MIPS_LO16,
    R_MIPS_NONE,
    RELOCATION_TYPE_NAMES,
    SHT_MIPS_PSPREL,
    SHT_MIPS_PSPREL2,
    ElfFile,
    Relocation,
    relocation_type_name,
)

#: ``sh_type`` of a PSP relocation table (fixed 8-byte entries).
SHT_PSPREL = SHT_MIPS_PSPREL
#: ``sh_type`` of a compressed PSP relocation table (not decoded here).
SHT_PSPREL2 = SHT_MIPS_PSPREL2

#: ``p_type`` of a segment that carries a compressed relocation payload.
PT_PSPREL1 = 0x700000A0
PT_PSPREL2 = 0x700000A1

#: PPSSPP masks the type with 4 bits and the two segment fields with 8.
TYPE_MASK = 0xF
SEGMENT_MASK = 0xFF
SEGMENT_SHIFT = 8
RELATIVE_SHIFT = 16

R_MIPS_GPREL16 = 7


@dataclass(frozen=True)
class PspInfo:
    """The three fields a PSP ``r_info`` packs."""

    type: int
    segment_index: int
    relative_index: int

    def summary(self) -> dict[str, object]:
        return {
            "type": relocation_type_name(self.type),
            "segment_index": self.segment_index,
            "relative_index": self.relative_index,
        }


def decode_info(info: int) -> PspInfo:
    """Split a raw PSP ``r_info`` into type, segment and relative segment.

    The type is masked with 4 bits (as the loader does), so a type that needs
    more than 4 bits cannot be silently produced by a stray high bit.
    """
    return PspInfo(
        type=info & TYPE_MASK,
        segment_index=(info >> SEGMENT_SHIFT) & SEGMENT_MASK,
        relative_index=(info >> RELATIVE_SHIFT) & SEGMENT_MASK,
    )


def _sign_extend_16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def relative_base(module: ElfFile, relocation: Relocation) -> int:
    """The base the loader adds for ``relocation`` (``segmentVAddr[relative]``).

    The segment's ``p_vaddr`` is the module-relative base; a missing or
    non-``PT_LOAD`` relative segment contributes ``0``, exactly as the loader
    treats a segment it did not load.
    """
    index = relocation.relative_index
    if index >= len(module.segments):
        return 0
    segment = module.segments[index]
    if segment.type != PT_LOAD:
        return 0
    return segment.vaddr & 0xFFFFFFFF


def apply_relocation(
    rel_type: int,
    word: int,
    base: int,
    *,
    lo16_word: int | None = None,
) -> int | None:
    """The word the PSP loader writes for one relocation, or ``None`` if unknown.

    ``word`` is the in-file value at the relocated address and ``base`` the
    module base the loader adds (see :func:`relative_base`).  ``R_MIPS_HI16``
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
    if rel_type == R_MIPS_16:
        return (word & 0xFFFF0000) | (((word & 0xFFFF) + base) & 0xFFFF)
    if rel_type == R_MIPS_LO16:
        return (word & 0xFFFF0000) | (((word & 0xFFFF) + base) & 0xFFFF)
    if rel_type == R_MIPS_HI16:
        if lo16_word is None:
            return None
        combined = (
            ((word & 0xFFFF) << 16) + _sign_extend_16(lo16_word) + base
        ) & 0xFFFFFFFF
        return (word & 0xFFFF0000) | ((combined >> 16) & 0xFFFF)
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

    by_section: dict[str, list[Relocation]] = {}
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

    formats = sorted({item.format for item in module.relocations})
    compressed = sorted(
        section.name for section in module.sections if section.type == SHT_PSPREL2
    )
    payloads = sorted(
        segment.index
        for segment in module.segments
        if segment.type in (PT_PSPREL1, PT_PSPREL2)
    )

    # The addend is only a module address when the relative segment is based at 0.
    rebased = [
        item.relative_index
        for item in psp
        if item.relative_index < len(module.segments)
        and module.segments[item.relative_index].type == PT_LOAD
        and module.segments[item.relative_index].vaddr != 0
    ]

    return {
        "formats": formats,
        "psp_entries": len(psp),
        "standard_entries": len(other),
        "sections": sections,
        "types": _type_counts(list(module.relocations)),
        "unknown_types": unknown,
        "segment_indices": {str(key): segment_counts[key] for key in sorted(segment_counts)},
        "relative_indices": {str(key): relative_counts[key] for key in sorted(relative_counts)},
        "compressed_sections": compressed,
        "segment_relocation_payloads": payloads,
        "entries_needing_a_rebase": sorted(set(rebased)),
    }
