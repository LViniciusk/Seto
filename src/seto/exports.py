"""Relocation-verified function exports from PSP PRX ``.lib.ent`` tables."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from seto import elf, mips, psp_reloc
from seto.elf import ElfFile, Relocation, Section

LIB_ENT_SECTION = ".lib.ent"
RESIDENT_SECTION = ".rodata.sceResident"
TEXT_SECTION = ".text"
_WORD = 4
_ENTRY_HEADER_SIZE = 12
_U32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class ProvenExport:
    """One validated NID/function-pointer slot; duplicate slots stay distinct."""

    library: str
    nid: int
    address: int
    entry_index: int
    slot_index: int
    pointer_site: int
    table_address: int
    function_count: int
    version: int
    attributes: int
    pointer_relocation: Relocation


@dataclass(frozen=True)
class ExportLimitation:
    """A table or slot that could not be proven safely."""

    library: str
    entry_index: int | None
    slot_index: int | None
    nid: int | None
    pointer_site: int | None
    reason: str


@dataclass(frozen=True)
class ExportNidGroup:
    """Duplicate NID slots and their distinct proven addresses."""

    nid: int
    exports: tuple[ProvenExport, ...]
    addresses: tuple[int, ...]

    @property
    def ambiguous(self) -> bool:
        return len(self.addresses) > 1


@dataclass(frozen=True)
class ExportAlias:
    """Distinct NIDs that point to one proven function address."""

    address: int
    exports: tuple[ProvenExport, ...]


@dataclass(frozen=True)
class ExportCollection:
    library: str
    exports: tuple[ProvenExport, ...]
    limitations: tuple[ExportLimitation, ...]
    nid_groups: tuple[ExportNidGroup, ...]
    aliases: tuple[ExportAlias, ...]

    @property
    def ambiguous_nids(self) -> tuple[ExportNidGroup, ...]:
        return tuple(group for group in self.nid_groups if group.ambiguous)

    def exports_for_nid(self, nid: int) -> tuple[ProvenExport, ...]:
        """Return every proven slot for ``nid`` without collapsing duplicates."""
        return tuple(item for item in self.exports if item.nid == nid)


class _InvalidPointer(ValueError):
    """A pointer field lacks sufficient relocation evidence."""


def _relocation_index(module: ElfFile, section: Section) -> dict[int, tuple[Relocation, ...]]:
    sites: dict[int, list[Relocation]] = defaultdict(list)
    for item in module.relocations_for(section.name):
        if item.section_offset is not None:
            sites[item.section_offset].append(item)
    return {offset: tuple(items) for offset, items in sites.items()}


def _resolve_pointer(
    module: ElfFile,
    section: Section,
    relocations: dict[int, tuple[Relocation, ...]],
    offset: int,
    raw_value: int,
    label: str,
) -> tuple[int, Relocation]:
    site = section.addr + offset
    matches = relocations.get(offset, ())
    if not matches:
        raise _InvalidPointer(f"{label} pointer at 0x{site:x} has no usable R_MIPS_32 relocation")
    if len(matches) != 1:
        raise _InvalidPointer(f"{label} pointer at 0x{site:x} has duplicate relocation records")

    relocation = matches[0]
    if relocation.type != elf.R_MIPS_32:
        raise _InvalidPointer(f"{label} pointer uses {relocation.type_name}, not R_MIPS_32")
    if (
        not relocation.application_valid
        or not relocation.addend_valid
        or relocation.target_section != section.name
        or relocation.section_offset != offset
        or relocation.offset != site
    ):
        raise _InvalidPointer(
            f"{label} pointer at 0x{site:x} has an invalid relocation application"
        )
    if relocation.addend != raw_value:
        raise _InvalidPointer(f"{label} pointer addend disagrees with its in-place word")

    if relocation.format == "PSP":
        base = psp_reloc.relative_base(module, relocation, load_base=0)
        if base is None:
            raise _InvalidPointer(f"{label} pointer relative segment is not a loadable PT_LOAD")
    elif relocation.format == "REL":
        base = 0
    else:
        raise _InvalidPointer(
            f"{label} pointer uses unsupported relocation format {relocation.format!r}"
        )

    if relocation.addend > _U32_MAX - base:
        raise _InvalidPointer(f"{label} pointer overflows the module-relative 32-bit address space")
    return relocation.addend + base, relocation


def _resident_string(data: bytes, resident: Section, address: int) -> str:
    if not resident.contains_address(address):
        raise _InvalidPointer(f"library-name pointer 0x{address:x} is outside .rodata.sceResident")
    offset = address - resident.addr
    end = data.find(b"\0", offset)
    if end < 0:
        raise _InvalidPointer(f"library name at 0x{address:x} is not NUL-terminated")
    try:
        name = data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _InvalidPointer(f"library name at 0x{address:x} is not ASCII") from exc
    if not name:
        raise _InvalidPointer(f"library name at 0x{address:x} is empty")
    return name


def _collisions(
    exports: tuple[ProvenExport, ...],
) -> tuple[tuple[ExportNidGroup, ...], tuple[ExportAlias, ...]]:
    by_nid: dict[int, list[ProvenExport]] = defaultdict(list)
    by_address: dict[int, list[ProvenExport]] = defaultdict(list)
    for item in exports:
        by_nid[item.nid].append(item)
        by_address[item.address].append(item)
    groups = tuple(
        ExportNidGroup(nid, tuple(items), tuple(sorted({item.address for item in items})))
        for nid, items in sorted(by_nid.items())
        if len(items) > 1
    )
    aliases = tuple(
        ExportAlias(address, tuple(items))
        for address, items in sorted(by_address.items())
        if len({item.nid for item in items}) > 1
    )
    return groups, aliases


def collect_exports(module: ElfFile, library: str) -> ExportCollection:
    """Collect independently proven function slots from a PSP PRX.

    This observed export layout stores NIDs followed by function pointers in one
    contiguous table. Returned PSP-relative addresses are in module coordinates
    (load base zero), not asserted runtime addresses. Every pointer field requires
    one usable ``R_MIPS_32`` relocation; uncertain entries/slots remain explicit
    limitations while other valid slots are retained.
    """
    if not isinstance(library, str) or not library:
        raise ValueError("library must be a non-empty string")

    limitations: list[ExportLimitation] = []
    exports: list[ProvenExport] = []

    def limit(
        reason: str,
        entry: int | None = None,
        slot: int | None = None,
        nid: int | None = None,
        site: int | None = None,
    ) -> None:
        limitations.append(ExportLimitation(library, entry, slot, nid, site, reason))

    if not module.is_prx or not module.is_mips:
        limit("module is not an ET_MIPS_PSP_PRX")
        return ExportCollection(library, (), tuple(limitations), (), ())

    lib_ent = module.section(LIB_ENT_SECTION)
    resident = module.section(RESIDENT_SECTION)
    text = module.section(TEXT_SECTION)
    if lib_ent is None or resident is None or text is None:
        for name, section in (
            (LIB_ENT_SECTION, lib_ent),
            (RESIDENT_SECTION, resident),
            (TEXT_SECTION, text),
        ):
            if section is None:
                limit(f"missing {name} section")
        return ExportCollection(library, (), tuple(limitations), (), ())
    if not text.flags & mips.SHF_EXECINSTR:
        limit(".text section is not marked executable")
        return ExportCollection(library, (), tuple(limitations), (), ())

    ent_data = module.section_data(lib_ent)
    resident_data = module.section_data(resident)
    ent_relocs = _relocation_index(module, lib_ent)
    resident_relocs = _relocation_index(module, resident)
    cursor = entry_index = 0
    found_library = False

    while cursor < len(ent_data):
        remaining = len(ent_data) - cursor
        if remaining < _ENTRY_HEADER_SIZE:
            limit(f"truncated .lib.ent header at section offset 0x{cursor:x}", entry_index)
            break
        entry_words = ent_data[cursor + 8]
        entry_size = entry_words * _WORD
        if entry_words == 0 or entry_size > remaining:
            reason = "zero declared length" if entry_words == 0 else "entry overruns .lib.ent"
            limit(f".lib.ent entry {entry_index} has {reason}", entry_index)
            break
        if entry_words < 3:
            limit(f".lib.ent entry {entry_index} is too short to contain its count", entry_index)
            cursor += entry_size
            entry_index += 1
            continue

        name_raw = int.from_bytes(ent_data[cursor : cursor + 4], "little")
        version = int.from_bytes(ent_data[cursor + 4 : cursor + 6], "little")
        attributes = int.from_bytes(ent_data[cursor + 6 : cursor + 8], "little")
        count = int.from_bytes(ent_data[cursor + 10 : cursor + 12], "little")
        if name_raw == 0:
            limit(f".lib.ent entry {entry_index} has a null library-name pointer", entry_index)
            cursor += entry_size
            entry_index += 1
            continue

        try:
            name_address, _ = _resolve_pointer(
                module, lib_ent, ent_relocs, cursor, name_raw, "library-name"
            )
            name = _resident_string(resident_data, resident, name_address)
        except _InvalidPointer as exc:
            limit(str(exc), entry_index, site=lib_ent.addr + cursor)
            cursor += entry_size
            entry_index += 1
            continue
        if name != library:
            cursor += entry_size
            entry_index += 1
            continue
        found_library = True

        if entry_words < 4:
            reason = (
                f".lib.ent entry {entry_index} has fewer than four words; "
                "table pointer is absent"
            )
        elif entry_words > 4:
            reason = (
                f".lib.ent entry {entry_index} declares an unsupported "
                f"{entry_words}-word layout"
            )
        else:
            reason = ""
        if reason:
            limit(reason, entry_index)
            cursor += entry_size
            entry_index += 1
            continue
        table_raw = int.from_bytes(ent_data[cursor + _ENTRY_HEADER_SIZE : cursor + 16], "little")
        try:
            table_address, _ = _resolve_pointer(
                module, lib_ent, ent_relocs, cursor + _ENTRY_HEADER_SIZE,
                table_raw, "export-table",
            )
        except _InvalidPointer as exc:
            limit(str(exc), entry_index, site=lib_ent.addr + cursor + _ENTRY_HEADER_SIZE)
            cursor += entry_size
            entry_index += 1
            continue
        if table_address % _WORD:
            limit(f"export table 0x{table_address:x} is not four-byte aligned", entry_index)
            cursor += entry_size
            entry_index += 1
            continue
        if not resident.addr <= table_address <= resident.end:
            limit(f"export table 0x{table_address:x} is outside .rodata.sceResident", entry_index)
            cursor += entry_size
            entry_index += 1
            continue
        if count > (resident.end - table_address) // (2 * _WORD):
            limit(f"export count {count} exceeds .rodata.sceResident bounds", entry_index)
            cursor += entry_size
            entry_index += 1
            continue

        for slot in range(count):
            nid_offset = table_address - resident.addr + slot * _WORD
            nid = int.from_bytes(resident_data[nid_offset : nid_offset + _WORD], "little")
            pointer_site = table_address + count * _WORD + slot * _WORD
            pointer_offset = pointer_site - resident.addr
            raw_pointer = int.from_bytes(
                resident_data[pointer_offset : pointer_offset + _WORD], "little"
            )
            try:
                address, relocation = _resolve_pointer(
                    module, resident, resident_relocs, pointer_offset,
                    raw_pointer, "function",
                )
            except _InvalidPointer as exc:
                limit(str(exc), entry_index, slot, nid, pointer_site)
                continue
            if address % _WORD:
                limit(
                    f"function address 0x{address:x} is not four-byte aligned",
                    entry_index,
                    slot,
                    nid,
                    pointer_site,
                )
                continue
            if not text.contains_address(address):
                limit(
                    f"resolved function address 0x{address:x} is outside executable .text",
                    entry_index,
                    slot,
                    nid,
                    pointer_site,
                )
                continue
            exports.append(
                ProvenExport(
                    library, nid, address, entry_index, slot, pointer_site,
                    table_address, count, version, attributes, relocation,
                )
            )

        cursor += entry_size
        entry_index += 1

    if not found_library:
        limit(f"no validated .lib.ent entry for {library!r}")
    proven = tuple(exports)
    nid_groups, aliases = _collisions(proven)
    return ExportCollection(library, proven, tuple(limitations), nid_groups, aliases)
