"""Secure ELF32 (little-endian MIPS / PSP PRX) parser.

Only the parts Seto actually needs are decoded: header, program headers,
section table, symbol table, relocation tables and the ``.comment`` compiler
signature. Nothing is trusted - section counts, offsets, string table indices
and relocation entries are all validated against the real buffer, and the
parser keeps the original bytes reachable so binaries can be inspected and
compared without ever being modified.

PSP quirk: in ``0xFFA0`` (PRX) files the ``sh_link``/``sh_info`` fields of the
relocation sections are not meaningful.  Seto detects this and falls back to
the standard ``.rel.<name>`` naming convention plus address-range inference,
recording the ambiguity as an observation instead of silently trusting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from seto.binio import BytesReader, ParseError, read_file

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2LSB = 1
EV_CURRENT = 1

EM_MIPS = 8

ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_MIPS_PSP_PRX = 0xFFA0

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_MIPS_PSPREL = 0x700000A0
SHT_MIPS_PSPREL2 = 0x700000A1

SHF_ALLOC = 0x2

PT_LOAD = 1

ELF_HEADER_SIZE = 0x34
SECTION_HEADER_SIZE = 0x28
PROGRAM_HEADER_SIZE = 0x20
SYMBOL_SIZE = 0x10
REL_ENTRY_SIZE = 0x08

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_XINDEX = 0xFFFF

R_MIPS_NONE = 0
R_MIPS_16 = 1
R_MIPS_32 = 2
R_MIPS_REL32 = 3
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6
R_MIPS_X_HI16 = 13
R_MIPS_X_J26 = 14
R_MIPS_X_JAL26 = 15

FILE_TYPE_NAMES: dict[int, str] = {
    0: "ET_NONE",
    ET_REL: "ET_REL",
    ET_EXEC: "ET_EXEC",
    ET_DYN: "ET_DYN",
    4: "ET_CORE",
    ET_MIPS_PSP_PRX: "ET_MIPS_PSP_PRX",
}

SECTION_TYPE_NAMES: dict[int, str] = {
    SHT_NULL: "SHT_NULL",
    SHT_PROGBITS: "SHT_PROGBITS",
    SHT_SYMTAB: "SHT_SYMTAB",
    SHT_STRTAB: "SHT_STRTAB",
    SHT_RELA: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    SHT_NOBITS: "SHT_NOBITS",
    SHT_REL: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    SHT_MIPS_PSPREL: "SHT_MIPS_PSPREL",
    SHT_MIPS_PSPREL2: "SHT_MIPS_PSPREL2",
}

RELOCATION_TYPE_NAMES: dict[int, str] = {
    R_MIPS_NONE: "R_MIPS_NONE",
    R_MIPS_16: "R_MIPS_16",
    R_MIPS_32: "R_MIPS_32",
    R_MIPS_REL32: "R_MIPS_REL32",
    R_MIPS_26: "R_MIPS_26",
    R_MIPS_HI16: "R_MIPS_HI16",
    R_MIPS_LO16: "R_MIPS_LO16",
    7: "R_MIPS_GPREL16",
    8: "R_MIPS_LITERAL",
    9: "R_MIPS_GOT16",
    10: "R_MIPS_PC16",
    11: "R_MIPS_CALL16",
    12: "R_MIPS_GPREL32",
    R_MIPS_X_HI16: "R_MIPS_X_HI16",
    R_MIPS_X_J26: "R_MIPS_X_J26",
    R_MIPS_X_JAL26: "R_MIPS_X_JAL26",
}

RELOCATION_SECTION_TYPES = (SHT_REL, SHT_MIPS_PSPREL, SHT_MIPS_PSPREL2)


def relocation_type_name(value: int) -> str:
    return RELOCATION_TYPE_NAMES.get(value, f"R_MIPS_UNKNOWN({value})")


def _sign_extend_16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def relocation_mask(rel_type: int) -> int:
    """Bits of the relocated word that the relocation is allowed to change.

    ``0`` means the relocation does not explain any bit of the word (unknown
    type) and the comparison must fall back to an exact word match.
    """
    if rel_type in (R_MIPS_32, R_MIPS_REL32):
        return 0xFFFFFFFF
    if rel_type in (R_MIPS_26, R_MIPS_X_J26, R_MIPS_X_JAL26):
        return 0x03FFFFFF
    if rel_type in (R_MIPS_HI16, R_MIPS_LO16, R_MIPS_X_HI16):
        return 0x0000FFFF
    return 0


def decode_relocation_addend(word: int, rel_type: int) -> int:
    """Return the in-place (link-time) addend encoded in a relocated word."""
    if rel_type in (R_MIPS_NONE,):
        return 0
    if rel_type in (R_MIPS_32, R_MIPS_REL32):
        return word & 0xFFFFFFFF
    if rel_type in (R_MIPS_26, R_MIPS_X_J26, R_MIPS_X_JAL26):
        return (word & 0x03FFFFFF) << 2
    if rel_type in (R_MIPS_HI16, R_MIPS_LO16, R_MIPS_X_HI16):
        return _sign_extend_16(word & 0x0000FFFF)
    return word & 0xFFFFFFFF


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def is_nobits(self) -> bool:
        return self.type == SHT_NOBITS

    @property
    def is_allocated(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    def contains_address(self, address: int) -> bool:
        return self.size > 0 and self.addr <= address < self.end

    def summary(self) -> dict[str, object]:
        return {
            "index": self.index,
            "name": self.name,
            "type": SECTION_TYPE_NAMES.get(self.type, f"0x{self.type:08x}"),
            "flags": self.flags,
            "addr": self.addr,
            "offset": self.offset,
            "size": self.size,
            "align": self.align,
        }


@dataclass(frozen=True)
class Segment:
    index: int
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int

    def summary(self) -> dict[str, object]:
        return {
            "index": self.index,
            "type": self.type,
            "offset": self.offset,
            "vaddr": self.vaddr,
            "filesz": self.filesz,
            "memsz": self.memsz,
            "flags": self.flags,
        }


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int

    @property
    def type(self) -> int:
        return self.info & 0xF

    @property
    def is_function(self) -> bool:
        return self.type == STT_FUNC

    @property
    def is_defined(self) -> bool:
        """False for undefined symbols and for the reserved (special) indices."""
        return SHN_UNDEF < self.shndx < SHN_LORESERVE


@dataclass(frozen=True)
class Relocation:
    """A single relocation entry, fully resolved and validated.

    ``format`` names the layout the entry was read with, because the same raw
    fields mean different things in each:

    * ``"REL"`` - a standard ``SHT_REL`` table.  ``r_info`` is
      ``(symbol_index << 8) | type`` and ``r_offset`` is the address the entry
      patches.
    * ``"PSP"`` - a PSP ``SHT_PSPREL`` (``0x700000A0``) table.  ``r_info`` is
      ``(relative_segment << 16) | (segment << 8) | type``; there is no symbol
      index (so ``symbol_index`` is ``0``), and ``r_offset`` is an offset
      *inside* the named segment.  ``offset`` is then
      ``segments[segment].vaddr + r_offset`` - the module address the loader
      patches - while ``psp_reloc`` holds the field-level evidence.

    A compressed ``SHT_PSPREL2`` stream is *not* a sequence of ``Elf32_Rel``
    entries, so no ``Relocation`` is produced for it at all; the parser records
    an observation instead of inventing values.

    ``info`` keeps the raw ``r_info``, so no field is lost.
    """

    offset: int
    type: int
    symbol_index: int
    addend: int
    symbol: str | None
    target_section: str | None
    section_offset: int | None
    file_offset: int | None
    info: int = 0
    format: str = "REL"
    segment_index: int = 0
    relative_index: int = 0
    source_section: str | None = None
    raw_offset: int = 0

    @property
    def type_name(self) -> str:
        return relocation_type_name(self.type)

    @property
    def mask(self) -> int:
        return relocation_mask(self.type)

    def summary(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "type": self.type_name,
            "format": self.format,
            "info": f"0x{self.info:08x}",
            "segment_index": self.segment_index,
            "relative_index": self.relative_index,
            "raw_offset": f"0x{self.raw_offset:x}",
            "symbol_index": self.symbol_index,
            "symbol": self.symbol,
            "addend": self.addend,
            "target_section": self.target_section,
            "section_offset": self.section_offset,
            "source_section": self.source_section,
        }


@dataclass(frozen=True)
class ElfHeader:
    ei_class: int
    ei_data: int
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    @property
    def file_type_name(self) -> str:
        return FILE_TYPE_NAMES.get(self.e_type, f"0x{self.e_type:04x}")

    def summary(self) -> dict[str, object]:
        return {
            "class": "ELF32" if self.ei_class == ELFCLASS32 else f"class{self.ei_class}",
            "endianness": "little" if self.ei_data == ELFDATA2LSB else f"data{self.ei_data}",
            "type": self.file_type_name,
            "machine": self.e_machine,
            "entry": self.e_entry,
            "flags": self.e_flags,
            "section_count": self.e_shnum,
            "segment_count": self.e_phnum,
        }


@dataclass
class ElfFile:
    """A parsed ELF32 file plus the raw bytes it was parsed from."""

    header: ElfHeader
    sections: tuple[Section, ...]
    segments: tuple[Segment, ...]
    symbols: tuple[Symbol, ...]
    relocations: tuple[Relocation, ...]
    reader: BytesReader
    observations: tuple[str, ...] = ()
    _by_name: dict[str, Section] = field(default_factory=dict, repr=False)
    _relocations_by_target: dict[str, tuple[Relocation, ...]] = field(
        default_factory=dict, repr=False
    )

    @property
    def is_prx(self) -> bool:
        return self.header.e_type == ET_MIPS_PSP_PRX

    @property
    def is_mips(self) -> bool:
        return self.header.e_machine == EM_MIPS

    def section(self, name: str) -> Section | None:
        return self._by_name.get(name)

    def require_section(self, name: str) -> Section:
        section = self.section(name)
        if section is None:
            raise ParseError(f"{self.reader.name}: section {name!r} not found")
        return section

    def section_data(self, section: Section | str) -> bytes:
        if isinstance(section, str):
            section = self.require_section(section)
        if section.is_nobits:
            return b""
        return self.reader.bytes_at(section.offset, section.size)

    def relocations_for(self, section_name: str) -> tuple[Relocation, ...]:
        return self._relocations_by_target.get(section_name, ())

    def comment(self) -> str | None:
        section = self.section(".comment")
        if section is None or section.size == 0:
            return None
        text = self.section_data(section).split(b"\x00", 1)[0]
        return text.decode("utf-8", "replace")

    def summary(self) -> dict[str, object]:
        return {
            "header": self.header.summary(),
            "sections": [s.summary() for s in self.sections],
            "segments": [s.summary() for s in self.segments],
            "comment": self.comment(),
            "relocation_count": len(self.relocations),
            "symbol_count": len(self.symbols),
            "observations": list(self.observations),
        }


def parse(
    source: BytesReader | bytes | str | Path,
    name: str | None = None,
    *,
    expected_machine: int | None = EM_MIPS,
) -> ElfFile:
    """Parse an ELF32 little-endian file from a reader, bytes or a path."""
    if isinstance(source, BytesReader):
        reader = source
    elif isinstance(source, (str, Path)):
        reader = read_file(source)
    else:
        reader = BytesReader(source, name or "<memory>")
    return _parse(reader, expected_machine)


def _parse(reader: BytesReader, expected_machine: int | None) -> ElfFile:
    if reader.size < ELF_HEADER_SIZE:
        raise ParseError(f"{reader.name}: too small for an ELF header")
    if reader.bytes_at(0, 4) != ELF_MAGIC:
        raise ParseError(f"{reader.name}: bad ELF magic")
    ei_class = reader.u8(4)
    ei_data = reader.u8(5)
    if ei_class != ELFCLASS32:
        raise ParseError(f"{reader.name}: unsupported ELF class {ei_class} (only ELF32)")
    if ei_data != ELFDATA2LSB:
        raise ParseError(
            f"{reader.name}: unsupported byte order {ei_data} (only little-endian)"
        )

    e_type = reader.u16(0x10)
    e_machine = reader.u16(0x12)
    if expected_machine is not None and e_machine != expected_machine:
        raise ParseError(
            f"{reader.name}: unexpected machine {e_machine} (expected MIPS={expected_machine})"
        )

    header = ElfHeader(
        ei_class=ei_class,
        ei_data=ei_data,
        e_type=e_type,
        e_machine=e_machine,
        e_version=reader.u32(0x14),
        e_entry=reader.u32(0x18),
        e_phoff=reader.u32(0x1C),
        e_shoff=reader.u32(0x20),
        e_flags=reader.u32(0x24),
        e_ehsize=reader.u16(0x28),
        e_phentsize=reader.u16(0x2A),
        e_phnum=reader.u16(0x2C),
        e_shentsize=reader.u16(0x2E),
        e_shnum=reader.u16(0x30),
        e_shstrndx=reader.u16(0x32),
    )

    observations: list[str] = []
    segments = _parse_segments(reader, header)
    sections, shstrtab = _parse_sections(reader, header)
    symbols = _parse_symbols(reader, sections)
    relocations = _parse_relocations(reader, header, sections, segments, symbols, observations)

    by_name = {section.name: section for section in sections if section.name}
    relocations_by_target: dict[str, list[Relocation]] = {}
    for relocation in relocations:
        if relocation.target_section:
            relocations_by_target.setdefault(relocation.target_section, []).append(relocation)

    if header.e_type == ET_MIPS_PSP_PRX:
        observations.append(
            "PRX (0xFFA0): relocation section sh_link/sh_info are not meaningful; "
            "targets are inferred from '.rel.<name>' naming and address ranges"
        )

    return ElfFile(
        header=header,
        sections=sections,
        segments=segments,
        symbols=symbols,
        relocations=relocations,
        reader=reader,
        observations=tuple(observations),
        _by_name=by_name,
        _relocations_by_target={
            name: tuple(items) for name, items in relocations_by_target.items()
        },
    )


def _parse_segments(reader: BytesReader, header: ElfHeader) -> tuple[Segment, ...]:
    if header.e_phoff == 0 or header.e_phnum == 0:
        return ()
    if header.e_phentsize < PROGRAM_HEADER_SIZE:
        raise ParseError(f"{reader.name}: program header entry size too small")
    reader.span(header.e_phoff, header.e_phentsize * header.e_phnum)
    segments: list[Segment] = []
    for index in range(header.e_phnum):
        base = header.e_phoff + index * header.e_phentsize
        segment = Segment(
            index=index,
            type=reader.u32(base),
            offset=reader.u32(base + 0x04),
            vaddr=reader.u32(base + 0x08),
            paddr=reader.u32(base + 0x0C),
            filesz=reader.u32(base + 0x10),
            memsz=reader.u32(base + 0x14),
            flags=reader.u32(base + 0x18),
            align=reader.u32(base + 0x1C),
        )
        if segment.filesz > segment.memsz:
            raise ParseError(
                f"{reader.name}: program header {index} has p_filesz (0x{segment.filesz:x}) "
                f"larger than p_memsz (0x{segment.memsz:x}); its bytes cannot be mapped"
            )
        if segment.filesz:
            reader.span(segment.offset, segment.filesz)
        segments.append(segment)
    return tuple(segments)


def _parse_sections(
    reader: BytesReader, header: ElfHeader
) -> tuple[tuple[Section, ...], bytes]:
    if header.e_shoff == 0 or header.e_shnum == 0:
        return (), b""
    if header.e_shentsize < SECTION_HEADER_SIZE:
        raise ParseError(f"{reader.name}: section header entry size too small")
    reader.span(header.e_shoff, header.e_shentsize * header.e_shnum)

    raw: list[tuple[int, ...]] = []
    for index in range(header.e_shnum):
        base = header.e_shoff + index * header.e_shentsize
        raw.append(
            (
                reader.u32(base),
                reader.u32(base + 0x04),
                reader.u32(base + 0x08),
                reader.u32(base + 0x0C),
                reader.u32(base + 0x10),
                reader.u32(base + 0x14),
                reader.u32(base + 0x18),
                reader.u32(base + 0x1C),
                reader.u32(base + 0x20),
                reader.u32(base + 0x24),
            )
        )

    if header.e_shstrndx == 0:
        shstrtab = b""
    elif header.e_shstrndx >= header.e_shnum:
        raise ParseError(f"{reader.name}: e_shstrndx {header.e_shstrndx} out of range")
    else:
        strtab_type = raw[header.e_shstrndx][1]
        strtab_off = raw[header.e_shstrndx][4]
        strtab_size = raw[header.e_shstrndx][5]
        if strtab_type != SHT_STRTAB:
            raise ParseError(f"{reader.name}: section name table is not a string table")
        if strtab_size:
            shstrtab = reader.bytes_at(strtab_off, strtab_size)
        else:
            shstrtab = b""

    sections: list[Section] = []
    for index, fields in enumerate(raw):
        (name_offset, sec_type, flags, addr, offset, size, link, info, align, entsize) = fields
        if sec_type != SHT_NOBITS and size:
            reader.span(offset, size)
        sections.append(
            Section(
                index=index,
                name=_section_name(shstrtab, name_offset, reader.name, index),
                type=sec_type,
                flags=flags,
                addr=addr,
                offset=offset,
                size=size,
                link=link,
                info=info,
                align=align,
                entsize=entsize,
            )
        )
    return tuple(sections), shstrtab


def _section_name(shstrtab: bytes, offset: int, name: str, index: int) -> str:
    if not shstrtab:
        return ""
    if offset >= len(shstrtab):
        raise ParseError(f"{name}: section {index} name offset escapes the string table")
    terminator = shstrtab.find(b"\x00", offset)
    if terminator < 0:
        raise ParseError(f"{name}: section {index} name is unterminated")
    return shstrtab[offset:terminator].decode("utf-8", "replace")


def _parse_symbols(reader: BytesReader, sections: tuple[Section, ...]) -> tuple[Symbol, ...]:
    for section in sections:
        if section.type != SHT_SYMTAB:
            continue
        if section.size % SYMBOL_SIZE:
            raise ParseError(f"{reader.name}: symbol table size is not a multiple of {SYMBOL_SIZE}")
        if not (0 < section.link < len(sections)):
            raise ParseError(f"{reader.name}: symbol table link {section.link} out of range")
        strtab = sections[section.link]
        if strtab.type != SHT_STRTAB:
            raise ParseError(f"{reader.name}: symbol table does not link to a string table")
        strings = reader.bytes_at(strtab.offset, strtab.size) if strtab.size else b""
        symbols: list[Symbol] = []
        for index in range(section.size // SYMBOL_SIZE):
            base = section.offset + index * SYMBOL_SIZE
            symbols.append(
                Symbol(
                    index=index,
                    name=_symbol_name(strings, reader.u32(base), reader.name, index),
                    value=reader.u32(base + 0x04),
                    size=reader.u32(base + 0x08),
                    info=reader.u8(base + 0x0C),
                    other=reader.u8(base + 0x0D),
                    shndx=reader.u16(base + 0x0E),
                )
            )
        return tuple(symbols)
    return ()


def _symbol_name(strings: bytes, offset: int, name: str, index: int) -> str:
    if not strings or offset >= len(strings):
        return ""
    terminator = strings.find(b"\x00", offset)
    if terminator < 0:
        raise ParseError(f"{name}: symbol {index} name is unterminated")
    return strings[offset:terminator].decode("utf-8", "replace")


def _parse_relocations(
    reader: BytesReader,
    header: ElfHeader,
    sections: tuple[Section, ...],
    segments: tuple[Segment, ...],
    symbols: tuple[Symbol, ...],
    observations: list[str],
) -> tuple[Relocation, ...]:
    relocations: list[Relocation] = []
    for section in sections:
        if section.type not in RELOCATION_SECTION_TYPES:
            continue
        if section.type == SHT_MIPS_PSPREL2:
            # A compressed PSPREL2 stream is not a sequence of Elf32_Rel entries.
            # Reading it with this layout would invent values, so it is reported
            # instead of decoded (this module has none).
            observations.append(
                f"relocation section {section.name!r}: compressed SHT_PSPREL2 is not decoded"
            )
            continue
        if section.size % REL_ENTRY_SIZE:
            raise ParseError(
                f"{reader.name}: relocation section {section.name!r} size is not a multiple of {REL_ENTRY_SIZE}"
            )
        psp = section.type == SHT_MIPS_PSPREL
        target = _relocation_target(header, section, sections)
        if target is None:
            observations.append(
                f"relocation section {section.name!r}: target section could not be resolved"
            )
        count = section.size // REL_ENTRY_SIZE
        for index in range(count):
            base = section.offset + index * REL_ENTRY_SIZE
            raw_offset = reader.u32(base)
            info = reader.u32(base + 0x04)
            rel_type = info & 0xFF
            if psp:
                # PSP r_info is (relative << 16) | (segment << 8) | type.  It is
                # not a symbol index, and r_offset is an offset *inside* the named
                # segment, so the patched address is segment.vaddr + r_offset.
                symbol_index = 0
                segment_index = (info >> 8) & 0xFF
                relative_index = (info >> 16) & 0xFF
                offset = _psp_address(
                    segments, segment_index, raw_offset, section.name, observations
                )
            else:
                symbol_index = info >> 8
                segment_index = 0
                relative_index = 0
                offset = raw_offset
            symbol = _symbol_name_for(symbols, symbol_index)
            if target is not None and offset < target.addr:
                # The address sits below the section the table names, so there is
                # no byte to read there.  The entry is reported instead of being
                # patched at a negative offset.
                observations.append(
                    f"relocation section {section.name!r}: entry at 0x{offset:x} is below "
                    f"its target section {target.name!r} (addr 0x{target.addr:x})"
                )
                section_offset = None
                file_offset = None
            else:
                section_offset = offset - target.addr if target is not None else None
                file_offset = _resolve_file_offset(header, sections, target, offset)
            word = reader.u32(file_offset) if file_offset is not None else 0
            relocations.append(
                Relocation(
                    offset=offset,
                    type=rel_type,
                    symbol_index=symbol_index,
                    addend=decode_relocation_addend(word, rel_type),
                    symbol=symbol,
                    target_section=target.name if target is not None else None,
                    section_offset=section_offset,
                    file_offset=file_offset,
                    info=info,
                    format="PSP" if psp else "REL",
                    segment_index=segment_index,
                    relative_index=relative_index,
                    source_section=section.name or None,
                    raw_offset=raw_offset,
                )
            )
    return tuple(relocations)


def _psp_address(
    segments: tuple[Segment, ...],
    segment_index: int,
    raw_offset: int,
    section_name: str,
    observations: list[str],
) -> int:
    """The module address a PSP relocation patches: ``segment.vaddr + r_offset``.

    The address is kept inside 32 bits, and a segment index the file cannot back
    is reported rather than silently patched: the raw ``r_offset`` is returned and
    the caller records the limitation.
    """
    if segment_index >= len(segments):
        observations.append(
            f"relocation section {section_name!r}: entry names segment {segment_index}, "
            f"but the file declares {len(segments)}"
        )
        return raw_offset & 0xFFFFFFFF
    segment = segments[segment_index]
    if segment.type != PT_LOAD:
        observations.append(
            f"relocation section {section_name!r}: entry names segment {segment_index}, "
            f"which is not PT_LOAD"
        )
        return raw_offset & 0xFFFFFFFF
    if segment.vaddr:
        observations.append(
            f"relocation section {section_name!r}: segment {segment_index} has vaddr "
            f"0x{segment.vaddr:x}; r_offset is segment-relative and was rebased"
        )
    return (segment.vaddr + raw_offset) & 0xFFFFFFFF


def _symbol_name_for(symbols: tuple[Symbol, ...], index: int) -> str | None:
    """Resolve a relocation's symbol index against the file's symbol table.

    A stripped file (such as a PSP PRX) has no symbol table, so ``None`` simply
    means "the symbol index carries no recoverable name".
    """
    if index >= len(symbols):
        return None
    return symbols[index].name or None


def _relocation_target(
    header: ElfHeader, section: Section, sections: tuple[Section, ...]
) -> Section | None:
    """Resolve the section a relocation table applies to.

    ``ET_REL`` objects carry a valid ``sh_info``.  PSP PRX files do not, so the
    standard ``.rel.<name>`` naming convention is used instead.
    """
    if header.e_type == ET_REL and 0 < section.info < len(sections):
        return sections[section.info]
    if section.name.startswith(".rel."):
        wanted = section.name[len(".rel") :]
        for candidate in sections:
            if candidate.name == wanted:
                return candidate
    return None


def _resolve_file_offset(
    header: ElfHeader,
    sections: tuple[Section, ...],
    target: Section | None,
    offset: int,
) -> int | None:
    if target is not None:
        if target.is_nobits:
            return None
        return target.offset + (offset - target.addr)
    # No declared target: fall back to the smallest allocated section that
    # contains the address. Non-allocated sections (.shstrtab, .comment) often
    # carry addr == 0 and must not shadow .text.
    candidates = [
        section
        for section in sections
        if section.is_allocated and not section.is_nobits and section.contains_address(offset)
    ]
    if not candidates:
        return None
    section = min(candidates, key=lambda item: item.size)
    return section.offset + (offset - section.addr)
