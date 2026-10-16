"""Synthetic inputs that prove an external tool can actually do its job.

Locating an executable and reading the version string it prints proves nothing
about whether the tool can handle the files Seto needs.  The smoke tests
therefore hand each tool a small file that Seto builds here, byte by byte and
deterministically - an ELF32 little-endian MIPS object with real Allegrex
instructions, a symbol table and a relocation - and then judge what comes back.

The object is deliberately tiny and carries nothing from the game: no byte of
``private/`` is read, and the same bytes are produced on every machine.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ELF32_HEADER_SIZE = 0x34
SECTION_HEADER_SIZE = 0x28
SYMBOL_ENTRY_SIZE = 0x10

EM_MIPS = 8
ET_REL = 1
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_REL = 9

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

R_MIPS_32 = 2

STB_GLOBAL = 0x10
STT_OBJECT = 0x1
STT_FUNC = 0x2

#: The body of the synthetic function: ``addiu $sp, $sp, -0x10``, ``jr $ra``
#: and the delay-slot ``nop``.  Real instructions, so a disassembler has
#: something meaningful to show and an assembler round-trips it.
SMOKE_TEXT = (0x27BDFFF0, 0x03E00008, 0x00000000)
#: The word the object's single relocation points at.
SMOKE_DATA = 0x12345678
#: Names that can never be mistaken for a symbol of the game.
SMOKE_FUNCTION = "seto_smoke_func"
SMOKE_DATA_SYMBOL = "seto_smoke_data"
#: The C the compiler smoke test builds.  Plain and dependency-free.
SMOKE_SOURCE = (
    "/* Built by `seto toolchain --smoke`; not part of the project. */\n"
    "int seto_smoke_add(int left, int right)\n"
    "{\n"
    "    return left + right;\n"
    "}\n"
)
#: The assembly the decompiler smoke test is handed.
SMOKE_ASSEMBLY = """\
.set noat
.set noreorder

.text
.globl {function}
{function}:
    addiu   $sp, $sp, -0x10
    sw      $ra, 0xc($sp)
    jal     {callee}
    nop
    lw      $ra, 0xc($sp)
    jr      $ra
    addiu   $sp, $sp, 0x10

.globl {callee}
{callee}:
    jr      $ra
    nop
""".format(function=SMOKE_FUNCTION, callee=SMOKE_FUNCTION + "_callee")


def _align(value: int, boundary: int) -> int:
    if boundary <= 1:
        return value
    return (value + boundary - 1) // boundary * boundary


def _string_table(names: tuple[str, ...]) -> tuple[bytes, dict[str, int]]:
    # The first byte is NUL, so the empty name is offset 0 by construction.
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {"": 0}
    for name in names:
        if not name or name in offsets:
            continue
        offsets[name] = len(blob)
        blob += name.encode("ascii") + b"\x00"
    return bytes(blob), offsets


@dataclass(frozen=True)
class _Section:
    name: str
    type: int
    flags: int
    align: int
    data: bytes
    addr: int = 0
    link: int = 0
    info: int = 0
    entsize: int = 0


def _assemble(sections: tuple[_Section, ...]) -> bytes:
    """Lay out sections and their header table in a valid ELF32 file."""
    cursor = ELF32_HEADER_SIZE
    offsets: list[int] = []
    for section in sections:
        cursor = _align(cursor, section.align)
        offsets.append(cursor)
        cursor += len(section.data)

    names = tuple(section.name for section in sections) + (".shstrtab",)
    shstrtab, name_offsets = _string_table(names)
    cursor = _align(cursor, 4)
    shstrtab_offset = cursor
    cursor += len(shstrtab)

    shoff = _align(cursor, 4)
    shnum = len(sections) + 2  # NULL, the sections, .shstrtab
    out = bytearray(b"\x00" * (shoff + SECTION_HEADER_SIZE * shnum))
    out[0:4] = b"\x7fELF"
    out[4] = 1  # ELFCLASS32
    out[5] = 1  # ELFDATA2LSB
    out[6] = 1  # EV_CURRENT
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        out,
        0x10,
        ET_REL,
        EM_MIPS,
        1,
        0,
        0,
        shoff,
        0,
        ELF32_HEADER_SIZE,
        0,
        0,
        SECTION_HEADER_SIZE,
        shnum,
        shnum - 1,
    )

    for section, offset in zip(sections, offsets):
        out[offset : offset + len(section.data)] = section.data
    out[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab

    def write(index: int, name: str, header: _Section | None, offset: int, size: int) -> None:
        base = shoff + index * SECTION_HEADER_SIZE
        struct.pack_into(
            "<IIIIIIIIII",
            out,
            base,
            name_offsets[name],
            header.type if header else SHT_STRTAB,
            header.flags if header else 0,
            header.addr if header else 0,
            offset,
            size,
            header.link if header else 0,
            header.info if header else 0,
            header.align if header else 1,
            header.entsize if header else 0,
        )

    for index, (section, offset) in enumerate(zip(sections, offsets), start=1):
        write(index, section.name, section, offset, len(section.data))
    write(shnum - 1, ".shstrtab", None, shstrtab_offset, len(shstrtab))
    return bytes(out)


def build_mips_object() -> bytes:
    """A tiny but completely real ELF32 little-endian MIPS relocatable object.

    It carries everything a tool has to be able to read to prove itself: an
    executable ``.text`` with Allegrex instructions, a ``.rodata`` word, a symbol
    table naming a function and an object, and one ``R_MIPS_32`` relocation.
    """
    text = b"".join(struct.pack("<I", word) for word in SMOKE_TEXT)
    rodata = struct.pack("<I", SMOKE_DATA)
    strtab, offsets = _string_table(("", SMOKE_FUNCTION, SMOKE_DATA_SYMBOL))
    symbols = (
        ("", 0, 0, 0, 0),
        (SMOKE_FUNCTION, 0, len(text), STB_GLOBAL | STT_FUNC, 1),
        (SMOKE_DATA_SYMBOL, 0, len(rodata), STB_GLOBAL | STT_OBJECT, 2),
    )
    symtab = b"".join(
        struct.pack("<IIIBBH", offsets[name], value, size, info, 0, shndx)
        for name, value, size, info, shndx in symbols
    )
    # One relocation, on the first instruction, against the object symbol.
    relocation = struct.pack("<II", 0, (2 << 8) | R_MIPS_32)

    return _assemble(
        (
            _Section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 4, text),
            _Section(".rodata", SHT_PROGBITS, SHF_ALLOC, 4, rodata),
            _Section(".rel.text", SHT_REL, 0, 4, relocation, link=4, info=1, entsize=8),
            _Section(
                ".symtab",
                SHT_SYMTAB,
                0,
                4,
                symtab,
                link=5,
                info=1,
                entsize=SYMBOL_ENTRY_SIZE,
            ),
            _Section(".strtab", SHT_STRTAB, 0, 1, strtab),
        )
    )


@dataclass(frozen=True)
class SmokeInputs:
    """The synthetic files a smoke test hands to a tool."""

    directory: Path
    object_path: Path
    source_path: Path
    assembly_path: Path


def write_inputs(directory: str | Path) -> SmokeInputs:
    """Write the synthetic object, C source and assembly into ``directory``."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    object_path = root / "seto_smoke.o"
    source_path = root / "seto_smoke.c"
    assembly_path = root / "seto_smoke.s"
    object_path.write_bytes(build_mips_object())
    source_path.write_text(SMOKE_SOURCE, encoding="utf-8")
    assembly_path.write_text(SMOKE_ASSEMBLY, encoding="utf-8")
    return SmokeInputs(
        directory=root,
        object_path=object_path,
        source_path=source_path,
        assembly_path=assembly_path,
    )
