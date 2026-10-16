"""Shared synthetic fixtures.

The unit tests never touch the commercial ISO: every fixture here is built
byte-by-byte in memory so the suite is deterministic and self-contained.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

ELF_HEADER_SIZE = 0x34
PROGRAM_HEADER_SIZE = 0x20
SECTION_HEADER_SIZE = 0x28
SYMBOL_SIZE = 0x10
ENTRY_SIZE = 0x10

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_REL = 9

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

PSF_TYPE_BIN = 0x0004
PSF_TYPE_STR = 0x0204
PSF_TYPE_VAL = 0x0404


def align(value: int, boundary: int) -> int:
    if boundary <= 1:
        return value
    return (value + boundary - 1) // boundary * boundary


# --------------------------------------------------------------------------- SFO


def build_sfo(
    entries: Sequence[tuple[str, int, Any]],
    *,
    version: int = 0x00000101,
    magic: bytes = b"\x00PSF",
    key_table_offset: int | None = None,
    data_table_offset: int | None = None,
    entry_count: int | None = None,
) -> bytes:
    """Build a synthetic PARAM.SFO.

    ``entries`` is a sequence of ``(key, fmt, value)`` where an int32 value is
    an ``int`` and a string/blob value is ``bytes``.
    """
    key_blob = bytearray()
    key_offsets: list[int] = []
    for key, _fmt, _value in entries:
        key_offsets.append(len(key_blob))
        key_blob += key.encode("ascii") + b"\x00"
    key_blob += b"\x00" * (-len(key_blob) % 4)

    data_blob = bytearray()
    data_offsets: list[int] = []
    lengths: list[int] = []
    for _key, fmt, value in entries:
        data_offsets.append(len(data_blob))
        if fmt == PSF_TYPE_VAL:
            raw = int(value).to_bytes(4, "little", signed=False)
        else:
            raw = bytes(value)
        lengths.append(len(raw))
        data_blob += raw
    data_blob += b"\x00" * (-len(data_blob) % 4)

    if key_table_offset is None:
        key_table_offset = 0x14 + ENTRY_SIZE * len(entries)
    if data_table_offset is None:
        data_table_offset = key_table_offset + len(key_blob)
    if entry_count is None:
        entry_count = len(entries)

    out = bytearray()
    out += magic
    out += struct.pack("<IIII", version, key_table_offset, data_table_offset, entry_count)
    for index, (key, fmt, _value) in enumerate(entries):
        out += struct.pack(
            "<HHIII",
            key_offsets[index],
            fmt,
            lengths[index],
            align(lengths[index], 4),
            data_offsets[index],
        )
    assert len(out) == 0x14 + 16 * len(entries)
    if len(out) < key_table_offset:
        out += b"\x00" * (key_table_offset - len(out))
    out += key_blob
    if len(out) < data_table_offset:
        out += b"\x00" * (data_table_offset - len(out))
    out += data_blob
    return bytes(out)


# --------------------------------------------------------------------------- ELF


def _build_string_table(names: Sequence[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        if name in offsets:
            continue
        offsets[name] = len(blob)
        blob += name.encode("ascii") + b"\x00"
    return bytes(blob), offsets


def build_elf32(
    *,
    e_type: int = 1,
    e_machine: int = 8,
    e_entry: int = 0,
    e_flags: int = 0,
    ei_class: int = 1,
    ei_data: int = 1,
    magic: bytes = b"\x7fELF",
    sections: Sequence[Mapping[str, Any]] = (),
    program_headers: Sequence[Mapping[str, Any]] = (),
    include_shstrtab: bool = True,
    e_shnum_override: int | None = None,
    e_shstrndx_override: int | None = None,
    e_shentsize_override: int | None = None,
    truncate_to: int | None = None,
) -> bytes:
    """Build a synthetic little-endian ELF32.

    A NULL section (index 0) is always inserted first; a ``.shstrtab`` is
    appended last unless ``include_shstrtab`` is False.  Section ``data`` blobs
    are laid out sequentially after the program headers.
    """
    provided = [dict(section) for section in sections]
    names = [str(section.get("name", f"section_{index}")) for index, section in enumerate(provided)]

    cursor = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * len(program_headers)
    placed: list[dict[str, Any]] = []
    for section, name in zip(provided, names):
        spec = dict(section)
        spec["name"] = name
        sec_type = int(spec.get("type", SHT_PROGBITS))
        spec["type"] = sec_type
        data = bytes(spec.get("data", b""))
        size = int(spec.get("size", len(data)))
        align_to = int(spec.get("align", 4))
        if sec_type == SHT_NOBITS:
            spec["offset"] = int(spec.get("offset", cursor))
            spec["size"] = size
            placed.append(spec)
            continue
        cursor = align(cursor, align_to)
        spec["offset"] = int(spec.get("offset", cursor))
        spec["size"] = size
        spec["_data"] = data
        cursor = spec["offset"] + size
        placed.append(spec)

    shstrtab_blob = b""
    offsets: dict[str, int] = {}
    if include_shstrtab:
        cursor = align(cursor, 4)
        shstrtab_offset = cursor
        shstrtab_blob, offsets = _build_string_table([*names, ".shstrtab"])
        cursor += len(shstrtab_blob)

    shoff = align(cursor, 4)
    shnum = 1 + len(placed) + (1 if include_shstrtab else 0)
    shstrndx = 0
    if include_shstrtab:
        shstrndx = shnum - 1
    if e_shnum_override is not None:
        shnum = e_shnum_override
    if e_shstrndx_override is not None:
        shstrndx = e_shstrndx_override

    out = bytearray(b"\x00" * (shoff + SECTION_HEADER_SIZE * shnum))
    out[0:4] = magic
    out[4] = ei_class
    out[5] = ei_data
    out[6] = 1
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        out,
        0x10,
        e_type,
        e_machine,
        1,
        e_entry,
        ELF_HEADER_SIZE if program_headers else 0,
        shoff,
        e_flags,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        len(program_headers),
        e_shentsize_override if e_shentsize_override is not None else SECTION_HEADER_SIZE,
        shnum,
        shstrndx,
    )

    for index, header in enumerate(program_headers):
        base = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE
        offset = int(header.get("offset", ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * len(program_headers)))
        filesz = int(header.get("filesz", 0))
        struct.pack_into(
            "<IIIIIIII",
            out,
            base,
            int(header.get("type", 1)),
            offset,
            int(header.get("vaddr", 0)),
            int(header.get("paddr", 0)),
            filesz,
            int(header.get("memsz", filesz)),
            int(header.get("flags", 0)),
            int(header.get("align", 4)),
        )

    for spec in placed:
        if spec["type"] == SHT_NOBITS:
            continue
        out[spec["offset"] : spec["offset"] + len(spec["_data"])] = spec["_data"]

    if include_shstrtab:
        out[shstrtab_offset : shstrtab_offset + len(shstrtab_blob)] = shstrtab_blob

    # Section header table: index 0 is NULL, then the provided sections.
    for index, spec in enumerate(placed, start=1):
        name_offset = offsets.get(spec["name"], 0) if include_shstrtab else 0
        struct.pack_into(
            "<IIIIIIIIII",
            out,
            shoff + index * SECTION_HEADER_SIZE,
            name_offset,
            int(spec.get("type", SHT_PROGBITS)),
            int(spec.get("flags", 0)),
            int(spec.get("addr", 0)),
            int(spec["offset"]),
            int(spec["size"]),
            int(spec.get("link", 0)),
            int(spec.get("info", 0)),
            int(spec.get("align", 4)),
            int(spec.get("entsize", 0)),
        )
    if include_shstrtab:
        struct.pack_into(
            "<IIIIIIIIII",
            out,
            shoff + (shnum - 1) * SECTION_HEADER_SIZE,
            offsets[".shstrtab"],
            SHT_STRTAB,
            0,
            0,
            shstrtab_offset,
            len(shstrtab_blob),
            0,
            0,
            1,
            0,
        )
    result = bytes(out)
    if truncate_to is not None:
        result = result[:truncate_to]
    return result


def build_symbol_table(names: Sequence[str]) -> tuple[bytes, bytes]:
    """Build a (symtab, strtab) pair; symbol ``i`` is named ``names[i]``."""
    strtab, offsets = _build_string_table(list(names))
    entries = bytearray()
    for index, name in enumerate(names):
        entries += struct.pack(
            "<IIIBBH",
            offsets[name] if name else 0,
            0,
            0,
            0x10,
            0,
            1 if index else 0,
        )
    return bytes(entries), strtab


def build_relocations(entries: Sequence[tuple[int, int, int]]) -> bytes:
    """Build an ``Elf32_Rel`` blob from ``(r_offset, type, symbol_index)`` tuples."""
    blob = bytearray()
    for offset, rel_type, symbol in entries:
        blob += struct.pack("<II", offset, (symbol << 8) | rel_type)
    return bytes(blob)


# --------------------------------------------------------------------------- MIPS


def word(value: int) -> bytes:
    return struct.pack("<I", value)


def jal(target: int) -> int:
    return 0x03 << 26 | ((target >> 2) & 0x03FFFFFF)


def jr(register: int = 31) -> int:
    return (register << 21) | 0x08


# --------------------------------------------------------------------------- pytest


@pytest.fixture
def sfo_file(tmp_path: Path) -> Path:
    payload = build_sfo(
        [
            ("TITLE", PSF_TYPE_STR, b"Test Game\x00"),
            ("BOOTABLE", PSF_TYPE_VAL, 1),
        ]
    )
    target = tmp_path / "PARAM.SFO"
    target.write_bytes(payload)
    return target
