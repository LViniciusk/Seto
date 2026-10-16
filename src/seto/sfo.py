"""Secure parser for ``PARAM.SFO`` (PSF) system metadata files.

The parser never trusts the file: table offsets, entry counts, key strings and
value lengths are all validated against the real buffer size before they are
used, and every failure is reported as a :class:`~seto.binio.ParseError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from seto.binio import BytesReader, ParseError, read_file

SFO_MAGIC = b"\x00PSF"
HEADER_SIZE = 0x14
ENTRY_SIZE = 0x10

# PARAM.SFO value formats, following the Sony / pspsdk convention:
#   0x0004 binary blob, 0x0204 UTF-8 string, 0x0404 int32.
PSF_TYPE_BIN = 0x0004
PSF_TYPE_STR = 0x0204
PSF_TYPE_VAL = 0x0404

FORMAT_NAMES: dict[int, str] = {
    PSF_TYPE_BIN: "bin",
    PSF_TYPE_STR: "string",
    PSF_TYPE_VAL: "int32",
}


@dataclass(frozen=True)
class SfoEntry:
    """A single ``PARAM.SFO`` key/value pair."""

    key: str
    fmt: int
    fmt_name: str
    value: bytes | int
    key_offset: int
    data_offset: int
    length: int
    max_length: int


@dataclass(frozen=True)
class SfoDocument:
    """A parsed ``PARAM.SFO`` file."""

    version: int
    entries: tuple[SfoEntry, ...]

    def get(self, key: str, default: str | int | None = None) -> str | int | None:
        for entry in self.entries:
            if entry.key == key:
                return entry.value
        return default

    def as_dict(self) -> dict[str, str | int]:
        return {entry.key: entry.value for entry in self.entries}

    def summary(self) -> dict[str, object]:
        return {"version": self.version, "keys": [e.key for e in self.entries]}


def parse_source(source: BytesReader | bytes | str | Path, name: str | None = None) -> SfoDocument:
    """Parse a ``PARAM.SFO`` from a reader, raw bytes or a filesystem path."""
    if isinstance(source, BytesReader):
        reader = source
    elif isinstance(source, (str, Path)):
        reader = read_file(source)
    else:
        reader = BytesReader(source, name or "<memory>")
    return parse(reader)


def parse(reader: BytesReader) -> SfoDocument:
    """Parse a ``PARAM.SFO`` from ``reader``, validating every declared span."""
    if reader.size < HEADER_SIZE:
        raise ParseError(f"{reader.name}: too small for an SFO header")
    if reader.bytes_at(0, 4) != SFO_MAGIC:
        raise ParseError(f"{reader.name}: bad SFO magic")

    version = reader.u32(0x04)
    key_table_offset = reader.u32(0x08)
    data_table_offset = reader.u32(0x0C)
    entry_count = reader.u32(0x10)

    if key_table_offset < HEADER_SIZE:
        raise ParseError(f"{reader.name}: key table starts inside the header")
    if data_table_offset < key_table_offset:
        raise ParseError(f"{reader.name}: data table starts before the key table")
    if data_table_offset > reader.size:
        raise ParseError(f"{reader.name}: data table starts past end of file")
    if entry_count > (key_table_offset - HEADER_SIZE) // ENTRY_SIZE:
        raise ParseError(f"{reader.name}: entry index table does not fit in the key table")

    entries: list[SfoEntry] = []
    for index in range(entry_count):
        base = HEADER_SIZE + index * ENTRY_SIZE
        key_offset = reader.u16(base)
        fmt = reader.u16(base + 0x02)
        length = reader.u32(base + 0x04)
        max_length = reader.u32(base + 0x08)
        data_offset = reader.u32(base + 0x0C)

        if length > max_length:
            raise ParseError(
                f"{reader.name}: entry {index} length {length} exceeds max length {max_length}"
            )

        key = _read_key(reader, key_table_offset, data_table_offset, key_offset, index)
        value = _read_value(reader, data_table_offset, fmt, length, data_offset, index)
        entries.append(
            SfoEntry(
                key=key,
                fmt=fmt,
                fmt_name=FORMAT_NAMES.get(fmt, f"unknown(0x{fmt:04x})"),
                value=value,
                key_offset=key_offset,
                data_offset=data_offset,
                length=length,
                max_length=max_length,
            )
        )

    _reject_duplicate_keys(reader, entries)
    return SfoDocument(version=version, entries=tuple(entries))


def _read_key(
    reader: BytesReader,
    key_table_offset: int,
    data_table_offset: int,
    key_offset: int,
    index: int,
) -> str:
    absolute = key_table_offset + key_offset
    if absolute >= data_table_offset:
        raise ParseError(f"{reader.name}: entry {index} key offset escapes the key table")
    return reader.cstring(absolute, limit=data_table_offset - absolute)


def _read_value(
    reader: BytesReader,
    data_table_offset: int,
    fmt: int,
    length: int,
    data_offset: int,
    index: int,
) -> bytes | int:
    absolute = data_table_offset + data_offset
    reader.span(absolute, length)
    if fmt == PSF_TYPE_VAL:
        if length not in (0, 4):
            raise ParseError(
                f"{reader.name}: entry {index} int32 value has invalid length {length}"
            )
        return reader.i32(absolute) if length == 4 else 0
    if fmt not in (PSF_TYPE_BIN, PSF_TYPE_STR):
        raise ParseError(f"{reader.name}: entry {index} uses unknown format 0x{fmt:04x}")
    return reader.bytes_at(absolute, length)


def _reject_duplicate_keys(reader: BytesReader, entries: list[SfoEntry]) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry.key in seen:
            raise ParseError(f"{reader.name}: duplicate key {entry.key!r}")
        seen.add(entry.key)


def value_as_text(entry: SfoEntry) -> str:
    """Render an entry value as text for reports."""
    if isinstance(entry.value, int):
        return str(entry.value)
    if entry.fmt_name == "string":
        return entry.value.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return "0x" + entry.value.hex()
