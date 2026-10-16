"""Tests for the PARAM.SFO parser: valid, invalid and truncated inputs."""

from __future__ import annotations

import struct

import pytest

from seto.binio import ParseError
from seto.sfo import (
    PSF_TYPE_STR,
    PSF_TYPE_VAL,
    parse,
    parse_source,
    value_as_text,
)
from seto.binio import BytesReader

from conftest import PSF_TYPE_BIN, build_sfo


def test_parse_valid_document() -> None:
    payload = build_sfo(
        [
            ("TITLE", PSF_TYPE_STR, b"Yu-Gi-Oh! Tag Force\x00"),
            ("BOOTABLE", PSF_TYPE_VAL, 1),
            ("REGION", PSF_TYPE_BIN, b"\x00\x80\x00\x00"),
        ]
    )
    document = parse_source(payload)
    assert document.version == 0x00000101
    assert document.get("TITLE") == b"Yu-Gi-Oh! Tag Force\x00"
    assert document.get("BOOTABLE") == 1
    assert document.get("MISSING", "fallback") == "fallback"
    assert document.get("REGION") == b"\x00\x80\x00\x00"
    assert value_as_text(document.entries[0]) == "Yu-Gi-Oh! Tag Force"
    assert value_as_text(document.entries[1]) == "1"
    assert value_as_text(document.entries[2]) == "0x00800000"


def test_parse_from_path(sfo_file) -> None:
    document = parse_source(sfo_file)
    keys = [entry.key for entry in document.entries]
    assert keys == ["TITLE", "BOOTABLE"]
    assert document.summary() == {"version": 0x00000101, "keys": ["TITLE", "BOOTABLE"]}


def test_parse_rejects_bad_magic() -> None:
    payload = build_sfo([("A", PSF_TYPE_VAL, 1)], magic=b"\x00PSX")
    with pytest.raises(ParseError, match="bad SFO magic"):
        parse_source(payload)


def test_parse_rejects_truncated_header() -> None:
    with pytest.raises(ParseError, match="too small"):
        parse_source(b"\x00PSF\x01\x01")


def test_parse_rejects_key_table_inside_header() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<I", payload, 0x08, 0x04)
    with pytest.raises(ParseError, match="key table"):
        parse_source(bytes(payload))


def test_parse_rejects_data_table_before_key_table() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<I", payload, 0x0C, 0x04)
    with pytest.raises(ParseError, match="data table"):
        parse_source(bytes(payload))


def test_parse_rejects_data_table_past_end_of_file() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<I", payload, 0x0C, 0xFFFF)
    with pytest.raises(ParseError, match="past end of file"):
        parse_source(bytes(payload))


def test_parse_rejects_entry_table_that_does_not_fit() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<I", payload, 0x10, 0x40)
    with pytest.raises(ParseError, match="does not fit"):
        parse_source(bytes(payload))


def test_parse_rejects_int32_with_wrong_length() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<I", payload, 0x14 + 4, 3)
    with pytest.raises(ParseError, match="invalid length"):
        parse_source(bytes(payload))


def test_parse_rejects_length_above_maximum() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_STR, b"abc\x00")]))
    struct.pack_into("<I", payload, 0x14 + 4, 0x40)  # length
    struct.pack_into("<I", payload, 0x14 + 8, 0x04)  # max length
    with pytest.raises(ParseError, match="exceeds max length"):
        parse_source(bytes(payload))


def test_parse_rejects_unknown_format() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_STR, b"abc\x00")]))
    struct.pack_into("<H", payload, 0x14 + 2, 0x1234)
    with pytest.raises(ParseError, match="unknown format"):
        parse_source(bytes(payload))


def test_parse_rejects_key_escaping_the_key_table() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_VAL, 1)]))
    struct.pack_into("<H", payload, 0x14, 0xFF)
    with pytest.raises(ParseError, match="escapes the key table"):
        parse_source(bytes(payload))


def test_parse_rejects_value_outside_the_file() -> None:
    payload = bytearray(build_sfo([("A", PSF_TYPE_STR, b"abcd\x00")]))
    struct.pack_into("<I", payload, 0x14 + 0x0C, 0xFFFF)  # data offset
    with pytest.raises(ParseError):
        parse_source(bytes(payload))


def test_parse_rejects_unterminated_key() -> None:
    payload = build_sfo([("AB", PSF_TYPE_VAL, 1)])
    truncated = payload[: 0x14 + 16 + 1]  # cut inside the key table
    with pytest.raises(ParseError):
        parse_source(truncated)


def test_parse_rejects_duplicate_keys() -> None:
    payload = build_sfo([("A", PSF_TYPE_VAL, 1), ("A", PSF_TYPE_VAL, 2)])
    with pytest.raises(ParseError, match="duplicate key"):
        parse_source(bytes(payload))


def test_parse_accepts_reader_input() -> None:
    payload = build_sfo([("A", PSF_TYPE_VAL, 7)])
    document = parse(BytesReader(payload, name="memory.sfo"))
    assert document.get("A") == 7
