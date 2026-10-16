"""Tests for the shared bounds-checked binary reader."""

from __future__ import annotations

import pytest

from seto.binio import (
    BoundsError,
    BytesReader,
    ParseError,
    checked_span,
    read_file,
)


def test_checked_span_accepts_exact_fit() -> None:
    assert checked_span(10, 0, 10) == slice(0, 10)
    assert checked_span(10, 10, 0) == slice(10, 10)


@pytest.mark.parametrize(
    ("size", "offset", "length"),
    [
        (10, 0, 11),
        (10, 5, 6),
        (10, 11, 0),
        (10, -1, 1),
        (10, 0, -1),
    ],
)
def test_checked_span_rejects_out_of_bounds(size: int, offset: int, length: int) -> None:
    with pytest.raises(ValueError):
        checked_span(size, offset, length)


def test_reader_scalar_accessors() -> None:
    reader = BytesReader(bytes([0xFF, 0x01, 0x02, 0xFE, 0xFF, 0xFF, 0xFF], ) + b"\x00")
    assert reader.u8(0) == 0xFF
    assert reader.u16(1) == 0x0201
    assert reader.u32(3) == 0xFFFFFFFE
    assert reader.i16(1) == 0x0201
    assert reader.i32(3) == -2


def test_reader_reports_bounds_with_context() -> None:
    reader = BytesReader(b"abc", name="tiny.bin")
    with pytest.raises(BoundsError) as error:
        reader.u32(0)
    assert "tiny.bin" in str(error.value)


def test_reader_words32_requires_multiple_of_four() -> None:
    reader = BytesReader(b"\x01\x00\x00\x00\x02\x00")
    with pytest.raises(ParseError):
        reader.words32(0, 6)
    assert reader.words32(0, 4) == [1]


def test_reader_cstring_terminated_and_unterminated() -> None:
    reader = BytesReader(b"hello\x00world")
    assert reader.cstring(0) == "hello"
    with pytest.raises(ParseError):
        reader.cstring(6)


def test_reader_cstring_honours_limit() -> None:
    reader = BytesReader(b"a\x00b\x00")
    assert reader.cstring(0, limit=2) == "a"
    with pytest.raises(ParseError):
        reader.cstring(0, limit=1)  # the terminator falls outside the window
    with pytest.raises(BoundsError):
        reader.cstring(99)


def test_reader_sub_and_read_file(tmp_path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"ABCDEF")
    reader = read_file(path)
    assert reader.name == str(path)
    assert reader.sub(1, 3).data == b"BCD"
    assert reader.sub(1, 3).name.startswith(str(path))


def test_reader_is_read_only() -> None:
    reader = BytesReader(b"payload")
    assert reader.data == b"payload"
    with pytest.raises(Exception):
        reader.data = b"other"  # type: ignore[misc]
