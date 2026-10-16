"""Bounds-checked binary reading primitives shared by every Seto parser.

Every parser treats its input as untrusted: all offsets and lengths that come
from the file itself are validated through :func:`checked_span` before use, so a
malformed header can never trigger an out-of-bounds read or an unbounded
allocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class SetoError(Exception):
    """Base class for every error raised by Seto."""


class ParseError(SetoError):
    """The input does not conform to the format being parsed."""


class BoundsError(ParseError):
    """A read would leave the bounds of the available data."""


def checked_span(size: int, offset: int, length: int) -> slice:
    """Return ``slice(offset, offset + length)`` after validating the bounds.

    ``size`` is the size of the buffer the span is taken from. Negative values
    and any span that is not fully contained in ``[0, size]`` are rejected.
    """
    if offset < 0 or length < 0:
        raise ValueError("Negative offset or length")
    if offset > size or length > size - offset:
        raise ValueError("Span exceeds buffer bounds")
    return slice(offset, offset + length)


@dataclass(frozen=True)
class BytesReader:
    """A read-only, bounds-checked view over an immutable byte buffer."""

    data: bytes
    name: str = "<memory>"

    @property
    def size(self) -> int:
        return len(self.data)

    def span(self, offset: int, length: int) -> slice:
        try:
            return checked_span(self.size, offset, length)
        except ValueError as exc:
            raise BoundsError(
                f"{self.name}: {exc} (offset={offset:#x}, length={length:#x})"
            ) from exc

    def bytes_at(self, offset: int, length: int) -> bytes:
        return self.data[self.span(offset, length)]

    def sub(self, offset: int, length: int, name: str | None = None) -> BytesReader:
        return BytesReader(
            self.bytes_at(offset, length),
            name or f"{self.name}[{offset:#x}:{offset + length:#x}]",
        )

    def u8(self, offset: int) -> int:
        return self.data[self.span(offset, 1)][0]

    def u16(self, offset: int) -> int:
        return int.from_bytes(self.bytes_at(offset, 2), "little")

    def u32(self, offset: int) -> int:
        return int.from_bytes(self.bytes_at(offset, 4), "little")

    def i16(self, offset: int) -> int:
        return int.from_bytes(self.bytes_at(offset, 2), "little", signed=True)

    def i32(self, offset: int) -> int:
        return int.from_bytes(self.bytes_at(offset, 4), "little", signed=True)

    def words32(self, offset: int, length: int) -> list[int]:
        """Decode ``length`` bytes as little-endian ``uint32`` words."""
        if length % 4:
            raise ParseError(
                f"{self.name}: word count is not a multiple of 4 "
                f"(offset={offset:#x}, length={length:#x})"
            )
        raw = self.bytes_at(offset, length)
        return [
            int.from_bytes(raw[i : i + 4], "little") for i in range(0, len(raw), 4)
        ]

    def cstring_bytes(self, offset: int, limit: int | None = None) -> bytes:
        """Read a NUL-terminated byte string, rejecting unterminated ones."""
        if offset < 0 or offset > self.size:
            raise BoundsError(f"{self.name}: offset {offset:#x} outside buffer")
        end = self.size if limit is None else min(self.size, offset + max(0, limit))
        terminator = self.data.find(b"\x00", offset, end)
        if terminator < 0:
            raise ParseError(f"{self.name}: unterminated string at {offset:#x}")
        return self.data[offset:terminator]

    def cstring(self, offset: int, limit: int | None = None) -> str:
        return self.cstring_bytes(offset, limit).decode("utf-8", "replace")


def read_file(path: str | Path) -> BytesReader:
    """Read a whole file into a :class:`BytesReader` (for small inputs only)."""
    resolved = Path(path)
    return BytesReader(resolved.read_bytes(), name=str(resolved))
