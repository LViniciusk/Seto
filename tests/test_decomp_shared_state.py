"""The shared-state block's C representation and its layout record.

SETO-DECOMP-011's audit hardening replaced a one-byte declaration of the object
at 0x604864 with ``SetoObservedBlock``, a record of the offsets that
``func_00000508`` writes and ``func_00000634`` reads.  The compile-time checks in
the header are the primary validation - the target compiler rejects a wrong
offset or size when the reconstructions are compiled.  These tests are the
media-free net underneath that: they recompute the layout from the header text,
check that every documented offset carries a compiler check, and check that the
two sources reach the block only through in-region members.

They read the header and the sources as text, so they need neither the PRX, the
licensed compiler nor Ghidra, and they run in the default suite.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HEADER = REPO_ROOT / "decomp" / "include" / "seto_shared_state.h"
SOURCE_508 = REPO_ROOT / "decomp" / "src" / "func_00000508.c"
SOURCE_634 = REPO_ROOT / "decomp" / "src" / "func_00000634.c"

BLOCK_SIZE = 0xA4

#: The members in declaration order: name, element kind, element count.
EXPECTED_MEMBERS = (
    ("words_00_2c", "unsigned int", 12),
    ("field_30", "pointer", 1),
    ("words_34_3c", "unsigned int", 3),
    ("field_40", "pointer", 1),
    ("words_44_4c", "unsigned int", 3),
    ("field_50", "pointer", 1),
    ("words_54_64", "unsigned int", 5),
    ("field_68", "pointer", 1),
    ("words_6c_78", "unsigned int", 4),
    ("reserved", "unsigned char", 0x28),
)

#: The member offsets the header must pin with a compile-time check.
CHECKED_OFFSETS = (0x00, 0x1C, 0x30, 0x34, 0x40, 0x50, 0x68, 0x78)

#: Every offset the two reconstructions touch, as bytes from the block start.
#: func_00000508 writes all of them except 0x1C; func_00000634 reads 0x1C.
EXPECTED_ACCESSES = frozenset(
    {
        0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18,
        0x30, 0x34, 0x40, 0x44, 0x48, 0x4C, 0x50,
        0x54, 0x58, 0x5C, 0x60, 0x64, 0x68, 0x6C,
        0x70, 0x74, 0x78,
    }
) | {0x1C}

_MEMBER = re.compile(
    r"^\s*(?P<kind>unsigned int|unsigned char|void\s*\*)"
    r"\s*(?P<name>[A-Za-z_]\w*)"
    r"(?:\[(?P<length>\d+|0x[0-9A-Fa-f]+)\])?\s*;",
    re.MULTILINE,
)


def _header_text() -> str:
    return HEADER.read_text(encoding="utf-8")


def _member_layout() -> tuple[dict[str, tuple[int, int, int]], int]:
    """Recompute the block layout from the header's own declaration.

    The target is 32-bit MIPS with 4-byte ``int`` and pointers, and the target
    compiler confirms the size when the sources are compiled; this mirror only
    re-derives the offsets from the declaration order, so a reordered, resized or
    retyped field is caught here as well.
    """
    body = re.search(
        r"typedef struct\s*\{(?P<body>.*?)\}\s*SetoObservedBlock\s*;",
        _header_text(),
        re.DOTALL,
    )
    assert body is not None, "the header must declare SetoObservedBlock"
    members = _MEMBER.findall(body.group("body"))
    assert members, "the header's struct must declare its members"

    layout: dict[str, tuple[int, int, int]] = {}
    offset = 0
    for kind, name, length in members:
        size = 1 if kind == "unsigned char" else 4
        count = int(length, 0) if length else 1
        offset = (offset + size - 1) // size * size
        layout[name] = (offset, size * count, count)
        offset += size * count
    return layout, (offset + 3) // 4 * 4


def _offsets(layout: dict[str, tuple[int, int, int]]) -> dict[str, int]:
    return {name: entry[0] for name, entry in layout.items()}


def _accessed_offsets(path: Path, offsets: dict[str, int]) -> set[int]:
    """Every byte offset the source reaches through the block."""
    text = path.read_text(encoding="utf-8")
    touched: set[int] = set()
    for name, index in re.findall(r"base->(\w+)(?:\[(\d+)\])?", text):
        assert name in offsets, f"{path.name} names an undeclared member {name!r}"
        base = offsets[name]
        touched.add(base + int(index) * 4 if index else base)
    # The two stores that keep a word-typed view of the block's first member
    # (see each source's "source forms forced by the words").
    for index in re.findall(r"(?<![\w.])words\[(\d+)\]", text):
        touched.add(int(index) * 4)
    return touched


def test_the_header_declares_the_expected_member_sequence() -> None:
    layout, _size = _member_layout()
    declared = [(name, entry[2]) for name, entry in layout.items()]
    assert declared == [(name, count) for name, _kind, count in EXPECTED_MEMBERS]


def test_the_block_is_0xa4_bytes_with_the_documented_offsets() -> None:
    layout, size = _member_layout()
    assert size == BLOCK_SIZE

    offsets = _offsets(layout)
    assert offsets["words_00_2c"] == 0x00
    assert offsets["field_30"] == 0x30
    assert offsets["words_34_3c"] == 0x34
    assert offsets["field_40"] == 0x40
    assert offsets["words_44_4c"] == 0x44
    assert offsets["field_50"] == 0x50
    assert offsets["words_54_64"] == 0x54
    assert offsets["field_68"] == 0x68
    assert offsets["words_6c_78"] == 0x6C
    assert offsets["reserved"] == 0x7C
    assert offsets["reserved"] + layout["reserved"][1] == BLOCK_SIZE


def test_the_header_pins_every_documented_offset_at_compile_time() -> None:
    text = _header_text()
    assert "== 0x%02X ? 1 : -1]" % BLOCK_SIZE in text
    for offset in CHECKED_OFFSETS:
        assert "== 0x%02X ? 1 : -1]" % offset in text, hex(offset)
    assert "seto_check_block_alignment" in text
    assert "seto_check_int_size" in text and "seto_check_pointer_size" in text


def test_the_header_does_not_need_the_absent_standard_headers() -> None:
    """The target compiler has no reachable ``<stddef.h>`` (no MWCIncludes)."""
    text = _header_text()
    assert "#include <stddef.h>" not in text
    assert "offsetof(" not in text.replace("SETO_OFFSETOF(", "")
    assert "SETO_OFFSETOF(type, member)" in text


def test_the_object_is_declared_once_as_the_typed_block() -> None:
    assert "extern SetoObservedBlock D_00604864;" in _header_text()
    for source in (SOURCE_508, SOURCE_634):
        text = source.read_text(encoding="utf-8")
        assert '#include "seto_shared_state.h"' in text
        assert "extern SetoObservedBlock D_00604864" not in text
        assert "extern unsigned char D_00604864" not in text, (
            "the object is declared in the header only"
        )
        # The byte-typed view and the pointer casts it forced are gone.
        assert "unsigned char *base" not in text
        assert "(int *)" not in text
        assert "(void **)" not in text


@pytest.mark.parametrize("source", [SOURCE_508, SOURCE_634], ids=["0508", "0634"])
def test_the_sources_only_touch_offsets_inside_the_block(source: Path) -> None:
    layout, _size = _member_layout()
    accessed = _accessed_offsets(source, _offsets(layout))
    assert accessed, "the source must reach the block"
    assert accessed <= EXPECTED_ACCESSES, accessed - EXPECTED_ACCESSES
    for offset in accessed:
        assert 0 <= offset < BLOCK_SIZE, hex(offset)


def test_the_two_sources_together_cover_exactly_the_documented_accesses() -> None:
    layout, _size = _member_layout()
    offsets = _offsets(layout)
    union = _accessed_offsets(SOURCE_508, offsets) | _accessed_offsets(SOURCE_634, offsets)
    assert union == EXPECTED_ACCESSES
    # The reserved tail is cleared byte-wise and is never field-accessed.
    reserved = offsets["reserved"]
    assert not {offset for offset in union if offset >= reserved}
