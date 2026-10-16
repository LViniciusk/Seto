"""Tests for the relocation-aware instruction comparator."""

from __future__ import annotations

import pytest

from seto.binio import ParseError
from seto.elf import R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_32, Relocation
from seto.matching import (
    MATCHED,
    NONMATCHING,
    RelocationSite,
    compare,
    compare_region,
    relocation_sites,
)

from conftest import jal, jr

NOP = 0x00000000


def _word(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _code(*words: int) -> bytes:
    return b"".join(_word(value) for value in words)


def rel(
    section_offset: int,
    rel_type: int = R_MIPS_26,
    *,
    addend: int = 0,
    symbol: str | None = None,
) -> Relocation:
    return Relocation(
        offset=section_offset,
        type=rel_type,
        symbol_index=0,
        addend=addend,
        symbol=symbol,
        target_section=".text",
        section_offset=section_offset,
        file_offset=None,
    )


# ------------------------------------------------------------------- identical


def test_identical_streams_match() -> None:
    code = _code(jr(31), NOP, jr(31))
    result = compare(code, code, name="func_00000000")
    assert result.status == MATCHED
    assert result.is_matched
    assert result.total_words == 3
    assert result.matching_words == 3
    assert result.percent == 100.0
    assert result.difference_count == 0
    assert result.differences == ()


def test_empty_streams_match_at_100_percent() -> None:
    result = compare(b"", b"", name="empty")
    assert result.status == MATCHED
    assert result.total_words == 0
    assert result.percent == 100.0


# ------------------------------------------------------------------ plain words


def test_plain_word_difference_is_reported() -> None:
    result = compare(_code(NOP, 0x24020001), _code(NOP, 0x24020002), name="f")
    assert result.status == NONMATCHING
    assert result.difference_count == 1
    assert result.matching_words == 1
    difference = result.differences[0]
    assert difference.word_index == 1
    assert difference.address == 4
    assert difference.reason == "word differs"
    assert result.relocation_issues == ()


def test_size_mismatch_is_reported_as_a_difference() -> None:
    result = compare(_code(NOP), _code(NOP, NOP), name="f")
    assert result.status == NONMATCHING
    assert result.difference_count == 1
    assert result.total_words == 2
    assert result.matching_words == 1
    assert any("size mismatch" in issue for issue in result.relocation_issues)


def test_address_offsets_the_reported_word_address() -> None:
    result = compare(_code(NOP, NOP), _code(NOP, jr(31)), name="f", address=0x244)
    assert result.differences[0].address == 0x248


# ---------------------------------------------------------------- relocations


def test_relocated_word_with_equal_type_and_addend_matches() -> None:
    word = jal(0x40)
    result = compare(
        _code(word),
        _code(word),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40)],
    )
    assert result.status == MATCHED
    assert result.matching_words == 1


def test_relocated_word_with_different_addend_is_a_difference() -> None:
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x80)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x80)],
    )
    assert result.status == NONMATCHING
    assert "addend" in result.differences[0].reason
    assert result.relocation_issues


def test_relocated_word_differing_outside_the_field_is_a_difference() -> None:
    # Same R_MIPS_26, but the opcode bits change (jal -> a different opcode),
    # which the relocation does not cover.
    original = jal(0x40)
    candidate = (original & 0x03FFFFFF) | (0x02 << 26)
    result = compare(
        _code(original),
        _code(candidate),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40)],
    )
    assert result.status == NONMATCHING
    assert "outside the relocation field" in result.differences[0].reason


def test_relocation_type_mismatch_is_a_difference() -> None:
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(0, R_MIPS_HI16, addend=0x40)],
    )
    assert result.status == NONMATCHING
    assert "relocation type" in result.differences[0].reason


def test_relocation_on_one_side_only_is_a_difference() -> None:
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
    )
    assert result.status == NONMATCHING
    # The words are byte-identical, so this is counted as matching...
    assert result.matching_words == 1
    # ...but the one-sided relocation is still surfaced as a hard issue.
    assert result.difference_count == 1
    assert "relocation present only on the original side" in result.relocation_issues[0]


def test_symbol_mismatch_is_a_difference() -> None:
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40, symbol="memcpy")],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40, symbol="memset")],
    )
    assert result.status == NONMATCHING
    assert "symbol" in result.differences[0].reason


def test_one_sided_symbol_is_a_recorded_limitation_not_a_difference() -> None:
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40, symbol="memcpy")],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40)],
    )
    assert result.status == MATCHED
    assert result.limitations
    assert "only one side" in result.limitations[0]


def test_unmodelled_relocation_falls_back_to_exact_word_match() -> None:
    # R_MIPS_16 (type 1) has no known mask.
    result = compare(
        _code(0x00001234),
        _code(0x00001234),
        name="f",
        original_relocations=[rel(0, 1)],
        candidate_relocations=[rel(0, 1)],
    )
    assert result.status == MATCHED
    assert any("no known mask" in item for item in result.limitations)


def test_unmodelled_relocation_reports_a_difference_when_words_differ() -> None:
    result = compare(
        _code(0x00001234),
        _code(0x00005678),
        name="f",
        original_relocations=[rel(0, 1)],
        candidate_relocations=[rel(0, 1)],
    )
    assert result.status == NONMATCHING
    assert result.differences[0].reason == "unmodelled relocation, word differs"


def test_relocation_with_no_section_offset_is_ignored() -> None:
    unanchored = Relocation(
        offset=0,
        type=R_MIPS_26,
        symbol_index=0,
        addend=0,
        symbol=None,
        target_section=None,
        section_offset=None,
        file_offset=None,
    )
    assert relocation_sites([unanchored], 0) == {}


def test_max_differences_truncates_the_reported_list() -> None:
    original = _code(*([NOP] * 10))
    candidate = _code(*([0x24020001] * 10))
    result = compare(original, candidate, name="f", max_differences=3)
    assert result.difference_count == 10
    assert len(result.differences) == 3


def test_duplicate_limitations_are_deduplicated() -> None:
    result = compare(
        _code(NOP),
        _code(NOP),
        name="f",
        limitations=["reconstructed from a decompiler", "reconstructed from a decompiler"],
    )
    assert result.limitations == ("reconstructed from a decompiler",)


def test_each_ambiguous_word_records_its_own_limitation() -> None:
    # Two relocated words, each with a symbol on only one side.
    original = _code(jal(0x40), jal(0x40))
    candidate = _code(jal(0x40), jal(0x40))
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_26, addend=0x40, symbol="a"),
            rel(4, R_MIPS_26, addend=0x40, symbol="b"),
        ],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40), rel(4, R_MIPS_26, addend=0x40)],
    )
    assert len(result.limitations) == 2


# ------------------------------------------------------------ relocation_sites


def test_relocation_sites_are_indexed_relative_to_the_region() -> None:
    sites = relocation_sites(
        [rel(0x104, R_MIPS_HI16, addend=1), rel(0x108, R_MIPS_LO16, addend=2)],
        0x100,
    )
    assert set(sites) == {1, 2}
    assert sites[1].type == R_MIPS_HI16
    assert sites[2].addend == 2
    assert isinstance(sites[1], RelocationSite)
    assert sites[1].mask == 0x0000FFFF


def test_relocation_sites_skip_offsets_before_or_misaligned_with_the_region() -> None:
    sites = relocation_sites(
        [rel(0xFC, R_MIPS_32), rel(0x102, R_MIPS_32), rel(0x104, R_MIPS_32)],
        0x100,
    )
    assert set(sites) == {1}


# ---------------------------------------------------------------- compare_region


def test_compare_region_passes_through_to_compare() -> None:
    code = _code(NOP, NOP)
    result = compare_region(code, 0, [], code, name="f")
    assert result.status == MATCHED


def test_compare_region_rejects_misaligned_original() -> None:
    with pytest.raises(ParseError, match="multiple of 4"):
        compare_region(b"\x00\x00\x00", 0, [], b"\x00\x00\x00\x00", name="f")


def test_summary_is_json_serialisable() -> None:
    import json

    result = compare(
        _code(jal(0x40)),
        _code(jal(0x80)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x80)],
    )
    payload = result.summary()
    json.dumps(payload)
    assert payload["status"] == NONMATCHING
    assert payload["percent"] == 0.0
