"""Tests for the relocation-aware instruction comparator."""

from __future__ import annotations

import pytest

from seto.binio import ParseError
from seto.elf import R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_32, Relocation
from seto.matching import (
    BLOCKED,
    EVIDENCE_BINARY_RANGE,
    EVIDENCE_COMPILED_OBJECT,
    INCONCLUSIVE,
    MATCHED,
    NONMATCHING,
    RelocationSite,
    combine_hi16_lo16,
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


def test_one_sided_symbol_is_inconclusive_not_matched() -> None:
    # The words and addends agree, but a symbol is only exposed on one side, so
    # symbol identity cannot be proven: this must not be reported as MATCHED.
    result = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40, symbol="memcpy")],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40)],
    )
    assert result.status == INCONCLUSIVE
    assert result.is_inconclusive
    assert not result.is_matched
    assert result.limitations
    assert "only one side" in result.limitations[0]


def test_unmodelled_relocation_is_inconclusive_not_matched() -> None:
    # R_MIPS_16 (type 1) has no known mask: byte equality is not proof.
    result = compare(
        _code(0x00001234),
        _code(0x00001234),
        name="f",
        original_relocations=[rel(0, 1)],
        candidate_relocations=[rel(0, 1)],
    )
    assert result.status == INCONCLUSIVE
    assert any("not modelled" in item for item in result.limitations)


def test_caller_limitations_downgrade_a_perfect_score_to_inconclusive() -> None:
    # A raw-blob candidate is reported by the caller as a limitation; even though
    # every byte matches it must not be claimed as MATCHED.
    result = compare(_code(NOP, NOP), _code(NOP, NOP), name="f", limitations=["candidate is not ELF"])
    assert result.status == INCONCLUSIVE
    assert result.percent == 100.0
    assert result.limitations == ("candidate is not ELF",)


def test_no_limitations_and_no_differences_is_matched() -> None:
    result = compare(_code(NOP), _code(NOP), name="f")
    assert result.status == MATCHED


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


def test_relocation_sites_ignore_relocations_past_the_region_end() -> None:
    sites = relocation_sites(
        [rel(0x100, R_MIPS_32), rel(0x104, R_MIPS_32), rel(0x108, R_MIPS_32)],
        0x100,
        region_size=8,
    )
    assert set(sites) == {0, 1}
    sites = relocation_sites(
        [rel(0x100, R_MIPS_32), rel(0x104, R_MIPS_32)],
        0x100,
        region_size=4,
    )
    assert set(sites) == {0}


def test_duplicate_relocations_are_rejected_not_silently_overwritten() -> None:
    with pytest.raises(ParseError, match="duplicate relocation"):
        relocation_sites([rel(0x100, R_MIPS_26), rel(0x100, R_MIPS_HI16)], 0x100)


# -------------------------------------------------------------------- HI16/LO16


def test_hi16_lo16_pair_with_equal_combined_value_matches() -> None:
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, 0x24840000)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002),
        ],
    )
    assert result.status == MATCHED
    assert result.matching_words == 2


def test_hi16_lo16_pair_with_different_combined_value_is_a_difference() -> None:
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, 0x24840000)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0002),
            rel(4, R_MIPS_LO16, addend=0x0002),
        ],
    )
    assert result.status == NONMATCHING
    assert "HI16/LO16 pair" in result.differences[0].reason


def test_combine_hi16_lo16_uses_the_raw_high_half_and_signed_low_half() -> None:
    assert combine_hi16_lo16(0x0001, 0x0002) == 0x00010002
    assert combine_hi16_lo16(0x0000, -4) == 0xFFFFFFFC
    # The high half is masked to 16 bits before shifting.
    assert combine_hi16_lo16(0xFFFF0001, 0) == 0x00010000


def test_blocked_status_constant_exists() -> None:
    assert BLOCKED == "BLOCKED"


# ---------------------------------------------------------------------- evidence


def test_default_evidence_is_binary_range() -> None:
    result = compare(_code(NOP), _code(NOP), name="f")
    assert result.evidence == EVIDENCE_BINARY_RANGE
    assert not result.is_verified_decompilation
    assert result.summary()["evidence"] == EVIDENCE_BINARY_RANGE


def test_compiled_object_evidence_is_verified_only_when_matched() -> None:
    matched = compare(_code(NOP), _code(NOP), name="f", evidence=EVIDENCE_COMPILED_OBJECT)
    assert matched.is_verified_decompilation

    inconclusive = compare(
        _code(jal(0x40)),
        _code(jal(0x40)),
        name="f",
        original_relocations=[rel(0, R_MIPS_26, addend=0x40, symbol="a")],
        candidate_relocations=[rel(0, R_MIPS_26, addend=0x40)],
        evidence=EVIDENCE_COMPILED_OBJECT,
    )
    assert inconclusive.status == INCONCLUSIVE
    assert not inconclusive.is_verified_decompilation


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
