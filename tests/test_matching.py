"""Tests for the relocation-aware instruction comparator."""

from __future__ import annotations

import pytest

from seto.binio import ParseError
from seto.elf import R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_32, Relocation
from seto.datarefs import DataIdentity, DataTarget
from seto.matching import (
    BLOCKED,
    EVIDENCE_BINARY_RANGE,
    EVIDENCE_COMPILED_OBJECT,
    EQUIVALENCE_RESOLVED_RELOCATIONS,
    INCONCLUSIVE,
    MATCHED,
    NONMATCHING,
    RelocationSite,
    combine_hi16_lo16,
    compare,
    compare_region,
    pair_hi16_lo16,
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
    symbol_index: int = 0,
) -> Relocation:
    return Relocation(
        offset=section_offset,
        type=rel_type,
        symbol_index=symbol_index,
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


def test_relocation_without_a_resolved_section_is_a_limitation() -> None:
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
    mapped = relocation_sites([unanchored], 0)
    assert mapped.sites == {}
    assert any("no resolved section" in item for item in mapped.limitations)


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
    mapped = relocation_sites(
        [rel(0x104, R_MIPS_HI16, addend=1), rel(0x108, R_MIPS_LO16, addend=2)],
        0x100,
    )
    sites = mapped.sites
    assert set(sites) == {1, 2}
    assert sites[1].type == R_MIPS_HI16
    assert sites[2].addend == 2
    assert isinstance(sites[1], RelocationSite)
    assert sites[1].mask == 0x0000FFFF
    assert mapped.limitations == ()


def test_relocation_sites_skip_offsets_before_the_region_but_flag_misalignment() -> None:
    mapped = relocation_sites(
        [rel(0xFC, R_MIPS_32), rel(0x102, R_MIPS_32), rel(0x104, R_MIPS_32)],
        0x100,
    )
    assert set(mapped.sites) == {1}
    # The misaligned relocation inside the range cannot be placed, so instead of
    # being dropped silently it degrades the comparison to INCONCLUSIVE.
    assert any("word-aligned" in item for item in mapped.limitations)


def test_relocation_sites_ignore_relocations_past_the_region_end() -> None:
    mapped = relocation_sites(
        [rel(0x100, R_MIPS_32), rel(0x104, R_MIPS_32), rel(0x108, R_MIPS_32)],
        0x100,
        region_size=8,
    )
    assert set(mapped.sites) == {0, 1}
    assert mapped.limitations == ()
    mapped = relocation_sites(
        [rel(0x100, R_MIPS_32), rel(0x104, R_MIPS_32)],
        0x100,
        region_size=4,
    )
    assert set(mapped.sites) == {0}


def test_duplicate_relocations_are_rejected_not_silently_overwritten() -> None:
    with pytest.raises(ParseError, match="duplicate relocation"):
        relocation_sites([rel(0x100, R_MIPS_26), rel(0x100, R_MIPS_HI16)], 0x100)


# -------------------------------------------------------------------- HI16/LO16


def test_hi16_lo16_pair_with_equal_symbols_matches() -> None:
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, 0x24840000)
    target = DataTarget(".data", 0x10)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001, symbol="target"),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="target"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001, symbol="target"),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="target"),
        ],
        original_data_resolver=_identity(target),
        candidate_data_resolver=_identity(target),
    )
    assert result.status == MATCHED
    assert result.matching_words == 2
    assert result.limitations == ()


def test_equal_numeric_pairs_without_object_identity_stay_inconclusive() -> None:
    # Even matching instructions/addends and a matching HI symbol cannot prove
    # that a separately compiled LO symbol denotes the original data object.
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, 0x24840000)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="first"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="second"),
        ],
    )
    assert result.status == INCONCLUSIVE
    assert any("identity cannot be proven" in item for item in result.limitations)
    assert result.matching_words == 0


def test_equal_hilo_addends_and_symbol_names_without_resolvers_are_inconclusive() -> None:
    code = _code(0x3C040000, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=1, symbol="same_name"),
        rel(4, R_MIPS_LO16, addend=2, symbol="same_name"),
    ]
    result = compare(
        code,
        code,
        name="independent-artifacts",
        original_relocations=relocations,
        candidate_relocations=relocations,
    )
    assert result.status == INCONCLUSIVE
    assert not result.resolved_data
    assert any("identity cannot be proven" in item for item in result.limitations)


def test_hi16_and_lo16_with_different_symbols_are_not_associated() -> None:
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, 0x24840000)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001, symbol="first"),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="first"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001, symbol="first"),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="second"),
        ],
    )
    assert result.status == NONMATCHING
    assert "association differs" in result.differences[0].reason


def test_hi16_lo16_association_does_not_require_adjacent_instructions() -> None:
    original = _code(0x3C040000, NOP, 0x24840000)
    candidate = _code(0x3C040000, NOP, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=0x0001, symbol="target"),
        rel(8, R_MIPS_LO16, addend=0x0002, symbol="target"),
    ]
    mapped = relocation_sites(relocations, 0)
    assert pair_hi16_lo16(mapped.sites).hi_to_lo == {0: 2}

    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=_identity(DataTarget(".data", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x10)),
    )
    assert result.status == MATCHED
    assert result.matching_words == 3


def test_hi16_lo16_association_follows_relocation_order_not_word_order() -> None:
    # The relocation table can list the HI16 before a LO16 that sits at a lower
    # address; the association is still (hi=1, lo=0) and must be compared as one
    # unit.
    relocations = [
        rel(4, R_MIPS_HI16, addend=0x0001, symbol="target"),
        rel(0, R_MIPS_LO16, addend=0x0002, symbol="target"),
    ]
    mapped = relocation_sites(relocations, 0)
    assert pair_hi16_lo16(mapped.sites).hi_to_lo == {1: 0}

    code = _code(0x24840000, 0x3C040000)
    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=_identity(DataTarget(".data", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x10)),
    )
    assert result.status == MATCHED
    assert result.matching_words == 2


def test_one_lo16_resolves_multiple_pending_hi16() -> None:
    original = _code(0x3C040000, 0x3C050000, 0x24840000)
    candidate = _code(0x3C040000, 0x3C050000, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=0x0001, symbol="target"),
        rel(4, R_MIPS_HI16, addend=0x0001, symbol="target"),
        rel(8, R_MIPS_LO16, addend=0x0002, symbol="target"),
    ]
    mapped = relocation_sites(relocations, 0)
    assert pair_hi16_lo16(mapped.sites).hi_to_lo == {0: 2, 1: 2}

    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=_identity(DataTarget(".data", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x10)),
    )
    assert result.status == MATCHED
    # The shared LO16 is one word, not two.
    assert result.matching_words == 3


def test_hi16_lo16_association_without_symbols_is_inconclusive() -> None:
    # Register flow proves which HI closes which LO, but that alone cannot prove
    # that an object in a separate candidate artifact is the same object.
    code = _code(0x3C040000, 0x24840000)
    relocations = [rel(0, R_MIPS_HI16, addend=1), rel(4, R_MIPS_LO16, addend=2)]
    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=lambda _site, _value: DataIdentity(
            "original", DataTarget(".data", 0x10)
        ),
        candidate_data_resolver=lambda _site, _value: None,
    )
    assert result.status == INCONCLUSIVE
    assert not result.is_matched
    assert not any("relocation order" in item for item in result.limitations)
    assert any("identity cannot be proven" in item for item in result.limitations)
    assert result.matching_words == 0


def _lui(register: int, immediate: int = 0) -> int:
    return (0x0F << 26) | (register << 16) | (immediate & 0xFFFF)


def _i_type(op: int, source: int, target: int, immediate: int = 0) -> int:
    return (op << 26) | (source << 21) | (target << 16) | (immediate & 0xFFFF)


def test_register_flow_proves_the_unique_hi16_lo16_pair() -> None:
    code = _code(_lui(4, 0x60), _i_type(9, 4, 4, 0x4860))
    relocations = [rel(0, R_MIPS_HI16, addend=0x60), rel(4, R_MIPS_LO16, addend=0x4860)]
    words = (_lui(4, 0x60), _i_type(9, 4, 4, 0x4860))
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 1}
    assert pairing.evidence == {0: "register-flow"}
    assert not any("relocation order" in item for item in pairing.limitations)


def test_register_redefinition_blocks_a_false_hi16_lo16_pair() -> None:
    words = (_lui(4), _i_type(9, 4, 4, 1), _i_type(9, 4, 5, 2))
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(8, R_MIPS_LO16, addend=2)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {}
    assert any("redefines the LO16 base register" in item for item in pairing.limitations)


@pytest.mark.parametrize(
    ("words", "low_index"),
    [
        ((_lui(5), 0x0C000000, _i_type(9, 5, 5, 0x4830)), 2),
        ((_lui(3), 0x03E00008, _i_type(0x2B, 3, 4, 0x4860)), 2),
    ],
)
def test_register_flow_observes_unconditional_control_delay_slots(words, low_index) -> None:
    hi_index = 0
    relocations = [rel(hi_index * 4, R_MIPS_HI16, addend=0)]
    relocations.append(rel(low_index * 4, R_MIPS_LO16, addend=0x4830))
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {hi_index: low_index}
    assert pairing.evidence[hi_index] == "register-flow"


def test_cfg_proves_a_hi16_across_a_conditional_branch() -> None:
    words = (_lui(4), 0x10800001, 0, _i_type(9, 4, 4, 0x4830))  # beq, delay slot, LO
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(12, R_MIPS_LO16, addend=0x4830)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 3}
    assert pairing.evidence[0] == "register-flow"
    assert not any("control flow crosses" in item for item in pairing.limitations)
    assert not any("relocation order" in item for item in pairing.limitations)


def test_cfg_keeps_mult_as_a_fallthrough_instruction() -> None:
    words = (
        _lui(4),
        _i_type(4, 5, 0, 2),
        NOP,
        (2 << 21) | (3 << 16) | 0x18,  # mult v0,v1: writes HI/LO, not a GPR
        _i_type(9, 4, 6, 0x4830),
    )
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(16, R_MIPS_LO16, addend=0x4830)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 4}
    assert pairing.evidence[0] == "register-flow"


@pytest.mark.parametrize(("words", "highs", "low"), [
    (
        (_lui(4), _i_type(5, 5, 0, 2), NOP, _lui(4), _i_type(0x23, 4, 6)),
        (0, 3), 4,
    ),
    (
        (_lui(4), _i_type(4, 5, 0, 2), NOP, _i_type(9, 0, 4), _i_type(0x23, 4, 6)),
        (0,), 4,
    ),
    (
        (_i_type(4, 5, 0, 3), NOP, _lui(4), NOP, _i_type(0x23, 4, 6)),
        (2,), 4,
    ),
    (
        (_lui(4), _i_type(0x23, 4, 6), 0x0C000000, NOP,
         _i_type(4, 0, 0, -4), NOP, 0x03E00008, NOP),
        (0,), 1,
    ),
], ids=["two-his", "hi-and-other", "hi-and-entry", "hi-and-call-clobber"])
def test_cfg_ambiguity_cannot_fall_back_to_a_linear_proof(words, highs, low) -> None:
    relocations = [rel(index * 4, R_MIPS_HI16) for index in highs]
    relocations.append(rel(low * 4, R_MIPS_LO16))
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {index: low for index in highs}
    assert pairing.evidence == {index: "relocation-order" for index in highs}
    assert any("pairing is uncertain" in item for item in pairing.limitations)

    # Even a resolver-proven destination difference must not be turned into a
    # definite divergence using a pair whose reaching association is ambiguous.
    code = _code(*words)
    result = compare(
        code, code, name="ambiguous",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=_identity(DataTarget(".data", 0x20)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x24)),
    )
    assert result.status == INCONCLUSIVE
    assert result.difference_count == 0


def test_cfg_all_ordinary_definitions_conclusively_exclude_a_hi16() -> None:
    words = (
        _lui(4), _i_type(4, 5, 0, 3), _i_type(9, 0, 4, 1),
        _i_type(9, 0, 4, 2), NOP, _i_type(0x23, 4, 6),
    )
    relocations = [rel(0, R_MIPS_HI16), rel(20, R_MIPS_LO16)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {}
    assert any("no relocated HI16 reaches" in item for item in pairing.limitations)


def test_cfg_ambiguity_does_not_discard_independent_elf_symbol_pairing() -> None:
    words = (_lui(4), _i_type(5, 5, 0, 2), NOP, _lui(4), _i_type(0x23, 4, 6))
    relocations = [
        rel(0, R_MIPS_HI16, symbol="table"),
        rel(12, R_MIPS_HI16, symbol="table"),
        rel(16, R_MIPS_LO16, symbol="table"),
    ]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 4, 3: 4}
    assert pairing.evidence == {0: "symbol", 3: "symbol"}
    assert not pairing.limitations


@pytest.mark.parametrize("after_lo", [
    (
        _i_type(9, 0, 4, 0),  # redefinition on the loop backedge
        _i_type(4, 7, 0, -3),
        NOP,
        0x03E00008,
        NOP,
    ),
    (
        0x0C000000,  # a returning call may clobber a0 before the backedge
        NOP,
        _i_type(4, 0, 0, -4),
        NOP,
        0x03E00008,
        NOP,
    ),
    (
        0x0320F809,  # jalr ra,t9 also returns after its delay slot
        NOP,
        _i_type(4, 0, 0, -4),
        NOP,
        0x03E00008,
        NOP,
    ),
], ids=["redefinition-backedge", "call-return-backedge", "jalr-return-backedge"])
def test_cfg_does_not_ignore_backedges_after_the_lo(after_lo) -> None:
    words = (
        _lui(4),
        _i_type(4, 5, 0, 2),
        NOP,
        NOP,
        _i_type(9, 4, 6, 0x4830),
        *after_lo,
    )
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(16, R_MIPS_LO16, addend=0x4830)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.evidence.get(0) != "register-flow"
    assert pairing.limitations


def test_cfg_does_not_treat_a_branch_target_as_an_owned_delay_slot() -> None:
    # Taken branch 1 enters word 4 normally, so word 5 redefines a0. Only a
    # word-4 execution inherited from branch 3 may skip word 5 and reach LO 6.
    words = (
        _lui(4),
        _i_type(4, 5, 0, 2),
        NOP,
        _i_type(4, 0, 0, 2),
        NOP,
        _i_type(9, 0, 4, 0),
        _i_type(9, 4, 6, 0x4830),
        0x03E00008,
        NOP,
    )
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(24, R_MIPS_LO16, addend=0x4830)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.evidence.get(0) != "register-flow"
    assert pairing.limitations


@pytest.mark.parametrize("rt", [0x10, 0x11, 0x12, 0x13])
def test_cfg_does_not_treat_a_conditional_call_as_a_local_branch(rt) -> None:
    # The link return address is LO 3. The callee path can redefine a0 at 4
    # then return to that LO; treating its jr as a function exit loses a path.
    words = (
        _lui(4),
        _i_type(1, 5, rt, 2),  # bltzal/bgezal and their likely forms
        NOP,
        _i_type(9, 4, 6, 0x4830),
        _i_type(9, 0, 4, 0),
        0x03E00008,
        NOP,
    )
    relocations = [rel(0, R_MIPS_HI16, addend=0), rel(12, R_MIPS_LO16, addend=0x4830)]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.evidence.get(0) != "register-flow"
    assert pairing.limitations


def test_cfg_proves_a_hi16_across_mutually_exclusive_delay_slots() -> None:
    # The 0x2c8 shape: the branch-likely target is the LO16, its delay slot
    # installs the HI16 base, while the fall-through path redefines the same
    # register in the delay slot of an unconditional branch that skips the LO.
    words = (
        _lui(2),
        _i_type(0x24, 2, 2, 0x6194),
        0x000216C0,
        0x000217C2,
        0x50400003,  # beql v0,zero,0x2e8
        _lui(2),
        0x10000002,  # beq zero,zero,0x2ec
        _i_type(9, 0, 2, -1),
        _i_type(0x25, 2, 2, 0x6196),
        0x03E00008,
        NOP,
    )
    relocations = [
        rel(0, R_MIPS_HI16, addend=0),
        rel(4, R_MIPS_LO16, addend=0x6194),
        rel(20, R_MIPS_HI16, addend=0),
        rel(32, R_MIPS_LO16, addend=0x6196),
    ]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 1, 5: 8}
    assert pairing.evidence == {0: "register-flow", 5: "register-flow"}
    assert not pairing.limitations


def test_cfg_keeps_mixed_hi16_and_fallthrough_redefinition_uncertain() -> None:
    words = (
        _lui(2),
        _i_type(0x24, 2, 2, 0x6194),
        0x000216C0,
        0x000217C2,
        0x50400003,
        _lui(2),
        NOP,
        _i_type(9, 0, 2, -1),
        _i_type(0x25, 2, 2, 0x6196),
        0x03E00008,
        NOP,
    )
    relocations = [
        rel(0, R_MIPS_HI16, addend=0),
        rel(4, R_MIPS_LO16, addend=0x6194),
        rel(20, R_MIPS_HI16, addend=0),
        rel(32, R_MIPS_LO16, addend=0x6196),
    ]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 1, 5: 8}
    assert pairing.evidence == {0: "register-flow", 5: "relocation-order"}
    assert any("multiple or unproven CFG reaching definitions" in item for item in pairing.limitations)


def test_register_flow_does_not_attach_one_lo_to_another_registers_hi() -> None:
    words = (_lui(4), _lui(5), _i_type(9, 4, 4, 1), _i_type(9, 5, 5, 2))
    relocations = [
        rel(0, R_MIPS_HI16, addend=0),
        rel(4, R_MIPS_HI16, addend=0),
        rel(8, R_MIPS_LO16, addend=1),
        rel(12, R_MIPS_LO16, addend=2),
    ]
    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites, words)
    assert pairing.hi_to_lo == {0: 2, 1: 3}
    assert pairing.evidence == {0: "register-flow", 1: "register-flow"}


def test_an_orphan_lo16_is_a_pairing_limitation() -> None:
    pairing = pair_hi16_lo16({0: RelocationSite(0, R_MIPS_LO16, 0x1234, None)})
    assert pairing.hi_to_lo == {}
    assert any("LO16 relocation has no associated HI16" in item for item in pairing.limitations)


def test_unnamed_section_symbols_pair_by_their_shared_symbol_table_index() -> None:
    code = _code(0x3C040000, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=1, symbol_index=3),
        rel(4, R_MIPS_LO16, addend=2, symbol_index=3),
    ]

    pairing = pair_hi16_lo16(relocation_sites(relocations, 0).sites)
    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
        original_data_resolver=_identity(DataTarget(".data", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x10)),
    )

    assert pairing.hi_to_lo == {0: 1}
    assert pairing.limitations == ()
    assert result.status == MATCHED


def test_unnamed_hi16_lo16_with_different_symbol_indices_stays_inconclusive() -> None:
    code = _code(0x3C040000, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=1, symbol_index=3),
        rel(4, R_MIPS_LO16, addend=2, symbol_index=4),
    ]

    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
    )

    assert result.status == INCONCLUSIVE
    assert any("HI16 relocation has no LO16" in item for item in result.limitations)


def test_ambiguous_hi16_lo16_association_is_inconclusive() -> None:
    # Two pending HI16 with unknown symbols but only one reaching-register match:
    # the other HI16 stays unresolved, and data identity is not inferred.
    code = _code(0x3C040000, 0x3C050000, 0x24840000)
    relocations = [
        rel(0, R_MIPS_HI16, addend=1),
        rel(4, R_MIPS_HI16, addend=1),
        rel(8, R_MIPS_LO16, addend=2),
    ]
    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
    )
    assert result.status == INCONCLUSIVE
    assert result.matching_words == 1


def test_hi16_lo16_pair_on_one_side_only_is_a_difference() -> None:
    original = _code(0x3C040000, 0x24840000)
    candidate = _code(0x3C040000, NOP)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001, symbol="target"),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="target"),
        ],
        candidate_relocations=[rel(0, R_MIPS_HI16, addend=0x0001, symbol="target")],
    )
    assert result.status == NONMATCHING
    assert "association differs" in result.differences[0].reason


def test_unresolved_hi16_is_inconclusive_not_matched() -> None:
    code = _code(0x3C040000, NOP)
    relocations = [rel(0, R_MIPS_HI16, addend=1, symbol="target")]
    result = compare(
        code,
        code,
        name="f",
        original_relocations=relocations,
        candidate_relocations=relocations,
    )
    assert result.status == INCONCLUSIVE
    assert any("has no LO16" in item for item in result.limitations)


def test_misaligned_relocation_is_inconclusive_not_matched() -> None:
    # A relocation the comparator cannot place must not be dropped silently.
    result = compare(
        _code(jr(31)),
        _code(jr(31)),
        name="f",
        original_relocations=[rel(2, R_MIPS_26, addend=0x40)],
        candidate_relocations=[rel(2, R_MIPS_26, addend=0x40)],
    )
    assert result.status == INCONCLUSIVE
    assert any("word-aligned" in item for item in result.limitations)


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
        original_data_resolver=_identity(DataTarget(".data", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x20)),
    )
    assert result.status == NONMATCHING
    assert "data target differs" in result.differences[0].reason
    assert result.matching_words == 0


def test_unlinked_different_symbols_do_not_make_a_pair_nonmatching() -> None:
    # Without an independent cross-artifact link, different candidate symbol
    # spellings cannot prove that the underlying data objects differ.
    original = _code(0x3C040000, 0x24840000, NOP)
    candidate = _code(0x3C040000, 0x24840000, NOP)
    result = compare(
        original,
        candidate,
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="first"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0001),
            rel(4, R_MIPS_LO16, addend=0x0002, symbol="second"),
        ],
    )
    assert result.status == INCONCLUSIVE
    assert result.total_words == 3
    assert result.matching_words == 1
    assert result.differences == ()
    assert any("identity cannot be proven" in item for item in result.limitations)


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


# ------------------------------------------------------- canonical data targets


def _identity(target: DataTarget, artifact: str = "original"):
    """A resolver that answers with one artifact-qualified location."""
    return lambda site, addend: DataIdentity(artifact, target)


def test_r_mips_32_resolved_to_the_same_section_offset_matches() -> None:
    target = DataTarget(".rodata", 0x10)
    result = compare(
        _code(0x00000100, 0x00000200),
        _code(0x00009000, 0x00000200),
        name="f",
        original_relocations=[rel(0, R_MIPS_32, addend=0x100)],
        candidate_relocations=[rel(0, R_MIPS_32, addend=0x9000)],
        original_data_resolver=_identity(target),
        candidate_data_resolver=_identity(target),
    )
    assert result.status == MATCHED
    assert result.resolved_data
    assert result.equivalence == EQUIVALENCE_RESOLVED_RELOCATIONS


def test_r_mips_32_equal_numeric_addends_without_resolvers_stay_inconclusive() -> None:
    result = compare(
        _code(0x00000100),
        _code(0x00000100),
        name="f",
        original_relocations=[rel(0, R_MIPS_32, addend=0x100)],
        candidate_relocations=[rel(0, R_MIPS_32, addend=0x100)],
    )
    assert result.status == INCONCLUSIVE
    assert any("identity cannot be proven" in item for item in result.limitations)


def test_r_mips_32_proven_different_targets_are_nonmatching() -> None:
    result = compare(
        _code(0x00000100),
        _code(0x00009000),
        name="f",
        original_relocations=[rel(0, R_MIPS_32, addend=0x100)],
        candidate_relocations=[rel(0, R_MIPS_32, addend=0x9000)],
        original_data_resolver=_identity(DataTarget(".rodata", 0x10)),
        candidate_data_resolver=_identity(DataTarget(".rodata", 0x20)),
    )
    assert result.status == NONMATCHING
    assert "R_MIPS_32 data target differs" in result.differences[0].reason


def test_r_mips_32_without_a_proven_target_is_inconclusive() -> None:
    result = compare(
        _code(0x00000100),
        _code(0x00009000),
        name="f",
        original_relocations=[rel(0, R_MIPS_32, addend=0x100)],
        candidate_relocations=[rel(0, R_MIPS_32, addend=0x9000)],
        original_data_resolver=lambda site, addend: None,
        candidate_data_resolver=_identity(DataTarget(".rodata", 0x10)),
    )
    assert result.status == INCONCLUSIVE
    assert any("cannot be proven" in item for item in result.limitations)


def test_two_artifacts_answering_the_same_offset_are_not_equal() -> None:
    # ``(.data, 0x20)`` is a location, not an identity.  Two independent ELF files
    # that each resolve their reference to it must never be treated as naming the
    # same object - the answers belong to different artifacts.
    result = compare(
        _code(0x00000100),
        _code(0x00009000),
        name="f",
        original_relocations=[rel(0, R_MIPS_32, addend=0x100)],
        candidate_relocations=[rel(0, R_MIPS_32, addend=0x9000)],
        original_data_resolver=_identity(DataTarget(".data", 0x20), artifact="module-a"),
        candidate_data_resolver=_identity(DataTarget(".data", 0x20), artifact="module-b"),
    )
    assert result.status == INCONCLUSIVE
    assert not result.resolved_data
    assert any("different artifacts" in item for item in result.limitations)


def test_two_artifacts_answering_the_same_pair_offset_are_not_equal() -> None:
    result = compare(
        _code(0x3C040001, 0x24840002),
        _code(0x3C040000, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x2, symbol="value"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x3, symbol="value"),
        ],
        original_data_resolver=_identity(DataTarget(".data", 0x20), artifact="module-a"),
        candidate_data_resolver=_identity(DataTarget(".data", 0x20), artifact="module-b"),
    )
    assert result.status == INCONCLUSIVE
    assert not result.resolved_data
    assert any("different artifacts" in item for item in result.limitations)


def test_hi16_lo16_data_resolver_bridges_a_different_encoding() -> None:
    target = DataTarget(".data", 0x20)
    result = compare(
        _code(0x3C040001, 0x24840002),
        _code(0x3C040000, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x2, symbol="value"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x3, symbol="value"),
        ],
        original_data_resolver=_identity(target),
        candidate_data_resolver=_identity(target),
    )
    assert result.status == MATCHED
    assert any(".data+0x20" in item for item in result.resolved_data)


def test_hi16_lo16_with_proven_symbols_and_different_targets_is_nonmatching() -> None:
    result = compare(
        _code(0x3C040001, 0x24840002),
        _code(0x3C040000, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x2, symbol="value"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x3, symbol="value"),
        ],
        original_data_resolver=_identity(DataTarget(".data", 0x20)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x24)),
    )
    assert result.status == NONMATCHING
    assert "data target differs" in result.differences[0].reason


def test_a_target_difference_on_a_register_proven_pair_is_nonmatching() -> None:
    # The straight-line LUI-to-LO16 register flow proves the association, so a
    # proven destination difference is a real data-reference divergence.
    result = compare(
        _code(0x3C040001, 0x24840002),
        _code(0x3C040000, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1),
            rel(4, R_MIPS_LO16, addend=0x2),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0),
            rel(4, R_MIPS_LO16, addend=0x3),
        ],
        original_data_resolver=_identity(DataTarget(".data", 0x20)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x24)),
    )
    assert result.status == NONMATCHING
    assert "data target differs" in result.differences[0].reason


def test_a_target_difference_on_a_cfg_proven_pair_is_nonmatching() -> None:
    # The CFG proves the LUI reaches the LO16 on both sides of the conditional
    # branch, so a proven destination difference is a real code/data divergence.
    result = compare(
        _code(0x3C040001, 0x10800001, 0, 0x24840002),
        _code(0x3C040000, 0x10800001, 0, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1),
            rel(12, R_MIPS_LO16, addend=0x2),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0),
            rel(12, R_MIPS_LO16, addend=0x3),
        ],
        original_data_resolver=_identity(DataTarget(".data", 0x20)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x24)),
    )
    assert result.status == NONMATCHING
    assert "data target differs" in result.differences[0].reason


def test_a_target_difference_on_an_order_only_pair_stays_inconclusive() -> None:
    # A call before the LO16 cannot be modeled by the local CFG; the order
    # fallback must not turn different resolved destinations into a proven
    # code/data divergence.
    result = compare(
        _code(0x3C040001, 0x0C000000, 0, 0x24840002),
        _code(0x3C040000, 0x0C000000, 0, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1),
            rel(12, R_MIPS_LO16, addend=0x2),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0),
            rel(12, R_MIPS_LO16, addend=0x3),
        ],
        original_data_resolver=_identity(DataTarget(".data", 0x20)),
        candidate_data_resolver=_identity(DataTarget(".data", 0x24)),
    )
    assert result.status == INCONCLUSIVE
    assert result.differences == ()
    assert any("pair lacks symbol identity" in item for item in result.limitations)


def test_data_resolution_never_hides_a_non_relocatable_difference() -> None:
    target = DataTarget(".rodata", 0x10)
    result = compare(
        _code(0x3C040001, 0x24840002),
        _code(0x3C050001, 0x24840003),
        name="f",
        original_relocations=[
            rel(0, R_MIPS_HI16, addend=0x1, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x2, symbol="value"),
        ],
        candidate_relocations=[
            rel(0, R_MIPS_HI16, addend=0x0, symbol="value"),
            rel(4, R_MIPS_LO16, addend=0x3, symbol="value"),
        ],
        original_data_resolver=_identity(target),
        candidate_data_resolver=_identity(target),
    )
    assert result.status == NONMATCHING
    assert "outside the relocation field" in result.differences[0].reason
