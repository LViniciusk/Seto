from __future__ import annotations

import pytest

from eboot_035_progress import (
    BASELINE_DIFFERENCE_INDICES,
    BASELINE_MATCHING_WORDS,
    BASELINE_TOTAL_WORDS,
    assert_match_progress,
)



def _result(
    address: int,
    *,
    status: str = "NONMATCHING",
    matching_words: int | None = None,
    difference_indices: frozenset[int] | None = None,
    verified_decompilation: bool | None = None,
    limitations: tuple[str, ...] = (),
    relocation_issues: tuple[str, ...] = (),
) -> dict[str, object]:
    total_words = BASELINE_TOTAL_WORDS[address]
    baseline_indices = BASELINE_DIFFERENCE_INDICES[address]
    if difference_indices is None:
        difference_indices = baseline_indices
    if matching_words is None:
        matching_words = total_words - len(difference_indices)
    if verified_decompilation is None:
        verified_decompilation = status == "MATCHED"
    return {
        "status": status,
        "verified_decompilation": verified_decompilation,
        "match": {
            "status": status,
            "total_words": total_words,
            "matching_words": matching_words,
            "difference_count": len(difference_indices),
            "differences": [{"word_index": index} for index in sorted(difference_indices)],
            "limitations": list(limitations),
            "relocation_issues": list(relocation_issues),
        },
    }


def _assert(address: int, result: dict[str, object]) -> None:
    total_words = BASELINE_TOTAL_WORDS[address]
    baseline_matching = BASELINE_MATCHING_WORDS[address]
    baseline_indices = BASELINE_DIFFERENCE_INDICES[address]
    assert_match_progress(
        result,
        total_words=total_words,
        baseline_matching_words=baseline_matching,
        baseline_difference_indices=baseline_indices,
    )


def test_baseline_difference_indices_match_both_real_compile_attempts() -> None:
    assert BASELINE_DIFFERENCE_INDICES[0x3643C] == frozenset(range(5, 21))
    assert BASELINE_DIFFERENCE_INDICES[0x9C98] == frozenset({0, 1, 2, *range(5, 31), 32})


@pytest.mark.parametrize("address", tuple(BASELINE_TOTAL_WORDS))
def test_accepts_unchanged_real_baseline(address: int) -> None:
    _assert(address, _result(address))


@pytest.mark.parametrize(
    ("address", "removed_indices"),
    (
        (0x3643C, frozenset({5, 6})),
        (0x9C98, frozenset({0, 1})),
    ),
)
def test_accepts_partial_matching_improvement(
    address: int, removed_indices: frozenset[int]
) -> None:
    baseline_indices = BASELINE_DIFFERENCE_INDICES[address]
    result = _result(address, difference_indices=baseline_indices - removed_indices)

    _assert(address, result)


@pytest.mark.parametrize("address", tuple(BASELINE_TOTAL_WORDS))
def test_accepts_full_promotion_to_matched(address: int) -> None:
    total_words = BASELINE_TOTAL_WORDS[address]

    _assert(
        address,
        _result(
            address,
            status="MATCHED",
            matching_words=total_words,
            difference_indices=frozenset(),
            limitations=(),
            relocation_issues=(),
        ),
    )


def test_rejects_a_new_difference_index_even_without_count_regression() -> None:
    baseline_indices = BASELINE_DIFFERENCE_INDICES[0x3643C]
    changed_indices = (baseline_indices - {20}) | {4}

    with pytest.raises(AssertionError):
        _assert(0x3643C, _result(0x3643C, difference_indices=changed_indices))


def test_rejects_matching_regression() -> None:
    baseline_indices = BASELINE_DIFFERENCE_INDICES[0x3643C]
    regressed_indices = baseline_indices | {21}

    with pytest.raises(AssertionError):
        _assert(
            0x3643C,
            _result(0x3643C, difference_indices=regressed_indices),
        )


def test_rejects_matched_status_with_remaining_differences() -> None:
    baseline_indices = BASELINE_DIFFERENCE_INDICES[0x3643C]

    with pytest.raises(AssertionError):
        _assert(
            0x3643C,
            _result(
                0x3643C,
                status="MATCHED",
                matching_words=41,
                difference_indices=frozenset({min(baseline_indices)}),
            ),
        )


def test_requires_nonmatching_status_to_have_a_difference() -> None:
    with pytest.raises(AssertionError):
        _assert(
            0x3643C,
            _result(
                0x3643C,
                status="NONMATCHING",
                matching_words=42,
                difference_indices=frozenset(),
            ),
        )


@pytest.mark.parametrize(
    ("status", "verified"),
    (("NONMATCHING", True), ("MATCHED", False), ("BLOCKED", True), ("INCONCLUSIVE", False)),
)
def test_rejects_false_verified_flags_and_non_comparison_statuses(
    status: str, verified: bool
) -> None:
    with pytest.raises(AssertionError):
        _assert(
            0x3643C,
            _result(
                0x3643C,
                status=status,
                verified_decompilation=verified,
            ),
        )


@pytest.mark.parametrize(
    ("limitations", "relocation_issues"),
    [
        (("unresolved",), ()),
        ((), ("bad relocation",)),
    ],
)
def test_matched_promotion_requires_empty_limitations_and_relocations(
    limitations: tuple[str, ...],
    relocation_issues: tuple[str, ...],
) -> None:
    with pytest.raises(AssertionError):
        _assert(
            0x3643C,
            _result(
                0x3643C,
                status="MATCHED",
                matching_words=42,
                difference_indices=frozenset(),
                limitations=limitations,
                relocation_issues=relocation_issues,
            ),
        )
