"""Assertions for non-regressing SETO-DECOMP-035 real match results."""

from __future__ import annotations

from typing import Any


# Captured from both independently compiled attempts in the real WSL2 035 run.
# Keep these literal rather than deriving an allowlist from the result under test.
BASELINE_TOTAL_WORDS = {0x3643C: 42, 0x9C98: 33}
BASELINE_MATCHING_WORDS = {0x3643C: 26, 0x9C98: 3}
BASELINE_DIFFERENCE_INDICES = {
    0x3643C: frozenset({5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
    0x9C98: frozenset(
        {
            0,
            1,
            2,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            32,
        }
    ),
}


def assert_match_progress(
    result: dict[str, Any],
    *,
    total_words: int,
    baseline_matching_words: int,
    baseline_difference_indices: frozenset[int],
) -> None:
    """Require a non-regressing result for a previously NONMATCHING function."""
    match = result["match"]
    status = result["status"]
    assert status in {"NONMATCHING", "MATCHED"}
    assert result["verified_decompilation"] is (status == "MATCHED")
    assert match["status"] == status
    assert match["total_words"] == total_words
    assert match["relocation_issues"] == []
    assert match["limitations"] == []

    matching_words = match["matching_words"]
    difference_count = match["difference_count"]
    differences = match["differences"]
    difference_indices = [item["word_index"] for item in differences]
    assert len(differences) == difference_count
    assert len(set(difference_indices)) == difference_count
    assert matching_words + difference_count == total_words
    assert matching_words >= baseline_matching_words
    assert difference_count <= len(baseline_difference_indices)
    assert set(difference_indices) <= baseline_difference_indices

    if status == "MATCHED":
        assert matching_words == total_words
        assert difference_count == 0
        assert differences == []
    else:
        assert difference_count > 0
