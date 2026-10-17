"""Tests for projecting pending indexes from existing match limitations.

These use synthetic limitation strings only; they do not read private media,
compile C, or create a candidate-symbol identity verifier.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from seto.binio import ParseError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_data_identity.py"
SPEC = importlib.util.spec_from_file_location("seto_audit_data_identity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def test_pending_indexes_come_from_exact_identity_limitations() -> None:
    limitations = [
        "word 7: HI16/LO16 data identity cannot be proven (original: unresolved; candidate: unresolved)",
        "word 9: HI16/LO16 association relies on relocation order (symbol identity unavailable)",
        "word 11: HI16/LO16 data identity cannot be proven (original: original:.data+0x8; candidate: unresolved)",
    ]

    assert audit.pending_hi_indices(limitations, 16) == {
        7: limitations[0],
        11: limitations[2],
    }


def test_pending_indexes_are_not_guessed_from_a_count() -> None:
    # No qualifying per-word limitation means no index is invented, regardless
    # of any matching/total count a caller may have elsewhere.
    assert audit.pending_hi_indices([], 13) == {}


def test_duplicate_pending_word_is_rejected() -> None:
    limitation = (
        "word 3: HI16/LO16 data identity cannot be proven "
        "(original: unresolved; candidate: unresolved)"
    )
    with pytest.raises(ParseError, match="duplicate identity limitation"):
        audit.pending_hi_indices([limitation, limitation], 8)


def test_out_of_range_pending_word_is_rejected() -> None:
    limitation = (
        "word 8: HI16/LO16 data identity cannot be proven "
        "(original: unresolved; candidate: unresolved)"
    )
    with pytest.raises(ParseError, match="outside 8 words"):
        audit.pending_hi_indices([limitation], 8)
