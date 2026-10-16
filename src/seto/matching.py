"""Relocation-aware instruction comparison (the "matching" engine).

Two instruction streams match when

* every word that is *not* covered by a relocation is byte-identical, and
* every word that *is* covered by a relocation carries a relocation of the same
  type whose in-place addend is equal, and
* symbols agree whenever both sides expose them.

The result is deliberately conservative.  Byte equality alone is **not** treated
as proof of a matching decompilation: whenever the available evidence cannot
establish equivalence (a raw blob candidate, an unmodelled relocation type, a
symbol present on only one side, ...) the outcome is ``INCONCLUSIVE`` rather than
``MATCHED``.

Statuses
--------
``MATCHED``       equivalence proven for the compared range
``NONMATCHING``   a divergence was proven
``INCONCLUSIVE``  the comparison ran but the evidence is insufficient
``BLOCKED``       an external prerequisite was unavailable (produced by callers)
"""

from __future__ import annotations

from dataclasses import dataclass

from seto.binio import ParseError
from seto.elf import (
    R_MIPS_HI16,
    R_MIPS_LO16,
    Relocation,
    decode_relocation_addend,
    relocation_mask,
    relocation_type_name,
)
from seto.mips import decode_words

MATCHED = "MATCHED"
NONMATCHING = "NONMATCHING"
INCONCLUSIVE = "INCONCLUSIVE"
BLOCKED = "BLOCKED"
DEFAULT_MAX_DIFFERENCES = 64

#: The comparison was between byte ranges (the original vs the original, or a raw
#: blob).  Equivalence here is "binary range equivalence", not proof that a
#: reconstruction compiles back to the original.
EVIDENCE_BINARY_RANGE = "binary-range"
#: The candidate was a relocatable object (ET_REL), i.e. the output of compiling
#: the reconstructed C.  A ``MATCHED`` with this evidence is a verified
#: decompilation match.
EVIDENCE_COMPILED_OBJECT = "compiled-object"


@dataclass(frozen=True)
class RelocationSite:
    """A relocation expressed relative to the start of the compared region."""

    word_index: int
    type: int
    addend: int
    symbol: str | None

    @property
    def type_name(self) -> str:
        return relocation_type_name(self.type)

    @property
    def mask(self) -> int:
        return relocation_mask(self.type)


@dataclass(frozen=True)
class WordDifference:
    word_index: int
    address: int
    original: int
    candidate: int
    reason: str

    def summary(self) -> dict[str, object]:
        return {
            "word_index": self.word_index,
            "address": self.address,
            "original": f"0x{self.original:08x}",
            "candidate": f"0x{self.candidate:08x}",
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MatchResult:
    name: str
    address: int
    total_words: int
    matching_words: int
    status: str
    difference_count: int = 0
    differences: tuple[WordDifference, ...] = ()
    relocation_issues: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    evidence: str = EVIDENCE_BINARY_RANGE

    @property
    def percent(self) -> float:
        if self.total_words == 0:
            return 100.0
        return round(self.matching_words * 100.0 / self.total_words, 6)

    @property
    def is_matched(self) -> bool:
        return self.status == MATCHED

    @property
    def is_inconclusive(self) -> bool:
        return self.status == INCONCLUSIVE

    @property
    def is_verified_decompilation(self) -> bool:
        """True only for a MATCHED comparison against a compiled object."""
        return self.status == MATCHED and self.evidence == EVIDENCE_COMPILED_OBJECT

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "address": self.address,
            "status": self.status,
            "evidence": self.evidence,
            "percent": self.percent,
            "total_words": self.total_words,
            "matching_words": self.matching_words,
            "difference_count": self.difference_count,
            "differences": [item.summary() for item in self.differences],
            "relocation_issues": list(self.relocation_issues),
            "limitations": list(self.limitations),
        }


def combine_hi16_lo16(hi_addend: int, lo_addend: int) -> int:
    """Combine a HI16/LO16 relocation pair into the 32-bit value it encodes.

    ``decode_relocation_addend`` already sign-extends the LO16 half and keeps the
    raw 16 bits of the HI16 half, so a plain modulo-2**32 sum is exact (there is
    no carry aliasing between the two encodings).
    """
    return (((hi_addend & 0xFFFF) << 16) + lo_addend) & 0xFFFFFFFF


def relocation_sites(
    relocations: tuple[Relocation, ...] | list[Relocation],
    region_offset: int,
    region_size: int | None = None,
) -> dict[int, RelocationSite]:
    """Index relocations by word index within a region.

    ``region_offset`` is the section-file offset of the region's first byte;
    ``region_size`` (when given) is its length in bytes, so relocations outside
    the compared range are ignored.  Relocations that are not word-aligned, have
    no resolvable offset, or fall outside the region are skipped.  Two
    relocations targeting the same word are rejected instead of being silently
    overwritten.
    """
    sites: dict[int, RelocationSite] = {}
    for relocation in relocations:
        if relocation.section_offset is None:
            continue
        delta = relocation.section_offset - region_offset
        if delta < 0 or delta % 4:
            continue
        if region_size is not None and delta + 4 > region_size:
            continue
        word_index = delta // 4
        if word_index in sites:
            raise ParseError(
                f"duplicate relocation for word {word_index} "
                f"(section offset 0x{relocation.section_offset:x})"
            )
        sites[word_index] = RelocationSite(
            word_index=word_index,
            type=relocation.type,
            addend=relocation.addend,
            symbol=relocation.symbol,
        )
    return sites


def _hi16_lo16_pairs(sites: dict[int, RelocationSite]) -> set[int]:
    """Indices of HI16 relocations immediately followed by a LO16 relocation."""
    pairs: set[int] = set()
    for index, site in sites.items():
        following = sites.get(index + 1)
        if site.type == R_MIPS_HI16 and following is not None and following.type == R_MIPS_LO16:
            pairs.add(index)
    return pairs


def compare(
    original: bytes,
    candidate: bytes,
    *,
    name: str,
    address: int = 0,
    original_relocations: tuple[Relocation, ...] | list[Relocation] = (),
    candidate_relocations: tuple[Relocation, ...] | list[Relocation] = (),
    original_section_offset: int = 0,
    candidate_section_offset: int = 0,
    max_differences: int = DEFAULT_MAX_DIFFERENCES,
    limitations: tuple[str, ...] | list[str] = (),
    evidence: str = EVIDENCE_BINARY_RANGE,
) -> MatchResult:
    """Compare two instruction streams with relocation-aware semantics.

    ``original_section_offset``/``candidate_section_offset`` are the byte offsets
    of the compared region relative to the start of its section, i.e. the same
    space as :attr:`seto.elf.Relocation.section_offset`.
    """
    original_words = decode_words(original, f"{name}: original")
    candidate_words = decode_words(candidate, f"{name}: candidate")
    original_sites = relocation_sites(original_relocations, original_section_offset, len(original))
    candidate_sites = relocation_sites(candidate_relocations, candidate_section_offset, len(candidate))
    original_pairs = _hi16_lo16_pairs(original_sites)
    candidate_pairs = _hi16_lo16_pairs(candidate_sites)

    limitations = list(limitations)
    issues: list[str] = []
    differences: list[WordDifference] = []
    matching = 0

    total = max(len(original_words), len(candidate_words))
    if len(original_words) != len(candidate_words):
        issues.append(
            f"size mismatch: original {len(original_words)} words, "
            f"candidate {len(candidate_words)} words"
        )

    compared = min(len(original_words), len(candidate_words))
    handled: set[int] = set()

    def outside_mask_equal(index: int, mask: int) -> bool:
        return (original_words[index] & ~mask) == (candidate_words[index] & ~mask)

    for index in range(compared):
        if index in handled:
            continue
        original_word = original_words[index]
        candidate_word = candidate_words[index]
        site_a = original_sites.get(index)
        site_b = candidate_sites.get(index)

        if site_a is None and site_b is None:
            if original_word == candidate_word:
                matching += 1
            else:
                differences.append(
                    WordDifference(index, address + index * 4, original_word, candidate_word, "word differs")
                )
            continue

        if site_a is None or site_b is None:
            side = "original" if site_a is not None else "candidate"
            if original_word == candidate_word:
                matching += 1
            differences.append(
                WordDifference(
                    index,
                    address + index * 4,
                    original_word,
                    candidate_word,
                    f"relocation only on the {side} side",
                )
            )
            issues.append(
                f"word {index} ({address + index * 4:#x}): relocation present only on "
                f"the {side} side ({site_a or site_b})"
            )
            continue

        assert site_a is not None and site_b is not None
        if site_a.type != site_b.type:
            differences.append(
                WordDifference(
                    index,
                    address + index * 4,
                    original_word,
                    candidate_word,
                    f"relocation type {site_a.type_name} vs {site_b.type_name}",
                )
            )
            issues.append(
                f"word {index} ({address + index * 4:#x}): relocation type "
                f"{site_a.type_name} vs {site_b.type_name}"
            )
            continue

        mask = relocation_mask(site_a.type)
        if mask == 0:
            limitations.append(
                f"word {index}: relocation type {site_a.type_name} is not modelled; "
                "equivalence cannot be proven"
            )
            if original_word == candidate_word:
                matching += 1
            else:
                differences.append(
                    WordDifference(
                        index, address + index * 4, original_word, candidate_word,
                        "unmodelled relocation, word differs",
                    )
                )
            continue

        # HI16/LO16 association: when both sides carry a pair at the same indices,
        # prove equivalence on the combined 32-bit value rather than each half.
        if index in original_pairs and index in candidate_pairs:
            low = index + 1
            site_a_lo = original_sites[low]
            site_b_lo = candidate_sites[low]
            low_mask = relocation_mask(site_a_lo.type)
            handled.add(low)
            if not outside_mask_equal(index, mask) or not outside_mask_equal(low, low_mask):
                differences.append(
                    WordDifference(
                        index, address + index * 4, original_word, candidate_word,
                        "relocated word differs outside the relocation field",
                    )
                )
                issues.append(
                    f"word {index} ({address + index * 4:#x}): HI16/LO16 pair differs "
                    "outside the relocation fields"
                )
                continue
            if combine_hi16_lo16(site_a.addend, site_a_lo.addend) == combine_hi16_lo16(
                site_b.addend, site_b_lo.addend
            ):
                matching += 2
                if not _symbols_agree(index, site_a, site_b, limitations):
                    differences.append(
                        WordDifference(
                            index, address + index * 4, original_word, candidate_word,
                            f"symbol {site_a.symbol!r} vs {site_b.symbol!r}",
                        )
                    )
                    issues.append(
                        f"word {index} ({address + index * 4:#x}): symbol "
                        f"{site_a.symbol!r} vs {site_b.symbol!r}"
                    )
            else:
                differences.append(
                    WordDifference(
                        index, address + index * 4, original_word, candidate_word,
                        "HI16/LO16 pair encodes a different value",
                    )
                )
                issues.append(
                    f"word {index} ({address + index * 4:#x}): HI16/LO16 pair encodes "
                    f"0x{combine_hi16_lo16(site_a.addend, site_a_lo.addend):08x} vs "
                    f"0x{combine_hi16_lo16(site_b.addend, site_b_lo.addend):08x}"
                )
            continue

        if not outside_mask_equal(index, mask):
            differences.append(
                WordDifference(
                    index, address + index * 4, original_word, candidate_word,
                    "relocated word differs outside the relocation field",
                )
            )
            issues.append(
                f"word {index} ({address + index * 4:#x}): relocated word differs "
                "outside the relocation field"
            )
            continue

        if site_a.addend != site_b.addend:
            differences.append(
                WordDifference(
                    index, address + index * 4, original_word, candidate_word,
                    f"addend 0x{site_a.addend:x} vs 0x{site_b.addend:x}",
                )
            )
            issues.append(
                f"word {index} ({address + index * 4:#x}): relocation addend "
                f"0x{site_a.addend:x} vs 0x{site_b.addend:x}"
            )
            continue

        if not _symbols_agree(index, site_a, site_b, limitations):
            differences.append(
                WordDifference(
                    index, address + index * 4, original_word, candidate_word,
                    f"symbol {site_a.symbol!r} vs {site_b.symbol!r}",
                )
            )
            issues.append(
                f"word {index} ({address + index * 4:#x}): symbol "
                f"{site_a.symbol!r} vs {site_b.symbol!r}"
            )
            continue
        matching += 1

    difference_count = len(differences) + (total - compared)
    if differences or issues:
        status = NONMATCHING
    elif limitations:
        status = INCONCLUSIVE
    else:
        status = MATCHED

    return MatchResult(
        name=name,
        address=address,
        total_words=total,
        matching_words=matching,
        status=status,
        difference_count=difference_count,
        differences=tuple(differences[:max_differences]),
        relocation_issues=tuple(dict.fromkeys(issues)),
        limitations=tuple(dict.fromkeys(limitations)),
        evidence=evidence,
    )


def _symbols_agree(
    index: int,
    site_a: RelocationSite,
    site_b: RelocationSite,
    limitations: list[str],
) -> bool:
    """Return ``False`` only on a *proven* symbol divergence."""
    if site_a.symbol is None and site_b.symbol is None:
        return True
    if site_a.symbol is not None and site_b.symbol is not None:
        return site_a.symbol == site_b.symbol
    limitations.append(
        f"word {index}: symbol available on only one side; symbol identity cannot be proven"
    )
    return True


def compare_region(
    original: bytes,
    original_section_offset: int,
    original_relocations: tuple[Relocation, ...] | list[Relocation],
    candidate: bytes,
    *,
    name: str,
    address: int = 0,
    candidate_section_offset: int = 0,
    candidate_relocations: tuple[Relocation, ...] | list[Relocation] = (),
) -> MatchResult:
    """Compare a slice of the original binary against a candidate slice.

    ``original_section_offset`` is the offset of ``original`` relative to the
    start of its section; ``candidate_section_offset`` is the same for
    ``candidate``.
    """
    if len(original) % 4:
        raise ParseError(f"{name}: original region length {len(original)} is not a multiple of 4")
    return compare(
        original,
        candidate,
        name=name,
        address=address,
        original_relocations=original_relocations,
        candidate_relocations=candidate_relocations,
        original_section_offset=original_section_offset,
        candidate_section_offset=candidate_section_offset,
    )


__all__ = [
    "BLOCKED",
    "EVIDENCE_BINARY_RANGE",
    "EVIDENCE_COMPILED_OBJECT",
    "INCONCLUSIVE",
    "MATCHED",
    "NONMATCHING",
    "MatchResult",
    "RelocationSite",
    "WordDifference",
    "combine_hi16_lo16",
    "compare",
    "compare_region",
    "decode_relocation_addend",
    "relocation_sites",
]
