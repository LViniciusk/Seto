"""Relocation-aware instruction comparison (the "matching" engine).

Two instruction streams match when

* every word that is *not* covered by a relocation is byte-identical, and
* every relocated word carries a relocation of the same type whose in-place
  addend is equal, and
* symbols agree whenever both sides expose them.

Relocated words are compared through a mask so that the same constant encoded
in different (but symbol-equivalent) ways still matches, which is exactly how
the reference projects' ``mwcc_diff`` treats globals and calls.  A stream is
declared ``MATCHED`` only when there is no proven divergence; a missing symbol
table is reported as a limitation instead of being silently ignored or
treated as success.
"""

from __future__ import annotations

from dataclasses import dataclass

from seto.binio import ParseError
from seto.elf import Relocation, decode_relocation_addend, relocation_mask, relocation_type_name
from seto.mips import decode_words

MATCHED = "MATCHED"
NONMATCHING = "NONMATCHING"
DEFAULT_MAX_DIFFERENCES = 64


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

    @property
    def percent(self) -> float:
        if self.total_words == 0:
            return 100.0
        return round(self.matching_words * 100.0 / self.total_words, 6)

    @property
    def is_matched(self) -> bool:
        return self.status == MATCHED

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "address": self.address,
            "status": self.status,
            "percent": self.percent,
            "total_words": self.total_words,
            "matching_words": self.matching_words,
            "difference_count": self.difference_count,
            "differences": [item.summary() for item in self.differences],
            "relocation_issues": list(self.relocation_issues),
            "limitations": list(self.limitations),
        }


def relocation_sites(
    relocations: tuple[Relocation, ...] | list[Relocation],
    region_offset: int,
) -> dict[int, RelocationSite]:
    """Index relocations by word index within a region.

    ``region_offset`` is the section-file offset of the region's first byte.
    Relocations that fall outside the region, are not word-aligned, or have an
    unresolvable offset are skipped.
    """
    sites: dict[int, RelocationSite] = {}
    for relocation in relocations:
        if relocation.section_offset is None:
            continue
        delta = relocation.section_offset - region_offset
        if delta < 0 or delta % 4:
            continue
        sites[delta // 4] = RelocationSite(
            word_index=delta // 4,
            type=relocation.type,
            addend=relocation.addend,
            symbol=relocation.symbol,
        )
    return sites


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
) -> MatchResult:
    """Compare two instruction streams with relocation-aware semantics.

    ``original_section_offset``/``candidate_section_offset`` are the byte offsets
    of the compared region relative to the start of its section, i.e. the same
    space as :attr:`seto.elf.Relocation.section_offset`.
    """
    original_words = decode_words(original, f"{name}: original")
    candidate_words = decode_words(candidate, f"{name}: candidate")
    original_sites = relocation_sites(original_relocations, original_section_offset)
    candidate_sites = relocation_sites(candidate_relocations, candidate_section_offset)

    limitations: list[str] = list(limitations)
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
    for index in range(compared):
        original_word = original_words[index]
        candidate_word = candidate_words[index]
        site_a = original_sites.get(index)
        site_b = candidate_sites.get(index)

        if site_a is None and site_b is None:
            if original_word == candidate_word:
                matching += 1
            else:
                differences.append(
                    WordDifference(
                        index, address + index * 4, original_word, candidate_word,
                        "word differs",
                    )
                )
            continue

        if site_a is None or site_b is None:
            side = "original" if site_a is not None else "candidate"
            if original_word == candidate_word:
                matching += 1
            differences.append(
                WordDifference(
                    index, address + index * 4, original_word, candidate_word,
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
                    index, address + index * 4, original_word, candidate_word,
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
                f"word {index}: relocation type {site_a.type_name} has no known mask; "
                "compared as a plain word"
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

        if (original_word & ~mask) != (candidate_word & ~mask):
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

        if site_a.addend == site_b.addend:
            if site_a.symbol is not None and site_b.symbol is not None:
                if site_a.symbol != site_b.symbol:
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
            elif site_a.symbol is not None or site_b.symbol is not None:
                limitations.append(
                    f"word {index}: symbol available on only one side; compared by addend"
                )
            matching += 1
            continue

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

    difference_count = len(differences) + (total - compared)
    status = MATCHED if difference_count == 0 and not issues else NONMATCHING

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
    )


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
    "MATCHED",
    "NONMATCHING",
    "MatchResult",
    "RelocationSite",
    "WordDifference",
    "compare",
    "compare_region",
    "relocation_sites",
    "decode_relocation_addend",
]
