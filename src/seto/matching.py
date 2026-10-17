"""Relocation-aware instruction comparison (the "matching" engine).

Two instruction streams match when

* every word that is *not* covered by a relocation is byte-identical,
* every word covered by a relocation carries a relocation of the same type whose
  in-place addend is equal, and
* the symbols the two sides expose agree.

A relocated word does not stand alone: an ``R_MIPS_HI16`` only acquires its
value together with the ``R_MIPS_LO16`` that resolves it, so pairs are
associated from the relocation table (never from mere adjacency) and compared as
a unit.

A call or data reference may be encoded differently on the two sides. A caller
may supply a :data:`CallResolver` for the module's proven call identities or
separate data resolvers for proven section/offset identities. They are only
consulted when their respective relocation kinds require them; unresolved
targets become ``INCONCLUSIVE``. A data resolver answers with a
:class:`~seto.datarefs.DataIdentity`, which carries the artifact the location
belongs to: two answers in different artifacts are inconclusive, never equal.

The result is deliberately conservative.  Byte equality alone is **not** treated
as proof of a matching decompilation: whenever the available evidence cannot
establish equivalence (a raw blob candidate, an unmodelled relocation type, a
symbol present on only one side, a HI16 with no resolvable LO16, a call whose
destination cannot be identified, ...) the outcome is ``INCONCLUSIVE`` rather
than ``MATCHED``.

Statuses
--------
``MATCHED``       equivalence proven for the compared range
``NONMATCHING``   a divergence was proven
``INCONCLUSIVE``  the comparison ran but the evidence is insufficient
``BLOCKED``       an external prerequisite was unavailable (produced by callers)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from seto.binio import ParseError
from seto.elf import (
    R_MIPS_26,
    R_MIPS_32,
    R_MIPS_HI16,
    R_MIPS_LO16,
    Relocation,
    decode_relocation_addend,
    relocation_mask,
    relocation_type_name,
)
from seto.datarefs import DataIdentity, DataIdentityResolver, DataTarget
from seto.mips import decode_words

MATCHED = "MATCHED"
NONMATCHING = "NONMATCHING"
INCONCLUSIVE = "INCONCLUSIVE"
BLOCKED = "BLOCKED"
DEFAULT_MAX_DIFFERENCES = 64

#: The comparison was between byte ranges (a raw blob, or the original compared
#: against itself).  Equivalence here is "binary-range equivalence", not proof
#: that a reconstruction compiles back to the original.
EVIDENCE_BINARY_RANGE = "binary-range"
#: The candidate was produced by compiling the reconstruction in the run that
#: performed this comparison.  ``ET_REL`` alone does **not** imply this: only the
#: caller that actually compiled the object may set it.  A ``MATCHED`` with this
#: evidence is a verified decompilation match.
EVIDENCE_COMPILED_OBJECT = "compiled-object"

#: What a ``MATCHED`` proves when every byte of the compared range agrees, so the
#: two streams are identical as they stand.
EQUIVALENCE_BINARY = "binary equality of the compared range"
#: What a ``MATCHED`` proves when it rests on canonically resolved call/data
#: relocations: the streams agree and every resolved reference names the same
#: proven identity. This is *not* full binary equality after linking.
EQUIVALENCE_RESOLVED_RELOCATIONS = "function equivalence with canonically resolved relocations"

#: Relocation types whose in-place field is a jump/call target.  A call reference
#: is the one relocated field whose encoding legitimately differs between a
#: linked module (which stores the trampoline address) and a relocatable object
#: (which stores a symbol name), so it is the only field a caller may ask to be
#: resolved to a proven identity instead of compared literally.
CALL_RELOCATION_TYPES: tuple[int, ...] = (R_MIPS_26,)


#: The first half of the identity of a call to another function of the same
#: module.  A library name is read from a NUL-terminated string, so it can never
#: contain a NUL and this marker can never collide with a real library: two
#: identical NIDs in two libraries stay distinct, and a module function is never
#: confused with an import.
SELF_LIBRARY = "\x00self"


@dataclass(frozen=True)
class CallTarget:
    """The proven destination of a call reference.

    An imported call is identified by ``(library, nid)``; a call to another
    function of the same module by ``(SELF_LIBRARY, address)``.  ``nid`` is the
    second half of the identity in both cases - the imported function's NID, or
    the address of the module function - while ``stub_address`` is the address
    the reference itself points at (the trampoline, or the function).

    ``origin`` records *how* the identity was obtained (an address stored in the
    instruction, or a symbol name that had to be looked up); it is left out of
    equality on purpose, because the identity is the pair alone.
    """

    library: str
    nid: int
    stub_address: int
    origin: str = field(default="", compare=False)

    @property
    def identity(self) -> tuple[str, int]:
        return (self.library, self.nid)

    @property
    def is_import(self) -> bool:
        return self.library != SELF_LIBRARY

    def describe(self) -> str:
        if not self.is_import:
            return f"this module @ 0x{self.nid:x}"
        detail = f", {self.origin}" if self.origin else ""
        return f"{self.library}/0x{self.nid:08X} (stub 0x{self.stub_address:x}{detail})"


#: Turns a call relocation into a proven destination, or ``None`` when the
#: evidence on hand is not enough to establish one.
CallResolver = Callable[["RelocationSite"], "CallTarget | None"]


@dataclass(frozen=True)
class RelocationSite:
    """A relocation expressed relative to the start of the compared region."""

    word_index: int
    type: int
    addend: int
    symbol: str | None
    symbol_index: int = 0

    @property
    def type_name(self) -> str:
        return relocation_type_name(self.type)

    @property
    def mask(self) -> int:
        return relocation_mask(self.type)


DataTargetResolver = DataIdentityResolver
"""Backwards-compatible alias; a resolver answers with a :class:`DataIdentity`."""


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
    resolved_calls: tuple[str, ...] = ()
    resolved_data: tuple[str, ...] = ()

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

    @property
    def equivalence(self) -> str:
        """What a ``MATCHED`` actually proves, in words.

        Empty for any other status: there is no equivalence to name.
        """
        if self.status != MATCHED:
            return ""
        return (
            EQUIVALENCE_RESOLVED_RELOCATIONS
            if self.resolved_calls or self.resolved_data
            else EQUIVALENCE_BINARY
        )

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "address": self.address,
            "status": self.status,
            "evidence": self.evidence,
            "equivalence": self.equivalence,
            "percent": self.percent,
            "total_words": self.total_words,
            "matching_words": self.matching_words,
            "difference_count": self.difference_count,
            "differences": [item.summary() for item in self.differences],
            "relocation_issues": list(self.relocation_issues),
            "limitations": list(self.limitations),
            "resolved_calls": list(self.resolved_calls),
            "resolved_data": list(self.resolved_data),
        }


def combine_hi16_lo16(hi_addend: int, lo_addend: int) -> int:
    """Combine a HI16/LO16 relocation pair into the 32-bit value it encodes.

    ``decode_relocation_addend`` already sign-extends the LO16 half and keeps the
    raw 16 bits of the HI16 half, so a plain modulo-2**32 sum is exact (there is
    no carry aliasing between the two encodings).
    """
    return (((hi_addend & 0xFFFF) << 16) + lo_addend) & 0xFFFFFFFF


@dataclass(frozen=True)
class RelocationMap:
    """Relocations placed inside a compared region, plus placement problems."""

    sites: dict[int, RelocationSite]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hi16Lo16Pairing:
    """How the ``R_MIPS_HI16`` relocations are resolved by ``R_MIPS_LO16`` ones."""

    hi_to_lo: dict[int, int]
    limitations: tuple[str, ...] = ()


def relocation_sites(
    relocations: tuple[Relocation, ...] | list[Relocation],
    region_offset: int,
    region_size: int | None = None,
) -> RelocationMap:
    """Index relocations by word index within a region.

    ``region_offset`` is the section offset of the region's first byte;
    ``region_size`` (when given) is its length in bytes, so relocations that
    belong to another function are ignored.  A relocation that cannot be placed
    inside the range is never dropped silently: it becomes a limitation, because
    a relocation we cannot account for may still change the expected bytes.  Two
    relocations targeting the same word are rejected instead of being silently
    overwritten.
    """
    sites: dict[int, RelocationSite] = {}
    limitations: list[str] = []
    for relocation in relocations:
        if relocation.section_offset is None:
            limitations.append(
                f"a {relocation.type_name} relocation has no resolved section and cannot be placed"
            )
            continue
        delta = relocation.section_offset - region_offset
        if delta < 0 or (region_size is not None and delta >= region_size):
            continue
        if delta % 4:
            limitations.append(
                f"relocation at section offset 0x{relocation.section_offset:x} is not "
                "word-aligned inside the compared range"
            )
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
            symbol_index=relocation.symbol_index,
        )
    return RelocationMap(sites=sites, limitations=tuple(dict.fromkeys(limitations)))


def _symbol_identity(original: str | None, candidate: str | None) -> bool | None:
    """``True``/``False`` when both sides expose a symbol, ``None`` when unknown."""
    if original is not None and candidate is not None:
        return original == candidate
    return None


def _pair_symbol_identity(hi: RelocationSite, lo: RelocationSite) -> bool | None:
    """Use an ELF symbol-table index when a local/section symbol has no name."""
    if hi.symbol is not None and lo.symbol is not None:
        return hi.symbol == lo.symbol
    if hi.symbol_index and lo.symbol_index:
        return hi.symbol_index == lo.symbol_index
    return None


def pair_hi16_lo16(sites: dict[int, RelocationSite]) -> Hi16Lo16Pairing:
    """Associate every ``R_MIPS_HI16`` with the ``R_MIPS_LO16`` that resolves it.

    Relocations are consumed in relocation-table order (the order of ``sites``),
    which is the order the assembler emitted them: the LO16 closing a HI16 does
    **not** have to be adjacent, and a single LO16 resolves every pending HI16
    that refers to the same symbol.  A HI16 still pending at the end is
    unresolved.  When the file does not expose the symbol identity the
    association can only fall back to relocation order, which is recorded as a
    limitation rather than presented as proven.
    """
    hi_to_lo: dict[int, int] = {}
    pending: list[int] = []
    limitations: list[str] = []
    for word_index, site in sites.items():
        if site.type == R_MIPS_HI16:
            pending.append(word_index)
            continue
        if site.type != R_MIPS_LO16:
            continue
        closed: list[int] = []
        unproven = False
        for hi_index in pending:
            verdict = _pair_symbol_identity(sites[hi_index], site)
            if verdict is False:
                continue
            closed.append(hi_index)
            unproven = unproven or verdict is None
        if not closed:
            continue
        if unproven:
            limitations.append(
                f"word {word_index}: HI16/LO16 association relies on relocation order "
                "(symbol identity unavailable)"
            )
        for hi_index in closed:
            hi_to_lo[hi_index] = word_index
        closed_set = set(closed)
        pending = [hi_index for hi_index in pending if hi_index not in closed_set]
    for hi_index in pending:
        limitations.append(f"word {hi_index}: HI16 relocation has no LO16 to resolve it")
    return Hi16Lo16Pairing(hi_to_lo=hi_to_lo, limitations=tuple(dict.fromkeys(limitations)))


def _describe_pair(low: int | None, sites: dict[int, RelocationSite], index: int) -> str:
    """Human-readable description of what sits at ``index`` in one relocation map."""
    if low is not None:
        return f"LO16 at word {low}"
    site = sites.get(index)
    if site is None:
        return "no relocation"
    if site.type == R_MIPS_HI16:
        return "unresolved HI16"
    return f"{site.type_name} alone"


def _describe_identity(identity: DataIdentity | None) -> str:
    """Describe a resolver answer without ever printing a bare location."""
    if identity is None:
        return "unresolved"
    return f"{identity.artifact}:{identity.target.section}+0x{identity.target.offset:x}"


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
    call_resolver: CallResolver | None = None,
    original_data_resolver: DataTargetResolver | None = None,
    candidate_data_resolver: DataTargetResolver | None = None,
) -> MatchResult:
    """Compare two instruction streams with relocation-aware semantics.

    ``original_section_offset``/``candidate_section_offset`` are the byte offsets
    of the compared region relative to the start of its section, i.e. the same
    space as :attr:`seto.elf.Relocation.section_offset`.

    ``call_resolver`` is optional and only used where the literal comparison
    cannot decide, i.e. two call relocations whose in-place targets differ.  It
    is never allowed to turn a divergence into a match on its own: it either
    proves that both sides name the same destination, proves that they name
    different ones, or leaves the outcome inconclusive.

    Data resolvers are optional. When supplied, ``R_MIPS_32`` and paired
    ``R_MIPS_HI16``/``LO16`` references are compared by artifact-qualified
    identity: the two answers must name the *same* artifact before their
    locations may be compared at all. If either side cannot prove an identity, or
    the two answers come from different artifacts, the result is
    ``INCONCLUSIVE``; symbol-like spelling or equal numeric addends alone never
    establishes data identity.
    """
    original_words = decode_words(original, f"{name}: original")
    candidate_words = decode_words(candidate, f"{name}: candidate")
    original_map = relocation_sites(original_relocations, original_section_offset, len(original))
    candidate_map = relocation_sites(candidate_relocations, candidate_section_offset, len(candidate))
    original_pairs = pair_hi16_lo16(original_map.sites)
    candidate_pairs = pair_hi16_lo16(candidate_map.sites)

    limitations = (
        list(limitations)
        + list(original_map.limitations)
        + list(candidate_map.limitations)
        + list(original_pairs.limitations)
        + list(candidate_pairs.limitations)
    )
    issues: list[str] = []
    differences: list[WordDifference] = []
    resolved_calls: list[str] = []
    resolved_data: list[str] = []
    matching = 0

    total = max(len(original_words), len(candidate_words))
    if len(original_words) != len(candidate_words):
        issues.append(
            f"size mismatch: original {len(original_words)} words, "
            f"candidate {len(candidate_words)} words"
        )

    compared = min(len(original_words), len(candidate_words))
    handled: set[int] = set()
    counted: set[int] = set()

    def outside_mask_equal(index: int, mask: int) -> bool:
        return (original_words[index] & ~mask) == (candidate_words[index] & ~mask)

    def count_matching(index: int) -> None:
        # A word is counted at most once: one LO16 may resolve several HI16.
        nonlocal matching
        if index not in counted:
            counted.add(index)
            matching += 1

    def record_difference(index: int, reason: str, *, relocation_issue: bool = True) -> None:
        differences.append(
            WordDifference(
                index, address + index * 4, original_words[index], candidate_words[index], reason
            )
        )
        if relocation_issue:
            issues.append(f"word {index} ({address + index * 4:#x}): {reason}")

    pair_limitations = list(original_pairs.limitations) + list(candidate_pairs.limitations)

    def pair_identity_is_inconclusive(hi_index: int, low_index: int) -> bool:
        # ``pair_hi16_lo16`` records the order-only note at the LO16's word index.
        return any(
            item.startswith(f"word {index}: HI16/LO16 association relies on relocation order")
            for index in (hi_index, low_index)
            for item in pair_limitations
        )

    def compare_data_identity(
        index: int,
        low_index: int | None,
        identity_a: DataIdentity | None,
        identity_b: DataIdentity | None,
        label: str,
    ) -> None:
        """Decide one resolved data reference from its artifact-qualified identities.

        A ``DataTarget`` is a location; only a :class:`DataIdentity` carries the
        artifact it belongs to. Two answers in different artifacts are therefore
        never treated as one object - they are inconclusive, not a mismatch.
        """
        if identity_a is None or identity_b is None:
            limitations.append(
                f"word {index}: {label} identity cannot be proven "
                f"(original: {_describe_identity(identity_a)}; "
                f"candidate: {_describe_identity(identity_b)})"
            )
            return
        if identity_a.artifact != identity_b.artifact:
            limitations.append(
                f"word {index}: {label} resolvers answer in different artifacts "
                f"({identity_a.artifact!r} vs {identity_b.artifact!r}); a location in one "
                "file does not name an object in another"
            )
            return
        if identity_a.target != identity_b.target:
            if low_index is not None and pair_identity_is_inconclusive(index, low_index):
                limitations.append(
                    f"word {index}: {label} targets differ, but at least one pair lacks "
                    "symbol identity; the differing destination is inconclusive"
                )
                return
            record_difference(
                index,
                f"{label} target differs "
                f"({identity_a.target.section}+0x{identity_a.target.offset:x} vs "
                f"{identity_b.target.section}+0x{identity_b.target.offset:x})",
            )
            return
        resolved_data.append(
            f"word {index}: {identity_a.target.section}+0x{identity_a.target.offset:x} "
            f"<=> {identity_b.target.section}+0x{identity_b.target.offset:x}"
        )
        count_matching(index)
        if low_index is not None:
            count_matching(low_index)

    # A HI16 only acquires its value together with the LO16 that resolves it, so
    # pairs are compared as units - before the word-by-word pass - and only when
    # both sides agree on how the pair is formed.
    for hi_index in sorted(set(original_pairs.hi_to_lo) | set(candidate_pairs.hi_to_lo)):
        if not 0 <= hi_index < compared:
            # Only reachable when the streams differ in length, which is itself an
            # issue; the pair cannot be judged.
            limitations.append(
                f"word {hi_index}: HI16 relocation lies outside the compared range"
            )
            continue
        hi_original = original_pairs.hi_to_lo.get(hi_index)
        hi_candidate = candidate_pairs.hi_to_lo.get(hi_index)
        if hi_original != hi_candidate:
            # The two sides do not agree on how this HI16 is resolved.
            handled.add(hi_index)
            for low in (hi_original, hi_candidate):
                if low is not None and 0 <= low < compared:
                    handled.add(low)
            record_difference(
                hi_index,
                "HI16/LO16 association differs ("
                f"original: {_describe_pair(hi_original, original_map.sites, hi_index)}; "
                f"candidate: {_describe_pair(hi_candidate, candidate_map.sites, hi_index)})",
            )
            continue

        assert hi_original is not None  # hi_index comes from the union of both maps
        # Each map only indexes words inside its own stream, so an agreed pair is
        # always inside the compared range.
        low = hi_original
        handled.add(hi_index)
        handled.add(low)

        site_a_hi = original_map.sites[hi_index]
        site_b_hi = candidate_map.sites[hi_index]
        site_a_lo = original_map.sites[low]
        site_b_lo = candidate_map.sites[low]

        if not outside_mask_equal(hi_index, site_a_hi.mask) or not outside_mask_equal(
            low, site_a_lo.mask
        ):
            record_difference(hi_index, "relocated word differs outside the relocation field")
            continue

        original_value = combine_hi16_lo16(site_a_hi.addend, site_a_lo.addend)
        candidate_value = combine_hi16_lo16(site_b_hi.addend, site_b_lo.addend)
        if original_data_resolver is not None or candidate_data_resolver is not None:
            identity_a = (
                None
                if original_data_resolver is None
                else original_data_resolver(site_a_hi, original_value)
            )
            identity_b = (
                None
                if candidate_data_resolver is None
                else candidate_data_resolver(site_b_hi, candidate_value)
            )
            compare_data_identity(hi_index, low, identity_a, identity_b, "HI16/LO16 data")
            continue

        if original_value != candidate_value:
            record_difference(
                hi_index,
                f"HI16/LO16 pair encodes 0x{original_value:08x} vs 0x{candidate_value:08x}",
            )
            continue

        symbol_issues: list[str] = []
        if not _symbols_agree(hi_index, site_a_hi, site_b_hi, limitations):
            symbol_issues.append(f"HI16 symbol {site_a_hi.symbol!r} vs {site_b_hi.symbol!r}")
        if not _symbols_agree(low, site_a_lo, site_b_lo, limitations):
            symbol_issues.append(f"LO16 symbol {site_a_lo.symbol!r} vs {site_b_lo.symbol!r}")
        if symbol_issues:
            record_difference(hi_index, "HI16/LO16 " + "; ".join(symbol_issues))
            continue
        count_matching(hi_index)
        count_matching(low)

    for index in range(compared):
        if index in handled:
            continue
        original_word = original_words[index]
        candidate_word = candidate_words[index]
        site_a = original_map.sites.get(index)
        site_b = candidate_map.sites.get(index)

        if site_a is None and site_b is None:
            if original_word == candidate_word:
                count_matching(index)
            else:
                record_difference(index, "word differs", relocation_issue=False)
            continue

        if site_a is None or site_b is None:
            side = "original" if site_a is not None else "candidate"
            if original_word == candidate_word:
                count_matching(index)
            record_difference(index, f"relocation present only on the {side} side")
            continue

        if site_a.type != site_b.type:
            record_difference(index, f"relocation type {site_a.type_name} vs {site_b.type_name}")
            continue

        mask = relocation_mask(site_a.type)
        if mask == 0:
            limitations.append(
                f"word {index}: relocation type {site_a.type_name} is not modelled; "
                "equivalence cannot be proven"
            )
            if original_word == candidate_word:
                count_matching(index)
            else:
                record_difference(index, "unmodelled relocation, word differs", relocation_issue=False)
            continue

        if not outside_mask_equal(index, mask):
            record_difference(index, "relocated word differs outside the relocation field")
            continue

        if site_a.type == R_MIPS_32 and (
            original_data_resolver is not None or candidate_data_resolver is not None
        ):
            identity_a = (
                None
                if original_data_resolver is None
                else original_data_resolver(site_a, site_a.addend)
            )
            identity_b = (
                None
                if candidate_data_resolver is None
                else candidate_data_resolver(site_b, site_b.addend)
            )
            compare_data_identity(index, None, identity_a, identity_b, "R_MIPS_32 data")
            continue

        if site_a.addend != site_b.addend:
            if site_a.type in CALL_RELOCATION_TYPES and call_resolver is not None:
                # The two encodings of the same reference: a linked module stores
                # the trampoline address, a relocatable object stores a symbol
                # name.  Only the resolver can tell whether they are the same call
                # - and it may only do so on evidence.
                target_a = call_resolver(site_a)
                target_b = call_resolver(site_b)
                if target_a is not None and target_b is not None:
                    if target_a.identity == target_b.identity:
                        # Record the evidence: a MATCHED that rests on a resolved
                        # reference must be able to show which one.
                        resolved_calls.append(
                            f"word {index} ({address + index * 4:#x}): "
                            f"{target_a.describe()} <=> {target_b.describe()}"
                        )
                        count_matching(index)
                        continue
                    record_difference(
                        index,
                        f"call target {target_a.describe()} vs {target_b.describe()}",
                    )
                    continue
                limitations.append(
                    f"word {index}: call targets 0x{site_a.addend:x} and 0x{site_b.addend:x} "
                    "differ and at least one of them has no proven imported identity; "
                    "equivalence cannot be proven"
                )
                continue
            record_difference(index, f"addend 0x{site_a.addend:x} vs 0x{site_b.addend:x}")
            continue

        if not _symbols_agree(index, site_a, site_b, limitations):
            record_difference(index, f"symbol {site_a.symbol!r} vs {site_b.symbol!r}")
            continue
        count_matching(index)

    differences.sort(key=lambda item: item.word_index)
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
        resolved_calls=tuple(resolved_calls),
        resolved_data=tuple(resolved_data),
    )


def _symbols_agree(
    index: int,
    site_a: RelocationSite,
    site_b: RelocationSite,
    limitations: list[str],
) -> bool:
    """Return ``False`` only on a *proven* symbol divergence.

    Shared by single relocations and by both halves of a HI16/LO16 pair, so the
    symbol identity of a pair is checked on the HI16 **and** the LO16.
    """
    verdict = _symbol_identity(site_a.symbol, site_b.symbol)
    if verdict is None:
        if site_a.symbol is not None or site_b.symbol is not None:
            limitations.append(
                f"word {index}: symbol available on only one side; "
                "symbol identity cannot be proven"
            )
        return True
    return verdict


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
    call_resolver: CallResolver | None = None,
    original_data_resolver: DataTargetResolver | None = None,
    candidate_data_resolver: DataTargetResolver | None = None,
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
        call_resolver=call_resolver,
        original_data_resolver=original_data_resolver,
        candidate_data_resolver=candidate_data_resolver,
    )


__all__ = [
    "BLOCKED",
    "CALL_RELOCATION_TYPES",
    "DataIdentity",
    "DataIdentityResolver",
    "DataTarget",
    "DataTargetResolver",
    "EVIDENCE_BINARY_RANGE",
    "EVIDENCE_COMPILED_OBJECT",
    "EQUIVALENCE_BINARY",
    "EQUIVALENCE_RESOLVED_RELOCATIONS",
    "INCONCLUSIVE",
    "MATCHED",
    "NONMATCHING",
    "SELF_LIBRARY",
    "CallResolver",
    "CallTarget",
    "Hi16Lo16Pairing",
    "MatchResult",
    "RelocationMap",
    "RelocationSite",
    "WordDifference",
    "combine_hi16_lo16",
    "compare",
    "compare_region",
    "decode_relocation_addend",
    "pair_hi16_lo16",
    "relocation_sites",
]
