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
may supply a :data:`CallResolver` for the module's proven call identities and
data resolvers for proven cross-artifact object identities. Data locations and
equal addends alone never prove identity; without data resolvers, data-relocated
words remain ``INCONCLUSIVE``. A data resolver answers with a
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
    decode_psp_relocation_info,
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
    addend_valid: bool = True

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
    evidence: dict[int, str] = field(default_factory=dict)


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
        if relocation.format == "PSP":
            _, _, _, reserved = decode_psp_relocation_info(relocation.info)
            if reserved:
                limitations.append(
                    f"{relocation.type_name} relocation has reserved PSP r_info bits "
                    f"0x{reserved:08x}"
                )
        if not relocation.addend_valid:
            limitations.append(
                f"a {relocation.type_name} relocation has no fully recoverable in-place addend"
            )
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
            addend_valid=relocation.addend_valid,
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


def pair_hi16_lo16(
    sites: dict[int, RelocationSite], words: tuple[int, ...] | None = None
) -> Hi16Lo16Pairing:
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
    evidence: dict[int, str] = {}
    pending: list[int] = []
    limitations: list[str] = []
    for word_index, site in sites.items():
        if site.type == R_MIPS_HI16:
            pending.append(word_index)
            continue
        if site.type != R_MIPS_LO16:
            continue
        flow_kind, flow_hi, flow_reason = _register_flow_pair(site, word_index, sites, words)

        # Explicitly shared ELF-symbol identity remains useful (some valid MIPS
        # streams have one LO resolving several pending HI relocations).  When
        # the symbols are absent, use the instruction stream only if the LO's
        # reaching definition is a unique relocated LUI.
        closed: list[int] = []
        for hi_index in pending:
            if _pair_symbol_identity(sites[hi_index], site) is True:
                closed.append(hi_index)

        if closed:
            for hi_index in closed:
                hi_to_lo[hi_index] = word_index
                evidence[hi_index] = "symbol"
        elif flow_kind == "match":
            if flow_hi not in pending:
                limitations.append(
                    f"word {word_index}: register flow reaches HI16 word {flow_hi}, "
                    "but it is not pending in relocation-table order"
                )
            elif _pair_symbol_identity(sites[flow_hi], site) is False:
                limitations.append(
                    f"word {word_index}: register flow reaches HI16 word {flow_hi}, "
                    "but the relocation symbols differ"
                )
            else:
                hi_to_lo[flow_hi] = word_index
                evidence[flow_hi] = "register-flow"
                closed.append(flow_hi)
        elif flow_kind == "definite-none":
            limitations.append(
                f"word {word_index}: no relocated HI16 reaches the LO16 source register "
                f"({flow_reason})"
            )
        else:
            # If the code cannot establish a reaching definition (e.g. a branch,
            # unknown instruction, or no instruction words were supplied), retain
            # the legacy order association but do not promote its confidence.
            order_candidates = [
                hi_index
                for hi_index in pending
                if _pair_symbol_identity(sites[hi_index], site) is None
            ]
            if flow_kind == "uncertain" and flow_reason:
                limitations.append(
                    f"word {word_index}: register-flow pairing is uncertain: {flow_reason}"
                )
            for hi_index in order_candidates:
                hi_to_lo[hi_index] = word_index
                evidence[hi_index] = "relocation-order"
                closed.append(hi_index)
            if order_candidates:
                limitations.append(
                    f"word {word_index}: HI16/LO16 association relies on relocation order "
                    "(symbol identity unavailable)"
                )

        if not closed:
            limitations.append(f"word {word_index}: LO16 relocation has no associated HI16")
            continue
        closed_set = set(closed)
        pending = [hi_index for hi_index in pending if hi_index not in closed_set]
    for hi_index in pending:
        limitations.append(f"word {hi_index}: HI16 relocation has no LO16 to resolve it")
    return Hi16Lo16Pairing(
        hi_to_lo=hi_to_lo,
        limitations=tuple(dict.fromkeys(limitations)),
        evidence=evidence,
    )


_CFG_BRANCH_LIKELY_OPS = frozenset((0x14, 0x15, 0x16, 0x17))
# Link variants are conditional calls, not ordinary intraprocedural edges.
# Leave them unsupported rather than discarding a possible callee return.
_CFG_REGIMM_BRANCHES = frozenset((0x00, 0x01))
_CFG_REGIMM_LIKELY = frozenset((0x02, 0x03))
_CFG_EXIT_FUNCTS = frozenset((0x0C, 0x0D))


def _cfg_control_kind(word: int) -> str | None:
    """Classify a word for the small intraprocedural CFG used by pairing."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    funct = word & 0x3F
    if op == 0:
        if funct == 8:  # jr
            return "jr"
        if funct == 9:  # jalr
            return "jalr"
        if funct in _CFG_EXIT_FUNCTS:  # syscall/break (SPECIAL 0x18 is mult)
            return "exit"
        return None
    if op in (2, 3):  # j/jal
        return "jump"
    if op == 1:
        if rt in _CFG_REGIMM_LIKELY:
            return "branch-likely"
        if rt in _CFG_REGIMM_BRANCHES:
            return "branch"
        return "unsupported"
    if op in (4, 5, 6, 7):  # beq/bne/blez/bgtz
        return "branch"
    if op in _CFG_BRANCH_LIKELY_OPS:
        return "branch-likely"
    if op in (0x10, 0x11, 0x12, 0x13) and rs == 8:
        # Coprocessor branches have not been modeled here.
        return "unsupported"
    if _instruction_effect(word)[0]:
        return "unsupported"
    return None


def _cfg_branch_relation(word: int) -> str:
    """Return always/never/conditional for a branch comparison of identical regs."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    if op == 4:
        return "always" if rs == rt else "conditional"
    if op == 5:
        return "never" if rs == rt else "conditional"
    return "conditional"


def _cfg_branch_target(index: int, word: int) -> int:
    immediate = word & 0xFFFF
    if immediate & 0x8000:
        immediate -= 0x10000
    return index + 1 + immediate


def _cfg_is_call(word: int) -> bool:
    op = (word >> 26) & 0x3F
    return op == 3 or (
        op == 0 and (word & 0x3F) == 9 and ((word >> 11) & 0x1F) != 0
    )


def _cfg_precheck(
    words: tuple[int, ...], low_index: int
) -> tuple[dict[int, int], str | None]:
    """Build delay-slot ownership and reject control flow we cannot model.

    The result is intentionally conservative.  A return value other than
    ``None`` means the straight-line analyzer remains the best available
    evidence and the CFG must not override it.
    """
    delay_of: dict[int, int] = {}
    # Successors can run beyond the LO and loop back to it. Delay-slot owners
    # must therefore cover the whole window, not only its prefix.
    for index in range(len(words)):
        kind = _cfg_control_kind(words[index])
        if kind is None:
            if _instruction_effect(words[index])[2] is None:
                return delay_of, f"unknown register effects at word {index}"
            continue
        if kind == "unsupported":
            return delay_of, f"unsupported control transfer at word {index}"
        if kind == "exit":
            return delay_of, f"control transfer at word {index} leaves the compared words"
        if index in delay_of:
            return delay_of, "a control transfer occupies a delay slot"
        if kind in ("jump", "jr", "jalr") and low_index != index + 1:
            is_return = kind == "jr" and ((words[index] >> 21) & 0x1F) == 31
            if index < low_index or not (_cfg_is_call(words[index]) or is_return):
                return delay_of, f"the LO16 lies beyond the {kind} at word {index}"
        if index + 1 >= len(words):
            return delay_of, f"control transfer at word {index} has no in-range delay slot"
        delay_of[index + 1] = index
        if kind in ("branch", "branch-likely") and low_index != index + 1:
            target = _cfg_branch_target(index, words[index])
            if not 0 <= target < len(words):
                return delay_of, f"branch at word {index} leaves the compared words"
    for index, word in enumerate(words):
        if _cfg_control_kind(word) in ("branch", "branch-likely"):
            if _cfg_branch_target(index, word) in delay_of:
                # Entering a delay instruction normally is not equivalent to
                # executing it with its owner's pending branch destination.
                return delay_of, f"branch at word {index} targets a delay slot"
    return delay_of, None


def _cfg_successors(
    index: int, words: tuple[int, ...], delay_of: dict[int, int]
) -> list[int]:
    """Return in-region successors for the local CFG.

    A delay-slot node inherits the branch's taken/not-taken successors.  A
    branch-likely additionally has a direct edge over its delay slot for the
    not-taken path.
    """
    count = len(words)
    if index in delay_of:
        branch = delay_of[index]
        kind = _cfg_control_kind(words[branch])
        if _cfg_is_call(words[branch]):
            # The call's delay slot precedes callee execution. A later return
            # can reenter the LO via a backedge; transfer() marks its GPR state
            # unknown rather than silently dropping this path.
            return [branch + 2] if branch + 2 < count else []
        if kind in ("jump", "jr", "jalr", "exit", "unsupported") or kind is None:
            return []
        target = _cfg_branch_target(branch, words[branch])
        fall_through = branch + 2
        if kind == "branch-likely":
            return [target] if 0 <= target < count else []
        relation = _cfg_branch_relation(words[branch])
        if relation == "always":
            return [target] if 0 <= target < count else []
        if relation == "never":
            return [fall_through] if 0 <= fall_through < count else []
        successors = []
        if 0 <= target < count:
            successors.append(target)
        if 0 <= fall_through < count and fall_through != target:
            successors.append(fall_through)
        return successors

    kind = _cfg_control_kind(words[index])
    if kind is None:
        return [index + 1] if index + 1 < count else []
    if kind == "branch-likely":
        successors = []
        if index + 1 < count:
            successors.append(index + 1)
        if index + 2 < count:
            successors.append(index + 2)
        return successors
    if kind in ("branch", "jump", "jr", "jalr"):
        return [index + 1] if index + 1 < count else []
    return []


def _cfg_register_flow(
    low: RelocationSite,
    low_index: int,
    sites: dict[int, RelocationSite],
    words: tuple[int, ...] | None,
) -> tuple[str, int | None, str] | None:
    """Prove a HI16 reaching a LO16 base register across mutually exclusive paths.

    Only positive proofs and unambiguous explicit redefinitions are returned.
    ``None`` means the local CFG could not model the window and the legacy
    straight-line analyzer must decide the result.  The analysis tracks only
    the LO16 source register, which keeps the lattice small while preserving
    branch-delay and branch-likely semantics.
    """
    if words is None or not 0 <= low_index < len(words):
        return None
    source = _lo_source_register(words[low_index])
    if source is None:
        return None
    if source == 0:
        return None
    delay_of, problem = _cfg_precheck(words, low_index)
    if problem is not None:
        return None

    def transfer(
        state: frozenset[tuple[str, int]], index: int
    ) -> frozenset[tuple[str, int]]:
        if index in delay_of and _cfg_is_call(words[delay_of[index]]):
            return frozenset({("unknown", index)})
        word = words[index]
        _control, _unconditional, writes = _instruction_effect(word)
        if writes is None:
            return frozenset({("unknown", index)})
        if source not in writes:
            return state
        if (word >> 26) == 0x0F and index in sites and sites[index].type == R_MIPS_HI16:
            return frozenset({("hi", index)})
        return frozenset({("other", index)})

    states: dict[int, frozenset[tuple[str, int]]] = {0: frozenset({("entry", 0)})}
    work = [0]
    steps = 0
    while work:
        index = work.pop()
        out = transfer(states[index], index)
        for successor in _cfg_successors(index, words, delay_of):
            if not 0 <= successor < len(words):
                continue
            previous = states.get(successor)
            merged = out if previous is None else previous | out
            if merged != previous:
                states[successor] = merged
                work.append(successor)
                steps += 1
                if steps > 10000:
                    return None

    reaching = states.get(low_index)
    if not reaching:
        return None
    if any(kind == "unknown" for kind, _index in reaching):
        return None
    hi_definitions = sorted(index for kind, index in reaching if kind == "hi")
    other_definitions = sorted(index for kind, index in reaching if kind == "other")
    if len(reaching) == 1 and len(hi_definitions) == 1:
        hi_index = hi_definitions[0]
        site = sites.get(hi_index)
        if site is not None and site.type == R_MIPS_HI16:
            return (
                "match",
                hi_index,
                "a unique relocated LUI reaches the LO16 base register "
                "along every modeled CFG path",
            )
    if other_definitions and not any(kind == "entry" for kind, _index in reaching):
        if len(reaching) == 1:
            return (
                "definite-none",
                None,
                f"word {other_definitions[0]} redefines the LO16 base register",
            )
        return (
            "definite-none",
            None,
            f"word {other_definitions[0]} redefines the LO16 base register "
            "on a reachable path",
        )
    return None


def _register_flow_pair(
    low: RelocationSite,
    low_index: int,
    sites: dict[int, RelocationSite],
    words: tuple[int, ...] | None,
) -> tuple[str, int | None, str]:
    """Find the unique ``lui`` reaching a supported LO16 use.

    A small CFG handles redefinitions that live on mutually exclusive branch
    paths.  If the CFG cannot model the window, the original straight-line
    scan remains the fallback.  An unconditional control transfer immediately
    before the LO is treated as its delay-slot predecessor.
    """
    cfg_result = _cfg_register_flow(low, low_index, sites, words)
    if cfg_result is not None:
        return cfg_result

    if words is None:
        return "unavailable", None, "instruction words were not supplied"
    if not 0 <= low_index < len(words):
        return "uncertain", None, "LO16 instruction lies outside the available words"
    source = _lo_source_register(words[low_index])
    if source is None:
        return "uncertain", None, "LO16 instruction form is not supported by the local analyzer"
    if source == 0:
        return "definite-none", None, "LO16 uses the constant zero register"

    for index in range(low_index - 1, -1, -1):
        word = words[index]
        control, unconditional, writes = _instruction_effect(word)
        if control:
            if index == low_index - 1 and unconditional:
                if writes is None:
                    return "uncertain", None, "delay-slot control transfer has unknown effects"
                if source in writes:
                    return "definite-none", None, "delay-slot link overwrites the source register"
                continue
            return "uncertain", None, "control flow crosses the HI16-to-LO16 scan"
        if writes is None:
            return "uncertain", None, f"unknown register effects at word {index}"
        if source not in writes:
            continue
        if (word >> 26) == 0x0F and index in sites and sites[index].type == R_MIPS_HI16:
            if index < low_index:
                return "match", index, "relocated LUI reaches the LO16 base register"
        return "definite-none", None, f"word {index} redefines the LO16 base register"
    return "uncertain", None, "no reaching definition inside the available straight-line range"


def _lo_source_register(word: int) -> int | None:
    """Return the register read as the base/source by supported I-type LO uses."""
    op = (word >> 26) & 0x3F
    if op in (0x08, 0x09):  # addi/addiu: signed immediate address arithmetic
        return (word >> 21) & 0x1F
    if 0x20 <= op <= 0x2F or 0x30 <= op <= 0x3F:  # loads, stores, cache/pref
        return (word >> 21) & 0x1F
    return None


def _instruction_effect(word: int) -> tuple[bool, bool, set[int] | None]:
    """Return (control transfer, unconditional, GPR destinations); None is unknown."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    funct = word & 0x3F
    if op == 0:
        if funct == 8:  # jr
            return True, True, set()
        if funct == 9:  # jalr
            return True, True, {rd} if rd else set()
        if funct in (0, 2, 3, 4, 6, 7, 10, 11, 16, 18, 32, 33, 34, 35, 36, 37, 38, 39, 42, 43):
            return False, False, {rd} if rd else set()
        if funct in (12, 13, 15, 17, 19, 24, 25, 26, 27):
            return False, False, set()
        return False, False, None
    if op in (2, 3):
        return True, True, ({31} if op == 3 else set())
    if op == 1 or 4 <= op <= 7 or 0x14 <= op <= 0x17:
        writes = {31} if op == 1 and rt in (16, 17, 18, 19) else set()
        return True, False, writes
    if 8 <= op <= 15:
        return False, False, {rt} if rt else set()
    if 0x20 <= op <= 0x27 or 0x30 <= op <= 0x37:
        return False, False, {rt} if rt else set()
    if op == 0x38:  # sc writes the success result back to rt
        return False, False, {rt} if rt else set()
    if 0x28 <= op <= 0x2F or 0x39 <= op <= 0x3F:
        return False, False, set()
    if op in (0x10, 0x11, 0x12, 0x13) and rs == 8:
        return True, False, set()
    return False, False, None


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

    Data resolvers are required to conclude equivalence for ``R_MIPS_32`` and
    paired ``R_MIPS_HI16``/``LO16`` references. When supplied, they answer with
    artifact-qualified identities: the two answers must name the *same* artifact
    before their locations may be compared at all. If either side cannot prove an
    identity, or the two answers come from different artifacts, the result is
    ``INCONCLUSIVE``; symbol-like spelling or equal numeric addends alone never
    establishes data identity.
    """
    original_words = decode_words(original, f"{name}: original")
    candidate_words = decode_words(candidate, f"{name}: candidate")
    original_map = relocation_sites(original_relocations, original_section_offset, len(original))
    candidate_map = relocation_sites(candidate_relocations, candidate_section_offset, len(candidate))
    original_pairs = pair_hi16_lo16(original_map.sites, original_words)
    candidate_pairs = pair_hi16_lo16(candidate_map.sites, candidate_words)

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

        if not all(
            site.addend_valid
            for site in (site_a_hi, site_a_lo, site_b_hi, site_b_lo)
        ):
            limitations.append(
                f"word {hi_index}: HI16/LO16 in-place addend is not fully recoverable "
                "from the file/zero-fill mapping"
            )
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

        limitations.append(
            f"word {hi_index}: HI16/LO16 cross-artifact data identity cannot be proven "
            "without data resolvers"
        )
        continue

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

        if not site_a.addend_valid or not site_b.addend_valid:
            limitations.append(
                f"word {index}: {site_a.type_name} in-place addend is not fully recoverable "
                "from the file/zero-fill mapping"
            )
            continue

        if site_a.type == R_MIPS_32:
            if original_data_resolver is None and candidate_data_resolver is None:
                limitations.append(
                    f"word {index}: R_MIPS_32 cross-artifact data identity cannot be proven "
                    "without data resolvers"
                )
                continue
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
