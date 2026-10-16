"""Tests for PSP import-table recovery and the identity of an imported call.

Everything here is synthetic: the fixtures reproduce the *shape* the PSPSDK
linker leaves behind (``.lib.stub`` entries pointing, through ``R_MIPS_32``
relocations, at ``.rodata.sceResident`` names, ``.rodata.sceNid`` NIDs and
``.sceStub.text`` trampolines), never a byte of the commercial module.
"""

from __future__ import annotations

import struct

import pytest

from seto import elf, imports, matching
from seto.binio import ParseError
from seto.elf import R_MIPS_26
from seto.matching import RelocationSite

from conftest import (
    LIB_STUB_SECTION,
    NID_SECTION,
    SHF_ALLOC,
    StubSpec,
    build_call_object,
    build_elf32,
    build_import_module,
    jal,
    jr,
    word,
)

#: The four NIDs the real ``func_00000244`` calls, reused as fixture data so the
#: synthetic cases mirror the module they exist to explain.
SCEHTTP_NIDS = (0x76D1363B, 0xD1C8945E, 0xF9D8EB63)
SCESSL_NIDS = (0x191CDEFF,)

#: ``.text`` holds four two-word calls, so the trampolines start at 0x20.
STUB_BASE = 0x20
GAP_TARGET = 0x9000


def _fixture() -> imports.ImportTable:
    """A module whose four calls reach stub 0, stub 3, a local address and a gap."""
    code = (
        word(jal(STUB_BASE)) + word(0) + word(jal(STUB_BASE + 24)) + word(0)
        + word(jal(0x18)) + word(0) + word(jal(GAP_TARGET)) + word(0)
    )
    specs = [StubSpec("sceHttp", SCEHTTP_NIDS), StubSpec("sceSsl", SCESSL_NIDS)]
    module = build_import_module(specs, code=code, calls=(0, 8, 16, 24))
    parsed = elf.parse(module.data, "libtest.prx")
    assert module.stub_addresses == (STUB_BASE, STUB_BASE + 8, STUB_BASE + 16, STUB_BASE + 24)
    return parsed, imports.build_import_table(parsed)


def _lib_stub_only(data: bytes) -> elf.ElfFile:
    """A PRX whose only import evidence is this raw ``.lib.stub`` blob."""
    return elf.parse(
        build_elf32(
            e_type=0xFFA0,
            sections=[
                {
                    "name": LIB_STUB_SECTION,
                    "type": 1,
                    "flags": SHF_ALLOC,
                    "addr": 0x100,
                    "size": len(data),
                    "data": data,
                }
            ],
        )
    )


def _calls(parsed, table, **kwargs):
    return imports.call_references(parsed, table, **kwargs)


# --------------------------------------------------------------------- table


def test_table_recovers_every_stub_of_every_library() -> None:
    _, table = _fixture()
    assert [item.library for item in table.tables] == ["sceHttp", "sceSsl"]
    assert [item.stub_count for item in table.tables] == [3, 1]
    assert table.limitations == ()
    assert len(table.imports) == 4
    expected = [
        ("sceHttp", 0x76D1363B, 0),
        ("sceHttp", 0xD1C8945E, 1),
        ("sceHttp", 0xF9D8EB63, 2),
        ("sceSsl", 0x191CDEFF, 0),
    ]
    for address, (library, nid, index) in zip(sorted(table.imports), expected):
        record = table.resolve(address)
        assert record is not None
        assert record.identity == (library, nid)
        assert record.stub_index == index
        assert record.stub_address == address
        assert record.table_offset == (0x00 if library == "sceHttp" else 0x14)


def test_ranges_tile_the_sections_the_counts_promise() -> None:
    _, table = _fixture()
    http, ssl = table.tables
    assert http.stub_end == ssl.stub_table
    assert http.nid_end == ssl.nid_table
    assert http.stub_end - http.stub_table == 8 * http.stub_count
    assert ssl.nid_end - ssl.nid_table == 4 * ssl.stub_count
    assert http.version == (1, 1)
    assert http.length_words == 5
    assert http.vstub_count == 0


def test_identical_nid_in_two_libraries_stays_distinct() -> None:
    nid = 0x12345678
    module = build_import_module([StubSpec("sceA", (nid,)), StubSpec("sceB", (nid,))])
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    first, second = module.stub_addresses
    assert table.resolve(first).identity == ("sceA", nid)
    assert table.resolve(second).identity == ("sceB", nid)
    assert table.resolve(first).identity != table.resolve(second).identity


def test_duplicate_nids_within_a_library_are_told_apart_by_index() -> None:
    module = build_import_module([StubSpec("sceHttp", (0xAAAA, 0xAAAA))])
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    first, second = module.stub_addresses
    assert table.resolve(first).stub_index == 0
    assert table.resolve(second).stub_index == 1
    assert table.resolve(first).identity == table.resolve(second).identity


def test_module_without_a_stub_table_declares_no_imports() -> None:
    module = build_import_module([])
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    assert table.tables == ()
    assert table.imports == {}
    assert table.limitations == ()


# ------------------------------------------------------- structural corruption


def test_a_section_shorter_than_one_entry_is_an_error() -> None:
    with pytest.raises(ParseError, match="truncated"):
        imports.build_import_table(_lib_stub_only(b"\x00" * 0x10))


def test_an_entry_shorter_than_the_minimum_is_an_error() -> None:
    data = bytearray(0x14)
    data[0x08] = 4
    with pytest.raises(ParseError, match="fewer than"):
        imports.build_import_table(_lib_stub_only(bytes(data)))


def test_an_entry_that_overruns_the_section_is_an_error() -> None:
    data = bytearray(0x14)
    data[0x08] = 8
    with pytest.raises(ParseError, match="overruns"):
        imports.build_import_table(_lib_stub_only(bytes(data)))


def test_a_pointer_outside_its_section_is_an_error() -> None:
    module = build_import_module([StubSpec("sceA", (1,), nid_table=0xDEADBEC)])
    with pytest.raises(ParseError, match="does not fit"):
        imports.build_import_table(elf.parse(module.data, "lib.prx"))


def test_a_missing_nid_section_is_an_error() -> None:
    module = build_import_module([StubSpec("sceA", (1,))], omit=(NID_SECTION,))
    with pytest.raises(ParseError, match="is absent"):
        imports.build_import_table(elf.parse(module.data, "lib.prx"))


def test_a_pointer_without_its_relocation_is_a_limitation() -> None:
    module = build_import_module([StubSpec("sceA", (1,), relocate=False)])
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    assert table.tables == ()
    assert table.imports == {}
    assert sum("no usable R_MIPS_32 relocation" in item for item in table.limitations) == 3


def test_a_stub_that_does_not_begin_with_the_trampoline_is_rejected() -> None:
    module = build_import_module([StubSpec("sceA", (1,))])
    section = elf.parse(module.data, "lib.prx").require_section(imports.STUB_TEXT_SECTION)
    data = bytearray(module.data)
    data[section.offset : section.offset + 4] = word(0)  # not a `jr $ra`
    table = imports.build_import_table(elf.parse(bytes(data), "lib.prx"))
    assert [item.stub_count for item in table.tables] == [1]
    assert table.imports == {}
    assert sum("is not a trampoline" in item for item in table.limitations) == 1


def test_a_trampoline_with_an_adulterated_delay_slot_is_rejected() -> None:
    """``jr $ra`` alone is not the trampoline the table declares.

    The pair the PSPSDK linker emits is ``jr $ra; nop``; the ``nop`` is the
    branch delay slot, so a stub whose second word is something else is not that
    trampoline and its address proves nothing.  The table itself is still
    recovered - only the stub is dropped, with the reason recorded.
    """
    module = build_import_module([StubSpec("sceA", (1,))])
    section = elf.parse(module.data, "lib.prx").require_section(imports.STUB_TEXT_SECTION)
    payload = bytearray(module.data)
    payload[section.offset + 4 : section.offset + 8] = word(0x24020001)  # addiu $v0, $zero, 1
    table = imports.build_import_table(elf.parse(bytes(payload), "lib.prx"))
    assert [item.stub_count for item in table.tables] == [1]
    assert table.imports == {}
    assert sum("not the 'jr $ra; nop' trampoline" in item for item in table.limitations) == 1


def test_a_stub_section_that_ends_mid_trampoline_is_an_error() -> None:
    """A truncated trampoline is structural damage, not a partial table."""
    module = build_import_module([StubSpec("sceA", (1,))])
    parsed = elf.parse(module.data, "lib.prx")
    section = parsed.require_section(imports.STUB_TEXT_SECTION)
    payload = bytearray(module.data)
    shoff = struct.unpack_from("<I", payload, 0x20)[0]
    struct.pack_into("<I", payload, shoff + section.index * 0x28 + 0x14, 4)
    with pytest.raises(ParseError, match="does not fit"):
        imports.build_import_table(elf.parse(bytes(payload), "lib.prx"))


def test_a_table_with_variable_stubs_keeps_its_own_stub_count() -> None:
    module = build_import_module([StubSpec("sceA", (7,), length_words=6)])
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    assert table.tables[0].length_words == 6
    assert table.tables[0].stub_count == 1
    assert table.resolve(module.stub_addresses[0]).nid == 7


def test_overlapping_stub_ranges_are_ambiguous() -> None:
    module = build_import_module(
        [
            StubSpec("sceA", (0x11111111,), stub_table=STUB_BASE),
            StubSpec("sceB", (0x22222222,), stub_table=STUB_BASE),
        ],
        code=b"\x00" * STUB_BASE,
    )
    table = imports.build_import_table(elf.parse(module.data, "lib.prx"))
    assert len(table.tables) == 2
    assert table.imports == {}
    assert table.resolve(STUB_BASE) is None
    assert any("overlaps" in item for item in table.limitations)


# ------------------------------------------------------------- call references


def test_call_references_classify_import_local_and_unknown() -> None:
    parsed, table = _fixture()
    references = _calls(parsed, table)
    assert [(item.address, item.kind) for item in references] == [
        (0x00, "import"),
        (0x08, "import"),
        (0x10, "local"),
        (0x18, "unknown"),
    ]
    assert references[0].imported.identity == ("sceHttp", 0x76D1363B)
    assert references[1].imported.identity == ("sceSsl", 0x191CDEFF)
    assert references[0].delay_slot == 0
    assert references[3].missing is not None
    assert "neither a trampoline" in references[3].missing
    assert references[3].imported is None


def test_the_function_range_filters_the_calls() -> None:
    parsed, table = _fixture()
    references = _calls(parsed, table, start=0x08, end=0x10)
    assert [item.address for item in references] == [0x08]


def test_a_relocated_instruction_that_is_not_a_jump_is_not_trusted() -> None:
    parsed = elf.parse(build_call_object(word(jr(31)), [(0, "func_00000020")]), "call.o")
    reference = _calls(parsed, imports.ImportTable(module="call.o"))[0]
    assert reference.kind == "unknown"
    assert "is not a label jump" in reference.missing


def test_a_call_relocation_of_an_unmodelled_type_is_reported() -> None:
    parsed = elf.parse(
        build_call_object(
            word(jal(0x20)) + word(0), [(0, "func_00000020")], relocation_type=14
        ),
        "call.o",
    )
    reference = _calls(parsed, imports.ImportTable(module="call.o"))[0]
    assert reference.kind == "unknown"
    assert "does not model" in reference.missing


def test_a_call_without_a_delay_slot_is_unresolved() -> None:
    parsed = elf.parse(build_call_object(word(jal(0x20)), [(0, "func_00000020")]), "call.o")
    reference = _calls(parsed, imports.ImportTable(module="call.o"))[0]
    assert reference.kind == "unknown"
    assert "no delay slot" in reference.missing


def test_a_relocation_past_the_end_of_the_section_is_unresolved() -> None:
    parsed = elf.parse(build_call_object(word(jr(31)), [(0x100, "func_00000000")]), "call.o")
    reference = _calls(parsed, imports.ImportTable(module="call.o"))[0]
    assert reference.kind == "unknown"
    assert "points outside" in reference.missing


# --------------------------------------------------------- resolve_call_target


def _site(*, addend: int = 0, symbol: str | None = None, type: int = R_MIPS_26) -> RelocationSite:
    return RelocationSite(word_index=0, type=type, addend=addend, symbol=symbol)


def test_resolve_call_target_from_an_address() -> None:
    _, table = _fixture()
    target = imports.resolve_call_target(_site(addend=STUB_BASE + 16), table)
    assert target is not None
    assert target.identity == ("sceHttp", 0xF9D8EB63)
    assert target.stub_address == STUB_BASE + 16


def test_resolve_call_target_from_a_symbol_name() -> None:
    _, table = _fixture()
    target = imports.resolve_call_target(_site(symbol="func_00000038"), table)
    assert target is not None
    assert target.identity == ("sceSsl", 0x191CDEFF)
    assert "symbol" in target.origin


def test_a_name_for_a_module_function_resolves_to_that_address() -> None:
    _, table = _fixture()
    # 0x04 is inside .text: another function of the module, not an import.
    target = imports.resolve_call_target(_site(symbol="func_00000004"), table)
    assert target is not None
    assert not target.is_import
    assert target.identity == (matching.SELF_LIBRARY, 0x04)
    assert target.describe() == "this module @ 0x4"


def test_a_name_that_proves_nothing_resolves_to_nothing() -> None:
    _, table = _fixture()
    assert imports.resolve_call_target(_site(symbol="not_a_function"), table) is None
    # Outside both the trampolines and the module's own code.
    assert imports.resolve_call_target(_site(symbol="func_00009000"), table) is None
    assert imports.resolve_call_target(_site(addend=GAP_TARGET), table) is None


def test_a_symbol_with_a_non_zero_addend_is_not_normalised() -> None:
    """``func_00000020+4`` is not ``func_00000020``.

    The addend is a displacement *on top of* the symbol, and nothing in the
    object demonstrates what that displacement means, so no identity may be
    claimed for it.  The zero-addend reference keeps resolving exactly as before.
    """
    _, table = _fixture()
    plain = imports.resolve_call_target(_site(symbol="func_00000020"), table)
    assert plain is not None
    assert plain.identity == ("sceHttp", 0x76D1363B)
    for addend in (4, 8, -4, -STUB_BASE):
        assert (
            imports.resolve_call_target(_site(symbol="func_00000020", addend=addend), table)
            is None
        )


def test_an_explicitly_resolved_symbol_with_a_non_zero_addend_is_not_normalised() -> None:
    """Explicit evidence for a name does not make a displacement provable."""
    _, table = _fixture()
    site = _site(symbol="sceHttp_DynSetSslCb", addend=4)
    assert (
        imports.resolve_call_target(
            site, table, candidate_symbols={"sceHttp_DynSetSslCb": STUB_BASE}
        )
        is None
    )


def test_candidate_symbols_override_names_that_do_not_follow_the_convention() -> None:
    _, table = _fixture()
    site = _site(symbol="sceHttp_DynSetSslCb")
    assert imports.resolve_call_target(site, table) is None
    target = imports.resolve_call_target(
        site, table, candidate_symbols={"sceHttp_DynSetSslCb": STUB_BASE + 24}
    )
    assert target is not None
    assert target.identity == ("sceSsl", 0x191CDEFF)


def test_a_relocation_of_another_type_is_not_a_call() -> None:
    _, table = _fixture()
    assert imports.resolve_call_target(_site(addend=STUB_BASE, type=2), table) is None


def test_a_module_without_imports_resolves_nothing() -> None:
    assert imports.resolve_call_target(_site(addend=STUB_BASE), None) is None
    assert (
        imports.resolve_call_target(_site(addend=STUB_BASE), imports.ImportTable(module="m")) is None
    )


# ------------------------------------------------------- comparison integration


def _resolver(table):
    return lambda site: imports.resolve_call_target(site, table)


def _compare(parsed, candidate_source: str, *, resolver=None):
    """Compare the first call of the fixture against a relocatable candidate."""
    candidate = elf.parse(candidate_source, "call.o")
    return matching.compare(
        parsed.section_data(".text")[:8],
        candidate.section_data(".text"),
        name="func_00000000",
        original_relocations=parsed.relocations_for(".text"),
        candidate_relocations=candidate.relocations_for(".text"),
        call_resolver=resolver,
    )


def test_equivalent_call_encodings_match() -> None:
    parsed, table = _fixture()
    # A compiler names the callee and leaves the in-place target at zero; the
    # linked module stores the trampoline address instead.
    candidate = build_call_object(word(jal(0)) + word(0), [(0, "func_00000020")])
    result = _compare(parsed, candidate, resolver=_resolver(table))
    assert result.status == matching.MATCHED
    assert result.evidence == matching.EVIDENCE_BINARY_RANGE
    assert not result.is_verified_decompilation
    assert result.limitations == ()


def test_a_call_to_a_different_import_does_not_match() -> None:
    parsed, table = _fixture()
    candidate = build_call_object(word(jal(0)) + word(0), [(0, "func_00000028")])
    result = _compare(parsed, candidate, resolver=_resolver(table))
    assert result.status == matching.NONMATCHING
    assert any("call target" in item.reason for item in result.differences)


def test_a_call_that_cannot_be_identified_is_inconclusive() -> None:
    parsed, table = _fixture()
    candidate = build_call_object(word(jal(0)) + word(0), [(0, "func_00009000")])
    result = _compare(parsed, candidate, resolver=_resolver(table))
    assert result.status == matching.INCONCLUSIVE
    assert any("no proven imported identity" in item for item in result.limitations)


def test_a_symbolic_offset_never_produces_a_false_match() -> None:
    """The linked module calls 0x20; a candidate calling ``0x20+4`` must not match.

    This is the whole point of refusing to normalise a non-zero symbolic addend:
    the two destinations differ, so the comparison has to stay inconclusive
    instead of reporting the symbol's own identity.
    """
    parsed, table = _fixture()
    candidate = build_call_object(word(jal(4)) + word(0), [(0, "func_00000020")])
    result = _compare(parsed, candidate, resolver=_resolver(table))
    assert result.status == matching.INCONCLUSIVE
    assert result.differences == ()
    assert any("no proven imported identity" in item for item in result.limitations)


def test_without_a_resolver_call_addends_are_compared_literally() -> None:
    parsed, _table = _fixture()
    candidate = build_call_object(word(jal(0)) + word(0), [(0, "func_00000020")])
    result = _compare(parsed, candidate)
    assert result.status == matching.NONMATCHING
    assert any("addend" in item.reason for item in result.differences)
