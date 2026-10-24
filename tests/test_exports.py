"""Synthetic tests for relocation-verified PSP library exports."""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pytest

from seto import elf
from seto.exports import collect_exports

from conftest import SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, build_elf32

SEGMENT_VADDR = 0x1000
LOAD_OFFSET = elf.ELF_HEADER_SIZE + elf.PROGRAM_HEADER_SIZE
TEXT_ADDRESS = SEGMENT_VADDR
TEXT_SIZE = 0x40
LIB_ENT_ADDRESS = SEGMENT_VADDR + 0x80
RESIDENT_ADDRESS = SEGMENT_VADDR + 0x1000
LIBRARY = "libehsys"
NID_A = 0x11223344
NID_B = 0x55667788


@dataclass(frozen=True)
class ExportSpec:
    library: str | None
    nids: tuple[int, ...]
    addresses: tuple[int, ...]
    relocate_name: bool = True
    relocate_table: bool = True
    missing_pointer_slots: tuple[int, ...] = ()
    duplicate_pointer_slots: tuple[int, ...] = ()
    pointer_types: tuple[tuple[int, int], ...] = ()
    pointer_segments: tuple[tuple[int, int], ...] = ()
    pointer_relative_segments: tuple[tuple[int, int], ...] = ()
    table_delta: int = 0
    function_count: int | None = None
    entry_words: int = 4
    terminate_name: bool = True


def _psp_rel(
    site: int,
    *,
    segment: int = 0,
    relative: int = 0,
    rel_type: int = elf.R_MIPS_32,
) -> bytes:
    info = (relative << 16) | (segment << 8) | rel_type
    return struct.pack("<II", site - SEGMENT_VADDR, info)


def _export_prx(
    specs: tuple[ExportSpec, ...],
    *,
    e_type: int = elf.ET_MIPS_PSP_PRX,
    truncate_lib_ent: int | None = None,
    omit_lib_ent: bool = False,
) -> elf.ElfFile:
    """Build a tiny PSP PRX with byte-built SHT_PSPREL pointer evidence."""
    resident = bytearray()
    tables: list[tuple[int, int]] = []
    for spec in specs:
        assert len(spec.nids) == len(spec.addresses)
        resident.extend(b"\x00" * (-len(resident) % 4))
        table_address = RESIDENT_ADDRESS + len(resident)
        resident.extend(b"".join(struct.pack("<I", nid) for nid in spec.nids))
        pointer_table = table_address + len(spec.nids) * 4
        resident.extend(
            b"".join(
                struct.pack("<I", address - SEGMENT_VADDR)
                for address in spec.addresses
            )
        )
        tables.append((table_address, pointer_table))

    names: list[int] = []
    for index, spec in enumerate(specs):
        if spec.library is None:
            names.append(0)
            continue
        resident.extend(b"\x00" * (-len(resident) % 4))
        names.append(RESIDENT_ADDRESS + len(resident))
        resident.extend(spec.library.encode("ascii"))
        if spec.terminate_name:
            resident.append(0)
            resident.extend(b"\x00" * (-len(resident) % 4))
        elif index != len(specs) - 1:
            raise ValueError("an unterminated fixture name must be last")

    lib_ent = bytearray()
    lib_ent_relocations: list[bytes] = []
    resident_relocations: list[bytes] = []
    for entry_index, spec in enumerate(specs):
        name_pointer = names[entry_index]
        table_address, _pointer_table = tables[entry_index]
        table_pointer = table_address + spec.table_delta
        count = len(spec.nids) if spec.function_count is None else spec.function_count
        header = struct.pack(
            "<IHHBBH",
            name_pointer - SEGMENT_VADDR if name_pointer else 0,
            0x48,
            0x0001,
            spec.entry_words,
            0,
            count,
        )
        if spec.entry_words >= 4:
            record = header + struct.pack("<I", table_pointer - SEGMENT_VADDR)
            record += b"\x00" * ((spec.entry_words - 4) * 4)
        elif spec.entry_words == 3:
            record = header
        else:
            record = header[: spec.entry_words * 4]

        entry_offset = len(lib_ent)
        lib_ent.extend(record)
        entry_address = LIB_ENT_ADDRESS + entry_offset
        if name_pointer and spec.relocate_name and len(record) >= 4:
            lib_ent_relocations.append(_psp_rel(entry_address))
        if spec.entry_words >= 4 and spec.relocate_table:
            lib_ent_relocations.append(_psp_rel(entry_address + 12))

        pointer_table = table_address + len(spec.nids) * 4
        type_by_slot = dict(spec.pointer_types)
        segment_by_slot = dict(spec.pointer_segments)
        relative_by_slot = dict(spec.pointer_relative_segments)
        for slot_index in range(len(spec.addresses)):
            if slot_index in spec.missing_pointer_slots:
                continue
            site = pointer_table + slot_index * 4
            args = {
                "segment": segment_by_slot.get(slot_index, 0),
                "relative": relative_by_slot.get(slot_index, 0),
                "rel_type": type_by_slot.get(slot_index, elf.R_MIPS_32),
            }
            resident_relocations.append(_psp_rel(site, **args))
            if slot_index in spec.duplicate_pointer_slots:
                resident_relocations.append(_psp_rel(site, **args))

    if truncate_lib_ent is not None:
        lib_ent = lib_ent[:truncate_lib_ent]

    sections = [
        {
            "name": ".text",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC | SHF_EXECINSTR,
            "addr": TEXT_ADDRESS,
            "offset": LOAD_OFFSET,
            "size": TEXT_SIZE,
            "data": b"\x00" * TEXT_SIZE,
            "align": 16,
        },
        {
            "name": ".lib.ent",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC,
            "addr": LIB_ENT_ADDRESS,
            "offset": LOAD_OFFSET + LIB_ENT_ADDRESS - SEGMENT_VADDR,
            "size": len(lib_ent),
            "data": bytes(lib_ent),
            "align": 4,
        },
        {
            "name": ".rodata.sceResident",
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC,
            "addr": RESIDENT_ADDRESS,
            "offset": LOAD_OFFSET + RESIDENT_ADDRESS - SEGMENT_VADDR,
            "size": len(resident),
            "data": bytes(resident),
            "align": 4,
        },
    ]
    if lib_ent_relocations and not omit_lib_ent:
        sections.append(
            {
                "name": ".rel.lib.ent",
                "type": elf.SHT_MIPS_PSPREL,
                "flags": 0,
                "addr": 0,
                "data": b"".join(sorted(lib_ent_relocations)),
                "entsize": 8,
            }
        )
    if resident_relocations:
        sections.append(
            {
                "name": ".rel.rodata.sceResident",
                "type": elf.SHT_MIPS_PSPREL,
                "flags": 0,
                "addr": 0,
                "data": b"".join(sorted(resident_relocations)),
                "entsize": 8,
            }
        )
    if omit_lib_ent:
        sections = [section for section in sections if section["name"] != ".lib.ent"]

    module_end = RESIDENT_ADDRESS - SEGMENT_VADDR + len(resident)
    return elf.parse(
        build_elf32(
            e_type=e_type,
            program_headers=[
                {
                    "type": elf.PT_LOAD,
                    "offset": LOAD_OFFSET,
                    "vaddr": SEGMENT_VADDR,
                    "paddr": SEGMENT_VADDR,
                    "filesz": module_end,
                    "memsz": module_end,
                    "flags": 7,
                    "align": 16,
                }
            ],
            sections=sections,
        ),
        "synthetic-exports.prx",
    )


def test_collects_verified_exports_and_resolves_prx_relative_base() -> None:
    module = _export_prx(
        (ExportSpec(LIBRARY, (NID_A, NID_B), (TEXT_ADDRESS + 4, TEXT_ADDRESS + 8)),)
    )

    collection = collect_exports(module, LIBRARY)

    assert collection.limitations == ()
    assert [(item.nid, item.address, item.slot_index) for item in collection.exports] == [
        (NID_A, TEXT_ADDRESS + 4, 0),
        (NID_B, TEXT_ADDRESS + 8, 1),
    ]
    assert collection.exports[0].pointer_site == RESIDENT_ADDRESS + 8
    assert collection.exports[0].pointer_relocation.format == "PSP"
    assert collection.exports[0].pointer_relocation.addend == 4
    assert collection.nid_groups == ()
    assert collection.aliases == ()


def test_missing_function_pointer_relocation_limits_only_that_slot() -> None:
    module = _export_prx(
        (
            ExportSpec(
                LIBRARY,
                (NID_A, NID_B),
                (TEXT_ADDRESS + 4, TEXT_ADDRESS + 8),
                missing_pointer_slots=(1,),
            ),
        )
    )

    collection = collect_exports(module, LIBRARY)

    assert [(item.nid, item.slot_index) for item in collection.exports] == [(NID_A, 0)]
    assert len(collection.limitations) == 1
    assert collection.limitations[0].slot_index == 1
    assert collection.limitations[0].nid == NID_B
    assert "R_MIPS_32" in collection.limitations[0].reason


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        (
            ExportSpec(
                LIBRARY,
                (NID_A,),
                (TEXT_ADDRESS + 4,),
                duplicate_pointer_slots=(0,),
            ),
            "duplicate",
        ),
        (
            ExportSpec(
                LIBRARY,
                (NID_A,),
                (TEXT_ADDRESS + 4,),
                pointer_types=((0, elf.R_MIPS_26),),
            ),
            "R_MIPS_32",
        ),
        (
            ExportSpec(
                LIBRARY,
                (NID_A,),
                (TEXT_ADDRESS + 4,),
                pointer_relative_segments=((0, 1),),
            ),
            "relative segment",
        ),
        (ExportSpec(LIBRARY, (NID_A,), (RESIDENT_ADDRESS + 0x100,),), "executable .text"),
    ],
)
def test_unusable_function_pointer_is_a_limitation(spec: ExportSpec, reason: str) -> None:
    collection = collect_exports(_export_prx((spec,)), LIBRARY)

    assert collection.exports == ()
    assert any(reason in limitation.reason for limitation in collection.limitations)


@pytest.mark.parametrize("field", ("name", "table"))
def test_entry_pointer_fields_require_r_mips_32_relocations(field: str) -> None:
    spec = ExportSpec(
        LIBRARY,
        (NID_A,),
        (TEXT_ADDRESS + 4,),
        relocate_name=field != "name",
        relocate_table=field != "table",
    )

    collection = collect_exports(_export_prx((spec,)), LIBRARY)

    assert collection.exports == ()
    assert any("R_MIPS_32" in limitation.reason for limitation in collection.limitations)


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,), table_delta=1), "aligned"),
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,), function_count=0xFFFF), "exceeds"),
    ],
)
def test_table_alignment_and_count_are_bounded(spec: ExportSpec, reason: str) -> None:
    collection = collect_exports(_export_prx((spec,)), LIBRARY)

    assert collection.exports == ()
    assert any(reason in limitation.reason for limitation in collection.limitations)


@pytest.mark.parametrize(
    ("spec", "truncate", "reason"),
    [
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,), entry_words=3), None, "four words"),
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,)), 10, "truncated"),
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,), terminate_name=False), None, "NUL"),
        (ExportSpec(LIBRARY, (NID_A,), (TEXT_ADDRESS + 4,), entry_words=5), None, "unsupported"),
    ],
)
def test_malformed_entries_and_names_are_reported(
    spec: ExportSpec, truncate: int | None, reason: str
) -> None:
    collection = collect_exports(
        _export_prx((spec,), truncate_lib_ent=truncate), LIBRARY
    )

    assert collection.exports == ()
    assert any(reason.lower() in limitation.reason.lower() for limitation in collection.limitations)


def test_valid_entries_survive_another_table_slot_limitation() -> None:
    module = _export_prx(
        (
            ExportSpec(
                LIBRARY,
                (NID_A,),
                (TEXT_ADDRESS + 4,),
                missing_pointer_slots=(0,),
            ),
            ExportSpec(LIBRARY, (NID_B,), (TEXT_ADDRESS + 8,)),
        )
    )

    collection = collect_exports(module, LIBRARY)

    assert [(item.nid, item.entry_index, item.slot_index) for item in collection.exports] == [
        (NID_B, 1, 0)
    ]
    assert len(collection.limitations) == 1
    assert collection.limitations[0].entry_index == 0


def test_duplicate_nids_conflicts_and_distinct_nid_aliases_keep_slot_identity() -> None:
    module = _export_prx(
        (
            ExportSpec(
                LIBRARY,
                (NID_A, NID_A, NID_A, NID_B),
                (TEXT_ADDRESS + 4, TEXT_ADDRESS + 4, TEXT_ADDRESS + 8, TEXT_ADDRESS + 4),
            ),
        )
    )

    collection = collect_exports(module, LIBRARY)

    assert len(collection.exports) == 4
    assert [item.slot_index for item in collection.exports] == [0, 1, 2, 3]
    group = next(item for item in collection.nid_groups if item.nid == NID_A)
    assert group.addresses == (TEXT_ADDRESS + 4, TEXT_ADDRESS + 8)
    assert group.ambiguous
    alias = next(item for item in collection.aliases if item.address == TEXT_ADDRESS + 4)
    assert [(item.nid, item.slot_index) for item in alias.exports] == [
        (NID_A, 0),
        (NID_A, 1),
        (NID_B, 3),
    ]


def test_missing_export_section_is_a_limitation() -> None:
    module = _export_prx((), omit_lib_ent=True)

    collection = collect_exports(module, LIBRARY)

    assert collection.exports == ()
    assert collection.limitations
    assert "lib.ent" in collection.limitations[0].reason


def test_non_prx_module_does_not_produce_export_addresses() -> None:
    module = _export_prx((), e_type=elf.ET_REL)

    collection = collect_exports(module, LIBRARY)

    assert collection.exports == ()
    assert len(collection.limitations) == 1
    assert "ET_MIPS_PSP_PRX" in collection.limitations[0].reason
