"""PSP import tables: the proven identity of an imported function call.

A PSP module reaches an imported function through a trampoline in
``.sceStub.text``.  The trampoline itself (``jr $ra; nop``) says nothing about
what it calls - the identity lives in the ``SceLibraryStubTable`` entries of
``.lib.stub``, each of which names a library and points at the array of NIDs and
the range of trampolines that array describes::

    .lib.stub entry -> libname   -> ".rodata.sceResident" string
                    -> nidtable  -> ".rodata.sceNid" NID array
                    -> stubtable -> ".sceStub.text" trampolines

Every step is validated against the real bytes: the section a pointer must land
in, alignment, the ``len`` field that walks the table, the ``R_MIPS_32``
relocation that makes a field a loader-fixed pointer, and the ranges the counts
imply.  A call target is therefore given a *proven* identity, and when the
evidence is incomplete the answer is "unknown" - never a guess.  Coarser
evidence, such as the provisional ``func_XXXXXXXX`` symbol name a reconstruction
declares its imports with, is only ever used to *name* a module address that the
module's own table then has to confirm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from seto.binio import ParseError
from seto.elf import (
    R_MIPS_26,
    R_MIPS_32,
    R_MIPS_X_J26,
    R_MIPS_X_JAL26,
    ET_REL,
    ElfFile,
    Relocation,
)
from seto.matching import SELF_LIBRARY, CallTarget, RelocationSite
from seto.mips import OP_J, OP_JAL, opcode, parse_function_name

#: The PSPSDK PRX section names this module reads.  They are the contract the
#: PSP linker emits; a module that deviates is reported, not guessed at.
LIB_STUB_SECTION = ".lib.stub"
STUB_TEXT_SECTION = ".sceStub.text"
NID_SECTION = ".rodata.sceNid"
RESIDENT_SECTION = ".rodata.sceResident"
#: The section the recovered calls are expected to live in.  Its range is what
#: separates a call to another function of the module from an unresolved target.
CODE_SECTION = ".text"

#: Relocation types whose in-place field is a jump target.  ``R_MIPS_26`` is the
#: type the PSP ABI uses for calls; the extended forms are recognised so that
#: they are *reported* as unmodelled instead of being silently skipped.
JUMP_RELOCATION_TYPES = (R_MIPS_26, R_MIPS_X_J26, R_MIPS_X_JAL26)
#: The one jump relocation this module models.
MODELLED_CALL_RELOCATION = R_MIPS_26

#: Every field of a ``SceLibraryStubTable`` is 4 bytes wide.
FIELD_SIZE = 4
#: A trampoline is two instructions, so its address advances by 8 bytes.
STUB_ENTRY_SIZE = 8
#: The whole trampoline, ``jr $ra; nop``, in memory order: ``jr $ra``
#: (``0x03E00008``) followed by its branch delay slot, a ``nop``.  Both
#: instructions are checked - a stub address that does not begin with ``jr $ra``
#: is not a trampoline, and one whose delay slot is not a ``nop`` is not the
#: trampoline this table claims either.  The pair is not an assumption: all 1268
#: trampolines of the reference module are exactly these eight bytes.
TRAMPOLINE = b"\x08\x00\xe0\x03\x00\x00\x00\x00"
#: ``jr $ra`` - the first instruction on its own.
TRAMPOLINE_HEAD = TRAMPOLINE[:FIELD_SIZE]
#: The delay slot of a trampoline, a ``nop``.
TRAMPOLINE_TAIL = TRAMPOLINE[FIELD_SIZE:]
#: ``libname``, version/attribute, len/vstubcount/stubcount, nidtable, stubtable.
MIN_TABLE_SIZE = 5 * FIELD_SIZE
#: The same, plus ``vstubtable`` (present when ``len`` is 6 words).
VSTUB_TABLE_SIZE = 6 * FIELD_SIZE


@dataclass(frozen=True)
class PspImport:
    """One imported function, recovered from a validated stub table."""

    library: str
    nid: int
    stub_address: int
    stub_index: int
    table_offset: int

    @property
    def identity(self) -> tuple[str, int]:
        return (self.library, self.nid)

    def summary(self) -> dict[str, object]:
        return {
            "library": self.library,
            "nid": f"0x{self.nid:08X}",
            "stub_address": f"0x{self.stub_address:x}",
            "stub_index": self.stub_index,
            "table_offset": f"0x{self.table_offset:x}",
        }


@dataclass(frozen=True)
class StubTable:
    """A validated ``SceLibraryStubTable`` and the ranges it declares."""

    library: str
    library_pointer: int
    version: tuple[int, int]
    attribute: int
    length_words: int
    stub_count: int
    vstub_count: int
    nid_table: int
    stub_table: int
    table_offset: int

    @property
    def stub_end(self) -> int:
        return self.stub_table + self.stub_count * STUB_ENTRY_SIZE

    @property
    def nid_end(self) -> int:
        return self.nid_table + self.stub_count * FIELD_SIZE

    def summary(self) -> dict[str, object]:
        return {
            "library": self.library,
            "library_pointer": f"0x{self.library_pointer:x}",
            "table_offset": f"0x{self.table_offset:x}",
            "length_words": self.length_words,
            "version": f"0x{self.version[0]:02x}{self.version[1]:02x}",
            "attribute": f"0x{self.attribute:04x}",
            "stub_count": self.stub_count,
            "vstub_count": self.vstub_count,
            "stub_range": [f"0x{self.stub_table:x}", f"0x{self.stub_end:x}"],
            "nid_range": [f"0x{self.nid_table:x}", f"0x{self.nid_end:x}"],
        }


@dataclass(frozen=True)
class ImportTable:
    """A module's validated ``stub address -> imported function`` mapping.

    Only unambiguous entries are kept: an address claimed by more than one
    library is dropped and recorded as a limitation, because an ambiguous
    identity is not an identity.

    ``code_range`` is the address range of the module's own code.  It is what
    tells a call to another function of the module apart from a call into the
    void: a target inside it is a module function, one outside it and not in the
    table is unresolved.
    """

    module: str
    tables: tuple[StubTable, ...] = ()
    imports: Mapping[int, PspImport] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    code_range: tuple[int, int] | None = None

    def resolve(self, address: int) -> PspImport | None:
        """The imported function reached through the trampoline at ``address``."""
        return self.imports.get(address)

    def contains_code(self, address: int) -> bool:
        """Whether ``address`` is inside the module's own code."""
        if self.code_range is None:
            return False
        start, end = self.code_range
        return start <= address < end

    def summary(self) -> dict[str, object]:
        return {
            "module": self.module,
            "table_count": len(self.tables),
            "stub_count": len(self.imports),
            "code_range": (
                None
                if self.code_range is None
                else [f"0x{self.code_range[0]:x}", f"0x{self.code_range[1]:x}"]
            ),
            "tables": [table.summary() for table in self.tables],
            "limitations": list(self.limitations),
        }


def _pointer_relocations(parsed: ElfFile) -> dict[int, Relocation]:
    """``.lib.stub`` 32-bit relocations indexed by their section offset.

    A duplicated offset is dropped: with two candidate relocations for one field
    there is no evidence for either, and silently keeping one would be a guess.
    """
    table: dict[int, Relocation] = {}
    ambiguous: set[int] = set()
    for relocation in parsed.relocations_for(LIB_STUB_SECTION):
        offset = relocation.section_offset
        if offset is None:
            continue
        if offset in table:
            del table[offset]
            ambiguous.add(offset)
            continue
        if offset in ambiguous:
            continue
        table[offset] = relocation
    return table


def _relocated_pointer(
    pointers: Mapping[int, Relocation],
    entry_offset: int,
    field_offset: int,
    label: str,
    field_name: str,
    limitations: list[str],
) -> int | None:
    """The address stored in a pointer field, or ``None`` with a limitation.

    A pointer field is only trusted when it carries an ``R_MIPS_32`` relocation:
    that relocation is what makes the stored word a loader-fixed address rather
    than ordinary data.
    """
    relocation = pointers.get(entry_offset + field_offset)
    if relocation is None:
        limitations.append(
            f"{label}: {field_name} at +0x{field_offset:x} carries no usable "
            "R_MIPS_32 relocation, so the pointer cannot be established"
        )
        return None
    if relocation.type != R_MIPS_32:
        limitations.append(
            f"{label}: {field_name} at +0x{field_offset:x} is relocated as "
            f"{relocation.type_name}, not R_MIPS_32, so it is not a pointer"
        )
        return None
    return relocation.addend


def _require_range(
    parsed: ElfFile,
    address: int,
    size: int,
    section_name: str,
    label: str,
    field_name: str,
) -> None:
    """Fail loudly when a declared range does not fit the section it names."""
    if size == 0:
        return
    section = parsed.section(section_name)
    if section is None:
        raise ParseError(
            f"{parsed.reader.name}: {label} {field_name} 0x{address:x} needs the "
            f"{section_name} section, which is absent"
        )
    if address % FIELD_SIZE:
        raise ParseError(
            f"{parsed.reader.name}: {label} {field_name} 0x{address:x} is not "
            f"{FIELD_SIZE}-byte aligned"
        )
    if address < section.addr or address + size > section.end:
        raise ParseError(
            f"{parsed.reader.name}: {label} {field_name} range "
            f"[0x{address:x}, 0x{address + size:x}) does not fit {section_name} "
            f"[0x{section.addr:x}, 0x{section.end:x})"
        )


def _resident_string(parsed: ElfFile, address: int) -> str | None:
    """The NUL-terminated library name at ``address``, or ``None``."""
    section = parsed.section(RESIDENT_SECTION)
    if section is None or not section.contains_address(address):
        return None
    data = parsed.section_data(section)
    offset = address - section.addr
    end = data.find(b"\x00", offset)
    if end < 0:
        return None
    return data[offset:end].decode("utf-8", "replace") or None


def build_import_table(parsed: ElfFile) -> ImportTable:
    """Recover every imported function a module declares.

    A module without a ``.lib.stub`` section declares no imports and yields an
    empty table.  A '.lib.stub' section that cannot be walked - a truncated
    entry, a length that does not fit, a pointer outside its section, a count
    that overruns it - is a structural break, not something to guess at, and
    raises :class:`~seto.binio.ParseError`.
    """
    module = Path(parsed.reader.name or "<elf>").name
    code = parsed.section(CODE_SECTION)
    code_range = (code.addr, code.end) if code is not None and code.size else None
    section = parsed.section(LIB_STUB_SECTION)
    if section is None or section.size == 0:
        return ImportTable(module=module, code_range=code_range)

    data = parsed.section_data(section)
    pointers = _pointer_relocations(parsed)
    limitations: list[str] = []
    tables: list[StubTable] = []
    candidates: list[PspImport] = []

    cursor = 0
    while cursor < len(data):
        remaining = len(data) - cursor
        label = f"{LIB_STUB_SECTION}+0x{cursor:x}"
        if remaining < MIN_TABLE_SIZE:
            raise ParseError(
                f"{parsed.reader.name}: {label} is truncated "
                f"({remaining} of {MIN_TABLE_SIZE} minimum bytes present)"
            )
        length_words = data[cursor + 0x08]
        entry_size = length_words * FIELD_SIZE
        if entry_size < MIN_TABLE_SIZE:
            raise ParseError(
                f"{parsed.reader.name}: {label} declares {length_words} words "
                f"(0x{entry_size:x} bytes), fewer than the {MIN_TABLE_SIZE}-byte minimum"
            )
        if entry_size > remaining:
            raise ParseError(
                f"{parsed.reader.name}: {label} declares {length_words} words "
                f"(0x{entry_size:x} bytes), which overruns the {remaining} bytes left"
            )

        version = (data[cursor + 0x04], data[cursor + 0x05])
        attribute = int.from_bytes(data[cursor + 0x06 : cursor + 0x08], "little")
        vstub_count = data[cursor + 0x09]
        stub_count = int.from_bytes(data[cursor + 0x0A : cursor + 0x0C], "little")

        library_pointer = _relocated_pointer(
            pointers, cursor, 0x00, label, "libname", limitations
        )
        nid_table = _relocated_pointer(pointers, cursor, 0x0C, label, "nidtable", limitations)
        stub_table = _relocated_pointer(
            pointers, cursor, 0x10, label, "stubtable", limitations
        )
        if vstub_count and entry_size >= VSTUB_TABLE_SIZE:
            _relocated_pointer(pointers, cursor, 0x14, label, "vstubtable", limitations)
        elif vstub_count:
            limitations.append(
                f"{label}: {vstub_count} variable stubs are declared but the entry has "
                "no vstubtable field, so they cannot be located"
            )

        if library_pointer is None or nid_table is None or stub_table is None:
            # Each unusable field has already been reported by name.
            cursor += entry_size
            continue

        library = _resident_string(parsed, library_pointer)
        if library is None:
            limitations.append(
                f"{label}: libname 0x{library_pointer:x} is not a NUL-terminated string "
                f"inside {RESIDENT_SECTION}"
            )
            cursor += entry_size
            continue

        _require_range(
            parsed,
            nid_table,
            stub_count * FIELD_SIZE,
            NID_SECTION,
            label,
            "nidtable",
        )
        _require_range(
            parsed,
            stub_table,
            stub_count * STUB_ENTRY_SIZE,
            STUB_TEXT_SECTION,
            label,
            "stubtable",
        )

        table = StubTable(
            library=library,
            library_pointer=library_pointer,
            version=version,
            attribute=attribute,
            length_words=length_words,
            stub_count=stub_count,
            vstub_count=vstub_count,
            nid_table=nid_table,
            stub_table=stub_table,
            table_offset=cursor,
        )
        for other in tables:
            if table.stub_table < other.stub_end and other.stub_table < table.stub_end:
                limitations.append(
                    f"{label}: the stub range of {library!r} overlaps that of "
                    f"{other.library!r}, so neither can be trusted"
                )
        tables.append(table)

        nid_section = parsed.require_section(NID_SECTION)
        nid_data = parsed.section_data(nid_section)
        nid_base = nid_table - nid_section.addr
        stub_section = parsed.require_section(STUB_TEXT_SECTION)
        stub_data = parsed.section_data(stub_section)
        stub_base = stub_table - stub_section.addr
        for index in range(stub_count):
            nid = int.from_bytes(
                nid_data[nid_base + index * FIELD_SIZE : nid_base + (index + 1) * FIELD_SIZE],
                "little",
            )
            stub_address = stub_table + index * STUB_ENTRY_SIZE
            begin = stub_base + index * STUB_ENTRY_SIZE
            entry = stub_data[begin : begin + STUB_ENTRY_SIZE]
            if entry[:FIELD_SIZE] != TRAMPOLINE_HEAD:
                # The table says this address is a trampoline; the bytes say it is
                # not.  Without a trampoline the address proves nothing.
                limitations.append(
                    f"{label}: stub 0x{stub_address:x} of {library!r} does not begin with "
                    "'jr $ra', so it is not a trampoline of this module"
                )
                continue
            if entry[FIELD_SIZE:] != TRAMPOLINE_TAIL:
                # The first instruction is right but the delay slot is not a
                # ``nop``, so these bytes are not the ``jr $ra; nop`` pair this
                # table declares.  Rejecting it is not arbitrary: it is what the
                # reference module's own trampolines look like, and a caller that
                # wanted another form would have to show one.
                limitations.append(
                    f"{label}: stub 0x{stub_address:x} of {library!r} is 'jr $ra' followed "
                    f"by 0x{int.from_bytes(entry[FIELD_SIZE:], 'little'):08x}, not the "
                    "'jr $ra; nop' trampoline the table declares"
                )
                continue
            candidates.append(
                PspImport(
                    library=library,
                    nid=nid,
                    stub_address=stub_address,
                    stub_index=index,
                    table_offset=cursor,
                )
            )
        cursor += entry_size

    grouped: dict[int, list[PspImport]] = {}
    for record in candidates:
        grouped.setdefault(record.stub_address, []).append(record)
    imports: dict[int, PspImport] = {}
    for address in sorted(grouped):
        records = grouped[address]
        if len(records) == 1:
            imports[address] = records[0]
            continue
        libraries = ", ".join(sorted({record.library for record in records}))
        limitations.append(
            f"stub 0x{address:x} is claimed by more than one library ({libraries}), "
            "so its identity is ambiguous"
        )

    return ImportTable(
        module=module,
        tables=tuple(tables),
        imports=imports,
        limitations=tuple(dict.fromkeys(limitations)),
        code_range=code_range,
    )


def resolve_call_target(
    relocation: Relocation | RelocationSite,
    module_imports: ImportTable | None,
    candidate_symbols: Mapping[str, int] | None = None,
) -> CallTarget | None:
    """Give a call reference the proven identity of what it reaches.

    Two encodings have to land on the same identity:

    * a *linked* reference stores the trampoline address in the instruction
      itself, so the identity comes from the relocation's own addend;
    * a *relocatable* reference stores it in the symbol name, because no address
      exists yet (``jal func_00002EDC`` with an in-place addend of 0).  The name
      only *names* an address: the module's own, validated import table has the
      final say, so a name that points at something that is not a trampoline of
      this module proves nothing.

    A symbolic reference whose addend is **not zero** is *not* the symbol: the
    addend is a displacement on top of it, so ``func_00002EDC+4`` is a different
    destination from ``func_00002EDC``.  Nothing in the object says what that
    displacement means - bytes, instructions, or a fragment of a split reference -
    so this function refuses to normalise it and returns ``None`` (inconclusive).
    Accepting it would silently claim that a reference to ``X+4`` reaches ``X``.

    A target the table does not claim but that lies inside the module's own code
    is another function of this module: its identity is the address itself
    (:data:`~seto.matching.SELF_LIBRARY`), which both encodings can agree on
    without either side claiming to know a name.  Anything else returns ``None``,
    and the caller has to treat the comparison as inconclusive.

    ``candidate_symbols`` maps a symbol name to the module address it stands for,
    letting a caller supply explicit evidence for names that do not follow the
    project's ``func_XXXXXXXX`` convention.  Returns ``None`` whenever the
    identity cannot be established.
    """
    if module_imports is None or relocation.type != MODELLED_CALL_RELOCATION:
        return None

    if relocation.symbol is not None:
        if relocation.addend:
            # ``symbol + addend`` is a distinct destination, and the meaning of
            # the displacement is not demonstrated by the object, so no identity
            # can be claimed.  This is what keeps ``func_00002EDC+4`` from being
            # reported as ``func_00002EDC``.
            return None
        address = None if candidate_symbols is None else candidate_symbols.get(relocation.symbol)
        if address is None:
            address = parse_function_name(relocation.symbol)
        if address is None:
            return None
        origin = f"symbol {relocation.symbol!r} -> 0x{address:x}"
    else:
        address = relocation.addend
        origin = f"target 0x{address:x}"

    found = module_imports.resolve(address)
    if found is not None:
        return CallTarget(
            library=found.library,
            nid=found.nid,
            stub_address=found.stub_address,
            origin=origin,
        )
    if module_imports.contains_code(address):
        return CallTarget(
            library=SELF_LIBRARY,
            nid=address,
            stub_address=address,
            origin=origin,
        )
    return None


def symbol_addresses(parsed: ElfFile) -> dict[str, int]:
    """Name -> module address for the defined symbols of a *linked* ELF.

    ``ET_REL`` values are offsets within a section, not addresses, so a
    relocatable object contributes nothing here: its imports are named, and the
    documented ``func_XXXXXXXX`` convention is what names maps them to addresses.
    """
    if parsed.header.e_type == ET_REL:
        return {}
    return {
        symbol.name: symbol.value
        for symbol in parsed.symbols
        if symbol.name and symbol.is_defined
    }


@dataclass(frozen=True)
class CallReference:
    """One call site of a code section and what it provably reaches."""

    address: int
    target: int
    relocation_type: str
    kind: str
    delay_slot: int | None = None
    imported: PspImport | None = None
    missing: str | None = None

    def summary(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "address": f"0x{self.address:x}",
            "target": f"0x{self.target:x}",
            "relocation": self.relocation_type,
            "kind": self.kind,
            "delay_slot": None if self.delay_slot is None else f"0x{self.delay_slot:08x}",
        }
        if self.imported is not None:
            payload["import"] = self.imported.summary()
        if self.missing is not None:
            payload["missing"] = self.missing
        return payload

    def line(self) -> str:
        slot = "" if self.delay_slot is None else f"+4:{self.delay_slot:08x} "
        head = (
            f"0x{self.address:06x}  {self.relocation_type:<10} {slot}-> 0x{self.target:06x}"
        )
        if self.imported is not None:
            return (
                f"{head}  {self.imported.library}/0x{self.imported.nid:08X} "
                f"(stub #{self.imported.stub_index})"
            )
        if self.kind == "local":
            return f"{head}  function of this module"
        return f"{head}  UNRESOLVED: {self.missing}"


def call_references(
    parsed: ElfFile,
    table: ImportTable,
    *,
    section: str = ".text",
    start: int | None = None,
    end: int | None = None,
) -> tuple[CallReference, ...]:
    """Resolve the call sites of a code section.

    Only relocations of :data:`JUMP_RELOCATION_TYPES` are considered, and each
    one has to survive four checks before its destination is identified: the
    relocation must land inside the section, the instruction it describes must
    really be a label jump, the relocation type must be the modelled
    :data:`MODELLED_CALL_RELOCATION`, and the call must have a delay slot inside
    the section.  A ``jal`` carries no register operands, so the opcode is the
    whole instruction-side evidence available.  A target that is neither a
    trampoline of the validated import table nor a function of the same section is
    reported as unresolved, with the exact missing step.

    When ``start``/``end`` are given only the calls inside that address range are
    reported (one function).
    """
    code_section = parsed.require_section(section)
    code = parsed.section_data(code_section)
    references: list[CallReference] = []

    def unresolved(address: int, target: int, relocation_type: str, reason: str) -> None:
        references.append(
            CallReference(
                address=address,
                target=target,
                relocation_type=relocation_type,
                kind="unknown",
                missing=reason,
            )
        )

    for relocation in parsed.relocations_for(section):
        if relocation.type not in JUMP_RELOCATION_TYPES or relocation.section_offset is None:
            continue
        offset = relocation.section_offset
        address = code_section.addr + offset
        if start is not None and address < start:
            continue
        if end is not None and address >= end:
            continue

        if offset < 0 or offset + FIELD_SIZE > len(code):
            unresolved(
                address,
                relocation.addend,
                relocation.type_name,
                f"the relocation at 0x{address:x} points outside {section}",
            )
            continue

        word = int.from_bytes(code[offset : offset + FIELD_SIZE], "little")
        operation = opcode(word)
        if operation not in (OP_J, OP_JAL):
            unresolved(
                address,
                relocation.addend,
                relocation.type_name,
                f"the instruction at 0x{address:x} has opcode {operation}, which is not a label jump",
            )
            continue
        if relocation.type != MODELLED_CALL_RELOCATION:
            unresolved(
                address,
                relocation.addend,
                relocation.type_name,
                f"the relocation at 0x{address:x} uses {relocation.type_name}, "
                "which this tool does not model",
            )
            continue
        if offset + 2 * FIELD_SIZE > len(code):
            unresolved(
                address,
                relocation.addend,
                relocation.type_name,
                f"the call at 0x{address:x} has no delay slot inside {section}",
            )
            continue
        delay_slot = int.from_bytes(code[offset + 4 : offset + 8], "little")

        target = relocation.addend
        imported = table.resolve(target)
        if imported is not None:
            references.append(
                CallReference(
                    address=address,
                    target=target,
                    relocation_type=relocation.type_name,
                    kind="import",
                    delay_slot=delay_slot,
                    imported=imported,
                )
            )
            continue
        if code_section.contains_address(target):
            references.append(
                CallReference(
                    address=address,
                    target=target,
                    relocation_type=relocation.type_name,
                    kind="local",
                    delay_slot=delay_slot,
                )
            )
            continue
        unresolved(
            address,
            target,
            relocation.type_name,
            f"0x{target:x} is neither a trampoline known to {LIB_STUB_SECTION} "
            f"nor inside {section}",
        )
    return tuple(references)


__all__ = [
    "CODE_SECTION",
    "JUMP_RELOCATION_TYPES",
    "LIB_STUB_SECTION",
    "MODELLED_CALL_RELOCATION",
    "NID_SECTION",
    "RESIDENT_SECTION",
    "STUB_TEXT_SECTION",
    "CallReference",
    "ImportTable",
    "PspImport",
    "StubTable",
    "build_import_table",
    "call_references",
    "resolve_call_target",
    "symbol_addresses",
]
