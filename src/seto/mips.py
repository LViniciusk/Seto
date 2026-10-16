"""Minimal MIPS32 (Allegrex) helpers: instruction fields and function discovery.

Seto deliberately does **not** ship a full disassembler.  Instruction *fields*
and jump/call targets are all that the matching pipeline needs to be
relocation-aware, and everything else is delegated to mature external tools
(Ghidra + ghidra-allegrex, m2c, rabbitizer).  Optional human-readable listings
use ``capstone`` when it is installed.
"""

from __future__ import annotations

from dataclasses import dataclass

from seto.binio import ParseError

OP_SPECIAL = 0
OP_J = 2
OP_JAL = 3

FUNCT_JR = 8
FUNCT_JALR = 9

REG_RA = 31

SHF_EXECINSTR = 0x4


def opcode(word: int) -> int:
    return (word >> 26) & 0x3F


def rs(word: int) -> int:
    return (word >> 21) & 0x1F


def rt(word: int) -> int:
    return (word >> 16) & 0x1F


def rd(word: int) -> int:
    return (word >> 11) & 0x1F


def sa(word: int) -> int:
    return (word >> 6) & 0x1F


def funct(word: int) -> int:
    return word & 0x3F


def immediate(word: int) -> int:
    return word & 0xFFFF


def signed_immediate(word: int) -> int:
    value = immediate(word)
    return value - 0x10000 if value & 0x8000 else value


def target_field(word: int) -> int:
    return word & 0x03FFFFFF


def jump_target(word: int, pc: int) -> int:
    """Absolute target of a ``j``/``jal`` instruction located at ``pc``."""
    return ((pc + 4) & 0xF0000000) | (target_field(word) << 2)


def is_jal(word: int) -> bool:
    return opcode(word) == OP_JAL


def is_jr(word: int) -> bool:
    return opcode(word) == OP_SPECIAL and funct(word) == FUNCT_JR


def is_return(word: int) -> bool:
    """``jr $ra`` - the canonical function terminator on this ABI."""
    return is_jr(word) and rs(word) == REG_RA


def decode_words(code: bytes, name: str = "<code>") -> tuple[int, ...]:
    if len(code) % 4:
        raise ParseError(f"{name}: code length {len(code)} is not a multiple of 4")
    return tuple(int.from_bytes(code[i : i + 4], "little") for i in range(0, len(code), 4))


def encode_words(words: tuple[int, ...]) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


@dataclass(frozen=True)
class Function:
    """A function range discovered inside a code section."""

    start: int
    end: int
    calls: tuple[int, ...] = ()

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def address(self) -> int:
        return self.start

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def name(self) -> str:
        return function_name(self.start)

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name(),
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "calls": list(self.calls),
        }


def function_name(address: int) -> str:
    """Provisional, address-derived name (the reference projects' convention)."""
    return f"func_{address:08X}"


def parse_function_name(name: str) -> int | None:
    """Inverse of :func:`function_name`: ``"func_00002EDC"`` -> ``0x2EDC``.

    Returns ``None`` for anything that is not an address-derived provisional
    name, so a caller can never mistake a real symbol for one.  The name is only
    a way of *naming* an address; it proves nothing by itself.
    """
    prefix = "func_"
    if not name.startswith(prefix):
        return None
    digits = name[len(prefix) :]
    if len(digits) != 8 or any(char not in "0123456789abcdefABCDEF" for char in digits):
        return None
    return int(digits, 16)


def find_functions(code: bytes, base: int = 0, name: str = "<code>") -> tuple[Function, ...]:
    """Discover function boundaries in a code section.

    Boundaries come from evidence that is stable across the ABI rather than
    from patterns that can appear mid-function:

    * the start of the section;
    * every ``jal`` target that lands inside the section (direct calls);
    * the instruction after a ``jr $ra`` delay slot (returns).

    Indirect jumps (``jr $v0`` jump tables) are *not* treated as boundaries,
    because they target intra-function labels.
    """
    words = decode_words(code, name)
    size = len(code)
    if size == 0:
        return ()

    starts: set[int] = {0}
    for index, word in enumerate(words):
        pc = base + index * 4
        if is_jal(word):
            target = jump_target(word, pc)
            relative = target - base
            if 0 <= relative < size and target % 4 == 0:
                starts.add(relative)
        if is_return(word):
            next_offset = index * 4 + 8
            if next_offset < size:
                starts.add(next_offset)

    ordered = sorted(starts)
    functions: list[Function] = []
    for position, start in enumerate(ordered):
        end = ordered[position + 1] if position + 1 < len(ordered) else size
        calls: list[int] = []
        for word_index in range(start // 4, end // 4):
            word = words[word_index]
            if is_jal(word):
                calls.append(jump_target(word, base + word_index * 4))
        functions.append(
            Function(start=base + start, end=base + end, calls=tuple(calls))
        )
    return tuple(functions)


def disassemble(code: bytes, base: int = 0, count: int | None = None) -> tuple[str, ...]:
    """Return human-readable instructions, or raise ``RuntimeError`` if unavailable.

    Uses capstone (optional dependency ``seto[disasm]``).  Disassembly is only
    ever used for reports and documentation; it is never a matching input.
    """
    try:
        from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "capstone is not installed; install seto[disasm] to enable listings"
        ) from exc

    engine = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    lines: list[str] = []
    for instruction in engine.disasm(code, base):
        if count is not None and len(lines) >= count:
            break
        lines.append(
            f"{instruction.address:08x}: {instruction.bytes.hex(' '):<11} "
            f"{instruction.mnemonic:<10} {instruction.op_str}".rstrip()
        )
    return tuple(lines)
