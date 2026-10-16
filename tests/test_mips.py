"""Tests for the minimal MIPS32 instruction helpers and function discovery."""

from __future__ import annotations

import pytest

from seto.binio import ParseError
from seto.mips import (
    Function,
    decode_words,
    encode_words,
    find_functions,
    function_name,
    funct,
    immediate,
    is_jal,
    is_jr,
    is_return,
    jump_target,
    opcode,
    parse_function_name,
    rd,
    rs,
    rt,
    sa,
    signed_immediate,
    target_field,
)

from conftest import jal, jr, word

NOP = 0x00000000


# --------------------------------------------------------------------- fields


def test_opcode_field() -> None:
    assert opcode(0x0C000000) == 0x03  # jal
    assert opcode(0x00000008) == 0x00  # special


def test_register_fields() -> None:
    value = (3 << 21) | (4 << 16) | (5 << 11) | (6 << 6)
    assert rs(value) == 3
    assert rt(value) == 4
    assert rd(value) == 5
    assert sa(value) == 6


def test_funct_field() -> None:
    assert funct(0x00000008) == 0x08
    assert funct(0x00000009) == 0x09


def test_immediate_is_unsigned_and_signed_immediate_sign_extends() -> None:
    assert immediate(0x2484FFFE) == 0xFFFE
    assert signed_immediate(0x2484FFFE) == -2
    assert signed_immediate(0x24840002) == 2
    assert signed_immediate(0x24848000) == -0x8000


def test_target_field_masks_low_26_bits() -> None:
    assert target_field(0x0FFFFFFF) == 0x03FFFFFF


def test_jump_target_keeps_high_pc_bits() -> None:
    inst = jal(0x00401234)
    assert jump_target(inst, 0x00400000) == 0x00401234
    # Only the top nibble of PC+4 is preserved; the rest comes from the field.
    assert jump_target(jal(0x00000040), 0x8F000000) == 0x80000040


# ------------------------------------------------------------------- predicates


def test_is_jal_only_matches_jal() -> None:
    assert is_jal(jal(0x40))
    assert not is_jal(0x00000008)


def test_is_jr_and_is_return() -> None:
    assert is_jr(jr(31))
    assert is_jr(jr(2))
    assert not is_jr(jal(0x40))
    assert is_return(jr(31))
    assert not is_return(jr(2))


# ------------------------------------------------------------------ word codecs


def test_decode_words_round_trips_with_encode_words() -> None:
    words = (0x00000000, 0x0C000010, 0xFFFFFFFF)
    assert decode_words(encode_words(words)) == words


def test_decode_words_rejects_misaligned_length() -> None:
    with pytest.raises(ParseError, match="multiple of 4"):
        decode_words(b"\x00\x00\x00")


# ---------------------------------------------------------------- Function type


def test_function_properties() -> None:
    function = Function(start=0x10, end=0x20, calls=(0x100,))
    assert function.size == 0x10
    assert function.address == 0x10
    assert function.contains(0x10)
    assert function.contains(0x1F)
    assert not function.contains(0x20)
    assert not function.contains(0x0F)
    assert function.name() == "func_00000010"
    assert function.summary() == {
        "name": "func_00000010",
        "start": 0x10,
        "end": 0x20,
        "size": 0x10,
        "calls": [0x100],
    }


def test_function_name_is_address_derived() -> None:
    assert function_name(0x244) == "func_00000244"
    assert function_name(0xFFFFFFF0) == "func_FFFFFFF0"


def test_parse_function_name_is_the_inverse_of_function_name() -> None:
    for address in (0x0, 0x244, 0x2EDC, 0xFFFFFFF0):
        assert parse_function_name(function_name(address)) == address


def test_parse_function_name_rejects_anything_else() -> None:
    for name in (
        "sceHttp_DynSetSslCb",
        "func_244",
        "func_000000244",
        "func_00002ED",
        "func_0000ZZZZ",
        "Func_00002EDC",
        "",
    ):
        assert parse_function_name(name) is None


# ------------------------------------------------------------- find_functions


def test_find_functions_on_empty_section() -> None:
    assert find_functions(b"") == ()


def test_find_functions_uses_calls_and_returns_as_boundaries() -> None:
    code = encode_words(
        (
            NOP,                  # 0x00
            jal(0x20),            # 0x04 -> call into the section
            NOP,                  # 0x08 (delay slot)
            jr(31),               # 0x0C -> next instruction starts a function
            NOP,                  # 0x10 (delay slot)
            NOP,                  # 0x14 start (after the return)
            NOP,                  # 0x18
            NOP,                  # 0x1C
            NOP,                  # 0x20 start (jal target)
            jr(31),               # 0x24 (return at the end: no trailing start)
        )
    )
    functions = find_functions(code)
    assert [f.start for f in functions] == [0x0, 0x14, 0x20]
    assert [f.end for f in functions] == [0x14, 0x20, 0x28]
    assert functions[0].calls == (0x20,)
    assert functions[1].calls == ()
    assert functions[2].calls == ()


def test_find_functions_ignores_calls_outside_the_section() -> None:
    code = encode_words((jal(0x400), NOP, jr(31)))
    functions = find_functions(code)
    assert [f.start for f in functions] == [0x0]


def test_find_functions_honours_a_nonzero_base() -> None:
    code = encode_words((NOP, jal(0x110), NOP, NOP, jr(31)))
    functions = find_functions(code, base=0x100)
    assert [f.start for f in functions] == [0x100, 0x110]
    assert functions[0].calls == (0x110,)


def test_find_functions_does_not_split_on_indirect_jumps() -> None:
    # jr $v0 (a jump table) must not create a function boundary.
    code = encode_words((jr(2), NOP, NOP, jr(31)))
    functions = find_functions(code)
    assert [f.start for f in functions] == [0x0]
