/*
 * libhtml_view.prx, .text 0x39C-0x414 (0x78 bytes, 30 instructions).
 *
 * EVIDENCE. `seto disasm --function 0x39c` gives a single non-leaf function with
 * one import call and one compiled `switch`:
 *
 *   000003a4:  jal   0x2364             ; R_MIPS_26 -> libehsys NID 0x31454993
 *   000003ac:  sltiu $at, $v0, 6
 *   000003b0:  beql  $at, $zero, 0x408  ; index >= 6 -> default
 *   000003b4:  addiu $v0, $zero, 1      ; (delay slot) default result
 *   000003b8:  lui   $v1, 0             ; R_MIPS_HI16 addend 0x00000000
 *   000003c0:  addiu $v1, $v1, 0x4770   ; R_MIPS_LO16 addend 0x00004770
 *   000003c8:  lw    $v0, ($v0)         ; case address from a 6-entry word table
 *   000003cc:  jr    $v0
 *
 * The table base is the function's only data reference. `seto datarefs` locates
 * it at `.data+0x8` (module address 0x4770, location PROVEN), and the module's own
 * `.data` bytes there are exactly [0x3d4, 0x3dc, 0x3e4, 0x3ec, 0x3f4, 0x3fc]:
 * entry i is the address of the case-i body, so case 0..5 return 0, 1, 6, 2, 5, 3
 * and `sltiu $v0, 6` bounds the index. The separate `addiu $v0, $zero, 1` at
 * 0x404 is the `default:` body the compiler emits; the `beql` delay slot already
 * carries the same value for the out-of-range path. Reading the table's identity
 * is what makes the arm order a fact rather than a guess; the table itself is
 * emitted by the compiler for the `switch` below, not a hand-written object.
 * BOUNDARIES. The Seto range is `[0x39C, 0x414)`: 30 instructions, with 0x414 the
 * next function's start. Ghidra's own flow analysis recognises a body of 116 bytes
 * spread over **two** regions and never defines the word at 0x404
 * (`SETO_BOUNDARY_STATUS=MISMATCH`, `SETO_DECOMP_STATUS=NOT_RUN`). That missing
 * word is the compiler-emitted `default:` body; its absence is *consistent* with
 * the jump-table reading above, but it is neither an `EXACT` body confirmation nor,
 * on its own, a proof of the original source's intent.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 28/30 words certified, 0 proven differences, 0 relocation issues.
 * The call resolves by `(libehsys, NID 0x31454993)`. The two uncertified words are
 * the HI16/LO16 pair that encodes the jump-table address: the original's
 * destination is proven at `.data+0x8`, but the object's own table is a local
 * symbol with no independent artifact proving it names that same object, so
 * relocation equivalence for those words remains unproven and the comparator will
 * not report MATCHED. No data map was supplied; a JSON assertion is not evidence.
 * The PRX records compiler 2.4.1.01; equivalence with that version is not claimed.
 *
 * The import name func_00002364 stays an address-derived label; the recovered
 * identity is the (library, NID) pair (decomp/imports/libhtml_view.json).
 */

#include "sce_stubs.h"

int func_0000039C(void)
{
    switch (func_00002364()) {
    case 0:
        return 0;
    case 1:
        return 1;
    case 2:
        return 6;
    case 3:
        return 2;
    case 4:
        return 5;
    case 5:
        return 3;
    default:
        return 1;
    }
}
