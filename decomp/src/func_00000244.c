/*
 * func_00000244 - libhtml_view.prx, .text offset 0x244, 0x34 bytes (13 words).
 *
 * ORIGINAL (verified from the real module; every `jal` target comes from the
 * relocation table, not from a guess):
 *
 *   00000244:  addiu $sp, $sp, -0x10
 *   00000248:  sw    $ra, 0xc($sp)
 *   0000024c:  jal   0x2edc        ; R_MIPS_26 addend=0x2edc
 *   00000250:  nop
 *   00000254:  jal   0x2f0c        ; R_MIPS_26 addend=0x2f0c
 *   00000258:  nop
 *   0000025c:  jal   0x2ef4        ; R_MIPS_26 addend=0x2ef4
 *   00000260:  nop
 *   00000264:  jal   0x2f54        ; R_MIPS_26 addend=0x2f54
 *   00000268:  nop
 *   0000026c:  lw    $ra, 0xc($sp)
 *   00000270:  jr    $ra
 *   00000274:  addiu $sp, $sp, 0x10   ; delay slot
 *
 * The body is four back-to-back calls with no data flow between them, so the
 * reconstruction is unambiguous: a non-leaf function with a 0x10-byte frame.
 *
 * STATUS: BLOCKED
 *   `seto match` proves this file byte-for-byte only once it is compiled with
 *   the original toolchain (mwccpsp, `MW MIPS C Compiler (2.4.1.01)`).  mwccpsp
 *   is proprietary and is not present in the reference environment, so the
 *   candidate below is an unverified hypothesis.  Run
 *   `python scripts/match_function.py ...` once the compiler is installed.
 *
 * See docs/decomp-progress.md for the full report.
 */

#include "sce_stubs.h"

void func_00000244(void)
{
    func_00002EDC();
    func_00002F0C();
    func_00002EF4();
    func_00002F54();
}
