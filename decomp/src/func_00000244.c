/*
 * func_00000244 - libhtml_view.prx, .text offset 0x244, 0x34 bytes (13 words).
 *
 * ORIGINAL (verified from the real module; every `jal` target comes from the
 * relocation table, not from a guess):
 *
 *   00000244:  addiu $sp, $sp, -0x10
 *   00000248:  sw    $ra, 0xc($sp)
 *   0000024c:  jal   0x2edc        ; R_MIPS_26 -> sceHttp NID 0x76D1363B
 *   00000250:  nop
 *   00000254:  jal   0x2f0c        ; R_MIPS_26 -> sceHttp NID 0xF9D8EB63
 *   00000258:  nop
 *   0000025c:  jal   0x2ef4        ; R_MIPS_26 -> sceHttp NID 0xD1C8945E
 *   00000260:  nop
 *   00000264:  jal   0x2f54        ; R_MIPS_26 -> sceSsl  NID 0x191CDEFF
 *   00000268:  nop
 *   0000026c:  lw    $ra, 0xc($sp)
 *   00000270:  jr    $ra
 *   00000274:  addiu $sp, $sp, 0x10   ; delay slot
 *
 * The four call targets are import trampolines, and their identities are
 * recovered from the module's own import tables rather than from their
 * provisional names (see decomp/imports/libhtml_view.json).  The body is four
 * back-to-back calls with no data flow between them, so the reconstruction is
 * unambiguous: a non-leaf function with a 0x10-byte frame.
 *
 * EVIDENCE:
 *   The emitted splat `text.s` was checked against the original bytes, Ghidra
 *   12.1.3 automatically loaded the real PRX with Allegrex and independently
 *   disassembled this 13-instruction range, and m2c produced the same four-call
 *   C body below.  These checks confirm the reconstruction is a plausible,
 *   minimal representation; they do not replace a real compile-and-match.
 *
 * STATUS: UNVERIFIED (compilation/matching BLOCKED)
 *   The four imported identities are PROVEN (library + NID, cross-checked
 *   against the trampoline bytes), but `seto match` can only prove this file
 *   byte-for-byte once it is compiled with the original toolchain (mwccpsp,
 *   `MW MIPS C Compiler (2.4.1.01)`).  mwccpsp is proprietary and is not present
 *   in the reference environment. Run `python scripts/match_function.py ...`
 *   once a licensed copy is supplied.
 *
 * See docs/decomp-progress.md for the full report.
 */

#include "sce_stubs.h"

void func_00000244(void)
{
    func_00002EDC(); /* sceHttp 0x76D1363B */
    func_00002F0C(); /* sceHttp 0xF9D8EB63 */
    func_00002EF4(); /* sceHttp 0xD1C8945E */
    func_00002F54(); /* sceSsl  0x191CDEFF */
}
