/*
 * libhtml_view.prx, .text 0x6E4-0x704 (0x20 bytes, 8 instructions).
 *
 * Evidence: splat's verified `text.s`, `seto disasm`, m2c 0.1.0 (MIPS target),
 * and Ghidra 12.1.3 / Allegrex headless analysis. All eight instructions are
 * straight-line code: write 1 to the global at 0x604860, form the address of
 * the image object at offset 0x4860, store it at 0x604B9C, and return. Ghidra
 * independently reports `_DAT_00604860 = 1` and `_DAT_00604b9c = 0x4860`.
 *
 * The original PRX is stripped. `D_...` names and the inferred global types are
 * provisional address-based labels, not recovered source names. No
 * `mwccpsp` is available, so this C is UNVERIFIED and must not be counted as a
 * matching decompilation.
 *
 * Status: UNVERIFIED (compilation/matching BLOCKED: no licensed mwccpsp).
 */

typedef unsigned int u32;

extern u32 D_00604860;
extern void *D_00604B9C;
extern unsigned char D_00004860;

void func_000006E4(void)
{
    D_00604860 = 1;
    D_00604B9C = &D_00004860;
}
