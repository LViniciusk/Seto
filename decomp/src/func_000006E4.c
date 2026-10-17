/*
 * libhtml_view.prx, .text 0x6E4-0x704 (0x20 bytes, 8 instructions).
 *
 * ORIGINAL (from the verified splat `text.s`, `seto disasm` and the module's
 * own relocation table):
 *
 *   000006e4:  addiu $a0, $zero, 1
 *   000006e8:  lui   $v1, 0x60        ; R_MIPS_HI16 addend 0x00000060
 *   000006ec:  sw    $a0, 0x4860($v1) ; R_MIPS_LO16 addend 0x00004860
 *   000006f0:  lui   $a0, 0           ; R_MIPS_HI16 addend 0x00000000
 *   000006f4:  addiu $a0, $a0, 0x4860 ; R_MIPS_LO16 addend 0x00004860
 *   000006f8:  lui   $v1, 0x60        ; R_MIPS_HI16 addend 0x00000060
 *   000006fc:  jr    $ra
 *   00000700:  sw    $a0, 0x4b9c($v1) ; R_MIPS_LO16 addend 0x00004b9c
 *
 * Two 32-bit stores and one address computation.  The combined HI16/LO16
 * addends are 0x00604860 (store target), 0x00004860 (the value stored) and
 * 0x00604b9c (store target).  Ghidra 12.1.3 independently reports the same two
 * stores as `_DAT_00604860 = 1` and `_DAT_00604b9c = 0x4860`.
 *
 * ADDRESS SPACES.  The store targets and the value differ by exactly 0x600000
 * (= the HI16 addend 0x60 << 16), and that constant is NOT the module's ELF base
 * (every section is based at 0).  The ELF section headers cover neither
 * 0x604860/0x604b9c nor 0x4860: `.data` ends at 0x4850 and the `.bss` section is
 * empty (size 0), so these bytes live only in the zero-filled tail of the single
 * PT_LOAD segment.  The transformation between the two spaces is therefore NOT
 * proven, and the two identifiers below stay distinct on purpose - the task is
 * not allowed to assume they name the same object.  `seto datarefs` records
 * both as INFERRED (their offset inside that segment), never as a section.
 *
 * The original PRX is stripped. `D_...` names and the inferred global types are
 * provisional address-based labels, not recovered source names. No `mwccpsp` is
 * available, so this C is UNVERIFIED and must not be counted as a matching
 * decompilation.
 *
 * Status: UNVERIFIED (compilation/matching BLOCKED: no licensed mwccpsp).
 */

typedef unsigned int u32;

extern u32 D_00604860;             /* store target 0x604860 */
extern void *D_00604B9C;           /* store target 0x604b9c */
extern unsigned char D_00004860;   /* object addressed as 0x4860 */

void func_000006E4(void)
{
    D_00604860 = 1;
    D_00604B9C = &D_00004860;
}
