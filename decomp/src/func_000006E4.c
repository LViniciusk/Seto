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
 * ADDRESS SPACES.  The three combined addends are 0x00604860, 0x00004860 and
 * 0x00604b9c.  They differ by exactly 0x600000, which is the HI16 addend 0x60
 * shifted by 16 - the high half of a *different* address, not a base.  The
 * module has a single PT_LOAD with p_vaddr 0, so the loader adds the same base to
 * every relocation (PPSSPP's `ElfReader::LoadRelocations`; `seto psp_reloc`
 * models it). `load_base=0` reproduces the stored module-relative addends; the
 * actual runtime load base is not encoded by this ELF and is not claimed to be
 * zero. Adding the same runtime base to all three preserves their differences,
 * so they cannot collapse onto each other. They are three distinct
 * module-relative addresses.
 *
 * Their *identity* still stays weak: the ELF section headers cover neither
 * 0x604860/0x604b9c nor 0x4860 - `.data` ends at 0x4850 and the `.bss` section is
 * empty (size 0) - so these bytes live only in the zero-filled tail of that
 * segment. `seto datarefs` records all three as INFERRED (their offset inside the
 * segment), never as a section. The local LUI-to-LO16 register flow proves each
 * pair even without symbols, but the destination/variable identities stay
 * unknown; these references are not cross-artifact identity proof. The
 * identifiers below stay distinct on purpose: nothing here may assume two
 * different addresses name the same object.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 2/8 words, 0 differences, 0 relocation issues. Register flow
 * proves all three pairs; the six uncounted words reflect unresolved data-object
 * identity, not six proven code divergences. The original PRX is stripped;
 * `D_...` names and inferred global types remain provisional address labels, not
 * recovered source names. The PRX records compiler 2.4.1.01; the observed match
 * status is for build 3.0.1 only.
 *
 * Status: INCONCLUSIVE (real compile succeeded; data identity remains unproven).
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
