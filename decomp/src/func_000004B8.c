/*
 * libhtml_view.prx, .text 0x4B8-0x508 (0x50 bytes, 20 instructions).
 *
 * ORIGINAL (from the verified splat `text.s`, `seto disasm` and the module's
 * own relocation table):
 *
 *   000004b8:  addiu $sp, $sp, -0x30
 *   000004bc:  sw    $ra, 0xc($sp)
 *   000004c0:  sw    $s0, 8($sp)
 *   000004c4:  lui   $a1, 0            ; R_MIPS_HI16 addend 0x00000000
 *   000004c8:  move  $s0, $a0
 *   000004cc:  jal   0x894             ; R_MIPS_26 addend 0x894
 *   000004d0:  addiu $a1, $a1, 0x4830  ; R_MIPS_LO16 addend 0x00004830
 *   000004d4:  addiu $a0, $sp, 0x10
 *   000004d8:  move  $a1, $zero
 *   000004dc:  jal   0x854             ; R_MIPS_26 addend 0x854
 *   000004e0:  addiu $a2, $zero, 0x20
 *   000004e4:  jal   0x2d0c            ; R_MIPS_26 addend 0x2d0c
 *   000004e8:  addiu $a0, $sp, 0x10
 *   000004ec:  move  $a0, $s0
 *   000004f0:  jal   0x8a4             ; R_MIPS_26 addend 0x8a4
 *   000004f4:  addiu $a1, $sp, 0x10
 *   000004f8:  lw    $ra, 0xc($sp)
 *   000004fc:  lw    $s0, 8($sp)
 *   00000500:  jr    $ra
 *   00000504:  addiu $sp, $sp, 0x30
 *
 * The string the HI16/LO16 pair builds is PROVEN: combined addend 0x00004830
 * lands inside `.data` (address 0x4768, size 0xe8) at offset 0xc8, and the
 * fourteen bytes at that file offset (0x4890) really are "/PSP/SAVEDATA/".
 * `seto datarefs` reports exactly that target.
 *
 * m2c's preliminary output omits the first argument to func_00000894. Ghidra's
 * disassembly shows `$a0` still contains the entry argument at 0x4CC and `$a1`
 * is set to the path in the delay slot, so this reconstruction follows the
 * instruction stream, not m2c's omitted argument. The helper prototypes and
 * the argument's semantic type remain provisional; the stripped PRX does not
 * supply their source declarations. No `mwccpsp` is available, so this C is
 * UNVERIFIED and must not be counted as a matching decompilation.
 *
 * Status: UNVERIFIED (compilation/matching BLOCKED: no licensed mwccpsp).
 */

typedef unsigned char u8;

extern const char D_00004830[];
extern void func_00000894(void *arg0, const char *path);
extern void func_00000854(void *buffer, int value, unsigned int size);
extern void func_00002D0C(void *buffer);
extern void func_000008A4(void *arg0, void *buffer);

void func_000004B8(void *arg0)
{
    u8 local_buffer[0x20];

    func_00000894(arg0, D_00004830);
    func_00000854(local_buffer, 0, 0x20);
    func_00002D0C(local_buffer);
    func_000008A4(arg0, local_buffer);
}
