/*
 * libhtml_view.prx, .text 0x0-0x34 (0x34 bytes, 13 instructions).
 *
 * EVIDENCE. The whole function is a 0x10-byte frame, three address computations
 * and one import call; it returns the constant 0:
 *
 *   00000004:  lui   $a0, 0             ; R_MIPS_HI16 addend 0x00000000
 *   00000008:  lui   $a1, 0             ; R_MIPS_HI16 addend 0x00000000
 *   0000000c:  lui   $a2, 0             ; R_MIPS_HI16 addend 0x00000000
 *   00000014:  addiu $a0, $a0, 0x34     ; R_MIPS_LO16 addend 0x00000034
 *   00000018:  addiu $a1, $a1, 0x84     ; R_MIPS_LO16 addend 0x00000084
 *   0000001c:  jal   0x1f04             ; R_MIPS_26 -> libehsys NID 0xB4471B5E
 *   00000020:  addiu $a2, $a2, 0x4850   ; R_MIPS_LO16 addend 0x00004850 (delay)
 *   00000024:  lw    $ra, 0xc($sp)
 *   00000028:  move  $v0, $zero
 *   0000002c:  jr    $ra
 *
 * All three arguments are relocatable addresses (each is a HI16/LO16 pair), not
 * immediates:
 *
 *  * `$a0` = `.text+0x34`, the address of the reconstructed `func_00000034`;
 *    `seto datarefs` places the pair inside the named `.text` section (PROVEN).
 *  * `$a1` = `.text+0x84`, the address just past `func_00000034`. `0x84` holds
 *    only the 8-byte `jr $ra; nop` sequence, and no other site takes its address,
 *    so the pair is consistent with the *exclusive end* of a code range
 *    [0x34, 0x84) rather than with a call to a distinct function. The PRX alone
 *    does not prove which reading the original source intended, so the
 *    reconstruction states only the address and does not presume its meaning.
 *  * `$a2` = 0x4850, the first byte past `p_filesz`, i.e. the start of the
 *    zero-filled load region. `seto datarefs` can place it only in load segment 0
 *    (location INFERRED); no named ELF section covers it.
 *
 * The callee identity is `(libehsys, NID 0xB4471B5E)` from the module's own import
 * table. What it does with the two code addresses and the data address is not
 * recoverable from this module, so the reconstruction fixes the call and the
 * return value but asserts no registration / thread / exit-handler meaning. No
 * inline assembly, `volatile` or invented struct is used; the argument types are
 * provisional (function pointers plus a `void *`) because they emit the observed
 * address relocations.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 7/13 words, 0 differences, 0 relocation issues. The call resolves
 * by `(libehsys, NID 0xB4471B5E)` and all 13 words are byte-identical to the
 * original; the six uncounted words are the three HI16/LO16 address pairs, which
 * the comparator will not certify without an artifact-qualified object identity
 * (the first two name `.text` code, the third a segment-only address). The PRX
 * records compiler 2.4.1.01; equivalence with that historical version is not
 * claimed. The import name func_00001F04 stays an address-derived label.
 */

#include "sce_stubs.h"

extern void func_00000034(void);
extern void func_00000084(void);
extern char D_00004850[];

int func_00000000(void)
{
    func_00001F04(func_00000034, func_00000084, D_00004850);
    return 0;
}
