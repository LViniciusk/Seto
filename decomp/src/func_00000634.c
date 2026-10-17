/*
 * libhtml_view.prx, .text 0x634-0x6E4 (0xB0 bytes, 44 instructions).
 *
 * EVIDENCE. The function forms one module address, makes one call with two zero
 * arguments, and then dispatches on a second call's result with a compiled
 * five-way `switch`:
 *
 *   00000640:  lui   $s0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   00000644:  move  $a0, $zero
 *   00000648:  move  $a1, $zero
 *   0000064c:  jal   0xb1c               ; R_MIPS_26 -> libehsys NID 0xE8D57DC6
 *   00000650:  addiu $s0, $s0, 0x4864    ; R_MIPS_LO16 addend 0x00004864 (delay)
 *   00000654:  jal   0x2f7c              ; R_MIPS_26 -> sceUtility NID 0xBDA7D894
 *   00000658:  nop
 *   0000065c:  beql  $v0, $zero, 0x6bc   ; case 0
 *   00000660:  lw    $v0, 0x1c($s0)      ; (delay)
 *   00000664:  addiu $v1, $zero, 3       ; case 3
 *   00000668:  beq   $v0, $v1, 0x6ac
 *   00000670:  addiu $a0, $zero, 2       ; case 2, constant shared with the call
 *   00000674:  beq   $v0, $a0, 0x69c
 *   0000067c:  addiu $v1, $zero, 4       ; case 4
 *   00000680:  beql  $v0, $v1, 0x6d4
 *   00000684:  move  $v0, $zero          ; (delay)
 *   00000688:  addiu $v1, $zero, 1       ; case 1
 *   0000068c:  beq   $v0, $v1, 0x6d0
 *   00000694:  b     0x6d0               ; default
 *   0000069c:  jal   0x2f64              ; R_MIPS_26 -> sceUtility NID 0x05AFB9E4
 *   000006ac:  jal   0x2f8c              ; R_MIPS_26 -> sceUtility NID 0xF5CE1134
 *   000006bc:  bnel  $v0, $zero, 0x6c8
 *   000006c0:  addiu $v0, $zero, 2       ; (delay)
 *   000006c4:  addiu $v0, $zero, 1
 *   000006d0:  move  $v0, $zero          ; shared return-0 block
 *   000006d4:  lw    $ra, 0xc($sp)       ; epilogue, reached with $v0 = 0
 *
 * `$s0` is the address 0x604864 (combined HI16/LO16 addend 0x00604864; the
 * LUI-to-LO16 register flow proves the pair). `seto datarefs` can place it only
 * in load segment 0, past `p_filesz = 0x4850`: no named ELF section covers it
 * (location INFERRED), so the object it names is not identified.
 *
 * CASES. Cases 2 and 3 call the two sceUtility entries; case 0 reads the word at
 * `0x604864 + 0x1c` (the load sits in the `beql` delay slot) and returns `1` or
 * `2`; cases 1 and 4 and the default reach the shared `move $v0, $zero` block.
 * The dispatched value in `$v0` survives the delay-slot load because a MIPS
 * "branch likely" nullifies its delay slot when the branch is not taken.
 *
 * Two source-level choices are forced by the emitted words and are recorded here
 * rather than guessed away:
 *
 *  * the argument of the case-2 call. The constant `2` is materialised exactly
 *    once, in `$a0`, at 0x670, and is shared by the case-2 comparison and the
 *    call, so that call passes a value equal to the case constant. The same case
 *    written with no argument compiles the constant into `$v1` and does not
 *    reproduce the words.
 *  * the order of the case labels. Over all 120 source orders, Metrowerks 3.0.1
 *    build 219 emits the comparison chain in the reverse of the source order;
 *    the observed chain (0, 3, 2, 4, 1) is therefore reproduced by the source
 *    order `1, 4, 2, 3, 0` used below.
 *
 * The words are the only authority: the case *values*, the calls and the
 * returned constants are facts of the binary; the label order and the argument
 * expression are the source forms that reproduce them. The import names stay
 * address-derived labels, and the meaning of the dispatched value and of the two
 * sceUtility calls is not recoverable from this module alone.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 42/44 words certified, 0 proven differences, 0 relocation
 * issues. The four calls resolve by `(libehsys, NID 0xE8D57DC6)`,
 * `(sceUtility, NID 0xBDA7D894)`, `(sceUtility, NID 0x05AFB9E4)` and
 * `(sceUtility, NID 0xF5CE1134)`. The two uncertified words are the HI16/LO16
 * pair for 0x604864: the destination is only in a load segment, and the object
 * exposes only an undefined `D_...` symbol, so relocation equivalence for those
 * words stays unproven and the comparator remains INCONCLUSIVE. The PRX records
 * compiler 2.4.1.01; no equivalence with that historical version is claimed.
 */

#include "sce_stubs.h"

extern unsigned char D_00604864; /* first byte of the block addressed at 0x604864 */

int func_00000634(void)
{
    unsigned char *base = &D_00604864;
    int state;

    func_00000B1C(0, 0);
    state = func_00002F7C();

    switch (state) {
    case 1:
        break;
    case 4:
        break;
    case 2:
        func_00002F64(2);
        break;
    case 3:
        func_00002F8C();
        break;
    case 0:
        return *(int *)(base + 0x1c) == 0 ? 1 : 2;
    }
    return 0;
}
