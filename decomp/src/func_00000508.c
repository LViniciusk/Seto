/*
 * libhtml_view.prx, .text 0x508-0x634 (0x12C bytes, 75 instructions).
 *
 * EVIDENCE. The function fills one global block. It addresses 0x604864 once
 * (`lui $s0, 0x60` / `addiu $s0, $s0, 0x4864`, a HI16/LO16 pair), keeps the
 * incoming argument in `$s1`, clears 0xa4 bytes of the block, stores a run of
 * field values and then makes three calls (two of them with a second block
 * address as argument) before returning the last call's result:
 *
 *   00000508: addiu $sp, $sp, -0x10      ; frame
 *   00000518: lui   $s0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   0000051c: move  $s1, $a0             ; incoming argument kept in $s1
 *   00000520: addiu $s0, $s0, 0x4864     ; R_MIPS_LO16 addend 0x00004864
 *   00000528: move  $a1, $zero
 *   0000052c: jal   0x854                ; R_MIPS_26 -> libehsys NID 0x10F3BB61
 *   00000530: addiu $a2, $zero, 0xa4     ; (delay) clear size
 *   00000534: addiu $v0, $zero, 0xa4
 *   00000538: jal   0x39c                ; R_MIPS_26 -> this module @ 0x39c
 *   0000053c: sw    $v0, ($s0)           ; (delay) field +0x00 = 0xa4
 *   00000540: sw    $v0, 4($s0)          ; field +0x04 = 0x39c's result
 *   00000544: jal   0x235c               ; R_MIPS_26 -> libehsys NID 0x8171F765
 *   00000548: move  $a0, $zero           ; (delay)
 *   0000054c: andi  $v1, $v0, 0xffff
 *   00000550: addiu $v0, $zero, 0x2000
 *   00000554: bnel  $v1, $v0, 0x564
 *   00000558: addiu $v0, $zero, 1        ; (delay) value for the taken path
 *   0000055c: b     0x568
 *   00000560: sw    $zero, 8($s0)        ; (delay) field +0x08 = 0
 *   00000564: sw    $v0, 8($s0)          ; field +0x08 = 1
 *   00000568: addiu $v0, $zero, 0x10     ; field +0x18 = 0x10
 *   00000570: addiu $v0, $zero, 0x11     ; field +0x0c = 0x11
 *   00000578: addiu $v0, $zero, 0x12     ; field +0x14 = 0x12
 *   00000580: addiu $v0, $zero, 0x13     ; field +0x10 = 0x13
 *   00000588: lui   $v0, 0x60            ; NO relocation: the word 0x00600000
 *   0000058c: lui   $a0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   00000590: sw    $v0, 0x34($s0)       ; field +0x34 = 0x600000
 *   00000594: addiu $a0, $a0, 0x4918     ; R_MIPS_LO16 addend 0x00004918
 *   00000598: jal   0x414                ; R_MIPS_26 -> this module @ 0x414
 *   0000059c: sw    $s1, 0x30($s0)       ; (delay) field +0x30 = argument
 *   000005a0: lui   $v0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   000005a4: addiu $v0, $v0, 0x4918     ; R_MIPS_LO16 addend 0x00004918
 *   000005a8: sw    $v0, 0x40($s0)       ; field +0x40 = 0x604918
 *   000005ac: addiu $v0, $zero, 3        ; field +0x44 = 3
 *   000005b4: addiu $v0, $zero, 2        ; field +0x48 = 2
 *   000005bc: addiu $v0, $zero, 0x2ba    ; field +0x4c = 0x2ba
 *   000005c0: lui   $a0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   000005c8: jal   0x4b8                ; R_MIPS_26 -> this module @ 0x4b8
 *   000005cc: addiu $a0, $a0, 0x4b18     ; (delay) R_MIPS_LO16 addend 0x00004b18
 *   000005d0: lui   $v0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   000005d4: addiu $v0, $v0, 0x4b18     ; R_MIPS_LO16 addend 0x00004b18
 *   000005d8: sw    $v0, 0x50($s0)       ; field +0x50 = 0x604b18
 *   000005dc: addiu $v0, $zero, 3        ; field +0x60 = 3
 *   000005e4: addiu $v0, $zero, 0x200    ; field +0x64 = 0x200
 *   000005ec: addiu $v0, $zero, 1        ; fields +0x6c, +0x70, +0x74 = 1
 *   000005fc: lui   $v0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   00000600: addiu $v0, $v0, 0x4918     ; R_MIPS_LO16 addend 0x00004918
 *   00000604: sw    $v0, 0x68($s0)       ; field +0x68 = 0x604918
 *   00000608: move  $a0, $s0
 *   0000060c: sw    $zero, 0x54($s0)     ; fields +0x54, +0x5c, +0x58 = 0
 *   00000618: jal   0x2f84               ; R_MIPS_26 -> sceUtility NID 0xCDC3AA41
 *   0000061c: sw    $zero, 0x78($s0)     ; (delay) field +0x78 = 0
 *   00000620: lw    $ra, 0xc($sp)        ; epilogue; $v0 is the last call's
 *                                        ;   value, which is what the caller
 *                                        ;   (0x704) tests with `< 0`
 *
 * The block address 0x604864 lies past `p_filesz = 0x4850` of the single load
 * segment, so `seto datarefs` can only mark it INFERRED: no named ELF section
 * covers it and the object it names is not identified.
 *
 * STORAGE. The block is described by `SetoObservedBlock` in
 * `decomp/include/seto_shared_state.h`, a provisional record of the offsets
 * observed here and read by `func_00000634`. The mapping is
 *
 *   +0x00..+0x2F  words_00_2c[0..11]   (words; +0x1C is 0x634's read)
 *   +0x30         field_30             (the incoming argument)
 *   +0x34..+0x3C  words_34_3c[0..2]    (+0x34 holds the literal 0x00600000)
 *   +0x40         field_40             (0x604918)
 *   +0x44..+0x4C  words_44_4c[0..2]
 *   +0x50         field_50             (0x604B18)
 *   +0x54..+0x64  words_54_64[0..4]
 *   +0x68         field_68             (0x604918)
 *   +0x6C..+0x78  words_6c_78[0..3]
 *   +0x7C..+0xA3  reserved             (cleared, never field-accessed)
 *
 * The header's compile-time layout checks pin every one of those offsets and the
 * 0xA4 size, so a wrong description fails the build rather than shifting a store
 * silently. This replaces the earlier `unsigned char` view of the object plus
 * `int`/`void` casts: the object was declared one byte wide while the function
 * wrote 0xA4 bytes through it.
 *
 * SOURCE FORMS FORCED BY THE WORDS. Three details cannot be written the obvious
 * way and still reproduce the emitted instructions:
 *
 *  * the first two stores need a named, word-typed pointer to the block
 *    (`unsigned int *words = (unsigned int *)base;`, the explicit form of
 *    `base->words_00_2c`, the struct's `unsigned int[12]` first member at offset
 *    0). Writing them as `base->words_00_2c[0]` / `[1]`, or binding the pointer by
 *    array decay (`= base->words_00_2c`), makes this build materialise the
 *    constant address a second time for the store (`lui` + in-place `lo`) instead
 *    of reusing `$s0`, which adds two instructions (77 words, not 75). Every
 *    other store uses the plain member form.
 *  * the ternary's sense: `== 0x2000` selects 0 and the fall-through selects 1,
 *    which is `... == 0x2000 ? 0 : 1`: the `bnel` is taken on inequality and the
 *    `1` is materialised in its delay slot.
 *  * `+0x34` is the literal 0x00600000, not an address: the `lui $v0, 0x60` at
 *    0x588 carries no relocation at all, while the surrounding addresses do.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 63/75 words certified, 0 proven differences, 0 relocation
 * issues. The three call sites resolve by (libehsys, NID 0x10F3BB61), (libehsys,
 * NID 0x8171F765) and (sceUtility, NID 0xCDC3AA41), and the three module-local
 * calls by address (0x39c, 0x414, 0x4b8). Six HI16/LO16 pairs (0x604864; three
 * pairs for 0x604918 at +0x40, +0x68 and the call argument to 0x414; two pairs
 * for 0x604b18 at +0x50 and the call argument to 0x4b8) name objects whose
 * identity is unprovable from the stripped module, so relocation equivalence for
 * those 12 words stays unproven and the comparator remains INCONCLUSIVE. The
 * PRX records compiler 2.4.1.01; no equivalence with that historical version is
 * claimed.
 *
 * Note on the previous revision: with the byte-typed object and casts, this
 * build emitted the last call's argument setup one slot later than the module
 * does (`sw 0x54 | sw 0x5c | sw 0x58 | move $a0,$s0 | jal | sw 0x78` instead of
 * `move $a0,$s0 | sw 0x54 | sw 0x5c | sw 0x58 | jal | sw 0x78`), which cost four
 * words. Exhaustive sweeps of all 120 statements orders of the closing block -
 * and all 120 that also moved the `+0x68` store among them - never hoisted it,
 * and the difference was attributed to a scheduling change between the PRX's
 * 2.4.1.01 and this build. Typing the block's members removes it: the five
 * instructions now sit exactly where the module puts them, and the four words
 * are certified. The attribution to the compiler version was wrong and the
 * round records the correction.
 */

#include "sce_stubs.h"
#include "seto_shared_state.h"

extern unsigned char D_00604918; /* first byte of the block addressed at 0x604918 */
extern unsigned char D_00604B18; /* first byte of the block addressed at 0x604b18 */

/* Module-local callees (this module @ 0x39c / 0x414 / 0x4b8). */
extern int func_0000039C(void);
extern void func_00000414(void *arg0);
extern void func_000004B8(void *arg0);

int func_00000508(void *arg0)
{
    SetoObservedBlock *base = &D_00604864;
    unsigned int *words = (unsigned int *)base;

    func_00000854(base, 0, 0xA4);
    words[0] = 0xA4;
    words[1] = func_0000039C();
    if ((func_0000235C(0) & 0xFFFF) == 0x2000) {
        base->words_00_2c[2] = 0;
    } else {
        base->words_00_2c[2] = 1;
    }
    base->words_00_2c[6] = 0x10;
    base->words_00_2c[3] = 0x11;
    base->words_00_2c[5] = 0x12;
    base->words_00_2c[4] = 0x13;
    base->words_34_3c[0] = 0x600000;
    base->field_30 = arg0;
    func_00000414(&D_00604918);
    base->field_40 = &D_00604918;
    base->words_44_4c[0] = 3;
    base->words_44_4c[1] = 2;
    base->words_44_4c[2] = 0x2BA;
    func_000004B8(&D_00604B18);
    base->field_50 = &D_00604B18;
    base->words_54_64[3] = 3;
    base->words_54_64[4] = 0x200;
    base->words_6c_78[0] = 1;
    base->words_6c_78[1] = 1;
    base->words_6c_78[2] = 1;
    base->field_68 = &D_00604918;
    base->words_54_64[0] = 0;
    base->words_54_64[2] = 0;
    base->words_54_64[1] = 0;
    base->words_6c_78[3] = 0;
    return func_00002F84(base);
}
