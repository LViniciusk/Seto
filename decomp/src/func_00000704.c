/*
 * libhtml_view.prx, .text 0x704-0x7F4 (0xF0 bytes, 60 instructions).
 *
 * EVIDENCE. The function reads one state word, dispatches on it with a compiled
 * four-way `switch`, and either rewrites that word or returns a value:
 *
 *   00000704: addiu $sp, $sp, -0x10
 *   0000070c: lui   $v0, 0x60            ; R_MIPS_HI16 addend 0x00000060
 *   00000710: lw    $v1, 0x4860($v0)     ; R_MIPS_LO16 addend 0x00004860
 *                                         ;   $v1 = *(int *)0x604860
 *   00000714: addiu $v0, $zero, 4
 *   00000718: beql  $v1, $v0, 0x7e8      ; case 4 -> return 1
 *   0000071c: addiu $v0, $zero, 1        ; (delay) return value
 *   00000720: addiu $v0, $zero, 3
 *   00000724: beq   $v1, $v0, 0x7c8      ; case 3
 *   0000072c: addiu $v0, $zero, 2
 *   00000730: beq   $v1, $v0, 0x7a0      ; case 2
 *   00000738: addiu $v0, $zero, 1
 *   0000073c: beq   $v1, $v0, 0x74c      ; case 1
 *   00000744: b     0x7e8                ; default
 *   00000748: move  $v0, $zero            ; (delay) return 0
 *
 *   0000074c: jal   0x278                ; case 1 (this module @ 0x278)
 *   00000754: bgezl $v0, 0x76c            ; if (0x278() >= 0) skip the failure
 *   0000075c: addiu $v1, $zero, 3         ; failure: state = 3
 *   00000764: b     0x7e4                ;   ... and return 0
 *   00000768: sw    $v1, 0x4860($v0)      ; (delay)
 *   0000076c: jal   0x508                ; second guard: this module @ 0x508
 *   00000770: lw    $a0, 0x4b9c($v0)      ; (delay) R_MIPS_LO16 addend 0x00004b9c
 *   00000774: bgezl $v0, 0x78c            ; if (0x508(...) >= 0) skip the failure
 *   0000077c: addiu $v1, $zero, 3         ; failure: state = 3
 *   00000784: b     0x7e4                ;   ... and return 0
 *   00000788: sw    $v1, 0x4860($v0)      ; (delay)
 *   0000078c: lw    $v1, 0x4860($v0)      ; both guards passed: state++
 *   00000794: addiu $v1, $v1, 1
 *   00000798: b     0x7e4                ;   ... and return 0
 *   0000079c: sw    $v1, 0x4860($v0)      ; (delay)
 *
 *   000007a0: jal   0x634                ; case 2 (this module @ 0x634)
 *   000007a8: beqz  $v0, 0x7e4            ; if (0x634() == 0) return 0
 *   000007b4: lw    $v1, 0x4860($v0)      ; else state++
 *   000007bc: addiu $v1, $v1, 1
 *   000007c0: b     0x7e4                ;   ... and return 0
 *   000007c4: sw    $v1, 0x4860($v0)      ; (delay)
 *
 *   000007c8: jal   0x358                ; case 3 (this module @ 0x358)
 *   000007d4: lw    $v1, 0x4860($v0)      ; state++
 *   000007dc: addiu $v1, $v1, 1
 *   000007e0: sw    $v1, 0x4860($v0)      ; then fall through to `return 0`
 *   000007e4: move  $v0, $zero            ; shared return-0 block
 *   000007e8: lw    $ra, 0xc($sp)         ; epilogue
 *
 * The state word at 0x604860 and the pointer word at 0x604b9c both lie past
 * `p_filesz = 0x4850` of the single load segment, so `seto datarefs` marks them
 * INFERRED: no named ELF section covers them and the objects they name are not
 * identified.
 *
 * SOURCE FORMS FORCED BY THE WORDS.
 *
 *  * the order of the case labels. As measured over all 120 permutations of a
 *    five-case switch (see func_00000634.c), Metrowerks 3.0.1 build 219 emits
 *    the comparison chain in the reverse of the source order. The observed
 *    chain here is 4, 3, 2, 1, so the source order is 1, 2, 3, 4.
 *  * the sense of the two guards. `func_00000278() < 0` and
 *    `func_00000508(...) < 0` compile to `bgezl` (branch-likely, delay slot
 *    nullified when the branch is not taken); writing the guards as `>= 0`
 *    inverts the branch and does not reproduce the words. The case-2 guard is a
 *    plain `beqz`, so only the two `< 0` tests are branch-likely here.
 *  * the state is re-read from memory for every increment. Each `state++` path
 *    reloads `0x4860` and stores the sum, so the source reads the global word,
 *    not a local copy kept live across the calls:
 *        lw    $v1, 0x4860($v0)
 *        addiu $v1, $v1, 1
 *        sw    $v1, 0x4860($v0)
 *  * case 4's `return 1` jumps over the shared `move $v0, $zero` block to the
 *    epilogue (the `beql` targets 0x7e8, not 0x7e4), which is why the case is
 *    `return 1` and not `state = ...; break`.
 *  * the argument of `func_00000508` is the *value* loaded from 0x604b9c
 *    (`lw $a0, 0x4b9c($v0)`), i.e. the pointer stored in that global word.
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 60 instructions, 0 proven differences, 0 relocation issues. The
 * four module-local calls resolve by address (0x278, 0x358, 0x508, 0x634). The
 * twenty uncertified words are ten HI16/LO16 pairs: nine of them name 0x604860
 * (one load of the dispatch word, three loads and five stores of the increments)
 * and one names 0x604b9c (the pointer word read into `$a0` for the call). Every
 * destination lies only in a load segment's zero-filled tail and the object
 * exposes only undefined `D_...` symbols, so relocation equivalence for those
 * words stays unproven and the comparator remains INCONCLUSIVE. For six of the
 * ten pairs the `lui` and its LO16 instruction are separated by a branch, so even
 * the pairing itself rests on relocation order. The PRX records compiler
 * 2.4.1.01; no equivalence with that historical version is claimed.
 *
 * The meaning of the state values (1, 2, 3, 4 and the literal 3 written on
 * failure) and of the four callees is not recoverable from this module alone.
 */

extern int D_00604860;   /* the shared state word addressed at 0x604860 */
extern void *D_00604B9C; /* the pointer word addressed at 0x604b9c */

/* Module-local callees (this module @ 0x278 / 0x358 / 0x508 / 0x634). */
extern int func_00000278(void);
extern void func_00000358(void);
extern int func_00000508(void *arg0);
extern int func_00000634(void);

int func_00000704(void)
{
    switch (D_00604860) {
    case 1:
        if (func_00000278() < 0) {
            D_00604860 = 3;
        } else if (func_00000508(D_00604B9C) < 0) {
            D_00604860 = 3;
        } else {
            D_00604860 = D_00604860 + 1;
        }
        break;
    case 2:
        if (func_00000634() != 0) {
            D_00604860 = D_00604860 + 1;
        }
        break;
    case 3:
        func_00000358();
        D_00604860 = D_00604860 + 1;
        break;
    case 4:
        return 1;
    }
    return 0;
}
