/*
 * libhtml_view.prx, .text 0x414-0x4B8 (0xA4 bytes, 41 instructions).
 *
 * EVIDENCE. The function saves `$ra`/`$s0`, moves its argument into `$s0`, calls
 * the import at 0x2354 (libehsys NID 0x1F190478) and dispatches on the result
 * with a compiled `switch`:
 *
 *   00000420:  jal   0x2354             ; R_MIPS_26 -> libehsys NID 0x1F190478
 *   00000428:  sltiu $at, $v0, 7
 *   0000042c:  beqz  $at, 0x498         ; index >= 7 -> default
 *   00000434:  lui   $v1, 0             ; R_MIPS_HI16 addend 0x00000000
 *   0000043c:  addiu $v1, $v1, 0x4788   ; R_MIPS_LO16 addend 0x00004788
 *   00000444:  lw    $v0, ($v0)         ; case address from a 7-entry word table
 *   00000448:  jr    $v0
 *
 * `seto datarefs` locates the table at `.data+0x20` (module address 0x4788,
 * location PROVEN), and the `.data` bytes there are exactly
 * [0x450, 0x468, 0x480, 0x480, 0x480, 0x480, 0x480]. So case 0 reaches 0x450,
 * case 1 reaches 0x468, cases 2-6 share 0x480, and the default reaches 0x498.
 * Each arm calls the same import at 0x8a4 (libehsys NID 0x476FD94A) with `$s0` in
 * `$a0` and one address argument in `$a1`:
 *
 *   0x450 (case 0):    $a1 = 0x47a4 = .data+0x3c
 *   0x468 (case 1):    $a1 = 0x47d0 = .data+0x68
 *   0x480 (cases 2-6): $a1 = 0x4800 = .data+0x98
 *   0x498 (default):   $a1 = 0x47d0 = .data+0x68
 *
 * Three of those destinations are distinct: `.data+0x68` is reached twice (case 1
 * and the default), which is why the usage map groups 0x468 and 0x4a4 together
 * while 0x47a4 and 0x4800 stand alone. The 0x3c/0x68/0x98 offsets hold
 * NUL-terminated ASCII paths (`.data+0x3c` and `.data+0x68` begin with
 * "http://www.konami.jp/..."), so the second argument is a string pointer; the
 * first is passed through from the caller. The 0x414-0x4B8 boundary is the next
 * function's start and Ghidra's exact body. There is no return-value handling:
 * the epilogue leaves `$v0` as the last call's result, so the function is
 * modelled as `void` (a return type would not change the emitted words).
 *
 * REAL COMPILE + MATCH: Metrowerks 3.0.1 build 219, `-O4,p -sdatathreshold 0`.
 * INCONCLUSIVE, 31/41 words, 0 differences, 0 relocation issues. The five import
 * calls resolve by `(libehsys, NID 0x476FD94A)` and
 * `(libehsys, NID 0x1F190478)`. The ten uncounted words are five HI16/LO16 pairs
 * (the jump table plus the three path arguments): each original destination is
 * proven in `.data`, but the object exposes only undefined `D_...` symbols and no
 * independent artifact links them to those objects, so the comparator stays
 * INCONCLUSIVE. The `D_...` names and the pointer types are provisional address
 * labels, not recovered source names. The PRX records compiler 2.4.1.01; no
 * equivalence with that historical version is claimed.
 */

#include "sce_stubs.h"

extern char D_000047A4[]; /* .data+0x3c, "http://www.konami.jp/..." */
extern char D_000047D0[]; /* .data+0x68, "http://www.konami.jp/..." */
extern char D_00004800[]; /* .data+0x98, "http://www.konami.jp/..." */

void func_00000414(void *arg0)
{
    switch (func_00002354()) {
    case 0:
        func_000008A4(arg0, D_000047A4);
        break;
    case 1:
        func_000008A4(arg0, D_000047D0);
        break;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
        func_000008A4(arg0, D_00004800);
        break;
    default:
        func_000008A4(arg0, D_000047D0);
        break;
    }
}
