/*
 * libtutoriallist.prx, .text [0x1DF4, 0x1E84), 36 instructions.
 *
 * If arg1 is positive, arg0 (when nonzero) is passed as the second argument to
 * libehsys stub 0x3780 with zero as the first; that import's return value is
 * unused. The function then increments the upper seven bits of the byte at
 * module offset 0x6250 modulo 128. It always sets bit 0 and returns the signed
 * predicate (arg1 > 0). This describes the visible operations without assigning
 * unproven SDK or subsystem semantics.
 *
 * The four original references are byte loads/stores to the same zero-filled
 * PT_LOAD location. They are register-flow paired, but the address is outside
 * named sections. The shared provisional candidate symbol therefore does not
 * establish cross-artifact identity.
 *
 * Unsigned-char bitfield assignments reproduce the complete 144-byte symbol,
 * including the register OR (rather than ori) and common return/epilogue.
 * Result: INCONCLUSIVE 28/36, zero instruction differences/relocation issues;
 * all four data pairs still lack cross-artifact identity.
 */

#include "libtutoriallist_stubs.h"

int func_00001DF4(int arg0, int arg1)
{
    int enabled;

    enabled = arg1 > 0;
    if (enabled != 0) {
        if (arg0 != 0)
            func_00003780(0, arg0);

        func_00006250_state.count++;
    }

    func_00006250_state.active = 1;
    return enabled;
}
