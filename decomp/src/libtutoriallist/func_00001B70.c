/*
 * libtutoriallist.prx, .text [0x1B70, 0x1C18), 42 instructions.
 *
 * The function tests the low bit of the byte at module offset 0x6250. When
 * active, it extracts the upper seven bits: a nonzero value is cleared and
 * returns 1; a zero value calls func_00001C58 and, on a nonzero return,
 * increments that seven-bit field modulo 128 before returning 0. The bit/field
 * interpretation follows the observed masks and shifts; higher-level meaning
 * is not established.
 *
 * All four original data references access the same byte location in the
 * zero-filled tail of PT_LOAD 0. The pair at 0x1BD8/0x1BE4 is associated by
 * relocation order only; the other three are confirmed by register flow. The
 * location is not in a named ELF section, so the provisional external symbol
 * cannot prove identity in the candidate object.
 *
 * The switch preserves the original count-zero branch followed by a jump to
 * the later clear block. An equivalent if/else omits two instructions. Byte
 * bitfields preserve the original insertion sequence even for count = 0.
 * Result: INCONCLUSIVE 34/42, zero instruction differences/relocation issues;
 * unresolved data identity and the original order-only pairing remain.
 */

#include "libtutoriallist_stubs.h"

int func_00001B70(void)
{
    if (func_00006250_state.active != 0) {
        switch (func_00006250_state.count) {
        case 0:
            if (func_00001C58() != 0)
                func_00006250_state.count++;
            break;
        default:
            func_00006250_state.count = 0;
            return 1;
        }
    }
    return 0;
}
