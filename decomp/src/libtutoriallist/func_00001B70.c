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
 * Current Metrowerks result: NONMATCHING 5/42 (30 differences, 8 relocation
 * issues and 2 pairing limitations). This is a real comparison; it does not
 * establish cross-artifact identity for the shared state.
 */

#include "libtutoriallist_stubs.h"

extern int func_00001C58(void);

int func_00001B70(void)
{
    unsigned char state;
    unsigned short count;
    unsigned char result;

    state = func_00006250_state;
    if ((state & 1) == 0)
        return 0;

    count = ((unsigned int)state << 24) >> 25;
    if (count != 0) {
        func_00006250_state = state & ~0xfe;
        result = 1;
    } else {
        if (func_00001C58() == 0)
            return 0;
        state = func_00006250_state;
        count = ((unsigned int)state << 24) >> 25;
        func_00006250_state = (state & ~0xfe) | (((count + 1) & 0x7f) << 1);
        result = 0;
    }
    return result;
}
