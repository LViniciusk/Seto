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
 * Current Metrowerks result: the source compiles to 152 bytes, while the
 * original interval is 168 bytes. The matcher returns ERROR before comparing
 * words because the candidate section is short; this is not NONMATCHING or
 * INCONCLUSIVE evidence. No no-op statements were added to pad the function.
 */

#include "libtutoriallist_stubs.h"

extern int func_00001C58(void);

int func_00001B70(void)
{
    unsigned char state;
    unsigned int count;
    unsigned int new_count;
    int result;

    result = 0;
    new_count = 0;
    state = func_00006250_state;
    if ((state & 1) != 0) {
        count = ((unsigned int)state << 24) >> 25;
        if (count != 0) {
            result = 1;
        } else {
            if (func_00001C58() == 0)
                return 0;
            state = func_00006250_state;
            count = ((unsigned int)state << 24) >> 25;
            new_count = (count + 1) & 0x7f;
            result = 0;
        }
        func_00006250_state = (state & ~0xfe) | (new_count << 1);
    }

    return result;
}
