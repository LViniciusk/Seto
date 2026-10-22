/* [0x2C8,0x2F4), address-taken export in the original resident table.
 * Returns -1 while the closing flag is set; otherwise the unsigned current key.
 *
 * RESULT: NONMATCHING 7/11, 44-byte candidate. The instruction words are
 * identical; the single recorded difference is a matcher limitation, not a
 * source mismatch. The original HI16 at 0x2DC cannot be associated with the
 * LO16 at 0x2E8 because word 7 (`addiu v0,zero,-1`) redefines the LO16 base
 * register; candidate-side pairing succeeds by symbol identity. The candidate
 * uses the expected symbol-relative LO16 addends (4/6). Do not relax the
 * matcher to promote this function.
 */
#include "libtutoriallist_panel.h"

int func_000002C8(void)
{
    if (func_00006190_panel.flags.closing != 0)
        return -1;
    return func_00006190_panel.current;
}
