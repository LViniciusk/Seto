/*
 * libtutoriallist.prx, .text [0x6E8, 0x7A4), 47 instructions.
 *
 * Ghidra confirmed an exact boundary. The function first calls the local
 * function at 0x1D08 with 0x1011; on zero it returns its input. Otherwise it
 * clears a 0x60-byte local block, reads one word through the import at 0x37E0,
 * and uses eight recovered imports in the setup/render chain. All identities are from
 * libtutoriallist.prx; names/signatures remain usage-derived hypotheses.
 */

#include "libtutoriallist_stubs.h"

void *func_000006E8(void *arg0)
{
    int status = func_00001D08(0x1011);
    int scratch[24];

    if (status == 0)
        return arg0;

    func_00002610(scratch, 0, 0x60);
    scratch[0] = *func_000037E0();

    arg0 = func_00003768(arg0);
    arg0 = func_00003758(arg0, status, scratch);
    arg0 = func_00003770(arg0);
    arg0 = func_00003AA8(arg0, 4);
    arg0 = func_00003BC8(arg0, 0, 1);
    return func_00003C70(arg0, 0, 2, 3, 0, 0);
}
