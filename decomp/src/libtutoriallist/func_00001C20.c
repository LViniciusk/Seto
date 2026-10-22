/* [0x1C20,0x1C58), target of the relocated tail jump at 0x1C18.
 *
 * RESULT: INCONCLUSIVE 8/14, complete 56-byte symbol, zero differences/
 * relocation issues. Three HI16/LO16 data-identity limitations (words 2, 6, 9)
 * account for the six non-matching words; the call to 0x3A08 resolves through
 * libehsys/0x20E340D9.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

extern int func_00006248_handle;
extern void func_00003A08(int, int);

void func_00001C20(void)
{
    if (func_00006248_handle != 0) {
        func_00003A08(func_00006238_context, func_00006248_handle);
        func_00006248_handle = 0;
    }
}
