/*
 * libtutoriallist.prx, .text [0x07A4, 0x08F0), 83 instructions.
 *
 * Ghidra confirmed one exact body range. The function initializes a renderer
 * through local func_00001D08 and then emits several configured rectangles and
 * one final digit-buffer draw. It has no static data references. Parameter and
 * import names/signatures remain usage-derived hypotheses.
 */

#include "libtutoriallist_stubs.h"

void *func_000007A4(void *arg0)
{
    int status = func_00001D08(0x1003);

    if (status == 0)
        return arg0;

    arg0 = func_00003850(arg0, status);
    arg0 = func_00003B78(arg0, -1);
    arg0 = func_00003BC0(arg0, 0, 0);
    arg0 = func_00003AF0(arg0, 12, 23, 12, 23);
    arg0 = func_00003AE8(arg0, 0, 0, 0, 0, 20, 0, 0);
    arg0 = func_00003AE8(arg0, 0x1D4, 0, 0, 13, 20, 0, 0);
    arg0 = func_00003AF0(arg0, 1, 23, 0x1C8, 23);
    arg0 = func_00003AE8(arg0, 12, 0, 0, 12, 20, 0, 0);
    func_00004270(14, 14);
    func_00004280(-1);
    func_00004350(arg0);
    arg0 = func_000041D8(func_00001D08(0x1020), 1);
    func_000042A0(0x200, 0x100, 0x7600, arg0);

    return func_00004358();
}
