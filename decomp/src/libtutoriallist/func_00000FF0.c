/*
 * libtutoriallist.prx, .text [0x0FF0, 0x1254), 153 instructions.
 *
 * Ghidra confirmed one exact body range. After the same local initialization
 * used by 0x7A4, this function issues a repeated sequence of renderer setup and
 * rectangle calls. It has no static data references; the four dimension-like
 * arguments and all import signatures remain provisional.
 */

#include "libtutoriallist_stubs.h"

void *func_00000FF0(
    void *arg0,
    unsigned int width,
    unsigned int height,
    unsigned int right_extent,
    unsigned int bottom_extent
)
{
    int status = func_00001D08(0x1003);
    /* Keep this declaration order: it reproduces the original saved registers. */
    unsigned int inner_bottom;
    unsigned int inner_right;

    if (status == 0)
        return arg0;

    arg0 = func_00003850(arg0, status);
    arg0 = func_00003B78(arg0, 0xFFFFFFFFu);
    arg0 = func_00003BC0(arg0, 0, 0);
    arg0 = func_00003AF0(arg0, 6, 6, 6, 6);

    arg0 = func_00003AE8(arg0, width, height, 0, 0x19, 0x2F, 0, 0);
    inner_bottom = height + bottom_extent - 6u;
    arg0 = func_00003AE8(arg0, width, inner_bottom, 0, 0x19, 0x3A, 0, 0);
    arg0 = func_00003AF0(arg0, 6, 6, 6, 6);

    inner_right = width + right_extent - 6u;
    arg0 = func_00003AE8(arg0, inner_right, height, 0, 0x24, 0x2F, 0, 0);
    arg0 = func_00003AE8(arg0, inner_right, inner_bottom, 0, 0x24, 0x3A, 0, 0);
    arg0 = func_00003AF0(arg0, 1, 6, right_extent - 12u, 6);
    arg0 = func_00003AE8(arg0, width + 6u, height, 0, 0x1F, 0x2F, 0, 0);
    arg0 = func_00003AE8(arg0, width + 6u, inner_bottom, 0, 0x1F, 0x3A, 0, 0);
    arg0 = func_00003AF0(arg0, 6, 1, 6, bottom_extent - 12u);
    arg0 = func_00003AE8(arg0, width, height + 6u, 0, 0x19, 0x35, 0, 0);
    arg0 = func_00003AE8(arg0, inner_right, height + 6u, 0, 0x24, 0x35, 0, 0);
    arg0 = func_00003AF0(
        arg0, 1, 1, right_extent - 12u, bottom_extent - 12u
    );

    return func_00003AE8(arg0, width + 6u, height + 6u, 0, 0x1F, 0x35, 0, 0);
}
