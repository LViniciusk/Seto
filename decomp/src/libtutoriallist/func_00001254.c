/*
 * libtutoriallist.prx, .text [0x1254, 0x14E0), 163 instructions.
 *
 * Ghidra confirmed one exact body range. The function initializes the renderer
 * through local func_00001D08, derives a two-pixel margin from bit 3 of the
 * context returned by func_000037E0, and emits a frame plus inner guides. There
 * are no static data references. Parameter and import names/signatures remain
 * usage-derived hypotheses.
 */

#include "libtutoriallist_stubs.h"

void *func_00001254(void *renderer, int x, int y, int width, int height)
{
    int ready = func_00001D08(0x1003);
    int extra;
    int half;
    int left;
    int top;
    int right;
    int bottom;
    int inner_top;
    int inner_left;

    if (ready == 0)
        return renderer;

    extra = ((*func_000037E0() >> 3) & 1) * 2;
    renderer = func_00003B78(renderer, 0xFFFFFFFFu);
    renderer = func_00003BC0(renderer, 0, 0);
    renderer = func_00003850(renderer, ready);
    renderer = func_00003AF0(renderer, 6, 6, 6, 6);

    half = extra / 2;
    left = x - 4 - half;
    top = y - 4 - half;
    right = half + (x + width - 2);
    bottom = half + (y + height - 2);

    renderer = func_00003AE8(renderer, left, top, 0, 0x19, 0x14, 0, 0);
    renderer = func_00003AE8(renderer, right, top, 0, 0x28, 0x14, 0, 0);
    renderer = func_00003AE8(renderer, left, bottom, 0, 0x19, 0x29, 0, 0);
    renderer = func_00003AE8(renderer, right, bottom, 0, 0x28, 0x29, 0, 0);
    renderer = func_00003AF0(renderer, 6, 1, 6, height + extra - 4);

    inner_top = y + 2 - half;
    renderer = func_00003AE8(renderer, left, inner_top, 0, 0x19, 0x1A, 0, 0);
    renderer = func_00003AE8(renderer, right, inner_top, 0, 0x28, 0x1A, 0, 0);
    renderer = func_00003AF0(renderer, 1, 6, width + extra - 4, 6);

    inner_left = x + 2 - half;
    renderer = func_00003AE8(renderer, inner_left, top, 0, 0x1F, 0x14, 0, 0);
    renderer = func_00003AE8(renderer, inner_left, bottom, 0, 0x1F, 0x29, 0, 0);
    return renderer;
}
