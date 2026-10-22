/* [0x8F0,0xE24), two-column panel renderer. Signed geometry follows the
 * original arithmetic. Coordinates/products/shifts must fit int; imports and
 * globals are usage-derived, with no invented data identity or null guards.
 *
 * RESULT: NONMATCHING 52/342 compared words (333 original + 9 extra candidate
 * words), 284 differences, 68 relocation issues, one HI16/LO16 limitation;
 * 1368-byte candidate versus 1332-byte original. First divergence is word 15:
 * the candidate spills `height` to 0x4c(sp), while the original keeps it in s2
 * through 0xb44 and later reuses s2 as the loop counter.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

void *func_000008F0(void *renderer, int x, int y, int width, int height)
{
    int first;
    int second;
    int atlas;
    int top;
    int bottom;
    int right;
    int i;
    int row;
    int icon;
    int half;
    int dim;
    int left_tile;
    int right_tile;

    first = func_00001D08(0x1002);
    second = func_00001D08(0x1003);
    if (first == 0)
        return renderer;
    renderer = func_00003850(renderer, first);
    renderer = func_00003B78(renderer, 0xFFFFFFFFu);
    renderer = func_00003BC0(renderer, 0, 0);
    atlas = func_00006190_panel.flags.group * 32;
    top = y + 15;
    renderer = func_00003AF0(renderer, 6, 6, 6, 6);
    renderer = func_00003AE8(renderer, x, top, 0, 0x40, atlas, 0, 0);
    bottom = y + height - 6;
    renderer = func_00003AE8(renderer, x, bottom, 0, 0x40, atlas + 11, 0, 0);
    renderer = func_00003AF0(renderer, 14, 6, 14, 6);
    right = x + width - 14;
    renderer = func_00003AE8(renderer, right, top, 0, 0x62, atlas, 0, 0);
    renderer = func_00003AE8(renderer, right, bottom, 0, 0x62, atlas + 26, 0, 0);
    renderer = func_00003AF0(renderer, 1, 6, width - 20, 6);
    renderer = func_00003AE8(renderer, x + 6, top, 0, 0x46, atlas, 0, 0);
    renderer = func_00003AE8(renderer, x + 6, bottom, 0, 0x46, atlas + 11, 0, 0);
    renderer = func_00003AF0(renderer, 6, 1, 6, height - 27);
    renderer = func_00003AE8(renderer, x, top + 6, 0, 0x40, atlas + 6, 0, 0);
    renderer = func_00003AF0(renderer, 14, 1, 14, height - 27);
    renderer = func_00003AE8(renderer, right, top + 6, 0, 0x62, atlas + 6, 0, 0);
    renderer = func_00003AF0(renderer, 1, 1, width - 20, height - 27);
    renderer = func_00003AE8(renderer, x + 6, top + 6, 0, 0x46, atlas + 6, 0, 0);
    func_00004270(13, 13);
    row = 0;
    icon = 0;
    for (i = 0; i < 2; i++) {
        half = width / (2 - i);
        width -= half;
        dim = 0;
        if (i == 0)
            left_tile = 0;
        else
            left_tile = 16;
        if (i == 1)
            right_tile = 48;
        else
            right_tile = 32;
        if (i == func_00006190_panel.flags.group) {
            renderer = func_00003B78(renderer, 0xFFFFFFFFu);
            func_00004280(0xFFFFFFFFu);
        } else {
            left_tile += 8;
            right_tile += 8;
            dim = 2;
            renderer = func_00003B78(renderer, 0x80FFFFFFu);
            func_00004280(0xFF808080u);
        }
        renderer = func_00003BC0(renderer, 0, 0);
        renderer = func_00003850(renderer, first);
        renderer = func_00003AF0(renderer, 8, 18, 8, 18);
        renderer = func_00003AE8(renderer, x, y, 0, left_tile, row, 0, 0);
        renderer = func_00003AE8(renderer, x + half - 8, y, 0, right_tile, row, 0, 0);
        renderer = func_00003AF0(renderer, 1, 18, half - 16, 18);
        renderer = func_00003AE8(renderer, x + 8, y, 0, left_tile + 4, row, 0, 0);
        if (i != func_00006190_panel.flags.group) {
            renderer = func_00003C38(renderer, x, y + dim, half - 8, 13);
            renderer = func_00003AA8(renderer, 2);
        }
        if (second != 0) {
            renderer = func_00003850(renderer, second);
            renderer = func_00003AF0(renderer, 16, 16, 16, 16);
            renderer = func_00003AE8(renderer, x + 4, y + 2 + dim, 0, icon, 0, 0, 0);
        }
        func_00004350(renderer);
        func_000042A0(
            (x + 20) << 6, (y + 4 + dim) << 6, (half - 8) << 6,
            func_000041D8(func_00001D08(0x1020), i + 2)
        );
        renderer = func_00003AB0(func_00004358(), 2);
        x += half;
        row += 32;
        icon += 16;
    }
    return renderer;
}
