/* [0x2F4,0x6E8), exported render driver. The old Ghidra range disagreement
 * includes branch-threaded blocks; the resident pointer and complete return
 * bound the executable interval. The renderer's address is passed to 0x4908,
 * so its observable stack-backed lifetime must be retained, not made volatile.
 * Table indices, imported pointers, and signed geometry retain original input
 * obligations; no speculative guards or data definitions are introduced.
 *
 * RESULT: NONMATCHING 134/253, 99 differences, 20 relocation issues, four
 * HI16/LO16 limitations; both symbols are 1012 bytes. The visible-row lookup
 * uses the shared accessor, removing the former size-induced differences at
 * words 32/34. First divergence: word 81 (candidate `lui v1`, original
 * `lui a0`) in the flags/list-loop setup. Size equality does not imply CFG
 * equality: the original's unreachable scheduler copies at 0x4B0, 0x560 and
 * 0x634 are not reproduced, and the accessor adds conversions/reloads.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

void func_000002F4(void)
{
    void *renderer;
    int total;
    int preceding;
    int leading;
    int i;
    int group;
    int key;
    int extent;
    int line;
    int row;
    int position;

    renderer = func_00003A68(0, 0);
    renderer = func_00003C90(renderer, 0xFF000000u);
    renderer = func_00003CA0(renderer, 0);
    renderer = func_00003C98(renderer, 0);
    renderer = func_00003CA8(renderer, 23);
    func_00003A70(renderer);
    if (func_00006190_panel.phase == 4)
        return;
    if (func_00006190_panel.phase == 0)
        return;
    renderer = func_00003A68(4, 0);
    renderer = func_00003AA8(renderer, 9);
    renderer = func_00003AA8(renderer, 4);
    renderer = func_00003BC8(renderer, 0, 1);
    renderer = func_00003BC0(renderer, 0, 0);
    renderer = func_00003C70(renderer, 0, 2, 3, 0, 0);
    renderer = func_00003AB0(renderer, 1);
    renderer = func_000006E8(renderer);
    renderer = func_000007A4(renderer);
    renderer = func_000008F0(renderer, 75, 39, 331, 219);

    total = 0;
    preceding = 0;
    leading = 0;
    group = func_00006190_panel.flags.group;
    for (i = 0; i < func_00006190_panel.count[group]; i++) {
        if (i >= func_00006190_panel.count[group])
            key = 24;
        else
            key = func_00006190_panel.entries[group][i];
        extent = func_00006190_panel.extents[key];
        total += extent;
        if (i < func_00006190_panel.leading[group] + func_00006190_panel.trailing[group])
            preceding += extent;
        if (i < func_00006190_panel.leading[group])
            leading += extent;
    }
    renderer = func_00001764(renderer, 394, 66, 179, leading, 8, total);

    line = 0;
    row = 0;
    do {
        group = func_00006190_panel.flags.group;
        position = func_00006190_panel.leading[group] + line;
        if (position >= func_00006190_panel.count[group])
            break;
        key = libtutoriallist_panel_key(group, position);
        renderer = func_00000E24(renderer, 81, (row * 3) * 8 + 60, key);
        row += func_00006190_panel.extents[key];
        line++;
    } while (row < 8);

    group = func_00006190_panel.flags.group;
    if (func_00006190_panel.count[group] > 0) {
        position = func_00006190_panel.leading[group] + func_00006190_panel.trailing[group];
        if (position >= func_00006190_panel.count[group])
            key = 24;
        else
            key = func_00006190_panel.entries[group][position];
        renderer = func_00001254(
            renderer, 110, ((preceding - leading) * 3) * 8 + 62,
            279, (func_00006190_panel.extents[key] * 3) * 8 - 5
        );
    }
    func_00003A70(renderer);
    renderer = func_00003A68(5, 0);
    renderer = func_00003AB0(renderer, 1);
    func_00004908(&renderer);
    func_00003A70(renderer);
}
