/* [0x1F10,0x21F8), builds two key lists and computes display extents/windows.
 * All indexing, integer divisions and import calls follow the original guards;
 * callers must supply valid table indices and a nonzero metric denominator.
 * Provisional storage/import types are shared with the input/render functions.
 *
 * RESULT: NONMATCHING 70/187 compared words (186 original + 1 extra), 81
 * differences, 3 relocation issues, 21 limitations; 748-byte candidate versus
 * 744-byte original. Words 0-95 match exactly; word 96 (`andi t0` vs `andi t2`)
 * starts the tail's register rotation, with `group` in t0 instead of t2.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

void func_00001F10(void)
{
    int selected_group = 0;
    int selected = 0;
    int metric;
    int i;
    unsigned char group;
    int position;
    int next;
    int sum;
    int j;
    int key;
    int extent;

    func_00004270(14, 14);
    metric = func_00004298();
    for (i = 0; i < 24; i++) {
        if (func_000040F8(i) == 2) {
            if (i >= 8) {
                func_00006190_panel.entries[0][func_00006190_panel.count[0]++] = i;
                if (i == func_00006190_panel.current) {
                    selected_group = 0;
                    selected = func_00006190_panel.count[0] - 1;
                }
            } else {
                func_00006190_panel.entries[1][func_00006190_panel.count[1]++] = i;
                if (i == func_00006190_panel.current) {
                    selected_group = 1;
                    selected = func_00006190_panel.count[1] - 1;
                }
            }
            func_00006190_panel.extents[i] =
                (func_000042C8(0x4400, func_000041D8(func_00001D08(0x1020), i + 4)) + 64) / metric;
        }
    }
    func_00006190_panel.extents[24] = 1;
    func_00006190_panel.flags.group = selected_group;
    group = func_00006190_panel.flags.group;
    position = func_00006190_panel.leading[group] + func_00006190_panel.trailing[group];
    while (selected != position) {
        if (position >= func_00006190_panel.count[group] - 1)
            break;
        next = libtutoriallist_panel_key(group, position + 1);
        extent = func_00006190_panel.extents[next];
        sum = 0;
        for (j = 0; j < 8; j++) {
            key = libtutoriallist_panel_key(group, func_00006190_panel.leading[group] + j);
            next = func_00006190_panel.extents[key];
            if (func_00006190_panel.trailing[group] < j)
                break;
            sum += next;
        }
        if (sum + extent > 8)
            func_00006190_panel.leading[group]++;
        else
            func_00006190_panel.trailing[group]++;
        group = func_00006190_panel.flags.group;
        position = func_00006190_panel.leading[group] + func_00006190_panel.trailing[group];
    }
}
