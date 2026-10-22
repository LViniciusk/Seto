/* [0x1F10,0x21F8), builds two key lists and computes display extents/windows.
 * All indexing, integer divisions and import calls follow the original guards;
 * callers must supply valid table indices and a nonzero metric denominator.
 * Provisional storage/import types are shared with the input/render functions.
 *
 * RESULT: NONMATCHING 89/186 compared words, 60 differences, 1 relocation
 * issue, 22 limitations; 744-byte candidate versus 744-byte original. Words
 * 0-95 match exactly. The original keeps the 4-bit group as a wide value and
 * narrows it only for the count lookup (0x20C8), so the local helpers below
 * take `int` for row addressing and `unsigned char` for the count array. The
 * remaining tail is a pure register permutation: group is t4 instead of t2,
 * position t2 instead of t4, plus the dependent pointer/value rotation. No
 * source-order, declaration-order, value-local or pointer variant tested
 * removed it; `j > trailing[group]` still reproduces the single post-loop
 * sum/exit merge.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

/* File-local views of the shared lookups. The original keeps the nibble group
 * wide for row indexing and converts it to a byte only for count[].
 */
static inline int panel_count_byte(unsigned char group)
{
    return func_00006190_panel.count[group];
}

static inline int panel_key_wide(int group, int index)
{
    if (index >= panel_count_byte(group))
        return 24;
    return func_00006190_panel.entries[group][index];
}

void func_00001F10(void)
{
    int selected_group = 0;
    int selected = 0;
    int metric;
    int i;
    int group;
    int lead;
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
    position = func_00006190_panel.trailing[group];
    lead = func_00006190_panel.leading[group];
    position += lead;
    while (selected != position) {
        if (position >= panel_count_byte(group) - 1)
            break;
        next = panel_key_wide(group, position + 1);
        extent = func_00006190_panel.extents[next];
        sum = 0;
        for (j = 0; j < 8; j++) {
            key = panel_key_wide(group, lead + j);
            next = func_00006190_panel.extents[key];
            if (j > func_00006190_panel.trailing[group])
                break;
            sum += next;
        }
        if (sum + extent > 8)
            func_00006190_panel.leading[group]++;
        else
            func_00006190_panel.trailing[group]++;
        group = func_00006190_panel.flags.group;
        position = func_00006190_panel.trailing[group];
        lead = func_00006190_panel.leading[group];
        position += lead;
    }
}
