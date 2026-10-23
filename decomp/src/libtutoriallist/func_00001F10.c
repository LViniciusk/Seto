/* [0x1F10,0x21F8), builds two key lists and computes display extents/windows.
 * All indexing, integer divisions and import calls follow the original guards;
 * callers must supply valid table indices and a nonzero metric denominator.
 * Provisional storage/import types are shared with the input/render functions.
 *
 * RESULT: NONMATCHING 137/186 compared words, 11 differences, 0 relocation
 * issues, 23 limitations; 744-byte candidate versus 744-byte original. Words
 * 0-99 match exactly. The inner trailing-bound check (0x2140) indexes
 * `trailing` with the same byte-narrowed group as `count[]` (0x20C8), so MWCC
 * reuses the loop-body count base (a1) instead of retaining the preheader's
 * wide `2 * group`; the original keeps the wide `&trailing` (t1) for the tail
 * increment and the narrow base (a1) for this check as separate values.
 * The declaration pressure that reproduces the original homes is: group t2,
 * position t4, j t3, sum t4 (sum declared before j), with group declared
 * before lead. The surviving 11 words are the dependent swap of the wide
 * `&trailing` (original t1, candidate a3) with `lead` (original a3, candidate
 * t1); the narrow base, panel base, group, position, j and sum now match.
 * After the CSE correction, leading-first ordering, single-expression loads,
 * reversed lead+position forms and panel-field widths all produced 187 words
 * (one extra instruction) or worse; moving lead/position declarations did not
 * change the remaining pair.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

/* File-local views of the shared lookups. The original keeps the nibble group
 * wide for rows and the outer trailing/leading reloads, but narrows it to a
 * byte for count[] and the inner trailing[] bound check.
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
    int extent;
    int key;
    int sum;
    int j;
    int next;
    int position;
    int group;
    int lead;
    int i;
    int metric;

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
            if (j > func_00006190_panel.trailing[(unsigned char)group])
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
