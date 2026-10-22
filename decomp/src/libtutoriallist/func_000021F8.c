/* [0x21F8,0x25B0), input/window update. The imported context is dereferenced
 * without null guards in the original. Table/group bounds are caller obligations.
 *
 * RESULT: NONMATCHING 119/241 compared words (238 original + 3 extra), 78
 * differences, 11 relocation issues, 21 limitations; 964-byte candidate versus
 * 952-byte original. The extra words shift early branch displacements; the
 * structural divergence rotates the group/window base registers (original:
 * group=a2, group*2=t2, &leading=a0, &count=a3; candidate: group=t0,
 * group*2=a3, &leading=a1, &count=a2).
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

void func_000021F8(void)
{
    int *input = func_00003A38();
    int pressed = input[1];
    int group;
    int position;
    int count;
    int key;
    int extent;
    int sum;
    int j;
    int entry;

    if ((pressed & func_00004118(1)) != 0) {
        func_00006190_panel.flags.closing = 1;
        func_000048F0(1, 0xFF000000u, 16);
        func_00004A00(600);
        func_00006190_panel.phase = 3;
        func_000049C0(0x6214);
    } else if ((pressed & func_00004118(0)) != 0) {
        group = func_00006190_panel.flags.group;
        position = func_00006190_panel.leading[group] + func_00006190_panel.trailing[group];
        count = func_00006190_panel.count[group];
        if (position >= count)
            key = 24;
        else
            key = func_00006190_panel.entries[group][position];
        if (key < 24) {
            if (position >= count)
                key = 24;
            else
                key = func_00006190_panel.entries[group][position];
            func_00006190_panel.current = key;
            func_000048F0(1, 0xFF000000u, 16);
            if (func_00006190_panel.current >= 8)
                func_00004A00(600);
            func_00006190_panel.phase = 3;
            func_000049C0(0x6213);
        }
    } else if ((pressed & 0x83A0) != 0) {
        func_00006190_panel.flags.group = (func_00006190_panel.flags.group + 1) & 1;
        func_000049C0(0x621B);
    } else if ((input[3] & 0x10) != 0) {
        group = func_00006190_panel.flags.group;
        if (func_00006190_panel.trailing[group] > 0) {
            func_00006190_panel.trailing[group]--;
            func_000049C0(0x6212);
        } else if (func_00006190_panel.leading[group] > 0) {
            func_00006190_panel.leading[group]--;
            func_000049C0(0x6212);
        }
    } else if ((input[3] & 0x40) != 0) {
        unsigned short *cursor;
        group = func_00006190_panel.flags.group;
        position = func_00006190_panel.leading[group] + func_00006190_panel.trailing[group];
        count = func_00006190_panel.count[group];
        if (position < count - 1) {
            if (position + 1 >= count)
                entry = 24;
            else
                entry = func_00006190_panel.entries[group][position + 1];
            extent = func_00006190_panel.extents[entry];
            sum = 0;
            cursor = &func_00006190_panel.entries[group][func_00006190_panel.leading[group]];
            for (j = 0; j < 8; j++, cursor++) {
                if (func_00006190_panel.leading[group] + j >= func_00006190_panel.count[group])
                    entry = 24;
                else
                    entry = *cursor;
                if (func_00006190_panel.trailing[group] < j)
                    break;
                sum += func_00006190_panel.extents[entry];
            }
            if (sum + extent > 8)
                func_00006190_panel.leading[group]++;
            else
                func_00006190_panel.trailing[group]++;
            func_000049C0(0x6212);
        }
    }
}
