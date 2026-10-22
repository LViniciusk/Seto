/* [0x21F8,0x25B0), input/window update. The imported context is dereferenced
 * without null guards in the original. Table/group bounds are caller obligations.
 *
 * RESULT: NONMATCHING 159/238, 31 differences, 2 relocation issues, 25
 * limitations; both symbols are 952 bytes. The byte-sized caller group removes
 * the accessor conversion. Loading the extent before `j > trailing[group]`
 * recovers the shared exit sum and original load-in-delay-slot scheduling.
 * First divergence: word 157, where LUI/ANDI order and the group/leading
 * register lifetimes still differ. No size-induced branch differences remain.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

void func_000021F8(void)
{
    int *input = func_00003A38();
    int pressed = input[1];
    unsigned char group;
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
        int lead;
        int next;
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
            lead = func_00006190_panel.leading[group];
            for (j = 0; j < 8; j++) {
                entry = libtutoriallist_panel_key(group, lead + j);
                next = func_00006190_panel.extents[entry];
                if (j > func_00006190_panel.trailing[group])
                    break;
                sum += next;
            }
            if (sum + extent > 8)
                func_00006190_panel.leading[group]++;
            else
                func_00006190_panel.trailing[group]++;
            func_000049C0(0x6212);
        }
    }
}
