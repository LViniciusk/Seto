/*
 * libtutoriallist.prx, .text [0x0E24, 0x0FF0), 115 instructions.
 *
 * Ghidra confirmed one exact body range. This renderer routine initializes the
 * tutorial panel, draws its frame and a progress segment, formats the current
 * page number, and restores the display state. The local calls are
 * func_00001D08 (twice: 0x1003 and 0x1020), func_00000FF0 and func_00001A3C;
 * the remaining call sites are imported libehsys trampolines.
 *
 * The halfword lookup at 0x0ECC/0x0ED4 combines to module offset 0x00006204.
 * It lies in the module's zero-filled load segment, not in a named section, so
 * the table cannot be identified with a versioned data object. The declaration
 * below is a reference to that location under a provisional name; it is not a
 * claim that a candidate symbol names the original object. The table entry is
 * scaled as (value * 3) * 8, matching the three shift/add words at 0x0EE8.
 *
 * Demonstrated by the binary for `func_00000E24_extents[index]`: the base
 * combines to module offset 0x00006204, the halfword load uses index directly,
 * and the path contains no bounds check.
 *
 * Required input domain for `func_00000E24_extents[index]` (hypothesis, not
 * demonstrated): index must select a valid element of that table. Its size and
 * ownership are not proven, and the known callers' index ranges are not
 * established here. This is the caller's obligation; the original does not
 * guard it.
 *
 * The import NIDs and the parameter meanings are usage-derived. In particular
 * 0x180/0x280, 12/14, 0x4400 and 0xFF000000 are passed through unchanged; they
 * are not assigned invented flag or unit meanings.
 *
 * The else-first form
 *     if (index >= 8) value = index - 8; else value = index;
 * reproduces the original branch layout at 0x0F54. The equivalent then-first
 * form compiles with the two paths exchanged and does not match.
 *
 * Status: INCONCLUSIVE 113/115, zero instruction differences. The single
 * limitation is the HI16/LO16 pair at 0x0ECC/0x0ED4: the original target
 * resolves only to the load segment (offset 0x00006204), while the candidate
 * symbol is unresolved. The comparator excludes both words of an unresolved
 * pair, so 113/115 is its maximum without inventing a cross-artifact identity.
 */

#include "libtutoriallist_stubs.h"

extern void *func_00000FF0(
    void *arg0,
    unsigned int width,
    unsigned int height,
    unsigned int right_extent,
    unsigned int bottom_extent
);
extern void func_00001A3C(int x, int y, int value);

extern unsigned short func_00000E24_extents[];

void *func_00000E24(void *renderer, int x, int y, int index)
{
    int ready;
    int extent;
    int value;

    ready = func_00001D08(0x1003);
    if (ready == 0)
        return renderer;

    renderer = func_00003850(renderer, ready);
    renderer = func_00003B78(renderer, 0xFFFFFFFFu);
    renderer = func_00003BC0(renderer, 0, 0);
    renderer = func_00003AF0(renderer, 0x19, 0x15, 0x19, 0x15);
    renderer = func_00003AE8(renderer, x, y + 1, 0, 0, 0x2B, 0, 0);

    extent = (func_00000E24_extents[index] * 3) * 8;
    renderer = func_00000FF0(renderer, x + 0x1B, y, 0x11B, extent - 1);

    if (func_00004120() == 0)
        func_00004340(0x280);
    else
        func_00004340(0x180);
    func_00004350(renderer);

    func_00004270(12, 14);
    func_00004280(0xFFFFFFFFu);

    if (index >= 8)
        value = index - 8;
    else
        value = index;

    func_00001A3C(x + 4, y + 4, value + 1);

    func_00004270(14, 14);
    func_00004280(0xFF000000u);

    func_000042A8(
        (x + 0x20) << 6, (y + 5) << 6, 0x4400, (extent - 7) << 6,
        func_000041D8(func_00001D08(0x1020), index + 4), -1
    );

    func_00004340(0);
    return func_00004358();
}
