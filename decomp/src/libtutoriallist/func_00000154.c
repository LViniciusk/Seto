/* [0x154,0x280), phase dispatch. Low nibble and closing flag are byte fields.
 * Return values 0/1/2 follow the original phase-4 cleanup path.
 *
 * RESULT: INCONCLUSIVE 65/75 words, zero instruction/relocation differences,
 * 300-byte candidate. Five HI16/LO16 pairs (9 limitation entries) remain
 * unproven.
 */
#include "libtutoriallist_stubs.h"
#include "libtutoriallist_panel.h"

int func_00000154(void)
{
    switch (func_00006190_panel.phase) {
    case 0:
        if (func_00001B70() != 0) {
            func_00001F10();
            func_00006190_panel.phase = 1;
            func_000048E8(1, 0xFF000000u, 16);
            func_00003D90(0);
            func_000049B0(6);
        }
        break;
    case 1:
        if (func_000048F8() != 0)
            func_00006190_panel.phase = 2;
        break;
    case 2:
        func_000021F8();
        break;
    case 3:
        if (func_000048F8() != 0)
            func_00006190_panel.phase = 4;
        break;
    case 4:
        if (func_00000280() != 0) {
            if (func_00006190_panel.flags.closing != 0)
                return 2;
            return 1;
        }
        break;
    }
    return 0;
}
