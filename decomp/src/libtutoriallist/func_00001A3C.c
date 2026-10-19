/*
 * libtutoriallist.prx, .text [0x1A3C, 0x1B0C), 52 instructions.
 *
 * Ghidra confirmed an exact one-range body. There are no static data
 * relocations; the only call is the recovered import
 * (libehsys, NID 0xB89D38DC) at stub 0x42A0. The code clears a four-byte local
 * digit buffer, adjusts the starting coordinate by 4 or 8, then emits decimal
 * digits while the value is positive. Parameter meanings and the import's SDK
 * signature remain provisional; the bytewise clear and arithmetic are based on
 * the observed instruction sequence, not an assumed API name.
 */

#include "libtutoriallist_stubs.h"

void func_00001A3C(int x, int y, int value)
{
    short digits[2];
    char *cursor = (char *)digits;
    int remaining = 4;

    if (cursor != (char *)0) {
        do {
            *cursor = 0;
            remaining -= 1;
            cursor += 1;
        } while (remaining != 0);
    }

    if (value < 10)
        x += 4;
    else
        x += 8;

    if (value > 0) {
        int pixel_x = x << 6;

        do {
            digits[0] = (short)((value % 10) + 0x30);
            func_000042A0(pixel_x, y << 6, (0x1E0 - x) << 6, digits);
            pixel_x -= 0x200;
            value /= 10;
            x -= 8;
        } while (value > 0);
    }
}
