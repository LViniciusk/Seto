/* EBOOT .text[0x3F2B0,0x3F328), libehsys export NID 0xE58C0FDC.
 * Ghidra 12.1.3 confirmed the exact 30-instruction Allegrex body.
 * Accepted ranges are 0x61..0x7A, 0xE0..0xFE, and odd values in
 * 0x100..0x17F; every other value returns zero.
 */
int func_0003F2B0(unsigned short param_1)
{
    int value = param_1;

    if ((value >= 0x61 && value <= 0x7a) ||
        (value >= 0xe0 && value <= 0xfe))
        return 1;
    if (value >= 0x100 && value < 0x180 && (value & 1) != 0)
        return 1;
    return 0;
}
