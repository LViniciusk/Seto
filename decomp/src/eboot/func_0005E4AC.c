/* Internal EBOOT helper at .text[0x5E4AC,0x5E4C8): exact seven-instruction
 * Ghidra boundary, no calls or data relocations. Initializes a compact set of
 * halfword/byte fields; this is not an export.
 */
void func_0005E4AC(unsigned short *data, unsigned short value)
{
    data[0] = value;
    data[1] = value;
    ((unsigned char *)data)[4] = 0x80;
    data[4] = 0;
    data[3] = 0;
}
