/* Internal EBOOT helper at .text[0x5E4C8,0x5E4E4): exact seven-instruction
 * Ghidra boundary, no calls or data relocations. Initializes byte and halfword
 * fields; the source order preserves the original store/delay-slot order.
 */
void func_0005E4C8(unsigned char *data, unsigned int value)
{
    data[0] = (unsigned char)value;
    data[1] = (unsigned char)value;
    data[2] = 0x80;
    ((unsigned short *)data)[3] = 0;
    ((unsigned short *)data)[2] = 0;
}
