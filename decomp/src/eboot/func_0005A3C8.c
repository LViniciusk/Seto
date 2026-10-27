/* Internal EBOOT helper at .text[0x5A3C8,0x5A3DC): exact five-instruction
 * Ghidra boundary, no calls or data relocations. Clears two words and writes
 * a halfword at offset 0x0A; this is not an export.
 */
void func_0005A3C8(unsigned int *data, unsigned short value)
{
    data[0] = 0;
    data[1] = 0;
    ((unsigned short *)data)[4] = 0;
    ((unsigned short *)data)[5] = value;
}
