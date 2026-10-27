/* Internal EBOOT helper at .text[0x5A50C,0x5A524): exact six-instruction
 * Ghidra boundary, no calls or data relocations. Clears five words; this is
 * not an export.
 */
void func_0005A50C(unsigned int *data)
{
    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
}
