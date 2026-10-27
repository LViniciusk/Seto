/* Internal EBOOT helper at .text[0x28B3C,0x28B48). Ghidra confirms the exact
 * three-instruction boundary. It stores a value at offset 0x34, clears the
 * following word, and has no call or data relocations. This is not an export.
 */
void func_00028B3C(unsigned int *data, unsigned int value)
{
    data[13] = value;
    data[14] = 0;
}
