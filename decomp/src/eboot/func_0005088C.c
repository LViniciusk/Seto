/* Internal EBOOT helper at .text[0x5088C,0x508A4): exact six-instruction
 * Ghidra boundary, no calls or data relocations. Tests the word at offset
 * 0xAC against 0x1A4D5043; this is not an export.
 */
int func_0005088C(const unsigned int *data)
{
    return data[0xacu / 4] == 0x1a4d5043u;
}
