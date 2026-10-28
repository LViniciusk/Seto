/* Internal EBOOT accessor at .text[0x4E5A8,0x4E5B0): exact two-instruction
 * Ghidra boundary, no calls or data relocations. Returns the word at offset
 * 0x14; this is not an export.
 */
unsigned int func_0004E5A8(const unsigned int *data)
{
    return data[5];
}
