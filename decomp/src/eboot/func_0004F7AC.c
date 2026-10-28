/* Internal EBOOT accessor at .text[0x4F7AC,0x4F7B4): exact two-instruction
 * Ghidra boundary, no calls or data relocations. Returns the word at offset
 * 0x20; this is not an export.
 */
unsigned int func_0004F7AC(const unsigned int *data)
{
    return data[8];
}
