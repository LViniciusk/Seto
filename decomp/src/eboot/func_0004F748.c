/* Internal EBOOT accessor at .text[0x4F748,0x4F750): exact two-instruction
 * Ghidra boundary, no calls or data relocations. Returns the word at offset
 * 0x18; this is not an export.
 */
unsigned int func_0004F748(const unsigned int *data)
{
    return data[6];
}
