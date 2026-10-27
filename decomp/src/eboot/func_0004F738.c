/* Internal EBOOT helper at .text[0x4F738,0x4F748): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Returns the difference
 * between adjacent words in the input structure; this is not an export.
 */
unsigned int func_0004F738(unsigned int *data)
{
    return data[7] - data[6];
}
