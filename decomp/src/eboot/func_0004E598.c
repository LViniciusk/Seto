/* Internal EBOOT helper at .text[0x4E598,0x4E5A8): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Returns the difference
 * between adjacent words in the input structure; this is not an export.
 */
unsigned int func_0004E598(unsigned int *data)
{
    return data[6] - data[5];
}
