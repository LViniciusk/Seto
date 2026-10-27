/* Internal EBOOT helper at .text[0x50678,0x50688): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Returns base plus the word
 * stored at offset 0xC8 plus 0xAC; this is not an export.
 */
unsigned int *func_00050678(unsigned int *data)
{
    return (unsigned int *)(data[50] + (unsigned int)data + 0xac);
}
