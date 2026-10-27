/* Internal EBOOT helper at .text[0x55814,0x55824): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Decrements the word at
 * offset 0x10; this is not an export.
 */
void func_00055814(unsigned int *data)
{
    data[4]--;
}
