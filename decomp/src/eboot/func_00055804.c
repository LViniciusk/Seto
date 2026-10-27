/* Internal EBOOT helper at .text[0x55804,0x55814): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Increments the word at
 * offset 0x10; this is not an export.
 */
void func_00055804(unsigned int *data)
{
    data[4]++;
}
