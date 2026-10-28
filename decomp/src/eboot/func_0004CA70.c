/* Internal EBOOT helper at .text[0x4CA70,0x4CA80): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Stores two words and returns
 * zero; this is not an export.
 */
int func_0004CA70(unsigned int *data,
                  unsigned int first,
                  unsigned int second)
{
    data[2] = first;
    data[3] = second;
    return 0;
}
