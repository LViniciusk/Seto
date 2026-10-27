/* Internal EBOOT helper at .text[0x4CA80,0x4CA94): exact five-instruction
 * Ghidra boundary, no calls or data relocations. Sets a flag, stores a value,
 * and returns zero; this is not an export.
 */
int func_0004CA80(unsigned int *data, unsigned int value)
{
    data[1] = 1;
    data[0] = value;
    return 0;
}
