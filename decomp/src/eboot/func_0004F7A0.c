/* Internal EBOOT helper at .text[0x4F7A0,0x4F7AC): exact three-instruction
 * Ghidra boundary, no calls or data relocations. Stores one word and returns
 * zero; this is not an export.
 */
int func_0004F7A0(unsigned int *data, unsigned int value)
{
    data[8] = value;
    return 0;
}
