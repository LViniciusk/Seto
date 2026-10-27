/* Internal EBOOT helper at .text[0x4CAA4,0x4CAB0): exact three-instruction
 * Ghidra boundary, no calls or data relocations. Stores one word and returns
 * zero; this is not an export.
 */
int func_0004CAA4(unsigned int *data, unsigned int value)
{
    data[1] = value;
    return 0;
}
