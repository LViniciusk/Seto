/* Internal EBOOT helper at .text[0x4F698,0x4F6B4): exact seven-instruction
 * Ghidra boundary, no calls or data relocations. Computes a slot from two
 * object fields and stores the value in the original delay slot; not export.
 */
int func_0004F698(const unsigned int *data, unsigned int value)
{
    unsigned int *slot = (unsigned int *)(data[3] + data[4] * 4);
    *slot = value;
    return 0;
}
