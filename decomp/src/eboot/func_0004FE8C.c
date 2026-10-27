/* Internal EBOOT helper at .text[0x4FE8C,0x4FE9C): exact four-instruction
 * Ghidra boundary, no calls or data relocations. Returns -1 or 0 from the
 * low bit of the signed byte at offset 0x88; this is not an export.
 */
int func_0004FE8C(const signed char *data)
{
    unsigned int value = (unsigned int)data[0x88];
    return (int)(value << 31) >> 31;
}
