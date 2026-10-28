/* Internal EBOOT helper at .text[0x5A19C,0x5A1B8): exact seven-instruction
 * Ghidra boundary, no calls or data relocations. Returns the combined base,
 * offset words, and eight-byte index displacement; not an export.
 */
unsigned char *func_0005A19C(unsigned int *base,
                            unsigned int *other,
                            unsigned int index)
{
    return (unsigned char *)base + base[3] + other[2] + (index << 3);
}
