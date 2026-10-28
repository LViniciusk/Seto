/* Internal EBOOT helper at .text[0x5A1CC,0x5A1E0): exact five-instruction
 * Ghidra boundary, no calls or data relocations. Returns base plus the word
 * at offset 0x10 and the first word in `other`; this is not an export.
 */
unsigned char *func_0005A1CC(unsigned char *base, unsigned int *other)
{
    return base + *(unsigned int *)(base + 0x10) + other[0];
}
