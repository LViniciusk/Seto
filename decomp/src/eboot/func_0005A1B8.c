/* Internal EBOOT helper at .text[0x5A1B8,0x5A1CC): exact five-instruction
 * Ghidra boundary, no calls or data relocations. Returns base plus the word
 * at offset 0x18 and the second word in `other`; this is not an export.
 */
unsigned char *func_0005A1B8(unsigned char *base, unsigned int *other)
{
    return base + *(unsigned int *)(base + 0x18) + other[1];
}
