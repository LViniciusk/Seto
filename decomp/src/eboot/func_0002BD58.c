/* Internal EBOOT .text[0x2BD58,0x2BD74): Ghidra confirms the exact
 * seven-instruction body. This helper is not an export and has no NID.
 * The branch returns the word at base+0x38 when nonzero; otherwise it returns
 * base plus the word at base+0x18. `fields` preserves the original delay-slot
 * address calculation for MWCC.
 */
unsigned char *func_0002BD58(unsigned char *base)
{
    unsigned char *fields = base + 0x10;
    unsigned int value = *(unsigned int *)(base + 0x38);

    if (value == 0)
        value = (unsigned int)base + *(unsigned int *)(fields + 8);
    return (unsigned char *)value;
}
