/* Internal EBOOT helper at .text[0x49BCC,0x49C10): exact seventeen-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Decodes a nine-bit field from word zero to a ten-byte unit offset, with the all-ones sentinel mapped to 0xFFFF; not an export. */
extern const unsigned int *func_00049850(void);
int func_00049BCC(void)
{
    unsigned int field = (func_00049850()[0] << 10) >> 23;
    if (field == 0x1ff) return 0xffff;
    return field * 10;
}
