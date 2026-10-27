/* Internal EBOOT helper at .text[0x49B44,0x49B88): exact seventeen-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Decodes a nine-bit field from word zero to a ten-byte unit offset, with the all-ones sentinel mapped to zero; not an export. */
extern const unsigned int *func_00049850(void);
int func_00049B44(void)
{
    unsigned int field = (func_00049850()[0] << 10) >> 23;
    return field == 0x1ff ? 0 : field * 10;
}
