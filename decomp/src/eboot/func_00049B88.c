/* Internal EBOOT helper at .text[0x49B88,0x49BCC): exact seventeen-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Decodes a nine-bit field from halfword one to a ten-byte unit offset, with the all-ones sentinel mapped to zero; not an export. */
extern const unsigned short *func_00049850(void);
int func_00049B88(void)
{
    unsigned int field = ((unsigned int)func_00049850()[1] << 17) >> 23;
    return field == 0x1ff ? 0 : field * 10;
}
