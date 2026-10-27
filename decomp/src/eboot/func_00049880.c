/* Internal EBOOT helper at .text[0x49880,0x498B0): exact twelve-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Expands the high bit of byte three into a 16-bit all-ones mask; not an export. */
extern const unsigned char *func_00049850(void);
int func_00049880(void)
{
    unsigned int bit = ((unsigned int)func_00049850()[3] << 24) >> 31;
    return (bit << 16) - bit;
}
