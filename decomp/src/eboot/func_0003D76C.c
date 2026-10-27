/* Internal EBOOT helper at .text[0x3D76C,0x3D7A4): exact fourteen-instruction Ghidra boundary, one resolved call to 0x3A90C and no data references. Returns the indexed 0x15C-byte record plus offset 0x4BF8; not an export. */
extern char *func_0003A90C(void);
char *func_0003D76C(int index)
{
    return func_0003A90C() + index * 0x15c + 0x4bf8;
}
