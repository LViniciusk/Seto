/* Internal EBOOT helper at .text[0x3CD9C,0x3CDC4): exact ten-instruction Ghidra boundary, one resolved call to 0x3A90C and no data references. Reads the 32-bit field at base+0x97E8; not an export. */
extern char *func_0003A90C(void);
int func_0003CD9C(void)
{
    return *(int *)(func_0003A90C() + 0x10000 - 0x6818);
}
