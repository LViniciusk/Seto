/* Internal EBOOT helper at .text[0x3D834,0x3D868): exact thirteen-instruction Ghidra boundary, one resolved call to 0x3A90C and no data references. Reads a byte at base + index + 0x10000 - 0x6830; not an export. */
extern void *func_0003A90C(void);
unsigned char func_0003D834(int index)
{
    unsigned int address = (unsigned int)func_0003A90C() + (unsigned int)index + 0x10000;
    return *(unsigned char *)(address - 0x6830);
}
