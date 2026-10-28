/* Internal EBOOT helper at .text[0x39F94,0x39FCC): exact fourteen-instruction Ghidra boundary, one resolved call to 0x3A90C and no data references. Sets the selected flag bit in field four; not an export. */
extern unsigned int *func_0003A90C(void);
void func_00039F94(int index)
{
    func_0003A90C()[1] |= 1u << index;
}
