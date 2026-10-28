/* Internal EBOOT helper at .text[0x3BABC,0x3BDF0): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3A90C and 0x9D1C, no data references. Copies 0x40 bytes from its input to base+0x4936; not an export. */
extern char *func_0003A90C(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003BABC(const void *source)
{
    func_00009D1C(func_0003A90C() + 0x4936, source, 0x40);
}
