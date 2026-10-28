/* Internal EBOOT helper at .text[0x3C3F0,0x3C424): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3A90C and 0x9D1C, no data references. Copies 0x200 bytes from its input to base+0x4976; not an export. */
extern char *func_0003A90C(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003C3F0(const void *source)
{
    func_00009D1C(func_0003A90C() + 0x4976, source, 0x200);
}
