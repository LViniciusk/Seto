/* Internal EBOOT helper at .text[0x3AA60,0x3AA94): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3A90C and 0x9D1C, no data references. Copies 0x30 bytes from its input to the base+0x1C field; not an export. */
extern char *func_0003A90C(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003AA60(void *source)
{
    func_00009D1C(func_0003A90C() + 28, source, 0x30);
}
