/* Internal EBOOT helper at .text[0x3B860,0x3B8B8): exact twenty-two-instruction Ghidra boundary, three resolved calls to 0x3A90C, 0xA140, and 0x3DFD8, no data references. Clears and copies a bounded text field when the base is non-null; not an export. */
extern char *func_0003A90C(void);
extern void func_0000A140(void *destination, int zero, int size);
extern void func_0003DFD8(void *destination, const void *source, int count);
void func_0003B860(const void *source)
{
    char *base = func_0003A90C();
    if (base == 0) return;
    func_0000A140(base + 0x4b76, 0, 0x80);
    func_0003DFD8(base + 0x4b76, source, 0x3f);
}
