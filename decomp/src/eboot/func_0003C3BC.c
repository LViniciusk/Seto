/* Internal EBOOT helper at .text[0x3C3BC,0x3C3F0): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3A90C and 0x9D1C, no data references. Copies 0x200 bytes from base+0x4976 to its output; not an export. */
extern char *func_0003A90C(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003C3BC(void *destination)
{
    func_00009D1C(destination, func_0003A90C() + 0x4976, 0x200);
}
