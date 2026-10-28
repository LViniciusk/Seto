/* Internal EBOOT helper at .text[0x3BA88,0x3BABC): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3A90C and 0x9D1C, no data references. Copies 0x40 bytes from base+0x4936 to its output; not an export. */
extern char *func_0003A90C(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003BA88(void *destination)
{
    func_00009D1C(destination, func_0003A90C() + 0x4936, 0x40);
}
