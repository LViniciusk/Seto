/* Internal EBOOT helper at .text[0x3BAF0,0x3BB1C): exact eleven-instruction Ghidra boundary, two resolved calls to 0x3BA34 and 0xA140, no data references. Clears 0x108 bytes at the returned state pointer; not an export. */
extern char *func_0003BA34(void);
extern void func_0000A140(void *destination, int zero, int size);
void func_0003BAF0(void)
{
    func_0000A140(func_0003BA34(), 0, 0x108);
}
