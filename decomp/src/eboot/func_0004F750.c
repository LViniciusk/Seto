/* Internal EBOOT helper at .text[0x4F750,0x4F7A0): exact twenty-instruction Ghidra boundary, two resolved calls to 0x4EF68 and 0x4F7A0 and no data references. Tests a flag byte, invokes the setter when bit 3 is present, and returns the result; not an export. */
extern void func_0004EF68(void *source, unsigned int *output);
extern void func_0004F7A0(void *self, int value);
int func_0004F750(int *self)
{
    unsigned int flags;
    func_0004EF68((void *)self[9], &flags);
    if ((flags & 8) == 8) {
        func_0004F7A0(self, 255);
        return 1;
    }
    return 0;
}
