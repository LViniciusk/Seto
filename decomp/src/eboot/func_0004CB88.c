/* Internal EBOOT helper at .text[0x4CB88,0x4CBD4): exact nineteen-instruction Ghidra boundary, two resolved calls to 0x4EF68 and 0x4CAA4 and no data references. Invokes the setter when the returned byte is 0xFF, then returns zero; not an export. */
extern void func_0004EF68(void *source, unsigned char *output);
extern void func_0004CAA4(void *self, int value);
int func_0004CB88(int *self)
{
    unsigned int temporary;
    unsigned char *result = (unsigned char *)&temporary;
    func_0004EF68((void *)self[3], result);
    if (result[0] == 0xff) func_0004CAA4(self, 3);
    return 0;
}
