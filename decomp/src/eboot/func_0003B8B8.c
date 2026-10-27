/* Internal EBOOT helper at .text[0x3B8B8,0x3B8E0): exact ten-instruction Ghidra boundary, one resolved call to 0x3A90C and no data references. Returns null for a null base, otherwise the field at byte offset 0x4B76; not an export. */
extern char *func_0003A90C(void);
char *func_0003B8B8(void)
{
    char *base = func_0003A90C();
    return base ? base + 19318 : 0;
}
