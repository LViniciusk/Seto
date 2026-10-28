/* Internal EBOOT helper at .text[0x3BA34,0x3BA54): exact eight-instruction Ghidra boundary, no data references. Returns the 18464-byte field offset from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003BA34(void) { return func_0003A90C() + 18464; }
