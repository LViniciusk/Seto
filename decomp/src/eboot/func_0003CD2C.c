/* Internal EBOOT helper at .text[0x3CD2C,0x3CD4C): exact eight-instruction Ghidra boundary, no data references. Returns the 100-byte field offset from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003CD2C(void) { return func_0003A90C() + 100; }
