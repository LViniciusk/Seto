/* Internal EBOOT helper at .text[0x3CD4C,0x3CD6C): exact eight-instruction Ghidra boundary, no data references. Returns the 2980-byte field offset from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003CD4C(void) { return func_0003A90C() + 2980; }
