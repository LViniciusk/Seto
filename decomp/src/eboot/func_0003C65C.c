/* Internal EBOOT helper at .text[0x3C65C,0x3C67C): exact eight-instruction Ghidra boundary, no data references. Returns the 92-byte field offset from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003C65C(void) { return func_0003A90C() + 92; }
