/* Internal EBOOT helper at .text[0x3AEC8,0x3AEE8): exact eight-instruction Ghidra boundary, no data references. Returns the 3748-byte field offset from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003AEC8(void) { return func_0003A90C() + 3748; }
