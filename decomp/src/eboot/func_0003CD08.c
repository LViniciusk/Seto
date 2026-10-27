/* Internal EBOOT helper at .text[0x3CD08,0x3CD2C): exact nine-instruction Ghidra boundary, no data references. Returns the chained 0x17F4 and 0x7FF8 byte offsets from 0x3A90C; not an export. */
extern char *func_0003A90C(void);
char *func_0003CD08(void) { return func_0003A90C() + 0x17F4 + 0x7FF8; }
