/* Internal EBOOT helper at .text[0x6A8C4,0x6A8EC): exact ten-instruction Ghidra boundary, two resolved calls to 0x6A7A4 and 0x6A674 and no data references. Returns byte two of the indexed string; not an export. */
extern int func_0006A7A4(void);
extern const signed char *func_0006A674(int index);
int func_0006A8C4(void) { return func_0006A674(func_0006A7A4())[2]; }
