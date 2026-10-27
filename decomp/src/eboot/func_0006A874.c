/* Internal EBOOT helper at .text[0x6A874,0x6A89C): exact ten-instruction Ghidra boundary, two resolved calls to 0x6A7A4 and 0x6A674 and no data references. Returns byte zero of the indexed string; not an export. */
extern int func_0006A7A4(void);
extern const signed char *func_0006A674(int index);
int func_0006A874(void) { return func_0006A674(func_0006A7A4())[0]; }
