/* Internal EBOOT helper at .text[0x6A92C,0x6A94C): exact eight-instruction Ghidra boundary, no data references. Returns signed byte two from the zero-indexed table at 0x6A674; not an export. */
extern const signed char *func_0006A674(int index);
int func_0006A92C(void) { return func_0006A674(0)[2]; }
