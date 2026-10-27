/* Internal EBOOT helper at .text[0x49AD4,0x49AF8): exact nine-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Returns byte five masked to four bits; not an export. */
extern unsigned char *func_00049850(void);
int func_00049AD4(void) { return func_00049850()[5] & 15; }
