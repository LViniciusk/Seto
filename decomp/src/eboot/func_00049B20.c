/* Internal EBOOT helper at .text[0x49B20,0x49B44): exact nine-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Returns byte four masked to four bits; not an export. */
extern unsigned char *func_00049850(void);
int func_00049B20(void) { return func_00049850()[4] & 15; }
