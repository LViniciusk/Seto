/* Internal EBOOT helper at .text[0x4A4C0,0x4A4E4): exact nine-instruction Ghidra boundary, one resolved call to 0x49F78 and no data references. Returns whether its result equals three; not an export. */
extern int func_00049F78(void);
int func_0004A4C0(void) { return func_00049F78() == 3; }
