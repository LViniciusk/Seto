/* Internal EBOOT helper at .text[0x4A574,0x4A598): exact nine-instruction Ghidra boundary, one resolved call to 0x49B20 and no data references. Returns whether that result equals eight; not an export. */
extern int func_00049B20(void);
int func_0004A574(void) { return func_00049B20() == 8; }
