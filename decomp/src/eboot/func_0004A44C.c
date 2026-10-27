/* Internal EBOOT helper at .text[0x4A44C,0x4A470): exact nine-instruction Ghidra boundary, one resolved call to 0x49B20 and no data references. Returns whether its result is zero; not an export. */
extern int func_00049B20(void);
int func_0004A44C(void) { return func_00049B20() == 0; }
