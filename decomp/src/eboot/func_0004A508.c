/* Internal EBOOT helper at .text[0x4A508,0x4A52C): exact nine-instruction Ghidra boundary, one resolved call to 0x49B20 and no data references. Returns whether its result equals nine; not an export. */
extern int func_00049B20(void);
int func_0004A508(void) { return func_00049B20() == 9; }
