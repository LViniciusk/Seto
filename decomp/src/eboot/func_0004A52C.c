/* Internal EBOOT helper at .text[0x4A52C,0x4A550): exact nine-instruction Ghidra boundary, one resolved call to 0x49B20 and no data references. Returns whether that result equals six; not an export. */
extern int func_00049B20(void);
int func_0004A52C(void) { return func_00049B20() == 6; }
