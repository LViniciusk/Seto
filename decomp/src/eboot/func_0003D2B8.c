/* Internal EBOOT helper at .text[0x3D2B8,0x3D2EC): exact thirteen-instruction Ghidra boundary, one resolved call to 0x3CD2C and no data references. Returns the 18-byte-stride record pointer; not an export. */
extern char *func_0003CD2C(void);
char *func_0003D2B8(int index) { return func_0003CD2C() + index * 18; }
