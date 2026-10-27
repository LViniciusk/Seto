/* Internal EBOOT helper at .text[0x3D4C0,0x3D4EC): exact eleven-instruction Ghidra boundary, one resolved call to 0x3CD4C and no data references. Returns an indexed halfword pointer; not an export. */
extern char *func_0003CD4C(void);
char *func_0003D4C0(int index) { return func_0003CD4C() + index * 2; }
