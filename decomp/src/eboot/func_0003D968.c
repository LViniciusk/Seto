/* Internal EBOOT helper at .text[0x3D968,0x3D98C): exact nine-instruction Ghidra boundary, one resolved call to 0x3C65C and no data references. Returns byte zero masked to three bits; not an export. */
extern unsigned char *func_0003C65C(void);
int func_0003D968(void) { return func_0003C65C()[0] & 7; }
