/* Internal EBOOT helper at .text[0x3C74C,0x3C774): exact ten-instruction Ghidra boundary, one resolved call to 0x3C65C and no data references. Extracts the selected two-bit field from byte zero; not an export. */
extern const unsigned char *func_0003C65C(void);
int func_0003C74C(void) { return ((unsigned int)func_0003C65C()[0] << 26) >> 30; }
