/* Internal EBOOT helper at .text[0x3C67C,0x3C6A4): exact ten-instruction Ghidra boundary, one resolved call to 0x3C65C and no data references. Extracts the top two bits of byte zero; not an export. */
extern const unsigned char *func_0003C65C(void);
int func_0003C67C(void) { return ((unsigned int)func_0003C65C()[0] << 24) >> 30; }
