/* Internal EBOOT helper at .text[0x3CA44,0x3CA6C): exact ten-instruction Ghidra boundary, one resolved call to 0x3C65C and no data references. Extracts the top two bits of byte one; not an export. */
extern const unsigned char *func_0003C65C(void);
int func_0003CA44(void) { return ((unsigned int)func_0003C65C()[1] << 27) >> 30; }
