/* Internal EBOOT helper at .text[0x49AAC,0x49AD4): exact ten-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Returns the high nibble of byte four; not an export. */
extern const unsigned char *func_00049850(void);
int func_00049AAC(void) { return ((unsigned int)func_00049850()[4] << 24) >> 28; }
