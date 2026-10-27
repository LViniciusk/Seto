/* Internal EBOOT helper at .text[0x49AF8,0x49B20): exact ten-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Returns the high three bits of byte five; not an export. */
extern const unsigned char *func_00049850(void);
int func_00049AF8(void) { return ((unsigned int)func_00049850()[5] << 25) >> 29; }
