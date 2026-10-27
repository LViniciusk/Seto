/* Internal EBOOT helper at .text[0x498E4,0x4990C): exact ten-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Extracts the top three bits of byte six; not an export. */
extern const unsigned char *func_00049850(void);
int func_000498E4(void) { return ((unsigned int)func_00049850()[6] << 25) >> 29; }
