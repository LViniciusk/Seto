/* Internal EBOOT helper at .text[0x49A84,0x49AAC): exact ten-instruction Ghidra boundary, one resolved call to 0x49850 and no data references. Extracts bits 15?19 of word one; not an export. */
extern const unsigned int *func_00049850(void);
int func_00049A84(void) { return (func_00049850()[1] << 12) >> 27; }
