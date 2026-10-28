/* Internal EBOOT helper at .text[0x3CEC8,0x3CEF4): exact eleven-instruction Ghidra boundary, one resolved call to 0x3CD08 and no data references. Copies one halfword to its output; not an export. */
extern short *func_0003CD08(void);
void func_0003CEC8(short *destination) { *destination = *func_0003CD08(); }
