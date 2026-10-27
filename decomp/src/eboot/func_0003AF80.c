/* Internal EBOOT helper at .text[0x3AF80,0x3AFA0): exact eight-instruction Ghidra boundary, one resolved call to 0x3AEC8 and no data references. Returns an additional 1308-byte field offset; not an export. */
extern char *func_0003AEC8(void);
char *func_0003AF80(void) { return func_0003AEC8() + 1308; }
