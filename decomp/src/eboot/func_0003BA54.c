/* Internal EBOOT helper at .text[0x3BA54,0x3BA88): exact thirteen-instruction Ghidra boundary, two resolved calls to 0x3BA34 and 0x9D1C, no data references. Copies 0x108 bytes from the internal source to its output; not an export. */
extern char *func_0003BA34(void);
extern void func_00009D1C(void *destination, const void *source, int size);
void func_0003BA54(void *destination) { func_00009D1C(destination, func_0003BA34(), 0x108); }
