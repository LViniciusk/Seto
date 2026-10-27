/* Internal EBOOT helper at .text[0x3D1F0,0x3D228): exact fourteen-instruction Ghidra boundary, one resolved call to 0x3CD2C and no data references. Reads the first halfword of an 18-byte-stride record; not an export. */
extern unsigned short *func_0003CD2C(void);
unsigned short func_0003D1F0(int index) { return *(unsigned short *)((char *)func_0003CD2C() + index * 18); }
