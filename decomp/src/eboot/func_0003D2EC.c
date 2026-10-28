/* Internal EBOOT helper at .text[0x3D2EC,0x3D324): exact fourteen-instruction Ghidra boundary, one resolved call to 0x3CD2C and no data references. Reads the halfword at offset 0x10 in an 18-byte-stride record; not an export. */
extern unsigned short *func_0003CD2C(void);
unsigned short func_0003D2EC(int index) { return *(unsigned short *)((char *)func_0003CD2C() + index * 18 + 0x10); }
