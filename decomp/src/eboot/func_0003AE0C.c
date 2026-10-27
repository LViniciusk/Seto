/* Internal EBOOT helper at .text[0x3AE0C,0x3AE3C): exact twelve-instruction Ghidra boundary, no data references. Indexes a 32-bit field at byte offset 0x54 from 0x3A90C plus index*4; not an export. */
extern void *func_0003A90C(void);
int func_0003AE0C(int index)
{
    unsigned int byte_offset = (unsigned int)index << 2;
    unsigned int address = byte_offset + (unsigned int)func_0003A90C();
    return *(int *)(address + 0x54);
}
