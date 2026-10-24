/* EBOOT .text[0x3643C,0x364E4), exported by libehsys NID 0x4175E3DB.
 * Ghidra confirms the rounded word offset, two-word command buffer, and call to
 * the internal helper at 0x31308. The original C names and source are unknown.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_0003643C(unsigned int *base_pointer, int offset)
{
    int rounded = offset + 3;
    unsigned int base = *base_pointer;
    unsigned int address;
    unsigned int command[2] = {0, 0};
    unsigned int high_byte;

    if (rounded < 0) {
        rounded = offset + 6;
    }
    address = base + (rounded >> 2) * 4 + 0x20;
    high_byte = (address & 0xFF000000) >> 24;
    command[0] = (high_byte & 0x0F) << 16 | 0x10000000;
    command[1] = (address & 0x00FFFFFF) | 0x08000000;
    func_00031308(base, command, 2);
    *base_pointer = address;
}
