/* EBOOT .text[0x37BC8,0x37C10), libehsys export 0xCABEA834.
 * Builds the 0x5E command word and submits it through the internal helper.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_00037BC8(unsigned int address, unsigned int value)
{
    unsigned int command[1] = {0};

    command[0] = value | 0x5E000000u;
    func_00031308(address, command, 1);
}
