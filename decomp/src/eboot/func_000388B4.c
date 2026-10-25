/* EBOOT .text[0x388B4,0x388FC), libehsys export 0x5CBB9E43.
 * Adds the 0xDE command tag and submits one word to the internal helper.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_000388B4(unsigned int address, unsigned int value)
{
    unsigned int command[1] = {0};

    command[0] = value | 0xDE000000u;
    func_00031308(address, command, 1);
}
