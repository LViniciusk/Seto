/* EBOOT .text[0x36CCC,0x36D1C), libehsys export 0xFDD168CA.
 * Packs the 0x36 command word from two arguments and submits it internally.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_00036CCC(unsigned int address, unsigned int value, int field)
{
    unsigned int command[1] = {0};

    command[0] = ((unsigned int)field << 8) | 0x36000000u | value;
    func_00031308(address, command, 1);
}
