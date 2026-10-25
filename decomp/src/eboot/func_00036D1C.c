/* EBOOT .text[0x36D1C,0x36D8C), libehsys export 0x8EA6B1E7.
 * Encodes a three-way selector in one 0x37 command word.
 */
extern void func_00031308(unsigned int address, unsigned int *command, int words);

void func_00036D1C(unsigned int address, int selector)
{
    unsigned int command[1] = {0};

    if (selector == 0) {
        command[0] = 0x37000002u;
    } else if (selector == 2) {
        command[0] = 0x37000001u;
    } else {
        command[0] = 0x37000000u;
    }

    func_00031308(address, command, 1);
}
