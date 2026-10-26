extern void func_00031308(unsigned int address, unsigned int *command, int words);


void func_00038B58(unsigned int address, unsigned int value)
{
    unsigned int command[2];
    unsigned char *p;
    unsigned int count;

    p = (unsigned char *)command;
    count = 8;
    if (p != 0) {
        do {
            *p = 0;
            p++;
        } while (--count != 0);
    }
    command[0] = (value & 0x00FFFFFF) | 0xE8000000;
    command[1] = (value >> 24) | 0xE9000000;
    func_00031308(address, command, 2);
}
