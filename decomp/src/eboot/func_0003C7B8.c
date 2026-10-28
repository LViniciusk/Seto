extern unsigned char *func_0003C65C(void);

void func_0003C7B8(int index, unsigned int value)
{
    unsigned char *base = func_0003C65C();
    unsigned char nibble = (unsigned char)(value & 0xf);
    unsigned int address = (unsigned int)index + (unsigned int)base;

    ((unsigned char *)address)[3] = nibble;
}
