extern int func_0003C65C(unsigned int base);

unsigned char func_0003C7F4(unsigned int base)
{
    int offset = func_0003C65C(base);

    return *(unsigned char *)(base + offset + 3);
}