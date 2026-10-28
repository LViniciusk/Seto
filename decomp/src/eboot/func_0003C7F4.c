extern char *func_0003C65C(void);

unsigned char func_0003C7F4(unsigned char *base)
{
    char *offset = func_0003C65C();

    return *(unsigned char *)(base + (unsigned int)offset + 3);
}