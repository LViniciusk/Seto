extern unsigned char *func_0003A90C(void);

unsigned char *func_0003C424(int index)
{
    unsigned char *base = func_0003A90C();

    if (index >= 0x30) {
        return 0;
    }

    return base + index * 42 + 0x8ff0;
}
