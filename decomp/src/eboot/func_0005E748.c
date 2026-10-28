int func_0005E748(unsigned char *data)
{
    int value = *(unsigned short *)(data + 0xa4) * *(short *)(data + 0x98);

    value >>= 12;
    if (value < 1)
        value = 1;
    if (value > 0x4000)
        value = 0x4000;
    return value;
}
