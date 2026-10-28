extern unsigned char *func_0003C424(int index);

unsigned int func_0003C4A8(int index)
{
    unsigned char *entry = func_0003C424(index);

    return entry != 0 ? *entry : 0;
}