extern unsigned char *func_0003C424(int index);

unsigned char *func_0003C544(int index)
{
    unsigned char *entry = func_0003C424(index);

    return entry != 0 ? entry + 2 : 0;
}