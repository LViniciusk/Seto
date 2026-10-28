extern unsigned char *func_0005A134(unsigned int id);

int func_0005A298(unsigned int id)
{
    unsigned char *entry = func_0005A134(id);

    if (entry == 0) {
        return -1;
    }
    return entry[7];
}