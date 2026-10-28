extern signed char *func_0005A134(unsigned int id);
int func_0005A204(unsigned int id)
{
    signed char *entry = func_0005A134(id);
    if (entry == 0) {
        return 0;
    }
    return *entry;
}