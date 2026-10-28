int func_0003F3A4(unsigned int *params, unsigned int index)
{
    if (params != 0) {
        unsigned int count = params[0];
        unsigned int *entries = (unsigned int *)((unsigned char *)params + params[1]);
        int base = (int)params + (int)params[2];

        if (index < count)
            return base + (int)entries[index];
    }

    return 0;
}
