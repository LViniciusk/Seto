unsigned int func_00048518(int *param_1)
{
    int index = 0;
    int *entry = param_1;

    do {
        if (*(int **)(*entry + 8) == param_1 + 0x13)
            return *(unsigned int *)(param_1[index] + 0xa0);
        index++;
        entry++;
    } while (index < 0x10);

    return 0;
}
