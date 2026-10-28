extern void func_0004EF68(void *source, unsigned int *output);

int func_0004E5B0(int *param_1)
{
    unsigned int local_4;

    func_0004EF68((void *)param_1[8], &local_4);
    return (local_4 & 8) == 8;
}
