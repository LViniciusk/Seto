extern unsigned int *func_0003BA34(void);

unsigned int func_0003BB1C(int selector)
{
    unsigned int *base = func_0003BA34();

    return selector != 3
        ? (selector != 2
            ? (selector != 1 ? 0 : base[0])
            : base[1])
        : base[2];
}
