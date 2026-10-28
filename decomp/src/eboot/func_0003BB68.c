extern unsigned int *func_0003BA34(void);

void func_0003BB68(int selector, unsigned int value)
{
    unsigned int *base = func_0003BA34();

    switch (selector) {
    case 3:
        base[2] = value;
        return;
    default:
        break;
    }
    switch (selector) {
    case 2:
        base[1] = value;
        return;
    default:
        break;
    }
    switch (selector) {
    case 1:
        base[0] = value;
        return;
    default:
        break;
    }
}
